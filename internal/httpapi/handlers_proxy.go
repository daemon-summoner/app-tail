// SPDX-License-Identifier: MIT

package httpapi

import (
	"net"
	"net/http"
	"runtime"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsproxy"
)

// pacContentType is the type browsers have expected for an auto-config script since
// Netscape defined the format. Serving it as text/javascript makes some engines refuse
// the file outright.
const pacContentType = "application/x-ns-proxy-autoconfig"

// exposureLimit is the grant the proxy makes while it is on, stated wherever the module
// is shown. A 127.0.0.1 bind restricts by host, not by user, and there is no portable
// peer-credential check for loopback TCP -- so this is a property of the feature rather
// than something a future release tightens.
const exposureLimit = "While this proxy is on, any process on this machine, running as any local user, " +
	"can reach everything its rules allow. Binding to 127.0.0.1 restricts by host, not by user."

// ProxyView is the proxy as the dashboard sees it: its state, the URLs to point things
// at, and the commands to do so. The commands are rendered server-side because a shell
// command assembled in the UI is one nothing tests.
type ProxyView struct {
	Enabled bool `json:"enabled"`
	// Listening is the bound host:port, empty when nothing is bound. Together with
	// Enabled it separates "off" from "on but could not bind".
	Listening string `json:"listening,omitempty"`
	NodeUp    bool   `json:"nodeUp"`
	Scope     string `json:"scope"`
	// ScopeCarries says in words what the scope does, since "tailnet" and "all" are
	// only meaningful to someone who already knows the answer.
	ScopeCarries string `json:"scopeCarries"`
	// ResolveVia is which resolver turns a name into an address, and ResolveExplains
	// says what that means. A name that resolves everywhere except through the proxy
	// is answered by this pair and by nothing else on the page.
	ResolveVia       string `json:"resolveVia"`
	ResolveExplains  string `json:"resolveExplains"`
	RequiresPassword bool   `json:"requiresPassword"`
	Error            string `json:"error,omitempty"`
	// ConfiguredAddr is what the settings ask for, and MovedFromConfig reports that a
	// port conflict put the listener somewhere else -- which is what explains a
	// snippet naming one port and the dashboard showing another.
	ConfiguredAddr  string            `json:"configuredAddr"`
	MovedFromConfig bool              `json:"movedFromConfig"`
	SocksURL        string            `json:"socksUrl,omitempty"`
	HTTPURL         string            `json:"httpUrl,omitempty"`
	PACURL          string            `json:"pacUrl,omitempty"`
	Counters        tsproxy.Counters  `json:"counters"`
	Capability      Capability        `json:"capability"`
	Snippets        []tsproxy.Snippet `json:"snippets"`
}

func (s *Server) handleGetProxy(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Proxy, "tailnet proxy"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.proxyView(s.deps.Proxy.Status(), r))
}

// proxyView assembles the whole proxy surface for one request. The dashboard address
// comes from the request rather than from configuration because it is the name the
// browser actually dialed -- a PAC URL naming a different one is a URL that browser
// cannot fetch. The Host guard has already established it names this agent.
func (s *Server) proxyView(st tsproxy.Status, r *http.Request) ProxyView {
	snippetCfg := tsproxy.SnippetConfig{
		ProxyAddr:        st.Listening,
		DashboardAddr:    r.Host,
		RequiresPassword: st.RequiresToken,
		Platform:         runtime.GOOS,
		// This endpoint answers for the instance the command line and the /proxy.pac route
		// address, so every way of pointing a program at a proxy applies to it.
		Default: true,
	}

	view := ProxyView{
		Enabled:          st.Enabled,
		Listening:        st.Listening,
		NodeUp:           st.NetworksUp,
		Scope:            string(st.Scope),
		ScopeCarries:     scopeDescription(st),
		ResolveVia:       string(st.ResolveVia),
		ResolveExplains:  resolveDescription(st),
		RequiresPassword: st.RequiresToken,
		Error:            st.Error,
		ConfiguredAddr:   st.ConfiguredAddr,
		MovedFromConfig:  st.MovedFromConfig,
		SocksURL:         tsproxy.SOCKSURL(snippetCfg),
		HTTPURL:          tsproxy.HTTPURL(snippetCfg),
		Counters:         st.Counters,
		Capability:       ProxyCapabilityOf(st),
		Snippets:         tsproxy.Snippets(snippetCfg),
	}
	if st.Listening != "" {
		view.PACURL = tsproxy.PACURL(r.Host)
	}
	if view.Snippets == nil {
		view.Snippets = []tsproxy.Snippet{}
	}
	return view
}

// scopeDescription states what this proxy carries, in one sentence.
//
// It is derived from the rules rather than stored, so it cannot drift from what the proxy
// actually does. A rule set that is not one of the two familiar shapes says so and points
// at the rules, which are the only complete answer.
func scopeDescription(st tsproxy.Status) string {
	switch {
	case st.Rules == 0:
		return "nothing: this proxy has no rules, and it carries only what a rule allows"
	case st.Scope == config.ScopeAll:
		return "one connection entirely, plus this machine's own network"
	case st.Scope == config.ScopeTailnet:
		return "one connection entirely; anything else is refused rather than sent direct"
	default:
		return "what its rules allow, and nothing else"
	}
}

// resolveDescription states which resolver a name goes to, in the terms the setting
// offers. Split DNS is the case it exists for: a name that resolves in a browser and
// fails through the proxy has no other explanation on the page.
func resolveDescription(st tsproxy.Status) string {
	if st.ResolveVia == config.ResolveViaTailnet {
		return "names go to the tailnet's own DNS first, so a split-DNS domain resolves to its private address"
	}
	return "tailnet device names come from the netmap; every other name goes to this machine's resolver"
}

// ProxyCapabilityOf answers "is this working, and if not why" in one place, so the
// dashboard, the tray and the CLI cannot each reach a different conclusion -- and so every
// instance is judged by the same rules the one every install has is.
func ProxyCapabilityOf(st tsproxy.Status) Capability {
	limits := []string{exposureLimit}
	if st.RequiresToken {
		// A PAC result line has no credential field, and neither Chrome nor Firefox
		// accepts one in a proxy URL, so requiring a password is what turns the
		// browser path off.
		limits = append(limits,
			"A password is required, so the browser auto-config script sends everything direct: "+
				"a PAC file has nowhere to put one. Point browsers at the proxy manually, or turn the requirement off.")
	}

	switch {
	case !st.Enabled:
		// Which of the two switches is off decides what the reader has to go and change.
		// Naming the module while it is on sends them to a switch that is already where
		// they want it, and leaves the instance's own switch unmentioned.
		if !st.ModuleOn {
			return Capability{Reason: "the proxy module is switched off", Limits: limits}
		}
		return Capability{Reason: "this proxy is switched off", Limits: limits}
	case st.Listening == "":
		reason := st.Error
		if reason == "" {
			reason = "the proxy is switched on but is not listening"
		}
		return Capability{Reason: reason, Limits: limits}
	case !st.NetworksUp:
		return Capability{
			Available: true,
			Degraded:  true,
			Reason: "the port is open but no connection is running, so every request is " +
				"refused rather than sent direct",
			Limits: limits,
		}
	case st.MovedFromConfig:
		return Capability{
			Available: true,
			Degraded:  true,
			Reason: "port " + portOf(st.ConfiguredAddr) + " was taken, so the proxy moved to " +
				st.Listening + "; update anything that names the old port",
			Limits: limits,
		}
	default:
		return Capability{Available: true, Limits: limits}
	}
}

func portOf(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return addr
}

// handleProxyProbe dials one destination on the caller's behalf. It exists because
// "the proxy is listening" and "the proxy can reach that peer" are different questions,
// and only the second one is what a user is actually asking.
func (s *Server) handleProxyProbe(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Proxy, "tailnet proxy"); err != nil {
		s.writeError(w, r, err)
		return
	}

	var body struct {
		Address string `json:"address"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeError(w, r, err)
		return
	}
	address := strings.TrimSpace(body.Address)
	if address == "" {
		s.writeError(w, r, badRequest("address is required, as host:port"))
		return
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		s.writeError(w, r, badRequest("address %q must be host:port", address))
		return
	}

	// A refused or unreachable destination is the probe's answer, not the request's
	// failure: the result carries it, and only a broken proxy produces an error here.
	result, err := s.deps.Proxy.Probe(r.Context(), address)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

// handlePAC serves the browser auto-config script.
//
// It sits on the dashboard's own mux because that is a port the browser can already
// reach and whose guards already apply. A browser fetches it with GET and no Origin,
// so the same-origin check does not affect it, and it asks for it under a loopback
// name, which the Host guard accepts.
func (s *Server) handlePAC(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Proxy, "tailnet proxy"); err != nil {
		s.writeError(w, r, err)
		return
	}
	script, err := s.deps.Proxy.PAC(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", pacContentType)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(script)); err != nil {
		s.logger.Error("writing the proxy auto-config script failed", "error", err)
	}
}
