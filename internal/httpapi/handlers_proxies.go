// SPDX-License-Identifier: MIT

package httpapi

import (
	"encoding/json"
	"net"
	"net/http"
	"runtime"
	"strings"

	"github.com/sellitus/app-tail/internal/access"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsproxy"
)

// withCommands fills in the parts of an instance view only a request can supply: the
// ready-to-run ways of pointing a program at it, and the address a browser fetches the
// auto-configuration script from.
//
// The dashboard address comes from the request rather than from configuration because it is
// the name the browser actually dialed -- an address naming a different one is one that
// browser cannot fetch. The Host guard has already established it names this agent.
//
// Only the default instance is offered the ways that go back through app-tail itself. On
// any other instance they would point a program at the default proxy's permissions from a
// card describing a different set.
func withCommands(view ProxyInstanceView, r *http.Request) ProxyInstanceView {
	cfg := tsproxy.SnippetConfig{
		ProxyAddr:        view.Listening,
		RequiresPassword: view.RequiresPassword,
		Platform:         runtime.GOOS,
		Default:          view.Default,
	}
	if view.Default {
		cfg.DashboardAddr = r.Host
		if view.Listening != "" {
			view.PACURL = tsproxy.PACURL(r.Host)
		}
	}
	view.Snippets = tsproxy.Snippets(cfg)
	if view.Snippets == nil {
		view.Snippets = []tsproxy.Snippet{}
	}
	return view
}

// eachWithCommands is the same for a whole list, so a client reading the list and a client
// reading one instance are told the same things about it.
func eachWithCommands(views []ProxyInstanceView, r *http.Request) []ProxyInstanceView {
	out := make([]ProxyInstanceView, 0, len(views))
	for _, view := range views {
		out = append(out, withCommands(view, r))
	}
	return out
}

// ProxySchemaView is the whole vocabulary a client needs to render an instance form: the
// fields, the sections those fields reference by id, and the switches they are gated on.
// Serving the fields alone would leave a client naming a section it cannot label.
type ProxySchemaView struct {
	Fields  []config.FieldSchema `json:"fields"`
	Groups  []config.GroupInfo   `json:"groups"`
	Modules []config.ModuleInfo  `json:"modules"`
	// Actions and Protocols are the vocabulary of a rule, served for the reason the field
	// options are: a client that held its own list would offer a value the agent refuses.
	Actions   []access.Action   `json:"actions"`
	Protocols []access.Protocol `json:"protocols"`
}

func (s *Server) handleListProxies(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Proxies, "proxies"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"proxies": eachWithCommands(s.deps.Proxies.List(), r),
	})
}

func (s *Server) handleGetProxyInstance(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Proxies, "proxies"); err != nil {
		s.writeError(w, r, err)
		return
	}
	view, err := s.deps.Proxies.Get(r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, withCommands(view, r))
}

func (s *Server) handleGetProxySchema(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Proxies, "proxies"); err != nil {
		s.writeError(w, r, err)
		return
	}
	fields := s.deps.Proxies.Schema()
	s.writeJSON(w, http.StatusOK, ProxySchemaView{
		Fields:    fields,
		Groups:    config.GroupsFor(fields),
		Modules:   config.ModulesFor(fields),
		Actions:   access.Actions,
		Protocols: access.Protocols,
	})
}

func (s *Server) handleCreateProxy(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Proxies, "proxies"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var spec ProxyInstanceSpec
	if err := decodeJSON(r, &spec); err != nil {
		s.writeError(w, r, err)
		return
	}
	view, err := s.deps.Proxies.Create(r.Context(), spec)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, withCommands(view, r))
}

func (s *Server) handleUpdateProxy(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Proxies, "proxies"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var patch map[string]json.RawMessage
	if err := decodeJSON(r, &patch); err != nil {
		s.writeError(w, r, err)
		return
	}
	view, err := s.deps.Proxies.Update(r.Context(), r.PathValue("id"), patch)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, withCommands(view, r))
}

// handleSetProxyRules replaces one instance's whole ordered rule list.
//
// The body is the list rather than an edit to it because order is semantics: the first
// matching rule decides. A caller sends what the list should be, which is also what makes
// two clients editing the same instance produce a list one of them recognises rather than
// an interleaving neither wrote.
func (s *Server) handleSetProxyRules(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Proxies, "proxies"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var body struct {
		Rules []access.Rule `json:"rules"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeError(w, r, err)
		return
	}
	view, err := s.deps.Proxies.SetRules(r.Context(), r.PathValue("id"), body.Rules)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, withCommands(view, r))
}

func (s *Server) handleDeleteProxy(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Proxies, "proxies"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.Proxies.Delete(r.Context(), r.PathValue("id")); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusNoContent, nil)
}

// handleTestProxy answers what an instance would do with one destination, without dialling
// it. A permission model nobody can question is one nobody trusts, and this is the endpoint
// that makes rule order visible: it names the line that decided.
func (s *Server) handleTestProxy(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Proxies, "proxies"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var body ProxyTestRequest
	if err := decodeJSON(r, &body); err != nil {
		s.writeError(w, r, err)
		return
	}
	body.Address = strings.TrimSpace(body.Address)
	if body.Address == "" {
		s.writeError(w, r, badRequest("address is required, as host:port"))
		return
	}
	if _, _, err := net.SplitHostPort(body.Address); err != nil {
		s.writeError(w, r, badRequest("address %q must be host:port", body.Address))
		return
	}
	switch access.Protocol(strings.TrimSpace(body.Protocol)) {
	case access.AnyProtocol, access.TCP, access.UDP:
	default:
		s.writeError(w, r, badRequest("protocol %q must be tcp or udp", body.Protocol))
		return
	}

	// A refused destination is the answer rather than the request's failure, exactly as it
	// is for a probe: only a broken instance produces an error here.
	result, err := s.deps.Proxies.Test(r.Context(), r.PathValue("id"), body)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}
