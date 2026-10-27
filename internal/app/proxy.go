// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
	"github.com/sellitus/app-tail/internal/tsproxy"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// probeTimeout bounds one dial made on a dashboard user's behalf. It is deliberately
// shorter than a proxy's own dial timeout: a probe is a question someone is watching the
// answer to, and a spinner that runs for half a minute answers nothing.
const probeTimeout = 10 * time.Second

// proxyAPI is the management API's view of the proxy. It answers for the default instance,
// which is the one the single-proxy surfaces -- /api/proxy, the tray, app-tail proxy status
// -- have always meant.
type proxyAPI struct{ a *Agent }

var _ httpapi.Proxy = proxyAPI{}

// Proxy reports the proxy surface, or nil when this agent has no proxies yet.
func (a *Agent) Proxy() httpapi.Proxy {
	if a.currentProxies() == nil {
		// A typed nil inside a non-nil interface would defeat the caller's nil check.
		return nil
	}
	return proxyAPI{a: a}
}

// defaultInstance is the running instance the single-proxy surfaces speak for.
func (p proxyAPI) defaultInstance() (*tsproxy.Instance, bool) {
	set := p.a.currentProxies()
	if set == nil {
		return nil, false
	}
	return set.Get(config.DefaultProxyID)
}

func (p proxyAPI) Status() tsproxy.Status {
	inst, ok := p.defaultInstance()
	if !ok {
		// Not running is a state rather than a fault: the module may be off, the instance
		// may be switched off, or it may have been removed. Its stored form still names it,
		// which is what keeps the page showing an off switch instead of an empty panel.
		cfg := p.a.store.Get()
		held, exists := cfg.Proxy(config.DefaultProxyID)
		if !exists {
			return tsproxy.Status{}
		}
		return tsproxy.Status{
			ID:   held.ID,
			Slug: held.Handle(),
			Name: held.Name,
			// The module switch gates every instance, so an instance switched on inside a
			// module that is off is off. Reporting the instance's own switch alone would
			// read as "on but could not bind" everywhere this status is shown.
			Enabled:        held.Enabled && cfg.Settings.ProxyEnabled,
			ModuleOn:       cfg.Settings.ProxyEnabled,
			Scope:          config.DerivedProxyScope(held.Rules),
			ResolveVia:     held.EffectiveResolveVia(),
			Rules:          len(held.Rules),
			ConfiguredAddr: held.ListenAddress(),
		}
	}
	return inst.Status()
}

// PAC renders the auto-config script from the tailnet's current state.
//
// Every input is live. A script built from constants would send the wrong traffic on any
// tailnet but the one it was written for: the name domain, the address ranges and the
// routes reachable through subnet routers all differ per tailnet, and the last of those
// changes while the app is running.
func (p proxyAPI) PAC(ctx context.Context) (string, error) {
	if p.a.currentProxies() == nil {
		return tsproxy.PAC(tsproxy.PACConfig{Reason: "the proxy is not part of this agent"}), nil
	}

	// Read through Status rather than off a running instance: a browser keeps fetching this
	// script after the module is switched off, and the script has to say so rather than
	// claim the proxy was never here.
	st := p.Status()
	if st.Listening == "" {
		reason := st.Error
		if reason == "" {
			reason = "the app-tail proxy is switched off"
		}
		return tsproxy.PAC(tsproxy.PACConfig{Reason: reason}), nil
	}
	if st.RequiresToken {
		// A PAC result line has nowhere to put a credential, so a script naming the proxy
		// would make every request fail authentication. Sending traffic direct is the
		// honest outcome, and the comment is where the user finds out why.
		return tsproxy.PAC(tsproxy.PACConfig{
			Reason: "the proxy requires a password, which a proxy auto-config file cannot carry",
		}), nil
	}

	node := p.a.currentNode()
	if node == nil {
		return tsproxy.PAC(tsproxy.PACConfig{Reason: "the tailnet node is not running"}), nil
	}

	// Routes reach the control plane, so a caller that went away must not leave this
	// waiting -- but a failure here is not a reason to serve a broken script.
	routes, err := node.Routes(ctx)
	if err != nil {
		return "", fmt.Errorf("read the routes this tailnet reaches: %w", err)
	}

	// The connections' own name suffixes, so a browser pointed at this script sends a name
	// on a private network to the proxy. Sent direct it would reach nothing: no resolver
	// outside this process answers one.
	suffixes := tunnelSuffixesOf(p.a.runtimeTunnels(), p.a.settings())
	names := make([]string, 0, len(suffixes))
	for _, s := range suffixes {
		names = append(names, s.Suffix)
	}

	status := node.Status()
	return tsproxy.PAC(tsproxy.PACConfig{
		ProxyAddr:      st.Listening,
		MagicDNSSuffix: status.MagicDNSSuffix,
		Ranges:         tsnode.TailnetRanges(),
		Routes:         routes,
		ExitNode:       status.ExitNodeActive,
		TunnelSuffixes: names,
	}), nil
}

// Probe dials one destination the way a client of the proxy would, and reports what
// happened rather than failing. "Is the proxy up" and "can it reach that peer" are
// different questions, and a refusal is a legitimate answer to the second.
func (p proxyAPI) Probe(ctx context.Context, address string) (httpapi.ProxyProbeResult, error) {
	inst, ok := p.defaultInstance()
	if !ok {
		return httpapi.ProxyProbeResult{}, httpapi.Unavailable("proxy", "not wired into this agent")
	}

	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	result := httpapi.ProxyProbeResult{Address: address}
	started := time.Now()
	defer func() { result.ElapsedMs = time.Since(started).Milliseconds() }()

	// The rules decide first, and a destination they refuse is never dialed. Without this
	// the endpoint is "open a connection from this agent to anywhere it can reach" -- every
	// tailnet peer, every network a connection carries, every address on this machine's own
	// LAN -- for any caller that reaches the API, which is a wider reach than the proxy the
	// endpoint reports on has. The refusal is the answer, in the sentence a real dial
	// through the proxy would have refused with.
	verdict := inst.Would(ctx, "tcp", address)
	result.ResolvedAddr = verdict.Resolved
	if !verdict.Allowed {
		result.Error = verdict.Reason
		result.Refused = true
		result.ElapsedMs = time.Since(started).Milliseconds()
		return result, nil
	}

	route, err := p.a.tunnels.Resolve(ctx, "tcp", address)
	if err != nil {
		result.Error = err.Error()
		result.ElapsedMs = time.Since(started).Milliseconds()
		return result, nil
	}
	result.ViaTailnet = !route.Direct()
	result.ResolvedAddr = route.Addr.String()

	conn, err := p.a.dialRoute(ctx, "tcp", route)
	if err != nil {
		result.Error = err.Error()
		result.ElapsedMs = time.Since(started).Milliseconds()
		return result, nil
	}
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		p.a.logger.Debug("closing a probe connection failed", "address", address, "error", err)
	}

	result.Reachable = true
	result.ElapsedMs = time.Since(started).Milliseconds()
	return result, nil
}

// dialRoute opens the connection a resolved route decided on: through the connection
// carrying it, through the one this machine's internet traffic leaves by, or out of this
// machine when neither applies.
//
// Via rather than the connection carrying the destination, because the probe answers "would
// the proxy reach this" and the proxy dials by the same rule. A probe that went out over
// this machine's own network would report on a path nothing else uses -- and where internet
// traffic is held, it would report reachable a destination every real request refuses.
func (a *Agent) dialRoute(ctx context.Context, network string, route tunnel.Route) (net.Conn, error) {
	via := route.Via()
	if via == nil {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, route.Addr.String())
	}
	return via.Dial(ctx, network, route.Addr.String())
}

// defaultProxyStatus is the default instance as every single-proxy surface reports it.
func (a *Agent) defaultProxyStatus() tsproxy.Status { return proxyAPI{a: a}.Status() }

func (a *Agent) currentProxies() *tsproxy.Set {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.proxies
}

// anyTunnelUp reports whether any connection is currently carrying traffic. It is what the
// proxies report as their own availability: with several networks, "the tailnet is signed
// out" says nothing about a proxy whose rules name a WireGuard peer.
func (a *Agent) anyTunnelUp() bool {
	for _, t := range a.tunnels.All() {
		if t.Status().State == tunnel.StateConnected || t.Status().State == tunnel.StateDegraded {
			return true
		}
	}
	return false
}

// applyProxies reconciles every proxy instance with the stored configuration and the
// connections' state, and records a bind that landed somewhere other than where it was
// asked to.
//
// A bind failure is logged rather than propagated: it must not stop forwards from being
// reconciled, and the reason is already published through the instance's own status where
// the dashboard shows it.
func (a *Agent) applyProxies(networksUp bool) {
	set := a.currentProxies()
	if set == nil {
		return
	}
	set.SetNetworksUp(networksUp)

	cfg := a.store.Get()
	// The module switch is a fact about the installation, so it gates every instance: with
	// the proxy module off, nothing binds however many instances are declared.
	want := cfg.Proxies
	if !cfg.Settings.ProxyEnabled {
		want = nil
	}
	if err := set.Apply(want); err != nil {
		a.logger.Warn("a proxy could not be reconciled", "error", err)
	}
	for _, st := range set.Statuses() {
		if err := a.persistProxyAddr(st); err != nil {
			a.logger.Warn("recording a proxy's bound address failed", "proxy", st.Slug, "error", err)
		}
	}
	// After the addresses are persisted, so the auto-config URL names where the listener
	// actually landed rather than where it was asked to.
	a.applySystemProxy(a.defaultProxyStatus())
}

// persistProxyAddr stores where an instance actually landed after a port conflict moved
// it. Every snippet, browser setting and shell profile a user has already saved names the
// old port, so writing the bound address back means the move happens once rather than on
// every restart.
//
// It keys off MovedFromConfig rather than comparing addresses itself, because a configured
// port of zero asks for any free port: persisting that would rewrite the configuration on
// every reconcile and rebind the listener under live connections.
func (a *Agent) persistProxyAddr(st tsproxy.Status) error {
	if !st.MovedFromConfig || st.Listening == "" {
		return nil
	}
	if held, ok := a.store.Get().Proxy(st.ID); ok && held.ListenAddr == st.Listening {
		return nil
	}
	if _, err := a.store.Update(func(c *config.Config) error {
		for i := range c.Proxies {
			if c.Proxies[i].ID == st.ID {
				c.Proxies[i].ListenAddr = st.Listening
				return nil
			}
		}
		return fmt.Errorf("proxy %s is no longer configured", st.ID)
	}); err != nil {
		return fmt.Errorf("persist the bound proxy address: %w", err)
	}
	return nil
}
