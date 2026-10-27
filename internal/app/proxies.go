// SPDX-License-Identifier: MIT

package app

// The proxy instances module: what the stored document says about each listener, merged
// with what the running one is doing.
//
// The two halves come from two places for the reason the connections module keeps them
// apart: permissions are in the store, so they survive a restart and an instance that never
// bound; liveness is in the running set, so an instance that is configured and down reports
// as configured and down rather than as missing.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sellitus/app-tail/internal/access"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsproxy"
)

// proxiesAPI presents the instance list to the management API.
type proxiesAPI struct{ a *Agent }

var _ httpapi.Proxies = proxiesAPI{}

// ProxiesAPI exposes the instance list.
func (a *Agent) ProxiesAPI() httpapi.Proxies { return proxiesAPI{a: a} }

// List returns every stored instance, in the order the document holds them, which is the
// order every surface lists them in.
func (p proxiesAPI) List() []httpapi.ProxyInstanceView {
	cfg := p.a.store.Get()
	app := p.a.settings()
	out := make([]httpapi.ProxyInstanceView, 0, len(cfg.Proxies))
	for _, held := range cfg.Proxies {
		out = append(out, p.view(cfg, held, &app))
	}
	return out
}

func (p proxiesAPI) Get(id string) (httpapi.ProxyInstanceView, error) {
	cfg := p.a.store.Get()
	held, ok := cfg.Proxy(id)
	if !ok {
		return httpapi.ProxyInstanceView{}, fmt.Errorf("proxy %q: %w", id, config.ErrNotFound)
	}
	app := p.a.settings()
	return p.view(cfg, held, &app), nil
}

func (p proxiesAPI) Schema() []config.FieldSchema {
	s := p.a.settings()
	return p.a.fillOptions(config.ProxySchema(&s))
}

// Create adds an instance. It is stored first and bound by the reconcile that follows,
// which is the order every other module comes up in.
func (p proxiesAPI) Create(ctx context.Context, spec httpapi.ProxyInstanceSpec) (httpapi.ProxyInstanceView, error) {
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		return httpapi.ProxyInstanceView{}, &config.ValidationError{
			Field:   "name",
			Message: "give this proxy a name; it is what the program you point at it is listed under",
		}
	}
	id, err := config.NewProxyID()
	if err != nil {
		return httpapi.ProxyInstanceView{}, err
	}

	if _, err := p.a.store.Update(func(c *config.Config) error {
		slug := strings.TrimSpace(spec.Slug)
		if slug == "" {
			slug = config.SuggestSlug(name, c.ProxySlugsTaken(id))
		}
		listen := strings.TrimSpace(spec.ListenAddr)
		if listen == "" {
			// A port of its own rather than the default one, which the instance every
			// install has is already listening on: two instances asking for one address is
			// refused, and a form that produced a refusal by default would be a form nobody
			// can submit.
			listen = config.SuggestProxyListenAddr(c.Proxies)
		}
		c.Proxies = append(c.Proxies, config.NewProxyInstance(id, slug, name, listen))
		return nil
	}); err != nil {
		return httpapi.ProxyInstanceView{}, err
	}

	p.adopt(ctx)
	return p.Get(id)
}

// Update applies a patch to one instance. The whole document is validated by the store, so
// a rename onto a handle another instance answers for, or a move onto a port another one
// asked for, is refused here rather than discovered at bind time by whichever listener came
// up second.
func (p proxiesAPI) Update(ctx context.Context, id string, patch map[string]json.RawMessage) (httpapi.ProxyInstanceView, error) {
	app := p.a.settings()
	if _, err := p.a.store.Update(func(c *config.Config) error {
		for i := range c.Proxies {
			if c.Proxies[i].ID != id {
				continue
			}
			return config.ApplyProxyPatch(&c.Proxies[i], &app, patch)
		}
		return fmt.Errorf("proxy %q: %w", id, config.ErrNotFound)
	}); err != nil {
		return httpapi.ProxyInstanceView{}, err
	}
	p.adopt(ctx)
	return p.Get(id)
}

// SetRules replaces one instance's whole ordered rule list.
//
// A rule with no id is minted one here rather than refused: the id exists so a decision can
// name the line that made it, which is bookkeeping the person adding a grant should not have
// to do. Everything else about the list -- what a rule may say, that two rules cannot share
// an id, that every connection it names is configured -- is the document's own rule and is
// checked by the store.
func (p proxiesAPI) SetRules(ctx context.Context, id string, rules []access.Rule) (httpapi.ProxyInstanceView, error) {
	minted := make([]access.Rule, len(rules))
	for i, r := range rules {
		if strings.TrimSpace(r.ID) == "" {
			newID, err := config.NewRuleID()
			if err != nil {
				return httpapi.ProxyInstanceView{}, err
			}
			r.ID = newID
		}
		minted[i] = r
	}

	if _, err := p.a.store.Update(func(c *config.Config) error {
		for i := range c.Proxies {
			if c.Proxies[i].ID != id {
				continue
			}
			c.Proxies[i].Rules = config.CloneRules(minted)
			return nil
		}
		return fmt.Errorf("proxy %q: %w", id, config.ErrNotFound)
	}); err != nil {
		return httpapi.ProxyInstanceView{}, err
	}
	p.adopt(ctx)
	return p.Get(id)
}

// Delete removes an instance and, through the reconcile it ends with, stops it.
func (p proxiesAPI) Delete(ctx context.Context, id string) error {
	// Refused before the store is touched, because the refusal is about what this instance
	// is rather than about the document: every settings key that named the one proxy writes
	// here, and a document without it refuses those inputs with nowhere to put them.
	if id == config.DefaultProxyID {
		return &config.ValidationError{
			Field: "id",
			Message: "the default proxy cannot be removed: it is where this installation's " +
				"own proxy settings are applied. Switch it off instead to stop it.",
		}
	}
	if _, err := p.a.store.Update(func(c *config.Config) error {
		for i, held := range c.Proxies {
			if held.ID != id {
				continue
			}
			c.Proxies = append(c.Proxies[:i], c.Proxies[i+1:]...)
			return nil
		}
		return fmt.Errorf("proxy %q: %w", id, config.ErrNotFound)
	}); err != nil {
		return err
	}

	p.adopt(ctx)
	return nil
}

// Test answers what one instance would do with a destination, without dialling it.
//
// It goes through the running set even for an instance that is not listening, because that
// is where the connections and their resolvers are: the answer has to be decided by the same
// resolver, the same rule list and the same matcher a real connection would be, or it is a
// second opinion rather than a test.
func (p proxiesAPI) Test(ctx context.Context, id string, req httpapi.ProxyTestRequest) (httpapi.ProxyTestResult, error) {
	held, ok := p.a.store.Get().Proxy(id)
	if !ok {
		return httpapi.ProxyTestResult{}, fmt.Errorf("proxy %q: %w", id, config.ErrNotFound)
	}
	set := p.a.currentProxies()
	if set == nil {
		return httpapi.ProxyTestResult{}, httpapi.Unavailable("proxies", "not wired into this agent")
	}

	network := "tcp"
	if access.Protocol(strings.TrimSpace(req.Protocol)) == access.UDP {
		network = "udp"
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	verdict := set.Would(ctx, tsproxy.ConfigOf(held), network, req.Address)
	out := httpapi.ProxyTestResult{
		Address:  verdict.Address,
		Allowed:  verdict.Allowed,
		Resolved: verdict.Resolved,
		Tunnel:   verdict.TunnelID,
		Rule:     verdict.Rule,
		Reason:   verdict.Reason,
	}
	if verdict.Index >= 0 {
		// One-based, so it names the row as the rules table numbers it.
		out.RuleIndex = verdict.Index + 1
	}
	if verdict.TunnelID != "" {
		out.TunnelName = p.a.connectionName(verdict.TunnelID)
	}
	if verdict.EgressID != "" {
		out.Egress = p.a.connectionName(verdict.EgressID)
	}
	return out, nil
}

// view is one stored instance merged with what the running one is doing.
func (p proxiesAPI) view(cfg *config.Config, held config.ProxyInstance, app *config.Settings) httpapi.ProxyInstanceView {
	// The module switch gates every instance, so an instance switched on inside a module
	// that is off is off -- the same reading the single-proxy status reports.
	enabled := held.Enabled && app.ProxyEnabled

	st := tsproxy.Status{
		ID:             held.ID,
		Slug:           held.Handle(),
		Name:           held.Name,
		Enabled:        enabled,
		ModuleOn:       app.ProxyEnabled,
		Scope:          config.DerivedProxyScope(held.Rules),
		ResolveVia:     held.EffectiveResolveVia(),
		RequiresToken:  held.RequireToken,
		Rules:          len(held.Rules),
		ConfiguredAddr: held.ListenAddress(),
	}
	if set := p.a.currentProxies(); set != nil {
		if inst, running := set.Get(held.ID); running {
			st = inst.Status()
			st.Enabled = enabled
			st.ModuleOn = app.ProxyEnabled
		}
	}

	snippets := tsproxy.SnippetConfig{ProxyAddr: st.Listening, RequiresPassword: st.RequiresToken}
	view := httpapi.ProxyInstanceView{
		ID:      held.ID,
		Name:    held.Name,
		Slug:    held.Handle(),
		Enabled: enabled,
		// Every instance but the one the settings keys write to may be removed, and that
		// same one is what the command line and the auto-configuration route reach when
		// nothing names an instance.
		Default:          held.ID == config.DefaultProxyID,
		Removable:        held.ID != config.DefaultProxyID,
		Settings:         config.BuildProxyView(held, app),
		Rules:            config.CloneRules(held.Rules),
		Reach:            reachSentences(cfg, held.Rules),
		Listening:        st.Listening,
		LocalSocket:      st.LocalSocket,
		ConfiguredAddr:   st.ConfiguredAddr,
		MovedFromConfig:  st.MovedFromConfig,
		RequiresPassword: st.RequiresToken,
		Error:            st.Error,
		SocksURL:         tsproxy.SOCKSURL(snippets),
		HTTPURL:          tsproxy.HTTPURL(snippets),
		Counters:         st.Counters,
		Capability:       httpapi.ProxyCapabilityOf(st),
	}
	if view.Rules == nil {
		view.Rules = []access.Rule{}
	}
	return view
}

// reachSentences is what an instance's rules amount to, one sentence per rule, with every
// connection named as a person calls it.
//
// An empty list gets a sentence of its own rather than nothing: an instance with no rules
// reaches nothing, and a blank space where a grant list goes reads as a page that failed to
// load rather than as a listener that carries nothing.
func reachSentences(cfg *config.Config, rules []access.Rule) []string {
	if len(rules) == 0 {
		return []string{"nothing: this proxy has no rules, and it carries only what a rule allows"}
	}
	name := func(id string) string {
		if held, ok := cfg.Tunnel(id); ok {
			return held.Name
		}
		return ""
	}
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		sentence := r.DescribeWith(name)
		if note := strings.TrimSpace(r.Note); note != "" {
			sentence += " -- " + note
		}
		out = append(out, sentence)
	}
	return out
}

// connectionName is one connection as a person calls it, for a result that would otherwise
// show a bare id. A route nothing carries is this machine's own network, which has no
// connection to name.
func (a *Agent) connectionName(id string) string {
	if id == access.ThisMachine {
		return "this machine's own network"
	}
	if held, ok := a.store.Get().Tunnel(id); ok {
		return held.Name
	}
	return id
}

// adopt republishes what this process runs on and waits for the engine to act on it, so a
// caller that just wrote an instance is answered with what is running rather than with what
// was about to be bound.
func (p proxiesAPI) adopt(ctx context.Context) {
	if _, err := p.a.adoptSettings(); err != nil {
		// The write already succeeded and the document is valid -- Store.Update validated it
		// -- so this is the precedence chain failing on a document it just accepted. Reported
		// rather than returned: the instance exists, and telling the caller its creation
		// failed would leave them deleting something that is already there.
		p.a.logger.Error("could not re-read the proxies after writing one", "error", err)
	}
	p.a.reconcileNow(ctx)
}
