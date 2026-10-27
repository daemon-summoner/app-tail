// SPDX-License-Identifier: MIT

package config

// A proxy instance is one listener with its own permissions. This file holds what is
// stored about one; internal/tsproxy holds what a live one does, and internal/access
// decides what one carries.
//
// There is more than one because a permission model with a single listener has nothing to
// attach a permission to: every program on the machine would share one grant, and the
// narrowest grant anybody needs would have to be wide enough for the broadest program.
// One instance per program is what makes "this app reaches exactly this service" a thing
// the user can express.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sellitus/app-tail/internal/access"
)

// DefaultProxyID is the instance every install has: the proxy that existed while there
// could be only one, carried forward by the migration with the reach its settings gave it.
const DefaultProxyID = "px_default"

// DefaultProxySlug is that instance's handle, and the label in its socket path and its
// auto-configuration URL.
const DefaultProxySlug = "default"

// ProxyInstance is one stored proxy listener.
type ProxyInstance struct {
	// ID is opaque, stable across renames, and never reused, so a rule or a snippet that
	// names an instance keeps naming the same one.
	ID string `json:"id"`
	// Slug is the label this instance is known by. It is unique because it appears in a
	// path -- the auto-configuration URL and, where the platform has them, the local
	// socket -- and two instances answering for one path is two programs reaching each
	// other's grants.
	Slug string `json:"slug"`
	// Name is what a person calls it on screen. Not unique and carrying no other meaning.
	Name string `json:"name"`
	// Enabled is whether this instance should be listening. A disabled instance is a
	// configured one that is off, which is a state rather than a fault.
	Enabled bool `json:"enabled"`

	// ListenAddr is where this instance binds, loopback only. Two instances asking for
	// one address is refused at validation rather than resolved at bind: whichever bound
	// second would silently be the one nothing could reach.
	ListenAddr string `json:"listenAddr,omitempty"`
	// ResolveVia is which resolver turns a name into an address for this instance.
	ResolveVia ProxyResolveVia `json:"resolveVia,omitempty"`
	// RequireToken puts a credential on the listener, and Token is it -- write-only
	// across the API, like every other secret in the document.
	RequireToken bool   `json:"requireToken,omitempty"`
	Token        string `json:"token,omitempty"`
	// DialTimeoutSec bounds one dial through this instance. Zero inherits the default.
	DialTimeoutSec int `json:"dialTimeoutSec,omitempty"`

	// Rules are this instance's permissions, in order. The first one that matches decides
	// and anything no rule matches is refused, so the order is the meaning and an empty
	// list reaches nothing.
	Rules []access.Rule `json:"rules,omitempty"`
}

// NewProxyID returns a unique identifier for a new proxy instance.
func NewProxyID() (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate proxy id: %w", err)
	}
	return "px_" + hex.EncodeToString(b), nil
}

// NewRuleID returns a unique identifier for a new access rule.
func NewRuleID() (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate rule id: %w", err)
	}
	return "ar_" + hex.EncodeToString(b), nil
}

// Handle is what an error calls this instance: the slug the user chose, falling back to
// the id only for a document hand-edited to leave the slug empty.
func (p ProxyInstance) Handle() string {
	if p.Slug != "" {
		return p.Slug
	}
	return p.ID
}

// ListenAddress resolves where this instance binds. An unset address means the default
// rather than "every interface on a random port", which is the same reading the single
// proxy has always had.
func (p ProxyInstance) ListenAddress() string {
	if p.ListenAddr != "" {
		return p.ListenAddr
	}
	return DefaultProxyListenAddr
}

// DialTimeout resolves how long one dial through this instance may take.
func (p ProxyInstance) DialTimeout() time.Duration {
	if p.DialTimeoutSec > 0 {
		return time.Duration(p.DialTimeoutSec) * time.Second
	}
	return DefaultProxyDialTimeoutSec * time.Second
}

// EffectiveResolveVia resolves which resolver this instance turns names into addresses
// with. Anything but the explicit tailnet choice is the network map, which answers
// without a query leaving this machine.
func (p ProxyInstance) EffectiveResolveVia() ProxyResolveVia {
	if p.ResolveVia == ResolveViaTailnet {
		return ResolveViaTailnet
	}
	return ResolveViaNetmap
}

// Clone returns a copy that shares nothing with p, so a snapshot handed to a caller
// cannot be edited into the stored document through a slice.
func (p ProxyInstance) Clone() ProxyInstance {
	out := p
	out.Rules = CloneRules(p.Rules)
	return out
}

// CloneRules copies an ordered rule list deeply enough that neither the ports of one rule
// nor the order of the list can be changed through the copy.
func CloneRules(in []access.Rule) []access.Rule {
	if in == nil {
		return nil
	}
	out := make([]access.Rule, len(in))
	for i, r := range in {
		out[i] = r
		out[i].Ports = append([]string(nil), r.Ports...)
	}
	return out
}

// Proxy returns the stored instance with this id.
func (c *Config) Proxy(id string) (ProxyInstance, bool) {
	for _, p := range c.Proxies {
		if p.ID == id {
			return p, true
		}
	}
	return ProxyInstance{}, false
}

// ProxySlugsTaken is every slug an instance other than the one named already answers for,
// so a suggestion can avoid them and a rename can be checked against them.
func (c *Config) ProxySlugsTaken(exceptID string) map[string]bool {
	taken := make(map[string]bool, len(c.Proxies))
	for _, p := range c.Proxies {
		if p.ID != exceptID {
			taken[p.Slug] = true
		}
	}
	return taken
}

// defaultProxy is the instance a first run creates and the migration synthesizes, with
// the rules that give it the reach the old scope setting described.
func defaultProxy(enabled bool, listen string, rules []access.Rule) ProxyInstance {
	return ProxyInstance{
		ID:         DefaultProxyID,
		Slug:       DefaultProxySlug,
		Name:       "Default",
		Enabled:    enabled,
		ListenAddr: listen,
		Rules:      rules,
	}
}

// Rule ids the two preset grants are minted with. They are fixed rather than random
// because both a first run and a migration produce them, and a migration that ran twice
// under a different id would leave one instance holding the same grant twice.
const (
	ruleReachConnection  = "ar_connection"
	ruleReachThisMachine = "ar_this_machine"
)

// reachOneConnection is the grant that carries everything on one connection and nothing
// else. It is what the proxy's "tailnet only" scope always meant, written as a rule.
func reachOneConnection(tunnelID string) []access.Rule {
	return []access.Rule{{
		ID:     ruleReachConnection,
		Action: access.Allow,
		Tunnel: tunnelID,
		Note:   "Everything on this connection.",
	}}
}

// reachThisMachineToo adds the second half of the old "anything" scope: destinations that
// leave this machine normally. It is a separate rule rather than a wider one because the
// two grants are separately revocable, which is the whole reason the scope became a list.
func reachThisMachineToo(rules []access.Rule) []access.Rule {
	return append(rules, access.Rule{
		ID:     ruleReachThisMachine,
		Action: access.Allow,
		Tunnel: access.ThisMachine,
		Note:   "Anything this machine can reach on its own, including the public internet.",
	})
}

// validateProxies checks the instances as a set: the things that can only be wrong about
// one instance relative to another.
func validateProxies(c *Config) error {
	ids := make(map[string]bool, len(c.Proxies))
	slugs := make(map[string]bool, len(c.Proxies))
	// bound is which instance asked for each concrete address, so the second one to ask
	// is refused by name rather than at bind time, where it would simply not come up.
	bound := make(map[string]string, len(c.Proxies))

	for _, p := range c.Proxies {
		if err := validateProxy(c, p); err != nil {
			return err
		}
		if ids[p.ID] {
			return fmt.Errorf("two proxies are stored under the id %q", p.ID)
		}
		ids[p.ID] = true
		if slugs[p.Slug] {
			return fmt.Errorf("two proxies are called %q; the name appears in an address, so it has to be unique", p.Slug)
		}
		slugs[p.Slug] = true

		if !p.Enabled {
			continue
		}
		addr := p.ListenAddress()
		if _, port, err := net.SplitHostPort(addr); err == nil && port == "0" {
			// Asking for whichever port is free cannot conflict with anything: each such
			// instance lands somewhere else.
			continue
		}
		if other, taken := bound[addr]; taken {
			return fmt.Errorf("proxies %q and %q both listen on %s", other, p.Handle(), addr)
		}
		bound[addr] = p.Handle()
	}
	return nil
}

// validateProxy checks one instance on its own.
func validateProxy(c *Config, p ProxyInstance) error {
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("a proxy called %q has no id", p.Name)
	}
	if ok, why := ValidSlug(p.Slug); !ok {
		return fmt.Errorf("the proxy %q has a name that cannot appear in an address: it %s", p.Handle(), why)
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("the proxy %q has no name", p.Handle())
	}
	// The same rule the single proxy's address has always been held to, reached through
	// the same validator: a proxy on a reachable interface is every private network this
	// app holds, offered to whoever can reach the machine.
	if err := loopbackOnly(p.ListenAddress()); err != nil {
		return fmt.Errorf("the proxy %q listens somewhere it must not: %w", p.Handle(), err)
	}
	switch p.ResolveVia {
	case "", ResolveViaNetmap, ResolveViaTailnet:
	default:
		return fmt.Errorf("the proxy %q resolves via %q, which is not a resolver this app has", p.Handle(), p.ResolveVia)
	}
	if p.RequireToken && strings.TrimSpace(p.Token) == "" {
		return fmt.Errorf("the proxy %q requires a password but none is stored; set one or turn the requirement off", p.Handle())
	}
	if p.DialTimeoutSec < 0 {
		return fmt.Errorf("the proxy %q has a negative dial timeout", p.Handle())
	}
	if err := access.ValidateRules(p.Rules); err != nil {
		return fmt.Errorf("the proxy %q: %w", p.Handle(), err)
	}
	// A rule naming a connection that is not in the document is a grant that will never
	// match. Refusing it here is what keeps a renamed or deleted connection from silently
	// turning a permission into a no-op.
	for i, r := range p.Rules {
		if r.Tunnel == "" || r.Tunnel == access.ThisMachine {
			continue
		}
		if _, exists := c.Tunnel(r.Tunnel); !exists {
			return fmt.Errorf("the proxy %q: rule %d names the connection %q, which is not configured", p.Handle(), i+1, r.Tunnel)
		}
	}
	return nil
}
