// SPDX-License-Identifier: MIT

package config

// What one proxy instance is configurable by. A third table over a third entity, for the
// reason the connection table exists: these are per-instance values, and per-instance
// values in the global settings table would multiply the CLI flags, the tray menu and the
// generated schema by the number of instances.
//
// The permissions are deliberately not in here. A rule is a tuple matched in order, not a
// field with a value, so it gets a hand-written editor -- the same line the package doc
// draws between the two kinds of configurable thing.

import (
	"encoding/json"
	"net"
	"strconv"

	"github.com/sellitus/app-tail/internal/access"
)

// ProxyField is a field of one stored proxy instance.
type ProxyField = FieldOf[ProxyInstance]

// proxyFields is the authored table; its order is the display order.
//
// Five of these keys are the ones the settings document carried while there could be only
// one proxy. They keep their wire keys and their CLI names so a script that sets
// proxy-addr keeps setting the address of the instance that has always been there.
var proxyFields = []ProxyField{
	{
		JSONKey: "name", Kind: KindString,
		Restart: RestartNone, Write: WritePatch,
		Label: "Name", Group: GroupProxy, Tier: TierBasic,
		Example: "Browser",
		Help: "What this proxy is called on screen. Naming it after the program you point " +
			"at it is what makes a list of instances readable.",
		get:      func(p *ProxyInstance) any { return p.Name },
		set:      func(p *ProxyInstance, v any) { p.Name = typed[string](v) },
		validate: displayableName,
	},
	{
		JSONKey: "slug", Kind: KindString,
		Restart: RestartNone, Write: WritePatch,
		Label: "Short name", Group: GroupProxy, Tier: TierBasic,
		Example: "browser",
		Help: "The short handle this proxy is known by. It appears in the auto-configuration " +
			"address, so it has to be unique. Lowercase letters, digits and hyphens.",
		get:      func(p *ProxyInstance) any { return p.Slug },
		set:      func(p *ProxyInstance, v any) { p.Slug = typed[string](v) },
		validate: validateSlugValue,
	},
	{
		JSONKey: "enabled", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch,
		Label: "Run this proxy", Group: GroupProxy, Tier: TierBasic,
		Default: true,
		Help: "Whether this instance should be listening. Switching it off frees its port " +
			"and leaves its permissions in place, which is what to do when you want to stop " +
			"a program reaching your networks without forgetting how it was set up.",
		get: func(p *ProxyInstance) any { return p.Enabled },
		set: func(p *ProxyInstance, v any) { p.Enabled = typed[bool](v) },
	},
	{
		JSONKey: "proxy.listenAddr", CLIName: "proxy-addr", Kind: KindAddrPort,
		Restart: RestartNone, Write: WritePatch, Module: ModuleProxy,
		Label: "Proxy address", Group: GroupProxy, Tier: TierBasic,
		Example: DefaultProxyListenAddr,
		Default: DefaultProxyListenAddr,
		Help: "Loopback host:port this instance listens on. A loopback bind is the only " +
			"thing keeping it off the network, since a proxy has no credential by default. " +
			"Two instances cannot ask for the same port.",
		get:      func(p *ProxyInstance) any { return p.ListenAddr },
		set:      func(p *ProxyInstance, v any) { p.ListenAddr = typed[string](v) },
		validate: loopbackOnly,
	},
	{
		JSONKey: "proxy.scope", CLIName: "proxy-scope", Kind: KindEnum,
		Restart: RestartNone, Write: WriteNone, Derived: true, Module: ModuleProxy,
		Label: "What this proxy will reach", Group: GroupProxy, Tier: TierBasic,
		Options: proxyScopeOptions(),
		Deprecated: "how far a proxy dials is now the rules below, which can grant one port " +
			"on one connection instead of a whole network; this reads back what they amount to",
		Help: "A reading of the rules below: whether they carry one connection, also carry " +
			"what this machine reaches on its own, or say something the two old settings " +
			"could not.",
		derive: func(p ProxyInstance, _ *Settings) any { return string(DerivedProxyScope(p.Rules)) },
	},
	{
		JSONKey: "proxy.resolveVia", CLIName: "proxy-resolve-via", Kind: KindEnum,
		Restart: RestartNone, Write: WritePatch, Module: ModuleProxy,
		Label: "Resolve names with", Group: GroupProxy, Tier: TierAdvanced,
		Default: string(ResolveViaNetmap),
		Options: []EnumOption{
			{
				Value: string(ResolveViaNetmap), Label: "Device names, then this machine",
				Help: "Read tailnet device names out of the netmap and hand every other name " +
					"to this machine's resolver. One fewer question per connection.",
			},
			{
				Value: string(ResolveViaTailnet), Label: "The tailnet's DNS",
				Help: "Ask the tailnet's own resolver first, so a domain your admin console " +
					"points at a private nameserver resolves to its private address. Names the " +
					"tailnet does not serve fall back to the answer above.",
			},
		},
		Help: "Which resolver turns a name into an address. Only the tailnet's own knows " +
			"about a split-DNS domain, so a name that resolves everywhere except through " +
			"the proxy is what this setting is for.",
		get: func(p *ProxyInstance) any { return string(p.ResolveVia) },
		set: func(p *ProxyInstance, v any) { p.ResolveVia = ProxyResolveVia(typed[string](v)) },
	},
	{
		JSONKey: "proxy.requireToken", CLIName: "proxy-require-token", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, Module: ModuleProxy,
		Label: "Require a password", Group: GroupProxy, Tier: TierAdvanced,
		Help: "Make this instance demand the password below. A PAC file has nowhere to put a " +
			"password, so turning this on stops browsers configured by PAC from using it.",
		get: func(p *ProxyInstance) any { return p.RequireToken },
		set: func(p *ProxyInstance, v any) { p.RequireToken = typed[bool](v) },
	},
	{
		JSONKey: "proxy.token", ViewKey: "proxy.hasToken", CLIName: "proxy-token",
		Kind: KindSecret, Restart: RestartNone, Write: WritePatch, Module: ModuleProxy,
		Label: "Proxy password", Group: GroupProxy, Tier: TierAdvanced,
		Help: "The password this instance demands, with the username app-tail. " +
			"Write-only: a stored password is never sent back out.",
		get:     func(p *ProxyInstance) any { return p.Token },
		set:     func(p *ProxyInstance, v any) { p.Token = typed[string](v) },
		present: func(p *ProxyInstance) bool { return p.Token != "" },
	},
	{
		JSONKey: "proxy.dialTimeoutSec", CLIName: "proxy-dial-timeout", Kind: KindInt,
		Restart: RestartNone, Write: WritePatch, Module: ModuleProxy,
		Label: "Dial timeout (s)", Group: GroupProxy, Tier: TierAdvanced,
		Default: DefaultProxyDialTimeoutSec, Constraint: between(0, 600),
		Help: "How long one connection through this instance may take to establish. " +
			"A first connection to a sleeping device negotiates a path first, so this " +
			"is longer than a local dial would need. Zero uses the default.",
		get: func(p *ProxyInstance) any { return p.DialTimeoutSec },
		set: func(p *ProxyInstance, v any) { p.DialTimeoutSec = typed[int](v) },
	},
}

// ScopeCustom is the third thing the derived reading can report: rules that are neither
// preset, so the instance reaches what its own list says and no two-valued setting could
// have described it.
const ScopeCustom ProxyScope = "custom"

func proxyScopeOptions() []EnumOption {
	return []EnumOption{
		{
			Value: string(ScopeTailnet), Label: "One connection",
			Help: "Everything on one of your networks, and nothing this machine reaches on its own.",
		},
		{
			Value: string(ScopeAll), Label: "That connection and this machine",
			Help: "Also carry destinations that leave this machine normally, which is what a " +
				"browser pointed entirely at the proxy needs.",
		},
		{
			Value: string(ScopeCustom), Label: "Its own rules",
			Help: "Rules that grant something more particular than either of the above -- a " +
				"port, a host, a range of addresses.",
		},
	}
}

// DerivedProxyScope reads an ordered rule list back as one of the two reaches the old
// scope setting could describe, or as neither.
//
// It exists so a surface that used to render a two-valued picker has something true to
// render, and so an upgraded install can see at a glance that its proxy still reaches what
// it always did. Anything the two presets cannot express reads as custom rather than as
// the nearest of the two, because rounding a rule list to the nearest preset would tell
// somebody their narrow grant is a whole network.
func DerivedProxyScope(rules []access.Rule) ProxyScope {
	isWholeConnection := func(r access.Rule) bool {
		return r.Action == access.Allow && r.Tunnel != "" && r.Tunnel != access.ThisMachine &&
			r.Host == "" && !r.CIDR.IsValid() && len(r.Ports) == 0 && r.Protocol == access.AnyProtocol
	}
	isThisMachine := func(r access.Rule) bool {
		return r.Action == access.Allow && r.Tunnel == access.ThisMachine &&
			r.Host == "" && !r.CIDR.IsValid() && len(r.Ports) == 0 && r.Protocol == access.AnyProtocol
	}
	switch len(rules) {
	case 1:
		if isWholeConnection(rules[0]) {
			return ScopeTailnet
		}
	case 2:
		if isWholeConnection(rules[0]) && isThisMachine(rules[1]) {
			return ScopeAll
		}
	}
	return ScopeCustom
}

// proxyRegistry is the indexed table. There are no variants: every instance is the same
// kind of thing, so every field applies to every one.
var proxyRegistry = NewRegistry(proxyFields)

// NewProxyInstance builds an instance with every field at its declared default, which is
// what a freshly added one starts from. It is deliberately given no rules: an instance
// reaches nothing until somebody grants it something, and a default grant would make the
// least-configured instance the most powerful.
func NewProxyInstance(id, slug, name, listenAddr string) ProxyInstance {
	p := ProxyInstance{}
	proxyRegistry.Defaults(&p)
	p.ID, p.Slug, p.Name = id, slug, name
	if listenAddr != "" {
		p.ListenAddr = listenAddr
	}
	p.Rules = nil
	return p
}

// SuggestProxyListenAddr is the address a new instance should be offered: the next port
// above the default that no stored instance has asked for.
//
// It counts up from a fixed port rather than asking the OS for a free one because the
// address ends up in every snippet, browser setting and ssh_config the user saves. A port
// that moved between runs would break all of them; one that is stored the moment the
// instance is created never moves.
func SuggestProxyListenAddr(proxies []ProxyInstance) string {
	host, basePort, err := net.SplitHostPort(DefaultProxyListenAddr)
	if err != nil {
		return DefaultProxyListenAddr
	}
	base, err := strconv.Atoi(basePort)
	if err != nil {
		return DefaultProxyListenAddr
	}
	taken := make(map[string]bool, len(proxies))
	for _, p := range proxies {
		taken[p.ListenAddress()] = true
	}
	for port := base; port <= 65535; port++ {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		if !taken[addr] {
			return addr
		}
	}
	// Every port above the default is spoken for, which takes tens of thousands of
	// instances. Whichever is free is a worse answer than a stable one and a better one
	// than none.
	return net.JoinHostPort(host, "0")
}

// ProxySchema is the instance form's table, with availability resolved against this
// installation.
func ProxySchema(app *Settings) []FieldSchema { return proxyRegistry.SchemaFor(app) }

// ProxySchemaStatic is the same table with availability left unanswered, for the
// generator: a checked-in file cannot know the machine that will run it.
func ProxySchemaStatic() []FieldSchema { return proxyRegistry.Schema() }

// BuildProxyView is one instance as the API serves it, with the password reported as
// presence only.
func BuildProxyView(p ProxyInstance, app *Settings) map[string]any {
	return proxyRegistry.View(p, app)
}

// ApplyProxyPatch writes the fields a request carried onto an instance.
func ApplyProxyPatch(p *ProxyInstance, app *Settings, patch map[string]json.RawMessage) error {
	return proxyRegistry.ApplyPatch(p, app, patch)
}
