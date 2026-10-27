// SPDX-License-Identifier: MIT

package config

import (
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/access"
)

// withProxies returns a default document carrying exactly these instances, so a case only
// has to say what is wrong with the one it is about.
func withProxies(p ...ProxyInstance) *Config {
	cfg := Defaults()
	cfg.Proxies = p
	return cfg
}

func validProxy() ProxyInstance {
	return ProxyInstance{
		ID:         "px_aaaaaa",
		Slug:       "psql",
		Name:       "psql",
		Enabled:    true,
		ListenAddr: "127.0.0.1:1081",
		Rules:      reachOneConnection(PrimaryTunnelID),
	}
}

func TestADocumentRefusesAProxyItCouldNotServe(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ProxyInstance)
		says   string
	}{
		{"no id", func(p *ProxyInstance) { p.ID = " " }, "has no id"},
		{"no name", func(p *ProxyInstance) { p.Name = "  " }, "has no name"},
		{"a slug that is not a label", func(p *ProxyInstance) { p.Slug = "Not A Label" }, "cannot appear in an address"},
		{"listening off the loopback", func(p *ProxyInstance) { p.ListenAddr = "0.0.0.0:1081" }, "listens somewhere it must not"},
		{"a resolver this app does not have", func(p *ProxyInstance) { p.ResolveVia = "carrier-pigeon" }, "not a resolver"},
		// The listener would either bind with no credential at all or refuse to bind: both
		// readings are wrong for a switch the user turned on, so the document refuses first.
		{"a password required with none stored",
			func(p *ProxyInstance) { p.RequireToken = true; p.Token = "  " }, "requires a password but none is stored"},
		{"a negative dial timeout", func(p *ProxyInstance) { p.DialTimeoutSec = -1 }, "negative dial timeout"},
		{"a rule with no action",
			func(p *ProxyInstance) { p.Rules = []access.Rule{{ID: "ar_x", Tunnel: PrimaryTunnelID}} },
			"whether it allows or refuses"},
		{"a rule naming a connection that is not configured",
			func(p *ProxyInstance) {
				p.Rules = []access.Rule{{ID: "ar_x", Action: access.Allow, Tunnel: "tn_gone"}}
			}, `names the connection "tn_gone"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := validProxy()
			tc.mutate(&p)

			err := withProxies(p).Validate()
			if err == nil {
				t.Fatalf("the document accepted %+v", p)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("error = %q, want it to say %q", err, tc.says)
			}
		})
	}
}

// The rules are the permissions, so a document that quietly dropped one would widen or
// narrow a grant with nothing on screen saying so. Every shape that is legal has to stay
// legal, or the editor cannot save what it just rendered.
func TestADocumentAcceptsTheProxyShapesTheEditorCanProduce(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ProxyInstance)
	}{
		{"the shape a first run creates", func(*ProxyInstance) {}},
		{"switched off", func(p *ProxyInstance) { p.Enabled = false }},
		{"no address, meaning the default one", func(p *ProxyInstance) { p.ListenAddr = "" }},
		{"whichever port is free", func(p *ProxyInstance) { p.ListenAddr = "127.0.0.1:0" }},
		{"a password with one stored", func(p *ProxyInstance) { p.RequireToken = true; p.Token = "hunter2" }},
		{"resolving through the tailnet", func(p *ProxyInstance) { p.ResolveVia = ResolveViaTailnet }},
		{"no rules at all, reaching nothing", func(p *ProxyInstance) { p.Rules = nil }},
		{"a grant for this machine, which is no connection",
			func(p *ProxyInstance) { p.Rules = reachThisMachineToo(reachOneConnection(PrimaryTunnelID)) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := validProxy()
			tc.mutate(&p)

			if err := withProxies(p).Validate(); err != nil {
				t.Fatalf("the document refused %+v: %v", p, err)
			}
		})
	}
}

// Both halves of an instance's identity appear in a path -- the auto-configuration URL and
// the local socket -- so a duplicate is two programs answering for one grant.
func TestTwoProxiesCannotShareAnIdentity(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ProxyInstance)
		says   string
	}{
		{"the same id", func(p *ProxyInstance) { p.Slug = "second" }, "under the id"},
		{"the same slug", func(p *ProxyInstance) { p.ID = "px_bbbbbb" }, "has to be unique"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			second := validProxy()
			second.ListenAddr = "127.0.0.1:1082"
			tc.mutate(&second)

			err := withProxies(validProxy(), second).Validate()
			if err == nil {
				t.Fatal("the document accepted two instances with one identity")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("error = %q, want it to say %q", err, tc.says)
			}
		})
	}
}

// Whichever instance bound second would simply not come up, and the one program pointed at
// that port would reach the other instance's grants instead.
func TestTwoProxiesCannotAskForOneAddress(t *testing.T) {
	second := validProxy()
	second.ID = "px_bbbbbb"
	second.Slug = "browser"

	err := withProxies(validProxy(), second).Validate()
	if err == nil {
		t.Fatal("two instances were accepted on one address")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1081") {
		t.Errorf("error = %q, want it to name the contested address", err)
	}
}

// An instance that is off binds nothing, and one asking for whichever port is free lands
// somewhere of its own -- neither can contend for an address, and refusing them would stop
// a user parking a second instance on the port they are about to move to.
func TestAddressesOnlyContendWhereTwoInstancesWouldBothBindThem(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ProxyInstance)
	}{
		{"the second one is off", func(p *ProxyInstance) { p.Enabled = false }},
		{"both ask for whichever port is free", func(p *ProxyInstance) { p.ListenAddr = "127.0.0.1:0" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			first, second := validProxy(), validProxy()
			second.ID = "px_bbbbbb"
			second.Slug = "browser"
			tc.mutate(&first)
			tc.mutate(&second)

			if err := withProxies(first, second).Validate(); err != nil {
				t.Fatalf("the document refused two instances that cannot contend: %v", err)
			}
		})
	}
}

// A snapshot is handed out by value, and a rule list is a slice: without the deep copy a
// caller could reorder another instance's permissions -- and order is what decides.
func TestASnapshotOfAnInstanceCannotBeEditedIntoTheStoredOne(t *testing.T) {
	p := validProxy()
	p.Rules = reachThisMachineToo(reachOneConnection(PrimaryTunnelID))
	p.Rules[0].Ports = []string{"5432"}

	clone := p.Clone()
	clone.Rules[0].Tunnel = "tn_somewhere-else"
	clone.Rules[0].Ports[0] = "22"
	clone.Rules[1].Action = access.Deny

	if p.Rules[0].Tunnel != PrimaryTunnelID {
		t.Errorf("the stored rule now names %q", p.Rules[0].Tunnel)
	}
	if p.Rules[0].Ports[0] != "5432" {
		t.Errorf("the stored rule now carries port %q", p.Rules[0].Ports[0])
	}
	if p.Rules[1].Action != access.Allow {
		t.Errorf("the stored rule is now %q", p.Rules[1].Action)
	}
}

func TestCloningNoRulesKeepsThemAbsentRatherThanEmpty(t *testing.T) {
	p := validProxy()
	p.Rules = nil
	if got := p.Clone().Rules; got != nil {
		t.Errorf("Rules = %v, want them still absent", got)
	}
}

// Every one of these is read on a path where the stored value may be unset, and each has a
// different reading of "unset" -- the defaults are the meaning, not a convenience.
func TestAnUnsetFieldReadsAsTheInstanceDefaultRatherThanZero(t *testing.T) {
	empty := ProxyInstance{ID: "px_aaaaaa"}

	if got := empty.ListenAddress(); got != DefaultProxyListenAddr {
		t.Errorf("ListenAddress = %q, want %q", got, DefaultProxyListenAddr)
	}
	if got, want := empty.DialTimeout(), DefaultProxyDialTimeoutSec; int(got.Seconds()) != want {
		t.Errorf("DialTimeout = %s, want %ds", got, want)
	}
	if got := empty.EffectiveResolveVia(); got != ResolveViaNetmap {
		t.Errorf("EffectiveResolveVia = %q, want %q", got, ResolveViaNetmap)
	}
	// The id is what an error falls back to, because a hand-edited document can leave the
	// slug empty and an error naming nothing is an error nobody can act on.
	if got := empty.Handle(); got != "px_aaaaaa" {
		t.Errorf("Handle = %q, want the id", got)
	}
}

func TestTheTailnetResolverIsTheOnlyOneThatIsNotTheNetworkMap(t *testing.T) {
	p := validProxy()
	p.ResolveVia = ResolveViaTailnet
	if got := p.EffectiveResolveVia(); got != ResolveViaTailnet {
		t.Errorf("EffectiveResolveVia = %q, want %q", got, ResolveViaTailnet)
	}
}

// A suggestion has to avoid every name another instance answers for, and must not avoid the
// one the instance being renamed already holds -- otherwise renaming it to itself is refused.
func TestTheNamesAlreadyTakenExcludeTheInstanceBeingRenamed(t *testing.T) {
	second := validProxy()
	second.ID = "px_bbbbbb"
	second.Slug = "browser"
	cfg := withProxies(validProxy(), second)

	taken := cfg.ProxySlugsTaken("px_aaaaaa")
	if taken["psql"] {
		t.Error("an instance's own name is held against it")
	}
	if !taken["browser"] {
		t.Error("another instance's name is not taken")
	}
}

func TestAnInstanceIsFoundByTheIDThatNamesIt(t *testing.T) {
	cfg := withProxies(validProxy())

	got, ok := cfg.Proxy("px_aaaaaa")
	if !ok {
		t.Fatal("the stored instance was not found by its id")
	}
	if got.Slug != "psql" {
		t.Errorf("slug = %q, want psql", got.Slug)
	}
	if _, ok := cfg.Proxy("px_gone"); ok {
		t.Error("an id nothing is stored under was found")
	}
}

// Both a first run and a migration mint the preset grants, so the ids have to be fixed:
// under random ids a migrated install would end up holding the same grant twice.
func TestThePresetGrantsAreMintedUnderFixedIDs(t *testing.T) {
	rules := reachThisMachineToo(reachOneConnection(PrimaryTunnelID))
	if len(rules) != 2 {
		t.Fatalf("the two preset grants produced %d rules", len(rules))
	}
	if rules[0].ID != ruleReachConnection || rules[1].ID != ruleReachThisMachine {
		t.Errorf("rule ids are %q and %q", rules[0].ID, rules[1].ID)
	}
	if rules[0].Tunnel != PrimaryTunnelID {
		t.Errorf("the connection grant names %q", rules[0].Tunnel)
	}
	if rules[1].Tunnel != access.ThisMachine {
		t.Errorf("the this-machine grant names %q", rules[1].Tunnel)
	}
	for i, r := range rules {
		if r.Action != access.Allow {
			t.Errorf("preset rule %d is %q", i, r.Action)
		}
		if r.Note == "" {
			t.Errorf("preset rule %d has nothing on screen explaining it", i)
		}
	}
}

func TestAMintedIdentifierIsUniqueAndSaysWhatItNames(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mint   func() (string, error)
		prefix string
	}{
		{"proxy", NewProxyID, "px_"},
		{"rule", NewRuleID, "ar_"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(map[string]bool, 64)
			for range 64 {
				id, err := tc.mint()
				if err != nil {
					t.Fatalf("minting an id failed: %v", err)
				}
				if !strings.HasPrefix(id, tc.prefix) {
					t.Fatalf("id = %q, want it to begin %q", id, tc.prefix)
				}
				if seen[id] {
					t.Fatalf("id %q was minted twice", id)
				}
				seen[id] = true
			}
		})
	}
}
