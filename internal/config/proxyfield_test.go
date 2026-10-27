// SPDX-License-Identifier: MIT

package config

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/sellitus/app-tail/internal/access"
)

// rawPatch is a patch as it arrives from the wire, so a test writes values rather than
// encoded bytes.
func rawPatch(t *testing.T, fields map[string]any) map[string]json.RawMessage {
	t.Helper()
	out := make(map[string]json.RawMessage, len(fields))
	for key, value := range fields {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("encode %q: %v", key, err)
		}
		out[key] = raw
	}
	return out
}

// The derived reading exists so a surface that used to render a two-valued picker has
// something true to render. Reading a rule list back as the wrong preset would tell somebody
// their narrow grant is a whole network, which is the one mistake this must not make.
func TestTheDerivedReachIsWhatTheRulesActuallyAmountTo(t *testing.T) {
	whole := access.Rule{ID: "ar_a", Action: access.Allow, Tunnel: PrimaryTunnelID}
	thisMachine := access.Rule{ID: "ar_b", Action: access.Allow, Tunnel: access.ThisMachine}

	tests := []struct {
		name  string
		rules []access.Rule
		want  ProxyScope
	}{
		{"one whole connection", []access.Rule{whole}, ScopeTailnet},
		{"that connection and this machine", []access.Rule{whole, thisMachine}, ScopeAll},
		{"nothing granted at all", nil, ScopeCustom},
		{"this machine alone", []access.Rule{thisMachine}, ScopeCustom},
		{"the two presets in the other order", []access.Rule{thisMachine, whole}, ScopeCustom},
		{"a third rule after the preset pair",
			[]access.Rule{whole, thisMachine, {ID: "ar_c", Action: access.Deny, Tunnel: PrimaryTunnelID}},
			ScopeCustom},
		{"one connection, one port", []access.Rule{{
			ID: "ar_a", Action: access.Allow, Tunnel: PrimaryTunnelID, Ports: []string{"5432"},
		}}, ScopeCustom},
		{"one connection, one host", []access.Rule{{
			ID: "ar_a", Action: access.Allow, Tunnel: PrimaryTunnelID, Host: "db",
		}}, ScopeCustom},
		{"one connection, one range", []access.Rule{{
			ID: "ar_a", Action: access.Allow, Tunnel: PrimaryTunnelID,
			CIDR: netip.MustParsePrefix("10.0.0.0/8"),
		}}, ScopeCustom},
		{"one connection, one transport", []access.Rule{{
			ID: "ar_a", Action: access.Allow, Tunnel: PrimaryTunnelID, Protocol: access.TCP,
		}}, ScopeCustom},
		{"a refusal rather than a grant", []access.Rule{{
			ID: "ar_a", Action: access.Deny, Tunnel: PrimaryTunnelID,
		}}, ScopeCustom},
		{"every connection rather than one", []access.Rule{{
			ID: "ar_a", Action: access.Allow,
		}}, ScopeCustom},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DerivedProxyScope(tc.rules); got != tc.want {
				t.Errorf("DerivedProxyScope = %q, want %q", got, tc.want)
			}
		})
	}
}

// Every value the reading can report has to be one the picker offers, or a form renders a
// selected option that is not in its own list and shows nothing at all.
func TestEveryReachTheReadingReportsIsOneThePickerOffers(t *testing.T) {
	offered := make(map[string]bool)
	for _, option := range proxyScopeOptions() {
		if option.Label == "" || option.Help == "" {
			t.Errorf("option %q is offered with no label or no help", option.Value)
		}
		offered[option.Value] = true
	}

	for _, scope := range []ProxyScope{ScopeTailnet, ScopeAll, ScopeCustom} {
		if !offered[string(scope)] {
			t.Errorf("the reading can report %q, which the picker does not offer", scope)
		}
	}
}

// A freshly added instance starts from the declared defaults and is granted nothing. A
// default grant would make the least-configured instance the most powerful one.
func TestANewInstanceStartsFromTheDefaultsAndReachesNothing(t *testing.T) {
	p := NewProxyInstance("px_aaaaaa", "browser", "Browser", "127.0.0.1:1081")

	if p.ID != "px_aaaaaa" || p.Slug != "browser" || p.Name != "Browser" {
		t.Errorf("instance = %+v, want the identity it was created under", p)
	}
	if p.ListenAddr != "127.0.0.1:1081" {
		t.Errorf("listenAddr = %q, want the address it was created with", p.ListenAddr)
	}
	if p.Rules != nil {
		t.Errorf("rules = %+v, want a new instance granted nothing", p.Rules)
	}
	if !p.Enabled {
		t.Error("a new instance is created switched off, so adding one appears to do nothing")
	}
	if p.DialTimeoutSec != DefaultProxyDialTimeoutSec {
		t.Errorf("dialTimeoutSec = %d, want the declared default %d",
			p.DialTimeoutSec, DefaultProxyDialTimeoutSec)
	}
	if p.ResolveVia != ResolveViaNetmap {
		t.Errorf("resolveVia = %q, want the declared default", p.ResolveVia)
	}
}

// An instance created with no address takes the field's own default rather than an empty
// one, since an instance with nowhere to listen is one that silently never binds.
func TestANewInstanceWithNoAddressTakesTheDefaultOne(t *testing.T) {
	p := NewProxyInstance("px_aaaaaa", "browser", "Browser", "")

	if p.ListenAddr != DefaultProxyListenAddr {
		t.Errorf("listenAddr = %q, want the declared default %q", p.ListenAddr, DefaultProxyListenAddr)
	}
}

// Two instances asking for one address is refused whole, so the address a form offers has to
// be one nothing else has asked for -- otherwise adding an instance produces a form that
// cannot be submitted.
func TestTheSuggestedAddressIsOneNoInstanceHasAskedFor(t *testing.T) {
	host, basePort, err := net.SplitHostPort(DefaultProxyListenAddr)
	if err != nil {
		t.Fatalf("the default address %q is not host:port: %v", DefaultProxyListenAddr, err)
	}
	base, err := strconv.Atoi(basePort)
	if err != nil {
		t.Fatalf("the default port %q is not a number: %v", basePort, err)
	}

	if got := SuggestProxyListenAddr(nil); got != DefaultProxyListenAddr {
		t.Errorf("with nothing stored the suggestion is %q, want the default %q",
			got, DefaultProxyListenAddr)
	}

	held := []ProxyInstance{{ListenAddr: DefaultProxyListenAddr}}
	want := net.JoinHostPort(host, strconv.Itoa(base+1))
	if got := SuggestProxyListenAddr(held); got != want {
		t.Errorf("suggestion = %q, want the next port above the one taken (%q)", got, want)
	}

	// A gap below a taken port is still free, and counting past it would move every
	// instance's address up by one for no reason.
	held = append(held, ProxyInstance{ListenAddr: net.JoinHostPort(host, strconv.Itoa(base+2))})
	if got := SuggestProxyListenAddr(held); got != want {
		t.Errorf("suggestion = %q, want the free port between the two taken ones (%q)", got, want)
	}
}

// An instance that left its address unset is still asking for the default one, so a
// suggestion that read the stored text rather than the effective address would hand the next
// instance an address the first one is about to bind.
func TestAnInstanceWithNoStoredAddressStillHoldsTheDefaultOne(t *testing.T) {
	got := SuggestProxyListenAddr([]ProxyInstance{{}})

	if got == DefaultProxyListenAddr {
		t.Errorf("suggestion = %q, want an address the unset instance is not about to bind", got)
	}
}

// Every port above the default being spoken for takes tens of thousands of instances, but the
// answer still has to be an address: returning nothing would leave the form with an empty
// field and no way to tell why.
func TestWithEveryPortTakenTheSuggestionIsStillAnAddress(t *testing.T) {
	host, basePort, err := net.SplitHostPort(DefaultProxyListenAddr)
	if err != nil {
		t.Fatalf("the default address %q is not host:port: %v", DefaultProxyListenAddr, err)
	}
	base, err := strconv.Atoi(basePort)
	if err != nil {
		t.Fatalf("the default port %q is not a number: %v", basePort, err)
	}

	held := make([]ProxyInstance, 0, 65536-base)
	for port := base; port <= 65535; port++ {
		held = append(held, ProxyInstance{ListenAddr: net.JoinHostPort(host, strconv.Itoa(port))})
	}

	got := SuggestProxyListenAddr(held)

	if _, _, err := net.SplitHostPort(got); err != nil {
		t.Errorf("suggestion = %q, which is not host:port: %v", got, err)
	}
	if got != net.JoinHostPort(host, "0") {
		t.Errorf("suggestion = %q, want whichever port is free once every fixed one is taken", got)
	}
}

// The served table has to answer whether each field applies to this installation, because a
// form that is not told cannot say why a control is greyed out -- and the checked-in table
// must not answer, because a generated file cannot know the machine that will run it.
func TestTheServedTableAnswersAvailabilityAndTheGeneratedOneDoesNot(t *testing.T) {
	app := Defaults().Settings

	served := ProxySchema(&app)
	static := ProxySchemaStatic()

	if len(served) == 0 {
		t.Fatal("the instance form's table is empty, so the form would render nothing")
	}
	if len(served) != len(static) {
		t.Fatalf("the served table has %d fields and the generated one %d; they are one table",
			len(served), len(static))
	}
	for i, field := range served {
		if field.Available == nil {
			t.Errorf("served field %q does not say whether it applies here", field.Key)
		}
		if static[i].Available != nil {
			t.Errorf("generated field %q answers availability, which a checked-in file cannot know",
				static[i].Key)
		}
		if static[i].Key != field.Key {
			t.Errorf("the two tables disagree at %d: %q and %q", i, field.Key, static[i].Key)
		}
	}
}

// The module switch gates most of what an instance is configurable by, and a field the switch
// governs has to say so with a reason -- otherwise a greyed-out control has no explanation.
func TestTheFieldsTheModuleGovernsSayWhyTheyAreUnavailableWhileItIsOff(t *testing.T) {
	app := Defaults().Settings
	app.ProxyEnabled = false

	gated := 0
	for _, field := range ProxySchema(&app) {
		if field.Module != ModuleProxy {
			continue
		}
		gated++
		if field.Available == nil || *field.Available {
			t.Errorf("field %q applies while the module that governs it is off", field.Key)
		}
		if field.AvailableReason == "" {
			t.Errorf("field %q is unavailable with no reason, so a form cannot say why", field.Key)
		}
	}
	if gated == 0 {
		t.Fatal("no instance field is governed by the proxy module, so this rule checks nothing")
	}
}

// The reading of the rules is served as read-only. A menu or a form that wrote it would round
// a rule list to the nearest of two presets, which is a permission change nobody asked for.
func TestTheDerivedReachIsServedAsSomethingNothingCanWrite(t *testing.T) {
	app := Defaults().Settings

	for _, field := range ProxySchema(&app) {
		if field.Key != "proxy.scope" {
			continue
		}
		if !field.Derived || !field.ReadOnly || field.Write != WriteNone {
			t.Errorf("field = %+v, want it served as a reading nothing writes", field)
		}
		if field.Deprecated == "" {
			t.Error("the reading carries no note, so nothing stops somebody reaching for it " +
				"instead of the rules that now say the same thing")
		}
		return
	}
	t.Fatal("the instance form serves no reading of the rules")
}

// A stored password is never sent back out, so the view has to report presence under a key of
// its own. Serving it under the field's own key would put the mask where a value goes and a
// form round-trip would store the mask as the password.
func TestTheViewReportsAPasswordAsPresenceUnderItsOwnKey(t *testing.T) {
	app := Defaults().Settings
	p := NewProxyInstance("px_aaaaaa", "browser", "Browser", "")
	p.Token = "hunter2"

	view := BuildProxyView(p, &app)

	if _, leaked := view["proxy.token"]; leaked {
		t.Errorf("the view carries %v under the password's own key", view["proxy.token"])
	}
	if view["proxy.hasToken"] != true {
		t.Errorf("proxy.hasToken = %v, want the stored password reported as present",
			view["proxy.hasToken"])
	}
	for _, value := range view {
		if value == "hunter2" {
			t.Fatalf("the stored password is in the view: %v", view)
		}
	}
}

// The view is what a form is rendered from, so the reading of the rules has to be in it: a
// derived field with no value renders as an empty picker.
func TestTheViewCarriesTheReadingOfTheRules(t *testing.T) {
	app := Defaults().Settings
	p := NewProxyInstance("px_aaaaaa", "browser", "Browser", "")
	p.Rules = []access.Rule{{ID: "ar_a", Action: access.Allow, Tunnel: PrimaryTunnelID}}

	view := BuildProxyView(p, &app)

	if view["proxy.scope"] != string(ScopeTailnet) {
		t.Errorf("proxy.scope = %v, want what the rules amount to", view["proxy.scope"])
	}
}

// A patch carries only what changed, and everything it does not name is left alone. A write
// that reset the rest to their defaults would revoke settings nobody touched.
func TestAPatchWritesOnlyTheFieldsItNames(t *testing.T) {
	app := Defaults().Settings
	p := NewProxyInstance("px_aaaaaa", "browser", "Browser", "127.0.0.1:1081")
	p.RequireToken = true
	p.Token = "hunter2"

	if err := ApplyProxyPatch(&p, &app, rawPatch(t, map[string]any{"name": "psql"})); err != nil {
		t.Fatalf("applying a patch: %v", err)
	}

	if p.Name != "psql" {
		t.Errorf("name = %q, want the value the patch carried", p.Name)
	}
	if p.ListenAddr != "127.0.0.1:1081" || !p.RequireToken || p.Token != "hunter2" {
		t.Errorf("instance = %+v, want everything the patch did not name left alone", p)
	}
}

// The reading of the rules is refused by name rather than ignored: a caller told their write
// succeeded, with nothing changed, has no way to find out why the value did not stick.
func TestAPatchThatWritesTheReadingOfTheRulesIsRefusedByName(t *testing.T) {
	app := Defaults().Settings
	p := NewProxyInstance("px_aaaaaa", "browser", "Browser", "")

	err := ApplyProxyPatch(&p, &app, rawPatch(t, map[string]any{"proxy.scope": string(ScopeAll)}))

	if err == nil {
		t.Fatal("the reading of the rules was written through the instance form")
	}
	var refusal *ValidationError
	if !errors.As(err, &refusal) || refusal.Field != "proxy.scope" {
		t.Errorf("error = %v, want a rejection naming the control", err)
	}
}
