// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/sellitus/app-tail/internal/access"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
)

// twoInstances seeds the pair the access model exists for: one listener granted a database
// host and nothing else, another granted a shell host and nothing else. Both ask for
// whichever port is free, because a fixed one makes the suite fail when a developer happens
// to be running something on it.
//
// The grants name hosts rather than ports because a stand-in peer here answers on whichever
// loopback port the OS handed it, so the address a rule is matched against carries that port
// rather than the one the destination named. Port matching against a real dialled address is
// pinned where the address is fixed, in the proxy's own suite.
func twoInstances(c *config.Config) {
	c.Settings.ProxyEnabled = true
	db := config.NewProxyInstance("px_aaaaaa", "db", "psql", "127.0.0.1:0")
	db.Rules = []access.Rule{{
		ID: "ar_db", Action: access.Allow, Tunnel: config.PrimaryTunnelID, Host: "db",
	}}
	shell := config.NewProxyInstance("px_bbbbbb", "shell", "ssh", "127.0.0.1:0")
	shell.Rules = []access.Rule{{
		ID: "ar_shell", Action: access.Allow, Tunnel: config.PrimaryTunnelID, Host: "shell",
	}}
	// The instance every install has is switched off, so the two under test are the only
	// listeners and a connection that opened cannot have been carried by a third.
	for i := range c.Proxies {
		if c.Proxies[i].ID == config.DefaultProxyID {
			c.Proxies[i].Enabled = false
		}
	}
	c.Proxies = append(c.Proxies, db, shell)
}

// waitForInstance waits for the reconcile loop to bring one instance to a state, since Apply
// runs on the lifecycle goroutine rather than on the request that caused it.
func waitForInstance(h *harness, id, why string, ready func(httpapi.ProxyInstanceView) bool) httpapi.ProxyInstanceView {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var view httpapi.ProxyInstanceView
	for time.Now().Before(deadline) {
		got, err := h.agent.ProxiesAPI().Get(id)
		if err != nil {
			h.t.Fatalf("reading proxy %q: %v", id, err)
		}
		view = got
		if ready(view) {
			return view
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("timed out after 5s waiting for %s; instance: %+v", why, view)
	return view
}

// dialRefusedThroughProxy is dialThroughProxy for the case that must fail: it returns the
// refusal rather than ending the test, because a refusal is what is being proven.
func dialRefusedThroughProxy(t *testing.T, proxyAddr, address string) error {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("build a SOCKS5 client: %v", err)
	}
	conn, err := dialer.Dial("tcp", address)
	if err == nil {
		conn.Close()
		return nil
	}
	return err
}

// The whole point of the access layer: two listeners on two ports, each carrying what it was
// granted and refusing what the other one was. A rule list that leaked between instances, or
// a matcher that read a grant as a global one, would show up here and nowhere else.
func TestTwoInstancesEachRefuseWhatTheOtherAllows(t *testing.T) {
	h := newHarness(t, twoInstances)
	peer := echoPeer(t)
	h.node.route("db:5432", peer)
	h.node.route("shell:22", peer)
	h.bringUp()

	db := waitForInstance(h, "px_aaaaaa", "the database proxy to bind",
		func(v httpapi.ProxyInstanceView) bool { return v.Listening != "" })
	shell := waitForInstance(h, "px_bbbbbb", "the shell proxy to bind",
		func(v httpapi.ProxyInstanceView) bool { return v.Listening != "" })
	if db.Listening == shell.Listening {
		t.Fatalf("both instances bound %s, so neither test below proves anything", db.Listening)
	}

	dialThroughProxy(t, db.Listening, "db:5432").Close()
	dialThroughProxy(t, shell.Listening, "shell:22").Close()

	if err := dialRefusedThroughProxy(t, db.Listening, "shell:22"); err == nil {
		t.Error("the database proxy carried the shell port, which only the other instance was granted")
	}
	if err := dialRefusedThroughProxy(t, shell.Listening, "db:5432"); err == nil {
		t.Error("the shell proxy carried the database port, which only the other instance was granted")
	}
}

// And nothing else: a grant naming one host carries that host and no neighbour of it. A host
// glob anchored at the wrong end would carry every name that merely starts the same way, and
// nothing shows it until something that should have been refused goes through.
func TestAGrantOfOneHostCarriesNoNeighbourOfIt(t *testing.T) {
	h := newHarness(t, twoInstances)
	peer := echoPeer(t)
	h.node.route("db:5432", peer)
	h.node.route("db-standby:5432", peer)
	h.node.route("db.corp:5432", peer)
	h.bringUp()

	db := waitForInstance(h, "px_aaaaaa", "the database proxy to bind",
		func(v httpapi.ProxyInstanceView) bool { return v.Listening != "" })

	dialThroughProxy(t, db.Listening, "db:5432").Close()

	for _, refused := range []string{"db-standby:5432", "db.corp:5432"} {
		if err := dialRefusedThroughProxy(t, db.Listening, refused); err == nil {
			t.Errorf("%s was carried, which no rule on this instance grants", refused)
		}
	}
}

// The test endpoint has to be decided by the same resolver, rule list and matcher a real
// connection is, or it is a second opinion rather than a test -- and a permission model whose
// tester disagrees with it is worse than one with no tester at all.
func TestATestAgreesWithWhatARealDialDoes(t *testing.T) {
	h := newHarness(t, twoInstances)
	peer := echoPeer(t)
	h.node.route("db:5432", peer)
	h.node.route("shell:22", peer)
	h.bringUp()

	db := waitForInstance(h, "px_aaaaaa", "the database proxy to bind",
		func(v httpapi.ProxyInstanceView) bool { return v.Listening != "" })

	for _, tc := range []struct {
		address string
		carried bool
	}{
		{"db:5432", true},
		{"shell:22", false},
	} {
		result, err := h.agent.ProxiesAPI().Test(context.Background(), "px_aaaaaa",
			httpapi.ProxyTestRequest{Address: tc.address, Protocol: "tcp"})
		if err != nil {
			t.Fatalf("testing %s: %v", tc.address, err)
		}
		if result.Allowed != tc.carried {
			t.Errorf("the test says %s allowed=%v, want %v", tc.address, result.Allowed, tc.carried)
		}
		dialErr := dialRefusedThroughProxy(t, db.Listening, tc.address)
		if carried := dialErr == nil; carried != tc.carried {
			t.Errorf("dialling %s carried=%v (%v), want %v -- the tester and the proxy disagree",
				tc.address, carried, dialErr, tc.carried)
		}
	}
}

// Naming the line that decided is the point of the endpoint: rule order is the whole
// difficulty of a permission model, and "refused" without "by which rule" leaves somebody
// editing rules and guessing which one they are actually changing.
func TestATestNamesTheRuleThatDecidedAndTheConnectionThatWouldCarryIt(t *testing.T) {
	h := newHarness(t, twoInstances)
	h.node.route("db:5432", echoPeer(t))
	h.bringUp()
	waitForInstance(h, "px_aaaaaa", "the database proxy to bind",
		func(v httpapi.ProxyInstanceView) bool { return v.Listening != "" })

	result, err := h.agent.ProxiesAPI().Test(context.Background(), "px_aaaaaa",
		httpapi.ProxyTestRequest{Address: "db:5432", Protocol: "tcp"})
	if err != nil {
		t.Fatalf("testing: %v", err)
	}

	if result.Rule != "ar_db" || result.RuleIndex != 1 {
		t.Errorf("rule = %q at %d, want the first rule named as the table numbers it",
			result.Rule, result.RuleIndex)
	}
	if result.Tunnel != config.PrimaryTunnelID {
		t.Errorf("tunnel = %q, want the connection that would carry it", result.Tunnel)
	}
	if result.TunnelName != "Tailnet" {
		t.Errorf("tunnelName = %q, want the connection as a person calls it", result.TunnelName)
	}
	if result.Resolved == "" {
		t.Error("the result carries no resolved address, so nothing shows what the name became")
	}
	if result.Reason == "" {
		t.Error("the result carries no sentence to show")
	}
}

// A destination nothing can place is a third answer, not a refusal: nobody's rules were
// consulted, and reporting it as refused sends someone to edit rules that had no part in it.
func TestADestinationNothingCanPlaceIsReportedAsSuchRatherThanAsRefused(t *testing.T) {
	h := newHarness(t, twoInstances)
	h.bringUp()

	result, err := h.agent.ProxiesAPI().Test(context.Background(), "px_aaaaaa",
		httpapi.ProxyTestRequest{Address: "nowhere.invalid:443", Protocol: "tcp"})
	if err != nil {
		t.Fatalf("testing: %v", err)
	}

	if result.Allowed {
		t.Error("a destination nothing could place came back allowed")
	}
	if result.Resolved != "" || result.Tunnel != "" {
		t.Errorf("result = %+v, want no resolved address and no connection", result)
	}
	if result.Rule != "" || result.RuleIndex != 0 {
		t.Errorf("rule = %q at %d, want no rule named: none was consulted",
			result.Rule, result.RuleIndex)
	}
	if result.Reason == "" {
		t.Error("the result carries no reason, so the page has nothing to explain it with")
	}
}

// An instance that is not listening is still one whose permissions a person is editing, so
// the tester has to answer for it -- otherwise the only way to find out what a rule does is
// to switch the listener on.
func TestAnInstanceThatIsNotListeningIsStillTestable(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		twoInstances(c)
		for i := range c.Proxies {
			if c.Proxies[i].ID == "px_aaaaaa" {
				c.Proxies[i].Enabled = false
			}
		}
	})
	h.node.route("db:5432", echoPeer(t))
	h.bringUp()

	view, err := h.agent.ProxiesAPI().Get("px_aaaaaa")
	if err != nil {
		t.Fatalf("reading the instance: %v", err)
	}
	if view.Listening != "" {
		t.Fatalf("the instance bound %s while switched off, so this proves nothing", view.Listening)
	}

	result, err := h.agent.ProxiesAPI().Test(context.Background(), "px_aaaaaa",
		httpapi.ProxyTestRequest{Address: "db:5432", Protocol: "tcp"})
	if err != nil {
		t.Fatalf("testing an instance that is off: %v", err)
	}
	if !result.Allowed || result.Rule != "ar_db" {
		t.Errorf("result = %+v, want the stored rules decided the same way they would when bound", result)
	}
}

// A new instance is named after the program pointed at it, gets a handle and a port of its
// own, and is granted nothing: a default grant would make the least-configured instance the
// most powerful.
func TestAddingAProxyGivesItAHandleAPortAndNoGrants(t *testing.T) {
	h := newHarness(t, nil)

	view, err := h.agent.ProxiesAPI().Create(context.Background(),
		httpapi.ProxyInstanceSpec{Name: "psql client"})
	if err != nil {
		t.Fatalf("adding an instance: %v", err)
	}

	if view.Slug != "psql-client" {
		t.Errorf("slug = %q, want one derived from the name", view.Slug)
	}
	if len(view.Rules) != 0 {
		t.Errorf("rules = %+v, want a new instance granted nothing", view.Rules)
	}
	if len(view.Reach) != 1 || !strings.Contains(view.Reach[0], "nothing") {
		t.Errorf("reach = %v, want it to say the instance carries nothing yet", view.Reach)
	}
	if !view.Removable {
		t.Error("an added instance reports itself unremovable")
	}

	held, ok := h.store.Get().Proxy(view.ID)
	if !ok {
		t.Fatalf("the instance is not in the stored document: %+v", h.store.Get().Proxies)
	}
	// Two instances asking for one address is refused whole, so a form that defaulted to the
	// address already spoken for would be one nobody can submit.
	if held.ListenAddress() == storedProxy(t, h.store).ListenAddress() {
		t.Errorf("the added instance asks for %s, the same address the default one does",
			held.ListenAddress())
	}
}

// An unnamed instance is refused rather than defaulted: an instance is named after the
// program pointed at it, and that is not something to guess.
func TestAddingAProxyWithoutANameIsRefusedAndStoresNothing(t *testing.T) {
	h := newHarness(t, nil)
	before := len(h.store.Get().Proxies)

	_, err := h.agent.ProxiesAPI().Create(context.Background(), httpapi.ProxyInstanceSpec{Name: "  "})

	if err == nil {
		t.Fatal("an instance with no name was added")
	}
	var refusal *config.ValidationError
	if !errors.As(err, &refusal) || refusal.Field != "name" {
		t.Errorf("error = %v, want a rejection naming the control the form can mark", err)
	}
	if now := len(h.store.Get().Proxies); now != before {
		t.Errorf("the document holds %d instances, want the %d it started with", now, before)
	}
}

// The id exists so a decision can name the line that made it, which is bookkeeping the person
// adding a grant should not have to do. Minting it on the way in is what keeps the rules table
// numbered and the tester's answer traceable.
func TestARuleWithNoIdentifierIsMintedOne(t *testing.T) {
	h := newHarness(t, nil)

	view, err := h.agent.ProxiesAPI().SetRules(context.Background(), config.DefaultProxyID,
		[]access.Rule{
			{Action: access.Deny, Tunnel: config.PrimaryTunnelID, Ports: []string{"22"}},
			{Action: access.Allow, Tunnel: config.PrimaryTunnelID},
		})
	if err != nil {
		t.Fatalf("setting rules: %v", err)
	}

	if len(view.Rules) != 2 {
		t.Fatalf("the instance holds %d rules, want both", len(view.Rules))
	}
	if view.Rules[0].ID == "" || view.Rules[1].ID == "" {
		t.Errorf("rules = %+v, want every one carrying an id a decision can name", view.Rules)
	}
	if view.Rules[0].ID == view.Rules[1].ID {
		t.Errorf("both rules were minted %q, so a decision could not say which one decided",
			view.Rules[0].ID)
	}
	// Order is the meaning: the deny was sent first so it is matched first.
	if view.Rules[0].Action != access.Deny {
		t.Errorf("rules = %+v, want them stored in the order they were sent", view.Rules)
	}
	if stored := storedProxy(t, h.store).Rules; len(stored) != 2 || stored[0].ID != view.Rules[0].ID {
		t.Errorf("the document holds %+v, want the minted list the answer described", stored)
	}
}

// An id the caller supplied is theirs, not something to replace: a rules table that renumbered
// on every save would make a decision naming a rule impossible to follow back to a row.
func TestARuleThatAlreadyHasAnIdentifierKeepsIt(t *testing.T) {
	h := newHarness(t, nil)

	view, err := h.agent.ProxiesAPI().SetRules(context.Background(), config.DefaultProxyID,
		[]access.Rule{{ID: "ar_mine", Action: access.Allow, Tunnel: config.PrimaryTunnelID}})
	if err != nil {
		t.Fatalf("setting rules: %v", err)
	}

	if len(view.Rules) != 1 || view.Rules[0].ID != "ar_mine" {
		t.Errorf("rules = %+v, want the id the caller sent kept", view.Rules)
	}
}

// The one instance every install has is where this installation's own proxy settings are
// applied, so a document without it would refuse every one of those settings with nowhere to
// put them. Switching it off is how it is stopped.
func TestTheDefaultProxyCannotBeRemoved(t *testing.T) {
	h := newHarness(t, nil)

	err := h.agent.ProxiesAPI().Delete(context.Background(), config.DefaultProxyID)

	if err == nil {
		t.Fatal("the default instance was removed")
	}
	var refusal *config.ValidationError
	if !errors.As(err, &refusal) {
		t.Errorf("error = %v, want a rejection rather than a fault", err)
	}
	if !strings.Contains(err.Error(), "off") {
		t.Errorf("error = %q, want it to say what to do instead", err)
	}
	if _, ok := h.store.Get().Proxy(config.DefaultProxyID); !ok {
		t.Error("the default instance is gone from the document after a refused removal")
	}
}

// Removing one stops it, through the reconcile the removal ends with. An instance deleted from
// the document but left bound would go on carrying whatever it was granted, with nothing on
// screen saying it exists.
func TestRemovingAProxyStopsItListening(t *testing.T) {
	h := newHarness(t, twoInstances)
	h.node.route("db:5432", echoPeer(t))
	h.bringUp()
	db := waitForInstance(h, "px_aaaaaa", "the database proxy to bind",
		func(v httpapi.ProxyInstanceView) bool { return v.Listening != "" })

	if err := h.agent.ProxiesAPI().Delete(context.Background(), "px_aaaaaa"); err != nil {
		t.Fatalf("removing the instance: %v", err)
	}

	if _, err := h.agent.ProxiesAPI().Get("px_aaaaaa"); !errors.Is(err, config.ErrNotFound) {
		t.Errorf("error = %v, want the removed instance to be gone", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", db.Listening, 200*time.Millisecond)
		if err != nil {
			break
		}
		conn.Close()
		if time.Now().After(deadline) {
			t.Fatalf("%s is still accepting connections after the instance was removed", db.Listening)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRemovingAProxyThatIsNotStoredIsNotFound(t *testing.T) {
	h := newHarness(t, nil)

	if err := h.agent.ProxiesAPI().Delete(context.Background(), "px_absent"); !errors.Is(err, config.ErrNotFound) {
		t.Errorf("error = %v, want a not-found", err)
	}
}

// The reach sentences are what somebody who does not read rule tables learns their grants
// from, so a bare connection id in one is the whole sentence failing at its job.
func TestReachSentencesNameTheConnectionAsAPersonCallsIt(t *testing.T) {
	h := newHarness(t, twoInstances)

	view, err := h.agent.ProxiesAPI().Get("px_aaaaaa")
	if err != nil {
		t.Fatalf("reading the instance: %v", err)
	}

	if len(view.Reach) != 1 {
		t.Fatalf("reach = %v, want one sentence per rule", view.Reach)
	}
	if strings.Contains(view.Reach[0], config.PrimaryTunnelID) {
		t.Errorf("reach = %q, want the connection named rather than its id", view.Reach[0])
	}
	if !strings.Contains(view.Reach[0], "Tailnet") {
		t.Errorf("reach = %q, want the connection as a person calls it", view.Reach[0])
	}
	if !strings.Contains(view.Reach[0], "db") {
		t.Errorf("reach = %q, want it to say which host was granted", view.Reach[0])
	}
}

// The module switch gates every instance. An instance reporting itself on inside a module that
// is off would put a listening card on the page for a port nothing is bound to.
func TestSwitchingTheModuleOffLeavesEveryInstanceOff(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		twoInstances(c)
		c.Settings.ProxyEnabled = false
	})
	h.bringUp()

	for _, view := range h.agent.ProxiesAPI().List() {
		if view.Enabled {
			t.Errorf("instance %q reports itself on while the module is off", view.ID)
		}
		if view.Listening != "" {
			t.Errorf("instance %q bound %s while the module is off", view.ID, view.Listening)
		}
		if view.Capability.Available {
			t.Errorf("instance %q reports itself available while the module is off", view.ID)
		}
		if !strings.Contains(view.Capability.Reason, "the proxy module is switched off") {
			t.Errorf("instance %q explains itself as %q, want it to name the module switch",
				view.ID, view.Capability.Reason)
		}
	}
}

// Switching one instance off is a routine act -- the menu bar does it in one click -- and the
// state it leaves has to name the switch that is actually off. Blaming the module while the
// module is on sends the reader to a switch already where they want it and never mentions the
// one that is not.
func TestAnInstanceSwitchedOffInsideARunningModuleSaysSoRatherThanBlamingTheModule(t *testing.T) {
	h := newHarness(t, twoInstances)
	h.bringUp()

	// twoInstances leaves the instance every install has switched off inside a module that is on.
	view, err := h.agent.ProxiesAPI().Get(config.DefaultProxyID)
	if err != nil {
		t.Fatalf("reading the default instance: %v", err)
	}

	if view.Enabled {
		t.Fatalf("the default instance is on, so this test proves nothing")
	}
	if strings.Contains(view.Capability.Reason, "module") {
		t.Errorf("reason = %q, want it to name this instance's switch rather than the module",
			view.Capability.Reason)
	}
	if !strings.Contains(view.Capability.Reason, "this proxy is switched off") {
		t.Errorf("reason = %q, want it to say the instance itself is off", view.Capability.Reason)
	}
}

// A saved setting has to reach the instance it names and only that instance. Instances
// reconcile as a set precisely so editing one does not drop the connections a program is
// holding open through another.
func TestEditingOneInstanceSavesItAndLeavesTheOthersBound(t *testing.T) {
	h := newHarness(t, twoInstances)
	h.bringUp()
	before := waitForInstance(h, "px_aaaaaa", "the instance to bind", func(v httpapi.ProxyInstanceView) bool {
		return v.Listening != ""
	}).Listening

	view, err := h.agent.ProxiesAPI().Update(context.Background(), "px_aaaaaa", patchOf(t, map[string]any{
		"name": "psql on staging",
		// The requirement and the password it needs are one write: a requirement stored
		// without one would be a listener nothing can get through.
		"proxy.requireToken": true,
		"proxy.token":        "not-a-real-password",
	}))
	if err != nil {
		t.Fatalf("editing the instance: %v", err)
	}

	if view.Name != "psql on staging" {
		t.Errorf("name = %q, want the write reflected in the answer", view.Name)
	}
	if !view.RequiresPassword {
		t.Error("the instance answers without a password after one was required")
	}
	held, ok := h.store.Get().Proxy("px_aaaaaa")
	if !ok {
		t.Fatal("the instance is gone from the stored document")
	}
	if held.Name != "psql on staging" || !held.RequireToken {
		t.Errorf("stored = %+v, want the write persisted", held)
	}
	// The other instance is untouched, which is the whole reason instances reconcile as a set:
	// editing one must not drop the connections a program holds open through another.
	if other := waitForInstance(h, "px_bbbbbb", "the other instance to stay bound",
		func(v httpapi.ProxyInstanceView) bool { return v.Listening != "" }); other.Name != "ssh" {
		t.Errorf("the other instance is now %q, want it left alone", other.Name)
	}
	if before == "" {
		t.Error("the instance never bound, so this test proves nothing about rebinding")
	}
}

// Writing to an instance that is not stored is the stale-tab case: a form left open on an
// instance somebody else removed. It has to be a not-found rather than a write that lands
// on whichever instance happens to be first in the document.
func TestWritingToAProxyThatIsNotStoredIsNotFound(t *testing.T) {
	h := newHarness(t, twoInstances)

	_, err := h.agent.ProxiesAPI().Update(context.Background(), "px_absent",
		patchOf(t, map[string]any{"name": "nowhere"}))

	if !errors.Is(err, config.ErrNotFound) {
		t.Errorf("error = %v, want a not-found", err)
	}
	for _, view := range h.agent.ProxiesAPI().List() {
		if view.Name == "nowhere" {
			t.Fatalf("the write landed on instance %q instead of being refused", view.ID)
		}
	}
}

// Rules sent to an instance that is not stored are the same stale tab, and they carry more:
// a rule list written onto the wrong instance is a grant somebody never asked for.
func TestSettingRulesOnAProxyThatIsNotStoredIsNotFound(t *testing.T) {
	h := newHarness(t, twoInstances)

	_, err := h.agent.ProxiesAPI().SetRules(context.Background(), "px_absent",
		[]access.Rule{{Action: access.Allow, Tunnel: config.PrimaryTunnelID}})

	if !errors.Is(err, config.ErrNotFound) {
		t.Errorf("error = %v, want a not-found", err)
	}
	for _, view := range h.agent.ProxiesAPI().List() {
		if len(view.Rules) != 1 {
			t.Errorf("instance %q holds %d rules, want the one it was seeded with -- the refused "+
				"list landed somewhere", view.ID, len(view.Rules))
		}
	}
}

// The form is rendered from the served schema rather than held by each client, so an
// instance whose fields the agent does not describe is one no client can edit at all.
func TestTheInstanceFormIsServedRatherThanHeldByEachClient(t *testing.T) {
	h := newHarness(t, nil)

	schema := h.agent.ProxiesAPI().Schema()

	if len(schema) == 0 {
		t.Fatal("no fields are described, so the instance form would render empty")
	}
	keys := make(map[string]config.FieldSchema, len(schema))
	for _, field := range schema {
		if field.Label == "" {
			t.Errorf("%q is served with no label, so a form would show a control with no name", field.Key)
		}
		keys[field.Key] = field
	}
	for _, want := range []string{"name", "enabled", "proxy.listenAddr"} {
		if _, described := keys[want]; !described {
			t.Errorf("%q is not in the served schema, so no client can edit it", want)
		}
	}
}

// A datagram destination is decided against the same rules a stream one is, and a tester
// that answered every question as TCP would tell somebody a UDP grant works when the rule
// they are looking at names TCP only.
func TestTestingADatagramDestinationIsDecidedAsOne(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.ProxyEnabled = true
		held := config.NewProxyInstance("px_dns", "dns", "resolver", "127.0.0.1:0")
		held.Rules = []access.Rule{{
			ID: "ar_dns", Action: access.Allow, Tunnel: config.PrimaryTunnelID,
			Host: "db", Protocol: access.TCP,
		}}
		c.Proxies = append(c.Proxies, held)
	})
	h.bringUp()

	got, err := h.agent.ProxiesAPI().Test(context.Background(), "px_dns",
		httpapi.ProxyTestRequest{Address: "db:53", Protocol: string(access.UDP)})
	if err != nil {
		t.Fatalf("testing a datagram destination: %v", err)
	}

	if got.Allowed {
		t.Errorf("a datagram destination was allowed by a rule that names TCP only: %+v", got)
	}
}

// Testing against an instance that is not stored is a not-found rather than an answer, or a
// stale tab would be told a grant it cannot see is in force.
func TestTestingAProxyThatIsNotStoredIsNotFound(t *testing.T) {
	h := newHarness(t, nil)

	_, err := h.agent.ProxiesAPI().Test(context.Background(), "px_absent",
		httpapi.ProxyTestRequest{Address: "db:5432"})

	if !errors.Is(err, config.ErrNotFound) {
		t.Errorf("error = %v, want a not-found", err)
	}
}

// A rule naming this machine's own network has no connection to name, and a result showing
// the sentinel would be a row nobody can read. A rule naming a connection that is no longer
// stored falls back to the id, which is at least something to search the document for.
func TestAResultNamesThisMachineAndFallsBackToTheIdentifierItWasGiven(t *testing.T) {
	h := newHarness(t, nil)

	if got := h.agent.connectionName(access.ThisMachine); !strings.Contains(got, "this machine") {
		t.Errorf("the sentinel reads as %q, want this machine's own network named", got)
	}
	if got := h.agent.connectionName("tn_removed"); got != "tn_removed" {
		t.Errorf("a connection that is not stored reads as %q, want the id it was given", got)
	}
	if got := h.agent.connectionName(config.PrimaryTunnelID); got == config.PrimaryTunnelID {
		t.Errorf("a stored connection reads as its id %q rather than as its name", got)
	}
}
