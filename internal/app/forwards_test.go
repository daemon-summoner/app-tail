// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/forward"
	"github.com/sellitus/app-tail/internal/httpapi"
)

// The list the dashboard renders is a join: stored configuration on one side, the
// engine's live counters on the other. Nothing else in the suite issues this call, so
// a join that dropped either half -- all rules showing "stopped", or live rules whose
// endpoint label is blank -- would ship looking perfectly healthy.
func TestListingForwardsMergesStoredConfigWithLiveCounters(t *testing.T) {
	echo := startEchoTCP(t)
	port := freePort(t)

	h := newHarness(t, func(c *config.Config) {
		c.Forwards = []config.Forward{{
			ID: "fwd_live", Name: "Live one", Direction: config.ToLocal, Protocol: config.TCP,
			BindAddr: "127.0.0.1", ListenPort: port, Target: "100.64.0.5:8100", Enabled: true,
		}, {
			ID: "fwd_off", Name: "Switched off", Direction: config.ToLocal, Protocol: config.UDP,
			BindAddr: "127.0.0.1", ListenPort: freePort(t), Target: "100.64.0.5:9100", Enabled: false,
		}}
	})
	h.node.route("100.64.0.5:8100", echo)
	h.bringUp()

	// Real traffic through the forward itself, so the counters under test are non-zero
	// for a reason rather than because something set them.
	const payload = "through the join"
	local := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if got := roundTripTCP(t, local, payload); got != payload {
		t.Fatalf("round trip through the forward = %q, want %q", got, payload)
	}

	var (
		raw  []byte
		body struct {
			Forwards []httpapi.ForwardView `json:"forwards"`
		}
	)
	fetch := func() {
		var resp *http.Response
		resp, raw = h.get("/api/forwards")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/forwards = %d: %s", resp.StatusCode, raw)
		}
		body.Forwards = nil
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("decode the forward list: %v (body %s)", err, raw)
		}
	}

	// A direction's bytes are counted when that direction finishes copying, and the reply
	// arriving at the client is not that moment: the upstream's own close still has to
	// cross the proxy. Polling for it is what keeps the join under test the only thing
	// this can fail on.
	waitFor(t, 5*time.Second, "the round trip to land on the forward's counters", func() bool {
		fetch()
		for _, f := range body.Forwards {
			if f.ID == "fwd_live" {
				return f.BytesUp > 0 && f.BytesDown > 0
			}
		}
		return false
	})

	if len(body.Forwards) != 2 {
		t.Fatalf("listed %d forwards, want both the enabled and the disabled one: %s", len(body.Forwards), raw)
	}

	live, off := body.Forwards[0], body.Forwards[1]
	if live.ID != "fwd_live" || off.ID != "fwd_off" {
		t.Fatalf("forwards came back as %q,%q; the list must be ordered by id so the table "+
			"does not reshuffle between polls", live.ID, off.ID)
	}

	// The stored half.
	if live.Name != "Live one" || live.Target != "100.64.0.5:8100" || live.ListenPort != port {
		t.Errorf("stored fields did not survive the join: %+v", live.Forward)
	}
	if live.Endpoint != config.Endpoint(live.Forward) {
		t.Errorf("Endpoint = %q, want the rendered label %q", live.Endpoint, config.Endpoint(live.Forward))
	}

	// The live half.
	if live.State != forward.StateRunning {
		t.Errorf("enabled forward reports state %q, want %q", live.State, forward.StateRunning)
	}
	if live.Listening == "" {
		t.Error("enabled forward reports no listening address; the engine's snapshot did not reach the view")
	}
	if want := int64(len(payload)); live.BytesUp != want || live.BytesDown != want {
		t.Errorf("byte counters came through as up=%d down=%d after a round trip of %d bytes "+
			"each way; the live snapshot was not merged", live.BytesUp, live.BytesDown, want)
	}

	// A forward that was never enabled was never registered with the engine, so its
	// live half is legitimately absent: the join contributes nothing and the dashboard
	// labels it from `enabled` alone. What matters is that it is still listed -- drop
	// it and the user cannot switch it back on -- and that it carries no borrowed live
	// state from its neighbour.
	if off.State != "" {
		t.Errorf("never-started forward reports state %q, want it empty", off.State)
	}
	if off.Listening != "" {
		t.Errorf("never-started forward claims to be listening on %q", off.Listening)
	}
	if off.BytesUp != 0 || off.BytesDown != 0 {
		t.Errorf("never-started forward carries counters up=%d down=%d; the join leaked its "+
			"neighbour's live status", off.BytesUp, off.BytesDown)
	}
	if off.Endpoint == "" {
		t.Error("never-started forward has no endpoint label; that half comes from stored config")
	}
}

// The agent hands the engine only the enabled forwards, so disabling one drops its
// registry entry and with it the whole live half of the join. A forward that kept its
// last snapshot would show a green "running" dot -- and a listening address -- for a
// rule whose port is already free.
func TestDisablingAForwardDropsItsLiveHalfButKeepsItListed(t *testing.T) {
	echo := startEchoTCP(t)
	port := freePort(t)

	h := newHarness(t, func(c *config.Config) {
		c.Forwards = []config.Forward{{
			ID: "fwd_toggle", Name: "Toggle me", Direction: config.ToLocal, Protocol: config.TCP,
			BindAddr: "127.0.0.1", ListenPort: port, Target: "100.64.0.5:8100", Enabled: true,
		}}
	})
	h.node.route("100.64.0.5:8100", echo)
	h.bringUp()

	if _, err := h.agent.Forwards().SetEnabled(context.Background(), "fwd_toggle", false); err != nil {
		t.Fatalf("disable the forward: %v", err)
	}

	views := h.agent.Forwards().List()
	if len(views) != 1 {
		t.Fatalf("listed %d forwards after a disable, want the forward to stay listed", len(views))
	}
	if views[0].State == forward.StateRunning {
		t.Error("disabled forward still reports running; its live status is stale")
	}
	if views[0].State != "" {
		t.Errorf("disabled forward reports state %q; a forward the engine no longer knows "+
			"about has no live half, and the dashboard labels it from `enabled`", views[0].State)
	}
	if views[0].Listening != "" {
		t.Errorf("disabled forward still claims to be listening on %q", views[0].Listening)
	}
	if !views[0].Enabled && views[0].Name != "Toggle me" {
		t.Errorf("stored fields were lost by the disable: %+v", views[0].Forward)
	}
}

// Listing has to answer before the node comes up: the dashboard's first poll happens
// while the agent is still connecting, and an empty list there would tell the user
// their rules were lost.
func TestListingForwardsWorksBeforeTheEngineExists(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Forwards = []config.Forward{{
			ID: "fwd_early", Name: "Configured", Direction: config.ToLocal, Protocol: config.TCP,
			BindAddr: "127.0.0.1", ListenPort: freePort(t), Target: "100.64.0.5:1", Enabled: true,
		}}
	})

	views := h.agent.Forwards().List()
	if len(views) != 1 {
		t.Fatalf("listed %d forwards before the node came up, want 1", len(views))
	}
	if views[0].Name != "Configured" {
		t.Errorf("stored name came back as %q", views[0].Name)
	}
	if views[0].State != "" {
		t.Errorf("state = %q before any engine existed, want it empty rather than invented", views[0].State)
	}
}

// --- the applySpec contract ------------------------------------------------

// applySpec is duplicated by hand in internal/httpapi's test fakes, because app imports
// httpapi and the fake cannot import back. Every httpapi CRUD test therefore validates
// the copy. These two tests are what guard the real one: without them a field could be
// added to ForwardSpec, wired into the fake, and never reach stored configuration --
// with the httpapi suite green the whole time.

// forwardFieldProbes gives each ForwardSpec field a value distinguishable from both the
// zero value and the "before" state, so a setter that writes the wrong destination is
// caught by the sibling check rather than passing on a coincidence.
type forwardFieldProbe struct {
	name string
	spec httpapi.ForwardSpec
	want func(config.Forward) bool
	got  func(config.Forward) any
}

func forwardFieldProbes() []forwardFieldProbe {
	return []forwardFieldProbe{
		{"Name", httpapi.ForwardSpec{Name: ptr("renamed")},
			func(f config.Forward) bool { return f.Name == "renamed" },
			func(f config.Forward) any { return f.Name }},
		{"TunnelID", httpapi.ForwardSpec{TunnelID: ptr("tn_office")},
			func(f config.Forward) bool { return f.TunnelID == "tn_office" },
			func(f config.Forward) any { return f.TunnelID }},
		{"Direction", httpapi.ForwardSpec{Direction: ptr(config.ToTailnet)},
			func(f config.Forward) bool { return f.Direction == config.ToTailnet },
			func(f config.Forward) any { return f.Direction }},
		{"Protocol", httpapi.ForwardSpec{Protocol: ptr(config.Both)},
			func(f config.Forward) bool { return f.Protocol == config.Both },
			func(f config.Forward) any { return f.Protocol }},
		{"BindAddr", httpapi.ForwardSpec{BindAddr: ptr("0.0.0.0")},
			func(f config.Forward) bool { return f.BindAddr == "0.0.0.0" },
			func(f config.Forward) any { return f.BindAddr }},
		{"ListenPort", httpapi.ForwardSpec{ListenPort: ptr(4242)},
			func(f config.Forward) bool { return f.ListenPort == 4242 },
			func(f config.Forward) any { return f.ListenPort }},
		{"Target", httpapi.ForwardSpec{Target: ptr("100.64.0.7:22")},
			func(f config.Forward) bool { return f.Target == "100.64.0.7:22" },
			func(f config.Forward) any { return f.Target }},
		{"Enabled", httpapi.ForwardSpec{Enabled: ptr(false)},
			func(f config.Forward) bool { return !f.Enabled },
			func(f config.Forward) any { return f.Enabled }},
		{"UDPTimeoutSec", httpapi.ForwardSpec{UDPTimeoutSec: ptr(99)},
			func(f config.Forward) bool { return f.UDPTimeoutSec == 99 },
			func(f config.Forward) any { return f.UDPTimeoutSec }},
		{"ExposeToNetwork", httpapi.ForwardSpec{ExposeToNetwork: ptr(true)},
			func(f config.Forward) bool { return f.ExposeToNetwork },
			func(f config.Forward) any { return f.ExposeToNetwork }},
	}
}

// baseForward is the "before" state every probe patches: every field is set to
// something other than its zero value and other than what the probes write, so both a
// setter that does nothing and a setter that clobbers a sibling are visible.
func baseForward() config.Forward {
	return config.Forward{
		ID: "fwd_base", Name: "Base", TunnelID: config.PrimaryTunnelID,
		Direction: config.ToLocal, Protocol: config.TCP,
		BindAddr: "127.0.0.1", ListenPort: 2222, Target: "100.64.0.5:22",
		Enabled: true, UDPTimeoutSec: 30,
	}
}

// A spec field that never reaches the stored forward makes the API answer 200 with the
// old value: the dashboard shows the edit as saved, the next poll silently reverts it,
// and the user's change is gone with no error anywhere.
func TestEveryForwardSpecFieldReachesTheStoredForward(t *testing.T) {
	for _, probe := range forwardFieldProbes() {
		t.Run(probe.name, func(t *testing.T) {
			before := baseForward()
			got := before
			applySpec(&got, probe.spec)

			if !probe.want(got) {
				t.Fatalf("patching %s left it as %v", probe.name, probe.got(got))
			}

			// Every other field must be untouched, which is what catches a setter
			// assigning to the wrong destination.
			for _, other := range forwardFieldProbes() {
				if other.name == probe.name {
					continue
				}
				if other.got(got) != other.got(before) {
					t.Errorf("patching %s also changed %s: %v -> %v",
						probe.name, other.name, other.got(before), other.got(got))
				}
			}
			if got.ID != before.ID {
				t.Errorf("patching %s changed the id from %q to %q", probe.name, before.ID, got.ID)
			}
		})
	}
}

// An empty spec is the "leave everything alone" case the pointer fields exist for. A
// setter that dereferenced unconditionally would blank the forward on any partial
// patch -- and SetEnabled sends exactly such a partial patch on every toggle.
func TestAnEmptyForwardSpecChangesNothing(t *testing.T) {
	before := baseForward()
	got := before
	applySpec(&got, httpapi.ForwardSpec{})

	if got != before {
		t.Fatalf("an empty spec rewrote the forward:\n before %+v\n  after %+v", before, got)
	}
}

// This is the test that fires when someone adds a ninth field to ForwardSpec and
// updates the httpapi test fake but not app/forwards.go. It walks the spec by
// reflection rather than by a hand-maintained list, so a new field is covered the
// moment it is declared and cannot be forgotten.
func TestForwardSpecHasNoFieldTheStoredForwardIgnores(t *testing.T) {
	specType := reflect.TypeOf(httpapi.ForwardSpec{})

	probes := make(map[string]bool, specType.NumField())
	for _, probe := range forwardFieldProbes() {
		probes[probe.name] = true
	}

	// A field with no probe is a field applySpec is never tested against, which is the
	// same defect one step earlier.
	for i := range specType.NumField() {
		field := specType.Field(i)
		if !probes[field.Name] {
			t.Errorf("ForwardSpec.%s has no probe in forwardFieldProbes; add one so "+
				"applySpec is proven to carry it into stored configuration", field.Name)
		}
	}

	// Now the real check: a spec with every field set must leave no field of the
	// stored forward still holding its prior value.
	full := httpapi.ForwardSpec{}
	fullValue := reflect.ValueOf(&full).Elem()
	for _, probe := range forwardFieldProbes() {
		probeValue := reflect.ValueOf(probe.spec)
		for i := range specType.NumField() {
			if !probeValue.Field(i).IsNil() {
				fullValue.Field(i).Set(probeValue.Field(i))
			}
		}
	}

	got := baseForward()
	applySpec(&got, full)
	for _, probe := range forwardFieldProbes() {
		if !probe.want(got) {
			t.Errorf("with every field set, %s came out as %v; applySpec drops it",
				probe.name, probe.got(got))
		}
	}
}

// Blocking incoming connections silences every forward that publishes a local service on
// the tailnet, and it does so without changing anything about the forward: it binds, it
// reports itself running, and every connection another device makes to it is dropped.
// Nothing else on the screen can show that, so without the warning the only way to find
// out is a connection that fails on the other device with no explanation anywhere.
func TestBlockingIncomingConnectionsWarnsOnTheForwardsItSilences(t *testing.T) {
	published := config.Forward{
		ID: "fwd_pub", Direction: config.ToTailnet, Protocol: config.TCP,
		ListenPort: 8080, Target: "127.0.0.1:8080", Enabled: true,
	}
	pulled := config.Forward{
		ID: "fwd_pull", Direction: config.ToLocal, Protocol: config.TCP,
		BindAddr: "127.0.0.1", ListenPort: 2222, Target: "100.64.0.5:22", Enabled: true,
	}

	warning := mergeView(published, forward.Status{}, true).Warning
	if warning == "" {
		t.Fatal("a forward publishing a service on the tailnet carries no warning while " +
			"incoming connections are blocked")
	}
	if !strings.Contains(warning, "Security") {
		t.Errorf("warning = %q, want it to name where the setting is", warning)
	}

	// The other direction dials out and is unaffected. Warning it too would train a user
	// to ignore the warning on the forward that really is dead.
	if got := mergeView(pulled, forward.Status{}, true).Warning; got != "" {
		t.Errorf("a forward that dials out carries %q; blocking incoming connections does "+
			"not affect it", got)
	}

	if got := mergeView(published, forward.Status{}, false).Warning; got != "" {
		t.Errorf("warning = %q with incoming connections not blocked", got)
	}
}

// A forward may bind beyond this machine, and that stays allowed -- publishing a tailnet
// service to the rest of the house is a real thing to want. What it may not do is look
// identical to a forward only this machine can reach: the port answers every machine on
// whatever network this one is attached to, with nothing in front of it, and the row
// otherwise reads exactly like a loopback one.
func TestAForwardListeningBeyondThisMachineSaysSo(t *testing.T) {
	pulled := config.Forward{
		ID: "fwd_pull", Direction: config.ToLocal, Protocol: config.TCP,
		ListenPort: 2222, Target: "100.64.0.5:22", Enabled: true,
	}
	tests := []struct {
		name, bind string
		want       []string
	}{
		{"every address", "0.0.0.0", []string{"every address this machine has", "127.0.0.1"}},
		{"every address, v6", "::", []string{"every address this machine has"}},
		{"one address on the network", "192.168.1.20", []string{"192.168.1.20"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := pulled
			f.BindAddr = tc.bind
			warning := mergeView(f, forward.Status{}, false).Warning
			if warning == "" {
				t.Fatalf("a forward bound to %s carries no warning", tc.bind)
			}
			for _, want := range tc.want {
				if !strings.Contains(warning, want) {
					t.Errorf("warning = %q, want it to say %q", warning, want)
				}
			}
		})
	}

	// Loopback is the whole point of the default and of every other listener this app opens.
	// Warning about it would train a user to ignore the sentence on the forward that is
	// really reachable from the network.
	for _, bind := range []string{"", "127.0.0.1", "127.0.0.2", "::1"} {
		f := pulled
		f.BindAddr = bind
		if got := mergeView(f, forward.Status{}, true).Warning; got != "" {
			t.Errorf("a forward bound to %q carries %q, and only this machine can reach it", bind, got)
		}
	}
}

// The warning reads a preference of the connection the forward crosses, and that preference
// is only in force while its module is on. Reading the stored value instead would put the
// warning on every forward of a user who set shields once and then switched the section off.
func TestTheShieldsWarningReadsTheConnectionTheForwardCrosses(t *testing.T) {
	published := config.Forward{
		ID: "fwd_pub", Direction: config.ToTailnet, Protocol: config.TCP,
		ListenPort: 8080, Target: "127.0.0.1:8080", Enabled: true,
	}

	h := newHarness(t, func(c *config.Config) {
		c.Settings.SecurityEnabled = true
		tailnetOf(t, c).ShieldsUp = true
	})
	if !h.agent.shieldsUpOn(published) {
		t.Error("the connection refuses incoming connections but the forward does not read it")
	}

	// Switching the module off has to reach the warning. Reading the stored value instead
	// would leave every published forward warning about a setting that is no longer in force.
	patchSettings(h, map[string]any{"security.enabled": false})
	if h.agent.shieldsUpOn(published) {
		t.Error("a stored shields setting reads as in force with the security module off")
	}

	// A forward naming a connection the document does not carry has no preferences to read.
	// Answering with the primary connection's would put the warning on the wrong forward.
	gone := published
	gone.TunnelID = "tn_gone"
	if h.agent.shieldsUpOn(gone) {
		t.Error("a forward on a connection that is not there took another connection's answer")
	}
}
