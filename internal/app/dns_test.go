// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

func dnsView(h *harness) httpapi.DNSView {
	h.t.Helper()
	resp, raw := h.get("/api/dns")
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("GET /api/dns = %d: %s", resp.StatusCode, raw)
	}
	var view httpapi.DNSView
	if err := json.Unmarshal(raw, &view); err != nil {
		h.t.Fatalf("decode %s: %v", raw, err)
	}
	return view
}

// tailnetServing is a tailnet publishing everything a DNS panel can show: its own
// resolver, a search domain, a split-DNS suffix pointed elsewhere, and a name that is not
// a device.
func tailnetServing() tsnode.TailnetDNS {
	return tsnode.TailnetDNS{
		MagicDNS:  true,
		Resolvers: []string{"100.100.100.100"},
		Domains:   []string{"tail1a2b3c.ts.net"},
		Routes: []tsnode.DNSRoute{
			{Suffix: "corp.example.com", Resolvers: []string{"10.0.0.53"}},
		},
		Records: []tsnode.DNSRecord{{Name: "wiki", Type: "A", Value: "100.64.0.9"}},
	}
}

// The single most important thing this panel does is not oversell what the setting means.
// Turning the tailnet's DNS on configures the resolver inside this process and changes
// nothing about any other program on the machine -- a claim that is now scoped rather than
// absolute, because the machine-wide resolver beside it does change the machine, and a
// sentence that read as though this switch were the one doing it would send a user to the
// wrong card.
func TestTheDNSViewNeverClaimsTheMachineWasChanged(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.DNSEnabled = true
		tailnetOf(t, c).DNSUseTailnet = true
	})
	h.node.tailnetDNS = tailnetServing()
	h.bringUp()

	view := dnsView(h)

	if view.Machine != nil {
		t.Errorf("machine = %+v, want nothing claimed about a resolver app-tail does not write",
			view.Machine)
	}
	if view.MachineReason == "" {
		t.Fatal("no reason is given for the empty machine half, so it reads as a failed read")
	}
	if !strings.Contains(view.MachineReason, "changes nothing about this machine") {
		t.Errorf("reason = %q, want it to say plainly that the machine is untouched",
			view.MachineReason)
	}
	// Which switch the sentence is about: an unattributed "nothing changed" is what a
	// reader of the card that does change the machine would take at face value.
	if !strings.Contains(view.MachineReason, "tailnet") ||
		!strings.Contains(view.MachineReason, "System resolver") {
		t.Errorf("reason = %q, want it to name the switch it is about and where the other one is",
			view.MachineReason)
	}
	if len(view.Capability.Limits) == 0 {
		t.Fatal("the view states no limits, so nothing tells a user their browser is unaffected")
	}
	joined := strings.ToLower(strings.Join(view.Capability.Limits, " "))
	for _, want := range []string{"other programs", "proxy"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the stated limits never mention %q: %v", want, view.Capability.Limits)
		}
	}
}

// Split DNS is the case a user cannot otherwise confirm: a suffix the admin console
// points at a private nameserver either arrives here or they are guessing at why a name
// does not resolve.
func TestTheSplitDNSSuffixesTheTailnetPublishesArriveWhole(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.DNSEnabled = true
		tailnetOf(t, c).DNSUseTailnet = true
	})
	h.node.tailnetDNS = tailnetServing()
	h.bringUp()

	view := dnsView(h)

	if !view.MagicDNS {
		t.Error("magicDNS reads off on a tailnet that resolves its own device names")
	}
	if len(view.Resolvers) != 1 || view.Resolvers[0] != "100.100.100.100" {
		t.Errorf("resolvers = %v, want the tailnet's nameservers", view.Resolvers)
	}
	if len(view.SearchDomains) != 1 || view.SearchDomains[0] != "tail1a2b3c.ts.net" {
		t.Errorf("search domains = %v, want what the tailnet publishes", view.SearchDomains)
	}
	if len(view.Routes) != 1 || view.Routes[0].Suffix != "corp.example.com" {
		t.Fatalf("routes = %+v, want the split-DNS suffix", view.Routes)
	}
	if len(view.Routes[0].Resolvers) != 1 || view.Routes[0].Resolvers[0] != "10.0.0.53" {
		t.Errorf("resolvers = %v, want whoever answers for that suffix", view.Routes[0].Resolvers)
	}
	if len(view.Records) != 1 || view.Records[0].Name != "wiki" || view.Records[0].Value != "100.64.0.9" {
		t.Errorf("records = %+v, want the names the tailnet serves beyond its devices", view.Records)
	}
}

// The module is off by default, and off must read as off rather than as a tailnet with no
// DNS. The two look identical on screen and only one is something a user can act on.
func TestTheModuleBeingOffIsTheReasonRatherThanAnEmptyTailnet(t *testing.T) {
	h := newHarness(t, nil)
	h.node.tailnetDNS = tailnetServing()
	h.bringUp()

	view := dnsView(h)

	if view.Enabled || view.Using {
		t.Fatalf("enabled = %v using = %v, want a module nobody turned on", view.Enabled, view.Using)
	}
	if view.Capability.Available {
		t.Errorf("capability = %+v, want unavailable for a module that is off", view.Capability)
	}
	if !strings.Contains(view.Capability.Reason, "module is off") {
		t.Errorf("reason = %q, want it to name the module rather than the tailnet",
			view.Capability.Reason)
	}
}

// Turning the module on without pointing app-tail at the tailnet's DNS is a real state a
// user can reach, and the reason it resolves nothing is the switch they did not flip.
func TestTheModuleOnButNotUsedIsReportedAsItsOwnState(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Settings.DNSEnabled = true })
	h.node.tailnetDNS = tailnetServing()
	h.bringUp()

	view := dnsView(h)

	if !view.Enabled || view.Using {
		t.Fatalf("enabled = %v using = %v, want the module on and the setting off",
			view.Enabled, view.Using)
	}
	if !view.Capability.Degraded {
		t.Errorf("capability = %+v, want degraded", view.Capability)
	}
	if !strings.Contains(view.Capability.Reason, "switched off") {
		t.Errorf("reason = %q, want it to name the setting", view.Capability.Reason)
	}
}

// Resolving through the exit node is the property people choose an exit node for and
// cannot confirm any other way. It is reported only when the exit node actually answers
// DNS, because an exit node that does not is the common case.
func TestResolvingThroughTheExitNodeIsReportedOnlyWhenItAnswers(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.DNSEnabled = true
		tailnetOf(t, c).DNSUseTailnet = true
		c.Settings.ExitNodeEnabled = true
		tailnetOf(t, c).ExitNodeID = "nGATE"
	})
	h.node.tailnetDNS = tailnetServing()
	h.node.exitDNS = map[string]bool{"nGATE": true}
	h.bringUp()

	view := dnsView(h)

	if !view.ExitNodeResolving {
		t.Fatal("the exit node answers DNS but the view does not say so")
	}
	if view.ExitNodeLabel == "" {
		t.Error("the answering device is not named, so a user cannot tell which one it is")
	}
}

func TestAnExitNodeThatDoesNotAnswerDNSIsNotReportedAsResolving(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.DNSEnabled = true
		tailnetOf(t, c).DNSUseTailnet = true
		c.Settings.ExitNodeEnabled = true
		tailnetOf(t, c).ExitNodeID = "nGATE"
	})
	h.node.tailnetDNS = tailnetServing()
	h.bringUp()

	if view := dnsView(h); view.ExitNodeResolving {
		t.Error("the view claims the exit node resolves names when it answers no DNS")
	}
}

// With no exit node selected there is nothing to ask about, and asking anyway is a round
// trip per poll for an answer that is already known.
func TestNoExitNodeMeansTheBackendIsNotAsked(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.DNSEnabled = true
		tailnetOf(t, c).DNSUseTailnet = true
	})
	h.node.tailnetDNS = tailnetServing()
	h.node.exitDNSErr = errors.New("the backend must not be asked with no exit node selected")
	h.bringUp()

	view := dnsView(h)

	if view.ExitNodeResolving {
		t.Error("the view claims an exit node resolves names with none selected")
	}
	if view.Error != "" {
		t.Errorf("error = %q, want the backend left alone with no exit node selected", view.Error)
	}
}

// A machine whose DNS app-tail genuinely manages -- the mode where it does write a
// resolver configuration -- must report it, or the panel understates what it changed.
func TestAManagedMachineResolverIsReported(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.DNSEnabled = true
		tailnetOf(t, c).DNSUseTailnet = true
	})
	h.node.tailnetDNS = tailnetServing()
	h.node.machineErr = nil
	h.node.machineDNS = tsnode.MachineDNS{
		Nameservers:   []string{"100.100.100.100"},
		SearchDomains: []string{"tail1a2b3c.ts.net"},
		MatchDomains:  []string{"corp.example.com"},
	}
	h.bringUp()

	view := dnsView(h)

	if view.Machine == nil {
		t.Fatal("a managed machine resolver was not reported")
	}
	if len(view.Machine.MatchDomains) != 1 || view.Machine.MatchDomains[0] != "corp.example.com" {
		t.Errorf("match domains = %v, want the domains routed to the tailnet resolver",
			view.Machine.MatchDomains)
	}
	if view.MachineReason != "" {
		t.Errorf("reason = %q, want none when there is a configuration to show", view.MachineReason)
	}
}

// A read that failed is a failure, not a machine app-tail does not manage. Collapsing the
// two would hide a backend that stopped answering behind the sentence that is normally
// correct.
func TestAFailedMachineReadIsNotMistakenForAnUnmanagedMachine(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.DNSEnabled = true
		tailnetOf(t, c).DNSUseTailnet = true
	})
	h.node.tailnetDNS = tailnetServing()
	h.node.machineErr = errors.New("the local api is not answering")
	h.bringUp()

	view := dnsView(h)

	if view.MachineReason != "" {
		t.Errorf("reason = %q, want a failed read reported as a failure", view.MachineReason)
	}
	if !view.Capability.Degraded || !strings.Contains(view.Capability.Reason, "not answering") {
		t.Errorf("capability = %+v, want the backend's own reason", view.Capability)
	}
}

// One answer feeds the dashboard, the tray and the CLI. Every state has to say what is
// wrong with that one, and every state -- healthy included -- has to carry the limits,
// because a card that stops mentioning them the moment everything works is the one a user
// reads as "my machine now resolves through my tailnet".
func TestEveryStateTheDNSModuleCanSitInSaysWhatIsWrongWithThatOne(t *testing.T) {
	// Only the module switch: whether the connection asks to resolve through its tailnet is
	// the view's own Using, which is where the capability reads it from.
	on := config.Settings{DNSEnabled: true}
	serving := httpapi.DNSView{Using: true, MagicDNS: true, Resolvers: []string{"100.100.100.100"}}

	for _, tc := range []struct {
		name        string
		settings    config.Settings
		view        httpapi.DNSView
		nodeProblem string
		want        string
		available   bool
		degraded    bool
	}{{
		name: "a module nobody turned on is the reason rather than the tailnet",
		want: "module is off",
	}, {
		name:        "a node that is not running resolves nothing through the tailnet",
		settings:    on,
		view:        serving,
		nodeProblem: "needs login",
		want:        "needs login",
		available:   true, degraded: true,
	}, {
		name:      "a read that failed is reported in its own words",
		settings:  on,
		view:      httpapi.DNSView{Using: true, Error: "the local api is not answering"},
		want:      "not answering",
		available: true, degraded: true,
	}, {
		name:      "the module on without the setting names the setting",
		settings:  config.Settings{DNSEnabled: true},
		view:      httpapi.DNSView{},
		want:      "switched off",
		available: true, degraded: true,
	}, {
		// A tailnet that publishes nothing is the admin console's doing, not this app's,
		// and reading it as a broken setting sends a user to the wrong screen.
		name:      "a tailnet publishing no nameserver says so rather than blaming the setting",
		settings:  on,
		view:      httpapi.DNSView{Using: true},
		want:      "publishes no nameserver",
		available: true, degraded: true,
	}, {
		name:      "a module resolving through the tailnet has nothing wrong with it",
		settings:  on,
		view:      serving,
		want:      "",
		available: true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got := dnsCapability(tc.settings, tc.view, tc.nodeProblem)

			if got.Available != tc.available || got.Degraded != tc.degraded {
				t.Errorf("available=%v degraded=%v, want %v and %v",
					got.Available, got.Degraded, tc.available, tc.degraded)
			}
			if !strings.Contains(got.Reason, tc.want) {
				t.Errorf("reason = %q, want it to contain %q", got.Reason, tc.want)
			}
			if len(got.Limits) == 0 {
				t.Error("no limits are stated, so nothing says the rest of the machine is unaffected")
			}
		})
	}
}

// A node that is not running has told us nothing, and "the tailnet publishes no
// nameserver" is a reading of that silence a user would act on.
func TestTheDNSViewRefusesToGuessWhileTheNodeIsDown(t *testing.T) {
	agent := newUnstartedAgent(t)

	view := agent.DNSAPI().View(context.Background())

	if view.Capability.Available {
		t.Errorf("capability = %+v, want unavailable while the node is down", view.Capability)
	}
	if view.MagicDNS || len(view.Resolvers) > 0 {
		t.Errorf("view = %+v, want nothing claimed about a tailnet that has not been read", view)
	}
	if view.Capability.Reason == "" {
		t.Error("no reason is given, so the empty panel reads as a tailnet with no DNS")
	}
}
