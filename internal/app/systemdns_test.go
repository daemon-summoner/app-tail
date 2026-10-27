// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsfwd"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/sysdns"
	"github.com/sellitus/app-tail/internal/testport"
	"github.com/sellitus/app-tail/internal/tsnode"
	"golang.org/x/net/dns/dnsmessage"
)

// resolverSettings is a save that asks for the machine-wide resolver, or does not.
func resolverSettings(on bool, profile string) config.Settings {
	return config.Settings{SystemDNSEnabled: on, SystemDNSProfile: profile}
}

// Both machine-level features are the same rights -- one helper, installed once -- and the
// dialog is a system password prompt. Two prompts for one save is how an app teaches people
// to dismiss its prompts without reading them, and a prompt for System default would be one
// for a setting that deliberately changes nothing.
func TestTheMachineIsSetUpOnceForWhicheverMachineFeaturesAWriteAsksFor(t *testing.T) {
	tests := []struct {
		name       string
		before     config.Settings
		after      config.Settings
		wantCalls  int
		wantRights tsnode.Rights
	}{
		{
			name:       "asking for the resolver sets the machine up for it",
			after:      resolverSettings(true, "cloudflare"),
			wantCalls:  1,
			wantRights: tsnode.RightsResolver,
		},
		{
			name:       "both features in one write prompt once",
			before:     config.Settings{},
			after:      config.Settings{InterfaceEnabled: true, InterfaceMode: config.NetworkTUN, SystemDNSEnabled: true, SystemDNSProfile: "cloudflare"},
			wantCalls:  1,
			wantRights: tsnode.RightsInterface,
		},
		{
			name:   "switching profiles while it is already on prompts for nothing",
			before: resolverSettings(true, "cloudflare"),
			after:  resolverSettings(true, "google"),
		},
		{
			name:   "turning the resolver off prompts for nothing",
			before: resolverSettings(true, "cloudflare"),
			after:  resolverSettings(false, "cloudflare"),
		},
		{
			name:  "choosing System default asks for no rights at all",
			after: resolverSettings(true, "system"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
			calls := 0
			var asked tsnode.Rights
			agent.provision = func(_ context.Context, _ func(string, ...any), want tsnode.Rights, _ bool, _ string) error {
				calls++
				asked = want
				return nil
			}

			agent.provisionRights(context.Background(), tc.before, tc.after)

			if calls != tc.wantCalls {
				t.Fatalf("the machine setup ran %d times, want %d", calls, tc.wantCalls)
			}
			if tc.wantCalls > 0 && asked != tc.wantRights {
				t.Errorf("the setup asked for %s, want %s", asked, tc.wantRights)
			}
		})
	}
}

// What the settings ask of the machine's resolver. Every case that answers "change nothing"
// has to say why, because the card shows that sentence and "off" and "the profile you chose
// was deleted" are not the same situation to be in.
func TestWhatTheSettingsAskOfTheMachineResolver(t *testing.T) {
	tests := []struct {
		name       string
		seed       func(*config.Config)
		wantOn     bool
		wantReason string
	}{
		{
			name:       "the module is off",
			seed:       func(c *config.Config) { c.Settings.SystemDNSEnabled = false },
			wantReason: "switched off",
		},
		{
			name: "System default is chosen",
			seed: func(c *config.Config) {
				c.Settings.SystemDNSEnabled = true
				c.Settings.SystemDNSProfile = "system"
			},
			wantReason: "System default",
		},
		{
			name: "the chosen profile was deleted underneath the settings",
			seed: func(c *config.Config) {
				c.Settings.SystemDNSEnabled = true
				c.Settings.SystemDNSProfile = "gone"
			},
			wantReason: `"gone"`,
		},
		{
			name: "a real profile is chosen",
			seed: func(c *config.Config) {
				c.Settings.SystemDNSEnabled = true
				c.Settings.SystemDNSProfile = "cloudflare"
			},
			wantOn: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
			if _, err := agent.store.Update(func(c *config.Config) error {
				tc.seed(c)
				return nil
			}); err != nil {
				t.Fatalf("seed settings: %v", err)
			}

			target := agent.systemDNSTarget(context.Background())

			if target.on != tc.wantOn {
				t.Fatalf("on = %v, want %v (reason %q)", target.on, tc.wantOn, target.reason)
			}
			if !tc.wantOn {
				if !strings.Contains(target.reason, tc.wantReason) {
					t.Errorf("reason = %q, want it to mention %q", target.reason, tc.wantReason)
				}
				return
			}
			if target.profile.ID != "cloudflare" {
				t.Errorf("profile = %q, want the one the settings name", target.profile.ID)
			}
			if target.listen.String() != config.DefaultSystemDNSListenAddr {
				t.Errorf("listen = %s, want %s", target.listen, config.DefaultSystemDNSListenAddr)
			}
		})
	}
}

// A name on a connection is answered from here or not at all. Nothing on this machine can
// route those networks in userspace mode, and a public resolver asked for such a name
// answers it with somebody else's address -- which the machine would then connect to. So
// the machine-wide resolver has to be told which suffixes the connections own, and this
// pins that the ones it is told are the ones the connections actually answer for.
func TestTheMachineResolverRefusesNamesOnAConnectionRatherThanForwardingThem(t *testing.T) {
	tests := []struct {
		name       string
		zone       string
		wantSuffix string
	}{
		{name: "the default zone", wantSuffix: "office." + config.DefaultDNSZone},
		{name: "a zone the user chose", zone: "corp.example.com", wantSuffix: "office.corp.example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(c *config.Config) {
				c.Settings.SystemDNSEnabled = true
				c.Settings.SystemDNSProfile = "cloudflare"
				c.Settings.DNSZone = tc.zone
				c.Tunnels = append(c.Tunnels, config.Tunnel{
					ID: "tn_office", Slug: "office", Name: "Office", Type: config.TunnelWireGuard,
				})
			})

			target := h.agent.systemDNSTarget(context.Background())

			if !target.on {
				t.Fatalf("the resolver is not on: %s", target.reason)
			}
			// Not carried: nothing is putting the connection's addresses on this machine, so
			// a name on it has nowhere to point and is refused rather than answered.
			if !slices.Contains(target.rules.TunnelSuffixes, dnsfwd.TunnelSuffix{Suffix: tc.wantSuffix, Name: "Office", ID: "tn_office"}) {
				t.Fatalf("suffixes = %+v, want the connection's own %q among them",
					target.rules.TunnelSuffixes, tc.wantSuffix)
			}

			q := dnsfwd.Question{Name: "db." + tc.wantSuffix, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
			decision := dnsfwd.Route(q, target.rules)
			if decision.Target != dnsfwd.Here || decision.RCode != dnsmessage.RCodeNameError {
				t.Errorf("Route(%s) = %s/%s (%s), want here/NXDOMAIN -- the name must not leave this machine",
					q.Name, decision.Target, decision.RCode, decision.Reason)
			}
			if !strings.Contains(decision.Reason, "Office") {
				t.Errorf("reason = %q, want it to name the connection the name is on", decision.Reason)
			}
		})
	}
}

// The card, the tray and the CLI all read this one answer, and the states it distinguishes
// are the ones a user would otherwise mistake for each other: a platform that cannot do it,
// a switch that is off, a profile that is gone, an override that never went in, and
// resolvers that stopped answering while the override is still in force.
func TestTheResolverCapabilityNamesEveryStateItCanBeIn(t *testing.T) {
	on := config.Settings{SystemDNSEnabled: true}
	tests := []struct {
		name          string
		settings      config.Settings
		view          httpapi.DNSSystemView
		known         bool
		wantAvailable bool
		wantDegraded  bool
		wantReason    string
	}{
		{
			name:       "the machine is not set up for it",
			settings:   on,
			view:       httpapi.DNSSystemView{Profile: "cloudflare", Blocker: "the privileged helper is not installed"},
			known:      true,
			wantReason: "helper is not installed",
		},
		{
			name:          "the module is off",
			settings:      config.Settings{},
			view:          httpapi.DNSSystemView{Ready: true, Profile: "cloudflare"},
			known:         true,
			wantAvailable: true,
			wantReason:    "the way it always did",
		},
		{
			name:          "the chosen profile no longer exists",
			settings:      on,
			view:          httpapi.DNSSystemView{Ready: true, Profile: "gone", Error: `the chosen resolver profile ("gone") no longer exists`},
			wantAvailable: true,
			wantDegraded:  true,
			wantReason:    "no longer exists",
		},
		{
			name:          "System default is chosen",
			settings:      on,
			view:          httpapi.DNSSystemView{Ready: true, Profile: "system"},
			known:         true,
			wantAvailable: true,
			wantReason:    "leaves this machine's own resolver",
		},
		{
			name:          "the override never went in",
			settings:      on,
			view:          httpapi.DNSSystemView{Ready: true, Profile: "cloudflare"},
			known:         true,
			wantAvailable: true,
			wantDegraded:  true,
			wantReason:    "has not been pointed at app-tail",
		},
		{
			name:     "the profile's resolvers stopped answering",
			settings: on,
			view: httpapi.DNSSystemView{
				Ready: true, Profile: "cloudflare", Applied: true,
				Unreachable: "the resolvers in this profile are not answering",
			},
			known:         true,
			wantAvailable: true,
			wantDegraded:  true,
			wantReason:    "sign in",
		},
		{
			name:          "everything is working",
			settings:      on,
			view:          httpapi.DNSSystemView{Ready: true, Profile: "cloudflare", Applied: true},
			known:         true,
			wantAvailable: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			view := tc.view
			got := systemDNSCapability(tc.settings, &view, tc.known)

			if got.Available != tc.wantAvailable || got.Degraded != tc.wantDegraded {
				t.Errorf("available = %v degraded = %v, want %v and %v",
					got.Available, got.Degraded, tc.wantAvailable, tc.wantDegraded)
			}
			if tc.wantReason != "" && !strings.Contains(got.Reason, tc.wantReason) {
				t.Errorf("reason = %q, want it to mention %q", got.Reason, tc.wantReason)
			}
			if len(got.Limits) == 0 {
				t.Error("no limits are stated, so nothing tells a user what this does to the rest of the machine")
			}
			joined := strings.ToLower(strings.Join(got.Limits, " "))
			for _, want := range []string{"every program", "put back", "no such name"} {
				if !strings.Contains(joined, want) {
					t.Errorf("the stated limits never mention %q: %v", want, got.Limits)
				}
			}
		})
	}
}

// A profile deleted out from under the settings loads rather than being refused -- the
// document was already saved -- so the card is the only thing that can tell the user their
// machine is not resolving through what the settings say it is.
func TestAProfileDeletedUnderneathTheSettingsIsReportedAndNothingIsApplied(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.inspect = func(context.Context, func(string, ...any)) tsnode.InterfaceReport {
		return tsnode.InterfaceReport{Platform: "darwin", Supported: true, Privileged: true}
	}
	if _, err := agent.store.Update(func(c *config.Config) error {
		c.Settings.SystemDNSEnabled = true
		c.Settings.SystemDNSProfile = "gone"
		return nil
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	view := agent.systemDNSView(context.Background())

	if view == nil {
		t.Fatal("the system half is absent, which a client reads as this build not having the feature")
	}
	if view.Applied {
		t.Error("the machine is reported as pointed at a profile that does not exist")
	}
	if !strings.Contains(view.Error, "gone") {
		t.Errorf("error = %q, want it to name the profile that is missing", view.Error)
	}
	if !view.Capability.Degraded || view.Capability.Available != true {
		t.Errorf("capability = %+v, want the feature offered but reported as not doing what was asked",
			view.Capability)
	}
}

// The switch being on and the machine really resolving through app-tail are separate
// answers, and a card that conflated them would say the feature works on a machine that was
// never set up for it.
func TestTheResolverViewReportsWhatWasChosenApartFromWhatIsInForce(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.inspect = func(context.Context, func(string, ...any)) tsnode.InterfaceReport {
		return tsnode.InterfaceReport{
			Platform: "darwin", Supported: true,
			Helper: tsnode.InterfaceHelperReport{Design: true, Installable: true},
		}
	}
	if _, err := agent.store.Update(func(c *config.Config) error {
		c.Settings.SystemDNSEnabled = true
		c.Settings.SystemDNSProfile = "cloudflare"
		return nil
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	view := agent.systemDNSView(context.Background())

	if !view.Enabled || view.Applied {
		t.Errorf("enabled = %v applied = %v, want the switch and the machine reported apart",
			view.Enabled, view.Applied)
	}
	if view.ProfileLabel != "Cloudflare" || len(view.Servers) != 2 {
		t.Errorf("label = %q servers = %v, want what the chosen profile actually resolves through",
			view.ProfileLabel, view.Servers)
	}
	if len(view.Protocols) != 1 || view.Protocols[0] != "https" {
		t.Errorf("protocols = %v, want how those resolvers are reached", view.Protocols)
	}
	if view.Ready {
		t.Fatal("a machine with no helper installed reports itself ready to change its own resolver")
	}
	if !view.NeedsSetup {
		t.Error("the one blocker a button can fix is not offered, so the card has nothing to do")
	}
	if view.Blocker == "" {
		t.Error("no blocker is named, so the switch reads as broken rather than as needing setup")
	}
}

// The Tailnet DNS profile stores no servers of its own: what it resolves through is what
// the tailnet publishes at the moment it is applied. A profile that carried a stored copy
// would keep resolving through a nameserver the admin console had already replaced.
func TestTheTailnetProfileResolvesThroughWhatTheTailnetPublishesRightNow(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.SystemDNSEnabled = true
		c.Settings.SystemDNSProfile = "tailnet"
	})
	h.node.tailnetDNS = tsnode.TailnetDNS{Resolvers: []string{"https://dns.nextdns.io/abc123"}}
	h.bringUp()

	target := h.agent.systemDNSTarget(context.Background())

	if !target.on {
		t.Fatalf("nothing is applied for a tailnet that publishes a nameserver: %q", target.reason)
	}
	if len(target.profile.Servers) != 1 || target.profile.Servers[0] != "https://dns.nextdns.io/abc123" {
		t.Fatalf("servers = %v, want the nameserver the tailnet publishes", target.profile.Servers)
	}

	// The card reads the same list, or it shows an empty resolver list while queries are
	// going somewhere -- but without the path, which is what identifies this account to the
	// provider and would otherwise be handed to every local process that reads the card.
	view := h.agent.systemDNSView(context.Background())
	if len(view.Servers) != 1 || view.Servers[0] != "https://dns.nextdns.io/..." {
		t.Errorf("view servers = %v, want the resolver named without the part that identifies it", view.Servers)
	}
}

// A tailnet with no nameserver of its own is the ordinary state of a tailnet that only
// resolves device names, and it has to leave the machine alone rather than point it at a
// profile with nothing in it -- which would be a machine that resolves nothing at all.
func TestTheTailnetProfileLeavesTheMachineAloneWhenThereIsNothingToResolveThrough(t *testing.T) {
	tests := []struct {
		name       string
		tailnet    tsnode.TailnetDNS
		up         bool
		wantReason string
	}{
		{
			name:       "the tailnet publishes no nameserver",
			tailnet:    tsnode.TailnetDNS{MagicDNS: true},
			up:         true,
			wantReason: "admin console",
		},
		{
			name:       "the node is not running",
			tailnet:    tsnode.TailnetDNS{Resolvers: []string{"https://dns.nextdns.io/abc123"}},
			wantReason: "not running",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(c *config.Config) {
				c.Settings.SystemDNSEnabled = true
				c.Settings.SystemDNSProfile = "tailnet"
			})
			h.node.tailnetDNS = tc.tailnet
			if tc.up {
				h.bringUp()
			}

			target := h.agent.systemDNSTarget(context.Background())

			if target.on {
				t.Fatalf("the machine was pointed at %v with nothing to resolve through", target.profile.Servers)
			}
			if !strings.Contains(target.reason, tc.wantReason) {
				t.Errorf("reason = %q, want it to mention %q", target.reason, tc.wantReason)
			}
		})
	}
}

// A network that redirects port 53 answers plain queries itself. Everything looks like it
// worked -- the override goes in, queries are counted, names resolve -- while not one of
// them reached the resolver that was picked. Saying so is the difference between a switch
// that works and a switch that appears to.
func TestANetworkThatAnswersPlainDNSItselfIsReportedRatherThanHidden(t *testing.T) {
	rights := &fakeResolverRights{}
	runner := newResolverRunner(t, rights)
	probes := 0
	runner.probe = func(context.Context) (bool, error) {
		probes++
		return true, nil
	}
	target := resolverTarget(t)
	target.profile = config.DNSProfile{ID: "router", Name: "Router", Servers: []string{"9.9.9.9"}}

	runner.apply(context.Background(), target)

	if probes != 1 {
		t.Fatalf("the network was probed %d times for a profile of plain resolvers, want once", probes)
	}
	snap := runner.snapshot()
	if !snap.applied {
		t.Fatalf("the override is not installed; reason %q failure %q", snap.reason, snap.failure)
	}
	if !strings.Contains(snap.intercepted, "answers plain DNS itself") {
		t.Fatalf("intercepted = %q, want it to say the answers are not coming from the chosen resolver", snap.intercepted)
	}

	view := &httpapi.DNSSystemView{
		Enabled: true, Applied: true, Ready: true,
		Profile: "router", Intercepted: snap.intercepted,
	}
	cap := systemDNSCapability(config.Settings{SystemDNSEnabled: true}, view, true)
	if !cap.Degraded || cap.Reason != snap.intercepted {
		t.Errorf("capability = %+v, want the interception stated on the card", cap)
	}
}

// An encrypted resolver is verified against its certificate, so a device on the path can
// block it but never answer for it. Probing anyway would put a packet on the network for a
// question that is already settled.
func TestAnEncryptedProfileIsNotProbedForInterception(t *testing.T) {
	rights := &fakeResolverRights{}
	runner := newResolverRunner(t, rights)
	probes := 0
	runner.probe = func(context.Context) (bool, error) {
		probes++
		return true, nil
	}

	runner.apply(context.Background(), resolverTarget(t))

	if probes != 0 {
		t.Errorf("an encrypted profile was probed %d times, want never", probes)
	}
	if snap := runner.snapshot(); snap.intercepted != "" {
		t.Errorf("intercepted = %q on a profile nothing on the path can answer for", snap.intercepted)
	}
}

// The button on the card is a request for the password dialog, so it has to ask for the
// rights the resolver needs and no others: asking for the interface rights would set a
// machine up for a network interface its owner never wanted.
func TestSettingThisMachineUpForTheResolverAsksForTheResolverRights(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	var asked []tsnode.Rights
	agent.provision = func(_ context.Context, _ func(string, ...any), want tsnode.Rights, _ bool, _ string) error {
		asked = append(asked, want)
		return nil
	}

	if err := agent.DNSAPI().SetUpSystem(context.Background()); err != nil {
		t.Fatalf("SetUpSystem: %v", err)
	}

	if len(asked) != 1 || asked[0] != tsnode.RightsResolver {
		t.Fatalf("the setup asked for %v, want exactly the resolver rights", asked)
	}
}

// The dialog can be declined, and the machine is then exactly as it was. A caller that
// asked for the arrangement is owed the reason rather than a success it can only disprove
// by reading the card again.
func TestAResolverSetupTheMachineRefusesComesBackToTheCaller(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.provision = func(context.Context, func(string, ...any), tsnode.Rights, bool, string) error {
		return errors.New("the password dialog was dismissed")
	}

	err := agent.DNSAPI().SetUpSystem(context.Background())

	if err == nil {
		t.Fatal("a refused arrangement was reported as a successful one")
	}
	if !strings.Contains(err.Error(), "dismissed") {
		t.Errorf("error = %v, want the reason the machine gave", err)
	}
}

// A profile that stops answering is what a captive portal looks like from here, and it is
// the one failure the card cannot show as an error: the override is installed and working,
// and the resolvers behind it are not. Saying nothing leaves the user with a machine that
// resolves nothing and an app reporting everything is fine.
func TestAProfileThatStopsAnsweringIsReportedUntilItAnswersAgain(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.inspect = func(context.Context, func(string, ...any)) tsnode.InterfaceReport {
		return tsnode.InterfaceReport{Platform: "darwin", Supported: true, Privileged: true}
	}
	rights := &fakeResolverRights{base: tsnode.BaseResolvers{
		Nameservers:   []netip.Addr{netip.MustParseAddr("192.168.6.1")},
		SearchDomains: []string{"lan"},
	}}
	runner := newResolverRunner(t, rights)
	runner.apply(context.Background(), resolverTarget(t))
	agent.mu.Lock()
	agent.systemDNS = runner
	agent.mu.Unlock()
	if _, err := agent.store.Update(func(c *config.Config) error {
		c.Settings.SystemDNSEnabled = true
		c.Settings.SystemDNSProfile = "cloudflare"
		return nil
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	runner.noteHealth(false, errors.New("i/o timeout"))
	view := agent.systemDNSView(context.Background())

	if !view.Applied {
		t.Fatalf("the override is not reported as installed, so this is a different failure: %+v", view)
	}
	if !strings.Contains(view.Unreachable, "not answering") || !strings.Contains(view.Unreachable, "i/o timeout") {
		t.Errorf("unreachable = %q, want it to say the profile is not answering and what happened",
			view.Unreachable)
	}
	if !view.Capability.Degraded {
		t.Error("a machine resolving through resolvers that answer nothing is reported as working")
	}
	if !strings.Contains(view.Capability.Reason, "sign in") {
		t.Errorf("reason = %q, want it to name the network that wants you to sign in", view.Capability.Reason)
	}
	// The base the forwarder captured is what the card shows as "and everything else still
	// goes here", so it has to survive the trip through the view as addresses a reader knows.
	if view.Base == nil || len(view.Base.Nameservers) != 1 || view.Base.Nameservers[0] != "192.168.6.1" {
		t.Errorf("base = %+v, want the network's own resolver named", view.Base)
	}
	if !slices.Contains(view.LocalSuffixes, "lan") {
		t.Errorf("local suffixes = %v, want the network's own search domain among them", view.LocalSuffixes)
	}

	runner.noteHealth(true, nil)

	if got := agent.systemDNSView(context.Background()); got.Unreachable != "" || got.Capability.Degraded {
		t.Errorf("a profile that answers again is still reported as unreachable: %q (degraded %v)",
			got.Unreachable, got.Capability.Degraded)
	}
}

// fakeResolverRights stands in for the privileged claim on this machine's name resolution.
// The real one asks for administrator rights and rewrites every network service, so the
// order it is driven in -- sockets first, machine second -- is what a test can check here
// and nowhere else.
type fakeResolverRights struct {
	mu      sync.Mutex
	order   []string
	applied [][]netip.Addr
	closed  int32

	base       tsnode.BaseResolvers
	baseErr    error
	openErr    error
	applyErr   error
	restoreErr error

	// runner is the runner driving this claim, read back inside Restore. It is how the
	// order that matters on the way out -- machine first, sockets second -- is observed at
	// the one moment it can be: the sockets are closed by the serve loops, which happens
	// after the pass that told them to, so counting closes afterwards proves nothing.
	runner *systemDNSRunner
	// servingAtRestore is whether app-tail was still answering DNS when the machine was
	// put back.
	servingAtRestore bool
	// observe, when set, is told each step as it happens, so a test can place it among the
	// steps other fakes take.
	observe func(step string)
	// opens counts the sockets handed out, which decides the address the next one lands on.
	opens int
	// laterOpenErr fails every open after the first, and oneAddress puts every socket on the
	// same address, which are the two ways a second address can be out of reach.
	laterOpenErr error
	oneAddress   bool
}

func (f *fakeResolverRights) note(what string) {
	f.mu.Lock()
	f.order = append(f.order, what)
	observe := f.observe
	f.mu.Unlock()
	if observe != nil {
		observe("dns " + what)
	}
}

func (f *fakeResolverRights) steps() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.order)
}

func (f *fakeResolverRights) OpenResolver(_ context.Context, want netip.AddrPort) (net.PacketConn, net.Listener, netip.AddrPort, error) {
	f.note("open")
	if f.openErr != nil {
		return nil, nil, netip.AddrPort{}, f.openErr
	}
	f.mu.Lock()
	n := f.opens
	f.opens++
	laterErr, oneAddress := f.laterOpenErr, f.oneAddress
	second := n%2 == 1
	if !want.IsValid() && len(f.applied) > 0 && len(f.applied[len(f.applied)-1]) == 1 {
		// Any free address, which the helper finds by walking its list: never the one the
		// machine is pointed at, since app-tail holds that.
		second = f.applied[len(f.applied)-1][0] == netip.MustParseAddr("127.0.0.1")
	}
	f.mu.Unlock()
	if n > 0 && laterErr != nil {
		return nil, nil, netip.AddrPort{}, laterErr
	}
	// Every other socket lands on a second loopback address, as the helper's own list does:
	// a resolver setting carries addresses alone, so two sockets on one address are one
	// place to point the machine at.
	hosts := []string{"127.0.0.1"}
	if second && !oneAddress {
		// ::1 is the second address macOS configures, and 127.0.0.2 the one a Linux machine
		// without IPv6 still routes.
		hosts = []string{"::1", "127.0.0.2"}
	}
	var errs []error
	for _, host := range hosts {
		pc, ln, err := bindTestResolver(host)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		bound := netip.MustParseAddrPort(pc.LocalAddr().String())
		return &countingPacketConn{PacketConn: pc, closed: &f.closed}, ln, bound, nil
	}
	return nil, nil, netip.AddrPort{}, errors.Join(errs...)
}

// bindTestResolver binds both halves of a DNS socket on one port of host.
func bindTestResolver(host string) (net.PacketConn, net.Listener, error) {
	// Reserved as bindable for both protocols: a ":0" UDP bind can land on a port the
	// machine keeps TCP off, as Windows does across the ranges it excludes.
	port, err := testport.Reserve()
	if err != nil {
		return nil, nil, err
	}
	pc, err := net.ListenPacket("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, nil, err
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		return nil, nil, errors.Join(err, pc.Close())
	}
	return pc, ln, nil
}

func (f *fakeResolverRights) Apply(_ context.Context, resolvers []netip.Addr) error {
	f.note("apply")
	if f.applyErr != nil {
		return f.applyErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, slices.Clone(resolvers))
	return nil
}

func (f *fakeResolverRights) Restore(context.Context) error {
	f.note("restore")
	// Read on the goroutine that holds the runner's lock, which is the one calling this.
	if f.runner != nil {
		f.servingAtRestore = f.runner.fwd != nil
	}
	return f.restoreErr
}

func (f *fakeResolverRights) Base(context.Context) (tsnode.BaseResolvers, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.baseErr != nil {
		return tsnode.BaseResolvers{}, f.baseErr
	}
	return f.base, nil
}

// baseBecomes changes what the machine reports as its own resolvers, or makes the report
// fail, as a network change or a service mid-change would.
func (f *fakeResolverRights) baseBecomes(base tsnode.BaseResolvers, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.base, f.baseErr = base, err
}

func (f *fakeResolverRights) Close() error {
	f.note("close")
	return nil
}

// countingPacketConn records that the socket really was closed, which is the difference
// between a forwarder that stopped answering and one still holding the port.
type countingPacketConn struct {
	net.PacketConn
	closed *int32
}

func (c *countingPacketConn) Close() error {
	atomic.AddInt32(c.closed, 1)
	return c.PacketConn.Close()
}

// newResolverRunner builds a runner over the fake claim, cleaning up whatever it opened.
func newResolverRunner(t *testing.T, rights *fakeResolverRights) *systemDNSRunner {
	t.Helper()
	runner := newSystemDNSRunner(quietLogger(), func(context.Context, func(string, ...any)) (tsnode.SystemDNSRights, error) {
		if rights.openErr != nil {
			return nil, rights.openErr
		}
		return rights, nil
	}, nil)
	t.Cleanup(func() { runner.close(context.Background()) })
	return runner
}

// resolverTarget is the settings resolved to a real profile, as the reconcile produces it.
func resolverTarget(t *testing.T) systemDNSTarget {
	t.Helper()
	profile, ok := dnsprofiles.ByID(nil, "cloudflare")
	if !ok {
		t.Fatal("the shipped cloudflare profile is missing")
	}
	return systemDNSTarget{on: true, profile: profile, listen: netip.MustParseAddrPort("127.0.0.153:53")}
}

// Bind first, override second, always. A machine pointed at an address nothing is listening
// on resolves nothing at all, and that is the one state this feature must never reach --
// including the moment between the two steps.
func TestTheMachineIsPointedAtAppTailOnlyAfterItIsAnsweringDNS(t *testing.T) {
	rights := &fakeResolverRights{base: tsnode.BaseResolvers{
		Nameservers:   []netip.Addr{netip.MustParseAddr("192.168.6.1")},
		SearchDomains: []string{"lan"},
	}}
	runner := newResolverRunner(t, rights)

	runner.apply(context.Background(), resolverTarget(t))

	steps := rights.steps()
	if len(steps) < 2 || steps[0] != "open" || steps[len(steps)-1] != "apply" {
		t.Fatalf("the machine was driven %v, want the sockets opened before the override went in", steps)
	}
	snap := runner.snapshot()
	if !snap.applied {
		t.Fatalf("the override is not reported as installed; reason %q failure %q", snap.reason, snap.failure)
	}
	if len(rights.applied) != 1 || len(rights.applied[0]) != 1 {
		t.Fatalf("the machine was pointed at %v, want exactly the address app-tail bound", rights.applied)
	}
	if got := rights.applied[0][0]; !got.IsLoopback() || got.String() != snap.listen[:strings.LastIndex(snap.listen, ":")] {
		t.Errorf("the machine was pointed at %s while app-tail listens on %s", got, snap.listen)
	}
	if snap.base.SearchDomains[0] != "lan" {
		t.Errorf("base = %+v, want the network's own resolvers kept for local names", snap.base)
	}
}

// A reconcile runs every few seconds. Rebuilding the sockets and the upstream connections
// each time would drop a live DNS-over-TLS session on a timer, which is a resolver that
// stutters for no reason the user can see.
func TestAReconcileThatChangesNothingKeepsTheSocketsAndTheConnections(t *testing.T) {
	rights := &fakeResolverRights{}
	runner := newResolverRunner(t, rights)
	target := resolverTarget(t)

	runner.apply(context.Background(), target)
	fwd := runner.fwd
	resolvers := runner.resolvers
	runner.apply(context.Background(), target)

	opens := 0
	for _, step := range rights.steps() {
		if step == "open" {
			opens++
		}
	}
	if opens != 1 {
		t.Errorf("the DNS sockets were opened %d times across two identical passes, want once", opens)
	}
	if runner.fwd != fwd {
		t.Error("the forwarder was replaced by a pass that changed nothing")
	}
	if runner.resolvers != resolvers || resolvers == "" {
		t.Errorf("the resolver pools were rebuilt by a pass that changed nothing (%q -> %q)", resolvers, runner.resolvers)
	}
}

// Switching the module off is the undo, and it has to be a real one: the machine put back,
// the claim released, and the sockets closed so nothing is left holding port 53.
func TestSwitchingTheResolverOffPutsTheMachineBackAndStopsAnswering(t *testing.T) {
	rights := &fakeResolverRights{}
	runner := newResolverRunner(t, rights)
	runner.apply(context.Background(), resolverTarget(t))

	runner.apply(context.Background(), systemDNSTarget{reason: "the machine-wide resolver is switched off"})

	steps := rights.steps()
	if len(steps) < 2 || steps[len(steps)-2] != "restore" || steps[len(steps)-1] != "close" {
		t.Fatalf("the machine was driven %v, want it restored and the claim released", steps)
	}
	snap := runner.snapshot()
	if snap.applied {
		t.Error("the override is still reported as installed after the module was switched off")
	}
	if !strings.Contains(snap.reason, "switched off") {
		t.Errorf("reason = %q, want the card to say why nothing is applied", snap.reason)
	}
	waitFor(t, 5*time.Second, "the DNS socket to be closed", func() bool {
		return atomic.LoadInt32(&rights.closed) > 0
	})
}

// The undo, driven through the settings API every surface writes to rather than through a
// document edit that would skip the module bookkeeping.
//
// Choosing System default is the way back for somebody whose resolver is breaking the site
// they are looking at, so it has to be a write the agent accepts. Turning a module off puts
// every setting it owns back to its default, and a write that also named the profile would
// be refused by the very switch it carries -- which is the second test here, pinned so no
// surface goes back to sending both keys.
func TestChoosingSystemDefaultTurnsTheResolverOffAndPutsTheProfileBack(t *testing.T) {
	agent := newResolverSettingsAgent(t)

	if _, _, err := agent.Settings().Update(t.Context(), settingsPatch(t, map[string]any{
		"systemDns.enabled": true,
		"systemDns.profile": "cloudflare",
	})); err != nil {
		t.Fatalf("switch this machine to a profile: %v", err)
	}

	if _, _, err := agent.Settings().Update(t.Context(), settingsPatch(t, map[string]any{
		"systemDns.enabled": false,
	})); err != nil {
		t.Fatalf("choose System default: %v", err)
	}

	s := agent.store.Get().Settings
	if s.SystemDNSEnabled {
		t.Error("the module is still on, so this machine stays pointed at app-tail")
	}
	if s.SystemDNSProfile != dnsprofiles.SystemID {
		t.Errorf("profile = %q, want the stored settings back to %q, as if the feature had never been used",
			s.SystemDNSProfile, dnsprofiles.SystemID)
	}
}

func TestAWriteThatTurnsTheResolverOffCannotAlsoNameAProfile(t *testing.T) {
	agent := newResolverSettingsAgent(t)

	if _, _, err := agent.Settings().Update(t.Context(), settingsPatch(t, map[string]any{
		"systemDns.enabled": true,
		"systemDns.profile": "cloudflare",
	})); err != nil {
		t.Fatalf("switch this machine to a profile: %v", err)
	}

	_, _, err := agent.Settings().Update(t.Context(), settingsPatch(t, map[string]any{
		"systemDns.enabled": false,
		"systemDns.profile": dnsprofiles.SystemID,
	}))

	if err == nil {
		t.Fatal("a profile named in the write that turns its own module off was accepted")
	}
	if !strings.Contains(err.Error(), "systemDns.profile") {
		t.Errorf("error = %v, which does not name the setting that was refused", err)
	}
}

// newResolverSettingsAgent is an agent whose settings writes reach the real registry and
// the real reconcile, with the machine itself faked out: no password dialog, no helper, and
// a claim that is granted so the write path is exercised to the end.
func newResolverSettingsAgent(t *testing.T) *Agent {
	t.Helper()
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.provision = func(context.Context, func(string, ...any), tsnode.Rights, bool, string) error { return nil }
	agent.inspect = func(context.Context, func(string, ...any)) tsnode.InterfaceReport {
		return tsnode.InterfaceReport{Platform: "darwin", Supported: true, Privileged: true}
	}
	rights := &fakeResolverRights{}
	agent.openSystemDNS = func(context.Context, func(string, ...any)) (tsnode.SystemDNSRights, error) {
		return rights, nil
	}
	return agent
}

// A claim that could not be obtained -- a declined password prompt, a helper that is not
// installed -- leaves this machine resolving names exactly as it was. What it must not do is
// go quiet: the reason is the only thing standing between the user and a switch that reads
// as on while nothing happened.
func TestAResolverClaimThatFailsLeavesTheMachineAloneAndSaysWhy(t *testing.T) {
	rights := &fakeResolverRights{openErr: errors.New("the request for administrator rights was declined")}
	runner := newResolverRunner(t, rights)

	runner.apply(context.Background(), resolverTarget(t))

	snap := runner.snapshot()
	if snap.applied {
		t.Fatal("the override is reported as installed although the claim failed")
	}
	if !strings.Contains(snap.reason, "declined") || !strings.Contains(snap.failure, "declined") {
		t.Errorf("reason = %q failure = %q, want the refusal carried to the card", snap.reason, snap.failure)
	}
	if steps := rights.steps(); len(steps) != 0 {
		t.Errorf("the machine was driven %v after a failed claim", steps)
	}
}

// Traffic inspection reads a run of names this machine asked about, and the only path that
// sees them is the resolver. A seam that never reached the forwarder would leave the DNS half
// of that signal silent, with everything else about it working.
func TestTheResolverHandsEveryNameToTrafficInspection(t *testing.T) {
	var asked []string
	rights := &fakeResolverRights{}
	runner := newSystemDNSRunner(quietLogger(), func(context.Context, func(string, ...any)) (tsnode.SystemDNSRights, error) {
		return rights, nil
	}, func(name string) { asked = append(asked, name) })
	t.Cleanup(func() { runner.close(context.Background()) })

	runner.apply(context.Background(), resolverTarget(t))
	runner.fwd.Answer(context.Background(), blockQuery(t, "one.tunnel.example"), false)

	if len(asked) != 1 || asked[0] != "one.tunnel.example" {
		t.Errorf("inspection was handed %v, want the one name the resolver was asked about", asked)
	}
}

// The way in is bind first, override second, because a machine pointed at an address nothing
// is listening on resolves nothing at all. The way out is the mirror of it: put the machine
// back, then stop answering. Reversed, every switch-off opens that same window for as long as
// the restore takes -- seconds per network service on Windows -- and an app killed inside it
// leaves the override standing.
func TestTheMachineIsPutBackBeforeTheSocketsItPointsAtClose(t *testing.T) {
	rights := &fakeResolverRights{}
	runner := newResolverRunner(t, rights)
	rights.runner = runner
	ctx := context.Background()

	runner.apply(ctx, resolverTarget(t))
	if !runner.snapshot().applied {
		t.Fatal("the override never went in, so there is no way out to test")
	}

	runner.apply(ctx, systemDNSTarget{reason: "the machine-wide resolver is switched off"})

	if !rights.servingAtRestore {
		t.Error("app-tail had already stopped answering DNS when it put the machine back, so nothing on this machine resolved anything in between")
	}
	steps := rights.steps()
	restore, closed := slices.Index(steps, "restore"), slices.Index(steps, "close")
	if restore < 0 || closed < 0 || restore > closed {
		t.Errorf("the machine was driven %v, want the override taken off before the claim was given up", steps)
	}
}

// An override that only partly landed is the worst of both: some services resolve through a
// forwarder this pass never finished configuring, and the runner reports the machine as
// untouched -- which is what sends app-tail's own lookups back through the machine resolver,
// into the half-configured forwarder, asking itself.
func TestAnOverrideThatOnlyPartlyLandedIsUndone(t *testing.T) {
	rights := &fakeResolverRights{applyErr: errors.New("one network service refused the change")}
	runner := newResolverRunner(t, rights)
	rights.runner = runner

	runner.apply(context.Background(), resolverTarget(t))

	snap := runner.snapshot()
	if snap.applied {
		t.Fatal("the override is reported as installed although the machine refused it")
	}
	if snap.failure == "" {
		t.Error("nothing was reported about a failed override, so the card says the feature is simply off")
	}
	steps := rights.steps()
	apply, restore := slices.Index(steps, "apply"), slices.Index(steps, "restore")
	if restore < 0 || restore < apply {
		t.Errorf("the machine was driven %v, want what landed taken back off after the failure", steps)
	}
}

// The undo can fail too, and then the machine is in the one state the card most needs to
// describe: some services pointed at app-tail, the override reported as not installed, and
// nothing that will put them back until the next pass. Both failures are named.
func TestAnUndoThatAlsoFailedIsNamedBesideTheFailureItWasUndoing(t *testing.T) {
	rights := &fakeResolverRights{
		applyErr:   errors.New("one network service refused the change"),
		restoreErr: errors.New("and another refused to be put back"),
	}
	runner := newResolverRunner(t, rights)

	runner.apply(context.Background(), resolverTarget(t))

	snap := runner.snapshot()
	if snap.applied {
		t.Fatal("the override is reported as installed although the machine refused it")
	}
	for _, said := range []string{"refused the change", "refused to be put back"} {
		if !strings.Contains(snap.failure, said) {
			t.Errorf("failure = %q, want it to say %q", snap.failure, said)
		}
		if !strings.Contains(snap.reason, said) {
			t.Errorf("reason = %q, want it to say %q", snap.reason, said)
		}
	}
}

// A base list that went unreadable for one pass is a network in the middle of changing.
// Dropping the network's own resolvers for it would send this machine's private names to a
// public resolver, so the last list read is kept, and the failure is on the card until the
// next pass reads one.
func TestABaseThatCannotBeReadForOnePassKeepsTheLastOneRead(t *testing.T) {
	rights := &fakeResolverRights{base: tsnode.BaseResolvers{
		Nameservers:   []netip.Addr{netip.MustParseAddr("192.168.6.1")},
		SearchDomains: []string{"lan"},
	}}
	runner := newResolverRunner(t, rights)
	target := resolverTarget(t)
	runner.apply(context.Background(), target)

	rights.baseBecomes(tsnode.BaseResolvers{}, errors.New("the network service list could not be read"))
	runner.apply(context.Background(), target)

	snap := runner.snapshot()
	if !snap.applied {
		t.Fatal("one unreadable pass took the override off a machine that was resolving fine")
	}
	if got := snap.base.Nameservers; len(got) != 1 || got[0] != netip.MustParseAddr("192.168.6.1") {
		t.Errorf("base = %v, want the last list read kept", got)
	}
	if !strings.Contains(snap.failure, "could not be read") {
		t.Errorf("failure = %q, want the unreadable base named on the card", snap.failure)
	}

	rights.baseBecomes(tsnode.BaseResolvers{Nameservers: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}, nil)
	runner.apply(context.Background(), target)

	snap = runner.snapshot()
	if snap.failure != "" {
		t.Errorf("failure = %q after the base read again, want it cleared", snap.failure)
	}
	if got := snap.base.Nameservers; len(got) != 1 || got[0] != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("base = %v, want the list the network now publishes", got)
	}
}

// A changed listen address is a different socket, and the machine is pointed at it while
// the old one is still answering: closed first, the old one would leave the machine pointed
// at an address nothing answers on for as long as rewriting its resolver setting takes. It
// is closed once the machine has moved.
func TestAChangedListenAddressRebindsAndRepointsTheMachine(t *testing.T) {
	rights := &fakeResolverRights{}
	runner := newResolverRunner(t, rights)
	target := resolverTarget(t)
	runner.apply(context.Background(), target)
	first := runner.snapshot().listen

	var answeredAtApply atomic.Bool
	rights.mu.Lock()
	rights.observe = func(step string) {
		if step == "dns apply" {
			answeredAtApply.Store(answersDNS(t, netip.MustParseAddrPort(first)))
		}
	}
	rights.mu.Unlock()
	target.listen = netip.MustParseAddrPort("127.0.0.154:53")
	runner.apply(context.Background(), target)

	if !answeredAtApply.Load() {
		t.Error("the old socket was not answering when the machine was pointed away from it, so every name on the machine failed while its setting was rewritten")
	}

	if got := rights.steps(); !slices.Equal(got, []string{"open", "apply", "open", "apply"}) {
		t.Errorf("the machine was driven %v, want the sockets rebound and the machine repointed", got)
	}
	second := runner.snapshot().listen
	if second == "" || second == first {
		t.Errorf("listening on %q after the address changed, want a different socket from %q", second, first)
	}
	rights.mu.Lock()
	applied := slices.Clone(rights.applied)
	rights.mu.Unlock()
	if len(applied) != 2 || applied[1][0].String() != netip.MustParseAddrPort(second).Addr().String() {
		t.Errorf("the machine was pointed at %v, want the new socket's address last", applied)
	}
	waitFor(t, 5*time.Second, "the first socket to be closed", func() bool {
		return atomic.LoadInt32(&rights.closed) > 0
	})
}

// What this machine cached came from the answers of the last pass, and a browser with a
// DNS client of its own lets go of its cache only when the resolver address it was
// configured with changes. So every change to what a name is answered with moves the
// machine to the other of two addresses; without it, switching the profile or the
// blocklist off leaves every name the browser already looked up answered the old way.
func TestAChangeOfAnswersMovesTheMachineToTheOtherAddress(t *testing.T) {
	google, ok := dnsprofiles.ByID(nil, "google")
	if !ok {
		t.Fatal("the shipped google profile is missing")
	}
	tests := []struct {
		name   string
		change func(*systemDNSTarget)
	}{
		{"the profile is switched", func(tg *systemDNSTarget) { tg.profile = google }},
		{"the blocklist is switched off", func(tg *systemDNSTarget) { tg.blocking = 0 }},
		{"the blocklist is compiled anew", func(tg *systemDNSTarget) { tg.blocking = 2 }},
		{"a blocked name is answered differently", func(tg *systemDNSTarget) { tg.rules.BlockAnswer = dnsfwd.AnswerRefused }},
		{"retrying on NXDOMAIN is switched", func(tg *systemDNSTarget) { tg.retry = true }},
		{"a suffix is sent to the network's own resolvers", func(tg *systemDNSTarget) { tg.rules.LocalSuffixes = []string{"corp"} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rights := &fakeResolverRights{}
			runner := newResolverRunner(t, rights)
			target := resolverTarget(t)
			target.blocking = 1
			runner.apply(context.Background(), target)
			before := pointedAt(t, rights)

			tc.change(&target)
			runner.apply(context.Background(), target)

			after := pointedAt(t, rights)
			if after == before {
				t.Fatalf("the machine stayed on %s, so what it cached from the old answers is still what it gets", after)
			}
			if listen := runner.snapshot().listen; netip.MustParseAddrPort(listen).Addr() != after {
				t.Errorf("the card says app-tail answers on %s while the machine is pointed at %s", listen, after)
			}
		})
	}
}

// The machine moves between two addresses rather than onto a new one each time, and both keep
// answering: a program that read the resolver setting before the move still asks the old one,
// and gets the new answers there too.
func TestTheMachineMovesBetweenTwoAddressesThatBothAnswer(t *testing.T) {
	google, ok := dnsprofiles.ByID(nil, "google")
	if !ok {
		t.Fatal("the shipped google profile is missing")
	}
	rights := &fakeResolverRights{}
	runner := newResolverRunner(t, rights)
	ctx := context.Background()
	target := resolverTarget(t)
	cloudflare := target.profile

	runner.apply(ctx, target)
	first := netip.MustParseAddrPort(runner.snapshot().listen)
	target.profile = google
	runner.apply(ctx, target)
	second := netip.MustParseAddrPort(runner.snapshot().listen)

	if second.Addr() == first.Addr() {
		t.Fatalf("both passes pointed the machine at %s", first.Addr())
	}
	for _, at := range []netip.AddrPort{first, second} {
		if !answersDNS(t, at) {
			t.Errorf("nothing answers on %s, where programs that read the setting before the move still ask", at)
		}
	}

	runner.apply(ctx, target)
	if got := pointedAt(t, rights); got != second.Addr() {
		t.Errorf("a pass that changed nothing moved the machine from %s to %s", second.Addr(), got)
	}

	target.profile = cloudflare
	runner.apply(ctx, target)
	if got := pointedAt(t, rights); got != first.Addr() {
		t.Errorf("switching back pointed the machine at %s, want the first address %s again", got, first.Addr())
	}
	if opens := countSteps(rights, "open"); opens != 2 {
		t.Errorf("the DNS sockets were opened %d times across three changes, want the two addresses opened once each", opens)
	}
}

// Only the address the machine is pointed at has to answer for it to resolve. The other one
// failing costs the next move a socket, not this machine its DNS.
func TestAnIdleAddressThatStopsAnsweringLeavesTheMachineResolving(t *testing.T) {
	google, ok := dnsprofiles.ByID(nil, "google")
	if !ok {
		t.Fatal("the shipped google profile is missing")
	}
	tests := []struct {
		name string
		// moves is how many changes of answers come before the failure, which decides whether
		// the idle address is the listen address or the second one.
		moves int
	}{
		{"the listen address, while the machine is on the second", 1},
		{"the second address, while the machine is on the listen address", 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rights := &fakeResolverRights{}
			runner := newResolverRunner(t, rights)
			ctx := context.Background()
			target := resolverTarget(t)
			profiles := []config.DNSProfile{target.profile, google}
			runner.apply(ctx, target)
			var idle netip.AddrPort
			for i := 1; i <= tc.moves; i++ {
				idle = netip.MustParseAddrPort(runner.snapshot().listen)
				target.profile = profiles[i%2]
				runner.apply(ctx, target)
			}
			using := netip.MustParseAddrPort(runner.snapshot().listen)

			runner.serve(ctx, idle, "packet", func() error { return errors.New("the socket was closed under us") })

			if !answersDNS(t, using) {
				t.Fatalf("nothing answers on %s, the address this machine is pointed at, after %s failed", using, idle)
			}
			if runner.needsAnotherPass() {
				t.Error("a resolver still answering where the machine points asked to be rebuilt")
			}
			if failure := runner.snapshot().failure; !strings.Contains(failure, idle.String()) {
				t.Errorf("failure = %q, want the address that stopped answering named", failure)
			}
			waitFor(t, 5*time.Second, "the socket that failed to be closed", func() bool {
				return !answersDNS(t, idle)
			})

			target.profile = profiles[(tc.moves+1)%2]
			runner.apply(ctx, target)
			moved := netip.MustParseAddrPort(runner.snapshot().listen)
			if moved.Addr() == using.Addr() || pointedAt(t, rights) != moved.Addr() {
				t.Fatalf("the next change left the machine on %s with app-tail on %s, want both on another address", pointedAt(t, rights), moved)
			}
			if moved == idle || !answersDNS(t, moved) {
				t.Errorf("the machine moved to %s, want a socket that answers in place of %s", moved, idle)
			}
		})
	}
}

// Moving the machine rewrites the resolver of every network service, which takes seconds and
// is visible to every program on it. A pass whose changes answer no name differently has
// nothing for a cache to drop, and moves nothing.
func TestAChangeThatAnswersEveryNameAsBeforeLeavesTheMachineWhereItIs(t *testing.T) {
	rights := &fakeResolverRights{}
	runner := newResolverRunner(t, rights)
	ctx := context.Background()
	target := resolverTarget(t)
	runner.apply(ctx, target)
	before := pointedAt(t, rights)

	// What a blocked name is answered with, while nothing is blocked.
	target.rules.BlockAnswer = dnsfwd.AnswerRefused
	runner.apply(ctx, target)
	// The network's own resolvers, which the system drops its caches for by itself.
	rights.baseBecomes(tsnode.BaseResolvers{Nameservers: []netip.Addr{netip.MustParseAddr("192.168.1.1")}}, nil)
	runner.apply(ctx, target)

	if after := pointedAt(t, rights); after != before {
		t.Errorf("the machine was moved from %s to %s by passes that answer every name as before", before, after)
	}
	if opens := countSteps(rights, "open"); opens != 1 {
		t.Errorf("the DNS sockets were opened %d times, want once", opens)
	}
}

// A second address that is out of reach costs the move and nothing else: the machine keeps
// resolving through app-tail with the new answers, and the card says that programs answer
// from what they cached until it expires, which is the one thing the user would otherwise
// see with no explanation.
func TestASecondAddressOutOfReachKeepsTheMachineResolvingAndSaysWhy(t *testing.T) {
	tests := []struct {
		name  string
		setUp func(*fakeResolverRights)
		want  string
	}{
		{"it cannot be opened", func(f *fakeResolverRights) { f.laterOpenErr = errors.New("every address is taken") }, "every address is taken"},
		{"it lands on the address in use", func(f *fakeResolverRights) { f.oneAddress = true }, "already uses"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rights := &fakeResolverRights{}
			runner := newResolverRunner(t, rights)
			ctx := context.Background()
			target := resolverTarget(t)
			target.blocking = 1
			runner.apply(ctx, target)
			before := netip.MustParseAddrPort(runner.snapshot().listen)
			rights.mu.Lock()
			tc.setUp(rights)
			rights.mu.Unlock()

			target.blocking = 0
			runner.apply(ctx, target)

			snap := runner.snapshot()
			if !snap.applied {
				t.Fatalf("the override was dropped because a second address was out of reach: %q", snap.reason)
			}
			if got := pointedAt(t, rights); got != before.Addr() {
				t.Errorf("the machine was pointed at %s, want it left on %s", got, before.Addr())
			}
			if !answersDNS(t, before) {
				t.Errorf("nothing answers on %s, where the machine still points", before)
			}
			if !strings.Contains(snap.failure, "cached") || !strings.Contains(snap.failure, tc.want) {
				t.Errorf("failure = %q, want it to say programs answer from their caches and why (%q)", snap.failure, tc.want)
			}
			if runner.needsAnotherPass() {
				t.Error("a move that could not happen asked for another pass, which would keep the ladder awake over a cache that expires by itself")
			}

			runner.apply(ctx, target)
			if got := runner.snapshot().failure; got != "" {
				t.Errorf("failure = %q on a pass that changed nothing, want the note gone", got)
			}
		})
	}
}

// Both notes reach the card when a pass has two things to say: the network's own resolvers
// could not be read, and the machine could not be moved.
func TestAMoveThatCouldNotHappenIsNamedBesideAnotherFailure(t *testing.T) {
	rights := &fakeResolverRights{}
	runner := newResolverRunner(t, rights)
	ctx := context.Background()
	target := resolverTarget(t)
	target.blocking = 1
	runner.apply(ctx, target)
	rights.mu.Lock()
	rights.laterOpenErr = errors.New("every address is taken")
	rights.mu.Unlock()
	rights.baseBecomes(tsnode.BaseResolvers{}, errors.New("the network service is mid-change"))

	target.blocking = 0
	runner.apply(ctx, target)

	failure := runner.snapshot().failure
	for _, want := range []string{"mid-change", "every address is taken"} {
		if !strings.Contains(failure, want) {
			t.Errorf("failure = %q, want it to carry %q", failure, want)
		}
	}
}

// A new listen address that cannot be opened leaves the machine on the socket it already
// uses, which keeps answering, and the pass is retried: the address may come free.
func TestAListenAddressThatCannotBeOpenedLeavesTheMachineOnTheOldOne(t *testing.T) {
	rights := &fakeResolverRights{}
	runner := newResolverRunner(t, rights)
	ctx := context.Background()
	target := resolverTarget(t)
	runner.apply(ctx, target)
	first := netip.MustParseAddrPort(runner.snapshot().listen)
	rights.mu.Lock()
	rights.laterOpenErr = errors.New("the address is taken")
	rights.mu.Unlock()

	target.listen = netip.MustParseAddrPort("127.0.0.154:53")
	runner.apply(ctx, target)

	if got := rights.steps(); !slices.Equal(got, []string{"open", "apply", "open"}) {
		t.Errorf("the machine was driven %v, want it left alone once the new socket failed", got)
	}
	if !answersDNS(t, first) {
		t.Fatalf("nothing answers on %s, where the machine still points", first)
	}
	if reason := runner.snapshot().reason; !strings.Contains(reason, "the address is taken") {
		t.Errorf("reason = %q, want the failed listen named", reason)
	}
	if !runner.needsAnotherPass() {
		t.Error("a listen address that could not be opened asked for no other pass")
	}

	rights.mu.Lock()
	rights.laterOpenErr = nil
	rights.mu.Unlock()
	runner.apply(ctx, target)

	listen := netip.MustParseAddrPort(runner.snapshot().listen)
	if listen == first || pointedAt(t, rights) != listen.Addr() {
		t.Errorf("after the address came free the machine is on %s and app-tail listens on %s, want both on a new socket", pointedAt(t, rights), listen)
	}
	waitFor(t, 5*time.Second, "the socket the machine left to stop answering", func() bool {
		return !answersDNS(t, first)
	})
}

// A resolver that stopped answering is rebuilt from nothing on the next pass. When that
// rebuild cannot open a socket, nothing of it is left behind: the next pass starts clean.
func TestARebuildThatCannotOpenASocketLeavesNothingBehind(t *testing.T) {
	rights := &fakeResolverRights{}
	runner := newResolverRunner(t, rights)
	ctx := context.Background()
	target := resolverTarget(t)
	runner.apply(ctx, target)
	runner.serve(ctx, netip.MustParseAddrPort(runner.snapshot().listen), "packet", func() error { return errors.New("the socket was closed under us") })
	rights.mu.Lock()
	rights.laterOpenErr = errors.New("the address is taken")
	rights.mu.Unlock()

	runner.apply(ctx, target)

	if runner.fwd != nil {
		t.Error("a forwarder with no socket was kept, so the next pass would build on nothing")
	}
	if reason := runner.snapshot().reason; !strings.Contains(reason, "the address is taken") {
		t.Errorf("reason = %q, want the failed listen named", reason)
	}
	if !runner.needsAnotherPass() {
		t.Error("a resolver with no socket asked for no other pass")
	}

	rights.mu.Lock()
	rights.laterOpenErr = nil
	rights.mu.Unlock()
	runner.apply(ctx, target)
	if at := runner.snapshot().listen; at == "" || !answersDNS(t, netip.MustParseAddrPort(at)) {
		t.Errorf("nothing answers on %q after the address came free", at)
	}
}

// A listen setting changed to the second address app-tail already answers on reuses that
// socket rather than asking for the address again, which the helper would refuse while
// app-tail holds it.
func TestAListenAddressAppTailAlreadyAnswersOnIsReused(t *testing.T) {
	rights := &fakeResolverRights{}
	runner := newResolverRunner(t, rights)
	ctx := context.Background()
	target := resolverTarget(t)
	target.blocking = 1
	runner.apply(ctx, target)
	first := netip.MustParseAddrPort(runner.snapshot().listen)
	target.blocking = 0
	runner.apply(ctx, target)
	second := netip.MustParseAddrPort(runner.snapshot().listen)
	// Pointed back at the first address, so the setting names the one the machine is not on.
	target.blocking = 1
	runner.apply(ctx, target)
	if got := pointedAt(t, rights); got != first.Addr() {
		t.Fatalf("the machine is on %s, want it back on %s before the setting changes", got, first.Addr())
	}

	target.listen = second
	runner.apply(ctx, target)

	if opens := countSteps(rights, "open"); opens != 2 {
		t.Errorf("the DNS sockets were opened %d times, want the second address reused", opens)
	}
	if got := pointedAt(t, rights); got != second.Addr() {
		t.Errorf("the machine was pointed at %s, want the address the setting names, %s", got, second.Addr())
	}
	waitFor(t, 5*time.Second, "the socket the machine left to stop answering", func() bool {
		return !answersDNS(t, first)
	})
}

// A listen address changed while the machine is on the second address is still where the
// machine goes: the second address is app-tail's own choice, and the setting is the user's.
func TestAChangedListenAddressWinsOverTheSecondAddress(t *testing.T) {
	rights := &fakeResolverRights{}
	runner := newResolverRunner(t, rights)
	ctx := context.Background()
	target := resolverTarget(t)
	target.blocking = 1
	runner.apply(ctx, target)
	target.blocking = 0
	runner.apply(ctx, target)
	spare := netip.MustParseAddrPort(runner.snapshot().listen)

	target.listen = netip.MustParseAddrPort("127.0.0.154:53")
	runner.apply(ctx, target)

	listen := netip.MustParseAddrPort(runner.snapshot().listen)
	if listen == spare {
		t.Fatalf("the machine stayed on %s after the listen address changed", spare)
	}
	if got := pointedAt(t, rights); got != listen.Addr() {
		t.Errorf("the machine was pointed at %s, want the socket opened for the new setting on %s", got, listen)
	}
	waitFor(t, 5*time.Second, "the socket the machine left to stop answering", func() bool {
		return !answersDNS(t, spare)
	})
}

// pointedAt is the address the machine was pointed at last.
func pointedAt(t *testing.T, rights *fakeResolverRights) netip.Addr {
	t.Helper()
	rights.mu.Lock()
	defer rights.mu.Unlock()
	if len(rights.applied) == 0 || len(rights.applied[len(rights.applied)-1]) != 1 {
		t.Fatalf("the machine was pointed at %v, want one address per pass", rights.applied)
	}
	return rights.applied[len(rights.applied)-1][0]
}

func countSteps(rights *fakeResolverRights, step string) int {
	n := 0
	for _, s := range rights.steps() {
		if s == step {
			n++
		}
	}
	return n
}

// answersDNS reports whether a resolver on at answers a query for localhost, which the
// forwarder answers itself and so needs nothing upstream.
func answersDNS(t *testing.T, at netip.AddrPort) bool {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(at))
	if err != nil {
		t.Fatalf("dial %s: %v", at, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set a deadline on the query to %s: %v", at, err)
	}
	if _, err := conn.Write(blockQuery(t, "localhost")); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}
	var p dnsmessage.Parser
	h, err := p.Start(buf[:n])
	return err == nil && h.Response && h.ID == 1
}

// A serve loop that stops on its own leaves the machine pointed at a socket nobody is reading:
// the override stands and every name on this machine resolves to nothing. The reconcile loop
// is event-driven, so unless something counts this as down, no timer is ever armed and an idle
// machine stays that way until the user notices.
func TestAResolverThatStoppedAnsweringAsksForAnotherPass(t *testing.T) {
	rights := &fakeResolverRights{}
	runner := newResolverRunner(t, rights)
	ctx := context.Background()

	runner.apply(ctx, resolverTarget(t))
	if runner.needsAnotherPass() {
		t.Fatal("a resolver that is answering asked for another pass, which would keep the ladder awake forever")
	}

	// What a socket closing underneath the forwarder does.
	runner.serve(ctx, netip.MustParseAddrPort(runner.snapshot().listen), "packet", func() error { return errors.New("the socket was closed under us") })

	if !runner.needsAnotherPass() {
		t.Fatal("a resolver that stopped answering asks for nothing, so nothing rebinds it")
	}

	h := newHarness(t, nil)
	h.agent.mu.Lock()
	h.agent.systemDNS = runner
	h.agent.mu.Unlock()
	if got := h.agent.downCount(); got != 1 {
		t.Errorf("the supervisor counts %d things down while this machine resolves nothing, want 1", got)
	}
}

// A profile whose resolver hostnames could not be looked up is the shape of starting before
// the network is up, and of a network that blocks the process for a moment. The reconcile loop
// is event-driven, so unless the failed override counts as down no timer is armed, and the
// card keeps the failure until the user changes a setting to shake it loose.
func TestAnOverrideThatCouldNotBePutUpAsksForAnotherPass(t *testing.T) {
	rights := &fakeResolverRights{applyErr: errors.New("the resolver service refused the change")}
	runner := newResolverRunner(t, rights)
	ctx := context.Background()

	runner.apply(ctx, resolverTarget(t))
	if runner.snapshot().applied {
		t.Fatal("the override is reported as installed although pointing the machine at it failed")
	}
	if !runner.needsAnotherPass() {
		t.Fatal("an override that failed to go up asks for nothing, so nothing tries again")
	}

	rights.mu.Lock()
	rights.applyErr = nil
	rights.mu.Unlock()
	runner.apply(ctx, resolverTarget(t))
	if !runner.snapshot().applied {
		t.Fatal("the pass after the cause cleared did not put the override up")
	}
	if runner.needsAnotherPass() {
		t.Error("an override that is up still asks for another pass, which would keep the ladder awake forever")
	}

	// Switched off, there is nothing to come back for whatever the last attempt did.
	runner.apply(ctx, systemDNSTarget{reason: "switched off"})
	if runner.needsAnotherPass() {
		t.Error("an override that is switched off asks for another pass")
	}
}

// Rights this process does not have are not something a timer changes: the elevation flow
// asks for a pass once it has them, and a ladder retrying the claim would be a password prompt
// every few seconds.
func TestAClaimThatWasRefusedDoesNotAskForAnotherPass(t *testing.T) {
	rights := &fakeResolverRights{openErr: errors.New("the request for administrator rights was declined")}
	runner := newResolverRunner(t, rights)

	runner.apply(context.Background(), resolverTarget(t))

	if runner.needsAnotherPass() {
		t.Fatal("a refused claim asks for another pass, which would prompt for rights again on a timer")
	}
}

// Quitting with an adapter switched off is an ordinary thing to do, and the restore that
// follows reaches every service except that one. Reporting it as a failed shutdown would exit
// non-zero and skip a restart the user asked for, over a machine that is as far back as it can
// be put and carries a record saying what is left.
func TestQuittingWithAnAdapterSwitchedOffIsStillAnOrdinaryQuit(t *testing.T) {
	partial := &sysdns.PartialRestoreError{Services: []string{"Ethernet"}}
	rights := &fakeResolverRights{restoreErr: partial}
	runner := newResolverRunner(t, rights)
	ctx := context.Background()

	runner.apply(ctx, resolverTarget(t))
	if !runner.snapshot().applied {
		t.Fatal("the override never went in, so there is no way out to test")
	}

	if err := runner.close(ctx); err != nil {
		t.Errorf("quitting reported %v, want a quit that succeeds and leaves the record to the next start", err)
	}
	if snap := runner.snapshot(); !strings.Contains(snap.failure, "Ethernet") {
		t.Errorf("the card says %q, want it to name the service still pointed at app-tail", snap.failure)
	}
}

// The other half: a restore that went wrong is not the recoverable state, and a shutdown that
// swallowed it would report a machine put back that is still pointed at app-tail.
func TestARestoreThatWentWrongStillFailsTheShutdown(t *testing.T) {
	rights := &fakeResolverRights{restoreErr: errors.New("the resolver settings could not be written")}
	runner := newResolverRunner(t, rights)
	ctx := context.Background()

	runner.apply(ctx, resolverTarget(t))
	if !runner.snapshot().applied {
		t.Fatal("the override never went in, so there is no way out to test")
	}

	err := runner.close(ctx)
	if err == nil {
		t.Fatal("a restore that failed outright reported a clean shutdown, so nothing says this machine is still pointed at app-tail")
	}
	if !strings.Contains(err.Error(), "could not be written") {
		t.Errorf("the shutdown reported %v, want it to carry what went wrong", err)
	}
	// The failure does not stop the rest of the teardown: the sockets go and the claim on the
	// machine is released, or the port stays held and the next start cannot take it. The
	// serve loops close the sockets after being told to, so the close is waited for.
	waitFor(t, 5*time.Second, "the resolver socket to be closed after a shutdown whose restore failed", func() bool {
		return atomic.LoadInt32(&rights.closed) > 0
	})
	if steps := rights.steps(); !slices.Contains(steps, "close") || slices.Index(steps, "restore") > slices.Index(steps, "close") {
		t.Errorf("the claim on the machine was not released after the restore failed; the teardown ran %v", steps)
	}
	if snap := runner.snapshot(); snap.applied || !strings.Contains(snap.failure, "could not be written") {
		t.Errorf("snapshot = applied %t, failure %q; want it unapplied and naming what went wrong", snap.applied, snap.failure)
	}
}
