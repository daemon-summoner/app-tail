// SPDX-License-Identifier: MIT

package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
)

func dnsRoutes(t *testing.T, view httpapi.DNSView) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"GET /api/dns": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, view)
		},
	}
}

// servingDNSView is a tailnet publishing everything the panel can show, on a machine
// app-tail does not configure -- which is every machine in the mode it ships in.
func servingDNSView() httpapi.DNSView {
	return httpapi.DNSView{
		Enabled: true, Using: true, MagicDNS: true,
		Resolvers:     []string{"100.100.100.100"},
		SearchDomains: []string{"tail1a2b3c.ts.net"},
		Routes:        []httpapi.DNSRouteView{{Suffix: "corp.example.com", Resolvers: []string{"10.0.0.53"}}},
		Records:       []httpapi.DNSRecordView{{Name: "wiki", Type: "A", Value: "100.64.0.9"}},
		MachineReason: "app-tail does not change how this machine resolves names.",
		Capability: httpapi.Capability{
			Available: true,
			Limits: []string{
				"Only app-tail's own connections use your tailnet's DNS.",
			},
		},
	}
}

// The sentence about the rest of the machine is the whole point of this command: the user
// running it is looking at a browser that will not resolve a name their tailnet serves.
func TestDNSSaysWhatItDoesNotChangeAboutTheMachine(t *testing.T) {
	h := newHarness(t, dnsRoutes(t, servingDNSView()))

	if err := Run(t.Context(), append([]string{"dns"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("dns: %v", err)
	}
	out := h.out()
	if !strings.Contains(out, "does not change how this machine resolves names") {
		t.Errorf("dns output never says the machine is untouched:\n%s", out)
	}
	if !strings.Contains(out, "Only app-tail's own connections") {
		t.Errorf("dns output drops the stated limits:\n%s", out)
	}
}

// Split DNS is the case someone runs this command about: a suffix pointed at a private
// nameserver that resolves for app-tail and nowhere else.
func TestDNSShowsTheSplitDNSSuffixesAndWhoAnswersForThem(t *testing.T) {
	h := newHarness(t, dnsRoutes(t, servingDNSView()))

	if err := Run(t.Context(), append([]string{"dns"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("dns: %v", err)
	}
	out := h.out()
	for _, want := range []string{"corp.example.com", "10.0.0.53", "100.100.100.100", "wiki"} {
		if !strings.Contains(out, want) {
			t.Errorf("dns output is missing %q:\n%s", want, out)
		}
	}
}

// A suffix with no nameserver of its own is answered by the tailnet's own resolver, and
// printing a blank there reads as a configuration that failed to load.
func TestDNSNamesWhoAnswersASuffixWithNoResolverOfItsOwn(t *testing.T) {
	view := servingDNSView()
	view.Routes = []httpapi.DNSRouteView{{Suffix: "corp.example.com"}}
	h := newHarness(t, dnsRoutes(t, view))

	if err := Run(t.Context(), append([]string{"dns"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("dns: %v", err)
	}
	if !strings.Contains(h.out(), "your tailnet's own resolver") {
		t.Errorf("dns output leaves the answering resolver blank:\n%s", h.out())
	}
}

// Resolving through the exit node is the property people choose an exit node for, and it
// is named rather than flagged so they know which device is doing it.
func TestDNSNamesTheExitNodeWhenItIsAnsweringLookups(t *testing.T) {
	view := servingDNSView()
	view.ExitNodeResolving = true
	view.ExitNodeLabel = "mullvad-berlin"
	h := newHarness(t, dnsRoutes(t, view))

	if err := Run(t.Context(), append([]string{"dns"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("dns: %v", err)
	}
	if !strings.Contains(h.out(), "mullvad-berlin") {
		t.Errorf("dns output does not name the device answering lookups:\n%s", h.out())
	}
}

// The half a user cannot see any other way. On a machine app-tail did configure, what it
// wrote is exactly the thing worth auditing, and which suffixes it sends to the tailnet is
// what decides whether a name resolves through the tailnet or past it.
func TestDNSShowsWhatThisMachineItselfResolvesWith(t *testing.T) {
	view := servingDNSView()
	view.MachineReason = ""
	view.Machine = &httpapi.DNSMachineView{
		Nameservers:  []string{"100.100.100.100", "1.1.1.1"},
		MatchDomains: []string{"corp.example.com"},
	}
	h := newHarness(t, dnsRoutes(t, view))

	if err := Run(t.Context(), append([]string{"dns"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("dns: %v", err)
	}
	out := h.out()
	if !strings.Contains(out, "This machine's nameservers") || !strings.Contains(out, "1.1.1.1") {
		t.Errorf("dns output does not say what this machine resolves with:\n%s", out)
	}
	if !strings.Contains(out, "Sent to your tailnet") {
		t.Errorf("dns output does not say which suffixes go to the tailnet:\n%s", out)
	}
}

func TestDNSSaysHowToTurnTheModuleOn(t *testing.T) {
	h := newHarness(t, dnsRoutes(t, httpapi.DNSView{}))

	if err := Run(t.Context(), append([]string{"dns"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("dns: %v", err)
	}
	if !strings.Contains(h.out(), "settings set dns true") {
		t.Errorf("dns output does not say how to turn the module on:\n%s", h.out())
	}
}

func TestDNSAsJSONIsTheAgentsOwnAnswer(t *testing.T) {
	h := newHarness(t, dnsRoutes(t, servingDNSView()))

	if err := Run(t.Context(), append([]string{"dns"}, append(h.cfg(), "--json")...), h.env()); err != nil {
		t.Fatalf("dns --json: %v", err)
	}
	var got httpapi.DNSView
	if err := json.Unmarshal([]byte(h.out()), &got); err != nil {
		t.Fatalf("parse the JSON output: %v\n%s", err, h.out())
	}
	if !got.Using || len(got.Routes) != 1 {
		t.Errorf("JSON output = %+v, want the agent's own view", got)
	}
}

// A positional argument that fell through silently would print the status view and look
// like it did what was typed.
func TestDNSChecksItsArguments(t *testing.T) {
	h := newHarness(t, dnsRoutes(t, servingDNSView()))

	err := Run(t.Context(), append([]string{"dns", "frobnicate"}, h.cfg()...), h.env())

	if !errors.Is(err, ErrUsage) {
		t.Fatalf("dns frobnicate = %v, want a usage error:\n%s", err, h.out())
	}
	if !strings.Contains(err.Error(), "frobnicate") {
		t.Errorf("error %q does not name what was typed", err)
	}
	if len(h.recorded()) != 0 {
		t.Errorf("a refused subcommand still asked the agent: %+v", h.recorded())
	}
}

// systemDNSView is a machine resolving names through a chosen profile.
func systemDNSView() *httpapi.DNSSystemView {
	return &httpapi.DNSSystemView{
		Enabled: true, Applied: true, Ready: true,
		Profile: "cloudflare", ProfileLabel: "Cloudflare",
		Servers:   []string{"1.1.1.1", "1.0.0.1"},
		Protocols: []string{"plain"},
		Listen:    "127.0.0.153:53",
		Base:      &httpapi.DNSBaseView{Nameservers: []string{"192.168.6.1"}},
		Queries:   httpapi.DNSSystemStats{Total: 42, ToProfile: 39, ToLocal: 3},
	}
}

// catalogRoutes serves the resolver catalog and the settings write `dns use` makes.
//
// The write moves the served view the way the agent's own write does, waiting for the
// reconcile before it answers, and a machine that is not ready stays not applied. A fake
// that always reported the profile in force would make every `dns use` test agree with a
// command that only ever reports back what it asked for.
func catalogRoutes(t *testing.T, view httpapi.DNSView, profiles []config.DNSProfile) map[string]http.HandlerFunc {
	var mu sync.Mutex
	routes := map[string]http.HandlerFunc{
		"GET /api/dns": func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			writeJSONResponse(t, w, http.StatusOK, view)
		},
	}
	routes["GET /api/dns/profiles"] = func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(t, w, http.StatusOK, map[string]any{"profiles": profiles})
	}
	routes["PUT /api/settings"] = func(w http.ResponseWriter, r *http.Request) {
		var patch struct {
			Enabled *bool   `json:"systemDns.enabled"`
			Profile *string `json:"systemDns.profile"`
		}
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			t.Errorf("decode the settings patch: %v", err)
		}
		mu.Lock()
		if sys := view.System; sys != nil {
			if patch.Enabled != nil {
				sys.Enabled = *patch.Enabled
				sys.Applied = *patch.Enabled && sys.Ready
			}
			if patch.Profile != nil {
				sys.Profile = *patch.Profile
				sys.ProfileLabel, sys.Servers = "", nil
				for _, p := range profiles {
					if p.ID == *patch.Profile {
						sys.ProfileLabel, sys.Servers = p.Name, p.Servers
					}
				}
			}
		}
		mu.Unlock()
		writeJSONResponse(t, w, http.StatusOK, map[string]any{})
	}
	routes["POST /api/dns/profiles"] = func(w http.ResponseWriter, r *http.Request) {
		var p config.DNSProfile
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Errorf("decode the created profile: %v", err)
		}
		p.ID = "nextdns"
		writeJSONResponse(t, w, http.StatusCreated, p)
	}
	routes["DELETE /api/dns/profiles/{id}"] = func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(t, w, http.StatusNoContent, nil)
	}
	return routes
}

func userProfiles() []config.DNSProfile {
	return []config.DNSProfile{
		{ID: "system", Name: "System default", BuiltIn: true},
		{ID: "cloudflare", Name: "Cloudflare", Servers: []string{"1.1.1.1", "1.0.0.1"}, BuiltIn: true},
		{ID: "nextdns", Name: "NextDNS", Servers: []string{"https://dns.nextdns.io/abc123"}},
	}
}

// The half somebody runs this command about is the machine's own: a browser that will not
// load a site is why they are here, and the tailnet's configuration is the other question.
func TestDNSShowsThisMachinesResolverBesideTheTailnets(t *testing.T) {
	view := servingDNSView()
	view.System = systemDNSView()
	h := newHarness(t, dnsRoutes(t, view))

	if err := Run(t.Context(), append([]string{"dns"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("dns: %v", err)
	}
	out := h.out()
	for _, want := range []string{"Cloudflare", "1.1.1.1, 1.0.0.1", "127.0.0.153:53", "192.168.6.1"} {
		if !strings.Contains(out, want) {
			t.Errorf("dns output never mentions %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "Using your tailnet's DNS") {
		t.Errorf("dns output dropped the tailnet half:\n%s", out)
	}
}

// A network that redirects port 53 answers plain queries itself, so the profile is in force
// and none of the queries reached it. Every other line of this command reads as success,
// which is exactly why the one line that does not has to be printed.
func TestDNSSaysWhenThisNetworkIsAnsweringInsteadOfTheChosenResolver(t *testing.T) {
	sys := systemDNSView()
	sys.Intercepted = "This network answers plain DNS itself: a query addressed to a server that does not exist came back answered."
	h := newHarness(t, dnsRoutes(t, httpapi.DNSView{System: sys}))

	if err := Run(t.Context(), append([]string{"dns"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("dns: %v", err)
	}
	if out := h.out(); !strings.Contains(out, "answers plain DNS itself") {
		t.Errorf("dns reported a machine resolving through Cloudflare without saying this network answers instead:\n%s", out)
	}
}

// Which resolver turned a hostname into an address decided which server this machine is
// really talking to. A command that reports the profile and not that is reporting the choice
// the user made while leaving out the one made for them.
func TestDNSSaysWhatLookedUpAResolverNamedByHostname(t *testing.T) {
	sys := systemDNSView()
	sys.Bootstrap = "dns.nextdns.io was looked up through this network's own resolvers: Quad9 did not answer (timeout)."
	h := newHarness(t, dnsRoutes(t, httpapi.DNSView{System: sys}))

	if err := Run(t.Context(), append([]string{"dns"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("dns: %v", err)
	}
	if out := h.out(); !strings.Contains(out, "was looked up through this network's own resolvers") {
		t.Errorf("dns never says what resolved the profile's hostname:\n%s", out)
	}
}

// A profile whose resolvers come from the tailnet stores none of its own, so the command has
// to print the ones the agent reports. The stored list would be an empty pair of brackets
// beside a machine that is resolving through them right now.
func TestDNSUseNamesTheResolversTheAgentReportsForAProfileThatStoresNone(t *testing.T) {
	view := httpapi.DNSView{System: systemDNSView()}
	profiles := append(userProfiles(), config.DNSProfile{ID: "tailnet", Name: "Tailnet DNS", BuiltIn: true})
	routes := catalogRoutes(t, view, profiles)
	// The agent fills in what the tailnet publishes when the profile is applied, which the
	// stored catalog never carries.
	routes["PUT /api/settings"] = func(w http.ResponseWriter, _ *http.Request) {
		view.System.Profile = "tailnet"
		view.System.ProfileLabel = "Tailnet DNS"
		view.System.Servers = []string{"https://dns.nextdns.io/abc123"}
		writeJSONResponse(t, w, http.StatusOK, map[string]any{})
	}
	h := newHarness(t, routes)

	if err := Run(t.Context(), append([]string{"dns", "use", "tailnet"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("dns use tailnet: %v", err)
	}
	out := h.out()
	if !strings.Contains(out, "https://dns.nextdns.io/abc123") {
		t.Errorf("dns use never says what the machine now resolves through:\n%s", out)
	}
	if strings.Contains(out, "()") {
		t.Errorf("dns use printed an empty resolver list:\n%s", out)
	}
}

// The tailnet module being off used to end the command, which is the one user this feature
// exists for: somebody switching resolvers who never turned the tailnet's DNS on.
func TestDNSStillReportsTheMachineWhenTheTailnetModuleIsOff(t *testing.T) {
	h := newHarness(t, dnsRoutes(t, httpapi.DNSView{System: systemDNSView()}))

	if err := Run(t.Context(), append([]string{"dns"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("dns: %v", err)
	}
	out := h.out()
	if !strings.Contains(out, "Cloudflare") {
		t.Errorf("dns went silent about the machine's own resolver:\n%s", out)
	}
	if !strings.Contains(out, "settings set dns true") {
		t.Errorf("dns output does not say how to turn the tailnet module on:\n%s", out)
	}
}

// Switching resolvers is what this whole feature is for, and it is one write: the profile
// is refused while the switch that governs it is off, so both keys travel together.
func TestDNSUseSwitchesTheMachineInOneWrite(t *testing.T) {
	h := newHarness(t, catalogRoutes(t, httpapi.DNSView{System: systemDNSView()}, userProfiles()))

	if err := Run(t.Context(), append([]string{"dns", "use"}, append(h.cfg(), "nextdns")...), h.env()); err != nil {
		t.Fatalf("dns use: %v", err)
	}

	writes := 0
	for _, req := range h.recorded() {
		if req.Method != http.MethodPut || req.Path != "/api/settings" {
			continue
		}
		writes++
		var patch map[string]json.RawMessage
		if err := json.Unmarshal([]byte(req.Body), &patch); err != nil {
			t.Fatalf("parse the settings patch %q: %v", req.Body, err)
		}
		if string(patch["systemDns.enabled"]) != "true" {
			t.Errorf("the patch left the module at %s, so the profile would be refused", patch["systemDns.enabled"])
		}
		if string(patch["systemDns.profile"]) != `"nextdns"` {
			t.Errorf("the patch names %s, want the profile that was asked for", patch["systemDns.profile"])
		}
	}
	if writes != 1 {
		t.Errorf("the switch took %d writes, want one", writes)
	}
}

// A profile is named by whatever the user calls it, and matching only on ids would make
// every command in the documentation an id lookup first.
func TestDNSUseAcceptsTheNameTheUserGaveTheProfile(t *testing.T) {
	h := newHarness(t, catalogRoutes(t, httpapi.DNSView{System: systemDNSView()}, userProfiles()))

	if err := Run(t.Context(), append([]string{"dns", "use"}, append(h.cfg(), "nextdns")...), h.env()); err != nil {
		t.Fatalf("dns use by name: %v", err)
	}
	if !strings.Contains(h.out(), "dns.nextdns.io") {
		t.Errorf("the confirmation does not say what this machine now resolves through:\n%s", h.out())
	}
}

// System default is the undo, so it has to leave the settings looking like a machine that
// never used the feature rather than one switched on doing nothing.
func TestDNSUseSystemDefaultSwitchesTheOverrideOff(t *testing.T) {
	h := newHarness(t, catalogRoutes(t, httpapi.DNSView{System: systemDNSView()}, userProfiles()))

	if err := Run(t.Context(), append([]string{"dns", "use"}, append(h.cfg(), "System default")...), h.env()); err != nil {
		t.Fatalf("dns use system: %v", err)
	}
	for _, req := range h.recorded() {
		if req.Method != http.MethodPut {
			continue
		}
		var patch map[string]json.RawMessage
		if err := json.Unmarshal([]byte(req.Body), &patch); err != nil {
			t.Fatalf("parse the settings patch %q: %v", req.Body, err)
		}
		if string(patch["systemDns.enabled"]) != "false" {
			t.Errorf("the patch left the module at %s, so this machine stays redirected", patch["systemDns.enabled"])
		}
		// The agent refuses a setting whose module the same write turns off, and turning it
		// off already puts the stored profile back to System default. Naming it here is a
		// refused write, which is the undo failing.
		if _, named := patch["systemDns.profile"]; named {
			t.Errorf("the undo names the profile as well as the switch: %s", req.Body)
		}
	}
	if !strings.Contains(h.out(), "resolves names the way it always did") {
		t.Errorf("the confirmation does not say the machine is back to normal:\n%s", h.out())
	}
}

// The write storing the choice is not the machine resolving through it. A machine whose
// administrator rights are not arranged stores the profile and keeps resolving exactly as
// before, and a confirmation that claimed otherwise would send somebody off debugging a site
// through a resolver they were never on.
func TestDNSUseDoesNotClaimAProfileThisMachineIsNotResolvingThrough(t *testing.T) {
	system := systemDNSView()
	system.Enabled, system.Applied, system.Ready = false, false, false
	system.NeedsSetup = true
	system.Blocker = "claim this machine's name resolution: the privileged helper is not installed"
	h := newHarness(t, catalogRoutes(t, httpapi.DNSView{System: system}, userProfiles()))

	err := Run(t.Context(), append([]string{"dns", "use"}, append(h.cfg(), "nextdns")...), h.env())
	if err == nil {
		t.Fatal("a switch that never reached this machine was reported as done")
	}
	if !strings.Contains(err.Error(), "the privileged helper is not installed") {
		t.Errorf("error = %v, which does not say what stands in the way", err)
	}
	if !strings.Contains(err.Error(), "dns setup") {
		t.Errorf("error = %v, which does not say how to arrange it", err)
	}
	out := h.out()
	if strings.Contains(out, "now resolves names through") {
		t.Errorf("the command claimed this machine switched resolvers:\n%s", out)
	}
	if !strings.Contains(out, "not resolving through it yet") {
		t.Errorf("the output does not say the profile was stored but is not in force:\n%s", out)
	}
}

// The undo has the same duty as the switch: a machine still pointed at app-tail after
// choosing System default is the failure this feature must never hide, because the user
// chose it to get their resolver back.
func TestDNSUseSystemDefaultSaysSoWhenTheMachineIsStillRedirected(t *testing.T) {
	routes := catalogRoutes(t, httpapi.DNSView{System: systemDNSView()}, userProfiles())
	// An agent that stored the choice and then could not put the machine's resolver back.
	routes["PUT /api/settings"] = func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(t, w, http.StatusOK, map[string]any{})
	}
	h := newHarness(t, routes)

	err := Run(t.Context(), append([]string{"dns", "use"}, append(h.cfg(), "system")...), h.env())
	if err == nil {
		t.Fatal("a machine still resolving through app-tail was reported as back to normal")
	}
	if !strings.Contains(err.Error(), "still pointed at app-tail") {
		t.Errorf("error = %v, which does not say the resolver is still redirected", err)
	}
	if strings.Contains(h.out(), "the way it always did") {
		t.Errorf("the command claimed the machine is back to normal:\n%s", h.out())
	}
}

// Pointing this machine's whole name resolution somewhere is not a command that guesses.
func TestDNSUseRefusesANameItCannotResolveToOneProfile(t *testing.T) {
	h := newHarness(t, catalogRoutes(t, httpapi.DNSView{System: systemDNSView()}, userProfiles()))

	err := Run(t.Context(), append([]string{"dns", "use"}, append(h.cfg(), "quad9")...), h.env())
	if err == nil {
		t.Fatal("a profile nobody has was accepted")
	}
	if !strings.Contains(err.Error(), "quad9") {
		t.Errorf("error = %v, which does not name what was typed", err)
	}
	for _, req := range h.recorded() {
		if req.Method == http.MethodPut {
			t.Errorf("a settings write went out for a profile that does not exist: %s", req.Body)
		}
	}
}

func TestDNSProfileAddSendsTheResolversInTheOrderTheyWereTyped(t *testing.T) {
	h := newHarness(t, catalogRoutes(t, httpapi.DNSView{System: systemDNSView()}, userProfiles()))

	err := Run(t.Context(), append([]string{"dns", "profile", "add"},
		append(h.cfg(), "--name", "NextDNS", "--servers", "https://dns.nextdns.io/abc123, 45.90.28.0")...), h.env())
	if err != nil {
		t.Fatalf("dns profile add: %v", err)
	}

	var sent config.DNSProfile
	for _, req := range h.recorded() {
		if req.Method == http.MethodPost && req.Path == "/api/dns/profiles" {
			if err := json.Unmarshal([]byte(req.Body), &sent); err != nil {
				t.Fatalf("parse the created profile %q: %v", req.Body, err)
			}
		}
	}
	want := []string{"https://dns.nextdns.io/abc123", "45.90.28.0"}
	if len(sent.Servers) != len(want) {
		t.Fatalf("servers = %v, want %v -- the order is the order they are tried in", sent.Servers, want)
	}
	for i := range want {
		if sent.Servers[i] != want[i] {
			t.Errorf("server %d = %q, want %q", i, sent.Servers[i], want[i])
		}
	}
	if !strings.Contains(h.out(), "dns use nextdns") {
		t.Errorf("the confirmation does not say how to switch to the profile just added:\n%s", h.out())
	}
}

// A built-in is the way back when a custom profile is what broke resolution, so the refusal
// happens here rather than as a round trip that could fail for some other reason.
func TestDNSProfileRemoveRefusesABuiltInWithoutAskingTheAgent(t *testing.T) {
	h := newHarness(t, catalogRoutes(t, httpapi.DNSView{System: systemDNSView()}, userProfiles()))

	err := Run(t.Context(), append([]string{"dns", "profile", "rm"}, append(h.cfg(), "cloudflare")...), h.env())
	if err == nil {
		t.Fatal("a built-in profile was removed")
	}
	if !strings.Contains(err.Error(), "built-in") {
		t.Errorf("error = %v, which does not say why it was refused", err)
	}
	for _, req := range h.recorded() {
		if req.Method == http.MethodDelete {
			t.Errorf("a delete went out for a built-in profile: %s", req.Path)
		}
	}
}

// The list is what somebody reads before switching, so the two facts that decide the next
// command have to be on it: which profiles exist, and which one this machine is on.
func TestDNSProfileListSaysWhichProfileTheMachineIsOn(t *testing.T) {
	view := httpapi.DNSView{System: systemDNSView()}
	h := newHarness(t, catalogRoutes(t, view, userProfiles()))

	if err := Run(t.Context(), append([]string{"dns", "profile", "list"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("dns profile list: %v", err)
	}

	out := h.out()
	for _, want := range []string{"NextDNS", "https://dns.nextdns.io/abc123", "built-in", "this machine's own"} {
		if !strings.Contains(out, want) {
			t.Errorf("the list never mentions %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "cloudflare") && !strings.HasSuffix(strings.TrimSpace(line), "yes"):
			t.Errorf("the profile in force is not marked as in use:\n%s", out)
		case strings.HasPrefix(line, "nextdns") && strings.HasSuffix(strings.TrimSpace(line), "yes"):
			t.Errorf("a profile that is not in force is marked as in use:\n%s", out)
		}
	}
}

// The module being off means no profile is in force, whatever the settings still name. A
// list that marked one anyway would send somebody looking for why their browser is not
// using it.
func TestDNSProfileListMarksNothingInUseWhileTheModuleIsOff(t *testing.T) {
	system := systemDNSView()
	system.Enabled, system.Applied = false, false
	h := newHarness(t, catalogRoutes(t, httpapi.DNSView{System: system}, userProfiles()))

	if err := Run(t.Context(), append([]string{"dns", "profile", "list"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("dns profile list: %v", err)
	}

	for _, line := range strings.Split(h.out(), "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), "yes") {
			t.Errorf("a profile is marked in use while the module is off:\n%s", h.out())
		}
	}
}

// The agent replaces the profile wholesale, so an edit of one field has to send the others
// back unchanged. Sending only --servers and having the name cleared is the failure this
// pins, and it is invisible until the picker shows a nameless entry.
func TestDNSProfileEditKeepsWhatWasNotEdited(t *testing.T) {
	routes := catalogRoutes(t, httpapi.DNSView{System: systemDNSView()}, userProfiles())
	routes["PUT /api/dns/profiles/{id}"] = func(w http.ResponseWriter, r *http.Request) {
		var p config.DNSProfile
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Errorf("decode the edited profile: %v", err)
		}
		p.ID = r.PathValue("id")
		writeJSONResponse(t, w, http.StatusOK, p)
	}
	h := newHarness(t, routes)

	err := Run(t.Context(), append([]string{"dns", "profile", "edit"},
		append(h.cfg(), "NextDNS", "--servers", "45.90.28.0, 45.90.30.0")...), h.env())
	if err != nil {
		t.Fatalf("dns profile edit: %v", err)
	}

	var sent config.DNSProfile
	var path string
	for _, req := range h.recorded() {
		if req.Method == http.MethodPut && strings.HasPrefix(req.Path, "/api/dns/profiles/") {
			path = req.Path
			if err := json.Unmarshal([]byte(req.Body), &sent); err != nil {
				t.Fatalf("parse the edited profile %q: %v", req.Body, err)
			}
		}
	}
	if path != "/api/dns/profiles/nextdns" {
		t.Fatalf("the edit went to %q, want the id the settings point at", path)
	}
	if sent.Name != "NextDNS" {
		t.Errorf("name = %q, want the profile's existing name resent unchanged", sent.Name)
	}
	want := []string{"45.90.28.0", "45.90.30.0"}
	if len(sent.Servers) != len(want) || sent.Servers[0] != want[0] || sent.Servers[1] != want[1] {
		t.Errorf("servers = %v, want %v", sent.Servers, want)
	}
	if !strings.Contains(h.out(), "45.90.28.0") {
		t.Errorf("the confirmation does not say what the profile now resolves through:\n%s", h.out())
	}
}

// An edit naming a profile nobody has must stop here rather than send a PUT that the agent
// answers with a 404 -- the message a user acts on is the one that names what they typed.
func TestDNSProfileEditRefusesANameItCannotResolve(t *testing.T) {
	h := newHarness(t, catalogRoutes(t, httpapi.DNSView{System: systemDNSView()}, userProfiles()))

	err := Run(t.Context(), append([]string{"dns", "profile", "edit"},
		append(h.cfg(), "quad9", "--servers", "9.9.9.9")...), h.env())

	if err == nil {
		t.Fatal("an edit of a profile nobody has was accepted")
	}
	if !strings.Contains(err.Error(), "quad9") {
		t.Errorf("error = %v, which does not name what was typed", err)
	}
	for _, req := range h.recorded() {
		if req.Method == http.MethodPut {
			t.Errorf("an edit went out for a profile that does not exist: %s", req.Path)
		}
	}
}

// Removing one of the user's own profiles is the ordinary case, and it is resolved by the
// name they typed rather than by an id they never see.
func TestDNSProfileRemoveDeletesTheOneNamed(t *testing.T) {
	h := newHarness(t, catalogRoutes(t, httpapi.DNSView{System: systemDNSView()}, userProfiles()))

	if err := Run(t.Context(), append([]string{"dns", "profile", "rm"}, append(h.cfg(), "NextDNS")...), h.env()); err != nil {
		t.Fatalf("dns profile rm: %v", err)
	}

	var deleted []string
	for _, req := range h.recorded() {
		if req.Method == http.MethodDelete {
			deleted = append(deleted, req.Path)
		}
	}
	if len(deleted) != 1 || deleted[0] != "/api/dns/profiles/nextdns" {
		t.Fatalf("deletes = %v, want exactly the profile named", deleted)
	}
	if !strings.Contains(h.out(), "NextDNS") {
		t.Errorf("the confirmation does not name what was removed:\n%s", h.out())
	}
}

// The password dialog can be declined, and the machine is then exactly as it was. Saying
// "this machine is ready" afterwards is the one answer that leaves a user waiting for a
// feature that will never come on.
func TestDNSSetupReportsAMachineThatIsStillNotReady(t *testing.T) {
	routes := dnsRoutes(t, httpapi.DNSView{})
	routes["POST /api/dns/setup"] = func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(t, w, http.StatusOK, httpapi.DNSView{System: &httpapi.DNSSystemView{
			Ready:   false,
			Blocker: "the privileged helper is not installed",
		}})
	}
	h := newHarness(t, routes)

	err := Run(t.Context(), append([]string{"dns", "setup"}, h.cfg()...), h.env())
	if err == nil {
		t.Fatal("a machine that is still not set up was reported as ready")
	}
	if !strings.Contains(err.Error(), "helper is not installed") {
		t.Errorf("error = %v, which does not say what is in the way", err)
	}
}
