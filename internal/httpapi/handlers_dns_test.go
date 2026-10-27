// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
)

// The one thing a DNS panel must never do is imply the machine changed. Every field here
// describes the tailnet's configuration and this process's own resolver, and the machine
// half is reported separately for exactly that reason.
func TestTheDNSViewSeparatesTheTailnetsConfigurationFromTheMachines(t *testing.T) {
	h := newHarness(t)

	view := decode[DNSView](t, h.do(t, http.MethodGet, "/api/dns", nil))

	if !view.Using || !view.MagicDNS {
		t.Errorf("using = %v magicDNS = %v, want the tailnet's own state carried through",
			view.Using, view.MagicDNS)
	}
	if len(view.Resolvers) != 1 || view.Resolvers[0] != "100.100.100.100" {
		t.Errorf("resolvers = %v, want the tailnet's nameservers", view.Resolvers)
	}
	if view.Machine != nil {
		t.Errorf("machine = %+v, want nothing claimed about a machine app-tail does not configure",
			view.Machine)
	}
	if view.MachineReason == "" {
		t.Error("no reason is given for the empty machine half, so it reads as a failed read")
	}
}

// Split DNS is the case people cannot otherwise confirm: a suffix pointed at a private
// resolver in the admin console either arrives here or the user is guessing.
func TestTheDNSViewCarriesSplitDNSAndTailnetRecords(t *testing.T) {
	h := newHarness(t)

	view := decode[DNSView](t, h.do(t, http.MethodGet, "/api/dns", nil))

	if len(view.Routes) != 1 || view.Routes[0].Suffix != "corp.example.com" {
		t.Fatalf("routes = %+v, want the split-DNS suffix", view.Routes)
	}
	if len(view.Routes[0].Resolvers) != 1 || view.Routes[0].Resolvers[0] != "10.0.0.53" {
		t.Errorf("resolvers = %v, want whoever answers for that suffix", view.Routes[0].Resolvers)
	}
	if len(view.Records) != 1 || view.Records[0].Name != "wiki" {
		t.Errorf("records = %+v, want the names the tailnet serves beyond its peers", view.Records)
	}
}

// The system half is the answer to "what is my machine resolving through right now", and
// every part of it is separately falsifiable: what was asked for, what is actually in
// force, what the network's own resolvers are, and how the traffic is splitting. A view
// that dropped any of them would leave the card guessing.
func TestTheDNSViewCarriesTheMachineResolverItsProfileAndItsCounters(t *testing.T) {
	h := newHarness(t)

	view := decode[DNSView](t, h.do(t, http.MethodGet, "/api/dns", nil))

	sys := view.System
	if sys == nil {
		t.Fatal("the system half is absent, which a client reads as this build not having the feature")
	}
	if !sys.Enabled || !sys.Applied {
		t.Errorf("enabled = %v applied = %v, want the switch and the override reported apart",
			sys.Enabled, sys.Applied)
	}
	if sys.Profile != "cloudflare" || sys.ProfileLabel == "" {
		t.Errorf("profile = %q label = %q, want the id and something a person recognizes",
			sys.Profile, sys.ProfileLabel)
	}
	if len(sys.Servers) != 2 || sys.Servers[0] != "1.1.1.1" {
		t.Errorf("servers = %v, want what the machine is resolving through", sys.Servers)
	}
	if sys.Listen != "127.0.0.153:53" {
		t.Errorf("listen = %q, want the address this machine was pointed at", sys.Listen)
	}
	if sys.Base == nil || len(sys.Base.Nameservers) != 1 {
		t.Fatalf("base = %+v, want the network's own resolvers, which is where local names go", sys.Base)
	}
	if sys.Queries.Total != 42 || sys.Queries.ToProfile != 39 || sys.Queries.ToLocal != 3 {
		t.Errorf("queries = %+v, want the split between the profile and the network", sys.Queries)
	}
}

// Arranging the rights raises a password prompt on a real machine, so the route answers
// with the view: what the user wants to know is what the machine can do now, and asking a
// second time is how a client would otherwise find out.
func TestArrangingTheMachineResolverAnswersWithTheStateItProduced(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/dns/setup", nil)

	requireStatus(t, rec, http.StatusOK)
	if h.dns.setups != 1 {
		t.Errorf("the machine was arranged %d times, want exactly once", h.dns.setups)
	}
	if view := decode[DNSView](t, rec); view.System == nil {
		t.Error("the answer carries no system half, so the client learned nothing from the round trip")
	}
}

// A declined password prompt is the ordinary outcome, not an internal fault: it has to
// reach the card as a stated refusal or the switch looks broken.
func TestADeclinedSetupIsReportedRatherThanSwallowed(t *testing.T) {
	h := newHarness(t)
	h.dns.setupErr = &config.ValidationError{
		Field: "systemDns.enabled", Message: "the administrator prompt was declined",
	}

	rec := h.do(t, http.MethodPost, "/api/dns/setup", nil)

	body := requireError(t, rec, http.StatusBadRequest, "declined")
	if body.Field != "systemDns.enabled" {
		t.Errorf("field = %q, want the refusal attributed to the switch that asked for it", body.Field)
	}
}

func TestListingProfilesCarriesTheShippedCatalogFlaggedAsBuiltIn(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodGet, "/api/dns/profiles", nil)

	requireStatus(t, rec, http.StatusOK)
	body := decode[struct {
		Profiles []config.DNSProfile `json:"profiles"`
	}](t, rec)
	if len(body.Profiles) != len(dnsprofiles.BuiltIn()) {
		t.Fatalf("profiles = %+v, want the shipped entries", body.Profiles)
	}
	for _, p := range body.Profiles {
		if !p.BuiltIn {
			t.Errorf("%s: builtIn = false, so the dashboard would offer to delete a shipped profile", p.ID)
		}
	}
}

// BuiltIn is the catalog's own word, never the client's. A profile that arrived claiming to
// be shipped would be one the user could neither edit nor delete afterwards.
func TestACreatedProfileCannotClaimToBeBuiltIn(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/dns/profiles", config.DNSProfile{
		Name: "NextDNS", Servers: []string{"https://dns.nextdns.io/abc123"}, BuiltIn: true,
	})

	requireStatus(t, rec, http.StatusCreated)
	created := decode[config.DNSProfile](t, rec)
	if created.BuiltIn {
		t.Error("a client minted a built-in profile, which nothing can delete afterwards")
	}
	if created.ID == "" {
		t.Error("the created profile has no id, so nothing can point at it")
	}
}

func TestAProfileWithNothingToDialIsRefusedWithTheReason(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/dns/profiles", config.DNSProfile{
		Name: "Broken", Servers: []string{"dns.example.com"},
	})

	requireError(t, rec, http.StatusBadRequest, "dns.example.com")
	if len(h.profiles.user) != 0 {
		t.Errorf("a refused profile was stored anyway: %+v", h.profiles.user)
	}
}

// The shipped profiles are the way back when a custom one is what broke resolution, so
// neither editing nor deleting them can be allowed to succeed.
func TestABuiltInProfileCanBeNeitherEditedNorDeleted(t *testing.T) {
	h := newHarness(t)

	edit := h.do(t, http.MethodPut, "/api/dns/profiles/cloudflare", config.DNSProfile{
		Name: "Cloudflare", Servers: []string{"10.0.0.9"},
	})
	requireError(t, edit, http.StatusBadRequest, "built-in")

	remove := h.do(t, http.MethodDelete, "/api/dns/profiles/google", nil)
	requireError(t, remove, http.StatusBadRequest, "built-in")

	if len(h.profiles.deletes) != 0 {
		t.Errorf("a shipped profile was deleted: %v", h.profiles.deletes)
	}
	if p, ok := findProfile(h.profiles.List(), "cloudflare"); !ok || p.Servers[0] != "https://1.1.1.1/dns-query" {
		t.Errorf("cloudflare = %+v, want the shipped servers untouched", p)
	}
}

func TestEditingAndDeletingAUserProfileGoThroughAndAnUnknownIdIsNotFound(t *testing.T) {
	h := newHarness(t)
	h.profiles.user = []config.DNSProfile{
		{ID: "work", Name: "Work", Servers: []string{"10.0.0.1"}},
	}

	edited := h.do(t, http.MethodPut, "/api/dns/profiles/work", config.DNSProfile{
		Name: "Work", Servers: []string{"tls://dot.example.com", "10.0.0.2"},
	})
	requireStatus(t, edited, http.StatusOK)
	if got := decode[config.DNSProfile](t, edited); got.ID != "work" || len(got.Servers) != 2 {
		t.Errorf("edited = %+v, want the id kept so the settings still point at it", got)
	}

	requireError(t, h.do(t, http.MethodPut, "/api/dns/profiles/ghost", config.DNSProfile{
		Name: "Ghost", Servers: []string{"9.9.9.9"},
	}), http.StatusNotFound, "ghost")

	removed := h.do(t, http.MethodDelete, "/api/dns/profiles/work", nil)
	requireStatus(t, removed, http.StatusNoContent)
	if len(h.profiles.deletes) != 1 || h.profiles.deletes[0] != "work" {
		t.Errorf("deletes = %v, want the user profile removed", h.profiles.deletes)
	}
	requireError(t, h.do(t, http.MethodDelete, "/api/dns/profiles/work", nil), http.StatusNotFound, "work")
}

func findProfile(list []config.DNSProfile, id string) (config.DNSProfile, bool) {
	for _, p := range list {
		if p.ID == id {
			return p, true
		}
	}
	return config.DNSProfile{}, false
}
