// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/net/dns"
	"tailscale.com/util/dnsname"
)

// quad100 is the address the tailnet's own resolver answers on.
var quad100 = netip.MustParseAddr("100.100.100.100")

// A resolver that answers for no domains is one macOS writes no file for, so the machine
// never asks it anything. This is a node whose peers are reachable by address and by no
// name at all.
func TestATailnetsOwnNamesAreSentToTheTailnetsResolver(t *testing.T) {
	got := matchTailnetDomains(dns.OSConfig{
		Nameservers:   []netip.Addr{quad100},
		SearchDomains: fqdns(t, "vulture-dab.ts.net."),
	}, true)

	if !slices.Contains(got.MatchDomains, dnsname.FQDN("vulture-dab.ts.net.")) {
		t.Errorf("the tailnet's suffix is matched by %v, so nothing resolves it", got.MatchDomains)
	}
}

// The search domains carry whatever the machine's own network handed it. Sending those to
// the tailnet's resolver takes the local network's names down with it -- a printer or a
// NAS that resolved a moment ago stops resolving the moment the interface comes up.
func TestTheLocalNetworksNamesAreNotSentToTheTailnetsResolver(t *testing.T) {
	got := matchTailnetDomains(dns.OSConfig{
		Nameservers:   []netip.Addr{quad100},
		SearchDomains: fqdns(t, "lan.", "corp.example.com.", "vulture-dab.ts.net."),
	}, true)

	want := fqdns(t, "vulture-dab.ts.net.")
	if !slices.Equal(got.MatchDomains, want) {
		t.Errorf("the tailnet's resolver was given %v, want only %v", got.MatchDomains, want)
	}
}

// A platform that installs one resolver for everything reads an empty match list as
// exactly that. Filling it there turns the tailnet's resolver from the machine's into one
// used for tailnet names only, and every other name stops being resolved through it.
func TestAPlatformWithOneResolverForEverythingIsLeftAlone(t *testing.T) {
	cfg := dns.OSConfig{
		Nameservers:   []netip.Addr{quad100},
		SearchDomains: fqdns(t, "vulture-dab.ts.net."),
	}

	if got := matchTailnetDomains(cfg, false); len(got.MatchDomains) != 0 {
		t.Errorf("the configuration was narrowed to %v on a platform that installs one resolver for everything", got.MatchDomains)
	}
}

// A configuration that names its own domains is a split-DNS one the control plane asked
// for. Adding to it would send names somewhere the tailnet did not ask for.
func TestAConfigurationThatNamesItsOwnDomainsIsLeftAsItIs(t *testing.T) {
	want := fqdns(t, "corp.example.com.")
	cfg := dns.OSConfig{
		Nameservers:   []netip.Addr{quad100},
		SearchDomains: fqdns(t, "vulture-dab.ts.net."),
		MatchDomains:  want,
	}

	if got := matchTailnetDomains(cfg, true); !slices.Equal(got.MatchDomains, want) {
		t.Errorf("the domains became %v, want the configuration's own %v", got.MatchDomains, want)
	}
}

// A configuration with no resolver is the machine being handed back its own. Naming
// domains on it would point them at nothing.
func TestAConfigurationWithNoResolverIsNotGivenDomains(t *testing.T) {
	got := matchTailnetDomains(dns.OSConfig{
		SearchDomains: fqdns(t, "vulture-dab.ts.net."),
	}, true)

	if len(got.MatchDomains) != 0 {
		t.Errorf("a configuration naming no resolver was given the domains %v", got.MatchDomains)
	}
}

// The suffix is compared as a domain and not as text, so a name that merely ends in those
// characters is not mistaken for a tailnet's.
func TestADomainThatOnlyLooksLikeATailnetsIsNotSentToIt(t *testing.T) {
	got := matchTailnetDomains(dns.OSConfig{
		Nameservers:   []netip.Addr{quad100},
		SearchDomains: fqdns(t, "notts.net.", "ts.net.evil.com."),
	}, true)

	if len(got.MatchDomains) != 0 {
		t.Errorf("%v was taken for a tailnet's own domain", got.MatchDomains)
	}
}

// recordingConfigurator is the platform's resolver, standing in for the one Open builds --
// which needs root and a live interface, and is the boundary this is installing through.
type recordingConfigurator struct {
	got dns.OSConfig
}

func (r *recordingConfigurator) SetDNS(cfg dns.OSConfig) error { r.got = cfg; return nil }
func (r *recordingConfigurator) SupportsSplitDNS() bool        { return true }
func (r *recordingConfigurator) GetBaseConfig() (dns.OSConfig, error) {
	return dns.OSConfig{}, dns.ErrGetBaseConfigNotSupported
}
func (r *recordingConfigurator) Close() error { return nil }

// The privileged side is the last place the configuration is touched before the platform
// writes it, so a configuration that reaches the platform unnarrowed is one nothing else
// will narrow.
func TestTheInstalledConfigurationIsTheNarrowedOne(t *testing.T) {
	if !resolvesPerDomain() {
		t.Skipf("this platform installs one resolver for everything, so there is nothing to narrow")
	}
	recorder := &recordingConfigurator{}
	local := &Local{dns: recorder}

	err := local.SetDNS(context.Background(), dns.OSConfig{
		Nameservers:   []netip.Addr{quad100},
		SearchDomains: fqdns(t, "vulture-dab.ts.net."),
	})
	if err != nil {
		t.Fatalf("SetDNS: %v", err)
	}

	want := fqdns(t, "vulture-dab.ts.net.")
	if !slices.Equal(recorder.got.MatchDomains, want) {
		t.Errorf("the platform was given the domains %v, want %v", recorder.got.MatchDomains, want)
	}
}

// fqdns parses domains the way the tailnet's own configuration carries them.
func fqdns(t *testing.T, names ...string) []dnsname.FQDN {
	t.Helper()
	out := make([]dnsname.FQDN, 0, len(names))
	for _, name := range names {
		fqdn, err := dnsname.ToFQDN(name)
		if err != nil {
			t.Fatalf("ToFQDN(%q): %v", name, err)
		}
		out = append(out, fqdn)
	}
	return out
}
