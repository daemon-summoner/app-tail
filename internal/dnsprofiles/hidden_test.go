// SPDX-License-Identifier: MIT

package dnsprofiles

import (
	"slices"
	"strings"
	"testing"
)

// A DNS-over-HTTPS provider identifies an account by the URL's path, so that path is a
// credential: whoever holds it resolves as this machine and reads what it asked for. The
// host is not, and hiding it would leave a profile nobody could recognise.
func TestWhatIsHiddenIsThePartThatIdentifiesTheAccount(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   string
	}{
		{"a personal DoH endpoint", "https://dns.nextdns.io/abc123", "https://dns.nextdns.io/..."},
		{
			"a personal endpoint under the well-known path",
			"https://d.adguard-dns.com/dns-query/abc123",
			"https://d.adguard-dns.com/...",
		},
		{"an account carried in the query", "https://doh.example.com/dns-query?token=abc123", "https://doh.example.com/..."},
		// The endpoint RFC 8484 defines is what every public resolver answers on and
		// identifies nobody.
		{"the well-known endpoint", "https://1.1.1.1/dns-query", "https://1.1.1.1/dns-query"},
		{"a host with no path at all", "https://dns.example.com", "https://dns.example.com"},
		// DoT and plain DNS are a host and a port, with nothing in them to hide.
		{"DNS over TLS", "tls://dot.example.com", "tls://dot.example.com"},
		{"a plain resolver", "9.9.9.9", "9.9.9.9"},
		{"a plain resolver on its own port", "9.9.9.9:5353", "9.9.9.9:5353"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Hide(tc.server); got != tc.want {
				t.Errorf("Hide(%q) = %q, want %q", tc.server, got, tc.want)
			}
		})
	}
}

// The stand-in is shown in a URL and comes back in one, so it has to survive the trip
// as it was written. Percent-encoded, it reads as the address of something rather than as
// the sign that something is missing -- and it would no longer match what was shown.
func TestTheStandInSurvivesBeingWrittenIntoAURL(t *testing.T) {
	hidden := Hide("https://dns.nextdns.io/abc123")
	if !strings.HasSuffix(hidden, HiddenPath) {
		t.Fatalf("Hide gave %q, want it to end in %q", hidden, HiddenPath)
	}
	if Hide(hidden) != hidden {
		t.Errorf("hiding an already hidden resolver gave %q, want it unchanged", Hide(hidden))
	}
}

// An edit that left the hidden resolvers alone must keep resolving through them. Without
// this the first edit of any other field -- the profile's name -- silently replaces the
// account's endpoint with a URL no provider serves.
func TestAnEditThatLeavesAHiddenResolverAloneKeepsIt(t *testing.T) {
	stored := []string{"https://dns.nextdns.io/abc123", "9.9.9.9"}
	edited := append(Hidden(stored), "1.1.1.1")

	got, err := Reveal(edited, stored)
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	want := []string{"https://dns.nextdns.io/abc123", "9.9.9.9", "1.1.1.1"}
	if !slices.Equal(got, want) {
		t.Errorf("Reveal gave %v, want %v", got, want)
	}
}

// The list is an ordered one and reordering it is an ordinary edit, so a stand-in is
// matched by what it hides rather than by where it sits.
func TestAReorderedListStillFindsWhatEachStandInStandsFor(t *testing.T) {
	stored := []string{"9.9.9.9", "https://dns.nextdns.io/abc123"}
	edited := []string{"https://dns.nextdns.io/...", "9.9.9.9"}

	got, err := Reveal(edited, stored)
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if !slices.Equal(got, []string{"https://dns.nextdns.io/abc123", "9.9.9.9"}) {
		t.Errorf("Reveal gave %v, want the stored endpoint in its new position", got)
	}
}

// Two endpoints at one provider hide to the same text. Answering both stand-ins with
// the same stored URL would point half of this machine's queries at an account its owner
// did not choose for them.
func TestTwoStandInsAtOneProviderTakeOneStoredEndpointEach(t *testing.T) {
	stored := []string{"https://dns.nextdns.io/abc123", "https://dns.nextdns.io/def456"}

	got, err := Reveal(Hidden(stored), stored)
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if !slices.Equal(got, stored) {
		t.Errorf("Reveal gave %v, want each stand-in to take a different stored endpoint", got)
	}
}

// A stand-in standing for nothing cannot be stored: the machine would be pointed at a
// URL no provider answers, and it would look like a resolver that had been chosen.
func TestAStandInForNothingIsRefused(t *testing.T) {
	tests := []struct {
		name           string
		edited, stored []string
	}{
		{"a profile with nothing stored behind it", []string{"https://dns.nextdns.io/..."}, nil},
		{
			"a stand-in for a provider this profile does not use",
			[]string{"https://dns.nextdns.io/..."},
			[]string{"https://doh.example.com/abc123"},
		},
		{
			"two stand-ins where one endpoint is stored",
			[]string{"https://dns.nextdns.io/...", "https://dns.nextdns.io/..."},
			[]string{"https://dns.nextdns.io/abc123"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Reveal(tc.edited, tc.stored)
			if err == nil {
				t.Fatalf("Reveal gave %v, want a refusal", got)
			}
			// The refusal has to say what to type, or the only way out of it is to guess.
			if !strings.Contains(err.Error(), "full URL") {
				t.Errorf("err = %v, want it to say what to write instead", err)
			}
		})
	}
}
