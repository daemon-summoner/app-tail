// SPDX-License-Identifier: MIT

package dnsprofiles

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
)

// HiddenPath stands in for the part of a DNS-over-HTTPS URL that identifies the account
// using it. It is deliberately not a path any provider serves, so a copy of it that reached
// the resolver list would fail loudly rather than resolve somewhere unintended, and it is
// written in characters a URL carries as they are: an elision that came back percent-encoded
// would read as the address of something rather than as the sign that something is missing.
const HiddenPath = "/..."

// wellKnownPath is the endpoint RFC 8484 defines and every public resolver answers on. It
// identifies nobody, and hiding it would turn a recognisable server into a row of
// punctuation for no gain.
const wellKnownPath = "/dns-query"

// Hide returns the form of one resolver that is safe to hand out.
//
// A DNS-over-HTTPS provider identifies an account by the URL's path or query -- that is
// what the "your endpoint" line on a provider's page is -- so the whole of it opens that
// account's resolver, and its query log, to whoever holds it. The management API answers
// every local process on this machine, whatever account that process runs as, which is a
// wider audience than the stored document has. The host stays: it says which provider this
// is, which is what makes the profile recognisable, and it is not the secret.
func Hide(server string) string {
	trimmed := strings.TrimSpace(server)
	if !strings.HasPrefix(strings.ToLower(trimmed), "https://") {
		// Plain and DoT resolvers are a host and a port, with nothing in them to hide.
		return server
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		// Unparseable, so it never reached the stored document through Validate. Returning it
		// whole keeps whatever a caller is holding legible to them.
		return server
	}
	if parsed.RawQuery == "" && parsed.Fragment == "" &&
		(parsed.Path == "" || parsed.Path == "/" || parsed.Path == wellKnownPath) {
		return server
	}
	parsed.Path, parsed.RawQuery, parsed.Fragment = HiddenPath, "", ""
	return parsed.String()
}

// Hidden is Hide over a resolver list.
func Hidden(servers []string) []string {
	if servers == nil {
		return nil
	}
	out := make([]string, len(servers))
	for i, s := range servers {
		out[i] = Hide(s)
	}
	return out
}

// HideProfile is one profile with its resolvers in the form that is safe to hand out.
func HideProfile(p config.DNSProfile) config.DNSProfile {
	p.Servers = Hidden(p.Servers)
	return p
}

// HideProfiles is HideProfile over a catalog.
func HideProfiles(profiles []config.DNSProfile) []config.DNSProfile {
	out := make([]config.DNSProfile, len(profiles))
	for i, p := range profiles {
		out[i] = HideProfile(p)
	}
	return out
}

// Reveal puts back what Hide took out, so an edit that left a hidden resolver alone keeps
// resolving through it.
//
// A caller edits the list it was shown, which carries stand-ins where the identifying
// paths were. Each stand-in is matched against the stored resolvers by the form they
// hide to, and each stored resolver answers for one stand-in only: two profiles at the
// same provider hide to the same text, and silently giving both edits the same account
// would point half the machine's queries somewhere its owner did not choose. A stand-in
// nothing stored accounts for is refused rather than stored, because storing it would
// leave the machine resolving through a URL no provider serves.
func Reveal(servers, stored []string) ([]string, error) {
	if servers == nil {
		return nil, nil
	}
	out := slices.Clone(servers)
	spent := make([]bool, len(stored))
	for i, server := range out {
		if !strings.Contains(server, HiddenPath) {
			continue
		}
		found := false
		for j, held := range stored {
			if spent[j] || Hide(held) != server {
				continue
			}
			out[i], spent[j], found = held, true, true
			break
		}
		if !found {
			return nil, fmt.Errorf(
				"%q is the stand-in shown in place of the part of a resolver URL that identifies "+
					"you; write the resolver's full URL to change it, or leave it exactly as it was shown "+
					"to keep the one already stored", server)
		}
	}
	return out, nil
}
