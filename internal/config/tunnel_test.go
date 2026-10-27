// SPDX-License-Identifier: MIT

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// renameTailnet gives the primary connection a device name, which is the smallest real
// change a test can make to a stored document now that the identity lives on the
// connection rather than in the settings.
func renameTailnet(c *Config, name string) error {
	ts, err := c.PrimaryTailscale()
	if err != nil {
		return err
	}
	ts.Hostname = name
	return nil
}

// storedHostname is the device name the store currently holds for that connection.
func storedHostname(t *testing.T, s *Store) string {
	t.Helper()
	held, ok := s.Get().Tunnel(PrimaryTunnelID)
	if !ok {
		t.Fatalf("the store holds no %q connection", PrimaryTunnelID)
	}
	return held.TS().Hostname
}

// Two connections must never be handed one state directory. A Tailscale node takes no
// lock on it and rewrites the whole file on every write, so a shared directory is two
// identities overwriting each other with nothing reporting it.
func TestEveryConnectionGetsItsOwnStateDirectory(t *testing.T) {
	ids := []string{PrimaryTunnelID, "tn_a1b2c3", "tn_d4e5f6"}

	seen := make(map[string]string, len(ids))
	for _, id := range ids {
		dir := TunnelStateDir("/state", id)
		if other, dup := seen[dir]; dup {
			t.Errorf("connections %q and %q are both given %q", other, id, dir)
		}
		seen[dir] = id
	}
}

// The connection every install already has keeps the directory it enrolled in. Anywhere
// else and an upgrade would look at an empty directory and ask a tailnet member to sign
// in again.
func TestThePrimaryConnectionKeepsTheDirectoryItAlreadyUses(t *testing.T) {
	if got := TunnelStateDir("/state", PrimaryTunnelID); got != "/state" {
		t.Errorf("TunnelStateDir(primary) = %q, want the root state directory", got)
	}
}

func TestOtherConnectionsAreKeptTogetherUnderTheStateDirectory(t *testing.T) {
	got := TunnelStateDir("/state", "tn_a1b2c3")

	if want := filepath.Join("/state", "tunnels", "tn_a1b2c3"); got != want {
		t.Errorf("TunnelStateDir = %q, want %q", got, want)
	}
}

// The uniqueness above is only true because the document refuses to hold one id twice --
// the path is a pure function of the id, so a duplicate id is a shared directory.
func TestADocumentHoldingOneConnectionIDTwiceIsRefused(t *testing.T) {
	cfg := Defaults()
	cfg.Tunnels = []Tunnel{primaryTunnel(), primaryTunnel()}
	cfg.Tunnels[1].Slug = "second"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("a document naming one connection twice was accepted")
	}
	if !strings.Contains(err.Error(), PrimaryTunnelID) {
		t.Errorf("error = %q, want the repeated id named", err)
	}
}

// Two names with different rules, and a person supplies one. What comes out has to be a
// DNS label whatever was typed, because it becomes a label in every name this connection
// answers for -- a slug that is only valid here produces names nothing can look up.
func TestTheNameOnScreenBecomesANameTheDNSCanCarry(t *testing.T) {
	cases := []struct{ name, typed, want string }{
		{"a plain name", "Office", "office"},
		{"spaces", "Office VPN", "office-vpn"},
		{"punctuation", "Acme, Inc. (EU)", "acme-inc-eu"},
		{"a run of characters a label cannot carry", "Office -- VPN", "office-vpn"},
		{"something at each end that a label cannot begin with", "  -Office-  ", "office"},
		{"digits", "site 2", "site-2"},
		// A name, not an error: what it cannot be is the label, and the name the user typed
		// is still what they read in the list.
		{"nothing a label can carry at all", "  ✦✦✦  ", "network"},
		{"nothing at all", "", "network"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SuggestSlug(tc.typed, nil); got != tc.want {
				t.Errorf("SuggestSlug(%q) = %q, want %q", tc.typed, got, tc.want)
			}
		})
	}
}

// A label is 63 characters at most, and the cut can land on a hyphen -- which is a
// character a label may not end with, so the result would be refused by the validator that
// this function exists to satisfy.
func TestASuggestedNameIsShortEnoughToBeALabel(t *testing.T) {
	got := SuggestSlug(strings.Repeat("office ", 20), nil)

	if len(got) > MaxSlugLen {
		t.Errorf("SuggestSlug returned %d characters, want at most %d", len(got), MaxSlugLen)
	}
	if ok, why := ValidSlug(got); !ok {
		t.Errorf("SuggestSlug returned %q, which is not a label: %s", got, why)
	}
}

// Two connections added from one template are "office" and "office-2", which is what a
// person would have typed. A suggestion that collided would be refused on save, leaving
// the dialog rejecting a name it filled in itself.
func TestASuggestedNameNoOtherConnectionAnswersFor(t *testing.T) {
	taken := map[string]bool{"office": true, "office-2": true}

	if got := SuggestSlug("Office", taken); got != "office-3" {
		t.Errorf("SuggestSlug = %q, want office-3", got)
	}
}

// The number has to fit inside the label along with the name, so the name is what gives
// way. Appending to a full-length slug would produce a label one character too long.
func TestANumberedNameStaysWithinALabel(t *testing.T) {
	full := strings.Repeat("a", MaxSlugLen)

	got := SuggestSlug(full, map[string]bool{full: true})

	if len(got) > MaxSlugLen {
		t.Errorf("SuggestSlug returned %d characters, want at most %d", len(got), MaxSlugLen)
	}
	if got != strings.Repeat("a", MaxSlugLen-2)+"-2" {
		t.Errorf("SuggestSlug = %q, want the name cut back to make room for the number", got)
	}
}

// Every connection's state directory is a pure function of its id, so two connections
// sharing one is two identities overwriting each other. Ids are minted rather than derived
// from anything a user controls, which is what keeps that from happening.
func TestEveryConnectionIsMintedWithAnIDOfItsOwn(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		id, err := NewTunnelID()
		if err != nil {
			t.Fatalf("minting a connection id failed: %v", err)
		}
		if !strings.HasPrefix(id, "tn_") || len(id) != len("tn_")+6 {
			t.Fatalf("id = %q, want tn_ and six hex characters", id)
		}
		if seen[id] {
			t.Fatalf("id %q was minted twice in a hundred", id)
		}
		seen[id] = true
	}
}
