// SPDX-License-Identifier: MIT

package tunnel

import "testing"

func TestANameSaysWhichConnectionItIsOn(t *testing.T) {
	names := NewNaming(map[string]string{
		"tn_office": "office.internal",
		"tn_lab":    "lab.internal",
	})

	tests := []struct {
		host     string
		wantID   string
		wantName string
		wantOK   bool
	}{
		{"db.office.internal", "tn_office", "db", true},
		{"db.lab.internal", "tn_lab", "db", true},
		// More than one label in front is a name inside the network, not a miss: private
		// zones have their own structure and this convention only owns the tail.
		{"db.eu.office.internal", "tn_office", "db.eu", true},
		// A fully qualified name and a mixed-case one are the same name.
		{"DB.Office.Internal.", "tn_office", "db", true},
		// The suffix on its own names the connection and no host on it.
		{"office.internal", "tn_office", "", true},
		// Anchored at a label boundary: a name that merely ends in the same letters is a
		// different name, and answering it here would be this app claiming somebody's
		// real domain.
		{"notoffice.internal", "", "", false},
		{"office.internal.example.com", "", "", false},
		{"example.com", "", "", false},
		{"", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			id, name, ok := names.Match(tt.host)

			if ok != tt.wantOK {
				t.Fatalf("Match(%q) matched = %v, want %v", tt.host, ok, tt.wantOK)
			}
			if id != tt.wantID {
				t.Errorf("Match(%q) connection = %q, want %q", tt.host, id, tt.wantID)
			}
			if name != tt.wantName {
				t.Errorf("Match(%q) name = %q, want %q", tt.host, name, tt.wantName)
			}
		})
	}
}

// Two zones where one sits under the other is a configuration a person can write, and the
// first match in map order would decide it by hash order -- so the same name would resolve
// to different connections between runs of the same binary.
func TestTheLongestSuffixDecidesWhenTwoWouldMatch(t *testing.T) {
	names := NewNaming(map[string]string{
		"tn_broad":  "internal",
		"tn_narrow": "office.internal",
	})

	id, name, ok := names.Match("db.office.internal")

	if !ok {
		t.Fatal("a name under both suffixes matched neither")
	}
	if id != "tn_narrow" {
		t.Errorf("connection = %q, want the one whose suffix is more specific", id)
	}
	if name != "db" {
		t.Errorf("name = %q, want the host with only the longer suffix taken off", name)
	}
}

// An empty suffix would match every name at once, so a connection that has none is left
// out of the lookup rather than mapped to nothing.
func TestAConnectionWithNoSuffixNamesNothing(t *testing.T) {
	names := NewNaming(map[string]string{"tn_office": "", "": "orphan.internal"})

	if names.Len() != 0 {
		t.Fatalf("Len = %d, want neither half-declared entry kept", names.Len())
	}
	if _, _, ok := names.Match("db.example.com"); ok {
		t.Error("a connection with no suffix matched a name")
	}
	if got := names.SuffixOf("tn_office"); got != "" {
		t.Errorf("SuffixOf = %q, want nothing", got)
	}
}

// The surfaces that show a connection its own suffix read it back from the same map that
// decides where a name goes, so what is displayed and what resolves cannot disagree.
func TestAConnectionReadsBackItsOwnSuffix(t *testing.T) {
	names := NewNaming(map[string]string{"tn_office": "Office.Internal."})

	if got := names.SuffixOf("tn_office"); got != "office.internal" {
		t.Errorf("SuffixOf = %q, want the normalized suffix", got)
	}
	if got := names.SuffixOf("tn_missing"); got != "" {
		t.Errorf("SuffixOf on an unknown connection = %q, want nothing", got)
	}
}
