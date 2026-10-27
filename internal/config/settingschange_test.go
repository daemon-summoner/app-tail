// SPDX-License-Identifier: MIT

package config

import (
	"net/netip"
	"testing"
)

// changeFor picks one reported change out of the list by its key, so an assertion about
// one setting is not coupled to how many others the same edit moved.
func changeFor(t *testing.T, changes []SettingChange, key string) SettingChange {
	t.Helper()
	for _, c := range changes {
		if c.Key == key {
			return c
		}
	}
	t.Fatalf("no change was reported for %q; got %v", key, changes)
	return SettingChange{}
}

// A save that moved nothing must report nothing. Every settings write goes through this,
// including the ones the agent makes itself, so a comparison that reported changes for
// equal documents would fill the log with entries for saves nobody made.
func TestTwoIdenticalDocumentsReportNoChangeAtAll(t *testing.T) {
	s := Defaults().Settings
	if got := SettingsChanged(s, s); len(got) != 0 {
		t.Errorf("comparing a document with itself reported %d changes: %v", len(got), got)
	}
}

// Values drawn from a small declared set carry nothing personal, so they are recorded in
// full: a log saying the network mode moved without saying what it moved to answers half
// the question a reader came with.
func TestABooleanNumberOrChoiceIsRecordedWithBothItsValues(t *testing.T) {
	before := Defaults().Settings
	after := before
	after.ProxyEnabled = !before.ProxyEnabled
	after.InterfaceMode = NetworkTUN
	after.UDPSessionTimeoutSec = before.UDPSessionTimeoutSec + 30

	changes := SettingsChanged(before, after)

	boolean := changeFor(t, changes, "proxy.enabled")
	if boolean.Redacted {
		t.Error("a boolean was recorded as redacted")
	}
	if boolean.To != "true" {
		t.Errorf("proxy.enabled was recorded as moving to %q, want %q", boolean.To, "true")
	}
	if boolean.Label == "" {
		t.Error("the change carries no label, so a log entry cannot read as a sentence")
	}

	choice := changeFor(t, changes, "interface.mode")
	if choice.Redacted || choice.To != string(NetworkTUN) {
		t.Errorf("an enum was recorded as %+v, want its value", choice)
	}

	number := changeFor(t, changes, "udpSessionTimeoutSec")
	if number.Redacted || number.To == "" {
		t.Errorf("a number was recorded as %+v, want its value", number)
	}
}

// This is the privacy rule the event log rests on. A hostname, a tag list, an address, a
// URL and a route list are all the user's rather than the app's, so the log says the
// setting changed and stops there.
func TestValuesThatBelongToTheUserAreReportedAsChangedWithoutBeingWrittenDown(t *testing.T) {
	before := Defaults().Settings
	after := before
	after.UIListen = "127.0.0.1:9999"

	changes := SettingsChanged(before, after)

	// The connection's own values are the user's for the same reason, and they go through
	// the same rule -- a device name is no less personal for having moved tables.
	tunnelBefore := primaryTunnel()
	tunnelAfter := tunnelBefore.Clone()
	tunnelAfter.ts().Hostname = "the-laptop-in-the-study"
	tunnelAfter.ts().Tags = []string{"tag:private"}
	tunnelAfter.ts().ControlURL = "https://headscale.example.internal"
	tunnelAfter.ts().RoutesAdvertise = []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")}
	changes = append(changes, TunnelChanged(tunnelBefore, tunnelAfter)...)

	for _, key := range []string{"hostname", "tags", "uiListenAddr", "controlURL", "routes.advertise"} {
		change := changeFor(t, changes, key)
		if !change.Redacted {
			t.Errorf("%s was recorded with its value", key)
		}
		if change.From != "" || change.To != "" {
			t.Errorf("%s was redacted but still carries %q -> %q", key, change.From, change.To)
		}
	}
}

// A secret must never reach a log, and the mechanism that keeps it out is the same one
// that redacts a hostname. Pinning it separately is deliberate: this is the case where
// getting it wrong writes a credential to disk.
func TestASecretIsNeverWrittenIntoAChangeRecord(t *testing.T) {
	before := primaryTunnel()
	after := before.Clone()
	after.ts().AuthKey = "tskey-auth-not-a-real-key"

	change := changeFor(t, TunnelChanged(before, after), "authKey")
	if !change.Redacted {
		t.Fatal("a secret was recorded with its value")
	}
	if change.From != "" || change.To != "" {
		t.Fatalf("a secret's change record carries %q -> %q", change.From, change.To)
	}
}

// The rule is a property of the kind rather than a list of setting names, so that adding
// a setting cannot silently opt its values into the log. This walks the whole registry:
// only the three kinds drawn from declared sets may record a value.
func TestOnlyKindsDrawnFromDeclaredSetsAreAllowedToRecordTheirValues(t *testing.T) {
	allowed := map[FieldKind]bool{KindBool: true, KindInt: true, KindEnum: true}
	check := func(key string, kind FieldKind) {
		if got := kind.recordsValue(); got != allowed[kind] {
			t.Errorf("%s is of kind %s, which reports recordsValue=%v; want %v",
				key, kind, got, allowed[kind])
		}
	}
	for _, f := range settingsFields {
		check(f.JSONKey, f.Kind)
	}
	// The connection table too: a field there is written down by the same rule, and a new
	// kind added for a connection would otherwise opt its values into the log unchecked.
	for _, f := range tunnelFields {
		check(f.JSONKey, f.Kind)
	}
}

// A derived value is a consequence of some other setting in the same list, never
// something a user changed. Reporting it would put two entries in the log for one edit,
// one of them describing a field with no switch behind it.
func TestDerivedAndReadOnlyFieldsAreNotReportedAsChanges(t *testing.T) {
	before := Defaults().Settings
	after := before
	after.UIListen = "127.0.0.1:9999"

	for _, change := range SettingsChanged(before, after) {
		for _, f := range settingsFields {
			if f.JSONKey == change.Key && f.Derived {
				t.Errorf("the derived field %q was reported as a change", change.Key)
			}
		}
	}
}

// The list is in registry order, which is the order the settings screen shows them in. A
// save that moved four things reads as four entries in the order the user saw them
// rather than in whatever order a map iterated.
func TestChangesAreReportedInTheOrderTheSettingsAreDeclared(t *testing.T) {
	before := Defaults().Settings
	after := before
	after.UIListen = "127.0.0.1:9999"
	after.ProxyEnabled = !before.ProxyEnabled
	after.DNSEnabled = !before.DNSEnabled

	changes := SettingsChanged(before, after)
	if len(changes) < 3 {
		t.Fatalf("three settings were moved but %d changes were reported", len(changes))
	}

	position := map[string]int{}
	for i, f := range settingsFields {
		position[f.JSONKey] = i
	}
	for i := 1; i < len(changes); i++ {
		if position[changes[i-1].Key] >= position[changes[i].Key] {
			t.Fatalf("changes are out of registry order: %q came before %q",
				changes[i-1].Key, changes[i].Key)
		}
	}
}

// Connections are matched by id across a save, so renaming one is a change to that
// connection rather than one connection disappearing and another arriving. A log that read
// a rename as a removal would say a network was taken off this machine when it never was.
func TestARenamedConnectionIsOneChangeRatherThanARemovalAndAnAddition(t *testing.T) {
	before := []Tunnel{NewTunnel("tn_lab", "lab", "Lab", TunnelWireGuard)}
	after := []Tunnel{NewTunnel("tn_lab", "lab", "The Lab", TunnelWireGuard)}

	changes := TunnelsChanged(before, after)

	if len(changes) != 1 {
		t.Fatalf("a rename reported %d changes: %v", len(changes), changes)
	}
	if changes[0].Label == "Connection added" || changes[0].Label == "Connection removed" {
		t.Errorf("a rename was recorded as %q", changes[0].Label)
	}
	// The key names which connection moved as well as which field, or a log across several
	// connections cannot say whose device name changed.
	if got := changes[0].Key; got != "connection.tn_lab.name" {
		t.Errorf("key = %q, want it to name both the connection and the field", got)
	}
}

// A connection arriving or leaving is recorded as one entry naming it. Its fields at that
// moment are not the useful record -- which connection joined this machine is -- and the
// name a user gave it is theirs, so the entry carries no value.
func TestAConnectionThatArrivedOrLeftIsOneEntryNamingIt(t *testing.T) {
	lab := NewTunnel("tn_lab", "lab", "Lab", TunnelWireGuard)
	office := NewTunnel("tn_office", "office", "Office", TunnelWireGuard)

	added := TunnelsChanged([]Tunnel{lab}, []Tunnel{lab, office})
	if len(added) != 1 {
		t.Fatalf("adding one connection reported %d changes: %v", len(added), added)
	}
	if added[0].Key != "connection.tn_office" || added[0].Label != "Connection added" {
		t.Errorf("the added connection was recorded as %+v", added[0])
	}
	if !added[0].Redacted || added[0].To != "" {
		t.Errorf("the entry carries %q, want a connection's own name left out of the log", added[0].To)
	}

	removed := TunnelsChanged([]Tunnel{lab, office}, []Tunnel{lab})
	if len(removed) != 1 {
		t.Fatalf("removing one connection reported %d changes: %v", len(removed), removed)
	}
	if removed[0].Key != "connection.tn_office" || removed[0].Label != "Connection removed" {
		t.Errorf("the removed connection was recorded as %+v", removed[0])
	}
}

// A save that moved nothing about any connection reports nothing, for the reason the
// settings comparison does: the agent writes the document itself on every reconcile, and an
// entry per pass would bury the writes somebody actually made.
func TestASaveThatMovedNoConnectionReportsNothing(t *testing.T) {
	held := []Tunnel{
		NewTunnel("tn_lab", "lab", "Lab", TunnelWireGuard),
		NewTunnel("tn_office", "office", "Office", TunnelTailscale),
	}

	if got := TunnelsChanged(held, held); len(got) != 0 {
		t.Errorf("comparing a connection list with itself reported %d changes: %v", len(got), got)
	}
}
