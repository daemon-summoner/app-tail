// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Overlap is what stops two forwards claiming the same endpoint, and a "both" rule
// occupies TCP and UDP at once. Comparing the protocol strings directly -- the obvious
// shortcut -- would let a tcp-only forward bind a port a both-protocol forward already
// holds, and the second one to start fails with a bare "address already in use" the
// user cannot trace back to the rule that caused it.
func TestProtocolOverlapCoversEveryCombination(t *testing.T) {
	all := []Protocol{TCP, UDP, Both}
	want := map[Protocol]map[Protocol]bool{
		TCP:  {TCP: true, UDP: false, Both: true},
		UDP:  {TCP: false, UDP: true, Both: true},
		Both: {TCP: true, UDP: true, Both: true},
	}

	for _, a := range all {
		for _, b := range all {
			t.Run(string(a)+" vs "+string(b), func(t *testing.T) {
				if got := ProtocolsOverlap(a, b); got != want[a][b] {
					t.Errorf("ProtocolsOverlap(%q, %q) = %v, want %v", a, b, got, want[a][b])
				}
				// Overlap is a property of the pair, so which forward is being checked
				// against which must not change the answer.
				if got := ProtocolsOverlap(b, a); got != want[a][b] {
					t.Errorf("reversed ProtocolsOverlap(%q, %q) = %v, want %v", b, a, got, want[a][b])
				}
			})
		}
	}
}

// A protocol nobody recognises must not be treated as occupying anything: validation
// refuses it separately, and having it silently claim ports would block real forwards.
func TestAnUnknownProtocolCarriesNeitherTransport(t *testing.T) {
	bogus := Protocol("sctp")

	if bogus.CarriesTCP() || bogus.CarriesUDP() {
		t.Errorf("%q carries tcp=%v udp=%v, want neither", bogus, bogus.CarriesTCP(), bogus.CarriesUDP())
	}
	for _, known := range []Protocol{TCP, UDP, Both} {
		if ProtocolsOverlap(bogus, known) {
			t.Errorf("%q was seen to overlap %q", bogus, known)
		}
	}
}

// CarriesUDP is what decides whether the session timeout applies to a forward. Missing
// the "both" case would leave a both-protocol forward's UDP sessions on the default
// timeout no matter what the user configured.
func TestEachProtocolReportsTheTransportsItCarries(t *testing.T) {
	tests := []struct {
		protocol Protocol
		tcp, udp bool
	}{
		{TCP, true, false},
		{UDP, false, true},
		{Both, true, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.protocol), func(t *testing.T) {
			if got := tt.protocol.CarriesTCP(); got != tt.tcp {
				t.Errorf("CarriesTCP = %v, want %v", got, tt.tcp)
			}
			if got := tt.protocol.CarriesUDP(); got != tt.udp {
				t.Errorf("CarriesUDP = %v, want %v", got, tt.udp)
			}
			// Protocols() feeds the port scanner and has to agree with the two above,
			// or a rule reserves one stack and binds the other.
			expanded := tt.protocol.Protocols()
			var sawTCP, sawUDP bool
			for _, p := range expanded {
				sawTCP = sawTCP || p == TCP
				sawUDP = sawUDP || p == UDP
			}
			if sawTCP != tt.tcp || sawUDP != tt.udp {
				t.Errorf("Protocols() = %v, which disagrees with CarriesTCP/UDP", expanded)
			}
		})
	}
}

// --- store persistence ----------------------------------------------------

// The write goes through a temp file in the same directory, so a directory the process
// cannot write to fails at the temp-file step. Reporting it is what stops the agent
// carrying on with settings that exist only in memory and vanish at the next restart.
func TestPersistingIntoAnUnwritableDirectoryIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the write bits this test depends on")
	}
	if runtime.GOOS == "windows" {
		t.Skip("windows does not enforce the directory write bit the same way")
	}

	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("make the directory read-only: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	_, err = store.Update(func(c *Config) error {
		return renameTailnet(c, "new-name")
	})

	if err == nil {
		t.Fatal("Update reported success over a directory it cannot write")
	}
	if !strings.Contains(err.Error(), "temp file") {
		t.Errorf("err = %v, want it to name the step that failed", err)
	}
	// The in-memory config must not have moved either: a store that accepted the
	// change would serve settings the file does not have.
	if got := storedHostname(t, store); got == "new-name" {
		t.Error("the failed write was applied in memory anyway")
	}
}

// The rename is the atomic step. A directory sitting where the config file belongs --
// a user who made app-tail.json a folder, or a botched restore -- makes it fail after
// the data is already written, which is the one path that can leave a stray temp file.
func TestPersistingOverADirectoryIsReportedAndLeavesNoStrayTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	// Replace the config file with a directory of the same name.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove the config file: %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("put a directory where the config belongs: %v", err)
	}

	_, err = store.Update(func(c *Config) error {
		return renameTailnet(c, "new-name")
	})

	if err == nil {
		t.Fatal("Update reported success over a directory in the config's place")
	}
	if !strings.Contains(err.Error(), "replace config") {
		t.Errorf("err = %v, want it to name the rename that failed", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the state dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".config-") {
			t.Errorf("a temp file was left behind: %s; repeated failures would fill "+
				"the state directory", e.Name())
		}
	}
}

// A config written before machine ids existed, or hand-edited without one, still has
// to get one: it seeds the default hostname template, so a node without it would
// enroll under a name that collides with every other such machine.
func TestOpeningAConfigWithNoMachineIDBackfillsOne(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	if err := os.WriteFile(path, []byte(`{"settings":{}}`), FileMode); err != nil {
		t.Fatalf("write the legacy config: %v", err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	id := store.Settings().MachineID
	if id == "" {
		t.Fatal("no machine id was minted for a config that had none")
	}

	// The backfill is in memory until something writes, but the next write has to
	// carry it rather than mint a second one.
	if _, err := store.Update(func(c *Config) error {
		return renameTailnet(c, "named")
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	if got := reopened.Settings().MachineID; got != id {
		t.Errorf("machine id changed from %q to %q across a write; the node would "+
			"rename itself on every restart", id, got)
	}
}

// The stored id is the node's identity across restarts. Regenerating it would make the
// default hostname template render a different name, and the tailnet would see a new
// device rather than the same one reconnecting.
func TestAStoredMachineIDIsNeverRegenerated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)

	first, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	id := first.Settings().MachineID
	if id == "" {
		t.Fatal("a fresh store was created with no machine id")
	}

	second, err := Open(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	if got := second.Settings().MachineID; got != id {
		t.Errorf("machine id = %q on reopen, want the stored %q", got, id)
	}
}

// A config file the agent cannot parse must not stop it: refusing to start leaves a
// background process with no tray, no dashboard and no way to repair the file. It must
// not be quietly discarded either -- the user's forwards are in it -- so it is kept, and
// the app starts on defaults with the record of what happened.
func TestAnUnparsableConfigIsKeptAndTheAppStartsAnyway(t *testing.T) {
	path := filepath.Join(t.TempDir(), ConfigFileName)
	if err := os.WriteFile(path, []byte(`{"settings":`), FileMode); err != nil {
		t.Fatalf("write the damaged config: %v", err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	note := store.Quarantined()
	if note == nil {
		t.Fatal("a damaged config was replaced with no record that it happened")
	}
	// The document has to survive exactly as it was, so the user can repair it.
	raw, readErr := os.ReadFile(note.Path)
	if readErr != nil {
		t.Fatalf("read the document that was moved aside: %v", readErr)
	}
	if string(raw) != `{"settings":` {
		t.Errorf("the damaged config was rewritten to %q", raw)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the app was left with no config at all: %v", err)
	}
}

// A config that parses but describes something impossible is set aside with the reason,
// so the user learns which field to fix instead of watching the agent fail to bind.
func TestAConfigThatFailsValidationIsSetAsideWithTheReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), ConfigFileName)
	body := `{"settings":{"machineId":"abc"},"forwards":[{"id":"f_1","direction":"to_local",` +
		`"protocol":"tcp","listenPort":99999,"target":"box:22"}]}`
	if err := os.WriteFile(path, []byte(body), FileMode); err != nil {
		t.Fatalf("write the config: %v", err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	note := store.Quarantined()
	if note == nil {
		t.Fatal("an invalid config was replaced with no record that it happened")
	}
	if !strings.Contains(note.Reason, "listenPort") {
		t.Errorf("reason = %q, want it to name the field the user has to edit", note.Reason)
	}
	// The install keeps its identity: a document that decoded far enough to hold it is
	// not a new machine, and a new id renames this device on every tailnet it is on.
	if got := store.Settings().MachineID; got != "abc" {
		t.Errorf("machine id = %q, want the stored %q carried over", got, "abc")
	}
}

// The path is how the CLI reports where settings live and how the agent re-resolves
// them after a write. An empty one would send every "config file:" line to nowhere.
func TestTheStoreReportsThePathItWritesTo(t *testing.T) {
	path := filepath.Join(t.TempDir(), ConfigFileName)
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	if got := store.Path(); got != path {
		t.Errorf("Path = %q, want %q", got, path)
	}
	if _, err := os.Stat(store.Path()); err != nil {
		t.Errorf("the reported path does not exist: %v", err)
	}
}

// Clone is what the store hands to every reader and what an Update mutates, so a field
// it forgets is a field whose writes are silently discarded and whose reads alias the
// store's own copy. Both failures are invisible until something far away misbehaves --
// Every one of these settings arrived after the first release, so a document written
// before it exists carries the zero value. Each resolver has to turn that zero into the
// working default -- and the wrong reading of a zero is a different failure in each
// case: a module switched on that maps nothing, or a device limit of none at all.
func TestAnUnsetSettingResolvesToItsDefaultRatherThanToZero(t *testing.T) {
	var unset Settings

	ports, err := unset.AutoMapPortList()
	if err != nil {
		t.Fatalf("AutoMapPortList() on an empty list: %v", err)
	}
	if len(ports) != 1 || ports[0] != DefaultAutoMapPort {
		t.Errorf("AutoMapPortList() = %v, want the default [%d] rather than nothing to map",
			ports, DefaultAutoMapPort)
	}
	if got := unset.AutoMapLimit(); got != DefaultAutoMapMax {
		t.Errorf("AutoMapLimit() = %d, want %d -- zero would map no device at all", got, DefaultAutoMapMax)
	}
	if got := unset.AutoMapBase(); got != DefaultAutoMapPortBase {
		t.Errorf("AutoMapBase() = %d, want the first port %d", got, DefaultAutoMapPortBase)
	}
}

// ...and a value that was chosen wins over the default, or the settings would be
// decoration.
func TestAChosenSettingWinsOverItsDefault(t *testing.T) {
	chosen := Settings{
		AutoMapPorts:    []string{"22", "80"},
		AutoMapMax:      7,
		AutoMapPortBase: 20000,
	}

	ports, err := chosen.AutoMapPortList()
	if err != nil {
		t.Fatalf("AutoMapPortList(): %v", err)
	}
	if !reflect.DeepEqual(ports, []int{22, 80}) {
		t.Errorf("AutoMapPortList() = %v, want [22 80]", ports)
	}
	if got := chosen.AutoMapLimit(); got != 7 {
		t.Errorf("AutoMapLimit() = %d, want 7", got)
	}
	if got := chosen.AutoMapBase(); got != 20000 {
		t.Errorf("AutoMapBase() = %d, want 20000", got)
	}
	// A list that cannot be read is an error rather than a silent fallback to the
	// default: mapping port 22 on every device because "ssh" did not parse is not what
	// anyone who typed it meant.
	broken := Settings{AutoMapPorts: []string{"ssh"}}
	if got, err := broken.AutoMapPortList(); err == nil {
		t.Errorf("AutoMapPortList() on an unreadable list = %v, want an error", got)
	}
}

// this is the guard that turns adding a field without extending Clone into a failure
// here instead.
//
// Pointers are compared rather than values: a shared backing array and an omitted field
// both show up, and neither depends on this test knowing what the fields mean.
func TestCloneSharesNothingWithWhatItCopied(t *testing.T) {
	original := &Config{}
	fillReferenceFields(t, reflect.ValueOf(original).Elem(), "Config")

	clone := original.Clone()

	forEachReferenceField(reflect.ValueOf(original).Elem(), reflect.ValueOf(clone).Elem(), "Config",
		func(path string, from, to reflect.Value) {
			if to.IsNil() {
				t.Errorf("%s is nil in the clone but set in the original, so Clone drops it", path)
				return
			}
			if from.Pointer() == to.Pointer() {
				t.Errorf("%s is shared with the original rather than copied, so a write to one changes the other", path)
			}
		})
}

// fillReferenceFields gives every slice and map in v something to point at, so the
// comparison above distinguishes "copied" from "both empty".
func fillReferenceFields(t *testing.T, v reflect.Value, path string) {
	t.Helper()
	switch v.Kind() {
	case reflect.Struct:
		for i := range v.NumField() {
			if !v.Field(i).CanSet() {
				continue
			}
			fillReferenceFields(t, v.Field(i), path+"."+v.Type().Field(i).Name)
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
	case reflect.Map:
		m := reflect.MakeMapWithSize(v.Type(), 1)
		m.SetMapIndex(reflect.Zero(v.Type().Key()), reflect.Zero(v.Type().Elem()))
		v.Set(m)
	case reflect.Pointer, reflect.Interface, reflect.Chan, reflect.Func, reflect.UnsafePointer:
		t.Fatalf("%s is a %s, which this guard does not know how to check for sharing", path, v.Kind())
	}
}

// forEachReferenceField walks two values of the same type in step, calling visit for
// every slice and map it reaches.
func forEachReferenceField(from, to reflect.Value, path string, visit func(string, reflect.Value, reflect.Value)) {
	switch from.Kind() {
	case reflect.Struct:
		for i := range from.NumField() {
			if !from.Field(i).CanInterface() {
				continue
			}
			forEachReferenceField(from.Field(i), to.Field(i), path+"."+from.Type().Field(i).Name, visit)
		}
	case reflect.Slice, reflect.Map:
		visit(path, from, to)
	}
}
