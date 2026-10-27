// SPDX-License-Identifier: MIT

package sysproxy

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// scratchRegistry is a windowsRegistry over a key of this test's own, deleted with it.
// The real key is this user's live proxy configuration, so a test that used it would
// repoint every WinINET program at whatever it wrote.
func scratchRegistry(t *testing.T) windowsRegistry {
	t.Helper()
	path := `Software\app-tail\test\` + strings.ReplaceAll(t.Name(), "/", "_")
	key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if err != nil {
		t.Fatalf("create the scratch key HKCU\\%s: %v", path, err)
	}
	if err := key.Close(); err != nil {
		t.Fatalf("close the scratch key: %v", err)
	}
	t.Cleanup(func() {
		if err := registry.DeleteKey(registry.CURRENT_USER, path); err != nil {
			t.Errorf("delete the scratch key HKCU\\%s: %v", path, err)
		}
	})
	return windowsRegistry{path: path}
}

// A machine with no auto-config URL is the ordinary state, and it has to read as "none
// is set" rather than as a failure: the manager records what it read as the value to put
// back, so a failure there stops the module from ever being switched on.
func TestNoAutoConfigURLReadsAsNoneRatherThanAFailure(t *testing.T) {
	got, err := scratchRegistry(t).get()
	if err != nil {
		t.Fatalf("read a machine with no auto-config URL: %v", err)
	}
	if got != "" {
		t.Errorf("read %q from a key that has no auto-config URL, want none", got)
	}
}

// The round trip is what the whole module rests on: what set writes is what get reads
// back, because the manager restores by writing back what it read.
func TestTheURLWrittenIsTheURLReadBack(t *testing.T) {
	w := scratchRegistry(t)
	const want = "http://127.0.0.1:8377/proxy.pac"

	if err := w.set(want); err != nil {
		t.Fatalf("write the auto-config URL: %v", err)
	}

	got, err := w.get()
	if err != nil {
		t.Fatalf("read the auto-config URL back: %v", err)
	}
	if got != want {
		t.Errorf("read %q, want the %q that was written", got, want)
	}
}

// Switching the module off writes an empty URL, and that has to remove the value rather
// than leave an empty one: WinINET treats an empty AutoConfigURL as a script it cannot
// fetch, so every program using the system setting loses its network.
func TestSwitchingOffRemovesTheValueRatherThanBlankingIt(t *testing.T) {
	w := scratchRegistry(t)
	if err := w.set("http://127.0.0.1:8377/proxy.pac"); err != nil {
		t.Fatalf("write the auto-config URL: %v", err)
	}

	if err := w.set(""); err != nil {
		t.Fatalf("remove the auto-config URL: %v", err)
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, w.path, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("open the scratch key: %v", err)
	}
	defer key.Close()
	if _, _, err := key.GetStringValue(autoConfigURLValue); err == nil {
		t.Error("the value is still there after being removed, so programs still fetch a script")
	}
}

// Removing a value that was never written is what happens whenever the module is
// switched off twice, or off on a machine that never had one. It is not a failure, and
// reporting it as one would leave the restore path stuck.
func TestRemovingAURLThatWasNeverThereIsNotAFailure(t *testing.T) {
	if err := scratchRegistry(t).set(""); err != nil {
		t.Errorf("removing an auto-config URL that was never set = %v, want it accepted", err)
	}
}

// Windows is the one platform this module writes automatically, which is the entire
// reason it exists here and not on the others.
func TestWindowsIsWritableWithoutAnAdministrator(t *testing.T) {
	ok, reason := windowsRegistry{}.supported()
	if !ok {
		t.Errorf("Windows reports its proxy cannot be written: %q", reason)
	}
	if reason != "" {
		t.Errorf("a writable platform still gave the reason %q", reason)
	}
}

// The limits are what the setting will still not do once it is on, and they are on the
// card beside the switch. Dropping them makes an automatic-looking switch read as
// covering the whole machine, which is what sends people looking for a Firefox bug.
func TestTheLimitsSayWhichProgramsAreLeftOut(t *testing.T) {
	limits := platformLimits()
	if len(limits) == 0 {
		t.Fatal("the Windows proxy setting is offered with no limits stated")
	}
	joined := strings.Join(limits, " ")
	for _, want := range []string{"Firefox", "user"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the limits do not mention %q:\n%s", want, joined)
		}
	}
}
