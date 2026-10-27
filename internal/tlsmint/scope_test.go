// SPDX-License-Identifier: MIT

package tlsmint

import (
	"net/netip"
	"strings"
	"testing"
)

func compileScope(t *testing.T, mode Mode, entries []string) *Scope {
	t.Helper()
	scope, err := CompileScope(mode, entries)
	if err != nil {
		t.Fatalf("compiling the list failed: %v", err)
	}
	return scope
}

func addr(t *testing.T, text string) netip.Addr {
	t.Helper()
	parsed, err := netip.ParseAddr(text)
	if err != nil {
		t.Fatalf("%q is not an address: %v", text, err)
	}
	return parsed
}

// TestOnlyTheDestinationsNamedAreIntercepted is the mode someone debugging one service picks:
// the named service is opened and every other connection this machine makes is carried
// untouched.
func TestOnlyTheDestinationsNamedAreIntercepted(t *testing.T) {
	t.Parallel()
	scope := compileScope(t, ModeOnly, []string{"api.example.com", "10.8.0.0/16"})

	for _, c := range []struct {
		name string
		at   string
		want bool
	}{
		{"api.example.com", "", true},
		{"deep.api.example.com", "", true},
		{"API.Example.Com", "", true},
		{"example.com", "", false},
		{"notapi.example.com", "", false},
		{"anything.else", "", false},
		{"", "10.8.4.9", true},
		{"", "10.9.0.1", false},
		{"", "", false},
	} {
		var at netip.Addr
		if c.at != "" {
			at = addr(t, c.at)
		}
		if got := scope.Intercepts(c.name, at); got != c.want {
			t.Fatalf("intercepting %q/%v is %v, want %v", c.name, c.at, got, c.want)
		}
	}
}

// TestEverythingIsInterceptedExceptTheDestinationsNamed is the other mode, and the one where
// the list is what keeps the machine working: a name on it has to come back false or the
// software behind it stops running.
func TestEverythingIsInterceptedExceptTheDestinationsNamed(t *testing.T) {
	t.Parallel()
	scope := compileScope(t, ModeExcept, []string{"apple.com", "192.168.0.0/16"})

	for _, c := range []struct {
		name string
		at   string
		want bool
	}{
		{"apple.com", "", false},
		{"gs.apple.com", "", false},
		{"notapple.com", "", true},
		{"example.com", "", true},
		{"", "192.168.4.9", false},
		{"", "9.9.9.9", true},
		{"", "", true},
	} {
		var at netip.Addr
		if c.at != "" {
			at = addr(t, c.at)
		}
		if got := scope.Intercepts(c.name, at); got != c.want {
			t.Fatalf("intercepting %q/%v is %v, want %v", c.name, c.at, got, c.want)
		}
	}
}

// TestAnAddressWrittenTheOtherWayIsStillTheSameAddress is the IPv4-mapped-IPv6 trap: a
// resolver that answered ::ffff:192.168.4.9 must reach the same decision as one that answered
// 192.168.4.9, or the same destination is intercepted or not depending on which form came
// back.
func TestAnAddressWrittenTheOtherWayIsStillTheSameAddress(t *testing.T) {
	t.Parallel()

	except := compileScope(t, ModeExcept, []string{"192.168.0.0/16"})
	if except.Intercepts("", addr(t, "::ffff:192.168.4.9")) {
		t.Fatal("an address left out of interception was intercepted because it arrived mapped")
	}

	only := compileScope(t, ModeOnly, []string{"10.8.0.0/16"})
	if !only.Intercepts("", addr(t, "::ffff:10.8.4.9")) {
		t.Fatal("a named address was not intercepted because it arrived mapped")
	}
}

// TestAListThatWouldMeanTheOppositeOfWhatWasAskedForIsRefused covers the two empty-list cases,
// which are not the same mistake and are not the same danger.
func TestAListThatWouldMeanTheOppositeOfWhatWasAskedForIsRefused(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		name    string
		mode    Mode
		entries []string
		message string
	}{
		{"nothing to intercept", ModeOnly, nil, "nothing would be"},
		{"only blank lines to intercept", ModeOnly, []string{"", "   "}, "nothing would be"},
		{"nothing left out", ModeExcept, nil, "every connection this machine makes"},
		{"only blank lines left out", ModeExcept, []string{" "}, "every connection this machine makes"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := CompileScope(c.mode, c.entries)
			if err == nil {
				t.Fatal("the list was accepted")
			}
			if !strings.Contains(err.Error(), c.message) {
				t.Fatalf("the refusal does not say what is wrong: %v", err)
			}
		})
	}
}

func TestInterceptionThatIsOffInterceptsNothingAndNeedsNoList(t *testing.T) {
	t.Parallel()

	scope, err := CompileScope(ModeOff, nil)
	if err != nil {
		t.Fatalf("switching interception off failed: %v", err)
	}
	if scope.On() {
		t.Fatal("interception is on with the mode off")
	}
	if scope.Intercepts("anything.example", addr(t, "9.9.9.9")) {
		t.Fatal("a connection was intercepted with interception off")
	}
	if scope.Count() != 0 {
		t.Fatalf("%d destinations are listed with interception off", scope.Count())
	}
}

// TestAScopeThatWasNeverBuiltInterceptsNothing is the failure-open property. A runner that
// could not compile the list holds a nil Scope, and the data path reading it must carry
// traffic rather than open it.
func TestAScopeThatWasNeverBuiltInterceptsNothing(t *testing.T) {
	t.Parallel()

	var scope *Scope
	if scope.On() {
		t.Fatal("interception is on with nothing compiled")
	}
	if scope.Intercepts("anything.example", addr(t, "9.9.9.9")) {
		t.Fatal("a connection was intercepted with nothing compiled")
	}
	if scope.Mode() != ModeOff {
		t.Fatalf("the mode with nothing compiled is %s", scope.Mode())
	}
	if scope.Count() != 0 {
		t.Fatalf("%d destinations are listed with nothing compiled", scope.Count())
	}
}

func TestAModeSurvivesBeingWrittenToSettingsAndReadBack(t *testing.T) {
	t.Parallel()

	for _, mode := range []Mode{ModeOff, ModeOnly, ModeExcept} {
		got, err := ParseMode(mode.String())
		if err != nil {
			t.Fatalf("reading back %s failed: %v", mode, err)
		}
		if got != mode {
			t.Fatalf("%s was read back as %s", mode, got)
		}
	}

	// An absent setting is off, which is the only default this feature may have.
	if got, err := ParseMode(""); err != nil || got != ModeOff {
		t.Fatalf("an unset mode read back as %s (%v)", got, err)
	}
	if got, err := ParseMode("  EXCEPT "); err != nil || got != ModeExcept {
		t.Fatalf("a mode with spacing and capitals read back as %s (%v)", got, err)
	}
}

// TestAModeNobodyRecognisesIsRefusedRatherThanTreatedAsOff keeps a typo from switching
// interception off while the card says it is on.
func TestAModeNobodyRecognisesIsRefusedRatherThanTreatedAsOff(t *testing.T) {
	t.Parallel()

	for _, text := range []string{"all", "on", "yes", "onlyy", "exceptt"} {
		got, err := ParseMode(text)
		if err == nil {
			t.Fatalf("%q was accepted as a way to choose what is intercepted", text)
		}
		if got != ModeOff {
			t.Fatalf("a mode that was refused still came back as %s", got)
		}
		if !strings.Contains(err.Error(), text) {
			t.Fatalf("the refusal does not name what was written: %v", err)
		}
	}
}

// TestTheShippedBypassListCoversWhatBreaksWhenItIsIntercepted checks the list is compiled and
// applied, not that it is any particular length: what is on it changes as vendors change what
// they pin. The entries checked here are the ones whose breakage is silent -- software updates
// and push notifications that stop arriving without an error anyone sees.
func TestTheShippedBypassListCoversWhatBreaksWhenItIsIntercepted(t *testing.T) {
	t.Parallel()
	scope := compileScope(t, ModeExcept, DefaultBypass)

	for _, name := range []string{
		"gs.apple.com",
		"swscan.apple.com",
		"windowsupdate.com",
		"update.googleapis.com",
		"aus5.mozilla.org",
		"chat.signal.org",
		"registry-1.docker.io",
		"controlplane.tailscale.com",
	} {
		if scope.Intercepts(name, netip.Addr{}) {
			t.Fatalf("%s is intercepted by the shipped list, and it verifies its own certificate", name)
		}
	}

	// The list is a bypass list, not an allow-everything: an ordinary destination still gets
	// intercepted in this mode.
	if !scope.Intercepts("example.com", netip.Addr{}) {
		t.Fatal("an ordinary destination is not intercepted, so the shipped list matches too much")
	}
	if scope.Count() != len(DefaultBypass) {
		t.Fatalf("%d of the %d shipped entries compiled", scope.Count(), len(DefaultBypass))
	}
}
