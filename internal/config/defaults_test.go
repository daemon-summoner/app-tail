// SPDX-License-Identifier: MIT

package config

import (
	"runtime"
	"strings"
	"testing"
)

func TestSanitizeHostname(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"BuildBox", "buildbox"},
		{"build_box", "build-box"},
		{"build.box.local", "build-box-local"},
		{"My Laptop", "my-laptop"},
		{"--weird--name--", "weird-name"},
		{"host!!!name", "hostname"},
		{"héllo", "hllo"},
		{"", ""},
		{"!!!", ""},
		{strings.Repeat("a", 80), strings.Repeat("a", 63)},
	}
	for _, tc := range tests {
		if got := SanitizeHostname(tc.in); got != tc.want {
			t.Errorf("SanitizeHostname(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSanitizeHostnameNeverEndsWithHyphen(t *testing.T) {
	// A 63-char truncation must not leave a trailing hyphen: that is not a legal DNS label.
	in := strings.Repeat("ab", 31) + "-tail"
	got := SanitizeHostname(in)
	if strings.HasPrefix(got, "-") || strings.HasSuffix(got, "-") {
		t.Errorf("SanitizeHostname(%q) = %q, which is not a legal DNS label", in, got)
	}
}

func TestRenderHostname(t *testing.T) {
	tests := []struct {
		name     string
		template string
		host     string
		id       string
		want     string
	}{
		{"default template", DefaultHostnameTemplate, "buildbox", "abc123", "app-tail-buildbox"},
		{"id token", "app-tail-{id}", "buildbox", "abc123", "app-tail-abc123"},
		{"os token", "node-{os}", "buildbox", "abc123", "node-" + runtime.GOOS},
		{"all tokens", "{hostname}-{os}-{id}", "Build_Box", "abc123", "build-box-" + runtime.GOOS + "-abc123"},
		{"empty template falls back to default", "", "buildbox", "abc123", "app-tail-buildbox"},
		{"literal template", "fixed-name", "buildbox", "abc123", "fixed-name"},
		{"unresolvable template still yields a name", "{id}", "buildbox", "", AppDirName},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := RenderHostname(tc.template, tc.host, tc.id); got != tc.want {
				t.Errorf("RenderHostname(%q, %q, %q) = %q, want %q", tc.template, tc.host, tc.id, got, tc.want)
			}
		})
	}
}

func TestTwoInstallsGetDistinctHostnames(t *testing.T) {
	// Fleet requirement: nodes provisioned from one profile must not collide in the
	// admin console, which is what the {id} token exists to guarantee.
	a, err := NewMachineID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewMachineID()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two installs generated the same machine id %q", a)
	}
	nameA := RenderHostname("app-tail-{id}", "samehost", a)
	nameB := RenderHostname("app-tail-{id}", "samehost", b)
	if nameA == nameB {
		t.Errorf("two installs on identically-named machines produced the same hostname %q", nameA)
	}
}

func TestNewForwardIDFormat(t *testing.T) {
	seen := make(map[string]struct{}, 200)
	for i := 0; i < 200; i++ {
		id, err := NewForwardID()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(id, "f_") {
			t.Fatalf("forward id %q lacks the f_ prefix", id)
		}
		if isProfileManaged(id) {
			t.Fatalf("generated id %q collides with the profile-managed namespace", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate forward id %q generated", id)
		}
		seen[id] = struct{}{}
	}
}

// A fresh install runs on exactly these values, and every one of them is load-bearing:
// the bind address decides whether the dashboard is reachable, the tag decides whether
// a node can enroll, and the two UDP numbers decide whether datagrams survive.
//
// Validate() alone proves nothing here -- an empty Config{} passes it too -- so a
// Defaults() that returned the zero value would clear this test while shipping an
// agent that binds nowhere and advertises no tag.
func TestTheBuiltInDefaultsAreTheOnesAFreshInstallRunsOn(t *testing.T) {
	got := Defaults()

	if err := got.Validate(); err != nil {
		t.Fatalf("built-in defaults do not pass validation: %v", err)
	}

	s := got.Settings
	if s.UIListen != DefaultUIListenAddr {
		t.Errorf("UIListen = %q, want %q; a fresh install would bind somewhere else",
			s.UIListen, DefaultUIListenAddr)
	}
	// The tailnet's own defaults sit on the connection a fresh install creates, which is
	// the only place they can now be wrong.
	primary, ok := got.Tunnel(PrimaryTunnelID)
	if !ok {
		t.Fatalf("a fresh install has no %q connection, so it joins nothing", PrimaryTunnelID)
	}
	ts := primary.TS()
	if len(ts.Tags) != 1 || ts.Tags[0] != DefaultTag {
		t.Errorf("Tags = %v, want exactly [%q]; a node with no tag cannot enroll under "+
			"a tag-owner policy", ts.Tags, DefaultTag)
	}
	if ts.HostnameTemplate != DefaultHostnameTemplate {
		t.Errorf("HostnameTemplate = %q, want %q", ts.HostnameTemplate, DefaultHostnameTemplate)
	}
	if s.UDPSessionTimeoutSec != DefaultUDPTimeoutSec {
		t.Errorf("UDPSessionTimeoutSec = %d, want %d; zero would make the janitor evict "+
			"every session immediately", s.UDPSessionTimeoutSec, DefaultUDPTimeoutSec)
	}
	if s.UDPBufferBytes != DefaultUDPBufferBytes {
		t.Errorf("UDPBufferBytes = %d, want %d; zero would truncate every datagram",
			s.UDPBufferBytes, DefaultUDPBufferBytes)
	}
	// Both default on: a desktop install shows its icon and opens the dashboard once,
	// which is the whole first-run experience.
	if !s.ShowTray {
		t.Error("ShowTray defaults off; a fresh desktop install would show no icon")
	}
	if !s.AutoOpenDashboard {
		t.Error("AutoOpenDashboard defaults off; a fresh install would open nothing and " +
			"the user would never find the dashboard")
	}

	// On, because the fault it watches for has no other reporter: a machine that loses the
	// route to its tailnet goes on saying the tailnet is up while nothing can reach it.
	if !s.TailnetRouteRepair {
		t.Error("TailnetRouteRepair defaults off; a fresh install would watch nothing")
	}

	// Nothing is configured yet, and a default forward would carry traffic the user
	// never asked for.
	if len(got.Forwards) != 0 {
		t.Errorf("Forwards = %+v, want none on a fresh install", got.Forwards)
	}

	// The zero value is what this test used to accept. Stating it here keeps the
	// assertions above from being quietly weakened back to a Validate() call.
	if err := (&Config{}).Validate(); err != nil {
		t.Fatalf("an empty Config no longer passes Validate (%v), so the comment above "+
			"is stale -- but the field assertions are still the point", err)
	}
}

func TestUDPBufferSizeFallsBackWhenUnset(t *testing.T) {
	if got := (Settings{}).UDPBufferSize(); got != DefaultUDPBufferBytes {
		t.Errorf("UDPBufferSize = %d, want %d", got, DefaultUDPBufferBytes)
	}
	if got := (Settings{UDPBufferBytes: 2048}).UDPBufferSize(); got != 2048 {
		t.Errorf("UDPBufferSize = %d, want 2048", got)
	}
}

// A switch that is off is not evidence its module was configured. Without this, giving
// any module-owned switch a default of true would adopt the module on every install
// written before the change: the stored false differs from the new default, which is
// exactly what adoption reads as a deliberate choice.
func TestAModuleIsNotAdoptedBecauseOneOfItsSwitchesIsOff(t *testing.T) {
	c := Defaults()
	c.Settings.DNSBlockEnabled = false
	c.Settings.DNSBlockOwn = false
	// What an install predating the default carries on disk.
	c.Settings.DNSBlockSystem = false

	applyDefaults(c)

	if c.Settings.DNSBlockEnabled {
		t.Error("the DNS blocking module was switched on for an install that never enabled it")
	}
	if c.Settings.DNSBlockSystem {
		t.Error("a stored false was overwritten by the default, losing the choice that was made")
	}
}

// The other half of the same rule: a value that is actually set still adopts the module,
// so a configuration that predates its switch is not left reporting the module off.
func TestAModuleIsStillAdoptedFromASwitchThatIsOn(t *testing.T) {
	c := Defaults()
	c.Settings.DNSBlockEnabled = false
	c.Settings.DNSBlockOwn = true

	applyDefaults(c)

	if !c.Settings.DNSBlockEnabled {
		t.Error("the DNS blocking module stayed off while one of its switches was on")
	}
}

// The IPS switches carry the same default-on shape as the DNS blocker's, so they are the
// second thing that would adopt its module on every install written before the default.
// Inspection reads traffic and keeps a short in-memory record, so switching it on for
// somebody who never asked is the one outcome that must not happen quietly.
func TestInspectionIsNotAdoptedFromItsDefaultOnSwitches(t *testing.T) {
	c := Defaults()
	c.Settings.IPSEnabled = false
	// What an install predating the defaults carries on disk.
	c.Settings.IPSNames = false
	c.Settings.IPSDestinations = false

	applyDefaults(c)

	if c.Settings.IPSEnabled {
		t.Error("inspection was switched on for an install that never enabled it")
	}
}

// A fresh install gets the two switches on, so turning inspection on is one action rather
// than three. The module stays off until somebody asks for it.
func TestAFreshInstallHasInspectionOffWithBothSwitchesReady(t *testing.T) {
	c := Defaults()

	if c.Settings.IPSEnabled {
		t.Error("inspection is on by default; it must be off until it is asked for")
	}
	if !c.Settings.IPSNames || !c.Settings.IPSDestinations {
		t.Errorf("a fresh install has names=%v destinations=%v, want both on so enabling "+
			"inspection examines something", c.Settings.IPSNames, c.Settings.IPSDestinations)
	}
}
