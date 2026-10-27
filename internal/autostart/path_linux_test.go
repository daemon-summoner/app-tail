// SPDX-License-Identifier: MIT

package autostart

import (
	"os"
	"path/filepath"
	"testing"
)

// The unit has to land where the user's systemd looks, and the link that makes it start has
// to point at the unit that is there now. Both are decided by paths, so both are pinned.

// XDG_CONFIG_HOME moves the unit, but only when it is an absolute path: the specification says
// a relative value is to be ignored, and a unit written relative to whatever the working
// directory happened to be is one systemd never finds.
func TestTheUnitFollowsXDGConfigHomeOnlyWhenItIsAbsolute(t *testing.T) {
	home := t.TempDir()
	m := testManager(home, "run")

	cases := []struct {
		name string
		xdg  string
		want string
	}{
		{"unset", "", filepath.Join(home, ".config")},
		{"absolute", filepath.Join(home, "elsewhere"), filepath.Join(home, "elsewhere")},
		{"relative", "relative/config", filepath.Join(home, ".config")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", c.xdg)

			unit := filepath.Join(c.want, "systemd", "user", ServiceName+".service")
			if got := m.Path(); got != unit {
				t.Errorf("Path() = %s, want %s", got, unit)
			}
			link := filepath.Join(c.want, "systemd", "user", "default.target.wants", ServiceName+".service")
			if got := m.wantedByPath(); got != link {
				t.Errorf("wantedByPath() = %s, want %s", got, link)
			}
		})
	}
}

// The link is what systemd reads at login. One left pointing somewhere stale is a login item
// that never starts, so installing over it points it at the unit again; and the two halves are
// only a login item together, so either one missing reads as not installed.
func TestTheWantedByLinkIsReplacedAndBothHalvesAreNeeded(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	m := testManager(home, "run", "--headless")

	if err := m.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	link := m.wantedByPath()
	if target, err := os.Readlink(link); err != nil || target != m.Path() {
		t.Fatalf("the link points at %q (%v), want the unit at %s", target, err, m.Path())
	}

	// Pointed somewhere stale by a hand edit or an old install, then installed over.
	if err := os.Remove(link); err != nil {
		t.Fatalf("remove the link: %v", err)
	}
	if err := os.Symlink(filepath.Join(home, "old", ServiceName+".service"), link); err != nil {
		t.Fatalf("point the link somewhere stale: %v", err)
	}
	if err := m.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled(true) over a stale link: %v", err)
	}
	if target, err := os.Readlink(link); err != nil || target != m.Path() {
		t.Errorf("after reinstalling the link points at %q (%v), want %s", target, err, m.Path())
	}
	if enabled, err := m.Enabled(); err != nil || !enabled {
		t.Errorf("Enabled() after reinstalling = %t, %v; want installed", enabled, err)
	}

	// The unit without the link never starts.
	if err := os.Remove(link); err != nil {
		t.Fatalf("remove the link: %v", err)
	}
	if enabled, err := m.Enabled(); err != nil || enabled {
		t.Errorf("Enabled() with the unit but no link = %t, %v; want not installed", enabled, err)
	}

	// The link without the unit points at nothing.
	if err := m.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	if err := os.Remove(m.Path()); err != nil {
		t.Fatalf("remove the unit: %v", err)
	}
	if enabled, err := m.Enabled(); err != nil || enabled {
		t.Errorf("Enabled() with the link but no unit = %t, %v; want not installed", enabled, err)
	}

	// Removal takes the dangling link with it rather than tripping over it.
	if err := m.SetEnabled(false); err != nil {
		t.Fatalf("SetEnabled(false) with a dangling link: %v", err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Errorf("the link survived removal: %v", err)
	}
}
