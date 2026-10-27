// SPDX-License-Identifier: MIT

//go:build !notray

package tray

import "testing"

// countingItem records how many times a row was written to, rather than what it ended up
// showing. The bug this guards against is invisible in the final state: the menu looks
// right and is repainted into that same right state over and over.
type countingItem struct {
	writes int
}

func (c *countingItem) SetTitle(string)   { c.writes++ }
func (c *countingItem) SetTooltip(string) { c.writes++ }
func (c *countingItem) Check()            { c.writes++ }
func (c *countingItem) Uncheck()          { c.writes++ }
func (c *countingItem) Show()             { c.writes++ }
func (c *countingItem) Hide()             { c.writes++ }
func (c *countingItem) Enable()           { c.writes++ }
func (c *countingItem) Disable()          { c.writes++ }

// A repaint that changes nothing must reach the native menu not at all. Windows rebuilds
// an open menu on every write, so a row rewritten with the value it already carries is
// what makes the menu flicker, a submenu widen, and a submenu the pointer is inside of
// close on its own a second after it was opened.
func TestARepaintThatChangesNothingWritesNothing(t *testing.T) {
	native := &countingItem{}
	item := steady(native)

	// The first pass has to land whatever the menu was built with: the wrapper knows
	// nothing about the row until it has written to it.
	item.SetTitle("Network devices")
	item.Show()
	item.Enable()
	item.Uncheck()
	first := native.writes
	if first != 4 {
		t.Fatalf("the first paint made %d writes, want one per value", first)
	}

	for range 10 {
		item.SetTitle("Network devices")
		item.Show()
		item.Enable()
		item.Uncheck()
	}
	if native.writes != first {
		t.Errorf("%d repaints of unchanged values made %d writes to the menu, want none",
			10, native.writes-first)
	}
}

// The point of skipping the repeats is to still deliver the changes. A wrapper that
// dropped a real change would leave a row showing a device that has left the tailnet,
// which is worse than the flicker it was written to stop.
func TestEveryRealChangeStillReachesTheMenu(t *testing.T) {
	native := &countingItem{}
	item := steady(native)

	item.SetTitle("first")
	item.SetTitle("first")
	item.SetTitle("second")
	if native.writes != 2 {
		t.Errorf("two distinct titles and a repeat made %d writes, want 2", native.writes)
	}

	native.writes = 0
	item.Check()
	item.Check()
	item.Uncheck()
	if native.writes != 2 {
		t.Errorf("a check, a repeat and an uncheck made %d writes, want 2", native.writes)
	}

	native.writes = 0
	item.Hide()
	item.Hide()
	item.Show()
	if native.writes != 2 {
		t.Errorf("a hide, a repeat and a show made %d writes, want 2", native.writes)
	}

	native.writes = 0
	item.Disable()
	item.Disable()
	item.Enable()
	if native.writes != 2 {
		t.Errorf("a disable, a repeat and an enable made %d writes, want 2", native.writes)
	}
}
