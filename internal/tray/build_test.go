// SPDX-License-Identifier: MIT

//go:build !notray

package tray

import (
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

// fakeMenu stands in for one native row, or for the menu itself, recording the rows added
// beneath it in order. A nil row is a separator. The real rows can only exist inside a
// running tray, so which row hangs where and what its click sends is checked against this.
type fakeMenu struct {
	fakeItem
	checkable bool
	rows      []*fakeMenu
	clicked   chan struct{}
}

func newFakeMenu(title, tooltip string, checkable bool) *fakeMenu {
	m := &fakeMenu{checkable: checkable, clicked: make(chan struct{}, 1)}
	m.title, m.tooltip, m.shown, m.enabled = title, tooltip, true, true
	return m
}

func (m *fakeMenu) add(title, tooltip string, checkable bool) *fakeMenu {
	child := newFakeMenu(title, tooltip, checkable)
	m.rows = append(m.rows, child)
	return child
}

func (m *fakeMenu) AddMenuItem(title, tooltip string) menuNode { return m.add(title, tooltip, false) }
func (m *fakeMenu) AddSubMenuItem(title, tooltip string) menuNode {
	return m.add(title, tooltip, false)
}
func (m *fakeMenu) AddSubMenuItemCheckbox(title, tooltip string, _ bool) menuNode {
	return m.add(title, tooltip, true)
}
func (m *fakeMenu) AddSeparator()            { m.rows = append(m.rows, nil) }
func (m *fakeMenu) Clicked() <-chan struct{} { return m.clicked }

// titled finds the row beneath this one with a title, at any depth.
func (m *fakeMenu) titled(title string) *fakeMenu {
	for _, row := range m.rows {
		if row == nil {
			continue
		}
		if row.title == title {
			return row
		}
		if found := row.titled(title); found != nil {
			return found
		}
	}
	return nil
}

// index is the position of one row beneath this one, or -1.
func (m *fakeMenu) index(row *fakeMenu) int {
	for i, r := range m.rows {
		if r == row {
			return i
		}
	}
	return -1
}

// shape is the titles of the rows beneath this one in order, a separator written as ---.
func (m *fakeMenu) shape() []string {
	out := make([]string, 0, len(m.rows))
	for _, row := range m.rows {
		if row == nil {
			out = append(out, "---")
			continue
		}
		out = append(out, row.title)
	}
	return out
}

// rowOf is the fake row a painted item was built on.
func rowOf(t *testing.T, item menuItem) *fakeMenu {
	t.Helper()
	s, ok := item.(*steadyItem)
	if !ok {
		t.Fatalf("the view holds a %T, want the steady wrapper the menu builds", item)
	}
	row, ok := s.item.(*fakeMenu)
	if !ok {
		t.Fatalf("the view was built on a %T, want the stand-in row", s.item)
	}
	return row
}

// click presses one row and returns the command that came out, failing if none does.
func click(t *testing.T, row *fakeMenu, commands <-chan Command) Command {
	t.Helper()
	row.clicked <- struct{}{}
	select {
	case cmd := <-commands:
		return cmd
	case <-time.After(3 * time.Second):
		t.Fatalf("clicking %q produced no command, so the row does nothing", row.title)
		return Command{}
	}
}

// buildFake builds the real menu over the stand-in, and tears the forwarders down with the
// test.
func buildFake(t *testing.T, groups []MenuGroup) (*systrayView, *fakeMenu, <-chan Command) {
	t.Helper()
	root := newFakeMenu("", "", false)
	view, commands, stop := buildMenu(groups, root)
	t.Cleanup(stop)
	return view.(*systrayView), root, commands
}

// Every picker slot carries its own position on the click: the model reads what sits in
// that slot at the moment of the click, so a slot wired to a neighbour's position would
// switch to the entry beside the one that was chosen.
func TestEveryPickerSlotClicksAsItsOwnPosition(t *testing.T) {
	view, _, commands := buildFake(t, SettingsMenu(config.SettingsCLISchema()))

	pickers := []struct {
		name   string
		slots  []menuItem
		action Action
	}{
		{"exit node", view.exitSlots, ActionSetExitNode},
		{"resolver profile", view.dnsSlots, ActionSetDNSProfile},
		{"egress", view.egressSlots, ActionSetEgress},
		{"proxy", view.proxySlots, ActionToggleProxy},
		{"connection", view.connectionSlots, ActionToggleConnection},
		{"device address", view.deviceAddresses, ActionCopyDeviceAddress},
		{"device name", view.deviceNames, ActionCopyDeviceName},
	}
	for _, p := range pickers {
		t.Run(p.name, func(t *testing.T) {
			if len(p.slots) == 0 {
				t.Fatal("the picker was built with no slots")
			}
			for i, slot := range p.slots {
				row := rowOf(t, slot)
				if row == nil {
					t.Fatalf("slot %d was never built", i)
				}
				if row.shown {
					t.Errorf("slot %d is visible before anything fills it", i)
				}
				if got, want := click(t, row, commands), (Command{Action: p.action, Slot: i}); got != want {
					t.Errorf("slot %d clicked as %+v, want %+v", i, got, want)
				}
			}
		})
	}
}

// The resolver picker is laid out in sections: the slot that changes nothing and the handoff
// to the dashboard, then the shipped profiles, then the user's own. The separators are what
// make it read as three lists, and each sits exactly before the slot that opens its section.
func TestTheResolverPickerIsLaidOutInItsThreeSections(t *testing.T) {
	view, root, commands := buildFake(t, SettingsMenu(config.SettingsCLISchema()))

	section := root.titled(trayGroupLabels[dnsProfilePickerGroup])
	if section == nil {
		t.Fatalf("no %q submenu was built", trayGroupLabels[dnsProfilePickerGroup])
	}
	slotAt := func(i int) int { return section.index(rowOf(t, view.dnsSlots[i])) }

	manage := section.titled("Resolver profiles...")
	if manage == nil {
		t.Fatal("the picker has no handoff to the dashboard, so no profile can be made from the tray")
	}
	if section.index(manage) != slotAt(dnsTailnetSlot)-1 {
		t.Errorf("the handoff sits at %d, want it beside the tailnet slot at %d", section.index(manage), slotAt(dnsTailnetSlot))
	}
	if got := click(t, manage, commands); got.Action != ActionOpenDNSProfiles {
		t.Errorf("the handoff clicked as %+v, want the dashboard's profile editor opened", got)
	}

	for _, from := range []int{dnsShippedFrom, dnsOwnProfilesFrom} {
		at := slotAt(from)
		if at < 1 || section.rows[at-1] != nil {
			t.Errorf("slot %d opens a section and the row before it is %q rather than a separator", from, section.shape()[max(at-1, 0)])
		}
	}
	fact, overflow := rowOf(t, view.systemDNS), rowOf(t, view.dnsOverflow)
	if section.index(fact) > slotAt(0) || section.index(overflow) < slotAt(DNSProfileSlots-1) {
		t.Errorf("the fact row sits at %d and the overflow at %d, want them either side of the slots:\n%q",
			section.index(fact), section.index(overflow), section.shape())
	}
	if got := click(t, overflow, commands); got.Action != ActionOpenDNSProfiles {
		t.Errorf("the overflow clicked as %+v, want the dashboard's profile editor opened", got)
	}
}

// The menu opens with the sections marked as leading, closed by one separator; the advanced
// sections share one parent that lands where the first of them sits; and the fixed rows
// bracket the whole thing. The order is the whole point of authoring the groups, so it is
// pinned as a shape.
func TestTheMenuIsLaidOutAsLeadRunAdvancedParentAndFixedRows(t *testing.T) {
	groups := []MenuGroup{
		{ID: config.GroupConnection, Label: "Connections", Lead: true},
		{ID: config.GroupInterface, Label: "Network Interface", Lead: true},
		{ID: config.GroupSystemDNS, Label: "Resolver"},
		{ID: config.GroupProxy, Label: "Proxies", Advanced: true},
		{ID: config.GroupIPS, Label: "Traffic Inspection", Advanced: true},
		{ID: config.GroupApplication, Label: "Application"},
	}
	_, root, _ := buildFake(t, groups)

	want := []string{
		"Starting...", "No forwards yet", "", "", "---", "Network Devices", "---",
		"Connections", "Network Interface", "---", "Resolver", advancedLabel, "Application",
		"---", "Log In", "Open Dashboard", "---", "Quit App-Tail",
	}
	got := root.shape()
	if len(got) != len(want) {
		t.Fatalf("the menu is %d rows, want %d:\n got %q\nwant %q", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d is %q, want %q", i, got[i], want[i])
		}
	}
	advanced := root.titled(advancedLabel)
	if shape := advanced.shape(); len(shape) != 2 || shape[0] != "Proxies" || shape[1] != "Traffic Inspection" {
		t.Errorf("the advanced submenu holds %q, want both advanced sections and nothing else", shape)
	}
	if advanced.tooltip != advancedTooltip {
		t.Errorf("the advanced row's tooltip is %q, want it to say what is behind it", advanced.tooltip)
	}
}

// The three fact rows are painted, never clicked, so they start disabled; and the exit node
// row starts hidden because most devices never use one.
func TestTheFactRowsStartDisabledAndTheExitNodeRowHidden(t *testing.T) {
	view, _, _ := buildFake(t, nil)

	if rowOf(t, view.status).enabled || rowOf(t, view.forwards).enabled {
		t.Error("a fact row is clickable, so it looks like an action that does nothing")
	}
	exitNode := rowOf(t, view.exitNode)
	if exitNode.shown || exitNode.enabled {
		t.Errorf("the exit node row starts shown=%v enabled=%v, want hidden and inert", exitNode.shown, exitNode.enabled)
	}
}

// A boolean setting is a checkbox that flips it; a setting with a fixed set of values is a
// submenu with one checkbox per value, each choosing that value. The command a click sends
// names the key, and for a value the value, or the model writes the wrong setting.
func TestASettingIsACheckboxAndAChoiceSetIsASubmenuOfThem(t *testing.T) {
	groups := []MenuGroup{{ID: config.GroupProxy, Label: "Proxies", Items: []SettingItem{
		{Key: "proxy.enabled", Label: "Run the proxy", Tooltip: "Whether the proxy listens"},
		{Key: "proxy.scope", Label: "Who may connect", Tooltip: "Which machines the proxy answers", Choices: []settingChoice{
			{Value: "tailnet", Label: "The tailnet", Tooltip: "Every device on the tailnet"},
			{Value: "all", Label: "Everyone", Tooltip: "Any machine that can reach the port"},
		}},
	}}}
	view, root, commands := buildFake(t, groups)

	box := root.titled("Run the proxy")
	if box == nil || !box.checkable || box.tooltip != "Whether the proxy listens" {
		t.Fatalf("the boolean setting was built as %+v, want a checkbox carrying its help", box)
	}
	if rowOf(t, view.settings["proxy.enabled"]) != box {
		t.Error("the view does not paint the boolean setting on the row that was built for it")
	}
	if got, want := click(t, box, commands), (Command{Action: ActionSetSetting, Key: "proxy.enabled"}); got != want {
		t.Errorf("the checkbox clicked as %+v, want %+v", got, want)
	}

	submenu := root.titled("Who may connect")
	if submenu == nil || submenu.checkable {
		t.Fatalf("the choice set was built as %+v, want a plain submenu row", submenu)
	}
	if rowOf(t, view.settings["proxy.scope"]) != submenu {
		t.Error("the view does not paint the choice set on the submenu row that was built for it")
	}
	if shape := submenu.shape(); len(shape) != 2 || shape[0] != "The tailnet" || shape[1] != "Everyone" {
		t.Fatalf("the submenu holds %q, want one row per value in the authored order", shape)
	}
	for _, value := range []string{"tailnet", "all"} {
		row := rowOf(t, view.choices[choiceKey("proxy.scope", value)])
		if !row.checkable {
			t.Errorf("the %q value is not a checkbox, so nothing marks it as in force", value)
		}
		if got, want := click(t, row, commands), (Command{Action: ActionSetChoice, Key: "proxy.scope", Choice: value}); got != want {
			t.Errorf("the %q value clicked as %+v, want %+v", value, got, want)
		}
	}
}

// The traffic-inspection switch is the newest thing the menu carries, and the one most
// recently wired: it has to be reachable from the real schema, as a checkbox, sending the
// click that flips its own key.
func TestTheTrafficInspectionSwitchIsInTheRealMenuAndClickable(t *testing.T) {
	view, root, commands := buildFake(t, SettingsMenu(config.SettingsCLISchema()))

	section := root.titled(trayGroupLabels[config.GroupIPS])
	if section == nil {
		t.Fatalf("no %q submenu was built from the real schema", trayGroupLabels[config.GroupIPS])
	}
	item, ok := view.settings["ips.enabled"]
	if !ok {
		t.Fatal("ips.enabled is not among the settings the menu paints")
	}
	row := rowOf(t, item)
	if section.index(row) < 0 {
		t.Errorf("the switch was built outside its own section:\n%q", section.shape())
	}
	if !row.checkable {
		t.Error("the switch is not a checkbox, so nothing shows whether inspection is on")
	}
	if got, want := click(t, row, commands), (Command{Action: ActionSetSetting, Key: "ips.enabled"}); got != want {
		t.Errorf("the switch clicked as %+v, want %+v", got, want)
	}
}

// The fixed rows are the way in and the way out, and each has to send its own command: a
// quit row wired to the dashboard is a tray that cannot be closed.
func TestTheFixedRowsSendTheirOwnCommands(t *testing.T) {
	_, root, commands := buildFake(t, nil)

	for title, want := range map[string]Action{
		"Log In":         ActionAuth,
		"Open Dashboard": ActionOpenDashboard,
		"Quit App-Tail":  ActionQuit,
	} {
		row := root.titled(title)
		if row == nil {
			t.Errorf("no %q row was built", title)
			continue
		}
		if got := click(t, row, commands); got.Action != want {
			t.Errorf("%q clicked as %+v, want action %v", title, got, want)
		}
	}
}

// The approve row starts hidden, because a machine has nothing waiting until the privileged
// side refuses something, and a click on it asks for the approval rather than anything else.
func TestTheApproveRowStartsHiddenAndAsksForTheApproval(t *testing.T) {
	view, _, commands := buildFake(t, nil)

	row := rowOf(t, view.approvals)
	if row.shown {
		t.Error("the approve row starts shown, offering a password prompt with nothing waiting")
	}
	if got := click(t, row, commands); got.Action != ActionApproveNetworkChanges {
		t.Errorf("the approve row clicked as %+v, want the approval asked for", got)
	}
}
