// SPDX-License-Identifier: MIT

//go:build !notray

package tray

import (
	"strconv"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/icon"
)

// fakeItem records what a menu row was painted with. The native item can only come from
// a running tray, so this is what the paint decisions are checked against.
type fakeItem struct {
	title   string
	tooltip string
	checked bool
	shown   bool
	enabled bool
}

func newFakeItem() *fakeItem { return &fakeItem{shown: true, enabled: true} }

func (i *fakeItem) SetTitle(s string)   { i.title = s }
func (i *fakeItem) SetTooltip(s string) { i.tooltip = s }
func (i *fakeItem) Check()              { i.checked = true }
func (i *fakeItem) Uncheck()            { i.checked = false }
func (i *fakeItem) Show()               { i.shown = true }
func (i *fakeItem) Hide()               { i.shown = false }
func (i *fakeItem) Enable()             { i.enabled = true }
func (i *fakeItem) Disable()            { i.enabled = false }

// fakeView is a systrayView over rows a test can read back. Every row the real menu
// builds is present, keyed the way a test names it: a setting by its key, one value of a
// setting by "key=value", and an exit-node slot by its position.
func fakeView(keys ...string) (*systrayView, map[string]*fakeItem) {
	rows := map[string]*fakeItem{
		"status":        newFakeItem(),
		"forwards":      newFakeItem(),
		"exitNode":      newFakeItem(),
		"toggle":        newFakeItem(),
		"auth":          newFakeItem(),
		"network":       newFakeItem(),
		"networkWhy":    newFakeItem(),
		"overflow":      newFakeItem(),
		"devOverflow":   newFakeItem(),
		"devEmpty":      newFakeItem(),
		"proxyOverflow": newFakeItem(),

		"connectionOverflow": newFakeItem(),
		"systemDNS":          newFakeItem(),
		"dnsOverflow":        newFakeItem(),
		"egress":             newFakeItem(),
		"egressOverflow":     newFakeItem(),
	}
	settings := make(map[string]menuItem, len(keys))
	for _, key := range keys {
		item := newFakeItem()
		rows[key] = item
		settings[key] = item
	}
	slots := make([]menuItem, ExitNodeSlots)
	for i := range slots {
		item := newFakeItem()
		rows["slot"+strconv.Itoa(i)] = item
		slots[i] = item
	}
	proxies := make([]menuItem, ProxySlots)
	for i := range proxies {
		item := newFakeItem()
		rows["proxy"+strconv.Itoa(i)] = item
		proxies[i] = item
	}
	connections := make([]menuItem, ConnectionSlots)
	for i := range connections {
		item := newFakeItem()
		rows["connection"+strconv.Itoa(i)] = item
		connections[i] = item
	}
	dnsSlots := make([]menuItem, DNSProfileSlots)
	for i := range dnsSlots {
		item := newFakeItem()
		rows["dns"+strconv.Itoa(i)] = item
		dnsSlots[i] = item
	}
	egressSlots := make([]menuItem, EgressSlots)
	for i := range egressSlots {
		item := newFakeItem()
		rows["egress"+strconv.Itoa(i)] = item
		egressSlots[i] = item
	}
	devices := make([]menuItem, DeviceSlots)
	addresses := make([]menuItem, DeviceSlots)
	names := make([]menuItem, DeviceSlots)
	for i := range devices {
		device, address, name := newFakeItem(), newFakeItem(), newFakeItem()
		rows["dev"+strconv.Itoa(i)] = device
		rows["dev"+strconv.Itoa(i)+"addr"] = address
		rows["dev"+strconv.Itoa(i)+"name"] = name
		devices[i], addresses[i], names[i] = device, address, name
	}
	return &systrayView{
		status:        rows["status"],
		forwards:      rows["forwards"],
		exitNode:      rows["exitNode"],
		toggle:        rows["toggle"],
		auth:          rows["auth"],
		settings:      settings,
		choices:       map[string]menuItem{},
		network:       rows["network"],
		networkWhy:    rows["networkWhy"],
		exitSlots:     slots,
		exitOverflow:  rows["overflow"],
		proxySlots:    proxies,
		proxyOverflow: rows["proxyOverflow"],

		connectionSlots:    connections,
		connectionOverflow: rows["connectionOverflow"],
		systemDNS:          rows["systemDNS"],
		dnsSlots:           dnsSlots,
		dnsOverflow:        rows["dnsOverflow"],
		egress:             rows["egress"],
		egressSlots:        egressSlots,
		egressOverflow:     rows["egressOverflow"],

		deviceSlots:     devices,
		deviceAddresses: addresses,
		deviceNames:     names,
		deviceOverflow:  rows["devOverflow"],
		deviceEmpty:     rows["devEmpty"],
	}, rows
}

// withChoices adds the values of one setting to a view, the way buildSetting does.
func withChoices(v *systrayView, rows map[string]*fakeItem, key string, values ...string) {
	for _, value := range values {
		item := newFakeItem()
		rows[choiceKey(key, value)] = item
		v.choices[choiceKey(key, value)] = item
	}
}

// The exit node row is the only one that appears and disappears. Most devices never use
// one, and a row reading "Exit node:" with nothing after it is worse than no row: it
// reads as a device whose traffic is leaving through something unnamed.
func TestTheExitNodeRowIsOnlyThereWhileOneIsInUse(t *testing.T) {
	v, rows := fakeView()

	v.SetExitNode("Exit node: mullvad-berlin")
	if !rows["exitNode"].shown {
		t.Error("the exit node in use has no row in the menu")
	}
	if rows["exitNode"].title != "Exit node: mullvad-berlin" {
		t.Errorf("the row reads %q, want it to name the device", rows["exitNode"].title)
	}

	v.SetExitNode("")
	if rows["exitNode"].shown {
		t.Errorf("no exit node is in use and the menu still shows %q", rows["exitNode"].title)
	}
}

// A checkbox the agent cannot read has no honest position to sit in, so it goes away
// rather than showing a guess -- a greyed one still reads as off. Both halves are one
// paint, and getting either backwards freezes a row at whatever it started as.
func TestASettingRowCarriesBothItsPositionAndWhetherItCanBeRead(t *testing.T) {
	v, rows := fakeView("dns", "security")

	v.SetSetting("dns", true, true)
	if !rows["dns"].checked || !rows["dns"].shown {
		t.Errorf("a setting that is on and readable painted checked=%v shown=%v, want both",
			rows["dns"].checked, rows["dns"].shown)
	}

	v.SetSetting("dns", false, true)
	if rows["dns"].checked {
		t.Error("a setting that was turned off still reads as on")
	}

	v.SetSetting("security", true, false)
	if rows["security"].shown {
		t.Error("a setting the agent cannot read is still offered, so its position is a guess")
	}
}

// The model paints only rows it was built with, so an unknown key cannot arrive from
// inside this package. It must not take the menu down if one ever does: a tray that
// panics leaves the user with no way to reach the app at all.
func TestASettingTheMenuDoesNotCarryIsDroppedRatherThanFatal(t *testing.T) {
	v, rows := fakeView("dns")

	v.SetSetting("nothing.like.this", true, true)

	if rows["dns"].checked {
		t.Error("a paint for an unknown key landed on another row")
	}
}

// One value of a setting is a checkbox among its siblings, so exactly one is ticked and
// the rest are not. Ticking without unticking would leave every value a user ever chose
// marked as the one in force.
func TestOneValueOfASettingIsTickedAndTheRestAreNot(t *testing.T) {
	v, rows := fakeView("proxy.scope")
	withChoices(v, rows, "proxy.scope", "tailnet", "all")

	v.SetChoice("proxy.scope", "tailnet", true, true)
	v.SetChoice("proxy.scope", "all", false, true)
	if !rows[choiceKey("proxy.scope", "tailnet")].checked || rows[choiceKey("proxy.scope", "all")].checked {
		t.Error("the value in force is not the only one ticked")
	}

	v.SetChoice("proxy.scope", "tailnet", false, true)
	v.SetChoice("proxy.scope", "all", true, true)
	if rows[choiceKey("proxy.scope", "tailnet")].checked || !rows[choiceKey("proxy.scope", "all")].checked {
		t.Error("choosing another value left the previous one ticked as well")
	}
}

// The submenu row the values hang off carries no state of its own, so it has to follow
// the setting: left behind while its values are hidden, it opens onto nothing.
func TestASettingTheAgentCannotWriteTakesItsValuesAndItsRowWithIt(t *testing.T) {
	v, rows := fakeView("proxy.scope")
	withChoices(v, rows, "proxy.scope", "tailnet", "all")

	v.SetChoice("proxy.scope", "tailnet", true, false)
	v.SetChoice("proxy.scope", "all", false, false)

	if rows[choiceKey("proxy.scope", "tailnet")].shown || rows[choiceKey("proxy.scope", "all")].shown {
		t.Error("a setting the agent cannot write still offers its values")
	}
	if rows["proxy.scope"].shown {
		t.Error("the submenu row survived its values, so it opens onto nothing")
	}
}

// Same rule as the settings rows: a value the menu was not built with cannot arrive from
// inside this package, and must not take the tray down if one ever does.
func TestAValueTheMenuDoesNotCarryIsDroppedRatherThanFatal(t *testing.T) {
	v, rows := fakeView("proxy.scope")
	withChoices(v, rows, "proxy.scope", "tailnet")

	v.SetChoice("proxy.scope", "nothing-like-this", true, true)

	if rows[choiceKey("proxy.scope", "tailnet")].checked {
		t.Error("a paint for an unknown value landed on another row")
	}
}

// The interface entry offers whichever mode the machine is not on, and a machine that
// cannot carry the mode gets the reason on the row beneath rather than a silent grey
// entry. The reason row goes away when there is none: an empty line reads as a blank fact.
func TestTheInterfaceRowCarriesItsOfferAndTheReasonItCannotBeTaken(t *testing.T) {
	v, rows := fakeView()

	v.SetNetworkMode("Turn on the network interface", false, "the privileged helper is not installed")
	if rows["network"].title != "Turn on the network interface" || rows["network"].enabled {
		t.Errorf("the row painted %q enabled=%v, want the offer stated and unclickable",
			rows["network"].title, rows["network"].enabled)
	}
	if !rows["networkWhy"].shown || rows["networkWhy"].title != "the privileged helper is not installed" {
		t.Errorf("the reason row painted %q shown=%v, want the obstacle named",
			rows["networkWhy"].title, rows["networkWhy"].shown)
	}

	v.SetNetworkMode("Turn off the network interface", true, "")
	if !rows["network"].enabled {
		t.Error("a machine that can carry the mode still cannot click the entry")
	}
	if rows["networkWhy"].shown {
		t.Errorf("nothing stands in the way and the menu still shows %q", rows["networkWhy"].title)
	}
}

// A slot keeps its title while hidden, so the tailnet shrinking and growing again must not
// leave a device that has gone sitting in a slot that came back.
func TestAnExitNodeSlotIsRetitledEvenWhileItIsHidden(t *testing.T) {
	v, rows := fakeView()

	v.SetExitNodeSlot(0, "gpu-box", true, true)
	v.SetExitNodeSlot(0, "gpu-box", false, false)
	if rows["slot0"].shown || rows["slot0"].checked {
		t.Error("a device that left the tailnet still holds its slot")
	}

	v.SetExitNodeSlot(0, "laptop", false, true)
	if rows["slot0"].title != "laptop" {
		t.Errorf("the slot came back reading %q, which is the device that went away", rows["slot0"].title)
	}
}

// The overflow row is a count, so it is there only while there is something to count.
func TestTheOverflowRowIsOnlyThereWhileDevicesAreMissing(t *testing.T) {
	v, rows := fakeView()

	v.SetExitNodeOverflow("3 more on the dashboard")
	if !rows["overflow"].shown || rows["overflow"].title != "3 more on the dashboard" {
		t.Errorf("the overflow row painted %q shown=%v, want the count stated",
			rows["overflow"].title, rows["overflow"].shown)
	}

	v.SetExitNodeOverflow("")
	if rows["overflow"].shown {
		t.Errorf("every device fits and the menu still shows %q", rows["overflow"].title)
	}
}

// A proxy row carries a checkbox, a name and a tooltip, and keeps its title while hidden:
// an instance deleted and another added must not leave the old one's name in a slot that
// came back, and a stale tooltip would name a port nothing is bound to.
func TestAProxySlotIsRetitledEvenWhileItIsHidden(t *testing.T) {
	v, rows := fakeView()

	v.SetProxySlot(0, "psql", "127.0.0.1:1081, reaches db.corp.internal", true, true)
	if !rows["proxy0"].checked || !rows["proxy0"].shown {
		t.Errorf("an instance that is on painted checked=%v shown=%v, want both",
			rows["proxy0"].checked, rows["proxy0"].shown)
	}
	if rows["proxy0"].tooltip != "127.0.0.1:1081, reaches db.corp.internal" {
		t.Errorf("the tooltip reads %q, want where it is bound and what it reaches", rows["proxy0"].tooltip)
	}

	v.SetProxySlot(0, "", "", false, false)
	if rows["proxy0"].shown || rows["proxy0"].checked {
		t.Error("an instance that was deleted still holds its slot")
	}

	v.SetProxySlot(0, "browser", "127.0.0.1:1082, reaches everything on office", false, true)
	if rows["proxy0"].title != "browser" || rows["proxy0"].tooltip != "127.0.0.1:1082, reaches everything on office" {
		t.Errorf("the slot came back reading %q/%q, which is the instance that went away",
			rows["proxy0"].title, rows["proxy0"].tooltip)
	}
}

// The proxies overflow row is a count, so it is there only while there is something to
// count -- the same contract the other pickers' overflow rows hold.
func TestTheProxiesOverflowRowIsOnlyThereWhileInstancesAreMissing(t *testing.T) {
	v, rows := fakeView()

	v.SetProxyOverflow("2 more on the dashboard...")
	if !rows["proxyOverflow"].shown || rows["proxyOverflow"].title != "2 more on the dashboard..." {
		t.Errorf("the overflow row painted %q shown=%v, want the count stated",
			rows["proxyOverflow"].title, rows["proxyOverflow"].shown)
	}

	v.SetProxyOverflow("")
	if rows["proxyOverflow"].shown {
		t.Errorf("every instance fits and the menu still shows %q", rows["proxyOverflow"].title)
	}
}

// The toggle is the one row whose label and whether it can be clicked move together: it
// reads "Enable all forwards" while there is something to enable, and is unclickable
// while the node is down. A label that changed without the state would offer an action
// that does nothing.
func TestTheToggleRowCarriesItsLabelAndWhetherItCanBeUsed(t *testing.T) {
	v, rows := fakeView()

	v.SetToggle("Disable all forwards", true)
	if rows["toggle"].title != "Disable all forwards" || !rows["toggle"].enabled {
		t.Errorf("toggle painted %q enabled=%v, want the label offered and clickable",
			rows["toggle"].title, rows["toggle"].enabled)
	}

	v.SetToggle("Enable all forwards", false)
	if rows["toggle"].enabled {
		t.Error("the toggle is clickable while there is nothing it can do")
	}
}

// The plain rows are facts, not actions, and the model rewrites them on every tick.
func TestTheStatusRowsCarryWhateverTheModelLastWrote(t *testing.T) {
	v, rows := fakeView()

	v.SetStatus("Connected as workstation")
	v.SetForwards("3 of 4 forwards running")
	v.SetAuth("Log Out")
	v.SetIcon(icon.StatusHealthy)

	if rows["status"].title != "Connected as workstation" {
		t.Errorf("status row = %q, want the line the model wrote", rows["status"].title)
	}
	if rows["forwards"].title != "3 of 4 forwards running" {
		t.Errorf("forwards row = %q, want the line the model wrote", rows["forwards"].title)
	}
	if rows["auth"].title != "Log Out" {
		t.Errorf("auth row = %q, want the line the model wrote", rows["auth"].title)
	}
}

// Every row's clicks become the one command that row means. Sending the wrong command
// makes a menu entry do another entry's job, which is the failure a user cannot undo.
func TestAClickBecomesTheCommandItsOwnRowStandsFor(t *testing.T) {
	clicks := make(chan struct{}, 1)
	commands := make(chan Command, 1)
	stop := make(chan struct{})
	defer close(stop)

	want := Command{Action: ActionSetSetting, Key: "dns.enabled"}
	go forwardClicks(clicks, want, commands, stop)

	clicks <- struct{}{}
	select {
	case got := <-commands:
		if got != want {
			t.Errorf("a click produced %+v, want %+v", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a click produced no command, so the menu row does nothing")
	}
}

// A removed row closes its click channel, and a closed channel is always ready. A loop
// that did not treat that as the end would spin a core for the life of the process.
func TestAClickForwarderEndsWhenItsRowGoesAway(t *testing.T) {
	clicks := make(chan struct{})
	commands := make(chan Command)
	stop := make(chan struct{})
	defer close(stop)

	done := make(chan struct{})
	go func() {
		defer close(done)
		forwardClicks(clicks, Command{Action: ActionQuit}, commands, stop)
	}()

	close(clicks)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the forwarder is still running after its row went away")
	}
}

// Tearing the menu down has to end every forwarder, including the ones parked on a
// command nobody is reading: the model has already stopped by then, so a forwarder
// blocked on the send would leak for the life of the process.
func TestTearingTheMenuDownEndsAForwarderWithACommandInHand(t *testing.T) {
	clicks := make(chan struct{}, 1)
	commands := make(chan Command)
	stop := make(chan struct{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		forwardClicks(clicks, Command{Action: ActionQuit}, commands, stop)
	}()

	// Clicked with nothing reading commands, so the forwarder is parked on the send.
	clicks <- struct{}{}
	close(stop)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a forwarder holding a command outlived the menu it belonged to")
	}
}

// A device row and the two rows under it are painted together, and the copy rows carry
// the values themselves: the menu answers "what is that machine's address" by being read,
// which is most of why it is opened.
func TestADeviceSlotPaintsTheMachineAndBothOfItsCopyRows(t *testing.T) {
	v, rows := fakeView()

	v.SetDeviceSlot(0, "htpc", "100.101.102.103", "htpc.tail1a2b3c.ts.net", true)

	if rows["dev0"].title != "htpc" || !rows["dev0"].shown {
		t.Errorf("the device row painted %q shown=%v, want the machine named",
			rows["dev0"].title, rows["dev0"].shown)
	}
	if rows["dev0addr"].title != "100.101.102.103" || !rows["dev0addr"].shown {
		t.Errorf("the address row painted %q shown=%v, want the address readable without a click",
			rows["dev0addr"].title, rows["dev0addr"].shown)
	}
	if rows["dev0name"].title != "htpc.tail1a2b3c.ts.net" || !rows["dev0name"].shown {
		t.Errorf("the name row painted %q shown=%v, want the name readable without a click",
			rows["dev0name"].title, rows["dev0name"].shown)
	}
}

// A row offering to copy a value the tailnet never published would put nothing on the
// clipboard while looking exactly like the row beside it that works.
func TestADeviceWithNoNamePaintsNoRowOfferingToCopyOne(t *testing.T) {
	v, rows := fakeView()

	v.SetDeviceSlot(0, "printer", "100.64.0.9", "", true)

	if !rows["dev0addr"].shown {
		t.Error("the device has an address and no row offers it")
	}
	if rows["dev0name"].shown {
		t.Errorf("the tailnet publishes no name for this device and the menu offers to copy %q",
			rows["dev0name"].title)
	}
}

// Hiding a device has to take its copy rows with it. A child left visible under a hidden
// parent is a row that copies a machine no longer on the tailnet.
func TestHidingADeviceTakesItsCopyRowsWithIt(t *testing.T) {
	v, rows := fakeView()

	v.SetDeviceSlot(0, "htpc", "100.101.102.103", "htpc.tail1a2b3c.ts.net", true)
	v.SetDeviceSlot(0, "", "", "", false)

	for _, row := range []string{"dev0", "dev0addr", "dev0name"} {
		if rows[row].shown {
			t.Errorf("%s is still shown after the device left the tailnet", row)
		}
	}
}

// The devices overflow row is a count, so it is there only while there is something to
// count -- the same contract the exit-node overflow row holds.
func TestTheDevicesOverflowRowIsOnlyThereWhileMachinesAreMissing(t *testing.T) {
	v, rows := fakeView()

	v.SetDeviceOverflow("7 more on the dashboard...")
	if !rows["devOverflow"].shown || rows["devOverflow"].title != "7 more on the dashboard..." {
		t.Errorf("the overflow row painted %q shown=%v, want the count stated",
			rows["devOverflow"].title, rows["devOverflow"].shown)
	}

	v.SetDeviceOverflow("")
	if rows["devOverflow"].shown {
		t.Errorf("every device fits and the menu still shows %q", rows["devOverflow"].title)
	}
}

// The placeholder is what keeps the devices submenu from opening onto nothing, so it is
// there exactly while the list is, and gone the moment a device fills a slot.
func TestTheDevicesPlaceholderRowIsOnlyThereWhileTheListIsEmpty(t *testing.T) {
	v, rows := fakeView()

	v.SetDeviceEmpty("Not connected yet")
	if !rows["devEmpty"].shown || rows["devEmpty"].title != "Not connected yet" {
		t.Errorf("the placeholder painted %q shown=%v, want the reason stated",
			rows["devEmpty"].title, rows["devEmpty"].shown)
	}

	v.SetDeviceEmpty("")
	if rows["devEmpty"].shown {
		t.Errorf("the tailnet has devices and the menu still shows %q", rows["devEmpty"].title)
	}
}

// The resolver and egress pickers each lead with a fact row that is only there while there
// is a fact to state, carry one checkbox per slot that keeps its title while hidden, and end
// with a count that is only there while something is missing. Each setter is its own paint,
// and any one of them inverted freezes a row at whatever it started as.
func TestTheResolverAndEgressPickersPaintTheirFactSlotsAndOverflowRows(t *testing.T) {
	v, rows := fakeView()

	pickers := []struct {
		name     string
		fact     func(string)
		slot     func(int, string, string, bool, bool)
		overflow func(string)
		factRow  string
		slotRow  string
		overRow  string
	}{
		{"resolver", v.SetSystemDNS, v.SetDNSProfileSlot, v.SetDNSProfileOverflow, "systemDNS", "dns0", "dnsOverflow"},
		{"egress", v.SetEgress, v.SetEgressSlot, v.SetEgressOverflow, "egress", "egress0", "egressOverflow"},
		{"connection", func(string) {}, v.SetConnectionSlot, v.SetConnectionOverflow, "", "connection0", "connectionOverflow"},
	}
	for _, p := range pickers {
		t.Run(p.name, func(t *testing.T) {
			if p.factRow != "" {
				p.fact("Resolving through Cloudflare")
				if !rows[p.factRow].shown || rows[p.factRow].title != "Resolving through Cloudflare" {
					t.Errorf("the fact row painted %q shown=%v, want the fact stated", rows[p.factRow].title, rows[p.factRow].shown)
				}
				p.fact("")
				if rows[p.factRow].shown {
					t.Errorf("nothing to state and the menu still shows %q", rows[p.factRow].title)
				}
			}

			p.slot(0, "Cloudflare", "1.1.1.1, 1.0.0.1", true, true)
			if !rows[p.slotRow].checked || !rows[p.slotRow].shown || rows[p.slotRow].tooltip != "1.1.1.1, 1.0.0.1" {
				t.Errorf("a selected slot painted checked=%v shown=%v tooltip=%q, want ticked, shown and described",
					rows[p.slotRow].checked, rows[p.slotRow].shown, rows[p.slotRow].tooltip)
			}
			p.slot(0, "", "", false, false)
			if rows[p.slotRow].shown || rows[p.slotRow].checked {
				t.Error("an entry that went away still holds its slot")
			}
			p.slot(0, "Quad9", "9.9.9.9", false, true)
			if rows[p.slotRow].title != "Quad9" || rows[p.slotRow].tooltip != "9.9.9.9" || rows[p.slotRow].checked {
				t.Errorf("the slot came back reading %q/%q checked=%v, want the entry now sitting there, unticked",
					rows[p.slotRow].title, rows[p.slotRow].tooltip, rows[p.slotRow].checked)
			}

			p.overflow("4 more on the dashboard...")
			if !rows[p.overRow].shown || rows[p.overRow].title != "4 more on the dashboard..." {
				t.Errorf("the overflow row painted %q shown=%v, want the count stated", rows[p.overRow].title, rows[p.overRow].shown)
			}
			p.overflow("")
			if rows[p.overRow].shown {
				t.Errorf("everything fits and the menu still shows %q", rows[p.overRow].title)
			}
		})
	}
}

// The tooltip and the icon belong to the tray rather than to a row, so nothing else remembers
// their last value: a repaint every two seconds with the same value would redraw the
// notification area every two seconds, and one that skipped a changed value would leave the
// icon saying the node is healthy after it stopped being.
func TestTheTrayIconAndTooltipAreRedrawnOnlyWhenTheyChange(t *testing.T) {
	var tooltips []string
	var icons int
	before := [2]any{setTrayTooltip, setTrayIcon}
	setTrayTooltip = func(text string) { tooltips = append(tooltips, text) }
	setTrayIcon = func([]byte) { icons++ }
	t.Cleanup(func() {
		setTrayTooltip = before[0].(func(string))
		setTrayIcon = before[1].(func([]byte))
	})
	v, _ := fakeView()

	v.SetTooltip("app-tail: connected")
	v.SetTooltip("app-tail: connected")
	v.SetTooltip("app-tail: 2 forwards down")
	if len(tooltips) != 2 || tooltips[1] != "app-tail: 2 forwards down" {
		t.Errorf("the tray tooltip was set to %q, want each distinct value once", tooltips)
	}

	v.SetIcon(icon.StatusHealthy)
	v.SetIcon(icon.StatusHealthy)
	v.SetIcon(icon.StatusFault)
	v.SetIcon(icon.StatusHealthy)
	if icons != 3 {
		t.Errorf("the icon was redrawn %d times over four paints of three changes, want 3", icons)
	}
}
