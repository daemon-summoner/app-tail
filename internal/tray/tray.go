// SPDX-License-Identifier: MIT

//go:build !notray

package tray

import (
	"context"
	"errors"
	"runtime"
	"time"

	"fyne.io/systray"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/icon"
)

// refreshInterval is how often the menu re-reads the agent's state. It matches the
// dashboard's status poll: fast enough that a login finishing feels immediate,
// slow enough to be invisible in a process list.
const refreshInterval = 2 * time.Second

// Options configures the tray front end.
type Options struct {
	// Controller is the agent the menu drives. Required.
	Controller Controller
	// OnError receives every action failure, so a click that fails reaches the log
	// as well as the menu.
	OnError func(error)
}

// Supported reports whether a tray icon can be shown in this session.
func Supported() bool {
	return hasDisplay()
}

// Run shows the tray icon and blocks until ctx is cancelled or the user picks Quit.
//
// systray drives a native event loop, so this must be called from the main
// goroutine; main runs the agent in a goroutine alongside it.
func Run(ctx context.Context, opts Options) error {
	if opts.Controller == nil {
		return errors.New("tray: no controller was provided")
	}
	if !Supported() {
		return errors.New("tray: this session has no display; run with --headless")
	}

	// Cancelling this on the way out unblocks the menu goroutine when the event loop
	// ended for a reason of its own, such as the user quitting from the OS.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	started := make(chan struct{})
	finished := make(chan struct{})

	onReady := func() {
		systray.SetIcon(TrayIcon(runtime.GOOS, icon.StatusStarting))
		systray.SetTooltip("app-tail")

		// The CLI schema, so the keys that moved onto the primary connection keep the menu
		// entries they have always had, in the positions they have always had. The menu is
		// a numbered list, and a settings-only schema would silently drop six of them.
		groups := SettingsMenu(config.SettingsCLISchema())
		view, commands, stopFanIn := buildMenu(groups, nativeRoot{})
		model := NewModel(opts.Controller, view, groups, opts.OnError)

		close(started)
		go func() {
			defer close(finished)
			defer stopFanIn()

			ticker := time.NewTicker(refreshInterval)
			defer ticker.Stop()

			model.Run(runCtx, commands, ticker.C)
			// Ends the native loop whether the user quit or the agent shut down.
			systray.Quit()
		}()
	}

	systray.Run(onReady, func() {})
	cancel()

	// If the event loop never got as far as onReady there is no goroutine to wait
	// for, and blocking here would hang shutdown.
	select {
	case <-started:
		<-finished
	default:
	}
	return nil
}

// menuItem is the slice of systray's menu item this package paints through.
//
// It is an interface because a real one can only come from the native menu, which no
// test process has. The paint decisions are where this goes wrong -- an inverted show
// or check leaves a row frozen at its initial state with nothing on screen to explain
// it -- so they are reachable without a tray, and only the construction is not.
type menuItem interface {
	SetTitle(string)
	SetTooltip(string)
	Check()
	Uncheck()
	Show()
	Hide()
	Enable()
	Disable()
}

// menuNode is one native row as the construction sees it: the paint slice, plus the ways a
// row grows children and reports clicks. The real one can only exist inside a running tray,
// so the construction -- which row hangs where, and which command a click sends -- is checked
// against a stand-in.
type menuNode interface {
	menuItem
	AddSubMenuItem(title, tooltip string) menuNode
	AddSubMenuItemCheckbox(title, tooltip string, checked bool) menuNode
	AddSeparator()
	Clicked() <-chan struct{}
}

// menuRoot is the menu itself: where the top-level rows and separators go.
type menuRoot interface {
	AddMenuItem(title, tooltip string) menuNode
	AddSeparator()
}

// nativeItem is systray's item behind menuNode. The two methods that grow children are
// redeclared because the promoted ones hand back systray's own type.
type nativeItem struct{ *systray.MenuItem }

func (n nativeItem) AddSubMenuItem(title, tooltip string) menuNode {
	return nativeItem{n.MenuItem.AddSubMenuItem(title, tooltip)}
}

func (n nativeItem) AddSubMenuItemCheckbox(title, tooltip string, checked bool) menuNode {
	return nativeItem{n.MenuItem.AddSubMenuItemCheckbox(title, tooltip, checked)}
}

func (n nativeItem) Clicked() <-chan struct{} { return n.ClickedCh }

// nativeRoot is systray's menu behind menuRoot.
type nativeRoot struct{}

func (nativeRoot) AddMenuItem(title, tooltip string) menuNode {
	return nativeItem{systray.AddMenuItem(title, tooltip)}
}

func (nativeRoot) AddSeparator() { systray.AddSeparator() }

// The tray's own tooltip and icon are set through package variables for the reason the rows
// are built through menuRoot: the repaint decisions above them are checked without a tray.
var (
	setTrayTooltip = systray.SetTooltip
	setTrayIcon    = systray.SetIcon
)

// systrayView adapts systray's menu items to the View the model writes to.
type systrayView struct {
	status   menuItem
	forwards menuItem
	exitNode menuItem
	toggle   menuItem
	auth     menuItem
	settings map[string]menuItem
	// choices holds every value of every enum setting, keyed by choiceKey, because one
	// setting owns a whole row of items and each is painted on its own.
	choices      map[string]menuItem
	network      menuItem
	networkWhy   menuItem
	approvals    menuItem
	exitSlots    []menuItem
	exitOverflow menuItem
	// systemDNS names what this machine resolves through; dnsSlots are the profiles it
	// can be switched to, one item each, painted on their own.
	systemDNS   menuItem
	dnsSlots    []menuItem
	dnsOverflow menuItem
	// egress names where the traffic no connection carries leaves through; egressSlots are
	// the destinations it can be moved to, one item each, painted on their own.
	egress         menuItem
	egressSlots    []menuItem
	egressOverflow menuItem
	// proxySlots holds one checkbox per proxy instance, painted on its own.
	proxySlots    []menuItem
	proxyOverflow menuItem
	// connectionSlots holds one checkbox per private network, painted on its own.
	connectionSlots    []menuItem
	connectionOverflow menuItem
	// deviceSlots holds one entry per device row; deviceAddresses and deviceNames hold
	// the two rows beneath it, at the same index, because each is painted on its own.
	deviceSlots     []menuItem
	deviceAddresses []menuItem
	deviceNames     []menuItem
	deviceOverflow  menuItem
	deviceEmpty     menuItem

	// The icon and the tooltip belong to the tray itself rather than to a row, so they
	// have no item to hold their last value. They are repainted on every pass like
	// everything else, and re-setting the icon redraws it in the notification area.
	tooltip      string
	tooltipKnown bool
	iconStatus   icon.Status
	iconKnown    bool
}

// choiceKey identifies one value of one setting among all of them.
func choiceKey(key, value string) string { return key + "=" + value }

func (v *systrayView) SetStatus(line string)   { v.status.SetTitle(line) }
func (v *systrayView) SetForwards(line string) { v.forwards.SetTitle(line) }

func (v *systrayView) SetExitNode(line string) {
	if line == "" {
		v.exitNode.Hide()
		return
	}
	v.exitNode.SetTitle(line)
	v.exitNode.Show()
}
func (v *systrayView) SetSystemDNS(line string) {
	if line == "" {
		v.systemDNS.Hide()
		return
	}
	v.systemDNS.SetTitle(line)
	v.systemDNS.Show()
}

func (v *systrayView) SetDNSProfileSlot(index int, label, tooltip string, selected, visible bool) {
	item := v.dnsSlots[index]
	if selected {
		item.Check()
	} else {
		item.Uncheck()
	}
	// Titled even while hidden, for the reason the exit-node slots are: a slot retitled
	// only when visible would show the profile that used to sit there.
	item.SetTitle(label)
	item.SetTooltip(tooltip)
	setVisible(item, visible)
}

func (v *systrayView) SetDNSProfileOverflow(label string) {
	if label == "" {
		v.dnsOverflow.Hide()
		return
	}
	v.dnsOverflow.SetTitle(label)
	v.dnsOverflow.Show()
}

func (v *systrayView) SetEgress(line string) {
	if line == "" {
		v.egress.Hide()
		return
	}
	v.egress.SetTitle(line)
	v.egress.Show()
}

func (v *systrayView) SetEgressSlot(index int, label, tooltip string, selected, visible bool) {
	item := v.egressSlots[index]
	if selected {
		item.Check()
	} else {
		item.Uncheck()
	}
	// Titled even while hidden, for the reason the other pickers' slots are: a slot
	// retitled only when visible would show the connection that used to sit there.
	item.SetTitle(label)
	item.SetTooltip(tooltip)
	setVisible(item, visible)
}

func (v *systrayView) SetEgressOverflow(label string) {
	if label == "" {
		v.egressOverflow.Hide()
		return
	}
	v.egressOverflow.SetTitle(label)
	v.egressOverflow.Show()
}

func (v *systrayView) SetProxySlot(index int, label, tooltip string, checked, visible bool) {
	item := v.proxySlots[index]
	if checked {
		item.Check()
	} else {
		item.Uncheck()
	}
	// Titled even while hidden, for the reason the other pickers' slots are: a slot
	// retitled only when visible would show the instance that used to sit there.
	item.SetTitle(label)
	item.SetTooltip(tooltip)
	setVisible(item, visible)
}

func (v *systrayView) SetProxyOverflow(label string) {
	if label == "" {
		v.proxyOverflow.Hide()
		return
	}
	v.proxyOverflow.SetTitle(label)
	v.proxyOverflow.Show()
}

func (v *systrayView) SetConnectionSlot(index int, label, tooltip string, checked, visible bool) {
	item := v.connectionSlots[index]
	if checked {
		item.Check()
	} else {
		item.Uncheck()
	}
	// Titled even while hidden, for the reason the other pickers' slots are: a slot
	// retitled only when visible would show the connection that used to sit there.
	item.SetTitle(label)
	item.SetTooltip(tooltip)
	setVisible(item, visible)
}

func (v *systrayView) SetConnectionOverflow(label string) {
	if label == "" {
		v.connectionOverflow.Hide()
		return
	}
	v.connectionOverflow.SetTitle(label)
	v.connectionOverflow.Show()
}

func (v *systrayView) SetAuth(label string) { v.auth.SetTitle(label) }

func (v *systrayView) SetApprovals(label string) {
	if label == "" {
		v.approvals.Hide()
		return
	}
	v.approvals.SetTitle(label)
	v.approvals.Show()
}

func (v *systrayView) SetTooltip(text string) {
	if v.tooltipKnown && v.tooltip == text {
		return
	}
	v.tooltip, v.tooltipKnown = text, true
	setTrayTooltip(text)
}

func (v *systrayView) SetToggle(label string, enabled bool) {
	v.toggle.SetTitle(label)
	setEnabled(v.toggle, enabled)
}

func (v *systrayView) SetIcon(status icon.Status) {
	if v.iconKnown && v.iconStatus == status {
		return
	}
	v.iconStatus, v.iconKnown = status, true
	setTrayIcon(TrayIcon(runtime.GOOS, status))
}

func (v *systrayView) SetSetting(key string, checked, available bool) {
	item, ok := v.settings[key]
	if !ok {
		// The model paints only the items it was built with, so this cannot happen
		// from within the package -- but silently dropping a paint would leave a
		// checkbox frozen at its initial state with nothing to explain it.
		return
	}
	if checked {
		item.Check()
	} else {
		item.Uncheck()
	}
	// Hidden rather than disabled: a greyed checkbox still shows a position, and for a
	// setting the agent cannot read that position would be a guess.
	setVisible(item, available)
}

func (v *systrayView) SetChoice(key, value string, selected, available bool) {
	item, ok := v.choices[choiceKey(key, value)]
	if !ok {
		// The model paints only the choices it was built with, so this cannot happen
		// from within the package -- but silently dropping a paint would leave a value
		// marked as the one in force after it stopped being it.
		return
	}
	if selected {
		item.Check()
	} else {
		item.Uncheck()
	}
	setVisible(item, available)
	// The row the values hang off is a plain submenu with no state of its own, so it
	// follows the setting: left behind, it would open onto nothing.
	if parent, ok := v.settings[key]; ok {
		setVisible(parent, available)
	}
}

func (v *systrayView) SetNetworkMode(label string, enabled bool, reason string) {
	v.network.SetTitle(label)
	setEnabled(v.network, enabled)
	if reason == "" {
		v.networkWhy.Hide()
		return
	}
	v.networkWhy.SetTitle(reason)
	v.networkWhy.Show()
}

func (v *systrayView) SetExitNodeSlot(index int, label string, selected, visible bool) {
	item := v.exitSlots[index]
	if selected {
		item.Check()
	} else {
		item.Uncheck()
	}
	// A slot keeps its old title while hidden; retitling only the visible ones would
	// show a stale device the moment the list grew back.
	item.SetTitle(label)
	setVisible(item, visible)
}

func (v *systrayView) SetExitNodeOverflow(label string) {
	if label == "" {
		v.exitOverflow.Hide()
		return
	}
	v.exitOverflow.SetTitle(label)
	v.exitOverflow.Show()
}

func (v *systrayView) SetDeviceSlot(index int, label, address, dnsName string, visible bool) {
	// Titled even while hidden, for the same reason the exit-node slots are: a slot
	// retitled only when visible shows the machine that used to be there.
	v.deviceSlots[index].SetTitle(label)
	setVisible(v.deviceSlots[index], visible)

	// A row whose value is empty stays hidden even in a visible slot: clicking it would
	// put nothing on the clipboard while looking like it had copied something.
	v.deviceAddresses[index].SetTitle(address)
	setVisible(v.deviceAddresses[index], visible && address != "")
	v.deviceNames[index].SetTitle(dnsName)
	setVisible(v.deviceNames[index], visible && dnsName != "")
}

func (v *systrayView) SetDeviceOverflow(label string) {
	if label == "" {
		v.deviceOverflow.Hide()
		return
	}
	v.deviceOverflow.SetTitle(label)
	v.deviceOverflow.Show()
}

func (v *systrayView) SetDeviceEmpty(label string) {
	if label == "" {
		v.deviceEmpty.Hide()
		return
	}
	v.deviceEmpty.SetTitle(label)
	v.deviceEmpty.Show()
}

func setEnabled(item menuItem, enabled bool) {
	if enabled {
		item.Enable()
		return
	}
	item.Disable()
}

func setVisible(item menuItem, visible bool) {
	if visible {
		item.Show()
		return
	}
	item.Hide()
}

// steadyItem is a menu row that applies only the changes that are changes.
//
// The whole menu is repainted on a timer, and almost every pass paints values the rows
// already carry. On Windows each of those writes rebuilds the native menu underneath an
// open one: it flickers, a submenu re-measures and visibly widens, and a submenu the
// pointer is inside of is dismissed outright. Writing a value a row already holds is
// what turns a menu nobody is looking at into one nobody can use, so it is not written.
//
// Nothing is assumed about a row before its first write. The menu is built with titles,
// checkmarks and hidden rows already set, and a wrapper that assumed it knew those would
// skip the first paint of any row that happened to match -- so the first write of each
// kind always reaches the item, and only repeats are dropped.
type steadyItem struct {
	item menuItem

	titled       bool
	title        string
	tooltipKnown bool
	tooltip      string
	checkedKnown bool
	checked      bool
	shownKnown   bool
	shown        bool
	enabledKnown bool
	enabled      bool
}

// steady wraps one native row. Clicks are not routed through it: those come off the
// item's own channel, which the wrapper neither holds nor hides.
func steady(item menuItem) *steadyItem { return &steadyItem{item: item} }

func (s *steadyItem) SetTitle(title string) {
	if s.titled && s.title == title {
		return
	}
	s.title, s.titled = title, true
	s.item.SetTitle(title)
}

func (s *steadyItem) SetTooltip(tooltip string) {
	if s.tooltipKnown && s.tooltip == tooltip {
		return
	}
	s.tooltip, s.tooltipKnown = tooltip, true
	s.item.SetTooltip(tooltip)
}

func (s *steadyItem) Check()   { s.setChecked(true) }
func (s *steadyItem) Uncheck() { s.setChecked(false) }

func (s *steadyItem) setChecked(checked bool) {
	if s.checkedKnown && s.checked == checked {
		return
	}
	s.checked, s.checkedKnown = checked, true
	if checked {
		s.item.Check()
		return
	}
	s.item.Uncheck()
}

func (s *steadyItem) Show() { s.setShown(true) }
func (s *steadyItem) Hide() { s.setShown(false) }

func (s *steadyItem) setShown(shown bool) {
	if s.shownKnown && s.shown == shown {
		return
	}
	s.shown, s.shownKnown = shown, true
	if shown {
		s.item.Show()
		return
	}
	s.item.Hide()
}

func (s *steadyItem) Enable()  { s.setEnabled(true) }
func (s *steadyItem) Disable() { s.setEnabled(false) }

func (s *steadyItem) setEnabled(enabled bool) {
	if s.enabledKnown && s.enabled == enabled {
		return
	}
	s.enabled, s.enabledKnown = enabled, true
	if enabled {
		s.item.Enable()
		return
	}
	s.item.Disable()
}

// The row the rarely-needed sections hang off. The tooltip says what kind of thing is
// behind it, because "Advanced" on its own means whatever the reader guesses it means.
const (
	advancedLabel   = "Advanced"
	advancedTooltip = "Capabilities most installs never turn on"
)

// buildMenu constructs the menu and returns the view, a channel carrying clicks, and
// a function that stops the click forwarders.
//
// Every item the menu will ever show is created here, because systray can hide and
// re-show an item but removing one closes its click channel underneath the goroutine
// reading it. Nothing afterwards does more than retitle, check and hide.
func buildMenu(groups []MenuGroup, root menuRoot) (View, <-chan Command, func()) {
	commands := make(chan Command)
	stop := make(chan struct{})
	onClick := func(item menuNode, cmd Command) {
		go forwardClicks(item.Clicked(), cmd, commands, stop)
	}

	view := &systrayView{
		settings:        make(map[string]menuItem),
		choices:         make(map[string]menuItem),
		exitSlots:       make([]menuItem, ExitNodeSlots),
		dnsSlots:        make([]menuItem, DNSProfileSlots),
		egressSlots:     make([]menuItem, EgressSlots),
		proxySlots:      make([]menuItem, ProxySlots),
		connectionSlots: make([]menuItem, ConnectionSlots),
		deviceSlots:     make([]menuItem, DeviceSlots),
		deviceAddresses: make([]menuItem, DeviceSlots),
		deviceNames:     make([]menuItem, DeviceSlots),
	}

	status := root.AddMenuItem("Starting...", "Current tailnet connection state")
	status.Disable()
	forwards := root.AddMenuItem("No forwards yet", "Configured port forwards")
	forwards.Disable()
	exitNode := root.AddMenuItem("", "The device this machine's other traffic leaves through")
	exitNode.Disable()
	exitNode.Hide()
	view.status, view.forwards, view.exitNode = steady(status), steady(forwards), steady(exitNode)
	// Beside the status, because a change waiting for an administrator is why something the
	// status reports is not working.
	approvals := root.AddMenuItem("", "Ask an administrator to approve the network changes app-tail is waiting on")
	approvals.Hide()
	view.approvals = steady(approvals)
	onClick(approvals, Command{Action: ActionApproveNetworkChanges})

	root.AddSeparator()
	buildDevices(view, root, onClick)

	root.AddSeparator()
	// The advanced parent is created on the first section that wants it, which is what
	// puts it where the authored order says those sections go.
	var advanced menuNode
	leading := false
	for _, group := range groups {
		// The run the menu opens with is closed by a separator, so the two choices somebody
		// opens the menu bar to make are a section of their own rather than the first two
		// rows of a list.
		if leading && !group.Lead {
			root.AddSeparator()
		}
		leading = group.Lead
		add := root.AddMenuItem
		if group.Advanced {
			if advanced == nil {
				advanced = root.AddMenuItem(advancedLabel, advancedTooltip)
			}
			add = advanced.AddSubMenuItem
		}
		buildGroup(view, group, add, onClick)
	}

	root.AddSeparator()
	auth := root.AddMenuItem("Log In", "Connect this device to your tailnet")
	view.auth = steady(auth)
	onClick(auth, Command{Action: ActionAuth})
	dashboard := root.AddMenuItem("Open Dashboard", "Open the app-tail dashboard in your browser")
	onClick(dashboard, Command{Action: ActionOpenDashboard})

	root.AddSeparator()
	quit := root.AddMenuItem("Quit App-Tail", "Stop all forwards and exit")
	onClick(quit, Command{Action: ActionQuit})

	return view, commands, func() { close(stop) }
}

// buildDevices adds the submenu listing the tailnet, one device per slot with a row for
// its address and a row for its name. Each row is titled with the value it copies, so
// the menu answers "what is that machine's address" by being read, without a click.
func buildDevices(view *systrayView, root menuRoot, onClick func(menuNode, Command)) {
	parent := root.AddMenuItem("Network Devices", "Every machine on your tailnet, with its address and name")
	empty := parent.AddSubMenuItem("", "Why this list has nothing in it")
	empty.Disable()
	empty.Hide()
	view.deviceEmpty = steady(empty)
	for i := range view.deviceSlots {
		device := parent.AddSubMenuItem("", "")
		device.Hide()
		view.deviceSlots[i] = steady(device)

		address := device.AddSubMenuItem("", "Copy this device's tailnet address")
		address.Hide()
		view.deviceAddresses[i] = steady(address)
		// The device is not known until a snapshot fills the slot, so the click carries
		// the slot and the model reads the device sitting there.
		onClick(address, Command{Action: ActionCopyDeviceAddress, Slot: i})

		name := device.AddSubMenuItem("", "Copy this device's tailnet name")
		name.Hide()
		view.deviceNames[i] = steady(name)
		onClick(name, Command{Action: ActionCopyDeviceName, Slot: i})
	}
	overflow := parent.AddSubMenuItem("", "Devices this menu has no room for")
	overflow.Hide()
	view.deviceOverflow = steady(overflow)
	onClick(overflow, Command{Action: ActionOpenDashboard})
}

// buildGroup adds one capability's submenu: the action it leads with, its settings, and
// whatever picker belongs to it. add is what the section hangs off -- the menu itself, or
// the advanced submenu.
func buildGroup(view *systrayView, group MenuGroup, add func(title, tooltip string) menuNode,
	onClick func(menuNode, Command)) {
	parent := add(group.Label, "")

	if group.ID == forwardsToggleGroup {
		toggle := parent.AddSubMenuItem("Enable all forwards", "Turn every configured forward on or off")
		view.toggle = steady(toggle)
		onClick(toggle, Command{Action: ActionToggleForwards})
		parent.AddSeparator()
	}
	if group.ID == networkModeGroup {
		network := parent.AddSubMenuItem("Turn on the network interface",
			"Run the tailnet on a network interface, so every program on this machine reaches it")
		view.network = steady(network)
		onClick(network, Command{Action: ActionSetNetworkMode})
		why := parent.AddSubMenuItem("", "What stands in the way of the network interface")
		why.Disable()
		why.Hide()
		view.networkWhy = steady(why)
		parent.AddSeparator()
	}

	for _, item := range group.Items {
		buildSetting(view, parent, item, onClick)
	}

	if group.ID == dnsProfilePickerGroup {
		resolver := parent.AddSubMenuItem("", "What this machine resolves names through")
		resolver.Disable()
		resolver.Hide()
		view.systemDNS = steady(resolver)
	}
	if group.ID == egressPickerGroup {
		where := parent.AddSubMenuItem("", "Where the traffic none of your connections carries leaves through")
		where.Disable()
		where.Hide()
		view.egress = steady(where)

		parent.AddSeparator()
		for i := range view.egressSlots {
			slot := parent.AddSubMenuItemCheckbox("", "Somewhere this machine's internet traffic can leave through", false)
			slot.Hide()
			view.egressSlots[i] = steady(slot)
			// The connection is not known until a snapshot fills the slot, so the click
			// carries the slot and the model turns it into the destination sitting there.
			onClick(slot, Command{Action: ActionSetEgress, Slot: i})
		}
		overflow := parent.AddSubMenuItem("", "Connections this menu has no room for")
		overflow.Hide()
		view.egressOverflow = steady(overflow)
		onClick(overflow, Command{Action: ActionOpenDashboard})
	}
	if group.ID == exitNodePickerGroup {
		parent.AddSeparator()
		for i := range view.exitSlots {
			slot := parent.AddSubMenuItemCheckbox("", "A device your traffic can leave through", false)
			slot.Hide()
			view.exitSlots[i] = steady(slot)
			// The identifier is not known until a snapshot fills the slot, so the click
			// carries the slot and the model turns it into the device sitting there.
			onClick(slot, Command{Action: ActionSetExitNode, Slot: i})
		}
		overflow := parent.AddSubMenuItem("", "Devices this menu has no room for")
		overflow.Hide()
		view.exitOverflow = steady(overflow)
		onClick(overflow, Command{Action: ActionOpenDashboard})
	}
	if group.ID == dnsProfilePickerGroup {
		parent.AddSeparator()
		for i := range view.dnsSlots {
			switch i {
			case dnsTailnetSlot:
				// A profile is a name and up to four addresses, neither of which a menu can
				// take. Switching between the ones that exist is what this menu is for;
				// making one is a handoff to the surface that has a keyboard. It sits with
				// the profile that changes nothing because both are about the list itself
				// rather than about which resolver answers.
				manage := parent.AddSubMenuItem("Resolver profiles...", "Add, change or remove resolver profiles in the dashboard")
				onClick(manage, Command{Action: ActionOpenDNSProfiles})
			case dnsShippedFrom, dnsOwnProfilesFrom:
				parent.AddSeparator()
			}
			slot := parent.AddSubMenuItemCheckbox("", "A set of resolvers this machine can use", false)
			slot.Hide()
			view.dnsSlots[i] = steady(slot)
			// The profile is not known until a snapshot fills the slot, so the click
			// carries the slot and the model turns it into the profile sitting there.
			onClick(slot, Command{Action: ActionSetDNSProfile, Slot: i})
		}
		overflow := parent.AddSubMenuItem("", "Resolver profiles this menu has no room for")
		overflow.Hide()
		view.dnsOverflow = steady(overflow)
		onClick(overflow, Command{Action: ActionOpenDNSProfiles})
	}
	if group.ID == proxyPickerGroup {
		parent.AddSeparator()
		// An instance is a name, an address and a list of rules, none of which a menu can
		// take. Switching the ones that exist on and off is what this menu is for; making
		// one, or granting it something, is a handoff to the surface that has a keyboard.
		manage := parent.AddSubMenuItem("Proxies...", "Add, change or grant proxies in the dashboard")
		onClick(manage, Command{Action: ActionOpenProxies})
		for i := range view.proxySlots {
			slot := parent.AddSubMenuItemCheckbox("", "A proxy this machine runs", false)
			slot.Hide()
			view.proxySlots[i] = steady(slot)
			// The instance is not known until a snapshot fills the slot, so the click carries
			// the slot and the model turns it into the instance sitting there.
			onClick(slot, Command{Action: ActionToggleProxy, Slot: i})
		}
		overflow := parent.AddSubMenuItem("", "Proxies this menu has no room for")
		overflow.Hide()
		view.proxyOverflow = steady(overflow)
		onClick(overflow, Command{Action: ActionOpenProxies})
	}
	if group.ID == connectionPickerGroup {
		// A connection is a server, a key and a set of addresses, none of which a menu can
		// take. Switching the ones that exist on and off is what this menu is for; adding,
		// importing or editing one is a handoff to the surface that has a keyboard.
		manage := parent.AddSubMenuItem("Connections...", "Add, import, edit or remove connections in the dashboard")
		onClick(manage, Command{Action: ActionOpenConnections})
		parent.AddSeparator()
		for i := range view.connectionSlots {
			slot := parent.AddSubMenuItemCheckbox("", "A private network this machine is attached to", false)
			slot.Hide()
			view.connectionSlots[i] = steady(slot)
			// The connection is not known until a snapshot fills the slot, so the click carries
			// the slot and the model turns it into the connection sitting there.
			onClick(slot, Command{Action: ActionToggleConnection, Slot: i})
		}
		overflow := parent.AddSubMenuItem("", "Connections this menu has no room for")
		overflow.Hide()
		view.connectionOverflow = steady(overflow)
		onClick(overflow, Command{Action: ActionOpenConnections})
	}
	if group.ID == allSettingsGroup {
		parent.AddSeparator()
		// Everything the menu is too small for. The dashboard renders the same registry,
		// so a setting is never unreachable just because it cannot be a checkbox.
		more := parent.AddSubMenuItem("All settings...", "Open the full settings form in your browser")
		onClick(more, Command{Action: ActionOpenSettings})
	}
}

// buildSetting adds one registry setting: a checkbox, or a submenu of them for a setting
// with a fixed set of values.
func buildSetting(view *systrayView, parent menuNode, item SettingItem, onClick func(menuNode, Command)) {
	if len(item.Choices) == 0 {
		entry := parent.AddSubMenuItemCheckbox(item.Label, item.Tooltip, false)
		view.settings[item.Key] = steady(entry)
		onClick(entry, Command{Action: ActionSetSetting, Key: item.Key})
		return
	}
	entry := parent.AddSubMenuItem(item.Label, item.Tooltip)
	view.settings[item.Key] = steady(entry)
	for _, choice := range item.Choices {
		value := entry.AddSubMenuItemCheckbox(choice.Label, choice.Tooltip, false)
		view.choices[choiceKey(item.Key, choice.Value)] = steady(value)
		onClick(value, Command{Action: ActionSetChoice, Key: item.Key, Choice: choice.Value})
	}
}

// forwardClicks turns one item's clicks into commands until the menu is torn down.
//
// It takes the click channel rather than the item because a removed item closes it, and
// a closed channel is a ready one: a loop that did not treat that as the end would spin
// on it forever.
func forwardClicks(clicked <-chan struct{}, cmd Command, out chan<- Command, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case _, ok := <-clicked:
			if !ok {
				return
			}
			select {
			case out <- cmd:
			case <-stop:
				return
			}
		}
	}
}
