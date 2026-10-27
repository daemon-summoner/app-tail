// SPDX-License-Identifier: MIT

// Package tray provides the optional system-tray front end.
//
// The tray is a thin client: it renders a snapshot the agent hands it and calls back
// into the agent for every action. All of the label logic lives here, free of build
// constraints and of systray itself, so it is exercised on every platform.
package tray

import (
	"fmt"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/icon"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// Controller is everything the tray needs from the agent. It is declared here, by
// the consumer, so the agent never has to import this package.
type Controller interface {
	// Snapshot returns the current state for the menu.
	Snapshot() Snapshot
	// OpenDashboard opens the loopback UI in the user's browser.
	OpenDashboard() error
	// OpenSettings opens the dashboard with the settings form already showing, which
	// is where every setting the menu is too small for lives.
	OpenSettings() error
	// OpenDNSProfiles opens the dashboard at the DNS section. A resolver profile is a name
	// and up to four server addresses, and a menu has no way to take either, so this is
	// where the menu hands over to the one surface that can.
	OpenDNSProfiles() error
	// OpenProxies opens the dashboard at the proxies section. An instance is a name, an
	// address and a list of rules, none of which a menu can take, so adding or granting
	// one is a handoff to the surface that can.
	OpenProxies() error
	// OpenConnections opens the dashboard at the connections section. A connection is a
	// server, a key and a set of addresses, none of which a menu can take, so adding,
	// importing or editing one is a handoff to the surface that can.
	OpenConnections() error
	// SetAllForwardsEnabled enables or disables every configured forward.
	SetAllForwardsEnabled(enabled bool) error
	// SetConnectionEnabled switches one private network on or off, by the id the document
	// gives it. Everything stored about it stays, so switching it back on brings up the
	// same network with the same settings.
	SetConnectionEnabled(id string, enabled bool) error
	// SetProxyEnabled switches one proxy instance on or off, by the id the document gives
	// it. Its rules are left in place, so switching it back on restores exactly what it
	// reached before.
	SetProxyEnabled(id string, enabled bool) error
	// SetSetting writes one registry setting by its wire key. The agent routes it to
	// the same write path the API uses, so the menu inherits validation and module
	// availability instead of growing a second way to change a setting.
	SetSetting(key string, value bool) error
	// SetChoice writes one registry setting that has a fixed set of values, and takes
	// the same route SetSetting does for the same reason.
	SetChoice(key, value string) error
	// SetDNSProfile points this machine's name resolution at one resolver profile, by
	// the id the catalog gives it.
	SetDNSProfile(id string) error
	// SetEgress points this machine's internet traffic at one connection, by the id the
	// document gives it. An empty id sends it out of this machine, which is a destination
	// like any other rather than the absence of one.
	SetEgress(tunnelID string) error
	// SetExitNode selects the device this machine's other traffic leaves through, by
	// its stable identifier. An empty identifier means the tailnet's own choice.
	SetExitNode(id string) error
	// CopyToClipboard puts a device's address or name where it can be pasted. It is the
	// one menu action whose whole result is outside app-tail.
	CopyToClipboard(text string) error
	// SetNetworkMode moves this machine onto a real network interface, or back off it.
	// It is an action rather than a setting because it arranges the machine, stores the
	// mode and rebuilds the node -- three steps a checkbox has no way to ask about.
	SetNetworkMode(tun bool) error
	// ApproveNetworkChanges asks an administrator to approve every change the privileged
	// side refused for want of an approval, then tries the refused features again. It is the
	// dashboard's approve button, reached from the menu.
	ApproveNetworkChanges() error
	// Login starts an interactive login and opens the resulting URL.
	Login() error
	// Logout disconnects the node from the tailnet.
	Logout() error
	// Shutdown asks the agent to stop; the process exits afterwards.
	Shutdown()
}

// SettingItem is one registry setting rendered as a menu entry: a checkbox for a
// boolean, and a submenu of checkboxes for a setting with a fixed set of values.
type SettingItem struct {
	// Key is the setting's wire key, carried back on the click.
	Key   string
	Label string
	// Tooltip is the setting's help text, which is the only room the menu has to say
	// what an entry does.
	Tooltip string
	// Choices are the values a setting with a fixed set offers, empty for a boolean.
	Choices []settingChoice
}

// settingChoice is one value of a setting that has a fixed set of them.
type settingChoice struct {
	Value   string
	Label   string
	Tooltip string
}

// SettingState is what the menu shows for one setting right now. A setting the agent
// cannot currently write is hidden rather than shown unchecked, which would claim it
// is off when it is really unavailable.
type SettingState struct {
	Checked   bool
	Available bool
	// Value is which choice is in force, for a setting that has a set of them. It is
	// empty for a boolean, whose position is Checked.
	Value string
}

// MenuGroup is one capability's submenu: the settings that belong to it, under the name
// the registry already gives that section. Grouping is what turns a flat list of
// checkboxes -- where "Reach networks other devices advertise" sits beside "Start at
// login" -- into a menu that says which capability each one belongs to.
type MenuGroup struct {
	ID    config.Group
	Label string
	Items []SettingItem
	// Advanced hangs this section off the advanced submenu rather than off the menu
	// itself.
	Advanced bool
	// Lead marks a section in the run the menu opens with, which a separator closes. The
	// run is what makes those sections read as the two things the menu is for rather than
	// as the first two of nine.
	Lead bool
}

// trayGroups are the sections that become submenus, in menu order. It is authored rather
// than taken from the registry's own order because the menu leads with how this machine
// reaches the tailnet and follows with what the node does on it, which is the dashboard's
// order and not the settings form's.
//
// The advanced sections are one contiguous run: they share a single parent, which lands
// where the first of them sits, so a section taken out of that run takes the parent's
// position with it.
//
// A group holding a tray-marked setting and missing from here would have that setting
// silently unreachable, so a guard test requires every one of them to appear.
var trayGroups = []config.Group{
	config.GroupConnection,
	config.GroupEgress,
	config.GroupSystemDNS,
	config.GroupDNSBlock,
	config.GroupIPS,
	config.GroupAutoMap,
	config.GroupInterface,
	config.GroupExitNode,
	config.GroupDNS,
	config.GroupProxy,
	config.GroupRouting,
	config.GroupSecurity,
	config.GroupApplication,
}

// trayLeadGroups are the sections the menu opens with, side by side: which private networks
// this machine is on, where its internet traffic goes, what it resolves names through, what
// it refuses to resolve and what it examines about the traffic it carries. They are the
// choices somebody opens the menu bar to change, and a separator after the run of them is
// what keeps them from reading as the first five entries of a list.
//
// The two DNS sections lead together because they are one decision seen twice: the resolver
// a name goes to, and whether it goes anywhere at all. Inspection leads beside them as the
// third answer to the same question -- a name resolves, is refused, or the connection it
// leads to is looked at -- and it is a switch an install turns on and off as it goes rather
// than one it sets once.
var trayLeadGroups = map[config.Group]bool{
	config.GroupConnection: true,
	config.GroupEgress:     true,
	config.GroupSystemDNS:  true,
	config.GroupDNSBlock:   true,
	config.GroupIPS:        true,
}

// trayAdvancedGroups are the sections that hang off the advanced submenu. They are the
// capabilities an install can run for years without turning on, so the top level spends
// one row naming them together rather than one row each.
var trayAdvancedGroups = map[config.Group]bool{
	config.GroupProxy:    true,
	config.GroupRouting:  true,
	config.GroupSecurity: true,
}

// trayGroupLabels renames a section for the menu. The settings form has room for a
// heading that says exactly which subsystem a group belongs to; a menu row has to say
// which capability the user is looking for, and automatic ports are a way of creating
// forwards rather than a thing of their own.
// Menu rows are titles rather than sentences, so every word in one is capitalized -- which
// is also what the sections taking their name from the settings form need overriding for.
var trayGroupLabels = map[config.Group]string{
	config.GroupAutoMap:     "Port Forwards",
	config.GroupApplication: "Settings",
	config.GroupInterface:   "Network Interface",
	config.GroupExitNode:    "Exit Node",
	config.GroupRouting:     "Subnet Routes",
	// "System resolver" is what the settings form calls it, where it sits under a heading
	// that has already said DNS. A menu row is on its own beside "DNS", which is the tailnet
	// one, and the pair only reads if both say which DNS they mean.
	config.GroupSystemDNS: "System DNS",
	// "Blocking" is the settings form's heading, under one that has already said DNS. In a
	// menu bar it sits a row below "System DNS" and beside the section that blocks incoming
	// connections, so it has to say which blocking it is.
	config.GroupDNSBlock: "DNS Blocker",
	// The settings form writes its headings as sentences; a menu row is a title, so every
	// word in one is capitalized.
	config.GroupIPS: "Traffic Inspection",
	// "Internet traffic" is the settings form's heading, where it labels a pair of fields.
	// The menu row is the thing itself, and one word says it in the width a menu bar has.
	config.GroupEgress: "Internet",
	// "Connection" is what the form calls the section naming one connection. The menu row
	// stands for every one of them, so it is plural here.
	config.GroupConnection: "Connections",
}

// Where the entries that are not registry settings hang. They are named here, beside the
// group order, so the menu's shape is checkable without a native menu to build it in.
const (
	// forwardsToggleGroup leads its submenu with the enable-everything action.
	forwardsToggleGroup = config.GroupAutoMap
	// networkModeGroup carries the action that moves this machine onto an interface,
	// and the row saying what stands in the way.
	networkModeGroup = config.GroupInterface
	// exitNodePickerGroup carries the fixed device slots and the overflow row.
	exitNodePickerGroup = config.GroupExitNode
	// dnsProfilePickerGroup carries the fixed resolver-profile slots and the row saying
	// what this machine resolves names through right now.
	dnsProfilePickerGroup = config.GroupSystemDNS
	// egressPickerGroup carries the fixed connection slots and the row saying where this
	// machine's internet traffic leaves through right now.
	egressPickerGroup = config.GroupEgress
	// proxyPickerGroup carries the fixed proxy-instance slots and the row that hands over
	// to the dashboard, where an instance can be added, renamed or granted something.
	proxyPickerGroup = config.GroupProxy
	// connectionPickerGroup carries the fixed connection slots and the row that hands over
	// to the dashboard, where a connection can be added, imported, edited or removed.
	connectionPickerGroup = config.GroupConnection
	// allSettingsGroup ends with the entry that opens the full settings form.
	allSettingsGroup = config.GroupApplication
)

// SettingsMenu is the settings the tray offers, grouped by capability in menu order.
//
// The item set is fixed at build time and only its state changes afterwards, because
// systray can hide and re-show an item but removing one closes its click channel and
// races the goroutine reading it. So this is called once, with the static schema, and
// availability arrives later through Snapshot.
func SettingsMenu(schema []config.FieldSchema) []MenuGroup {
	byGroup := make(map[config.Group][]SettingItem, len(trayGroups))
	for _, f := range schema {
		if !f.Tray {
			continue
		}
		item := SettingItem{Key: f.Key, Label: f.Label, Tooltip: f.Help}
		for _, opt := range f.Options {
			item.Choices = append(item.Choices, settingChoice{
				Value: opt.Value, Label: opt.Label, Tooltip: opt.Help,
			})
		}
		byGroup[f.Group] = append(byGroup[f.Group], item)
	}

	groups := make([]MenuGroup, 0, len(trayGroups))
	for _, id := range trayGroups {
		items := byGroup[id]
		// A submenu with neither settings nor an action of its own would open onto
		// nothing, which reads as the capability being broken rather than absent.
		if len(items) == 0 && !hostsAction(id) {
			continue
		}
		groups = append(groups, MenuGroup{
			ID: id, Label: trayGroupLabel(id), Items: items, Advanced: trayAdvancedGroups[id],
			Lead: trayLeadGroups[id],
		})
	}
	return groups
}

// hostsAction reports whether a section carries an entry that is not a registry setting,
// and so is worth a submenu even with no settings under it.
func hostsAction(id config.Group) bool {
	switch id {
	case forwardsToggleGroup, networkModeGroup, exitNodePickerGroup, dnsProfilePickerGroup,
		egressPickerGroup, proxyPickerGroup, connectionPickerGroup, allSettingsGroup:
		return true
	default:
		return false
	}
}

// trayGroupLabel names a section in the menu, falling back to the name every other
// surface gives it.
func trayGroupLabel(id config.Group) string {
	if label, ok := trayGroupLabels[id]; ok {
		return label
	}
	for _, g := range config.SettingsGroups() {
		if g.ID == id {
			return g.Label
		}
	}
	return id.String()
}

// SettingItems flattens the grouped menu, for the paint loop and for naming a setting in
// a refusal -- neither of which cares which submenu an item sits in.
func SettingItems(groups []MenuGroup) []SettingItem {
	var items []SettingItem
	for _, g := range groups {
		items = append(items, g.Items...)
	}
	return items
}

// Snapshot is the state the menu renders. It is a value, so the tray goroutine never
// holds a lock belonging to the agent.
type Snapshot struct {
	// State is the node state, using tsnode's vocabulary ("Running", "NeedsLogin",
	// "Starting", "Stopped").
	State string
	// DeviceName is this node's name on the tailnet, empty until it is Running.
	DeviceName string
	// ExitNode describes the device this machine's other traffic leaves through, empty
	// when the module is off. It is a rendered sentence rather than the parts, because
	// the exit-node module already renders one for the card and the CLI and the menu
	// must not be a third place that words the same state differently.
	ExitNode string
	// ForwardsTotal counts every configured forward, enabled or not.
	ForwardsTotal int
	// ForwardsEnabled counts the forwards the user has switched on.
	ForwardsEnabled int
	// ForwardsRunning counts the enabled forwards that actually hold a listener.
	ForwardsRunning int
	// Settings holds the current state of each setting the menu shows, keyed by wire
	// key. A key the agent could not read is absent, which the menu renders as
	// unavailable rather than as off.
	Settings map[string]SettingState
	// NetworkInterface is the state of the one mode the menu drives as an action rather
	// than a setting, because turning it on arranges the machine and rebuilds the node.
	NetworkInterface NetworkState
	// ApprovalsPending counts the changes waiting for an administrator's approval, which is
	// what decides whether the menu offers to ask for one.
	ApprovalsPending int
	// SystemDNS describes what this machine resolves names through, empty when the module
	// is off. Like ExitNode it is a rendered sentence rather than the parts: the resolver
	// module already words this state for the card and the CLI, and the menu must not be a
	// third place that words it differently.
	SystemDNS string
	// DNSProfiles are the resolver profiles the catalog offers, shipped ones first. The
	// menu shows a fixed number of them; the rest are reached from the dashboard.
	DNSProfiles []DNSProfileChoice
	// Egress describes where the traffic none of this machine's connections carries leaves
	// through. Like ExitNode and SystemDNS it is a rendered sentence rather than the parts:
	// the egress module already words this state for the card and the CLI.
	Egress string
	// EgressChoices are the places that traffic can leave through -- out of this machine,
	// and each stored connection. The menu shows a fixed number of them; the rest are
	// reached from the dashboard.
	EgressChoices []EgressChoice
	// ExitNodeCandidates are the devices the tailnet offers to route through, in the
	// order the exit-node module ranks them. The menu shows a fixed number of them; the
	// rest are reached from the dashboard.
	ExitNodeCandidates []ExitNodeChoice
	// Proxies are the proxy instances this machine runs, in the order the document holds
	// them. It is empty while the module that runs them is off, because an instance's own
	// switch changes nothing then -- the same reason the exit-node candidates are empty
	// while the module that would route to them is off.
	Proxies []ProxyChoice
	// Connections are the private networks this machine is attached to, in the order the
	// document holds them. The menu shows a fixed number of them; the rest are reached from
	// the dashboard.
	Connections []ConnectionChoice
	// Devices is every machine on the tailnet, this one first and the rest ranked by
	// whether they are reachable. The menu shows a fixed number of them; the rest are
	// reached from the dashboard.
	Devices []Device
	// LastError is the most recent action failure, surfaced in the menu so a click
	// that did nothing is never silent.
	LastError string
}

// NetworkState is what the menu knows about the network-interface mode.
type NetworkState struct {
	// InForce reports that the node is really on an interface, which is not the same as
	// the mode being switched on: a node that could not create one falls back and keeps
	// running, and only this tells the two apart.
	InForce bool
	// Available reports that this machine could carry the mode at all, and Reason says
	// why not when it could not.
	Available bool
	Reason    string
}

// ExitNodeChoice is one device the tailnet offers as an exit node.
type ExitNodeChoice struct {
	// ID is the device's stable identifier, carried back on the click.
	ID      string
	Label   string
	Online  bool
	Current bool
}

// ExitNodeSlots is how many devices the exit-node submenu can show.
//
// It is a fixed count because the menu is built once, at start: systray can hide and
// re-show an item but removing one closes its click channel and races the goroutine
// reading it, so a list that grows with the tailnet is not something this menu can have.
// A tailnet offering more than this says so on the last row, which opens the dashboard.
const ExitNodeSlots = 12

// ExitNodeSlotLabel is the title for one device slot. A device that is offline is named
// as such rather than hidden: it is still the one selected, and a slot that vanished
// would read as the device having left the tailnet.
func ExitNodeSlotLabel(c ExitNodeChoice) string {
	if c.Online {
		return c.Label
	}
	return c.Label + " (offline)"
}

// ExitNodeOverflow reports how many devices the menu could not show.
func ExitNodeOverflow(s Snapshot) int {
	if extra := len(s.ExitNodeCandidates) - ExitNodeSlots; extra > 0 {
		return extra
	}
	return 0
}

// ExitNodeOverflowLabel says how many devices are only on the dashboard. Stating the
// count is what stops a truncated list reading as the tailnet having twelve devices.
func ExitNodeOverflowLabel(s Snapshot) string {
	extra := ExitNodeOverflow(s)
	if extra == 0 {
		return ""
	}
	return fmt.Sprintf("%d more on the dashboard...", extra)
}

// DNSProfileChoice is one resolver profile the menu can switch to.
type DNSProfileChoice struct {
	// ID is the profile's stable identifier, carried back on the click.
	ID    string
	Label string
	// Servers is what the profile resolves through, which is the only thing that tells
	// two profiles apart once they are named "Work" and "Home".
	Servers []string
	Current bool
}

// DNSProfileSlots is how many resolver profiles the picker can show.
//
// Fixed for the reason the exit-node picker is: the menu is built once at start, and
// removing an item closes its click channel underneath the goroutine reading it. A
// catalog with more than this says so on the last row, which opens the dashboard. The
// count is generous because the shipped catalog takes the first several of them, and what
// is left is what a user's own profiles get.
const DNSProfileSlots = 12

// DNSProfileSlotLabel titles one profile slot: the profile's name and nothing else. The
// addresses behind it are a DoH URL apiece and would set the whole menu's width from the
// longest of them; they are on the row's tooltip, on the card and in `app-tail dns`.
func DNSProfileSlotLabel(c DNSProfileChoice) string { return c.Label }

// DNSProfileSlotTooltip is what the profile resolves through, which is the only thing that
// tells two profiles apart once they are named "Work" and "Home".
func DNSProfileSlotTooltip(c DNSProfileChoice) string {
	if len(c.Servers) == 0 {
		return "A set of resolvers this machine can use"
	}
	return strings.Join(c.Servers, ", ")
}

// The picker's sections, as slot positions. The catalog leads with the two entries that are
// not a stored set of servers at all -- the one that changes nothing, and the one whose
// servers come from the tailnet -- then the shipped public resolvers, then the user's own.
// Separators sit on those boundaries.
//
// They are positions rather than a property of a slot because the menu is built once at
// start: systray can hide and re-show a row but not move one, and it cannot hide a separator
// at all. dnsOwnProfilesFrom is taken from the catalog so that shipping another built-in
// moves the boundary with it rather than leaving a separator mid-list.
const (
	dnsSystemSlot  = 0
	dnsTailnetSlot = 1
	dnsShippedFrom = 2
)

var dnsOwnProfilesFrom = len(dnsprofiles.BuiltIn())

// DNSProfileOverflow reports how many profiles the menu could not show.
func DNSProfileOverflow(s Snapshot) int {
	if extra := len(s.DNSProfiles) - DNSProfileSlots; extra > 0 {
		return extra
	}
	return 0
}

// DNSProfileOverflowLabel says how many profiles are only on the dashboard, for the same
// reason the exit-node one does: a truncated list with nothing saying so reads as the
// whole catalog.
func DNSProfileOverflowLabel(s Snapshot) string {
	extra := DNSProfileOverflow(s)
	if extra == 0 {
		return ""
	}
	return fmt.Sprintf("%d more on the dashboard...", extra)
}

// EgressChoice is one place this machine's internet traffic can leave through.
type EgressChoice struct {
	// ID is the connection's stable identifier, carried back on the click. Empty is this
	// machine's own network, which is a destination like any other rather than the absence
	// of a choice.
	ID    string
	Label string
	// Detail is what choosing this amounts to, in the words the settings registry already
	// gives it. It is on the row's tooltip rather than the row, because it is a sentence.
	Detail  string
	Current bool
}

// EgressSlots is how many places the internet picker can show.
//
// Fixed for the reason the other pickers are: the menu is built once at start, and removing
// an item closes its click channel underneath the goroutine reading it. The first slot is
// this machine's own network and the rest are connections, so an installation with more
// connections than eleven says so on the last row, which opens the dashboard.
const EgressSlots = 12

// EgressSlotLabel titles one slot: the connection's name, or what this machine's own
// network is called in the choice above it.
func EgressSlotLabel(c EgressChoice) string { return c.Label }

// EgressSlotTooltip is what choosing this row does, which is the only thing that separates
// two connections once both are named after the office they are in.
func EgressSlotTooltip(c EgressChoice) string { return c.Detail }

// EgressOverflow reports how many places the menu could not show.
func EgressOverflow(s Snapshot) int {
	if extra := len(s.EgressChoices) - EgressSlots; extra > 0 {
		return extra
	}
	return 0
}

// EgressOverflowLabel says how many connections are only on the dashboard, for the reason
// the other pickers do: a truncated list with nothing saying so reads as the whole set.
func EgressOverflowLabel(s Snapshot) string {
	extra := EgressOverflow(s)
	if extra == 0 {
		return ""
	}
	return fmt.Sprintf("%d more on the dashboard...", extra)
}

// ProxyChoice is one proxy instance the menu can switch on or off.
type ProxyChoice struct {
	// ID is the instance's stable identifier, carried back on the click.
	ID    string
	Label string
	// Enabled is whether this instance is meant to be listening, which is the position
	// the checkbox sits in.
	Enabled bool
	// Listening is where it is bound, empty when nothing is. With Enabled it separates an
	// instance that is switched off from one that is switched on and could not bind.
	Listening string
	// Reach is what this instance's rules amount to, in sentences the agent words. The
	// menu shows them rather than wording its own, for the reason it does not word the
	// exit-node or resolver lines: one instance's permissions must not read one way here
	// and another way on the dashboard.
	Reach []string
}

// ProxySlots is how many proxy instances the picker can show.
//
// Fixed for the reason the exit-node and resolver pickers are: the menu is built once at
// start, and removing an item closes its click channel underneath the goroutine reading
// it. An installation with more instances than this says so on the last row, which opens
// the dashboard. The count is what a machine with one instance per program pointed at
// app-tail runs to before the list stops being something to read in a menu.
const ProxySlots = 12

// ProxySlotLabel titles one instance slot. An instance switched on with nothing bound is
// named as such: its checkbox is ticked and no program can reach it, and that is the one
// state a bare name would misreport.
func ProxySlotLabel(c ProxyChoice) string {
	if c.Enabled && c.Listening == "" {
		return c.Label + " (not listening)"
	}
	return c.Label
}

// ProxySlotTooltip is where the instance is bound and what its rules let it reach, which
// is the pair that tells two instances apart once both are named after the program pointed
// at them. It is off the row itself so the menu's width is set by the names rather than by
// a host:port and a sentence on every line.
func ProxySlotTooltip(c ProxyChoice) string {
	reach := "nothing until a rule grants it something"
	if len(c.Reach) > 0 {
		reach = strings.Join(c.Reach, "; ")
	}
	if c.Listening == "" {
		return "Reaches " + reach
	}
	return c.Listening + ", reaches " + reach
}

// ProxyOverflow reports how many instances the menu could not show.
func ProxyOverflow(s Snapshot) int {
	if extra := len(s.Proxies) - ProxySlots; extra > 0 {
		return extra
	}
	return 0
}

// ProxyOverflowLabel says how many instances are only on the dashboard, for the reason the
// other pickers do: a truncated list with nothing saying so reads as the whole set.
func ProxyOverflowLabel(s Snapshot) string {
	extra := ProxyOverflow(s)
	if extra == 0 {
		return ""
	}
	return fmt.Sprintf("%d more on the dashboard...", extra)
}

// ConnectionChoice is one private network this machine is attached to, as the menu shows
// it: a checkbox for whether it is meant to be up, and what it is actually doing.
type ConnectionChoice struct {
	// ID is the connection's stable identifier, carried back on the click.
	ID    string
	Label string
	// Enabled is whether this connection is meant to be up, which is the position the
	// checkbox sits in and not the same question as whether it is.
	Enabled bool
	// Live reports that traffic can cross right now. It is what separates a connection
	// doing what its checkbox says from one that is switched on and carrying nothing --
	// the state a bare name would misreport.
	Live bool
	// State is the word the agent gives this connection, and Detail explains a state that
	// needs explaining. Both are taken from the agent rather than worded here, for the
	// reason the proxy rows take their reach from it: one connection must not read one way
	// in the menu and another way on its own page.
	State  string
	Detail string
	// Kind is what sort of network this is, in the agent's word for it. It is what tells
	// two connections apart once both are named after the office they reach.
	Kind string
}

// ConnectionSlots is how many private networks the menu can show.
//
// Fixed for the reason the other pickers are: the menu is built once at start, and removing
// an item closes its click channel underneath the goroutine reading it. An installation with
// more connections than this says so on the last row, which opens the dashboard.
const ConnectionSlots = 12

// ConnectionSlotLabel titles one connection slot. A connection switched on and carrying
// nothing is named as such: its checkbox is ticked and nothing crosses it, and that is the
// one state a bare name would misreport.
func ConnectionSlotLabel(c ConnectionChoice) string {
	if !c.Enabled || c.Live {
		return c.Label
	}
	state := c.State
	if state == "" {
		state = "not connected"
	}
	return c.Label + " (" + strings.ToLower(state) + ")"
}

// ConnectionSlotTooltip is what kind of network this is and why it is in the state it is
// in. It is off the row itself so the menu's width is set by the connection names rather
// than by a sentence on every line.
func ConnectionSlotTooltip(c ConnectionChoice) string {
	switch {
	case c.Kind == "":
		return c.Detail
	case c.Detail == "":
		return c.Kind
	default:
		return c.Kind + ": " + c.Detail
	}
}

// ConnectionOverflow reports how many connections the menu could not show.
func ConnectionOverflow(s Snapshot) int {
	if extra := len(s.Connections) - ConnectionSlots; extra > 0 {
		return extra
	}
	return 0
}

// ConnectionOverflowLabel says how many connections are only on the dashboard, for the
// reason the other pickers do: a truncated list with nothing saying so reads as the whole
// set.
func ConnectionOverflowLabel(s Snapshot) string {
	extra := ConnectionOverflow(s)
	if extra == 0 {
		return ""
	}
	return fmt.Sprintf("%d more on the dashboard...", extra)
}

// Device is one machine on the tailnet, as the devices submenu shows it.
type Device struct {
	// Name is what the row is titled: the short hostname, which is what people call
	// their machines. The full name is on the row that copies it.
	Name string
	// Address is the device's tailnet IPv4 address, empty for a device the tailnet has
	// not given one.
	Address string
	// DNSName is the device's MagicDNS name, empty on a tailnet that does not publish
	// names.
	DNSName string
	Online  bool
	// State is what this node can actually do with the device, which is not what Online
	// says: the control plane lists a device it still believes in, and a device this node
	// has no path to is listed exactly like one it can reach. The menu is where an address
	// gets copied, so a row that reads healthy is a row that sends somebody to a machine
	// nothing reaches. Empty means the caller did not state one, and Online stands in.
	State tsnode.PeerState
	// Self marks this machine, which is listed alongside the rest because its own
	// address is the one most often wanted and nothing else in the menu carries it.
	Self bool
}

// DeviceSlots is how many devices the network-devices submenu can show.
//
// Fixed for the same reason ExitNodeSlots is: the menu is built once and an item cannot
// be removed afterwards. It is larger because this list is every machine on the tailnet
// rather than only the ones approved to carry traffic.
const DeviceSlots = 24

// DeviceSlotLabel titles one device row. What the row says about a device is what
// distinguishes it from the others in the list: whether it can be reached at all, and
// which one of them is the machine reading the menu.
func DeviceSlotLabel(d Device) string {
	if d.Self {
		return d.Name + " (this machine)"
	}
	if note := deviceStateNote(d.State.Or(d.Online)); note != "" {
		return d.Name + " " + note
	}
	return d.Name
}

// deviceStateNote is the parenthesised half of a device row: short, because a menu item
// has no room for the sentence the dashboard and the CLI carry, and present for every
// state but the healthy one.
func deviceStateNote(state tsnode.PeerState) string {
	switch state {
	case tsnode.PeerReady:
		return ""
	case tsnode.PeerRelayed:
		return "(relayed)"
	case tsnode.PeerNoPath:
		return "(unreachable)"
	case tsnode.PeerExpired:
		return "(key expired)"
	case tsnode.PeerOffline:
		return "(offline)"
	default:
		// A state this build does not know about is still not a healthy one, and saying
		// the bare word beats a row that looks fine.
		return "(" + string(state) + ")"
	}
}

// DeviceOverflow reports how many devices the menu could not show.
func DeviceOverflow(s Snapshot) int {
	if extra := len(s.Devices) - DeviceSlots; extra > 0 {
		return extra
	}
	return 0
}

// DeviceOverflowLabel says how many devices are only on the dashboard. Stating the count
// is what stops a truncated list reading as the whole tailnet.
func DeviceOverflowLabel(s Snapshot) string {
	extra := DeviceOverflow(s)
	if extra == 0 {
		return ""
	}
	return fmt.Sprintf("%d more on the dashboard...", extra)
}

// DeviceEmptyLabel is the row the devices submenu shows in place of a list it has nothing
// for, and is empty once it holds a device. Which of the two reasons it gives matters: a
// node that has not connected has no tailnet to list yet, and one that has is reporting a
// tailnet of one -- and "no devices" on a machine that never logged in sends somebody
// looking for machines that are there.
func DeviceEmptyLabel(s Snapshot) string {
	if len(s.Devices) > 0 {
		return ""
	}
	if s.State != "Running" {
		return "Not connected yet"
	}
	return "No devices yet"
}

// NetworkModeLabel names what the click does, not the state it is in -- the same shape
// as the forwards toggle and the login entry.
func NetworkModeLabel(s Snapshot) string {
	if NetworkModeTarget(s) {
		return "Turn on the network interface"
	}
	return "Turn off the network interface"
}

// NetworkModeTarget is the mode the click asks for.
func NetworkModeTarget(s Snapshot) bool { return !s.NetworkInterface.InForce }

// NetworkModeEnabled reports whether the entry can do anything. A machine that cannot
// carry the mode keeps the entry, disabled, with the reason on the row beneath it: an
// entry that disappeared would leave somebody looking for a feature the app advertises.
func NetworkModeEnabled(s Snapshot) bool {
	return s.NetworkInterface.Available || s.NetworkInterface.InForce
}

// NetworkModeReason is the row under the action, saying what stands in the way. It is
// empty when nothing does, which hides the row.
func NetworkModeReason(s Snapshot) string {
	if s.NetworkInterface.Available || s.NetworkInterface.InForce {
		return ""
	}
	if s.NetworkInterface.Reason == "" {
		return "Not available on this machine"
	}
	return firstLine(s.NetworkInterface.Reason)
}

// StatusLine is the first, non-clickable menu entry.
func StatusLine(s Snapshot) string {
	switch s.State {
	case "Running":
		if s.DeviceName == "" {
			return "Connected"
		}
		return "Connected as " + s.DeviceName
	case "NeedsLogin":
		return "Needs login"
	case "Starting":
		return "Connecting..."
	case "":
		return "Starting..."
	default:
		return s.State
	}
}

// ForwardsLine summarises the forwards. It reports running against enabled, because
// an enabled forward that is not running is the failure the user needs to notice.
func ForwardsLine(s Snapshot) string {
	switch {
	case s.ForwardsTotal == 0:
		return "No forwards yet"
	case s.ForwardsEnabled == 0:
		return fmt.Sprintf("%s, all disabled", plural(s.ForwardsTotal, "forward"))
	case s.ForwardsRunning == s.ForwardsEnabled:
		return fmt.Sprintf("%s running", plural(s.ForwardsRunning, "forward"))
	default:
		return fmt.Sprintf("%d of %s running", s.ForwardsRunning, plural(s.ForwardsEnabled, "forward"))
	}
}

// ExitNodeLine is the menu entry naming where this machine's other traffic leaves. An
// empty answer hides the entry rather than reading "no exit node": on the install this
// app ships as, there is no exit node and never was one, so a line about it is noise.
func ExitNodeLine(s Snapshot) string {
	if s.ExitNode == "" {
		return ""
	}
	return "Exit node: " + s.ExitNode
}

// IconStatus is the health the tray icon's dot reports. It answers one question --
// is app-tail doing its job right now -- so anything the user has to act on reads as
// a fault, and only the states that resolve on their own read as starting.
//
// The forwards test mirrors ForwardsLine's: the icon and the menu entry beneath it
// must never disagree about whether the forwards are healthy.
func IconStatus(s Snapshot) icon.Status {
	if s.LastError != "" {
		return icon.StatusFault
	}
	switch s.State {
	case "Running":
		if s.ForwardsRunning != s.ForwardsEnabled {
			return icon.StatusFault
		}
		return icon.StatusHealthy
	case "", "Starting":
		return icon.StatusStarting
	default:
		return icon.StatusFault
	}
}

// TrayIcon is the image the tray expects for status s on the given GOOS. Windows reads
// an ICO from the notification area and every other platform takes the PNG, so handing
// a platform the other format leaves the tray with a blank slot rather than a failure.
// The target is a parameter so both formats are covered wherever the tests run.
//
// macOS gets the colour icon, not a template one: a template image is alpha-only and
// is recoloured to a single menu-bar tint, which would erase the status dot.
func TrayIcon(goos string, s icon.Status) []byte {
	if goos == "windows" {
		return icon.ICO(s)
	}
	return icon.PNG(s)
}

// ToggleLabel names the action the click performs, not the current state.
func ToggleLabel(s Snapshot) string {
	if ToggleTarget(s) {
		return "Enable all forwards"
	}
	return "Disable all forwards"
}

// ToggleTarget is the value the toggle sets. Any forward still enabled means the
// click should switch everything off; only when none are does it switch them on.
func ToggleTarget(s Snapshot) bool {
	return s.ForwardsEnabled == 0
}

// ToggleEnabled reports whether the toggle entry can do anything.
func ToggleEnabled(s Snapshot) bool {
	return s.ForwardsTotal > 0
}

// ApprovalsLabel is the approve entry's title, or "" to hide it while nothing is waiting.
func ApprovalsLabel(s Snapshot) string {
	if s.ApprovalsPending == 0 {
		return ""
	}
	return "Approve network changes…"
}

// AuthLabel names the login action available in the current state.
func AuthLabel(s Snapshot) string {
	if s.State == "Running" {
		return "Log Out"
	}
	return "Log In"
}

// Tooltip is the hover text on the tray icon itself.
func Tooltip(s Snapshot) string {
	line := "app-tail: " + StatusLine(s)
	if s.LastError != "" {
		return line + " (" + firstLine(s.LastError) + ")"
	}
	return line
}

// plural renders a count with its noun, so the menu reads "1 forward" rather than
// "1 forwards".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// firstLine keeps a multi-line error from stretching a tray tooltip off-screen.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
