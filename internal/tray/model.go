// SPDX-License-Identifier: MIT

package tray

import (
	"context"
	"fmt"
	"time"

	"github.com/sellitus/app-tail/internal/icon"
)

// Action is a menu command. Clicks are reduced to these values so the event loop is
// driven by plain channels and can be exercised without a display.
type Action int

const (
	// ActionNone is the zero value, and is deliberately not a command: commands now
	// carry data, and a zero Command arriving from a closed channel or an unset field
	// must do nothing rather than silently mean whichever action happened to be first.
	ActionNone Action = iota
	// ActionOpenDashboard opens the loopback UI.
	ActionOpenDashboard
	// ActionOpenSettings opens the loopback UI with the settings form showing.
	ActionOpenSettings
	// ActionOpenDNSProfiles opens the loopback UI at the DNS section, where a resolver
	// profile can be added or edited.
	ActionOpenDNSProfiles
	// ActionOpenProxies opens the loopback UI at the proxies section, where an instance
	// can be added, renamed or granted something.
	ActionOpenProxies
	// ActionOpenConnections opens the loopback UI at the connections section, where a
	// private network can be added, imported, edited or removed.
	ActionOpenConnections
	// ActionToggleForwards enables or disables every forward at once.
	ActionToggleForwards
	// ActionAuth logs in or out, whichever the current state allows.
	ActionAuth
	// ActionSetSetting flips the registry setting named by the command's Key.
	ActionSetSetting
	// ActionSetChoice selects one value of the registry setting named by the command's
	// Key, carried in Choice.
	ActionSetChoice
	// ActionSetExitNode selects the device sitting in the command's Slot.
	ActionSetExitNode
	// ActionSetDNSProfile points this machine's name resolution at the resolver profile
	// sitting in the command's Slot.
	ActionSetDNSProfile
	// ActionSetEgress sends this machine's internet traffic through the connection sitting
	// in the command's Slot.
	ActionSetEgress
	// ActionCopyDeviceAddress puts the tailnet address of the device in the command's
	// Slot on the clipboard.
	ActionCopyDeviceAddress
	// ActionCopyDeviceName puts the MagicDNS name of the device in the command's Slot
	// on the clipboard.
	ActionCopyDeviceName
	// ActionToggleProxy switches the proxy instance sitting in the command's Slot on or
	// off, whichever it is not.
	ActionToggleProxy
	// ActionToggleConnection switches the private network sitting in the command's Slot
	// on or off, whichever it is not.
	ActionToggleConnection
	// ActionSetNetworkMode moves this machine onto a real network interface, or off it.
	ActionSetNetworkMode
	// ActionApproveNetworkChanges asks an administrator to approve the changes this machine
	// refused for want of an approval.
	ActionApproveNetworkChanges
	// ActionQuit stops the agent and closes the tray.
	ActionQuit
)

// Command is one menu click. Most actions need nothing else; a settings entry carries
// the setting it belongs to and, where the setting has a fixed set of values, which one
// was clicked -- so one menu item shape serves every setting the registry declares.
type Command struct {
	Action Action
	Key    string
	Value  bool
	Choice string
	// Slot is which of the fixed exit-node, device, resolver-profile or proxy positions
	// was clicked. What sits there is not known when the menu is built, so the position is
	// what a click can carry and the model reads the entry off the current snapshot.
	Slot int
}

// View is the menu surface the model writes to. systray implements it in tray.go;
// tests implement it with a recorder.
type View interface {
	SetStatus(line string)
	SetForwards(line string)
	// SetExitNode paints the exit-node line. An empty line hides the entry: with the
	// module off there is nothing about an exit node worth a permanent menu row.
	SetExitNode(line string)
	// SetSystemDNS paints the line naming what this machine resolves names through. An
	// empty line hides the entry: with the module off there is nothing about a resolver
	// profile worth a permanent menu row.
	SetSystemDNS(line string)
	// SetDNSProfileSlot paints one of the fixed resolver-profile slots. A slot with no
	// profile is hidden rather than blanked, so a short catalog leaves no empty rows. The
	// tooltip carries what the profile resolves through, which is off the row itself so the
	// menu's width is set by the profile names rather than by the longest DoH URL in it.
	SetDNSProfileSlot(index int, label, tooltip string, selected, visible bool)
	// SetDNSProfileOverflow paints the row saying how many profiles are only on the
	// dashboard. An empty label hides it.
	SetDNSProfileOverflow(label string)
	// SetEgress paints the line naming where the traffic none of this machine's connections
	// carries leaves through. An empty line hides the entry, which is the state before the
	// agent can say where anything goes.
	SetEgress(line string)
	// SetEgressSlot paints one of the fixed internet-destination slots. A slot with no
	// destination is hidden rather than blanked, so a machine with one connection leaves no
	// empty rows. The tooltip carries what choosing the row does, which is a sentence and
	// would otherwise set the menu's width.
	SetEgressSlot(index int, label, tooltip string, selected, visible bool)
	// SetEgressOverflow paints the row saying how many connections are only on the
	// dashboard. An empty label hides it.
	SetEgressOverflow(label string)
	SetToggle(label string, enabled bool)
	SetAuth(label string)
	// SetSetting paints one settings checkbox. An unavailable setting is hidden, not
	// shown unchecked, so the menu never claims a setting is off when it is really out
	// of reach.
	SetSetting(key string, checked, available bool)
	// SetChoice paints one value of a setting that has a fixed set of them. Exactly one
	// of a setting's choices is selected at a time, so the group reads as a picker.
	SetChoice(key, value string, selected, available bool)
	// SetNetworkMode paints the entry that moves this machine onto a network interface,
	// and the row beneath it saying what stands in the way. An empty reason hides that
	// row: on a machine where nothing does, it would be a permanent blank line.
	SetNetworkMode(label string, enabled bool, reason string)
	// SetApprovals paints the entry that asks an administrator to approve the changes this
	// machine is waiting on. An empty label hides it: with nothing waiting it would offer a
	// password prompt for nothing.
	SetApprovals(label string)
	// SetExitNodeSlot paints one of the fixed device slots. A slot with no device is
	// hidden rather than blanked, so a short list does not leave empty rows behind.
	SetExitNodeSlot(index int, label string, selected, visible bool)
	// SetExitNodeOverflow paints the row saying how many devices are only on the
	// dashboard. An empty label hides it.
	SetExitNodeOverflow(label string)
	// SetProxySlot paints one of the fixed proxy-instance slots. A slot with no instance is
	// hidden rather than blanked, so a machine with one proxy leaves no empty rows. The
	// tooltip carries where the instance is bound and what it reaches, which is off the row
	// itself so the menu's width is set by the instance names.
	SetProxySlot(index int, label, tooltip string, checked, visible bool)
	// SetProxyOverflow paints the row saying how many instances are only on the dashboard.
	// An empty label hides it.
	SetProxyOverflow(label string)
	// SetConnectionSlot paints one of the fixed connection slots. A slot with no connection
	// is hidden rather than blanked, so a machine with one network leaves no empty rows. The
	// tooltip carries what kind of network it is and why it is in the state it is in, which
	// is off the row itself so the menu's width is set by the connection names.
	SetConnectionSlot(index int, label, tooltip string, checked, visible bool)
	// SetConnectionOverflow paints the row saying how many connections are only on the
	// dashboard. An empty label hides it.
	SetConnectionOverflow(label string)
	// SetDeviceSlot paints one of the fixed device slots: the row naming the device and
	// the two rows beneath it that copy its address and its name. A slot holding no
	// device is hidden rather than blanked, and so is a row whose value the tailnet does
	// not publish -- an empty row offers a copy that would put nothing on the clipboard.
	SetDeviceSlot(index int, label, address, dnsName string, visible bool)
	// SetDeviceOverflow paints the row saying how many devices are only on the
	// dashboard. An empty label hides it.
	SetDeviceOverflow(label string)
	// SetDeviceEmpty paints the row standing in for a list with nothing in it, since a
	// submenu whose every row is hidden opens onto nothing and reads as the tailnet
	// being unreadable rather than as this machine not being on one yet. An empty label
	// hides it.
	SetDeviceEmpty(label string)
	SetTooltip(text string)
	SetIcon(status icon.Status)
}

// Model renders a Controller's state into a View and applies menu actions to it. It
// is single-goroutine by construction: Run owns it, and nothing else touches it.
type Model struct {
	controller Controller
	view       View
	settings   []SettingItem
	onError    func(error)

	last    Snapshot
	lastErr string
}

// NewModel wires a controller to a view. groups is the fixed item set the view was
// built with, so painting covers every entry on screen even when a snapshot omits one.
// onError may be nil, in which case failures are still surfaced in the menu but not
// logged.
func NewModel(controller Controller, view View, groups []MenuGroup, onError func(error)) *Model {
	return &Model{controller: controller, view: view, settings: SettingItems(groups), onError: onError}
}

// Refresh pulls a fresh snapshot and repaints every menu entry. A failed action leads
// whatever the snapshot reported, because it is the thing the user just did and is waiting
// to hear about -- ahead of the rest rather than instead of it, since those are still true
// and one of them is often why the action failed.
func (m *Model) Refresh() {
	m.last = m.controller.Snapshot()
	switch {
	case m.lastErr == "":
	case m.last.LastError == "":
		m.last.LastError = m.lastErr
	default:
		m.last.LastError = m.lastErr + "; " + m.last.LastError
	}
	m.paint()
}

func (m *Model) paint() {
	m.view.SetStatus(StatusLine(m.last))
	m.view.SetForwards(ForwardsLine(m.last))
	m.view.SetExitNode(ExitNodeLine(m.last))
	m.view.SetToggle(ToggleLabel(m.last), ToggleEnabled(m.last))
	m.view.SetAuth(AuthLabel(m.last))
	m.view.SetNetworkMode(NetworkModeLabel(m.last), NetworkModeEnabled(m.last), NetworkModeReason(m.last))
	m.view.SetApprovals(ApprovalsLabel(m.last))
	for _, item := range m.settings {
		state := m.last.Settings[item.Key]
		if len(item.Choices) == 0 {
			m.view.SetSetting(item.Key, state.Checked, state.Available)
			continue
		}
		for _, choice := range item.Choices {
			m.view.SetChoice(item.Key, choice.Value, choice.Value == state.Value, state.Available)
		}
	}
	m.view.SetSystemDNS(m.last.SystemDNS)
	m.paintDNSProfiles()
	m.view.SetEgress(m.last.Egress)
	m.paintEgress()
	m.paintExitNodes()
	m.paintProxies()
	m.paintConnections()
	m.paintDevices()
	m.view.SetTooltip(Tooltip(m.last))
	m.view.SetIcon(IconStatus(m.last))
}

// paintExitNodes fills the fixed device slots from whatever the tailnet currently offers.
// Every slot is painted on each pass, including the empty ones: a slot left alone would
// keep showing a device that has since gone from the list.
func (m *Model) paintExitNodes() {
	for i := range ExitNodeSlots {
		if i >= len(m.last.ExitNodeCandidates) {
			m.view.SetExitNodeSlot(i, "", false, false)
			continue
		}
		candidate := m.last.ExitNodeCandidates[i]
		m.view.SetExitNodeSlot(i, ExitNodeSlotLabel(candidate), candidate.Current, true)
	}
	m.view.SetExitNodeOverflow(ExitNodeOverflowLabel(m.last))
}

// paintDNSProfiles fills the fixed resolver slots from the catalog as it stands now.
// Every slot is painted on each pass, including the empty ones: a slot left alone would
// keep offering a profile the user has since deleted.
func (m *Model) paintDNSProfiles() {
	for i := range DNSProfileSlots {
		if i >= len(m.last.DNSProfiles) {
			m.view.SetDNSProfileSlot(i, "", "", false, false)
			continue
		}
		profile := m.last.DNSProfiles[i]
		m.view.SetDNSProfileSlot(i, DNSProfileSlotLabel(profile), DNSProfileSlotTooltip(profile), profile.Current, true)
	}
	m.view.SetDNSProfileOverflow(DNSProfileOverflowLabel(m.last))
}

// paintEgress fills the fixed internet-destination slots from the connections the document
// holds now. Every slot is painted on each pass, including the empty ones: a slot left alone
// would keep offering a connection that has since been removed.
func (m *Model) paintEgress() {
	for i := range EgressSlots {
		if i >= len(m.last.EgressChoices) {
			m.view.SetEgressSlot(i, "", "", false, false)
			continue
		}
		choice := m.last.EgressChoices[i]
		m.view.SetEgressSlot(i, EgressSlotLabel(choice), EgressSlotTooltip(choice), choice.Current, true)
	}
	m.view.SetEgressOverflow(EgressOverflowLabel(m.last))
}

// paintProxies fills the fixed instance slots from the document as it stands now. Every
// slot is painted on each pass, including the empty ones: a slot left alone would keep
// offering an instance that has since been deleted, or one whose module has been switched
// off underneath it.
func (m *Model) paintProxies() {
	for i := range ProxySlots {
		if i >= len(m.last.Proxies) {
			m.view.SetProxySlot(i, "", "", false, false)
			continue
		}
		proxy := m.last.Proxies[i]
		m.view.SetProxySlot(i, ProxySlotLabel(proxy), ProxySlotTooltip(proxy), proxy.Enabled, true)
	}
	m.view.SetProxyOverflow(ProxyOverflowLabel(m.last))
}

// paintConnections fills the fixed connection slots from the document as it stands now.
// Every slot is painted on each pass, including the empty ones: a slot left alone would
// keep offering a private network that has since been removed.
func (m *Model) paintConnections() {
	for i := range ConnectionSlots {
		if i >= len(m.last.Connections) {
			m.view.SetConnectionSlot(i, "", "", false, false)
			continue
		}
		connection := m.last.Connections[i]
		m.view.SetConnectionSlot(i, ConnectionSlotLabel(connection), ConnectionSlotTooltip(connection), connection.Enabled, true)
	}
	m.view.SetConnectionOverflow(ConnectionOverflowLabel(m.last))
}

// paintDevices fills the fixed device slots from the tailnet as it stands now. Like the
// exit-node slots, every one is painted on each pass so a slot never keeps showing a
// machine that has since left.
func (m *Model) paintDevices() {
	for i := range DeviceSlots {
		if i >= len(m.last.Devices) {
			m.view.SetDeviceSlot(i, "", "", "", false)
			continue
		}
		device := m.last.Devices[i]
		m.view.SetDeviceSlot(i, DeviceSlotLabel(device), device.Address, device.DNSName, true)
	}
	m.view.SetDeviceOverflow(DeviceOverflowLabel(m.last))
	m.view.SetDeviceEmpty(DeviceEmptyLabel(m.last))
}

// Do applies a command and repaints. A failed command is recorded so it shows up in
// the menu instead of the click appearing to do nothing.
func (m *Model) Do(cmd Command) {
	if err := m.apply(cmd); err != nil {
		m.lastErr = err.Error()
		if m.onError != nil {
			m.onError(err)
		}
	} else {
		m.lastErr = ""
	}
	m.Refresh()
}

func (m *Model) apply(cmd Command) error {
	switch cmd.Action {
	case ActionOpenDashboard:
		return m.controller.OpenDashboard()
	case ActionOpenSettings:
		return m.controller.OpenSettings()
	case ActionOpenDNSProfiles:
		return m.controller.OpenDNSProfiles()
	case ActionOpenProxies:
		return m.controller.OpenProxies()
	case ActionOpenConnections:
		return m.controller.OpenConnections()
	case ActionToggleForwards:
		if !ToggleEnabled(m.last) {
			return fmt.Errorf("there are no forwards to enable yet")
		}
		return m.controller.SetAllForwardsEnabled(ToggleTarget(m.last))
	case ActionApproveNetworkChanges:
		if m.last.ApprovalsPending == 0 {
			return fmt.Errorf("no network changes are waiting for an administrator's approval")
		}
		return m.controller.ApproveNetworkChanges()
	case ActionAuth:
		if m.last.State == "Running" {
			return m.controller.Logout()
		}
		return m.controller.Login()
	case ActionSetSetting:
		state, ok := m.last.Settings[cmd.Key]
		if !ok || !state.Available {
			return fmt.Errorf("%q cannot be changed on this system right now", m.settingLabel(cmd.Key))
		}
		return m.controller.SetSetting(cmd.Key, !state.Checked)
	case ActionSetChoice:
		state, ok := m.last.Settings[cmd.Key]
		if !ok || !state.Available {
			return fmt.Errorf("%q cannot be changed on this system right now", m.settingLabel(cmd.Key))
		}
		// Clicking the value already in force is not a write: it would send the same
		// value back through validation and a restart classification for nothing.
		if state.Value == cmd.Choice {
			return nil
		}
		return m.controller.SetChoice(cmd.Key, cmd.Choice)
	case ActionSetExitNode:
		if cmd.Slot < 0 || cmd.Slot >= len(m.last.ExitNodeCandidates) {
			return fmt.Errorf("that device is no longer on the tailnet")
		}
		candidate := m.last.ExitNodeCandidates[cmd.Slot]
		// Clicking the device already in use is not a write; the checkbox above the
		// list is what turns the exit node off.
		if candidate.Current {
			return nil
		}
		return m.controller.SetExitNode(candidate.ID)
	case ActionSetDNSProfile:
		if cmd.Slot < 0 || cmd.Slot >= len(m.last.DNSProfiles) {
			return fmt.Errorf("that resolver profile is no longer in the catalog")
		}
		profile := m.last.DNSProfiles[cmd.Slot]
		// Clicking the profile already in force is not a write: it would send the same
		// value back through validation, and on this setting it would also mean asking
		// the machine for a change it has already made.
		if profile.Current {
			return nil
		}
		return m.controller.SetDNSProfile(profile.ID)
	case ActionSetEgress:
		if cmd.Slot < 0 || cmd.Slot >= len(m.last.EgressChoices) {
			return fmt.Errorf("that connection is no longer one this machine holds")
		}
		choice := m.last.EgressChoices[cmd.Slot]
		// Clicking the destination already in force is not a write: it would send the same
		// pair of values back through validation for nothing.
		if choice.Current {
			return nil
		}
		return m.controller.SetEgress(choice.ID)
	case ActionToggleProxy:
		if cmd.Slot < 0 || cmd.Slot >= len(m.last.Proxies) {
			// Either the instance was deleted between the paint and the click, or the module
			// that runs the instances was switched off -- which empties the list, because an
			// instance's own switch changes nothing while it is off.
			return fmt.Errorf("that proxy is no longer one this machine runs")
		}
		proxy := m.last.Proxies[cmd.Slot]
		return m.controller.SetProxyEnabled(proxy.ID, !proxy.Enabled)
	case ActionToggleConnection:
		if cmd.Slot < 0 || cmd.Slot >= len(m.last.Connections) {
			return fmt.Errorf("that connection is no longer one this machine holds")
		}
		connection := m.last.Connections[cmd.Slot]
		return m.controller.SetConnectionEnabled(connection.ID, !connection.Enabled)
	case ActionCopyDeviceAddress:
		device, err := m.deviceAt(cmd.Slot)
		if err != nil {
			return err
		}
		if device.Address == "" {
			return fmt.Errorf("%s has no tailnet address to copy", device.Name)
		}
		return m.controller.CopyToClipboard(device.Address)
	case ActionCopyDeviceName:
		device, err := m.deviceAt(cmd.Slot)
		if err != nil {
			return err
		}
		if device.DNSName == "" {
			return fmt.Errorf("%s has no tailnet name to copy", device.Name)
		}
		return m.controller.CopyToClipboard(device.DNSName)
	case ActionSetNetworkMode:
		if !NetworkModeEnabled(m.last) {
			return fmt.Errorf("this machine cannot run on a network interface: %s", NetworkModeReason(m.last))
		}
		return m.controller.SetNetworkMode(NetworkModeTarget(m.last))
	case ActionQuit:
		m.controller.Shutdown()
		return nil
	default:
		return fmt.Errorf("unknown tray action %d", cmd.Action)
	}
}

// deviceAt reads the device sitting in a slot. A click carries the position rather than
// the device, so the list can have moved on between the paint and the click.
func (m *Model) deviceAt(slot int) (Device, error) {
	if slot < 0 || slot >= len(m.last.Devices) {
		return Device{}, fmt.Errorf("that device is no longer on the tailnet")
	}
	return m.last.Devices[slot], nil
}

// settingLabel names a setting the way the menu does, so a refusal reads as the item
// the user just clicked rather than as its wire key.
func (m *Model) settingLabel(key string) string {
	for _, item := range m.settings {
		if item.Key == key {
			return item.Label
		}
	}
	return key
}

// Run drives the menu until ctx is cancelled or the user quits. It returns true when
// the user asked to quit, so the caller knows to tear the tray down rather than
// waiting for a shutdown that is already under way.
func (m *Model) Run(ctx context.Context, commands <-chan Command, tick <-chan time.Time) bool {
	m.Refresh()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-tick:
			m.Refresh()
		case cmd, ok := <-commands:
			if !ok {
				return false
			}
			m.Do(cmd)
			if cmd.Action == ActionQuit {
				return true
			}
		}
	}
}
