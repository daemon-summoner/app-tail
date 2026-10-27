// SPDX-License-Identifier: MIT

package tray

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/icon"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// trayMenu is the menu these tests are built against. It is hand-written rather than
// taken from the registry so the wiring is what is under test, not whichever settings
// happen to carry Tray today. It carries both shapes a setting can take, because the
// paint loop and the click routing differ between them.
var trayMenu = []MenuGroup{
	{ID: config.GroupApplication, Label: "Settings", Items: []SettingItem{
		{Key: "showTray", Label: "Show the menu-bar icon", Tooltip: "Show or hide the icon"},
		{Key: "startAtLogin", Label: "Start at login", Tooltip: "Launch app-tail when you log in"},
	}},
	{ID: config.GroupProxy, Label: "Tailnet proxy", Items: []SettingItem{
		{Key: "proxy.scope", Label: "What the proxy will reach", Tooltip: "How far the proxy will dial",
			Choices: []settingChoice{
				{Value: "tailnet", Label: "Tailnet only"},
				{Value: "all", Label: "Anything"},
			}},
	}},
}

// settingWrite is one SetSetting call, recorded so a test can assert both the setting
// named and the value asked for.
type settingWrite struct {
	key   string
	value bool
}

// choiceCall is one SetChoice call.
type choiceCall struct {
	key   string
	value string
}

// proxyWrite is one SetProxyEnabled call, recorded so a test can assert both the instance
// named and the state asked for -- a click that switched the wrong instance and a click
// that switched the right one the wrong way are different failures.
type proxyWrite struct {
	id      string
	enabled bool
}

// fakeController stands in for the agent. It records every call so a test can assert
// that a click reached the thing it names. Model.Run reads it from its own
// goroutine, so every field is guarded.
type fakeController struct {
	mu       sync.Mutex
	snapshot Snapshot

	opened            int
	openedSetting     int
	openedDNS         int
	openedProxies     int
	openedConnections int

	setAllCalls     []bool
	proxyCalls      []proxyWrite
	connectionCalls []connectionWrite
	settingCalls    []settingWrite
	choiceCalls     []choiceCall
	exitNodeCalls   []string
	dnsCalls        []string
	egressCalls     []string
	copied          []string
	networkCalls    []bool
	approvals       int
	approveErr      error
	logins          int
	logouts         int
	shutdowns       int
	openErr         error
	settingsErr     error
	dnsOpenErr      error
	setAllErr       error
	settingErr      error
	loginErr        error
	logoutErr       error
	choiceErr       error
	exitNodeErr     error
	dnsErr          error
	egressErr       error
	copyErr         error
	networkErr      error
	proxyOpenErr    error
	proxyErr        error

	connectionOpenErr error
	connectionErr     error
}

// connectionWrite is one connection switched on or off. It carries the id as well as the
// position for the reason proxyWrite does: a click that switched nothing and one that
// switched the wrong connection are different failures.
type connectionWrite struct {
	id      string
	enabled bool
}

func (f *fakeController) Snapshot() Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshot
}

func (f *fakeController) setSnapshot(s Snapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshot = s
}

func (f *fakeController) setOpenErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.openErr = err
}

func (f *fakeController) OpenDashboard() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opened++
	return f.openErr
}

func (f *fakeController) OpenSettings() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.openedSetting++
	return f.settingsErr
}

func (f *fakeController) OpenDNSProfiles() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.openedDNS++
	return f.dnsOpenErr
}

func (f *fakeController) dnsProfilesOpened() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.openedDNS
}

func (f *fakeController) OpenProxies() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.openedProxies++
	return f.proxyOpenErr
}

func (f *fakeController) proxiesOpened() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.openedProxies
}

func (f *fakeController) SetProxyEnabled(id string, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proxyCalls = append(f.proxyCalls, proxyWrite{id: id, enabled: enabled})
	return f.proxyErr
}

func (f *fakeController) proxyWrites() []proxyWrite {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]proxyWrite(nil), f.proxyCalls...)
}

func (f *fakeController) OpenConnections() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.openedConnections++
	return f.connectionOpenErr
}

func (f *fakeController) connectionsOpened() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.openedConnections
}

func (f *fakeController) SetConnectionEnabled(id string, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connectionCalls = append(f.connectionCalls, connectionWrite{id: id, enabled: enabled})
	return f.connectionErr
}

func (f *fakeController) connectionWrites() []connectionWrite {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]connectionWrite(nil), f.connectionCalls...)
}

func (f *fakeController) SetAllForwardsEnabled(enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setAllCalls = append(f.setAllCalls, enabled)
	return f.setAllErr
}

func (f *fakeController) SetSetting(key string, value bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settingCalls = append(f.settingCalls, settingWrite{key: key, value: value})
	return f.settingErr
}

func (f *fakeController) SetChoice(key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.choiceCalls = append(f.choiceCalls, choiceCall{key: key, value: value})
	return f.choiceErr
}

func (f *fakeController) SetExitNode(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exitNodeCalls = append(f.exitNodeCalls, id)
	return f.exitNodeErr
}

func (f *fakeController) SetDNSProfile(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dnsCalls = append(f.dnsCalls, id)
	return f.dnsErr
}

func (f *fakeController) dnsProfiles() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dnsCalls...)
}

func (f *fakeController) SetEgress(tunnelID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.egressCalls = append(f.egressCalls, tunnelID)
	return f.egressErr
}

func (f *fakeController) egressWrites() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.egressCalls...)
}

func (f *fakeController) copies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.copied...)
}

func (f *fakeController) CopyToClipboard(text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.copied = append(f.copied, text)
	return f.copyErr
}

func (f *fakeController) SetNetworkMode(tun bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.networkCalls = append(f.networkCalls, tun)
	return f.networkErr
}

func (f *fakeController) ApproveNetworkChanges() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.approvals++
	return f.approveErr
}

func (f *fakeController) approvalsAsked() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.approvals
}

func (f *fakeController) Login() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logins++
	return f.loginErr
}

func (f *fakeController) Logout() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logouts++
	return f.logoutErr
}

func (f *fakeController) Shutdown() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shutdowns++
}

func (f *fakeController) counts() (opened, logins, logouts, shutdowns int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opened, f.logins, f.logouts, f.shutdowns
}

func (f *fakeController) settingsOpened() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.openedSetting
}

func (f *fakeController) toggles() []bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]bool(nil), f.setAllCalls...)
}

func (f *fakeController) writes() []settingWrite {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]settingWrite(nil), f.settingCalls...)
}

func (f *fakeController) choices() []choiceCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]choiceCall(nil), f.choiceCalls...)
}

func (f *fakeController) exitNodes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.exitNodeCalls...)
}

func (f *fakeController) networkModes() []bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]bool(nil), f.networkCalls...)
}

// painted is one snapshot of what the menu shows.
type painted struct {
	status        string
	forwards      string
	exitNode      string
	toggleLabel   string
	toggleEnabled bool
	auth          string
	settings      map[string]SettingState
	// choices is every value of every enum setting, keyed by "setting=value".
	choices        map[string]SettingState
	networkLabel   string
	networkEnabled bool
	networkReason  string
	// approvals is the approve item's label, empty while it is hidden.
	approvals string
	// exitSlots is what each fixed device position shows, indexed by position.
	exitSlots    map[int]exitSlot
	exitOverflow string
	systemDNS    string
	// dnsSlots is what each fixed resolver-profile position shows, indexed by position.
	dnsSlots    map[int]dnsSlot
	dnsOverflow string
	egress      string
	// egressSlots is what each fixed internet-destination position shows, indexed by
	// position.
	egressSlots    map[int]egressSlot
	egressOverflow string
	// proxySlots is what each fixed proxy-instance position shows, indexed by position.
	proxySlots    map[int]proxySlot
	proxyOverflow string
	// connectionSlots is what each fixed connection position shows, indexed by position.
	connectionSlots    map[int]connectionSlot
	connectionOverflow string
	// deviceSlots is what each fixed network-device position shows, indexed by position.
	deviceSlots    map[int]deviceSlot
	deviceOverflow string
	deviceEmpty    string
	tooltip        string
	iconStatus     icon.Status
}

// deviceSlot is one painted network-device position: the row naming the machine and the
// two rows beneath it that copy its address and its name.
type deviceSlot struct {
	label   string
	address string
	dnsName string
	visible bool
}

// exitSlot is one painted device position.
type exitSlot struct {
	label    string
	selected bool
	visible  bool
}

// dnsSlot is one painted resolver-profile position. The tooltip is its own field because
// what the profile resolves through is deliberately not on the row itself.
type dnsSlot struct {
	label    string
	tooltip  string
	selected bool
	visible  bool
}

// egressSlot is one painted internet-destination position. The tooltip is its own field
// because what choosing the row does is a sentence and is deliberately not on the row.
type egressSlot struct {
	label    string
	tooltip  string
	selected bool
	visible  bool
}

// proxySlot is one painted proxy-instance position. The tooltip is its own field because
// where the instance is bound and what it reaches are deliberately not on the row itself.
type proxySlot struct {
	label   string
	tooltip string
	checked bool
	visible bool
}

// connectionSlot is one painted connection position. The tooltip is its own field because
// what kind of network it is and why it is in the state it is in are deliberately not on
// the row itself.
type connectionSlot struct {
	label   string
	tooltip string
	checked bool
	visible bool
}

// recordingView captures what the menu would display. The model paints from its own
// goroutine in the Run tests, so reads go through state().
type recordingView struct {
	mu sync.Mutex
	p  painted
}

func (v *recordingView) state() painted {
	v.mu.Lock()
	defer v.mu.Unlock()
	copied := v.p
	copied.settings = make(map[string]SettingState, len(v.p.settings))
	for k, s := range v.p.settings {
		copied.settings[k] = s
	}
	copied.choices = make(map[string]SettingState, len(v.p.choices))
	for k, s := range v.p.choices {
		copied.choices[k] = s
	}
	copied.exitSlots = make(map[int]exitSlot, len(v.p.exitSlots))
	for i, slot := range v.p.exitSlots {
		copied.exitSlots[i] = slot
	}
	copied.deviceSlots = make(map[int]deviceSlot, len(v.p.deviceSlots))
	for i, slot := range v.p.deviceSlots {
		copied.deviceSlots[i] = slot
	}
	copied.dnsSlots = make(map[int]dnsSlot, len(v.p.dnsSlots))
	for i, slot := range v.p.dnsSlots {
		copied.dnsSlots[i] = slot
	}
	copied.egressSlots = make(map[int]egressSlot, len(v.p.egressSlots))
	for i, slot := range v.p.egressSlots {
		copied.egressSlots[i] = slot
	}
	copied.proxySlots = make(map[int]proxySlot, len(v.p.proxySlots))
	for i, slot := range v.p.proxySlots {
		copied.proxySlots[i] = slot
	}
	copied.connectionSlots = make(map[int]connectionSlot, len(v.p.connectionSlots))
	for i, slot := range v.p.connectionSlots {
		copied.connectionSlots[i] = slot
	}
	return copied
}

func (v *recordingView) SetStatus(line string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.status = line
}

func (v *recordingView) SetForwards(line string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.forwards = line
}

func (v *recordingView) SetExitNode(line string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.exitNode = line
}

func (v *recordingView) SetAuth(label string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.auth = label
}

func (v *recordingView) SetTooltip(text string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.tooltip = text
}

func (v *recordingView) SetToggle(label string, enabled bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.toggleLabel = label
	v.p.toggleEnabled = enabled
}

func (v *recordingView) SetIcon(status icon.Status) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.iconStatus = status
}

func (v *recordingView) SetSetting(key string, checked, available bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.p.settings == nil {
		v.p.settings = make(map[string]SettingState)
	}
	v.p.settings[key] = SettingState{Checked: checked, Available: available}
}

func (v *recordingView) SetChoice(key, value string, selected, available bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.p.choices == nil {
		v.p.choices = make(map[string]SettingState)
	}
	v.p.choices[key+"="+value] = SettingState{Checked: selected, Available: available, Value: value}
}

func (v *recordingView) SetNetworkMode(label string, enabled bool, reason string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.networkLabel, v.p.networkEnabled, v.p.networkReason = label, enabled, reason
}

func (v *recordingView) SetApprovals(label string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.approvals = label
}

func (v *recordingView) SetExitNodeSlot(index int, label string, selected, visible bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.p.exitSlots == nil {
		v.p.exitSlots = make(map[int]exitSlot)
	}
	v.p.exitSlots[index] = exitSlot{label: label, selected: selected, visible: visible}
}

func (v *recordingView) SetDeviceSlot(index int, label, address, dnsName string, visible bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.p.deviceSlots == nil {
		v.p.deviceSlots = make(map[int]deviceSlot)
	}
	v.p.deviceSlots[index] = deviceSlot{label: label, address: address, dnsName: dnsName, visible: visible}
}

func (v *recordingView) SetDeviceOverflow(label string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.deviceOverflow = label
}

func (v *recordingView) SetDeviceEmpty(label string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.deviceEmpty = label
}

func (v *recordingView) SetExitNodeOverflow(label string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.exitOverflow = label
}

func (v *recordingView) SetSystemDNS(line string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.systemDNS = line
}

func (v *recordingView) SetDNSProfileSlot(index int, label, tooltip string, selected, visible bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.p.dnsSlots == nil {
		v.p.dnsSlots = make(map[int]dnsSlot)
	}
	v.p.dnsSlots[index] = dnsSlot{label: label, tooltip: tooltip, selected: selected, visible: visible}
}

func (v *recordingView) SetDNSProfileOverflow(label string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.dnsOverflow = label
}

func (v *recordingView) SetEgress(line string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.egress = line
}

func (v *recordingView) SetEgressSlot(index int, label, tooltip string, selected, visible bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.p.egressSlots == nil {
		v.p.egressSlots = make(map[int]egressSlot)
	}
	v.p.egressSlots[index] = egressSlot{label: label, tooltip: tooltip, selected: selected, visible: visible}
}

func (v *recordingView) SetEgressOverflow(label string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.egressOverflow = label
}

func (v *recordingView) SetProxySlot(index int, label, tooltip string, checked, visible bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.p.proxySlots == nil {
		v.p.proxySlots = make(map[int]proxySlot)
	}
	v.p.proxySlots[index] = proxySlot{label: label, tooltip: tooltip, checked: checked, visible: visible}
}

func (v *recordingView) SetProxyOverflow(label string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.proxyOverflow = label
}

func (v *recordingView) SetConnectionSlot(index int, label, tooltip string, checked, visible bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.p.connectionSlots == nil {
		v.p.connectionSlots = make(map[int]connectionSlot)
	}
	v.p.connectionSlots[index] = connectionSlot{label: label, tooltip: tooltip, checked: checked, visible: visible}
}

func (v *recordingView) SetConnectionOverflow(label string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.p.connectionOverflow = label
}

func TestStatusLineNamesTheDeviceOnceConnected(t *testing.T) {
	cases := []struct {
		name string
		snap Snapshot
		want string
	}{
		{"running with a name", Snapshot{State: "Running", DeviceName: "app-tail-laptop"}, "Connected as app-tail-laptop"},
		{"running before the name arrives", Snapshot{State: "Running"}, "Connected"},
		{"needs login", Snapshot{State: "NeedsLogin"}, "Needs login"},
		{"starting", Snapshot{State: "Starting"}, "Connecting..."},
		{"before the first snapshot", Snapshot{}, "Starting..."},
		{"unknown state passes through", Snapshot{State: "Stopped"}, "Stopped"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := StatusLine(tc.snap); got != tc.want {
				t.Errorf("StatusLine = %q, want %q", got, tc.want)
			}
		})
	}
}

// An enabled forward that is not running is a failure the user must be able to see
// without opening the dashboard.
func TestForwardsLineDistinguishesEnabledFromActuallyRunning(t *testing.T) {
	cases := []struct {
		name string
		snap Snapshot
		want string
	}{
		{"none configured", Snapshot{}, "No forwards yet"},
		{"all switched off", Snapshot{ForwardsTotal: 3}, "3 forwards, all disabled"},
		{"one switched off", Snapshot{ForwardsTotal: 1}, "1 forward, all disabled"},
		{"all healthy", Snapshot{ForwardsTotal: 2, ForwardsEnabled: 2, ForwardsRunning: 2}, "2 forwards running"},
		{"one healthy", Snapshot{ForwardsTotal: 1, ForwardsEnabled: 1, ForwardsRunning: 1}, "1 forward running"},
		{"one failing", Snapshot{ForwardsTotal: 3, ForwardsEnabled: 3, ForwardsRunning: 2}, "2 of 3 forwards running"},
		{"all failing", Snapshot{ForwardsTotal: 2, ForwardsEnabled: 2}, "0 of 2 forwards running"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ForwardsLine(tc.snap); got != tc.want {
				t.Errorf("ForwardsLine = %q, want %q", got, tc.want)
			}
		})
	}
}

// An install that never turned the module on has no exit node and never had one, so a
// permanent "Exit node: none" row is noise in a menu that has room for very little. The
// line appears only when there is something to say.
func TestTheExitNodeLineIsAbsentUntilThereIsSomethingToSay(t *testing.T) {
	if got := ExitNodeLine(Snapshot{}); got != "" {
		t.Errorf("ExitNodeLine = %q with the module off, want no menu entry at all", got)
	}
	if got := ExitNodeLine(Snapshot{ExitNode: "gateway"}); got != "Exit node: gateway" {
		t.Errorf("ExitNodeLine = %q, want the device named", got)
	}
}

// The label must name what the click will do. Getting this backwards would make the
// menu read "Enable all forwards" while everything is already on.
func TestToggleDescribesTheActionItPerforms(t *testing.T) {
	cases := []struct {
		name       string
		snap       Snapshot
		wantLabel  string
		wantTarget bool
		wantUsable bool
	}{
		{"nothing configured", Snapshot{}, "Enable all forwards", true, false},
		{"all off", Snapshot{ForwardsTotal: 2}, "Enable all forwards", true, true},
		{"some on", Snapshot{ForwardsTotal: 3, ForwardsEnabled: 1}, "Disable all forwards", false, true},
		{"all on", Snapshot{ForwardsTotal: 3, ForwardsEnabled: 3}, "Disable all forwards", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ToggleLabel(tc.snap); got != tc.wantLabel {
				t.Errorf("ToggleLabel = %q, want %q", got, tc.wantLabel)
			}
			if got := ToggleTarget(tc.snap); got != tc.wantTarget {
				t.Errorf("ToggleTarget = %v, want %v", got, tc.wantTarget)
			}
			if got := ToggleEnabled(tc.snap); got != tc.wantUsable {
				t.Errorf("ToggleEnabled = %v, want %v", got, tc.wantUsable)
			}
		})
	}
}

func TestAuthLabelOffersLogoutOnlyWhileConnected(t *testing.T) {
	if got := AuthLabel(Snapshot{State: "Running"}); got != "Log Out" {
		t.Errorf("AuthLabel(Running) = %q, want %q", got, "Log Out")
	}
	for _, state := range []string{"NeedsLogin", "Starting", "Stopped", ""} {
		if got := AuthLabel(Snapshot{State: state}); got != "Log In" {
			t.Errorf("AuthLabel(%q) = %q, want %q", state, got, "Log In")
		}
	}
}

// The menu is built from the registry, not from a list kept here: a setting marked for
// the tray must reach the menu with no work in this package, and one that is not must
// stay out of it.
func TestTheMenuIsExactlyTheSettingsTheRegistryMarkedForIt(t *testing.T) {
	schema := []config.FieldSchema{
		{Key: "notInTheMenu", Label: "Not in the menu", Help: "no Tray member", Group: config.GroupApplication},
		{Key: "showTray", Label: "Show the menu-bar icon", Help: "Show or hide the icon",
			Group: config.GroupApplication, Tray: true},
		{Key: "startAtLogin", Label: "Start at login", Help: "Launch at login",
			Group: config.GroupApplication, Tray: true},
		{Key: "dns.useTailnet", Label: "Resolve names with your tailnet's DNS", Help: "Ask the tailnet",
			Group: config.GroupDNS, Tray: true},
	}

	got := SettingItems(SettingsMenu(schema))
	want := []SettingItem{
		{Key: "dns.useTailnet", Label: "Resolve names with your tailnet's DNS", Tooltip: "Ask the tailnet"},
		{Key: "showTray", Label: "Show the menu-bar icon", Tooltip: "Show or hide the icon"},
		{Key: "startAtLogin", Label: "Start at login", Tooltip: "Launch at login"},
	}
	if len(got) != len(want) {
		t.Fatalf("SettingsMenu produced %d items, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Key != want[i].Key || got[i].Label != want[i].Label || got[i].Tooltip != want[i].Tooltip {
			t.Errorf("item %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// A setting reaches the menu only through its group's submenu, so a group that carries a
// tray-marked setting and is missing from the order is that setting silently gone: it is
// in the registry, it paints nowhere, and no other test notices.
func TestEveryGroupHoldingATraySettingBecomesASubmenu(t *testing.T) {
	inMenu := make(map[config.Group]bool, len(trayGroups))
	for _, id := range trayGroups {
		inMenu[id] = true
	}
	for _, f := range config.SettingsSchema() {
		if f.Tray && !inMenu[f.Group] {
			t.Errorf("setting %q is marked for the tray but its group %s has no submenu",
				f.Key, f.Group)
		}
	}
}

// Each of the three ways this machine reaches the tailnet needs its own section, and the
// two entries that are not settings need somewhere to hang. A placement naming a group the
// menu does not build would leave the whole action off the menu.
func TestEverySectionTheMenuPlacesAnActionInIsBuilt(t *testing.T) {
	built := make(map[config.Group]string)
	for _, group := range SettingsMenu(config.SettingsSchema()) {
		built[group.ID] = group.Label
	}
	for _, id := range []config.Group{
		forwardsToggleGroup, networkModeGroup, exitNodePickerGroup, allSettingsGroup,
	} {
		if _, ok := built[id]; !ok {
			t.Errorf("group %s carries a menu action and never becomes a submenu", id)
		}
	}
	if label := built[forwardsToggleGroup]; label != "Port Forwards" {
		t.Errorf("the forwards submenu is titled %q, so the enable-everything entry is "+
			"somewhere nobody would look for it", label)
	}
}

// The top level is the capabilities an install reaches for; the rest cost it one row
// between them. The advanced sections have to stay one contiguous run, because the parent
// they share is built where the first of them sits: a top-level section in the middle of
// that run is a section pushed below the advanced row.
func TestTheRarelyNeededSectionsHangOffOneAdvancedRow(t *testing.T) {
	groups := SettingsMenu(config.SettingsSchema())

	var top, advanced []string
	first, last := -1, -1
	for i, group := range groups {
		if !group.Advanced {
			top = append(top, group.Label)
			continue
		}
		advanced = append(advanced, group.Label)
		if first < 0 {
			first = i
		}
		last = i
	}

	wantTop := []string{"Connections", "Internet", "System DNS", "DNS Blocker", "Traffic Inspection", "Port Forwards", "Network Interface", "Exit Node", "DNS", "Settings"}
	wantAdvanced := []string{"Proxy", "Subnet Routes", "Security"}
	if !slices.Equal(top, wantTop) {
		t.Errorf("the menu's top level is %v, want %v", top, wantTop)
	}
	if !slices.Equal(advanced, wantAdvanced) {
		t.Errorf("the advanced submenu holds %v, want %v", advanced, wantAdvanced)
	}
	for _, group := range groups[first : last+1] {
		if !group.Advanced {
			t.Errorf("%s sits between two advanced sections, so the menu builds it below "+
				"the advanced row rather than above it", group.Label)
		}
	}
}

// A section whose every row is hidden opens onto nothing, which reads as the capability
// being broken rather than switched off. Every module is off on a fresh install, so that
// is the state each section has to survive: it needs an action of its own, or a row no
// module gates -- which in practice is the switch that turns its own module on.
func TestNoSectionOpensOntoNothingWithEveryModuleOff(t *testing.T) {
	available := make(map[string]bool)
	for _, f := range config.SettingsSchemaFor(config.Settings{}) {
		available[f.Key] = f.Available != nil && *f.Available
	}

	for _, group := range SettingsMenu(config.SettingsSchema()) {
		if hostsAction(group.ID) {
			continue
		}
		shown := false
		for _, item := range group.Items {
			if available[item.Key] {
				shown = true
				break
			}
		}
		if !shown {
			t.Errorf("the %s submenu has no row on a fresh install, so it opens onto nothing",
				group.Label)
		}
	}
}

// The real registry has to put something in the menu. An empty result compiles, paints
// and passes every wiring test above while silently costing the tray its checkboxes.
func TestTheRealRegistryOffersSettingsInTheMenu(t *testing.T) {
	if items := SettingItems(SettingsMenu(config.SettingsSchema())); len(items) == 0 {
		t.Error("no setting in the registry is marked for the tray, so the menu has no checkboxes")
	}
}

// The client features this app offers -- reaching advertised subnets, and the exit-node
// and DNS switches built on the same footing -- are settings the tailnet node holds
// rather than ones applied inside this process. They take effect on the click like any
// other menu checkbox, so a menu that carried none of them would be a tray with none of
// the features anyone opens it for.
func TestSettingsTheTailnetNodeHoldsReachTheMenu(t *testing.T) {
	// The CLI schema, because that is what Run builds the menu from: these settings are the
	// primary connection's preferences now, and a settings-only schema carries none of them.
	schema := config.SettingsCLISchema()
	offered := make(map[string]bool)
	for _, item := range SettingItems(SettingsMenu(schema)) {
		offered[item.Key] = true
	}

	held := 0
	for _, f := range schema {
		if f.Restart != config.RestartPrefs || !f.Tray {
			continue
		}
		held++
		if !offered[f.Key] {
			t.Errorf("setting %q is marked for the tray and never reaches the menu", f.Key)
		}
	}
	if held == 0 {
		t.Error("no setting the tailnet node holds is offered in the menu, so every client " +
			"feature is reachable only through the dashboard")
	}
}

// Each platform's tray reads one container format and shows nothing at all for the
// other, so a wrong format is an empty slot in the notification area rather than a
// failure anyone can see -- and the platform that gets it wrong is the one the
// developer is not running. The bytes are checked by their container magic: a PNG
// handed to Windows still decodes as an image, and only the header tells the two apart.
func TestEveryPlatformIsHandedTheTrayIconFormatItsShellReads(t *testing.T) {
	// A PNG opens with its signature; an ICO opens with a zero reserved field and
	// image type 1, little-endian.
	pngMagic := []byte("\x89PNG\r\n\x1a\n")
	icoMagic := []byte{0, 0, 1, 0}

	for _, goos := range []string{"windows", "darwin", "linux", runtime.GOOS} {
		want, format := pngMagic, "PNG"
		if goos == "windows" {
			want, format = icoMagic, "ICO"
		}
		for _, status := range []icon.Status{icon.StatusStarting, icon.StatusHealthy, icon.StatusFault} {
			got := TrayIcon(goos, status)
			if len(got) < len(want) {
				t.Fatalf("%s/%v produced %d bytes, too few to be an icon", goos, status, len(got))
			}
			if !bytes.HasPrefix(got, want) {
				t.Errorf("%s/%v was handed %x, which is not a %s", goos, status, got[:4], format)
			}
		}
	}
}

// The dot is the only part of the app most users look at, and it has exactly one
// meaning: cyan says the forwards are up. A state that reads healthy while traffic is
// not flowing is worse than no indicator, because it stops the user investigating.
func TestTheIconDotReportsHealthyOnlyWhenTrafficIsActuallyFlowing(t *testing.T) {
	cases := []struct {
		name string
		snap Snapshot
		want icon.Status
	}{
		{"connected with every forward up", Snapshot{State: "Running", ForwardsTotal: 2, ForwardsEnabled: 2, ForwardsRunning: 2}, icon.StatusHealthy},
		{"connected with nothing configured", Snapshot{State: "Running"}, icon.StatusHealthy},
		{"connected with forwards deliberately off", Snapshot{State: "Running", ForwardsTotal: 2}, icon.StatusHealthy},
		{"connected but an enabled forward is down", Snapshot{State: "Running", ForwardsTotal: 2, ForwardsEnabled: 2, ForwardsRunning: 1}, icon.StatusFault},
		{"before the first snapshot", Snapshot{}, icon.StatusStarting},
		{"still connecting", Snapshot{State: "Starting"}, icon.StatusStarting},
		{"waiting for a login", Snapshot{State: "NeedsLogin"}, icon.StatusFault},
		{"stopped", Snapshot{State: "Stopped"}, icon.StatusFault},
		{"a click that failed outranks a healthy node", Snapshot{State: "Running", LastError: "no browser found"}, icon.StatusFault},
		{"a click that failed outranks a quiet start", Snapshot{State: "Starting", LastError: "no browser found"}, icon.StatusFault},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IconStatus(tc.snap); got != tc.want {
				t.Errorf("IconStatus = %v, want %v", got, tc.want)
			}
		})
	}
}

// The icon and the forwards line sit one above the other in the same menu. A dot
// saying everything is fine over a line reading "1 of 2 forwards running" makes the
// user distrust both.
func TestTheIconAgreesWithTheForwardsLineBeneathIt(t *testing.T) {
	cases := []Snapshot{
		{State: "Running", ForwardsTotal: 2, ForwardsEnabled: 2, ForwardsRunning: 2},
		{State: "Running", ForwardsTotal: 2, ForwardsEnabled: 2, ForwardsRunning: 1},
		{State: "Running", ForwardsTotal: 3, ForwardsEnabled: 3},
		{State: "Running", ForwardsTotal: 3},
		{State: "Running"},
	}
	for _, snap := range cases {
		line := ForwardsLine(snap)
		lineIsHappy := !strings.Contains(line, " of ")
		if dotIsHappy := IconStatus(snap) == icon.StatusHealthy; dotIsHappy != lineIsHappy {
			t.Errorf("%+v: the dot says healthy=%v while the menu says %q", snap, dotIsHappy, line)
		}
	}
}

func TestRefreshPaintsEveryMenuEntryFromTheSnapshot(t *testing.T) {
	controller := &fakeController{snapshot: Snapshot{
		State:           "Running",
		DeviceName:      "app-tail-laptop",
		ForwardsTotal:   2,
		ForwardsEnabled: 2,
		ForwardsRunning: 1,
		Settings: map[string]SettingState{
			"showTray":     {Checked: true, Available: true},
			"startAtLogin": {Checked: false, Available: true},
		},
	}}
	view := &recordingView{}
	NewModel(controller, view, trayMenu, nil).Refresh()
	got := view.state()

	if got.status != "Connected as app-tail-laptop" {
		t.Errorf("status = %q", got.status)
	}
	if got.forwards != "1 of 2 forwards running" {
		t.Errorf("forwards = %q", got.forwards)
	}
	if got.toggleLabel != "Disable all forwards" || !got.toggleEnabled {
		t.Errorf("toggle = %q enabled=%v", got.toggleLabel, got.toggleEnabled)
	}
	if got.auth != "Log Out" {
		t.Errorf("auth = %q", got.auth)
	}
	if state := got.settings["showTray"]; !state.Checked || !state.Available {
		t.Errorf("showTray painted as %+v, want checked and available", state)
	}
	if state := got.settings["startAtLogin"]; state.Checked || !state.Available {
		t.Errorf("startAtLogin painted as %+v, want unchecked and available", state)
	}
	if !strings.Contains(got.tooltip, "Connected as app-tail-laptop") {
		t.Errorf("tooltip = %q", got.tooltip)
	}
	// One of the two enabled forwards is down, so the dot has to say so.
	if got.iconStatus != icon.StatusFault {
		t.Errorf("icon = %v, want %v", got.iconStatus, icon.StatusFault)
	}
}

// A setting the agent could not read is absent from the snapshot. Painting it as
// unchecked would claim it is switched off, so it must be painted unavailable and
// disappear from the menu instead.
func TestASettingMissingFromTheSnapshotIsHiddenRatherThanShownOff(t *testing.T) {
	controller := &fakeController{snapshot: Snapshot{
		Settings: map[string]SettingState{"showTray": {Checked: true, Available: true}},
	}}
	view := &recordingView{}
	NewModel(controller, view, trayMenu, nil).Refresh()

	state, painted := view.state().settings["startAtLogin"]
	if !painted {
		t.Fatal("startAtLogin was never painted, so its checkbox keeps whatever it was built with")
	}
	if state.Available {
		t.Errorf("startAtLogin painted as %+v, want unavailable", state)
	}
}

// Each menu entry must reach the matching agent call. A click wired to the wrong
// method is exactly the kind of bug a hand test on one platform would miss.
func TestEachActionReachesTheAgent(t *testing.T) {
	t.Run("open dashboard", func(t *testing.T) {
		c := &fakeController{}
		NewModel(c, &recordingView{}, trayMenu, nil).Do(Command{Action: ActionOpenDashboard})
		if opened, _, _, _ := c.counts(); opened != 1 {
			t.Errorf("OpenDashboard called %d times, want 1", opened)
		}
	})

	t.Run("open settings", func(t *testing.T) {
		c := &fakeController{}
		NewModel(c, &recordingView{}, trayMenu, nil).Do(Command{Action: ActionOpenSettings})
		if got := c.settingsOpened(); got != 1 {
			t.Errorf("OpenSettings called %d times, want 1", got)
		}
		if opened, _, _, _ := c.counts(); opened != 0 {
			t.Errorf("the settings entry opened the plain dashboard %d times", opened)
		}
	})

	t.Run("open resolver profiles", func(t *testing.T) {
		c := &fakeController{}
		NewModel(c, &recordingView{}, trayMenu, nil).Do(Command{Action: ActionOpenDNSProfiles})
		if got := c.dnsProfilesOpened(); got != 1 {
			t.Errorf("OpenDNSProfiles called %d times, want 1", got)
		}
		// The entry that makes a profile must not be able to switch to one: a menu row
		// mis-wired to the picker would silently change what this machine resolves with.
		if got := c.dnsProfiles(); len(got) != 0 {
			t.Errorf("the manage entry switched profiles: %v", got)
		}
		if opened, _, _, _ := c.counts(); opened != 0 {
			t.Errorf("the manage entry opened the plain dashboard %d times", opened)
		}
	})

	t.Run("open proxies", func(t *testing.T) {
		c := &fakeController{}
		NewModel(c, &recordingView{}, trayMenu, nil).Do(Command{Action: ActionOpenProxies})
		if got := c.proxiesOpened(); got != 1 {
			t.Errorf("OpenProxies called %d times, want 1", got)
		}
		// The entry that hands over to the dashboard must not be able to switch an instance:
		// a row mis-wired to the picker would take a proxy offline on a click that reads as
		// opening a page.
		if got := c.proxyWrites(); len(got) != 0 {
			t.Errorf("the handover entry switched an instance: %v", got)
		}
		if opened, _, _, _ := c.counts(); opened != 0 {
			t.Errorf("the handover entry opened the plain dashboard %d times", opened)
		}
	})

	t.Run("toggle switches everything off when any is on", func(t *testing.T) {
		c := &fakeController{snapshot: Snapshot{ForwardsTotal: 3, ForwardsEnabled: 1}}
		model := NewModel(c, &recordingView{}, trayMenu, nil)
		model.Refresh()
		model.Do(Command{Action: ActionToggleForwards})
		if got := c.toggles(); len(got) != 1 || got[0] {
			t.Errorf("SetAllForwardsEnabled calls = %v, want [false]", got)
		}
	})

	t.Run("toggle switches everything on when all are off", func(t *testing.T) {
		c := &fakeController{snapshot: Snapshot{ForwardsTotal: 3}}
		model := NewModel(c, &recordingView{}, trayMenu, nil)
		model.Refresh()
		model.Do(Command{Action: ActionToggleForwards})
		if got := c.toggles(); len(got) != 1 || !got[0] {
			t.Errorf("SetAllForwardsEnabled calls = %v, want [true]", got)
		}
	})

	t.Run("auth logs out while connected", func(t *testing.T) {
		c := &fakeController{snapshot: Snapshot{State: "Running"}}
		model := NewModel(c, &recordingView{}, trayMenu, nil)
		model.Refresh()
		model.Do(Command{Action: ActionAuth})
		if _, logins, logouts, _ := c.counts(); logouts != 1 || logins != 0 {
			t.Errorf("logins=%d logouts=%d, want 0 and 1", logins, logouts)
		}
	})

	t.Run("auth logs in otherwise", func(t *testing.T) {
		c := &fakeController{snapshot: Snapshot{State: "NeedsLogin"}}
		model := NewModel(c, &recordingView{}, trayMenu, nil)
		model.Refresh()
		model.Do(Command{Action: ActionAuth})
		if _, logins, logouts, _ := c.counts(); logins != 1 || logouts != 0 {
			t.Errorf("logins=%d logouts=%d, want 1 and 0", logins, logouts)
		}
	})

	t.Run("quit stops the agent", func(t *testing.T) {
		c := &fakeController{}
		NewModel(c, &recordingView{}, trayMenu, nil).Do(Command{Action: ActionQuit})
		if _, _, _, shutdowns := c.counts(); shutdowns != 1 {
			t.Errorf("Shutdown called %d times, want 1", shutdowns)
		}
	})
}

// Every settings checkbox shares one action, so the key on the command is the only
// thing distinguishing them. A menu that wired every checkbox to the same key would
// paint correctly and write the wrong setting on every click.
func TestASettingsClickWritesTheSettingItBelongsToAndFlipsIt(t *testing.T) {
	cases := []struct {
		key     string
		checked bool
		want    bool
	}{
		{"showTray", true, false},
		{"startAtLogin", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			c := &fakeController{snapshot: Snapshot{Settings: map[string]SettingState{
				tc.key: {Checked: tc.checked, Available: true},
			}}}
			model := NewModel(c, &recordingView{}, trayMenu, nil)
			model.Refresh()
			model.Do(Command{Action: ActionSetSetting, Key: tc.key})

			got := c.writes()
			if len(got) != 1 {
				t.Fatalf("SetSetting calls = %v, want exactly one", got)
			}
			if got[0].key != tc.key || got[0].value != tc.want {
				t.Errorf("SetSetting(%q, %v), want SetSetting(%q, %v)",
					got[0].key, got[0].value, tc.key, tc.want)
			}
		})
	}
}

// A tray click that fails has nowhere else to report itself, so the failure has to
// reach both the callback and the menu.
func TestAFailedActionIsReportedRatherThanSwallowed(t *testing.T) {
	c := &fakeController{
		snapshot: Snapshot{State: "NeedsLogin"},
		openErr:  errors.New("no browser found on this system"),
	}
	view := &recordingView{}

	var reported []error
	model := NewModel(c, view, trayMenu, func(err error) { reported = append(reported, err) })

	model.Do(Command{Action: ActionOpenDashboard})
	if len(reported) != 1 {
		t.Fatalf("OnError called %d times, want 1", len(reported))
	}
	if tooltip := view.state().tooltip; !strings.Contains(tooltip, "no browser found") {
		t.Errorf("tooltip does not surface the failure: %q", tooltip)
	}

	// A later success must clear it, or the tray would accuse the app forever.
	c.setOpenErr(nil)
	model.Do(Command{Action: ActionOpenDashboard})
	if tooltip := view.state().tooltip; strings.Contains(tooltip, "no browser found") {
		t.Errorf("tooltip still shows a stale failure: %q", tooltip)
	}
}

// A click that failed leads, and what the snapshot already found stays behind it. Replacing
// it would hide a standing fault the moment the user touched anything -- and that fault is
// often why the click failed, so it is the more useful half of the sentence.
func TestAFailedActionDoesNotHideWhatWasAlreadyWrong(t *testing.T) {
	c := &fakeController{
		snapshot: Snapshot{State: "Running", LastError: "the auth key was rejected"},
		openErr:  errors.New("no browser found on this system"),
	}
	view := &recordingView{}
	model := NewModel(c, view, trayMenu, nil)

	model.Do(Command{Action: ActionOpenDashboard})

	tooltip := view.state().tooltip
	if !strings.Contains(tooltip, "no browser found") {
		t.Errorf("the tooltip does not report the click that failed: %q", tooltip)
	}
	if !strings.Contains(tooltip, "the auth key was rejected") {
		t.Errorf("the tooltip dropped what was already wrong: %q", tooltip)
	}
	if strings.Index(tooltip, "no browser found") > strings.Index(tooltip, "the auth key was rejected") {
		t.Errorf("the click that failed is not reported first: %q", tooltip)
	}
}

// A rejected settings write is the case with the most room to mislead: the checkbox has
// already moved under the user's cursor, so the refusal must reach the menu and the
// value must not be written.
func TestARejectedSettingsWriteReachesTheMenu(t *testing.T) {
	c := &fakeController{
		snapshot:   Snapshot{Settings: map[string]SettingState{"showTray": {Checked: false, Available: true}}},
		settingErr: errors.New("showTray: the settings file is read-only"),
	}
	view := &recordingView{}

	var reported []error
	model := NewModel(c, view, trayMenu, func(err error) { reported = append(reported, err) })
	model.Refresh()
	model.Do(Command{Action: ActionSetSetting, Key: "showTray"})

	if len(reported) != 1 || !strings.Contains(reported[0].Error(), "read-only") {
		t.Fatalf("reported = %v, want the store's own refusal", reported)
	}
	if tooltip := view.state().tooltip; !strings.Contains(tooltip, "read-only") {
		t.Errorf("tooltip does not surface the refusal: %q", tooltip)
	}
}

// A disabled entry that silently does nothing when clicked reads as a broken app.
func TestUnavailableActionsFailLoudlyInsteadOfDoingNothing(t *testing.T) {
	t.Run("toggle with no forwards", func(t *testing.T) {
		c := &fakeController{}
		var reported []error
		model := NewModel(c, &recordingView{}, trayMenu, func(err error) { reported = append(reported, err) })
		model.Refresh()
		model.Do(Command{Action: ActionToggleForwards})

		if got := c.toggles(); len(got) != 0 {
			t.Errorf("the agent was asked to toggle %v forwards that do not exist", got)
		}
		if len(reported) != 1 || !strings.Contains(reported[0].Error(), "no forwards") {
			t.Errorf("reported = %v, want one error about there being no forwards", reported)
		}
	})

	t.Run("a setting this system cannot change", func(t *testing.T) {
		c := &fakeController{snapshot: Snapshot{Settings: map[string]SettingState{
			"startAtLogin": {Available: false},
		}}}
		var reported []error
		model := NewModel(c, &recordingView{}, trayMenu, func(err error) { reported = append(reported, err) })
		model.Refresh()
		model.Do(Command{Action: ActionSetSetting, Key: "startAtLogin"})

		if got := c.writes(); len(got) != 0 {
			t.Errorf("the agent was asked to change an unavailable setting: %v", got)
		}
		// The refusal has to name the entry the user clicked, not its wire key.
		if len(reported) != 1 || !strings.Contains(reported[0].Error(), "Start at login") {
			t.Errorf("reported = %v, want one refusal naming the menu entry", reported)
		}
	})

	t.Run("a setting the menu does not carry", func(t *testing.T) {
		c := &fakeController{}
		var reported []error
		model := NewModel(c, &recordingView{}, trayMenu, func(err error) { reported = append(reported, err) })
		model.Refresh()
		model.Do(Command{Action: ActionSetSetting, Key: "somethingElse"})

		if got := c.writes(); len(got) != 0 {
			t.Errorf("the agent was asked to change a setting the menu never showed: %v", got)
		}
		if len(reported) != 1 || !strings.Contains(reported[0].Error(), "somethingElse") {
			t.Errorf("reported = %v, want one refusal naming the unknown setting", reported)
		}
	})
}

// Commands carry data now, so a zero Command arrives from a closed channel or an unset
// field. Running the first action in the iota would make that silently open a browser.
func TestAZeroCommandDoesNothingAndSaysSo(t *testing.T) {
	c := &fakeController{}
	var reported []error
	model := NewModel(c, &recordingView{}, trayMenu, func(err error) { reported = append(reported, err) })
	model.Do(Command{})

	opened, logins, logouts, shutdowns := c.counts()
	if opened+logins+logouts+shutdowns != 0 || len(c.toggles()) != 0 || len(c.writes()) != 0 {
		t.Errorf("a zero Command reached the agent: opened=%d logins=%d logouts=%d shutdowns=%d",
			opened, logins, logouts, shutdowns)
	}
	if len(reported) != 1 {
		t.Errorf("reported = %v, want one error about the unknown action", reported)
	}
}

func TestRunRepaintsOnEachTickAndStopsWhenTheContextEnds(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{State: "Starting"}}
	view := &recordingView{}
	model := NewModel(c, view, trayMenu, nil)

	ctx, cancel := context.WithCancel(context.Background())
	commands := make(chan Command)
	tick := make(chan time.Time)

	done := make(chan bool, 1)
	go func() { done <- model.Run(ctx, commands, tick) }()

	// The first paint happens before any tick, so a user never sees an empty menu.
	waitFor(t, func() bool { return view.state().status == "Connecting..." }, "initial paint")

	c.setSnapshot(Snapshot{State: "Running", DeviceName: "app-tail-laptop"})
	tick <- time.Time{}
	waitFor(t, func() bool { return view.state().status == "Connected as app-tail-laptop" }, "repaint after tick")

	cancel()
	select {
	case userQuit := <-done:
		if userQuit {
			t.Error("Run reported a user quit after a context cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

// The Quit entry has to end the event loop as well as stop the agent, or the icon
// would stay in the menu bar after the app is gone.
func TestRunReturnsAfterTheUserPicksQuit(t *testing.T) {
	c := &fakeController{}
	model := NewModel(c, &recordingView{}, trayMenu, nil)

	commands := make(chan Command)
	done := make(chan bool, 1)
	go func() { done <- model.Run(context.Background(), commands, nil) }()

	commands <- Command{Action: ActionQuit}
	select {
	case userQuit := <-done:
		if !userQuit {
			t.Error("Run did not report the quit as user-initiated")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the user picked Quit")
	}
	if _, _, _, shutdowns := c.counts(); shutdowns != 1 {
		t.Errorf("Shutdown called %d times, want 1", shutdowns)
	}
}

func TestRunStopsWhenTheActionChannelCloses(t *testing.T) {
	model := NewModel(&fakeController{}, &recordingView{}, trayMenu, nil)

	commands := make(chan Command)
	done := make(chan bool, 1)
	go func() { done <- model.Run(context.Background(), commands, nil) }()

	close(commands)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the menu was torn down")
	}
}

// The tray refuses to start without a controller rather than showing an icon whose
// every entry would panic.
func TestRunRefusesToStartWithoutAController(t *testing.T) {
	if err := Run(context.Background(), Options{}); err == nil {
		t.Fatal("Run accepted an empty Options")
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A setting with a fixed set of values is one row of checkboxes that has to read as a
// picker: exactly one marked, and the mark following whichever value the agent reports.
func TestASettingWithASetOfValuesPaintsTheOneInForce(t *testing.T) {
	for _, inForce := range []string{"tailnet", "all"} {
		t.Run(inForce, func(t *testing.T) {
			c := &fakeController{snapshot: Snapshot{Settings: map[string]SettingState{
				"proxy.scope": {Available: true, Value: inForce},
			}}}
			view := &recordingView{}
			NewModel(c, view, trayMenu, nil).Refresh()

			got := view.state().choices
			if len(got) != 2 {
				t.Fatalf("painted %d choices, want both values of the setting: %+v", len(got), got)
			}
			for _, value := range []string{"tailnet", "all"} {
				state, painted := got["proxy.scope="+value]
				if !painted {
					t.Fatalf("the %q choice was never painted", value)
				}
				if want := value == inForce; state.Checked != want {
					t.Errorf("%q painted checked=%v, want %v", value, state.Checked, want)
				}
				if !state.Available {
					t.Errorf("%q painted unavailable while the setting is writable", value)
				}
			}
		})
	}
}

// A choice click sends the value it names. Wiring every value of a setting to the same
// command would paint correctly and write whichever one happened to be first.
func TestAChoiceClickWritesTheValueItNames(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{Settings: map[string]SettingState{
		"proxy.scope": {Available: true, Value: "tailnet"},
	}}}
	model := NewModel(c, &recordingView{}, trayMenu, nil)
	model.Refresh()
	model.Do(Command{Action: ActionSetChoice, Key: "proxy.scope", Choice: "all"})

	got := c.choices()
	if len(got) != 1 || got[0].key != "proxy.scope" || got[0].value != "all" {
		t.Fatalf("SetChoice calls = %v, want one for proxy.scope=all", got)
	}
}

// Clicking the value already in force is not a write. Sending it anyway would push the
// same value back through validation and a restart classification for nothing.
func TestClickingTheChoiceAlreadyInForceWritesNothing(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{Settings: map[string]SettingState{
		"proxy.scope": {Available: true, Value: "tailnet"},
	}}}
	var reported []error
	model := NewModel(c, &recordingView{}, trayMenu, func(err error) { reported = append(reported, err) })
	model.Refresh()
	model.Do(Command{Action: ActionSetChoice, Key: "proxy.scope", Choice: "tailnet"})

	if got := c.choices(); len(got) != 0 {
		t.Errorf("the agent was asked to re-write the value already in force: %v", got)
	}
	if len(reported) != 0 {
		t.Errorf("clicking the current value reported %v, want nothing -- it is not a failure", reported)
	}
}

// A setting whose module is off must not be writable from the menu, the same rule the
// boolean checkboxes follow.
func TestAChoiceInAModuleThatIsOffIsRefusedRatherThanWritten(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{Settings: map[string]SettingState{
		"proxy.scope": {Available: false, Value: "tailnet"},
	}}}
	var reported []error
	model := NewModel(c, &recordingView{}, trayMenu, func(err error) { reported = append(reported, err) })
	model.Refresh()
	model.Do(Command{Action: ActionSetChoice, Key: "proxy.scope", Choice: "all"})

	if got := c.choices(); len(got) != 0 {
		t.Errorf("the agent was asked to change an unavailable setting: %v", got)
	}
	if len(reported) != 1 || !strings.Contains(reported[0].Error(), "What the proxy will reach") {
		t.Errorf("reported = %v, want one refusal naming the menu entry", reported)
	}
}

// The picker has a fixed number of positions, so the ones the tailnet does not fill have
// to be emptied on every pass: a slot left alone keeps showing a device that has gone.
func TestTheExitNodeSlotsShowTheTailnetsDevicesAndHideTheRest(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{ExitNodeCandidates: []ExitNodeChoice{
		{ID: "a", Label: "gpu-box", Online: true},
		{ID: "b", Label: "laptop", Current: true},
	}}}
	view := &recordingView{}
	NewModel(c, view, trayMenu, nil).Refresh()
	got := view.state()

	if len(got.exitSlots) != ExitNodeSlots {
		t.Fatalf("painted %d slots, want all %d", len(got.exitSlots), ExitNodeSlots)
	}
	if slot := got.exitSlots[0]; slot.label != "gpu-box" || !slot.visible || slot.selected {
		t.Errorf("slot 0 = %+v, want the online device shown and unselected", slot)
	}
	// An offline device is named as such rather than hidden: it is still the one selected.
	if slot := got.exitSlots[1]; slot.label != "laptop (offline)" || !slot.visible || !slot.selected {
		t.Errorf("slot 1 = %+v, want the selected offline device named and marked", slot)
	}
	for i := 2; i < ExitNodeSlots; i++ {
		if got.exitSlots[i].visible {
			t.Errorf("slot %d is shown with no device in it: %+v", i, got.exitSlots[i])
		}
	}
	if got.exitOverflow != "" {
		t.Errorf("overflow = %q, want nothing while every device fits", got.exitOverflow)
	}
}

// A truncated list that says nothing reads as the tailnet having exactly this many
// devices, which is the one reading that stops somebody looking for the missing one.
func TestATailnetWithMoreDevicesThanSlotsSaysHowManyAreMissing(t *testing.T) {
	candidates := make([]ExitNodeChoice, ExitNodeSlots+3)
	for i := range candidates {
		candidates[i] = ExitNodeChoice{ID: strconv.Itoa(i), Label: "device-" + strconv.Itoa(i), Online: true}
	}
	c := &fakeController{snapshot: Snapshot{ExitNodeCandidates: candidates}}
	view := &recordingView{}
	NewModel(c, view, trayMenu, nil).Refresh()
	got := view.state()

	if !strings.Contains(got.exitOverflow, "3 more") {
		t.Errorf("overflow = %q, want it to count the three devices with no slot", got.exitOverflow)
	}
	for i := range ExitNodeSlots {
		if !got.exitSlots[i].visible {
			t.Errorf("slot %d is empty while devices are going unshown", i)
		}
	}
}

// The slot is what a click can carry -- the devices are not known when the menu is built
// -- so the model has to turn the position back into the device sitting in it.
func TestAnExitNodeClickSelectsTheDeviceInThatSlot(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{ExitNodeCandidates: []ExitNodeChoice{
		{ID: "node-a", Label: "gpu-box", Online: true},
		{ID: "node-b", Label: "laptop", Online: true},
	}}}
	model := NewModel(c, &recordingView{}, trayMenu, nil)
	model.Refresh()
	model.Do(Command{Action: ActionSetExitNode, Slot: 1})

	if got := c.exitNodes(); len(got) != 1 || got[0] != "node-b" {
		t.Fatalf("SetExitNode calls = %v, want one for node-b", got)
	}
}

// A device can leave the tailnet between the paint and the click. Reading past the list
// would panic in the menu goroutine and take the app's icon with it.
func TestClickingASlotWhoseDeviceHasGoneIsRefusedRatherThanCrashing(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{ExitNodeCandidates: []ExitNodeChoice{
		{ID: "node-a", Label: "gpu-box", Online: true},
	}}}
	var reported []error
	model := NewModel(c, &recordingView{}, trayMenu, func(err error) { reported = append(reported, err) })
	model.Refresh()
	model.Do(Command{Action: ActionSetExitNode, Slot: 5})

	if got := c.exitNodes(); len(got) != 0 {
		t.Errorf("the agent was asked for a device that is not there: %v", got)
	}
	if len(reported) != 1 || !strings.Contains(reported[0].Error(), "no longer on the tailnet") {
		t.Errorf("reported = %v, want one refusal about the device having gone", reported)
	}
}

// The row shows the profile's name and nothing else, so the submenu is as wide as the names
// rather than as wide as the longest DoH URL in the catalog. What each profile resolves
// through still has to be reachable -- two profiles named "Work" and "Home" are
// indistinguishable otherwise -- so it goes in the tooltip. The profile in force is the
// checked one, and it is the only one.
func TestTheResolverPickerNamesEachProfileAndChecksTheOneInForce(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{
		SystemDNS: "Resolving through Cloudflare",
		DNSProfiles: []DNSProfileChoice{
			{ID: "system", Label: "System default"},
			{ID: "cloudflare", Label: "Cloudflare", Servers: []string{"1.1.1.1", "1.0.0.1"}, Current: true},
		},
	}}
	view := &recordingView{}
	NewModel(c, view, trayMenu, nil).Refresh()
	got := view.state()

	if got.systemDNS != "Resolving through Cloudflare" {
		t.Errorf("state line = %q, want the sentence the snapshot already rendered", got.systemDNS)
	}
	if got.dnsSlots[0].label != "System default" || got.dnsSlots[1].label != "Cloudflare" {
		t.Errorf("slots = %q/%q, want each row to carry the profile name alone",
			got.dnsSlots[0].label, got.dnsSlots[1].label)
	}
	if got.dnsSlots[1].tooltip != "1.1.1.1, 1.0.0.1" {
		t.Errorf("slot 1 tooltip = %q, want what the profile resolves through", got.dnsSlots[1].tooltip)
	}
	if strings.Contains(got.dnsSlots[0].tooltip, "1.1.1.1") || got.dnsSlots[0].tooltip == "" {
		t.Errorf("slot 0 tooltip = %q, want the profile that names no servers to describe itself "+
			"rather than borrow the next one's servers", got.dnsSlots[0].tooltip)
	}
	if got.dnsSlots[0].selected || !got.dnsSlots[1].selected {
		t.Errorf("checked = %v/%v, want only the profile in force checked",
			got.dnsSlots[0].selected, got.dnsSlots[1].selected)
	}
	for i := 2; i < DNSProfileSlots; i++ {
		if got.dnsSlots[i].visible {
			t.Errorf("slot %d is shown with no profile in it: %+v", i, got.dnsSlots[i])
		}
	}
	if got.dnsOverflow != "" {
		t.Errorf("overflow = %q, want nothing while every profile fits", got.dnsOverflow)
	}
}

// The picker's separators are slot positions, fixed at build time because systray cannot move
// or hide one. That only lines up with the sections a user sees if the catalog still leads
// with the two entries that carry no stored servers. Reorder it -- ship a resolver ahead of
// "Tailnet DNS", say -- and the menu draws a divider between two shipped resolvers and none
// after the tailnet row, which no amount of repainting can correct.
func TestTheCatalogOrderIsWhatThePickersSeparatorsAssume(t *testing.T) {
	builtIn := dnsprofiles.BuiltIn()
	if builtIn[dnsSystemSlot].ID != dnsprofiles.SystemID {
		t.Errorf("slot %d holds %q, want the profile that changes nothing", dnsSystemSlot, builtIn[dnsSystemSlot].ID)
	}
	if builtIn[dnsTailnetSlot].ID != dnsprofiles.TailnetID {
		t.Errorf("slot %d holds %q, want the tailnet profile", dnsTailnetSlot, builtIn[dnsTailnetSlot].ID)
	}
	for i, p := range builtIn[dnsShippedFrom:] {
		if len(p.Servers) == 0 {
			t.Errorf("shipped profile %q at slot %d names no servers, so it belongs above the "+
				"separator with the other two that carry none", p.ID, dnsShippedFrom+i)
		}
	}
	if dnsOwnProfilesFrom != len(builtIn) {
		t.Errorf("the user's profiles start at slot %d with %d shipped, so a shipped profile "+
			"lands in the section below the separator", dnsOwnProfilesFrom, len(builtIn))
	}
	if dnsOwnProfilesFrom >= DNSProfileSlots {
		t.Errorf("%d shipped profiles fill all %d slots, leaving the user's own nowhere to go",
			dnsOwnProfilesFrom, DNSProfileSlots)
	}
}

// A catalog longer than the menu that says nothing reads as the profile somebody added
// having failed to save.
func TestACatalogWithMoreProfilesThanSlotsSaysHowManyAreMissing(t *testing.T) {
	profiles := make([]DNSProfileChoice, DNSProfileSlots+2)
	for i := range profiles {
		profiles[i] = DNSProfileChoice{ID: strconv.Itoa(i), Label: "profile-" + strconv.Itoa(i)}
	}
	c := &fakeController{snapshot: Snapshot{DNSProfiles: profiles}}
	view := &recordingView{}
	NewModel(c, view, trayMenu, nil).Refresh()
	got := view.state()

	if !strings.Contains(got.dnsOverflow, "2 more") {
		t.Errorf("overflow = %q, want it to count the two profiles with no slot", got.dnsOverflow)
	}
	for i := range DNSProfileSlots {
		if !got.dnsSlots[i].visible {
			t.Errorf("slot %d is empty while profiles are going unshown", i)
		}
	}
}

// Switching resolvers is what the menu exists for: the click carries a position, and the
// model has to turn it back into the profile sitting there. Clicking the one already in
// force is not a write -- on this setting it would ask the machine to make a change it has
// already made, which on macOS is a networksetup call per service for nothing.
func TestAResolverClickSwitchesToThatProfileAndReclickingTheCurrentOneDoesNothing(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{DNSProfiles: []DNSProfileChoice{
		{ID: "system", Label: "System default", Current: true},
		{ID: "nextdns", Label: "NextDNS", Servers: []string{"https://dns.nextdns.io/abc"}},
	}}}
	model := NewModel(c, &recordingView{}, trayMenu, nil)
	model.Refresh()

	model.Do(Command{Action: ActionSetDNSProfile, Slot: 1})
	if got := c.dnsProfiles(); len(got) != 1 || got[0] != "nextdns" {
		t.Fatalf("SetDNSProfile calls = %v, want one for nextdns", got)
	}

	model.Do(Command{Action: ActionSetDNSProfile, Slot: 0})
	if got := c.dnsProfiles(); len(got) != 1 {
		t.Errorf("SetDNSProfile calls = %v, want the click on the current profile to write nothing", got)
	}
}

// A profile can be deleted from the dashboard between the paint and the click. Reading past
// the list would panic in the menu goroutine and take the app's icon with it.
func TestClickingASlotWhoseProfileHasGoneIsRefusedRatherThanCrashing(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{DNSProfiles: []DNSProfileChoice{
		{ID: "system", Label: "System default", Current: true},
	}}}
	var reported []error
	model := NewModel(c, &recordingView{}, trayMenu, func(err error) { reported = append(reported, err) })
	model.Refresh()
	model.Do(Command{Action: ActionSetDNSProfile, Slot: 4})

	if got := c.dnsProfiles(); len(got) != 0 {
		t.Errorf("the agent was asked for a profile that is not there: %v", got)
	}
	if len(reported) != 1 || !strings.Contains(reported[0].Error(), "no longer in the catalog") {
		t.Errorf("reported = %v, want one refusal about the profile having gone", reported)
	}
}

// The menu opens with the choices somebody goes to the menu bar to make: which private
// networks this machine is on, where its internet traffic goes, what it resolves names
// through, what it refuses to resolve and what it examines about the traffic it carries.
// They are one run, marked so the menu draws a separator after them -- a run that leaked
// further down the list would put that separator in the middle of the ordinary sections.
func TestTheMenuOpensWithConnectionsInternetBothDNSSectionsAndInspectionAsOneRun(t *testing.T) {
	groups := SettingsMenu(config.SettingsSchema())

	var lead []string
	for i, group := range groups {
		if !group.Lead {
			continue
		}
		lead = append(lead, group.Label)
		if i != len(lead)-1 {
			t.Errorf("%s leads the menu from position %d, so the separator after the run lands "+
				"in the middle of the sections below it", group.Label, i)
		}
	}
	if want := []string{"Connections", "Internet", "System DNS", "DNS Blocker", "Traffic Inspection"}; !slices.Equal(lead, want) {
		t.Errorf("the menu opens with %v, want %v", lead, want)
	}
}

// The picker is where this machine's internet traffic is moved, so the row that matters is
// the one that is checked: everything else on the machine looks identical whether the
// traffic is going out directly or through a connection.
func TestTheInternetPickerNamesEachDestinationAndChecksTheOneInForce(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{
		Egress: "Office",
		EgressChoices: []EgressChoice{
			{Label: "Out of this machine", Detail: "Traffic leaves the way it always has."},
			{ID: "tn_office", Label: "Office", Detail: "A wireguard connection.", Current: true},
			{ID: "tn_lab", Label: "Lab", Detail: "A wireguard connection."},
		},
	}}
	view := &recordingView{}
	NewModel(c, view, trayMenu, nil).Refresh()
	got := view.state()

	if got.egress != "Office" {
		t.Errorf("state line = %q, want the sentence the snapshot already rendered", got.egress)
	}
	if got.egressSlots[0].label != "Out of this machine" || got.egressSlots[1].label != "Office" {
		t.Errorf("slots = %q/%q, want this machine first and then the connections",
			got.egressSlots[0].label, got.egressSlots[1].label)
	}
	if got.egressSlots[1].tooltip != "A wireguard connection." {
		t.Errorf("slot 1 tooltip = %q, want what choosing it amounts to", got.egressSlots[1].tooltip)
	}
	if got.egressSlots[0].selected || !got.egressSlots[1].selected || got.egressSlots[2].selected {
		t.Errorf("checked = %v/%v/%v, want only the connection carrying it checked",
			got.egressSlots[0].selected, got.egressSlots[1].selected, got.egressSlots[2].selected)
	}
	for i := 3; i < EgressSlots; i++ {
		if got.egressSlots[i].visible {
			t.Errorf("slot %d is shown with no destination in it: %+v", i, got.egressSlots[i])
		}
	}
	if got.egressOverflow != "" {
		t.Errorf("overflow = %q, want nothing while every connection fits", got.egressOverflow)
	}
}

// Moving the internet is what this picker exists for: the click carries a position and the
// model turns it back into the connection sitting there. Clicking the one already carrying
// it is not a write, and the row for this machine's own network writes the empty id -- which
// is a destination rather than the absence of one.
func TestAnInternetClickMovesTheTrafficAndReclickingTheCurrentOneDoesNothing(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{EgressChoices: []EgressChoice{
		{Label: "Out of this machine"},
		{ID: "tn_office", Label: "Office", Current: true},
	}}}
	model := NewModel(c, &recordingView{}, trayMenu, nil)
	model.Refresh()

	model.Do(Command{Action: ActionSetEgress, Slot: 0})
	if got := c.egressWrites(); len(got) != 1 || got[0] != "" {
		t.Fatalf("SetEgress calls = %#v, want one for this machine's own network", got)
	}

	model.Do(Command{Action: ActionSetEgress, Slot: 1})
	if got := c.egressWrites(); len(got) != 1 {
		t.Errorf("SetEgress calls = %#v, want the click on the connection already carrying it "+
			"to write nothing", got)
	}
}

// A connection can be removed from the dashboard between the paint and the click. Reading
// past the list would panic in the menu goroutine and take the app's icon with it.
func TestClickingASlotWhoseConnectionHasGoneIsRefusedRatherThanCrashing(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{EgressChoices: []EgressChoice{
		{Label: "Out of this machine", Current: true},
	}}}
	var reported []error
	model := NewModel(c, &recordingView{}, trayMenu, func(err error) { reported = append(reported, err) })
	model.Refresh()
	model.Do(Command{Action: ActionSetEgress, Slot: 3})

	if got := c.egressWrites(); len(got) != 0 {
		t.Errorf("the agent was asked for a connection that is not there: %v", got)
	}
	if len(reported) != 1 || !strings.Contains(reported[0].Error(), "no longer one this machine holds") {
		t.Errorf("reported = %v, want one refusal about the connection having gone", reported)
	}
}

// A list longer than the menu that says nothing reads as the connection somebody added
// having failed to save.
func TestMoreConnectionsThanSlotsSaysHowManyAreMissing(t *testing.T) {
	choices := make([]EgressChoice, EgressSlots+2)
	for i := range choices {
		choices[i] = EgressChoice{ID: strconv.Itoa(i), Label: "connection-" + strconv.Itoa(i)}
	}
	c := &fakeController{snapshot: Snapshot{EgressChoices: choices}}
	view := &recordingView{}
	NewModel(c, view, trayMenu, nil).Refresh()
	got := view.state()

	if !strings.Contains(got.egressOverflow, "2 more") {
		t.Errorf("overflow = %q, want it to count the two connections with no slot", got.egressOverflow)
	}
	for i := range EgressSlots {
		if !got.egressSlots[i].visible {
			t.Errorf("slot %d is empty while connections are going unshown", i)
		}
	}
}

// The picker is one checkbox per instance, and the checkbox is the whole point: it says
// which programs can reach anything right now. A row that carried the name alone would
// leave every instance looking the same whether it was running or switched off.
func TestTheProxyPickerNamesEachInstanceAndChecksTheOnesThatAreOn(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{Proxies: []ProxyChoice{
		{ID: "px_default", Label: "Default", Enabled: true, Listening: "127.0.0.1:1080",
			Reach: []string{"everything on tailnet"}},
		{ID: "px_psql", Label: "psql"},
	}}}
	view := &recordingView{}
	NewModel(c, view, trayMenu, nil).Refresh()
	got := view.state()

	if got.proxySlots[0].label != "Default" || got.proxySlots[1].label != "psql" {
		t.Errorf("slots = %q/%q, want each row to carry the instance name",
			got.proxySlots[0].label, got.proxySlots[1].label)
	}
	if !got.proxySlots[0].checked || got.proxySlots[1].checked {
		t.Errorf("checked = %v/%v, want only the instance that is on ticked",
			got.proxySlots[0].checked, got.proxySlots[1].checked)
	}
	if !strings.Contains(got.proxySlots[0].tooltip, "127.0.0.1:1080") ||
		!strings.Contains(got.proxySlots[0].tooltip, "everything on tailnet") {
		t.Errorf("slot 0 tooltip = %q, want where it is bound and what it reaches",
			got.proxySlots[0].tooltip)
	}
	if strings.Contains(got.proxySlots[0].label, "127.0.0.1") {
		t.Errorf("slot 0 label = %q, want the address off the row so the names set the width",
			got.proxySlots[0].label)
	}
	for i := 2; i < ProxySlots; i++ {
		if got.proxySlots[i].visible {
			t.Errorf("slot %d is shown with no instance in it: %+v", i, got.proxySlots[i])
		}
	}
	if got.proxyOverflow != "" {
		t.Errorf("overflow = %q, want nothing while every instance fits", got.proxyOverflow)
	}
}

// An instance switched on with nothing bound is the one state a bare name misreports: the
// checkbox is ticked, no program can reach it, and the port it wanted is the thing to go
// looking at.
func TestAProxySwitchedOnWithNothingBoundIsNamedAsSuch(t *testing.T) {
	cases := []struct {
		name   string
		choice ProxyChoice
		want   string
	}{
		{"listening", ProxyChoice{Label: "psql", Enabled: true, Listening: "127.0.0.1:1081"}, "psql"},
		{"switched off", ProxyChoice{Label: "psql"}, "psql"},
		{"on but not bound", ProxyChoice{Label: "psql", Enabled: true}, "psql (not listening)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProxySlotLabel(tc.choice); got != tc.want {
				t.Errorf("ProxySlotLabel = %q, want %q", got, tc.want)
			}
		})
	}
}

// An instance with no rules reaches nothing, and a tooltip that said nothing at all would
// read as one whose permissions could not be looked up.
func TestAProxyWithNoGrantsSaysSoRatherThanShowingAnEmptyTooltip(t *testing.T) {
	got := ProxySlotTooltip(ProxyChoice{Label: "psql", Listening: "127.0.0.1:1081"})
	if !strings.Contains(got, "127.0.0.1:1081") || !strings.Contains(got, "nothing") {
		t.Errorf("tooltip = %q, want it to name the address and say it reaches nothing", got)
	}
}

// A list longer than the menu that says nothing reads as the instance somebody added
// having failed to save.
func TestMoreProxiesThanSlotsSaysHowManyAreMissing(t *testing.T) {
	proxies := make([]ProxyChoice, ProxySlots+2)
	for i := range proxies {
		proxies[i] = ProxyChoice{ID: strconv.Itoa(i), Label: "proxy-" + strconv.Itoa(i)}
	}
	c := &fakeController{snapshot: Snapshot{Proxies: proxies}}
	view := &recordingView{}
	NewModel(c, view, trayMenu, nil).Refresh()
	got := view.state()

	if !strings.Contains(got.proxyOverflow, "2 more") {
		t.Errorf("overflow = %q, want it to count the two instances with no slot", got.proxyOverflow)
	}
	for i := range ProxySlots {
		if !got.proxySlots[i].visible {
			t.Errorf("slot %d is empty while instances are going unshown", i)
		}
	}
}

// The click carries a position, and the model turns it into the instance sitting there and
// asks for the state it is not in. Sending the state it is already in would make the
// checkbox unclickable in one direction.
func TestAProxyClickAsksForTheStateThatInstanceIsNotIn(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{Proxies: []ProxyChoice{
		{ID: "px_default", Label: "Default", Enabled: true, Listening: "127.0.0.1:1080"},
		{ID: "px_psql", Label: "psql"},
	}}}
	model := NewModel(c, &recordingView{}, trayMenu, nil)
	model.Refresh()

	model.Do(Command{Action: ActionToggleProxy, Slot: 1})
	model.Do(Command{Action: ActionToggleProxy, Slot: 0})

	want := []proxyWrite{{id: "px_psql", enabled: true}, {id: "px_default", enabled: false}}
	if got := c.proxyWrites(); !reflect.DeepEqual(got, want) {
		t.Errorf("SetProxyEnabled calls = %+v, want %+v", got, want)
	}
}

// An instance can be deleted from the dashboard, or the module that runs them switched off,
// between the paint and the click. Reading past the list would panic in the menu goroutine
// and take the app's icon with it.
func TestClickingASlotWhoseProxyHasGoneIsRefusedRatherThanCrashing(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{Proxies: []ProxyChoice{
		{ID: "px_default", Label: "Default", Enabled: true},
	}}}
	var reported []error
	model := NewModel(c, &recordingView{}, trayMenu, func(err error) { reported = append(reported, err) })
	model.Refresh()
	model.Do(Command{Action: ActionToggleProxy, Slot: 5})

	if got := c.proxyWrites(); len(got) != 0 {
		t.Errorf("the agent was asked to switch an instance that is not there: %v", got)
	}
	if len(reported) != 1 || !strings.Contains(reported[0].Error(), "no longer one this machine runs") {
		t.Errorf("reported = %v, want one refusal about the instance having gone", reported)
	}
}

// The picker is one checkbox per private network, and the checkbox is what a menu-bar user
// comes for: it says which networks this machine is meant to be on right now. A row
// carrying the name alone would leave a network that is up looking exactly like one that
// is switched off.
func TestTheConnectionPickerNamesEachNetworkAndChecksTheOnesSwitchedOn(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{Connections: []ConnectionChoice{
		{ID: "tn_office", Label: "Office", Enabled: true, Live: true, State: "Connected", Kind: "WireGuard"},
		{ID: "tn_lab", Label: "Lab", State: "Disabled", Kind: "OpenVPN"},
	}}}
	view := &recordingView{}
	NewModel(c, view, trayMenu, nil).Refresh()
	got := view.state()

	if got.connectionSlots[0].label != "Office" || got.connectionSlots[1].label != "Lab" {
		t.Errorf("slots = %q/%q, want each row to carry the connection name",
			got.connectionSlots[0].label, got.connectionSlots[1].label)
	}
	if !got.connectionSlots[0].checked || got.connectionSlots[1].checked {
		t.Errorf("checked = %v/%v, want only the connection that is switched on ticked",
			got.connectionSlots[0].checked, got.connectionSlots[1].checked)
	}
	if got.connectionSlots[0].tooltip != "WireGuard" {
		t.Errorf("slot 0 tooltip = %q, want the kind of network it is", got.connectionSlots[0].tooltip)
	}
	for i := 2; i < ConnectionSlots; i++ {
		if got.connectionSlots[i].visible {
			t.Errorf("slot %d is shown with no connection in it: %+v", i, got.connectionSlots[i])
		}
	}
	if got.connectionOverflow != "" {
		t.Errorf("overflow = %q, want nothing while every connection fits", got.connectionOverflow)
	}
}

// A connection removed from the dashboard leaves its slot behind. A slot painted only while
// something sits in it would keep offering the network that used to be there, and clicking
// it would ask the agent to switch a connection that no longer exists.
func TestARemovedConnectionLeavesNoRowBehind(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{Connections: []ConnectionChoice{
		{ID: "tn_office", Label: "Office", Enabled: true, Live: true},
		{ID: "tn_lab", Label: "Lab", Enabled: true, Live: true},
	}}}
	view := &recordingView{}
	model := NewModel(c, view, trayMenu, nil)
	model.Refresh()

	c.setSnapshot(Snapshot{Connections: []ConnectionChoice{
		{ID: "tn_office", Label: "Office", Enabled: true, Live: true},
	}})
	model.Refresh()

	got := view.state()
	if got.connectionSlots[1].visible || got.connectionSlots[1].label != "" {
		t.Errorf("slot 1 is still showing %+v after that connection was removed", got.connectionSlots[1])
	}
}

// A connection switched on and carrying nothing is the one state a bare name misreports:
// the checkbox is ticked, nothing crosses it, and the state is the thing to go looking at.
// A connection nobody switched on is not in a state worth naming -- it is off because it
// was turned off.
func TestAConnectionSwitchedOnAndCarryingNothingIsNamedAsSuch(t *testing.T) {
	cases := []struct {
		name   string
		choice ConnectionChoice
		want   string
	}{
		{"carrying", ConnectionChoice{Label: "Office", Enabled: true, Live: true, State: "Connected"}, "Office"},
		{"switched off", ConnectionChoice{Label: "Office", State: "Disabled"}, "Office"},
		{"on but not up", ConnectionChoice{Label: "Office", Enabled: true, State: "Failed"}, "Office (failed)"},
		{"on and still dialling", ConnectionChoice{Label: "Office", Enabled: true, State: "Connecting"}, "Office (connecting)"},
		{"on with nothing said", ConnectionChoice{Label: "Office", Enabled: true}, "Office (not connected)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ConnectionSlotLabel(tc.choice); got != tc.want {
				t.Errorf("ConnectionSlotLabel = %q, want %q", got, tc.want)
			}
		})
	}
}

// The reason a connection is not up is the whole of what a menu-bar user needs, and it is
// on the tooltip so one long sentence does not set the width of every row.
func TestAConnectionThatFailedCarriesTheReasonInItsTooltip(t *testing.T) {
	cases := []struct {
		name   string
		choice ConnectionChoice
		want   string
	}{
		{
			"kind and reason",
			ConnectionChoice{Kind: "WireGuard", Detail: "no handshake for 3m"},
			"WireGuard: no handshake for 3m",
		},
		{"kind alone", ConnectionChoice{Kind: "WireGuard"}, "WireGuard"},
		{"reason alone", ConnectionChoice{Detail: "no handshake for 3m"}, "no handshake for 3m"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ConnectionSlotTooltip(tc.choice); got != tc.want {
				t.Errorf("ConnectionSlotTooltip = %q, want %q", got, tc.want)
			}
		})
	}
}

// A list longer than the menu that says nothing reads as the connection somebody added
// having failed to save.
func TestMoreNetworksThanConnectionSlotsSaysHowManyAreMissing(t *testing.T) {
	connections := make([]ConnectionChoice, ConnectionSlots+2)
	for i := range connections {
		connections[i] = ConnectionChoice{ID: strconv.Itoa(i), Label: "net-" + strconv.Itoa(i)}
	}
	c := &fakeController{snapshot: Snapshot{Connections: connections}}
	view := &recordingView{}
	NewModel(c, view, trayMenu, nil).Refresh()
	got := view.state()

	if !strings.Contains(got.connectionOverflow, "2 more") {
		t.Errorf("overflow = %q, want it to count the two connections with no slot", got.connectionOverflow)
	}
	for i := range ConnectionSlots {
		if !got.connectionSlots[i].visible {
			t.Errorf("slot %d is empty while connections are going unshown", i)
		}
	}
}

// The click carries a position, and the model turns it into the connection sitting there
// and asks for the state it is not in. Sending the state it is already in would make the
// checkbox unclickable in one direction.
func TestAConnectionClickAsksForTheStateThatNetworkIsNotIn(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{Connections: []ConnectionChoice{
		{ID: "tn_office", Label: "Office", Enabled: true, Live: true},
		{ID: "tn_lab", Label: "Lab"},
	}}}
	model := NewModel(c, &recordingView{}, trayMenu, nil)
	model.Refresh()

	model.Do(Command{Action: ActionToggleConnection, Slot: 1})
	model.Do(Command{Action: ActionToggleConnection, Slot: 0})

	want := []connectionWrite{{id: "tn_lab", enabled: true}, {id: "tn_office", enabled: false}}
	if got := c.connectionWrites(); !reflect.DeepEqual(got, want) {
		t.Errorf("SetConnectionEnabled calls = %+v, want %+v", got, want)
	}
}

// A connection can be removed from the dashboard between the paint and the click. Reading
// past the list would panic in the menu goroutine and take the app's icon with it.
func TestClickingAConnectionSlotWhoseNetworkHasGoneIsRefusedRatherThanCrashing(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{Connections: []ConnectionChoice{
		{ID: "tn_office", Label: "Office", Enabled: true},
	}}}
	var reported []error
	model := NewModel(c, &recordingView{}, trayMenu, func(err error) { reported = append(reported, err) })
	model.Refresh()
	model.Do(Command{Action: ActionToggleConnection, Slot: 5})

	if got := c.connectionWrites(); len(got) != 0 {
		t.Errorf("the agent was asked to switch a connection that is not there: %v", got)
	}
	if len(reported) != 1 || !strings.Contains(reported[0].Error(), "no longer one this machine holds") {
		t.Errorf("reported = %v, want one refusal about the connection having gone", reported)
	}
}

// Adding, importing or editing a connection needs a keyboard, so the menu hands over to the
// surface that has one rather than offering half of it.
func TestTheConnectionsRowHandsOverToTheDashboard(t *testing.T) {
	c := &fakeController{}
	model := NewModel(c, &recordingView{}, trayMenu, nil)
	model.Do(Command{Action: ActionOpenConnections})

	if got := c.connectionsOpened(); got != 1 {
		t.Errorf("the connections page was opened %d times, want once", got)
	}
}

// The interface entry names what the click does, not the state it is in, and asks for the
// mode this machine is not already on.
func TestTheInterfaceEntryOffersWhicheverModeThisMachineIsNotOn(t *testing.T) {
	cases := []struct {
		name    string
		state   NetworkState
		label   string
		enabled bool
		reason  string
		want    bool
	}{
		{
			name: "ready and off", state: NetworkState{Available: true},
			label: "Turn on the network interface", enabled: true, want: true,
		},
		{
			name: "already on", state: NetworkState{InForce: true},
			label: "Turn off the network interface", enabled: true, want: false,
		},
		{
			name:  "the helper is missing",
			state: NetworkState{Reason: "the privileged helper is not installed"},
			label: "Turn on the network interface", enabled: false,
			reason: "the privileged helper is not installed", want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &fakeController{snapshot: Snapshot{NetworkInterface: tc.state}}
			view := &recordingView{}
			model := NewModel(c, view, trayMenu, nil)
			model.Refresh()

			got := view.state()
			if got.networkLabel != tc.label {
				t.Errorf("label = %q, want %q", got.networkLabel, tc.label)
			}
			if got.networkEnabled != tc.enabled {
				t.Errorf("enabled = %v, want %v", got.networkEnabled, tc.enabled)
			}
			if got.networkReason != tc.reason {
				t.Errorf("reason = %q, want %q", got.networkReason, tc.reason)
			}

			model.Do(Command{Action: ActionSetNetworkMode})
			asked := c.networkModes()
			if !tc.enabled {
				if len(asked) != 0 {
					t.Fatalf("the agent was asked to switch mode on a machine that cannot: %v", asked)
				}
				return
			}
			if len(asked) != 1 || asked[0] != tc.want {
				t.Fatalf("SetNetworkMode calls = %v, want [%v]", asked, tc.want)
			}
		})
	}
}

// A machine that cannot carry the mode keeps the entry, so the reason has somewhere to
// live -- but an entry that disappeared or a blank row would each be worse than saying so.
func TestAMachineThatCannotCarryTheModeSaysWhyOnTheRowBeneath(t *testing.T) {
	if got := NetworkModeReason(Snapshot{NetworkInterface: NetworkState{Available: true}}); got != "" {
		t.Errorf("reason = %q on a ready machine, want the row hidden", got)
	}
	if got := NetworkModeReason(Snapshot{NetworkInterface: NetworkState{InForce: true}}); got != "" {
		t.Errorf("reason = %q while the mode is in force, want the row hidden", got)
	}
	// A machine with no reason to give still gets a row rather than an enabled entry
	// that fails on click.
	if got := NetworkModeReason(Snapshot{}); got != "Not available on this machine" {
		t.Errorf("reason = %q, want a stated one", got)
	}
	// A multi-line reason would stretch the menu off screen.
	snap := Snapshot{NetworkInterface: NetworkState{Reason: "the helper is not running\ndial unix: no such file"}}
	if got := NetworkModeReason(snap); got != "the helper is not running" {
		t.Errorf("reason = %q, want only its first line", got)
	}
}

// Clicking the device already carrying this machine's traffic is not a write. Sending it
// again would push the same identifier back through validation and onto the node for
// nothing; the switch above the list is what turns the exit node off.
func TestClickingTheExitNodeAlreadyInUseWritesNothing(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{ExitNodeCandidates: []ExitNodeChoice{
		{ID: "node-a", Label: "gpu-box", Online: true, Current: true},
	}}}
	var reported []error
	model := NewModel(c, &recordingView{}, trayMenu, func(err error) { reported = append(reported, err) })
	model.Refresh()
	model.Do(Command{Action: ActionSetExitNode, Slot: 0})

	if got := c.exitNodes(); len(got) != 0 {
		t.Errorf("the agent was asked to re-select the device already in use: %v", got)
	}
	if len(reported) != 0 {
		t.Errorf("clicking the current device reported %v, want nothing -- it is not a failure", reported)
	}
}

// The click carries a slot, not a device, so the copy is only right if the model reads
// the machine sitting there now. Two devices with the same rows in a different order is
// the case that catches a model reading the wrong one.
func TestACopyClickSendsTheValueOfTheDeviceInThatSlot(t *testing.T) {
	devices := []Device{
		{Name: "laptop", Address: "100.64.0.1", DNSName: "laptop.tail1a2b3c.ts.net", Online: true, Self: true},
		{Name: "htpc", Address: "100.64.0.2", DNSName: "htpc.tail1a2b3c.ts.net", Online: true},
	}
	controller := &fakeController{snapshot: Snapshot{State: "Running", Devices: devices}}
	model := NewModel(controller, &recordingView{}, nil, nil)
	model.Refresh()

	model.Do(Command{Action: ActionCopyDeviceAddress, Slot: 1})
	model.Do(Command{Action: ActionCopyDeviceName, Slot: 0})

	want := []string{"100.64.0.2", "laptop.tail1a2b3c.ts.net"}
	if got := controller.copies(); !reflect.DeepEqual(got, want) {
		t.Errorf("copied %q, want %q", got, want)
	}
}

// The list is repainted every couple of seconds, so a machine can leave the tailnet
// between the paint and the click. Reading past the end of the list would panic on the
// tray's own goroutine and take the menu down with it.
func TestCopyingFromASlotWhoseDeviceHasGoneIsRefusedRatherThanCrashing(t *testing.T) {
	controller := &fakeController{snapshot: Snapshot{State: "Running"}}
	model := NewModel(controller, &recordingView{}, nil, nil)
	model.Refresh()

	model.Do(Command{Action: ActionCopyDeviceAddress, Slot: 3})

	if got := controller.copies(); len(got) != 0 {
		t.Errorf("copied %q from a slot holding no device", got)
	}
	if !strings.Contains(model.last.LastError, "no longer on the tailnet") {
		t.Errorf("the menu reports %q, want it to say the device has gone", model.last.LastError)
	}
}

// A device the tailnet publishes no name for has no row offering to copy one, so a click
// here means the list moved under the menu. Copying the empty string would replace
// whatever the user had on their clipboard with nothing.
func TestCopyingAValueTheTailnetDoesNotPublishIsRefusedRatherThanCopyingNothing(t *testing.T) {
	controller := &fakeController{snapshot: Snapshot{
		State:   "Running",
		Devices: []Device{{Name: "printer", Address: "100.64.0.9", Online: true}},
	}}
	model := NewModel(controller, &recordingView{}, nil, nil)
	model.Refresh()

	model.Do(Command{Action: ActionCopyDeviceName, Slot: 0})

	if got := controller.copies(); len(got) != 0 {
		t.Errorf("copied %q for a device with no tailnet name", got)
	}
	if !strings.Contains(model.last.LastError, "printer") {
		t.Errorf("the menu reports %q, want it to name the device it could not copy from", model.last.LastError)
	}
}

// A clipboard that refused the write must not read as a copy that worked: the whole
// result of this action is somewhere the menu cannot see.
func TestAClipboardThatRefusesTheCopyIsReportedInTheMenu(t *testing.T) {
	controller := &fakeController{
		snapshot: Snapshot{State: "Running", Devices: []Device{{Name: "htpc", Address: "100.64.0.2", Online: true}}},
		copyErr:  errors.New("no clipboard program is installed"),
	}
	model := NewModel(controller, &recordingView{}, nil, nil)
	model.Refresh()

	model.Do(Command{Action: ActionCopyDeviceAddress, Slot: 0})

	if !strings.Contains(model.last.LastError, "no clipboard program") {
		t.Errorf("the menu reports %q, want the clipboard's own refusal", model.last.LastError)
	}
}

// Every slot is repainted on every pass, including the ones past the end of the list: a
// slot left alone keeps showing a machine that has since left the tailnet.
func TestEveryDeviceSlotIsPaintedIncludingTheEmptyOnes(t *testing.T) {
	controller := &fakeController{snapshot: Snapshot{
		State:   "Running",
		Devices: []Device{{Name: "laptop", Address: "100.64.0.1", Online: true, Self: true}},
	}}
	view := &recordingView{}
	model := NewModel(controller, view, nil, nil)

	model.Refresh()

	painted := view.state()
	if len(painted.deviceSlots) != DeviceSlots {
		t.Fatalf("%d of %d slots were painted", len(painted.deviceSlots), DeviceSlots)
	}
	if got := painted.deviceSlots[0]; got.label != "laptop (this machine)" || !got.visible {
		t.Errorf("slot 0 painted %+v, want this machine named and shown", got)
	}
	if painted.deviceSlots[1].visible {
		t.Errorf("slot 1 shows %q with only one device on the tailnet", painted.deviceSlots[1].label)
	}
}

// A device the tailnet publishes only one of the two values for still gets its row for the
// other one clicked, and a device can leave the tailnet between the paint and the click.
// Neither may reach the clipboard: copying nothing looks exactly like copying successfully.
func TestACopyThatHasNoValueBehindItIsRefusedRatherThanSilentlyDoingNothing(t *testing.T) {
	devices := []Device{{Name: "printer", DNSName: "printer.tail1a2b3c.ts.net", Online: true}}

	cases := []struct {
		name   string
		action Action
		slot   int
		says   string
	}{
		{"a device the tailnet gave no address", ActionCopyDeviceAddress, 0, "printer"},
		{"a device that is no longer listed", ActionCopyDeviceName, 7, "no longer on the tailnet"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			controller := &fakeController{snapshot: Snapshot{State: "Running", Devices: devices}}
			model := NewModel(controller, &recordingView{}, nil, nil)
			model.Refresh()

			model.Do(Command{Action: tc.action, Slot: tc.slot})

			if got := controller.copies(); len(got) != 0 {
				t.Errorf("copied %q when there was no value to copy", got)
			}
			if !strings.Contains(model.last.LastError, tc.says) {
				t.Errorf("the menu reports %q, want it to mention %q", model.last.LastError, tc.says)
			}
		})
	}
}

// The label is the only thing distinguishing one device row from another, so it has to
// carry what the user needs to tell them apart: which machine is theirs and which are
// out of reach.
func TestADeviceLabelSaysWhatSetsThatMachineApart(t *testing.T) {
	cases := []struct {
		name   string
		device Device
		want   string
	}{
		{"this machine", Device{Name: "laptop", Online: true, Self: true}, "laptop (this machine)"},
		{"a machine that can be reached", Device{Name: "htpc", Online: true}, "htpc"},
		{"a machine that cannot", Device{Name: "attic-pi"}, "attic-pi (offline)"},
		{"this machine while it is offline", Device{Name: "laptop", Self: true}, "laptop (this machine)"},
		{
			// The row this whole field exists for: the tailnet still lists the machine, so
			// Online alone would print a bare name and send somebody to copy its address.
			"a machine the tailnet lists but nothing reaches",
			Device{Name: "gitlab", Online: true, State: tsnode.PeerNoPath},
			"gitlab (unreachable)",
		},
		{
			"a machine whose key expired",
			Device{Name: "builder", Online: true, State: tsnode.PeerExpired},
			"builder (key expired)",
		},
		{
			"a machine reachable only through a relay",
			Device{Name: "nas", Online: true, State: tsnode.PeerRelayed},
			"nas (relayed)",
		},
		{
			"a machine the node calls ready",
			Device{Name: "develop", Online: true, State: tsnode.PeerReady},
			"develop",
		},
		{
			// The state travels from the agent, so a build older than the label switch can
			// hand it a word this one does not list. Saying it beats printing a clean row.
			"a state this build does not know",
			Device{Name: "odd", Online: true, State: tsnode.PeerState("quarantined")},
			"odd (quarantined)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeviceSlotLabel(tc.device); got != tc.want {
				t.Errorf("DeviceSlotLabel(%+v) = %q, want %q", tc.device, got, tc.want)
			}
		})
	}
}

// A list cut off at the slot count reads as the whole tailnet unless it says otherwise,
// so the count of what is missing is the point of the overflow row.
func TestTheOverflowRowCountsExactlyTheDevicesTheMenuHadNoRoomFor(t *testing.T) {
	cases := []struct {
		name  string
		total int
		want  string
	}{
		{"a tailnet that fits", DeviceSlots, ""},
		{"one device too many", DeviceSlots + 1, "1 more on the dashboard..."},
		{"a tailnet much larger than the menu", DeviceSlots + 40, "40 more on the dashboard..."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := Snapshot{Devices: make([]Device, tc.total)}
			if got := DeviceOverflowLabel(snapshot); got != tc.want {
				t.Errorf("DeviceOverflowLabel(%d devices) = %q, want %q", tc.total, got, tc.want)
			}
		})
	}
}

// The placeholder has to give the reason that is true of the node, not just a reason: a
// machine that never logged in has no tailnet to list yet, and telling it there are no
// devices sends somebody looking for machines that are sitting there.
func TestThePlaceholderNamesWhyTheDeviceListIsEmpty(t *testing.T) {
	cases := []struct {
		name string
		snap Snapshot
		want string
	}{
		{"before the first snapshot", Snapshot{}, "Not connected yet"},
		{"waiting for a login", Snapshot{State: "NeedsLogin"}, "Not connected yet"},
		{"connected, nothing listed yet", Snapshot{State: "Running"}, "No devices yet"},
		{"connected with a device", Snapshot{State: "Running", Devices: []Device{{Name: "htpc"}}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeviceEmptyLabel(tc.snap); got != tc.want {
				t.Errorf("DeviceEmptyLabel = %q, want %q", got, tc.want)
			}
		})
	}
}

// The approve item is there only while something waits for an administrator: a permanent row
// offering to approve nothing would be a password prompt with no reason behind it.
func TestTheApproveItemShowsOnlyWhileChangesWaitForAnAdministrator(t *testing.T) {
	c := &fakeController{}
	view := &recordingView{}
	model := NewModel(c, view, trayMenu, nil)
	model.Refresh()
	if got := view.state().approvals; got != "" {
		t.Errorf("approve item = %q with nothing waiting, want it hidden", got)
	}

	c.mu.Lock()
	c.snapshot.ApprovalsPending = 2
	c.mu.Unlock()
	model.Refresh()
	if got := view.state().approvals; got != "Approve network changes…" {
		t.Errorf("approve item = %q with two changes waiting, want it offered", got)
	}

	model.Do(Command{Action: ActionApproveNetworkChanges})
	if n := c.approvalsAsked(); n != 1 {
		t.Errorf("the agent was asked to approve %d times, want once", n)
	}
}

// A click that reaches the item after the list emptied asks for nothing, and says so rather
// than raising a prompt with nothing in it.
func TestApprovingWithNothingWaitingAsksTheAgentForNothing(t *testing.T) {
	c := &fakeController{}
	var reported []error
	model := NewModel(c, &recordingView{}, trayMenu, func(err error) { reported = append(reported, err) })
	model.Refresh()
	model.Do(Command{Action: ActionApproveNetworkChanges})

	if n := c.approvalsAsked(); n != 0 {
		t.Errorf("the agent was asked to approve %d times with nothing waiting", n)
	}
	if len(reported) != 1 {
		t.Errorf("reported %v, want one error saying nothing is waiting", reported)
	}
}

// A dismissed prompt is shown in the menu like any failed click, so the item does not appear to
// have done nothing.
func TestADismissedApprovalPromptIsShownInTheMenu(t *testing.T) {
	c := &fakeController{snapshot: Snapshot{ApprovalsPending: 1},
		approveErr: errors.New("the administrator prompt was dismissed, so nothing was approved")}
	view := &recordingView{}
	model := NewModel(c, view, trayMenu, nil)
	model.Refresh()
	model.Do(Command{Action: ActionApproveNetworkChanges})

	if got := view.state().status; !strings.Contains(got, "dismissed") && !strings.Contains(view.state().tooltip, "dismissed") {
		t.Errorf("status %q and tooltip %q do not say the prompt was dismissed", got, view.state().tooltip)
	}
}
