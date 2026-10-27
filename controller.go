// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sellitus/app-tail/internal/app"
	"github.com/sellitus/app-tail/internal/browser"
	"github.com/sellitus/app-tail/internal/clipboard"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/forward"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tray"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// actionTimeout bounds a menu action. Login and logout talk to the local backend,
// not the control plane, so anything slower than this is a wedged node.
const actionTimeout = 20 * time.Second

// snapshotTimeout bounds a read taken while painting the menu. It is short because the
// menu repaints every couple of seconds: a wedged backend must cost one stale list, not
// a menu that stops responding.
const snapshotTimeout = 2 * time.Second

// agentView is what the front ends need from the running agent. Declaring it here,
// where it is consumed, keeps the tray glue testable without a tailnet.
type agentView interface {
	// Node is the tailnet identity, or nil before the agent has built it.
	Node() httpapi.Node
	// Forwards is the forward registry.
	Forwards() httpapi.Forwards
	// Autostart manages the login item, or nil when the platform has none.
	Autostart() httpapi.Autostart
	// Settings is the settings document, which the tray both reads and writes.
	Settings() httpapi.SettingsAPI
	// ExitNodeAPI is the exit-node module, or nil before the agent has built it.
	ExitNodeAPI() httpapi.ExitNode
	// DNSAPI reads how names resolve, for this machine and for the tailnet.
	DNSAPI() httpapi.DNS
	// DNSProfiles is the resolver catalog the menu's picker fills its slots from.
	DNSProfiles() httpapi.DNSProfiles
	// EgressAPI reads where the traffic none of the connections carries leaves through,
	// and whether the connection chosen for it is carrying any.
	EgressAPI() httpapi.Egress
	// ProxiesAPI is the proxy instances the menu switches on and off, or nil before the
	// agent has built them.
	ProxiesAPI() httpapi.Proxies
	// TunnelsAPI is the private networks this machine is attached to, which the menu lists
	// and switches on and off, or nil before the agent has built them.
	TunnelsAPI() httpapi.Tunnels
	// InterfaceSetup reads and arranges the network-interface mode.
	InterfaceSetup() httpapi.InterfaceSetup
	// RestartNode rebuilds the tailnet node, which is what moves it between stacks.
	RestartNode(ctx context.Context) error
	// Approvals is what the privileged side refused for want of an administrator's approval,
	// and the way to ask for it.
	Approvals() httpapi.Approvals
	// DashboardURL is the dashboard's address, empty before the agent binds. It is what is
	// shown and logged; a browser is handed DashboardLaunchURL instead.
	DashboardURL() string
	// DashboardLaunchURL is a one-time link that opens the dashboard signed in, with query
	// merged in, or an error before the agent binds.
	DashboardLaunchURL(query string) (string, error)
	// ConfigQuarantine is the stored configuration this run could not use, or nil when it
	// loaded normally.
	ConfigQuarantine() *httpapi.ConfigQuarantineView
}

// settingsQuery marks the dashboard URL so the settings form is already open when the
// browser lands, which is what makes a "Settings..." menu item feel like a menu item
// rather than a link to a page the user then has to navigate.
const settingsQuery = "?settings=1"

// dnsQuery marks the dashboard URL so the browser lands on the DNS section rather than at
// the top of a page the reader then has to scroll. It is the same handoff as the settings
// query and reads the same way at the other end.
const dnsQuery = "?section=dns"

// proxiesQuery marks the dashboard URL so the browser lands on the proxies section. It is
// the same handoff the DNS query is, and for the same reason: what the menu cannot take --
// a name, an address, a list of rules -- is taken there.
const proxiesQuery = "?section=proxies"

// connectionsQuery marks the dashboard URL so the browser lands on the connections list.
// It is the same handoff the proxies query is: a server, a key and a set of addresses are
// taken where there is a keyboard.
const connectionsQuery = "?section=connections"

// trayController drives the agent from the menu bar. It is the only place the tray
// and the agent meet, and it holds no state of its own.
type trayController struct {
	agent agentView
	// stop cancels the agent's context, which is how Quit ends the process.
	stop context.CancelFunc
	// open launches a URL. Tests substitute a recorder for it.
	open func(string) error
}

var _ tray.Controller = (*trayController)(nil)

func newTrayController(agent agentView, stop context.CancelFunc) *trayController {
	return &trayController{agent: agent, stop: stop, open: browser.Open}
}

func (c *trayController) Snapshot() tray.Snapshot {
	snapshot := tray.Snapshot{}

	// First, because it explains the rest: every switch and every choice in the menu is
	// reading a default rather than what this machine was set up with.
	if c.agent.ConfigQuarantine() != nil {
		noteProblem(&snapshot, "The stored configuration could not be used; app-tail is running on the defaults")
	}

	if node := c.agent.Node(); node != nil {
		status := node.Status()
		snapshot.State = status.BackendState
		snapshot.DeviceName = status.Hostname
		noteProblem(&snapshot, status.Problem)
	}

	for _, f := range c.agent.Forwards().List() {
		snapshot.ForwardsTotal++
		if !f.Enabled {
			continue
		}
		snapshot.ForwardsEnabled++
		if f.State == forward.StateRunning {
			snapshot.ForwardsRunning++
		}
	}

	snapshot.SystemDNS, snapshot.DNSProfiles = c.systemDNS()
	snapshot.Egress, snapshot.EgressChoices = c.egress()
	snapshot.ExitNode = c.exitNodeLine()
	snapshot.ExitNodeCandidates = c.exitNodeCandidates()
	snapshot.Devices = c.devices(&snapshot)
	snapshot.NetworkInterface = c.networkState()
	if approvals := c.agent.Approvals(); approvals != nil {
		if waiting := approvals.Pending(); waiting != nil {
			snapshot.ApprovalsPending = len(waiting.Needs)
		}
	}
	snapshot.Settings = c.traySettings(&snapshot)
	// After the settings, because whether the instances are worth offering is one of them.
	snapshot.Proxies = c.proxies(snapshot.Settings[proxyModuleKey].Checked)
	snapshot.Connections = c.connections()

	return snapshot
}

// noteProblem records a reason the menu could not read something, keeping every one.
//
// The snapshot is assembled from several sources and the earliest is the most specific: a
// node that will not start is what explains a device list that could not be read, so it
// stays first and the rest are added behind it rather than replacing it. They are kept
// rather than dropped because a menu with three things wrong that names one sends its reader
// back for the other two, having already been told everything is otherwise fine.
func noteProblem(snapshot *tray.Snapshot, problem string) {
	if problem == "" {
		return
	}
	if snapshot.LastError == "" {
		snapshot.LastError = problem
		return
	}
	snapshot.LastError += "; " + problem
}

// exitNodeCandidates is the device list the picker fills its slots from, in the order the
// module ranks them. It is empty while the module is off: the picker sits under the switch
// that turns it on, and offering devices there would be offering a choice with no effect.
func (c *trayController) exitNodeCandidates() []tray.ExitNodeChoice {
	api := c.agent.ExitNodeAPI()
	if api == nil {
		return nil
	}
	view := api.View()
	if !view.Enabled {
		return nil
	}
	choices := make([]tray.ExitNodeChoice, 0, len(view.Candidates))
	for _, candidate := range view.Candidates {
		choices = append(choices, tray.ExitNodeChoice{
			ID:      candidate.ID,
			Label:   candidate.Display,
			Online:  candidate.Online,
			Current: candidate.Current,
		})
	}
	return choices
}

// proxies is the instances the menu can switch on and off, empty while the module that
// runs them is off.
//
// Empty for the reason the exit-node candidates are: with the switch above them off no
// instance listens whatever its own switch says, so a checkbox there would offer a change
// with no effect -- and the state each instance reports folds the module switch in, so
// every one of them would read as off however it was really left.
func (c *trayController) proxies(moduleOn bool) []tray.ProxyChoice {
	api := c.agent.ProxiesAPI()
	if api == nil || !moduleOn {
		return nil
	}
	list := api.List()
	choices := make([]tray.ProxyChoice, 0, len(list))
	for _, view := range list {
		choices = append(choices, tray.ProxyChoice{
			ID:        view.ID,
			Label:     view.Name,
			Enabled:   view.Enabled,
			Listening: view.Listening,
			Reach:     view.Reach,
		})
	}
	return choices
}

// connections is the private networks the menu lists and switches on and off, in the order
// the document holds them.
//
// Every stored one is offered, unlike the proxy instances: a connection's switch is the
// whole of whether it is brought up, so there is no module above it that could make a
// checkbox here mean nothing.
func (c *trayController) connections() []tray.ConnectionChoice {
	api := c.agent.TunnelsAPI()
	if api == nil {
		return nil
	}
	list := api.List()
	choices := make([]tray.ConnectionChoice, 0, len(list))
	for _, view := range list {
		choices = append(choices, tray.ConnectionChoice{
			ID:      view.ID,
			Label:   view.Name,
			Enabled: view.Enabled,
			Live:    view.Live,
			State:   view.StateLabel,
			Detail:  view.Detail,
			Kind:    view.TypeLabel,
		})
	}
	return choices
}

// systemDNS is what this machine resolves names through and the profiles it can be
// switched to.
//
// The sentence comes from the resolver module's own view rather than being worded here, so
// the menu, the card and the CLI cannot disagree about the same state. The picker is filled
// whether or not the module is on, because switching it on is exactly what clicking a
// profile does -- unlike the exit-node picker, whose devices mean nothing until the module
// that routes to them is running.
func (c *trayController) systemDNS() (string, []tray.DNSProfileChoice) {
	api := c.agent.DNSAPI()
	catalog := c.agent.DNSProfiles()
	if api == nil || catalog == nil {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), snapshotTimeout)
	defer cancel()

	view := api.View(ctx).System
	if view == nil {
		return "", nil
	}

	profiles := catalog.List()
	choices := make([]tray.DNSProfileChoice, 0, len(profiles))
	for _, p := range profiles {
		choices = append(choices, tray.DNSProfileChoice{
			ID:      p.ID,
			Label:   p.Name,
			Servers: p.Servers,
			Current: view.Enabled && p.ID == view.Profile,
		})
	}
	return systemDNSLine(view), choices
}

// systemDNSLine names what this machine resolves names through. The states it tells apart
// are the ones a user would otherwise mistake for each other: switched off, switched on but
// not in force, and in force with the chosen resolvers not answering.
func systemDNSLine(view *httpapi.DNSSystemView) string {
	label := view.ProfileLabel
	if label == "" {
		label = view.Profile
	}
	switch {
	case !view.Enabled:
		return "this machine's own resolver"
	case view.Applied && view.Unreachable != "":
		return label + " (not answering)"
	case view.Applied && view.Intercepted != "":
		// The override is in force and this network is answering for the resolver anyway.
		// A menu that showed the profile's name alone would be the one surface still
		// claiming the switch did what it says.
		return label + " (this network is answering)"
	case view.Applied && view.BootstrapDegraded:
		// The override is in force and the resolvers behind it were found by asking this
		// network where they live, which is a different fact from either of the two above and
		// the only one a menu line can carry about it.
		return label + " (found through this network)"
	case view.Applied:
		return label
	case view.Error != "":
		return label + " (not in force: " + view.Error + ")"
	default:
		return label + " (not in force yet)"
	}
}

// egress is where the traffic none of this machine's connections carries leaves through,
// and the destinations it can be moved to.
//
// The sentence comes from the egress module's own view rather than being worded here, for
// the reason the resolver line is: the card and the CLI already word this state, and a menu
// that worded its own would be a third answer to the same question. The destinations come
// from the settings schema, which is where the connection list is already resolved for the
// dashboard's picker, so the menu and the form offer exactly the same connections.
func (c *trayController) egress() (string, []tray.EgressChoice) {
	api := c.agent.EgressAPI()
	settings := c.agent.Settings()
	if api == nil || settings == nil {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), snapshotTimeout)
	defer cancel()

	view := api.View(ctx)
	direct := view.Mode != string(config.EgressTunnel)

	var choices []tray.EgressChoice
	for _, f := range settings.Schema() {
		switch f.Key {
		case egressModeKey:
			// This machine's own network, worded as the registry words it, so the row and the
			// settings form name the same choice the same way.
			for _, opt := range f.Options {
				if opt.Value != string(config.EgressDirect) {
					continue
				}
				choices = append(choices, tray.EgressChoice{
					Label: opt.Label, Detail: opt.Help, Current: direct,
				})
			}
		case egressTunnelKey:
			for _, opt := range f.Options {
				choices = append(choices, tray.EgressChoice{
					ID:      opt.Value,
					Label:   opt.Label,
					Detail:  opt.Help,
					Current: !direct && opt.Value == view.TunnelID,
				})
			}
		}
	}
	return egressLine(view), choices
}

// egressLine names where this machine's internet traffic leaves through. The states it
// tells apart are the ones a user would otherwise mistake for each other: leaving directly
// on purpose, set to a connection that is carrying it, and set to one that is not -- which
// looks identical to the first from anywhere but here.
func egressLine(view httpapi.EgressView) string {
	if view.Mode != string(config.EgressTunnel) {
		return "out of this machine"
	}
	label := view.TunnelName
	if label == "" {
		label = view.TunnelID
	}
	switch {
	case view.Carrying:
		return label
	case label == "":
		// The mode is set and no connection is named, so the traffic is leaving this machine
		// while the setting says otherwise. Naming nothing would read as the direct case,
		// which is the one reading that hides a half-made choice.
		return "no connection chosen, so it is leaving this machine"
	case view.Reason != "":
		return label + " (not carrying it: " + firstLine(view.Reason) + ")"
	default:
		// Every path that refuses to carry gives a reason and a test holds them to it, so
		// this is a build where one stopped. The row still has to say that the connection is
		// not doing what the setting claims.
		return label + " (not carrying it)"
	}
}

// firstLine keeps a multi-line reason from stretching a menu row off-screen.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// devices is every machine on the tailnet, for the submenu that hands their addresses
// and names to the clipboard. This machine leads the list: its own address is the one
// most often wanted and nothing else in the menu carries it.
//
// A tailnet that cannot be read yet is an empty list rather than a failure -- before
// login there is no tailnet to list, which is a state and not a fault. Any other reason
// reaches the menu through LastError, because a submenu that is silently empty on a
// running node is indistinguishable from a tailnet of one.
func (c *trayController) devices(snapshot *tray.Snapshot) []tray.Device {
	node := c.agent.Node()
	if node == nil {
		return nil
	}
	status := node.Status()

	ctx, cancel := context.WithTimeout(context.Background(), snapshotTimeout)
	defer cancel()
	peers, err := node.Peers(ctx)
	if err != nil {
		if !errors.Is(err, tsnode.ErrNotRunning) {
			noteProblem(snapshot, fmt.Sprintf("could not read the tailnet's devices: %v", err))
		}
		return nil
	}

	others := make([]tray.Device, 0, len(peers))
	for _, peer := range peers {
		others = append(others, tray.Device{
			Name:    peer.HostName,
			Address: tailnetAddress(peer.IPs),
			DNSName: peer.DNSName,
			Online:  peer.Online,
			State:   peer.Reach.State,
		})
	}
	// Reachable first, then by name. Ordering only by name buries the devices that can
	// actually be connected to among the ones that cannot. Online is not that test: a
	// device the tailnet still lists can have no path from here, and sorting on it puts
	// an unreachable machine above one that works.
	sort.SliceStable(others, func(i, j int) bool {
		iOK, jOK := others[i].State.Or(others[i].Online).OK(), others[j].State.Or(others[j].Online).OK()
		if iOK != jOK {
			return iOK
		}
		return strings.ToLower(others[i].Name) < strings.ToLower(others[j].Name)
	})

	devices := make([]tray.Device, 0, len(others)+1)
	if status.Hostname != "" {
		devices = append(devices, tray.Device{
			Name:    status.Hostname,
			Address: tailnetAddress(status.TailscaleIPs),
			DNSName: status.DNSName,
			Online:  true,
			Self:    true,
		})
	}
	return append(devices, others...)
}

// tailnetAddress picks the address worth pasting. A device carries both an IPv4 and an
// IPv6 address, and the IPv4 one is what fits in the places people paste it.
func tailnetAddress(ips []string) string {
	var fallback string
	for _, raw := range ips {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		if addr.Is4() {
			return addr.String()
		}
		if fallback == "" {
			fallback = addr.String()
		}
	}
	return fallback
}

// CopyToClipboard puts a device's address or name where the user can paste it.
func (c *trayController) CopyToClipboard(text string) error {
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()
	return clipboard.Copy(ctx, text)
}

// networkState reads the machine so the menu says what is really true of it now, which
// is the whole point of an entry that offers to change it.
func (c *trayController) networkState() tray.NetworkState {
	setup := c.agent.InterfaceSetup()
	if setup == nil {
		return tray.NetworkState{Reason: "the network-interface mode is not available yet"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()

	view := setup.View(ctx)
	return tray.NetworkState{
		InForce:   view.InForce,
		Available: view.Ready,
		Reason:    view.Blocker,
	}
}

// exitNodeLine names where this machine's other traffic leaves, or is empty when the
// module is off and there is nothing to say. The device the tailnet reports carrying
// traffic outranks the one app-tail asked for: the menu answers "where is my traffic
// going", and while a change is in flight those are two different devices.
func (c *trayController) exitNodeLine() string {
	api := c.agent.ExitNodeAPI()
	if api == nil {
		return ""
	}
	view := api.View()
	if !view.Enabled {
		return ""
	}
	switch {
	case view.LiveOnline && view.CurrentLabel != "" && view.LiveID == view.Current:
		return view.CurrentLabel
	case view.LiveOnline && view.LiveID != "":
		return labelFor(view, view.LiveID)
	case view.CurrentLabel != "":
		return view.CurrentLabel + " (not carrying traffic)"
	case view.Current != "":
		return view.Current + " (not carrying traffic)"
	case view.LiveID != "":
		// The node holds a device app-tail did not ask for and the tailnet does not
		// report as up -- adopted from a prior enrolment, or selected outside this app.
		// Its routes still own the default route, so the backend blackholes everything
		// leaving this machine. "None chosen" would read as ordinary direct egress,
		// which is the one reading that sends someone looking for a broken network.
		return labelFor(view, view.LiveID) + " (offline; traffic is being dropped)"
	default:
		return "none chosen"
	}
}

// labelFor names a device the way the rest of the app does, falling back to its
// identifier. The fallback is not an edge case: a device the tailnet has stopped
// offering has no entry to read a name from, and that is exactly the situation the
// menu is naming it in.
func labelFor(view httpapi.ExitNodeView, id string) string {
	for _, c := range view.Candidates {
		if c.ID == id {
			return c.Display
		}
	}
	return id
}

// traySettings reads the current value of every setting the menu shows. Which those
// are is the registry's answer, not this file's, so a setting marked for the tray
// reaches the menu with no work here.
//
// A read that fails lands in the snapshot's error rather than being dropped: a menu
// showing an unchecked box for a setting it could not read would be lying.
func (c *trayController) traySettings(snapshot *tray.Snapshot) map[string]tray.SettingState {
	settings := c.agent.Settings()
	if settings == nil {
		return nil
	}

	var view map[string]any
	states := make(map[string]tray.SettingState)
	for _, f := range settings.Schema() {
		if !f.Tray || (f.Available != nil && !*f.Available) {
			continue
		}
		if f.Write == config.WriteAutostart {
			manager := c.agent.Autostart()
			if manager == nil {
				continue
			}
			enabled, err := manager.Enabled()
			if err != nil {
				noteProblem(snapshot, "cannot read the start-at-login setting: "+err.Error())
				continue
			}
			states[f.Key] = tray.SettingState{Checked: enabled, Available: true}
			continue
		}
		if view == nil {
			view = settings.Get()
		}
		if f.Kind == config.KindEnum {
			value, ok := view[f.ViewKey].(string)
			if !ok {
				noteProblem(snapshot, fmt.Sprintf("the settings document carries no text %q", f.ViewKey))
				continue
			}
			states[f.Key] = tray.SettingState{Available: true, Value: value}
			continue
		}
		value, ok := view[f.ViewKey].(bool)
		if !ok {
			noteProblem(snapshot, fmt.Sprintf("the settings document carries no boolean %q", f.ViewKey))
			continue
		}
		states[f.Key] = tray.SettingState{Checked: value, Available: true}
	}
	return states
}

// openDashboard hands the browser a sign-in link rather than the bare address: the API
// answers only a signed-in dashboard, and the menu is one of the two places such a link
// comes from.
func (c *trayController) openDashboard(query string) error {
	link, err := c.agent.DashboardLaunchURL(query)
	if err != nil {
		return err
	}
	return c.open(link)
}

func (c *trayController) OpenDashboard() error {
	return c.openDashboard("")
}

func (c *trayController) OpenSettings() error {
	return c.openDashboard(settingsQuery)
}

func (c *trayController) OpenDNSProfiles() error {
	return c.openDashboard(dnsQuery)
}

func (c *trayController) OpenProxies() error {
	return c.openDashboard(proxiesQuery)
}

func (c *trayController) OpenConnections() error {
	return c.openDashboard(connectionsQuery)
}

// SetConnectionEnabled switches one private network on or off through the connections API,
// so a menu click inherits the validation and the reconcile a dashboard save gets rather
// than being a second way to change the same value.
func (c *trayController) SetConnectionEnabled(id string, enabled bool) error {
	api := c.agent.TunnelsAPI()
	if api == nil {
		return errors.New("the connections are not ready yet")
	}
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()

	raw := json.RawMessage(strconv.FormatBool(enabled))
	_, err := api.Update(ctx, id, map[string]json.RawMessage{connectionEnabledKey: raw})
	return err
}

// connectionEnabledKey is a connection's own switch, which is a field of the connection
// rather than a setting, so the menu names it here as it does the proxy's.
const connectionEnabledKey = "enabled"

// SetProxyEnabled switches one instance on or off through the proxies API, so a menu click
// inherits the validation and the rebinding a dashboard save gets rather than being a
// second way to change the same value.
func (c *trayController) SetProxyEnabled(id string, enabled bool) error {
	api := c.agent.ProxiesAPI()
	if api == nil {
		return errors.New("the proxies are not ready yet")
	}
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()

	// A checkbox carries a boolean, so the value is its own JSON and there is no encoding
	// step to fail.
	raw := json.RawMessage(strconv.FormatBool(enabled))
	_, err := api.Update(ctx, id, map[string]json.RawMessage{proxyEnabledKey: raw})
	return err
}

// The keys the menu reads or writes without owning a checkbox for them: the module switch
// gates whether an instance's own switch means anything, and an instance's switch is a
// field of the instance rather than a setting.
const (
	proxyModuleKey  = "proxy.enabled"
	proxyEnabledKey = "enabled"
)

func (c *trayController) SetAllForwardsEnabled(enabled bool) error {
	forwards := c.agent.Forwards()

	// No request stands behind a menu item to carry a deadline, and each toggle waits
	// for the forwarding engine, so the sweep gets the same bound as any other action.
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()

	var errs []error
	for _, f := range forwards.List() {
		if f.Enabled == enabled {
			continue
		}
		if _, err := forwards.SetEnabled(ctx, f.ID, enabled); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.Name, err))
		}
	}
	return errors.Join(errs...)
}

// SetSetting writes one setting by its wire key, routed to whichever endpoint owns it.
// Going through the settings API rather than straight to the store is what gives a
// menu click the same validation, module-availability and restart classification a
// dashboard save gets, instead of a second write path that can disagree with it.
func (c *trayController) SetSetting(key string, value bool) error {
	// By name rather than out of the settings table alone, because the menu is built from
	// the CLI schema and some of what it offers is stored on the primary connection now. A
	// settings-only lookup would refuse a checkbox the menu itself put on screen.
	field, ok := config.SettingByName(key)
	if !ok {
		return fmt.Errorf("there is no setting called %q", key)
	}
	// The menu offers only the settings the registry marks for it, and this write turns
	// a value into a boolean on the way through. Refusing anything else here is what
	// keeps that conversion honest, rather than trusting whatever built the menu.
	if !field.Tray {
		return fmt.Errorf("%q is not a setting the menu offers", key)
	}

	if field.Write == config.WriteAutostart {
		manager := c.agent.Autostart()
		if manager == nil {
			return errors.New("start at login is not available on this system")
		}
		return manager.SetEnabled(value)
	}

	// A menu checkbox carries a boolean and the registry admits nothing else into the
	// tray, so the value is its own JSON and there is no encoding step to fail.
	raw := json.RawMessage(strconv.FormatBool(value))

	// The result is discarded because neither half of it can say anything here. A
	// restart is impossible: the registry admits only live and pref-backed settings to
	// the tray, which is what the eligibility guard in internal/config enforces, so a
	// one-key tray patch never raises a restart flag. The one restart it can cause, the
	// relaunch that obtains administrator rights on Windows, the write performs itself.
	// And a deferral is not news the
	// menu has anywhere to put: a checkbox shows the stored value, which is the source
	// of truth a pref is projected from, so a setting waiting on a node that is down is
	// checked and correct -- and the status row above it already says the node is down.
	return c.writeSetting(key, raw)
}

// SetChoice selects one value of a setting that has a fixed set of them, by the same
// route SetSetting takes and for the same reason.
func (c *trayController) SetChoice(key, value string) error {
	field, ok := config.SettingByName(key)
	if !ok {
		return fmt.Errorf("there is no setting called %q", key)
	}
	if !field.Tray || field.Kind != config.KindEnum {
		return fmt.Errorf("%q is not a setting the menu offers a choice of", key)
	}
	// The menu is built from the registry's own options, so the value is one of them --
	// but it arrives here as text and the settings API is what decides that, not this. That
	// includes a field that only reads back what other settings amount to: the write path
	// refuses one as read-only and names what to set instead, which a refusal worded here
	// could not.
	return c.writeText(key, value)
}

// SetExitNode points this machine's other traffic at one device. The identifier is
// written to the same setting the dashboard's picker writes, so the schedule, the
// warning and the card all see the change the way they see any other.
func (c *trayController) SetExitNode(id string) error {
	return c.writeText(exitNodeKey, id)
}

// The settings the menu writes without owning a checkbox for them: the exit-node picker
// fills its slots from the tailnet, and the interface action is three steps rather than
// a value, so neither is in the tray's item set and each names its key here.
const (
	exitNodeKey    = "exitNode.nodeId"
	networkModeKey = "interface.mode"
	// The internet picker is a pair of settings written together, and the connections it
	// offers are the options the served schema resolves for the second of them.
	egressModeKey   = "egress.mode"
	egressTunnelKey = "egress.tunnelId"
)

// SetEgress sends this machine's internet traffic through one connection, or back out of
// the machine itself.
//
// Choosing a connection writes the mode and the connection together, because the connection
// is read only while the mode sends traffic through one. Choosing this machine writes only
// the mode: the connection stays named, which is what lets someone switch back without
// picking again, and it carries nothing while the mode says direct.
func (c *trayController) SetEgress(tunnelID string) error {
	settings := c.agent.Settings()
	if settings == nil {
		return errors.New("the settings store is not ready yet")
	}
	mode := config.EgressDirect
	if tunnelID != "" {
		mode = config.EgressTunnel
	}
	rawMode, err := json.Marshal(string(mode))
	if err != nil {
		return fmt.Errorf("cannot encode the internet-traffic mode %q: %w", mode, err)
	}
	patch := map[string]json.RawMessage{egressModeKey: rawMode}
	if tunnelID != "" {
		rawTunnel, err := json.Marshal(tunnelID)
		if err != nil {
			return fmt.Errorf("cannot encode the connection %q: %w", tunnelID, err)
		}
		patch[egressTunnelKey] = rawTunnel
	}

	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()
	_, _, err = settings.Update(ctx, patch)
	return err
}

// SetDNSProfile points this machine's name resolution at one resolver profile.
//
// Choosing a profile writes the switch and the profile together, because the profile is
// refused while the switch that governs it is off. Choosing System default writes only the
// switch: turning a module off resets every setting it owns back to its default, and the
// profile named in the same write would be refused by the switch that write just turned
// off. Either way the settings end up as they were before the feature was used, which is
// what `app-tail dns use` and the dashboard picker leave behind -- a menu click and a
// command that mean the same thing must not leave two different documents.
func (c *trayController) SetDNSProfile(id string) error {
	settings := c.agent.Settings()
	if settings == nil {
		return errors.New("the settings store is not ready yet")
	}
	on := id != dnsprofiles.SystemID
	if on {
		// The rights are what the resolver needs before it can do anything, and this click
		// is somebody asking for the feature, which is the one moment a password prompt is
		// expected rather than mysterious.
		dns := c.agent.DNSAPI()
		if dns == nil {
			return errors.New("the machine-wide resolver is not available yet")
		}
		ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
		defer cancel()
		// On Windows the rights arrive with a restart, and storing the profile below is what
		// performs it, so that answer is the go-ahead rather than a refusal.
		if err := dns.SetUpSystem(ctx); err != nil && !errors.Is(err, app.ErrRightsAtRestart) {
			return err
		}
	}

	enabled, err := json.Marshal(on)
	if err != nil {
		return fmt.Errorf("cannot encode the machine-wide resolver switch: %w", err)
	}
	patch := map[string]json.RawMessage{"systemDns.enabled": enabled}
	if on {
		profile, err := json.Marshal(id)
		if err != nil {
			return fmt.Errorf("cannot encode the resolver profile %q: %w", id, err)
		}
		patch["systemDns.profile"] = profile
	}
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()
	_, _, err = settings.Update(ctx, patch)
	return err
}

// SetNetworkMode moves this machine onto a network interface, or back off it.
//
// Turning it on is three things and not one: the machine has to be able to carry the
// mode, the mode has to be stored, and the node has to be rebuilt onto it. A menu entry
// that did only the middle one would report success beside a node still running exactly
// as before.
func (c *trayController) SetNetworkMode(tun bool) error {
	mode := config.NetworkUserspace
	rightsAtRestart := false
	if tun {
		mode = config.NetworkTUN
		setup := c.agent.InterfaceSetup()
		if setup == nil {
			return errors.New("the network-interface mode is not available yet")
		}
		ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
		defer cancel()
		if err := setup.SetUpInterface(ctx); err != nil {
			if !errors.Is(err, app.ErrRightsAtRestart) {
				return err
			}
			rightsAtRestart = true
		}
	}

	if err := c.writeText(networkModeKey, string(mode)); err != nil {
		return err
	}
	// The write restarts the whole process to obtain the rights, and the node it starts is
	// built onto the stored mode, so rebuilding this one would only race that shutdown.
	if rightsAtRestart {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()
	return c.agent.RestartNode(ctx)
}

// ApproveNetworkChanges asks an administrator to approve what the privileged side refused,
// through the same agent method the dashboard's button calls.
func (c *trayController) ApproveNetworkChanges() error {
	approvals := c.agent.Approvals()
	if approvals == nil {
		return errors.New("approving network changes is not available yet")
	}
	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()
	_, err := approvals.Approve(ctx)
	return err
}

// setupTimeout bounds arranging the machine and rebuilding the node. It is longer than
// an ordinary action because installing the privileged helper waits on the operating
// system's own authorisation prompt, which waits on a person.
const setupTimeout = 2 * time.Minute

// writeText writes a setting whose value is a piece of text. The encoding is gathered
// here so the callers carry no error they cannot produce: encoding/json refuses
// unsupported types, cycles and failing marshalers, and a string is none of those.
func (c *trayController) writeText(key, value string) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("cannot encode %q for %s: %w", value, key, err)
	}
	return c.writeSetting(key, raw)
}

// writeSetting patches one key through the settings API, so a menu click inherits the
// validation, module availability and restart classification a dashboard save gets.
func (c *trayController) writeSetting(key string, raw json.RawMessage) error {
	settings := c.agent.Settings()
	if settings == nil {
		return errors.New("the settings store is not ready yet")
	}
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()

	_, _, err := settings.Update(ctx, map[string]json.RawMessage{key: raw})
	return err
}

// Login starts an interactive login and takes the user straight to the page that
// finishes it, which is the whole reason the entry exists in the menu.
func (c *trayController) Login() error {
	node := c.agent.Node()
	if node == nil {
		return errors.New("the tailnet node is still starting")
	}
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()

	if err := node.StartLogin(ctx); err != nil {
		return err
	}
	if url := node.Status().AuthURL; url != "" {
		return c.open(url)
	}
	return c.OpenDashboard()
}

func (c *trayController) Logout() error {
	node := c.agent.Node()
	if node == nil {
		return errors.New("the tailnet node is still starting")
	}
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()
	return node.Logout(ctx)
}

func (c *trayController) Shutdown() { c.stop() }

// dashboardOpener opens the dashboard once, when there is something worth showing:
// either this is a first run with no config yet, or the node is waiting for a login
// only a browser can complete. It gives up quietly when neither happens, since a
// node that connects on its own needs no attention.
type dashboardOpener struct {
	agent    agentView
	open     func(string) error
	logger   *slog.Logger
	firstRun bool
	// noFrontEnd is a reason of its own: nothing else on screen names this process, so
	// without the dashboard the user has a running background app with no icon, no window
	// and no address to reach it at.
	noFrontEnd bool
	// opened is shared with every other opener in this process, so a run that has more
	// than one reason to show the dashboard shows it once rather than in two tabs. A nil
	// flag is an opener that shares with nobody.
	opened *atomic.Bool
	// window bounds how long to wait for a reason to open; interval is the poll rate.
	window   time.Duration
	interval time.Duration
}

func (d dashboardOpener) run(ctx context.Context) {
	deadline := time.NewTimer(d.window)
	defer deadline.Stop()

	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-ticker.C:
			if d.tryOpen() {
				return
			}
		}
	}
}

// tryOpen reports whether the watcher is finished, either because it opened the
// dashboard or because opening failed and retrying would not help.
func (d dashboardOpener) tryOpen() bool {
	url := d.agent.DashboardURL()
	if url == "" {
		return false
	}
	node := d.agent.Node()
	if node == nil {
		return false
	}
	if !d.firstRun && !d.noFrontEnd && node.Status().BackendState != tsnode.StateNeedsLogin {
		return false
	}
	if !d.claim() {
		return true
	}

	// The link carries a sign-in token, so the logs name the bare address instead.
	link, err := d.agent.DashboardLaunchURL("")
	if err != nil {
		d.logger.Warn("could not open the dashboard automatically", "url", url, "error", err)
		return true
	}
	if err := d.open(link); err != nil {
		d.logger.Warn("could not open the dashboard automatically", "url", url, "error", err)
		return true
	}
	d.logger.Info("opened the dashboard", "url", url)
	return true
}

// claim takes the one open this process makes, or reports that another opener already
// took it.
func (d dashboardOpener) claim() bool {
	return d.opened == nil || d.opened.CompareAndSwap(false, true)
}
