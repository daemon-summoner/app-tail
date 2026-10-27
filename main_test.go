// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/access"
	"github.com/sellitus/app-tail/internal/app"
	"github.com/sellitus/app-tail/internal/autostart"
	"github.com/sellitus/app-tail/internal/cli"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/forward"
	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/instance"
	"github.com/sellitus/app-tail/internal/tray"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// fakeAgent stands in for the running agent. Every method is guarded because the
// tray and the dashboard watcher both read it from their own goroutines.
type fakeAgent struct {
	mu sync.Mutex

	node         *fakeNode
	forwards     *fakeForwards
	autostart    *fakeAutostart
	settings     *fakeSettings
	exitNode     *fakeExitNode
	dns          *fakeDNS
	profiles     *fakeDNSProfiles
	proxies      *fakeProxies
	tunnels      *fakeTunnels
	egress       *fakeEgress
	iface        *fakeInterfaceSetup
	approvals    *fakeApprovals
	restarts     int
	restartErr   error
	dashboardURL string
	// launches counts the sign-in links minted, and stands in for the token in each.
	launches   int
	quarantine *httpapi.ConfigQuarantineView
}

func (a *fakeAgent) Node() httpapi.Node {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.node == nil {
		return nil
	}
	return a.node
}

func (a *fakeAgent) Forwards() httpapi.Forwards {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.forwards
}

func (a *fakeAgent) Autostart() httpapi.Autostart {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.autostart == nil {
		return nil
	}
	return a.autostart
}

func (a *fakeAgent) Settings() httpapi.SettingsAPI {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.settings == nil {
		return nil
	}
	return a.settings
}

func (a *fakeAgent) ExitNodeAPI() httpapi.ExitNode {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.exitNode == nil {
		return nil
	}
	return a.exitNode
}

func (a *fakeAgent) DNSAPI() httpapi.DNS {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dns == nil {
		return nil
	}
	return a.dns
}

func (a *fakeAgent) DNSProfiles() httpapi.DNSProfiles {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.profiles == nil {
		return nil
	}
	return a.profiles
}

func (a *fakeAgent) ProxiesAPI() httpapi.Proxies {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.proxies == nil {
		return nil
	}
	return a.proxies
}

func (a *fakeAgent) TunnelsAPI() httpapi.Tunnels {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tunnels == nil {
		return nil
	}
	return a.tunnels
}

func (a *fakeAgent) EgressAPI() httpapi.Egress {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.egress == nil {
		return nil
	}
	return a.egress
}

func (a *fakeAgent) InterfaceSetup() httpapi.InterfaceSetup {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.iface == nil {
		return nil
	}
	return a.iface
}

func (a *fakeAgent) Approvals() httpapi.Approvals {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.approvals == nil {
		return nil
	}
	return a.approvals
}

func (a *fakeAgent) RestartNode(context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.restarts++
	return a.restartErr
}

func (a *fakeAgent) restartCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.restarts
}

func (a *fakeAgent) DashboardURL() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dashboardURL
}

// DashboardLaunchURL builds the link the way the agent does, with a counter in place of the
// token, so a test can tell a sign-in link was asked for rather than the bare address.
func (a *fakeAgent) DashboardLaunchURL(query string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dashboardURL == "" {
		return "", errors.New("the dashboard is not listening yet")
	}
	a.launches++
	link := fmt.Sprintf("%s/?launch=L%d", a.dashboardURL, a.launches)
	if q := strings.TrimPrefix(query, "?"); q != "" {
		link += "&" + q
	}
	return link, nil
}

func (a *fakeAgent) ConfigQuarantine() *httpapi.ConfigQuarantineView {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.quarantine
}

func (a *fakeAgent) setNode(node *fakeNode) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.node = node
}

func (a *fakeAgent) setDashboardURL(url string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.dashboardURL = url
}

type fakeNode struct {
	mu        sync.Mutex
	status    tsnode.Status
	peers     []tsnode.Peer
	peersErr  error
	logins    int
	logouts   int
	loginErr  error
	logoutErr error
}

func (n *fakeNode) Status() tsnode.Status {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.status
}

func (n *fakeNode) setStatus(status tsnode.Status) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.status = status
}

func (n *fakeNode) StartLogin(context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.logins++
	return n.loginErr
}

func (n *fakeNode) Logout(context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.logouts++
	return n.logoutErr
}

func (n *fakeNode) Peers(context.Context) ([]tsnode.Peer, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.peers, n.peersErr
}

func (n *fakeNode) counts() (logins, logouts int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.logins, n.logouts
}

type fakeForwards struct {
	mu       sync.Mutex
	list     []httpapi.ForwardView
	toggles  []toggle
	setError error
}

type toggle struct {
	id      string
	enabled bool
}

func (f *fakeForwards) List() []httpapi.ForwardView {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]httpapi.ForwardView(nil), f.list...)
}

func (f *fakeForwards) SetEnabled(_ context.Context, id string, enabled bool) (httpapi.ForwardView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.toggles = append(f.toggles, toggle{id: id, enabled: enabled})
	if f.setError != nil {
		return httpapi.ForwardView{}, f.setError
	}
	for i := range f.list {
		if f.list[i].ID == id {
			f.list[i].Enabled = enabled
			return f.list[i], nil
		}
	}
	return httpapi.ForwardView{}, config.ErrNotFound
}

func (f *fakeForwards) recordedToggles() []toggle {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]toggle(nil), f.toggles...)
}

// The remaining Forwards methods are not reachable from the tray; they exist so the
// fake satisfies the interface.
func (f *fakeForwards) Get(string) (httpapi.ForwardView, error) {
	return httpapi.ForwardView{}, config.ErrNotFound
}

func (f *fakeForwards) Create(context.Context, httpapi.ForwardSpec) (httpapi.ForwardView, error) {
	return httpapi.ForwardView{}, errors.New("not used by the tray")
}

func (f *fakeForwards) Update(context.Context, string, httpapi.ForwardSpec) (httpapi.ForwardView, error) {
	return httpapi.ForwardView{}, errors.New("not used by the tray")
}

func (f *fakeForwards) Delete(context.Context, string) error {
	return errors.New("not used by the tray")
}

func (f *fakeForwards) SuggestPort(config.Protocol, string, int) (int, error) {
	return 0, errors.New("not used by the tray")
}

func (f *fakeForwards) AllRunning() bool { return false }

type fakeAutostart struct {
	mu       sync.Mutex
	enabled  bool
	problem  string
	readErr  error
	writeErr error
	writes   []bool
}

func (a *fakeAutostart) Enabled() (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.enabled, a.readErr
}

func (a *fakeAutostart) SetEnabled(enabled bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.writes = append(a.writes, enabled)
	if a.writeErr != nil {
		return a.writeErr
	}
	a.enabled = enabled
	return nil
}

func (a *fakeAutostart) Problem() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.problem
}

func (a *fakeAutostart) recordedWrites() []bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]bool(nil), a.writes...)
}

// fakeSettings stands in for the settings document the tray reads and writes. Its
// schema is hand-written rather than taken from the registry, so what is under test is
// the controller's routing rather than whichever settings carry Tray today.
type fakeSettings struct {
	mu      sync.Mutex
	view    map[string]any
	schema  []config.FieldSchema
	patches []map[string]json.RawMessage
	err     error
}

// traySchema is a settings document with one of each thing the tray has to tell apart:
// a checkbox written through the settings store, one written through the login-item
// manager, and one the menu must leave alone.
func traySchema() []config.FieldSchema {
	return []config.FieldSchema{
		{
			Key: "showTray", ViewKey: "showTray", Kind: config.KindBool,
			Write: config.WritePatch, Label: "Show the menu-bar icon", Tray: true,
		},
		{
			Key: "startAtLogin", ViewKey: "startAtLogin", Kind: config.KindBool,
			Write: config.WriteAutostart, Label: "Start at login", Tray: true,
		},
		{
			Key: "hostname", ViewKey: "hostname", Kind: config.KindString,
			Write: config.WritePatch, Label: "Device name",
		},
	}
}

func newFakeSettings(view map[string]any) *fakeSettings {
	return &fakeSettings{view: view, schema: traySchema()}
}

// egressSettings is a settings document whose schema carries the pair the internet picker
// is built from, with the connection list already resolved into the second of them -- which
// is the shape the served schema has and the shape the dashboard's own picker reads.
func egressSettings(connections ...config.EnumOption) *fakeSettings {
	return &fakeSettings{view: map[string]any{}, schema: []config.FieldSchema{
		{
			Key: "egress.mode", ViewKey: "egress.mode", Kind: config.KindEnum,
			Write: config.WritePatch, Label: "Where internet traffic goes",
			Options: []config.EnumOption{
				{
					Value: string(config.EgressDirect), Label: "Out of this machine",
					Help: "Anything your connections do not carry leaves the way it always has.",
				},
				{
					Value: string(config.EgressTunnel), Label: "Through one of your connections",
					Help: "Anything your connections do not carry goes out through the connection you choose.",
				},
			},
		},
		{
			Key: "egress.tunnelId", ViewKey: "egress.tunnelId", Kind: config.KindTunnelRef,
			Write: config.WritePatch, Label: "Connection carrying it", Options: connections,
		},
	}}
}

func (s *fakeSettings) Get() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot()
}

// snapshot copies the view for a caller that already holds the lock.
func (s *fakeSettings) snapshot() map[string]any {
	out := make(map[string]any, len(s.view))
	for k, v := range s.view {
		out[k] = v
	}
	return out
}

func (s *fakeSettings) Update(_ context.Context, patch map[string]json.RawMessage) (map[string]any, httpapi.SettingsUpdateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.patches = append(s.patches, patch)
	if s.err != nil {
		return nil, httpapi.SettingsUpdateResult{}, s.err
	}
	for key, raw := range patch {
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, httpapi.SettingsUpdateResult{}, err
		}
		s.view[key] = value
	}
	return s.snapshot(), httpapi.SettingsUpdateResult{}, nil
}

func (s *fakeSettings) Schema() []config.FieldSchema {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]config.FieldSchema(nil), s.schema...)
}

func (s *fakeSettings) setUnavailable(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unavailable := false
	for i := range s.schema {
		if s.schema[i].Key == key {
			s.schema[i].Available = &unavailable
		}
	}
}

func (s *fakeSettings) recordedPatches() []map[string]json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]json.RawMessage(nil), s.patches...)
}

// fakeExitNode stands in for the exit-node module the menu reads its line from.
type fakeExitNode struct {
	mu   sync.Mutex
	view httpapi.ExitNodeView
}

func (f *fakeExitNode) View() httpapi.ExitNodeView {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.view
}

func (f *fakeExitNode) Suggest(context.Context) (httpapi.ExitNodeSuggestion, error) {
	return httpapi.ExitNodeSuggestion{}, nil
}

// fakeDNS stands in for the resolver module. The tray reads only the machine half, so a
// test sets that and nothing else.
type fakeDNS struct {
	mu     sync.Mutex
	view   httpapi.DNSView
	setups int
	setErr error
}

func (f *fakeDNS) View(context.Context) httpapi.DNSView {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.view
}

func (f *fakeDNS) SetUpSystem(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setups++
	return f.setErr
}

func (f *fakeDNS) setupCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.setups
}

// fakeEgress stands in for the module reporting where the traffic none of the connections
// carries leaves through. It only reads, so the whole of it is the view it hands back.
type fakeEgress struct {
	mu   sync.Mutex
	view httpapi.EgressView
}

func (f *fakeEgress) View(context.Context) httpapi.EgressView {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.view
}

// fakeDNSProfiles is the resolver catalog. The tray only lists, so the writing half
// records what it was asked to do and refuses nothing.
type fakeDNSProfiles struct {
	mu   sync.Mutex
	list []config.DNSProfile
}

func (f *fakeDNSProfiles) List() []config.DNSProfile {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]config.DNSProfile(nil), f.list...)
}

func (f *fakeDNSProfiles) Create(p config.DNSProfile) (config.DNSProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list = append(f.list, p)
	return p, nil
}

func (f *fakeDNSProfiles) Update(id string, p config.DNSProfile) (config.DNSProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, existing := range f.list {
		if existing.ID == id {
			p.ID = id
			f.list[i] = p
			return p, nil
		}
	}
	return config.DNSProfile{}, errors.New("no such profile")
}

func (f *fakeDNSProfiles) Delete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, existing := range f.list {
		if existing.ID == id {
			f.list = append(f.list[:i], f.list[i+1:]...)
			return nil
		}
	}
	return errors.New("no such profile")
}

// fakeProxies stands in for the proxy instances.
//
// The menu reads the list and writes one field of one instance, so those two are real
// here. The rest of the API belongs to the dashboard and refuses instead of answering,
// which is what makes a menu that started calling one fail where a test can see it rather
// than quietly succeed against a value nobody stored.
type fakeProxies struct {
	mu        sync.Mutex
	list      []httpapi.ProxyInstanceView
	updates   []proxyUpdate
	updateErr error
}

// proxyUpdate is one Update call, kept whole so a test can assert which instance was
// written and what was asked of it.
type proxyUpdate struct {
	id    string
	patch map[string]json.RawMessage
}

func (f *fakeProxies) List() []httpapi.ProxyInstanceView {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]httpapi.ProxyInstanceView(nil), f.list...)
}

func (f *fakeProxies) Update(_ context.Context, id string, patch map[string]json.RawMessage) (httpapi.ProxyInstanceView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates = append(f.updates, proxyUpdate{id: id, patch: patch})
	if f.updateErr != nil {
		return httpapi.ProxyInstanceView{}, f.updateErr
	}
	for i, view := range f.list {
		if view.ID != id {
			continue
		}
		if raw, ok := patch["enabled"]; ok {
			var enabled bool
			if err := json.Unmarshal(raw, &enabled); err != nil {
				return httpapi.ProxyInstanceView{}, err
			}
			f.list[i].Enabled = enabled
		}
		return f.list[i], nil
	}
	return httpapi.ProxyInstanceView{}, errors.New("no such proxy")
}

func (f *fakeProxies) recordedUpdates() []proxyUpdate {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]proxyUpdate(nil), f.updates...)
}

// errNotFromTheMenu is what the half of the proxies API the menu never touches answers
// with. A silent zero value would let a wrong call look like a working one.
var errNotFromTheMenu = errors.New("the menu does not use this part of the proxies API")

func (f *fakeProxies) Get(string) (httpapi.ProxyInstanceView, error) {
	return httpapi.ProxyInstanceView{}, errNotFromTheMenu
}
func (f *fakeProxies) Schema() []config.FieldSchema { return nil }
func (f *fakeProxies) Create(context.Context, httpapi.ProxyInstanceSpec) (httpapi.ProxyInstanceView, error) {
	return httpapi.ProxyInstanceView{}, errNotFromTheMenu
}
func (f *fakeProxies) SetRules(context.Context, string, []access.Rule) (httpapi.ProxyInstanceView, error) {
	return httpapi.ProxyInstanceView{}, errNotFromTheMenu
}
func (f *fakeProxies) Delete(context.Context, string) error { return errNotFromTheMenu }
func (f *fakeProxies) Test(context.Context, string, httpapi.ProxyTestRequest) (httpapi.ProxyTestResult, error) {
	return httpapi.ProxyTestResult{}, errNotFromTheMenu
}

// fakeTunnels stands in for the private networks this machine is attached to.
type fakeTunnels struct {
	mu        sync.Mutex
	list      []httpapi.TunnelView
	updates   []tunnelUpdate
	updateErr error
}

// tunnelUpdate is one Update call, kept whole so a test can assert which connection was
// written and what was asked of it.
type tunnelUpdate struct {
	id    string
	patch map[string]json.RawMessage
}

func (f *fakeTunnels) List() []httpapi.TunnelView {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]httpapi.TunnelView(nil), f.list...)
}

func (f *fakeTunnels) Update(_ context.Context, id string, patch map[string]json.RawMessage) (httpapi.TunnelView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates = append(f.updates, tunnelUpdate{id: id, patch: patch})
	if f.updateErr != nil {
		return httpapi.TunnelView{}, f.updateErr
	}
	for i, view := range f.list {
		if view.ID != id {
			continue
		}
		if raw, ok := patch["enabled"]; ok {
			var enabled bool
			if err := json.Unmarshal(raw, &enabled); err != nil {
				return httpapi.TunnelView{}, err
			}
			f.list[i].Enabled = enabled
		}
		return f.list[i], nil
	}
	return httpapi.TunnelView{}, errors.New("no such connection")
}

func (f *fakeTunnels) recordedUpdates() []tunnelUpdate {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]tunnelUpdate(nil), f.updates...)
}

// errNotFromTheTray is what the half of the connections API the menu never touches answers
// with. A silent zero value would let a wrong call look like a working one.
var errNotFromTheTray = errors.New("the menu does not use this part of the connections API")

func (f *fakeTunnels) Get(string) (httpapi.TunnelView, error) {
	return httpapi.TunnelView{}, errNotFromTheTray
}
func (f *fakeTunnels) Schema() []config.FieldSchema         { return nil }
func (f *fakeTunnels) Types() []httpapi.TunnelTypeInfo      { return nil }
func (f *fakeTunnels) Delete(context.Context, string) error { return errNotFromTheTray }
func (f *fakeTunnels) Create(context.Context, httpapi.TunnelSpec) (httpapi.TunnelView, error) {
	return httpapi.TunnelView{}, errNotFromTheTray
}
func (f *fakeTunnels) Import(context.Context, string, string) (httpapi.TunnelView, error) {
	return httpapi.TunnelView{}, errNotFromTheTray
}
func (f *fakeTunnels) Retry(context.Context, string) (httpapi.TunnelView, error) {
	return httpapi.TunnelView{}, errNotFromTheTray
}
func (f *fakeTunnels) Peers(context.Context, string) ([]tsnode.Peer, error) {
	return nil, errNotFromTheTray
}

// fakeInterfaceSetup stands in for the machine. Every state the menu has to render --
// a helper that is missing, a mode already in force -- is reachable by setting a field,
// on a test machine that is in exactly one of them.
type fakeInterfaceSetup struct {
	mu       sync.Mutex
	view     httpapi.InterfaceView
	setups   int
	setupErr error
}

func (f *fakeInterfaceSetup) View(context.Context) httpapi.InterfaceView {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.view
}

func (f *fakeInterfaceSetup) SetUpInterface(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setups++
	return f.setupErr
}

func (f *fakeInterfaceSetup) setupCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.setups
}

// fakeApprovals stands in for the administrator prompt, which a suite must never raise.
type fakeApprovals struct {
	mu       sync.Mutex
	pending  *httpapi.ApprovalsView
	err      error
	approved int
}

func (f *fakeApprovals) Pending() *httpapi.ApprovalsView {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pending
}

func (f *fakeApprovals) Approve(context.Context) (httpapi.ApprovalsView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.approved++
	if f.err != nil {
		return httpapi.ApprovalsView{}, f.err
	}
	f.pending = nil
	return httpapi.ApprovalsView{Needs: []grants.PendingNeed{}}, nil
}

func (f *fakeApprovals) approveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.approved
}

// recorder captures the URLs the controller would have opened.
type recorder struct {
	mu   sync.Mutex
	urls []string
	err  error
}

func (r *recorder) open(url string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.urls = append(r.urls, url)
	return r.err
}

func (r *recorder) opened() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.urls...)
}

func newTestController(agent agentView, stop context.CancelFunc) (*trayController, *recorder) {
	rec := &recorder{}
	return &trayController{agent: agent, stop: stop, open: rec.open}, rec
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// The menu has to distinguish "on" from "actually working"; a forward that is
// enabled but failed is the case the user most needs to see.
func TestSnapshotReportsRunningSeparatelyFromEnabled(t *testing.T) {
	agent := &fakeAgent{
		node: &fakeNode{status: tsnode.Status{BackendState: tsnode.StateRunning, Hostname: "app-tail-laptop"}},
		forwards: &fakeForwards{list: []httpapi.ForwardView{
			{Forward: config.Forward{ID: "a", Enabled: true}, State: forward.StateRunning},
			{Forward: config.Forward{ID: "b", Enabled: true}, State: forward.StateError},
			{Forward: config.Forward{ID: "c", Enabled: false}},
		}},
		autostart: &fakeAutostart{enabled: true},
		settings:  newFakeSettings(map[string]any{"showTray": true}),
		iface:     &fakeInterfaceSetup{view: httpapi.InterfaceView{Ready: true}},
	}
	controller, _ := newTestController(agent, func() {})

	got := controller.Snapshot()
	want := tray.Snapshot{
		State:           tsnode.StateRunning,
		DeviceName:      "app-tail-laptop",
		ForwardsTotal:   3,
		ForwardsEnabled: 2,
		ForwardsRunning: 1,
		Settings: map[string]tray.SettingState{
			"showTray":     {Checked: true, Available: true},
			"startAtLogin": {Checked: true, Available: true},
		},
		NetworkInterface: tray.NetworkState{Available: true},
		// A running node lists itself: its own address is the one the devices submenu
		// is most often opened for, and nothing else in the menu carries it.
		Devices: []tray.Device{{Name: "app-tail-laptop", Online: true, Self: true}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Snapshot() = %+v\nwant %+v", got, want)
	}
}

// The menu is the registry's answer, not this file's: a setting with no Tray member
// must never reach it, however ordinary it looks in the schema.
func TestSnapshotReportsOnlyTheSettingsTheRegistryMarkedForTheTray(t *testing.T) {
	agent := &fakeAgent{
		forwards:  &fakeForwards{},
		autostart: &fakeAutostart{},
		settings:  newFakeSettings(map[string]any{"showTray": true, "hostname": "laptop"}),
	}
	controller, _ := newTestController(agent, func() {})

	if _, ok := controller.Snapshot().Settings["hostname"]; ok {
		t.Error("a setting the registry did not mark for the tray reached the menu")
	}
}

// Before the agent has built its node the tray still has to render something, not
// dereference a nil.
func TestSnapshotSurvivesAnAgentThatHasNotStartedYet(t *testing.T) {
	agent := &fakeAgent{forwards: &fakeForwards{}}
	controller, _ := newTestController(agent, func() {})

	got := controller.Snapshot()
	if got.State != "" || got.ForwardsTotal != 0 {
		t.Errorf("Snapshot() = %+v, want a zero snapshot", got)
	}
	if len(got.Settings) != 0 {
		t.Errorf("settings = %+v, want none with no settings store yet", got.Settings)
	}
}

// The menu answers "where is my traffic going", so the device the tailnet reports
// carrying it outranks the one app-tail asked for -- while a change is in flight
// those are two different devices, and naming the asked-for one would be a guess.
func TestTheMenuNamesTheDeviceTrafficIsActuallyLeavingThrough(t *testing.T) {
	cases := []struct {
		name string
		view httpapi.ExitNodeView
		want string
	}{
		{
			name: "the module is off",
			view: httpapi.ExitNodeView{Current: "nABC", CurrentLabel: "gateway", LiveID: "nABC", LiveOnline: true},
			want: "",
		},
		{
			name: "the device we asked for is the one carrying traffic",
			view: httpapi.ExitNodeView{Enabled: true, Current: "nABC", CurrentLabel: "gateway", LiveID: "nABC", LiveOnline: true},
			want: "gateway",
		},
		{
			name: "another device is carrying traffic and the tailnet offers its name",
			view: httpapi.ExitNodeView{
				Enabled: true, Current: "nABC", CurrentLabel: "gateway",
				LiveID: "nXYZ", LiveOnline: true,
				Candidates: []httpapi.ExitNodeCandidate{{ID: "nXYZ", Label: "berlin", Display: "berlin (Germany)"}},
			},
			want: "berlin (Germany)",
		},
		{
			name: "another device is carrying traffic and the tailnet no longer offers it",
			view: httpapi.ExitNodeView{Enabled: true, Current: "nABC", CurrentLabel: "gateway", LiveID: "nXYZ", LiveOnline: true},
			want: "nXYZ",
		},
		{
			name: "the device we asked for is not carrying traffic",
			view: httpapi.ExitNodeView{Enabled: true, Current: "nABC", CurrentLabel: "gateway"},
			want: "gateway (not carrying traffic)",
		},
		{
			name: "the device we asked for has no name yet",
			view: httpapi.ExitNodeView{Enabled: true, Current: "nABC"},
			want: "nABC (not carrying traffic)",
		},
		{
			name: "a device nobody asked for is installed and is down",
			view: httpapi.ExitNodeView{Enabled: true, LiveID: "nSTALE"},
			want: "nSTALE (offline; traffic is being dropped)",
		},
		{
			name: "the module is on but no device is chosen",
			view: httpapi.ExitNodeView{Enabled: true},
			want: "none chosen",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agent := &fakeAgent{forwards: &fakeForwards{}, exitNode: &fakeExitNode{view: tc.view}}
			controller, _ := newTestController(agent, func() {})

			if got := controller.Snapshot().ExitNode; got != tc.want {
				t.Errorf("ExitNode = %q, want %q", got, tc.want)
			}
		})
	}
}

// The tray starts painting before the agent has finished building its modules, and a
// menu that panicked on the way up is worse than one missing a line.
func TestTheMenuLeavesTheExitNodeLineOutBeforeTheModuleExists(t *testing.T) {
	agent := &fakeAgent{forwards: &fakeForwards{}}
	controller, _ := newTestController(agent, func() {})

	if got := controller.Snapshot().ExitNode; got != "" {
		t.Errorf("ExitNode = %q before the agent built the module, want no line at all", got)
	}
}

// A start-at-login setting that could not be read must not render as an unchecked
// box, which would tell the user it is off when nobody knows.
func TestSnapshotReportsAnUnreadableAutostartSettingInsteadOfGuessing(t *testing.T) {
	agent := &fakeAgent{
		forwards:  &fakeForwards{},
		autostart: &fakeAutostart{enabled: true, readErr: errors.New("permission denied")},
		settings:  newFakeSettings(map[string]any{"showTray": true}),
	}
	controller, _ := newTestController(agent, func() {})

	got := controller.Snapshot()
	if state, ok := got.Settings["startAtLogin"]; ok {
		t.Errorf("an unreadable setting was reported as %+v rather than left out", state)
	}
	if !strings.Contains(got.LastError, "permission denied") {
		t.Errorf("LastError = %q, want the underlying reason", got.LastError)
	}
	// The one setting that did read must still be shown; a single failure cannot take
	// the rest of the menu with it.
	if state := got.Settings["showTray"]; !state.Checked || !state.Available {
		t.Errorf("showTray = %+v, want checked and available", state)
	}
}

// A platform with no login item has nothing wrong with it. Reporting the absence as an
// error would put a permanent complaint on the menu of every machine that simply does not
// have the feature, which is how a user learns to ignore the error line entirely.
func TestSnapshotLeavesOutTheLoginItemQuietlyWhereThereIsNone(t *testing.T) {
	agent := &fakeAgent{
		forwards: &fakeForwards{},
		settings: newFakeSettings(map[string]any{"showTray": true}),
	}
	controller, _ := newTestController(agent, func() {})

	got := controller.Snapshot()

	if state, ok := got.Settings["startAtLogin"]; ok {
		t.Errorf("a login item this system has no manager for was offered as %+v", state)
	}
	if got.LastError != "" {
		t.Errorf("LastError = %q, want nothing: there is no failure in not having the feature", got.LastError)
	}
	if state := got.Settings["showTray"]; !state.Checked || !state.Available {
		t.Errorf("showTray = %+v, want the rest of the menu unaffected", state)
	}
}

// A view missing the boolean a checkbox renders would paint it unchecked, which reads
// as "off" rather than "unknown".
func TestSnapshotReportsASettingMissingFromTheViewInsteadOfShowingItOff(t *testing.T) {
	agent := &fakeAgent{
		forwards:  &fakeForwards{},
		autostart: &fakeAutostart{},
		settings:  newFakeSettings(map[string]any{}),
	}
	controller, _ := newTestController(agent, func() {})

	got := controller.Snapshot()
	if state, ok := got.Settings["showTray"]; ok {
		t.Errorf("a setting the view does not carry was reported as %+v", state)
	}
	if !strings.Contains(got.LastError, "showTray") {
		t.Errorf("LastError = %q, want it to name the missing setting", got.LastError)
	}
}

// A setting this configuration cannot currently change is hidden, not offered: the
// menu has no way to explain a refusal after the click.
func TestSnapshotLeavesOutASettingTheSchemaReportsUnavailable(t *testing.T) {
	settings := newFakeSettings(map[string]any{"showTray": true})
	settings.setUnavailable("showTray")
	agent := &fakeAgent{forwards: &fakeForwards{}, autostart: &fakeAutostart{}, settings: settings}
	controller, _ := newTestController(agent, func() {})

	if state, ok := controller.Snapshot().Settings["showTray"]; ok {
		t.Errorf("an unavailable setting was offered as %+v", state)
	}
}

func TestOpenDashboardRefusesBeforeTheAgentHasBound(t *testing.T) {
	agent := &fakeAgent{forwards: &fakeForwards{}}
	controller, rec := newTestController(agent, func() {})

	if err := controller.OpenDashboard(); err == nil {
		t.Fatal("OpenDashboard succeeded before the dashboard existed")
	}
	if len(rec.opened()) != 0 {
		t.Errorf("a browser was launched at %v with no dashboard bound", rec.opened())
	}

	agent.setDashboardURL("http://127.0.0.1:8377")
	if err := controller.OpenDashboard(); err != nil {
		t.Fatalf("OpenDashboard: %v", err)
	}
	if opened := rec.opened(); len(opened) != 1 || opened[0] != "http://127.0.0.1:8377/?launch=L1" {
		t.Errorf("opened %v, want a sign-in link to the dashboard", opened)
	}
}

// Toggling everything must skip the forwards already in the wanted state; asking
// the agent to re-enable a running forward would restart it for nothing.
func TestSetAllForwardsOnlyTouchesTheOnesThatNeedChanging(t *testing.T) {
	forwards := &fakeForwards{list: []httpapi.ForwardView{
		{Forward: config.Forward{ID: "a", Enabled: true}},
		{Forward: config.Forward{ID: "b", Enabled: false}},
		{Forward: config.Forward{ID: "c", Enabled: false}},
	}}
	agent := &fakeAgent{forwards: forwards}
	controller, _ := newTestController(agent, func() {})

	if err := controller.SetAllForwardsEnabled(true); err != nil {
		t.Fatalf("SetAllForwardsEnabled: %v", err)
	}
	got := forwards.recordedToggles()
	if len(got) != 2 {
		t.Fatalf("toggled %v, want only the two disabled forwards", got)
	}
	for _, tg := range got {
		if tg.id == "a" {
			t.Error("an already-enabled forward was toggled")
		}
		if !tg.enabled {
			t.Errorf("toggle %+v did not enable", tg)
		}
	}
}

// One forward failing to start must not hide the others' failures or be swallowed.
func TestSetAllForwardsReportsEveryFailure(t *testing.T) {
	forwards := &fakeForwards{
		list: []httpapi.ForwardView{
			{Forward: config.Forward{ID: "a", Name: "llm", Enabled: false}},
			{Forward: config.Forward{ID: "b", Name: "ssh", Enabled: false}},
		},
		setError: errors.New("address already in use"),
	}
	controller, _ := newTestController(&fakeAgent{forwards: forwards}, func() {})

	err := controller.SetAllForwardsEnabled(true)
	if err == nil {
		t.Fatal("SetAllForwardsEnabled reported success despite every forward failing")
	}
	for _, name := range []string{"llm", "ssh"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name the failing forward %q", err, name)
		}
	}
}

// Picking "Log in" should land the user on the page that finishes the login, not on
// a dashboard they then have to click through.
func TestLoginOpensTheAuthURLTheNodeProduces(t *testing.T) {
	node := &fakeNode{status: tsnode.Status{BackendState: tsnode.StateNeedsLogin}}
	agent := &fakeAgent{node: node, forwards: &fakeForwards{}, dashboardURL: "http://127.0.0.1:8377"}
	controller, rec := newTestController(agent, func() {})

	// StartLogin is what populates the URL, exactly as the real node does.
	node.setStatus(tsnode.Status{
		BackendState: tsnode.StateNeedsLogin,
		AuthURL:      "https://login.tailscale.com/a/abc123",
	})

	if err := controller.Login(); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if logins, _ := node.counts(); logins != 1 {
		t.Errorf("StartLogin called %d times, want 1", logins)
	}
	if opened := rec.opened(); len(opened) != 1 || opened[0] != "https://login.tailscale.com/a/abc123" {
		t.Errorf("opened %v, want the auth URL", opened)
	}
}

// A node with no auth URL is mid-transition or using a key; the dashboard is the
// only useful place to send the user.
func TestLoginFallsBackToTheDashboardWithNoAuthURL(t *testing.T) {
	node := &fakeNode{status: tsnode.Status{BackendState: tsnode.StateStarting}}
	agent := &fakeAgent{node: node, forwards: &fakeForwards{}, dashboardURL: "http://127.0.0.1:8377"}
	controller, rec := newTestController(agent, func() {})

	if err := controller.Login(); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if opened := rec.opened(); len(opened) != 1 || opened[0] != "http://127.0.0.1:8377/?launch=L1" {
		t.Errorf("opened %v, want a sign-in link to the dashboard", opened)
	}
}

// A login that the node itself refused must surface, not open a browser at a URL
// that was never produced.
func TestLoginReportsTheNodesRefusal(t *testing.T) {
	node := &fakeNode{loginErr: errors.New("this node authenticates with an auth key")}
	agent := &fakeAgent{node: node, forwards: &fakeForwards{}, dashboardURL: "http://127.0.0.1:8377"}
	controller, rec := newTestController(agent, func() {})

	err := controller.Login()
	if err == nil {
		t.Fatal("Login reported success after the node refused")
	}
	if !strings.Contains(err.Error(), "auth key") {
		t.Errorf("error = %q, want the node's explanation", err)
	}
	if len(rec.opened()) != 0 {
		t.Errorf("a browser was opened at %v despite the login failing", rec.opened())
	}
}

func TestLoginAndLogoutRefuseBeforeTheNodeExists(t *testing.T) {
	controller, _ := newTestController(&fakeAgent{forwards: &fakeForwards{}}, func() {})

	if err := controller.Login(); err == nil {
		t.Error("Login succeeded with no node")
	}
	if err := controller.Logout(); err == nil {
		t.Error("Logout succeeded with no node")
	}
}

func TestLogoutReachesTheNode(t *testing.T) {
	node := &fakeNode{status: tsnode.Status{BackendState: tsnode.StateRunning}}
	controller, _ := newTestController(&fakeAgent{node: node, forwards: &fakeForwards{}}, func() {})

	if err := controller.Logout(); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, logouts := node.counts(); logouts != 1 {
		t.Errorf("Logout called %d times, want 1", logouts)
	}
}

// The tray writes settings the same way the dashboard does, so a menu click inherits
// validation and module availability instead of reaching past them into the store.
func TestSetSettingWritesThroughTheSettingsAPI(t *testing.T) {
	settings := newFakeSettings(map[string]any{"showTray": true})
	agent := &fakeAgent{forwards: &fakeForwards{}, autostart: &fakeAutostart{}, settings: settings}
	controller, _ := newTestController(agent, func() {})

	if err := controller.SetSetting("showTray", false); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	patches := settings.recordedPatches()
	if len(patches) != 1 {
		t.Fatalf("patches = %v, want exactly one", patches)
	}
	// One click writes one setting: a patch carrying anything else would let the menu
	// silently revert a change made from the CLI or the dashboard.
	if len(patches[0]) != 1 || string(patches[0]["showTray"]) != "false" {
		t.Errorf("patch = %v, want only showTray set to false", patches[0])
	}
}

// A setting the login-item manager owns is not in the settings document at all, so
// the write has to be routed by the registry rather than sent to the store.
func TestSetSettingRoutesTheLoginItemToItsOwnManager(t *testing.T) {
	manager := &fakeAutostart{}
	settings := newFakeSettings(map[string]any{"showTray": true})
	agent := &fakeAgent{forwards: &fakeForwards{}, autostart: manager, settings: settings}
	controller, _ := newTestController(agent, func() {})

	if err := controller.SetSetting("startAtLogin", true); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if got := manager.recordedWrites(); len(got) != 1 || !got[0] {
		t.Errorf("login-item writes = %v, want [true]", got)
	}
	if got := settings.recordedPatches(); len(got) != 0 {
		t.Errorf("the settings store was patched with %v for a login-item setting", got)
	}
}

// On Windows the network mode decides which login item is installed, not merely how one
// behaves, so a manager built without the stored mode reports on one form and removes the
// other. The projection is one line and its failure is invisible until the next login.
//
// The resolver rows are here for the same reason: it is the second feature that needs
// administrator rights, and a machine that only switched its resolver would otherwise get
// the Run value, come up contained at the next login, and be unable to put back the
// override it left on the machine.
func TestTheLoginItemIsBuiltForTheStoredNetworkMode(t *testing.T) {
	cases := []struct {
		name     string
		settings config.Settings
		want     bool
	}{
		{"the mode this app installs as", config.Settings{InterfaceMode: config.NetworkUserspace}, false},
		{"the module on, still contained", config.Settings{InterfaceEnabled: true, InterfaceMode: config.NetworkUserspace}, false},
		{"the interface mode", config.Settings{InterfaceEnabled: true, InterfaceMode: config.NetworkTUN}, true},
		{
			"the resolver switched, no interface",
			config.Settings{InterfaceMode: config.NetworkUserspace, SystemDNSEnabled: true, SystemDNSProfile: "cloudflare"},
			true,
		},
		{
			"the resolver module on, still the system default",
			config.Settings{InterfaceMode: config.NetworkUserspace, SystemDNSEnabled: true, SystemDNSProfile: dnsprofiles.SystemID},
			false,
		},
		{
			"a resolver profile chosen with the module off",
			config.Settings{InterfaceMode: config.NetworkUserspace, SystemDNSProfile: "cloudflare"},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

			item := loginItem(config.Runtime{Settings: tc.settings}, logger)

			manager, ok := item.(*autostart.Manager)
			if !ok {
				t.Fatalf("loginItem returned %T, which cannot carry the network mode", item)
			}
			if manager.Elevated != tc.want {
				t.Errorf("login item built with Elevated = %t, want %t", manager.Elevated, tc.want)
			}
		})
	}
}

// A login item installed for the other network mode has no symptom until the next login,
// where it appears as a consent prompt nobody can connect to a setting changed weeks
// earlier. Correcting it is worth doing on every start and is worth doing quietly -- but
// never at the cost of the agent starting, which is why every failure below is a log line
// rather than a return.
func TestALoginItemInstalledForTheOtherModeIsCorrectedOnTheNextStart(t *testing.T) {
	t.Run("a login item that matches the mode is left alone", func(t *testing.T) {
		item := &fakeLoginItem{}
		var log bytes.Buffer

		correctLoginItem(item, slog.New(slog.NewTextHandler(&log, nil)))

		if item.writes != 0 {
			t.Errorf("the login item was re-installed %d times for a mode it already matched", item.writes)
		}
	})

	t.Run("one that does not is re-installed", func(t *testing.T) {
		item := &fakeLoginItem{stale: true}
		var log bytes.Buffer

		correctLoginItem(item, slog.New(slog.NewTextHandler(&log, nil)))

		if item.writes != 1 {
			t.Errorf("the login item was re-installed %d times, want once", item.writes)
		}
		if !strings.Contains(log.String(), "re-installed") {
			t.Errorf("the correction was silent; the log says:\n%s", log.String())
		}
	})

	t.Run("a re-install that fails names the command that would fix it", func(t *testing.T) {
		item := &fakeLoginItem{stale: true, writeErr: errors.New("access is denied")}
		var log bytes.Buffer

		correctLoginItem(item, slog.New(slog.NewTextHandler(&log, nil)))

		text := log.String()
		if !strings.Contains(text, "access is denied") {
			t.Errorf("the failure did not carry the reason:\n%s", text)
		}
		if !strings.Contains(text, "app-tail install-autostart") {
			t.Errorf("the failure did not name the command that corrects it:\n%s", text)
		}
	})

	t.Run("a correction is refused, loudly, from a build directory", func(t *testing.T) {
		// Re-installing records the running binary's path. From `go run` output or a
		// build directory that trades a login item broken now for one broken at the next
		// reboot, and the log would call it fixed.
		item := &fakeLoginItem{stale: true, temporary: "the login item points at /var/folders/x, which is a temporary build location"}
		var log bytes.Buffer

		correctLoginItem(item, slog.New(slog.NewTextHandler(&log, nil)))

		if item.writes != 0 {
			t.Errorf("the login item was rewritten %d times from a build directory", item.writes)
		}
		text := log.String()
		if !strings.Contains(text, "temporary build location") {
			t.Errorf("the refusal did not say why it could not correct the item:\n%s", text)
		}
		if !strings.Contains(text, "app-tail install-autostart") {
			t.Errorf("the refusal did not name what would correct it:\n%s", text)
		}
		if strings.Contains(text, "re-installed") {
			t.Errorf("the log claims the item was corrected when it was not:\n%s", text)
		}
	})

	t.Run("a login item that cannot be inspected is reported rather than replaced", func(t *testing.T) {
		// Stale is reported alongside the error deliberately: an answer that came with a
		// failure is not an answer, and acting on it replaces a working login item on the
		// strength of a value the caller could not read.
		item := &fakeLoginItem{stale: true, checkErr: errors.New("the registry is unreadable")}
		var log bytes.Buffer

		correctLoginItem(item, slog.New(slog.NewTextHandler(&log, nil)))

		// Installing over something that could not be read would be a guess, and the
		// guess replaces a working login item with one for the wrong mode.
		if item.writes != 0 {
			t.Errorf("the login item was replaced %d times without knowing what was there", item.writes)
		}
		if !strings.Contains(log.String(), "the registry is unreadable") {
			t.Errorf("the failure was swallowed; the log says:\n%s", log.String())
		}
	})
}

// fakeLoginItem stands in for the platform's login item. The state it models -- an
// installed item that starts app-tail with the wrong rights -- exists on Windows alone,
// so a real manager anywhere else can never reach these branches.
type fakeLoginItem struct {
	stale    bool
	checkErr error
	writeErr error
	writes   int
	// temporary is the warning a manager gives when the running binary sits somewhere a
	// login item cannot rely on. Empty is the ordinary installed case.
	temporary string
}

func (f *fakeLoginItem) NeedsReinstall() (bool, error) { return f.stale, f.checkErr }

func (f *fakeLoginItem) SetEnabled(bool) error {
	f.writes++
	return f.writeErr
}

func (f *fakeLoginItem) TemporaryPathWarning() string { return f.temporary }
func (f *fakeLoginItem) Kind() string                 { return "test login item" }
func (f *fakeLoginItem) Path() string                 { return "/nowhere/app-tail" }

// Every refusal names what could not be done. A menu click has no other channel, so a
// silent no-op here reads as a broken app.
func TestSetSettingRefusesWhatItCannotWrite(t *testing.T) {
	t.Run("a setting that does not exist", func(t *testing.T) {
		settings := newFakeSettings(map[string]any{})
		agent := &fakeAgent{forwards: &fakeForwards{}, autostart: &fakeAutostart{}, settings: settings}
		controller, _ := newTestController(agent, func() {})

		err := controller.SetSetting("noSuchSetting", true)
		if err == nil || !strings.Contains(err.Error(), "noSuchSetting") {
			t.Errorf("error = %v, want a refusal naming the setting", err)
		}
		if got := settings.recordedPatches(); len(got) != 0 {
			t.Errorf("an unknown setting reached the store as %v", got)
		}
	})

	t.Run("a setting the menu does not offer", func(t *testing.T) {
		settings := newFakeSettings(map[string]any{})
		agent := &fakeAgent{forwards: &fakeForwards{}, autostart: &fakeAutostart{}, settings: settings}
		controller, _ := newTestController(agent, func() {})

		// A real registry key, so this is the boundary being checked and not the
		// unknown-setting refusal above. A click carries a checkbox, and a setting the
		// menu never offered is one nothing established could be written as a boolean.
		err := controller.SetSetting("uiListenAddr", true)
		if err == nil || !strings.Contains(err.Error(), "uiListenAddr") {
			t.Errorf("error = %v, want a refusal naming the setting", err)
		}
		if got := settings.recordedPatches(); len(got) != 0 {
			t.Errorf("a setting the menu does not offer reached the store as %v", got)
		}
	})

	t.Run("the login item on a system without one", func(t *testing.T) {
		agent := &fakeAgent{forwards: &fakeForwards{}, settings: newFakeSettings(map[string]any{})}
		controller, _ := newTestController(agent, func() {})

		if err := controller.SetSetting("startAtLogin", true); err == nil {
			t.Error("SetSetting succeeded with no login-item manager")
		}
	})

	t.Run("before the settings store is ready", func(t *testing.T) {
		controller, _ := newTestController(&fakeAgent{forwards: &fakeForwards{}}, func() {})

		if err := controller.SetSetting("showTray", true); err == nil {
			t.Error("SetSetting succeeded before the settings store existed")
		}
	})

	t.Run("a write the store itself rejects", func(t *testing.T) {
		settings := newFakeSettings(map[string]any{"showTray": true})
		settings.err = errors.New("showTray: the settings file is read-only")
		agent := &fakeAgent{forwards: &fakeForwards{}, autostart: &fakeAutostart{}, settings: settings}
		controller, _ := newTestController(agent, func() {})

		err := controller.SetSetting("showTray", false)
		if err == nil || !strings.Contains(err.Error(), "read-only") {
			t.Errorf("error = %v, want the store's own refusal", err)
		}
	})
}

// The "Settings..." entry has to land on the form itself. Dropping the marker would
// leave the user on the dashboard with the settings still one click away, which is the
// whole thing the entry exists to save them.
func TestOpenSettingsLandsOnTheSettingsForm(t *testing.T) {
	agent := &fakeAgent{forwards: &fakeForwards{}}
	controller, rec := newTestController(agent, func() {})

	if err := controller.OpenSettings(); err == nil {
		t.Fatal("OpenSettings succeeded before the dashboard existed")
	}
	if len(rec.opened()) != 0 {
		t.Errorf("a browser was launched at %v with no dashboard bound", rec.opened())
	}

	agent.setDashboardURL("http://127.0.0.1:8377")
	if err := controller.OpenSettings(); err != nil {
		t.Fatalf("OpenSettings: %v", err)
	}
	want := "http://127.0.0.1:8377/?launch=L1&settings=1"
	if opened := rec.opened(); len(opened) != 1 || opened[0] != want {
		t.Errorf("opened %v, want [%s]", opened, want)
	}
}

// A menu cannot take a profile name and four server addresses, so the "Resolver
// profiles..." entry hands over to the one surface that can. Landing on the dashboard's
// top instead leaves the DNS cards below the fold with nothing saying where they are.
func TestOpenDNSProfilesLandsOnTheDNSCards(t *testing.T) {
	agent := &fakeAgent{forwards: &fakeForwards{}}
	controller, rec := newTestController(agent, func() {})

	if err := controller.OpenDNSProfiles(); err == nil {
		t.Fatal("OpenDNSProfiles succeeded before the dashboard existed")
	}
	if len(rec.opened()) != 0 {
		t.Errorf("a browser was launched at %v with no dashboard bound", rec.opened())
	}

	agent.setDashboardURL("http://127.0.0.1:8377")
	if err := controller.OpenDNSProfiles(); err != nil {
		t.Fatalf("OpenDNSProfiles: %v", err)
	}
	want := "http://127.0.0.1:8377/?launch=L1&section=dns"
	if opened := rec.opened(); len(opened) != 1 || opened[0] != want {
		t.Errorf("opened %v, want [%s]", opened, want)
	}
}

func TestQuitStopsTheAgent(t *testing.T) {
	stopped := false
	controller, _ := newTestController(&fakeAgent{forwards: &fakeForwards{}}, func() { stopped = true })

	controller.Shutdown()
	if !stopped {
		t.Fatal("Quit did not cancel the agent's context")
	}
}

// blockingTray stands in for the native event loop: it shows nothing and runs until its
// context ends, which is exactly what systray does on a desktop with nobody at it.
func blockingTray(ctx context.Context, _ tray.Options) error {
	<-ctx.Done()
	return nil
}

// A second copy of app-tail asking this one to quit, or the dashboard asking for a
// restart, ends the agent from the inside; the process has to end with it. Left to itself
// the native loop runs until the user picks Quit, so an agent that stopped on its own would
// leave an icon behind with nothing under it -- and the restart would never start, because
// it is started by the same main that is parked in the loop.
func TestTheProcessEndsWhenTheAgentStopsOnItsOwn(t *testing.T) {
	agent := &fakeAgent{forwards: &fakeForwards{}}
	stopped := errors.New("asked to quit")
	run := func(ctx context.Context) error {
		time.Sleep(20 * time.Millisecond)
		return stopped
	}

	done := make(chan error, 1)
	go func() {
		done <- runBesideTray(context.Background(), run, blockingTray, agent, discardLogger(), dashboardOpener{})
	}()

	select {
	case err := <-done:
		if !errors.Is(err, stopped) {
			t.Errorf("runBesideTray = %v, want the agent's own result %v", err, stopped)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the tray kept the process alive after the agent stopped")
	}
}

// The other direction: the user picking Quit in the menu, or the OS ending the loop, has to
// stop an agent that would otherwise run on.
func TestTheAgentStopsWhenTheTrayEnds(t *testing.T) {
	agent := &fakeAgent{forwards: &fakeForwards{}}
	run := func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	quitFromTheMenu := func(ctx context.Context, opts tray.Options) error {
		opts.Controller.Shutdown()
		return nil
	}

	done := make(chan error, 1)
	go func() {
		done <- runBesideTray(context.Background(), run, quitFromTheMenu, agent, discardLogger(), dashboardOpener{})
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("runBesideTray = %v, want the agent to have been cancelled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the agent kept running after the tray ended")
	}
}

// The whole point of the first-run watcher is that a user with no config lands on
// the dashboard without being told to open a URL.
func TestTheDashboardOpensOnAFirstRun(t *testing.T) {
	agent := &fakeAgent{
		node:         &fakeNode{status: tsnode.Status{BackendState: tsnode.StateStarting}},
		forwards:     &fakeForwards{},
		dashboardURL: "http://127.0.0.1:8377",
	}
	rec := &recorder{}
	opener := dashboardOpener{
		agent: agent, open: rec.open, logger: discardLogger(),
		firstRun: true, window: 2 * time.Second, interval: time.Millisecond,
	}
	opener.run(context.Background())

	if opened := rec.opened(); len(opened) != 1 || opened[0] != "http://127.0.0.1:8377/?launch=L1" {
		t.Errorf("opened %v, want a sign-in link to the dashboard exactly once", opened)
	}
}

// The link the watcher opens carries a sign-in token, and a log is read by more people than
// the browser is, so the log names the bare address.
func TestTheAutomaticOpenLogsTheAddressButNotTheSignInLink(t *testing.T) {
	agent := &fakeAgent{
		node:         &fakeNode{status: tsnode.Status{BackendState: tsnode.StateStarting}},
		forwards:     &fakeForwards{},
		dashboardURL: "http://127.0.0.1:8377",
	}
	var logs bytes.Buffer
	rec := &recorder{}
	opener := dashboardOpener{
		agent: agent, open: rec.open, logger: slog.New(slog.NewTextHandler(&logs, nil)),
		firstRun: true, window: 2 * time.Second, interval: time.Millisecond,
	}
	opener.run(context.Background())

	if opened := rec.opened(); len(opened) != 1 || !strings.Contains(opened[0], "launch=") {
		t.Fatalf("opened %v, want one sign-in link", opened)
	}
	if !strings.Contains(logs.String(), "http://127.0.0.1:8377") {
		t.Errorf("the log does not name the dashboard address: %q", logs.String())
	}
	if strings.Contains(logs.String(), "launch=") {
		t.Errorf("the log carries the sign-in link: %q", logs.String())
	}
}

// On a later run the dashboard is an interruption unless a login is actually needed.
func TestTheDashboardOpensOnlyForALoginOnLaterRuns(t *testing.T) {
	agent := &fakeAgent{
		node:         &fakeNode{status: tsnode.Status{BackendState: tsnode.StateRunning}},
		forwards:     &fakeForwards{},
		dashboardURL: "http://127.0.0.1:8377",
	}
	rec := &recorder{}
	opener := dashboardOpener{
		agent: agent, open: rec.open, logger: discardLogger(),
		firstRun: false, window: 60 * time.Millisecond, interval: time.Millisecond,
	}
	opener.run(context.Background())

	if opened := rec.opened(); len(opened) != 0 {
		t.Fatalf("opened %v for a node that connected on its own", opened)
	}

	// The same watcher must fire once the node does ask for a login.
	agent.node.setStatus(tsnode.Status{BackendState: tsnode.StateNeedsLogin})
	opener.window = 2 * time.Second
	opener.run(context.Background())

	if opened := rec.opened(); len(opened) != 1 {
		t.Errorf("opened %v, want one open once a login was needed", opened)
	}
}

// Before the agent binds there is no URL to open, and the watcher must wait rather
// than launch a browser at an empty address.
func TestTheDashboardWatcherWaitsForTheAgentToBind(t *testing.T) {
	agent := &fakeAgent{forwards: &fakeForwards{}}
	rec := &recorder{}
	opener := dashboardOpener{
		agent: agent, open: rec.open, logger: discardLogger(),
		firstRun: true, window: 2 * time.Second, interval: time.Millisecond,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		opener.run(context.Background())
	}()

	time.Sleep(20 * time.Millisecond)
	if opened := rec.opened(); len(opened) != 0 {
		t.Errorf("opened %v before the agent had bound anything", opened)
	}

	agent.setNode(&fakeNode{status: tsnode.Status{BackendState: tsnode.StateStarting}})
	agent.setDashboardURL("http://127.0.0.1:9999")

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the watcher never opened the dashboard after the agent bound")
	}
	if opened := rec.opened(); len(opened) != 1 || opened[0] != "http://127.0.0.1:9999/?launch=L1" {
		t.Errorf("opened %v, want the bound dashboard URL", opened)
	}
}

// A tray that could not start leaves nothing on screen naming this process: no icon, no
// window, and an address nobody has been told. The dashboard is the only surface left, so
// it opens whatever the node is doing -- a connected node is exactly the case where the
// ordinary watcher would decide there was nothing worth showing.
func TestTheDashboardOpensWhenThereIsNoTrayIcon(t *testing.T) {
	agent := &fakeAgent{
		node:         &fakeNode{status: tsnode.Status{BackendState: tsnode.StateRunning}},
		forwards:     &fakeForwards{},
		dashboardURL: "http://127.0.0.1:8377",
	}
	rec := &recorder{}
	opener := dashboardOpener{
		agent: agent, open: rec.open, logger: discardLogger(),
		noFrontEnd: true, window: 2 * time.Second, interval: time.Millisecond,
	}
	opener.run(context.Background())

	if opened := rec.opened(); len(opened) != 1 || opened[0] != "http://127.0.0.1:8377/?launch=L1" {
		t.Errorf("opened %v, want a sign-in link to the dashboard exactly once", opened)
	}
}

// A first run that also loses its tray icon has two reasons to show the dashboard and one
// dashboard to show, so the user gets one tab rather than two.
func TestTwoReasonsToShowTheDashboardOpenOneTab(t *testing.T) {
	agent := &fakeAgent{
		node:         &fakeNode{status: tsnode.Status{BackendState: tsnode.StateRunning}},
		forwards:     &fakeForwards{},
		dashboardURL: "http://127.0.0.1:8377",
	}
	rec := &recorder{}
	opened := new(atomic.Bool)
	first := dashboardOpener{
		agent: agent, open: rec.open, logger: discardLogger(),
		firstRun: true, opened: opened, window: 2 * time.Second, interval: time.Millisecond,
	}
	noIcon := dashboardOpener{
		agent: agent, open: rec.open, logger: discardLogger(),
		noFrontEnd: true, opened: opened, window: 2 * time.Second, interval: time.Millisecond,
	}

	first.run(context.Background())
	noIcon.run(context.Background())

	if got := rec.opened(); len(got) != 1 {
		t.Errorf("opened %v, want one tab for the one dashboard", got)
	}
}

func TestTheDashboardWatcherStopsWithTheAgent(t *testing.T) {
	agent := &fakeAgent{forwards: &fakeForwards{}}
	opener := dashboardOpener{
		agent: agent, open: (&recorder{}).open, logger: discardLogger(),
		firstRun: true, window: time.Hour, interval: time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		opener.run(ctx)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the watcher outlived the agent's context")
	}
}

func TestModeSelectionExplainsItself(t *testing.T) {
	// Windows hands its notification area to every session, so no environment takes the
	// display away there the way the one set below takes it away everywhere else.
	displayAlwaysPresent := runtime.GOOS == "windows"

	cases := []struct {
		name       string
		runtime    config.Runtime
		wantTray   bool
		wantReason string
	}{
		{
			name:       "headless flag",
			runtime:    config.Runtime{Headless: true, Settings: config.Settings{ShowTray: true}},
			wantReason: "--headless was requested",
		},
		{
			name:       "tray disabled in config",
			runtime:    config.Runtime{Settings: config.Settings{ShowTray: false}},
			wantReason: "showTray is off in the config",
		},
		{
			name:       "no display",
			runtime:    config.Runtime{Settings: config.Settings{ShowTray: true}},
			wantTray:   displayAlwaysPresent,
			wantReason: "this session has no display",
		},
	}
	// Forcing the process to look like an SSH session is what makes the third case
	// deterministic on a developer's desktop.
	t.Setenv("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 22")
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := showTray(tc.runtime); got != tc.wantTray {
				t.Errorf("showTray = %v, want %v", got, tc.wantTray)
			}
			if got := headlessReason(tc.runtime); got != tc.wantReason {
				t.Errorf("headlessReason = %q, want %q", got, tc.wantReason)
			}
		})
	}
}

// A headless run is read by log collectors, so its output has to be JSON. A desktop
// run is read by a person.
func TestHeadlessRunsLogJSONAndDesktopRunsLogText(t *testing.T) {
	var headless bytes.Buffer
	newLogger(config.Runtime{Headless: true}, &headless).Info("agent started", "ui", "127.0.0.1:8377")

	var decoded map[string]any
	if err := json.Unmarshal(headless.Bytes(), &decoded); err != nil {
		t.Fatalf("headless output is not JSON: %v\n%s", err, headless.String())
	}
	if decoded["msg"] != "agent started" {
		t.Errorf("decoded msg = %v", decoded["msg"])
	}

	var desktop bytes.Buffer
	newLogger(config.Runtime{}, &desktop).Info("agent started")
	if json.Valid(desktop.Bytes()) {
		t.Errorf("a desktop run emitted JSON, which is harder to read at a terminal:\n%s", desktop.String())
	}
	if !strings.Contains(desktop.String(), "agent started") {
		t.Errorf("desktop output lost the message:\n%s", desktop.String())
	}
}

func TestVerboseTurnsOnDebugLogging(t *testing.T) {
	var quiet, loud bytes.Buffer
	newLogger(config.Runtime{}, &quiet).Debug("tailscale internals")
	newLogger(config.Runtime{Verbose: true}, &loud).Debug("tailscale internals")

	if quiet.Len() != 0 {
		t.Errorf("debug output appeared without --verbose:\n%s", quiet.String())
	}
	if !strings.Contains(loud.String(), "tailscale internals") {
		t.Errorf("--verbose did not enable debug logging:\n%s", loud.String())
	}
}

// noClaim stands in for the single-instance claim in tests that only exercise how a run is
// dispatched. Taking a real one would stop whatever app-tail is running on the machine the
// test is running on.
type noClaim struct{}

func (noClaim) Take(context.Context, config.Flags) error { return nil }
func (noClaim) Release() error                           { return nil }

// The claim covers the state directory this run was pointed at, not some fixed place: a run
// given its own directory is its own agent and must not displace one running elsewhere. Every
// case here uses a directory of its own for that reason -- a test that took the real claim
// would stop the app-tail running on this machine.
func TestTheClaimCoversTheStateDirectoryTheRunWasPointedAt(t *testing.T) {
	stateDir := t.TempDir()
	claim := &singleInstance{getenv: func(string) string { return "" }, logf: func(string, ...any) {}}

	if err := claim.Take(context.Background(), config.Flags{StateDir: &stateDir}); err != nil {
		t.Fatalf("Take: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, instance.FileName)); err != nil {
		t.Errorf("the claim is not on the state directory the run named: %v", err)
	}
	if err := claim.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// What a restart does: the copy that replaces this one takes the claim back without
	// having to stop anything, because the one it replaces gave it up first. It is a
	// different process, so a different claim: one that remembered its own lock would
	// pass here without ever having let go of the file.
	next := &singleInstance{getenv: func(string) string { return "" }, logf: func(string, ...any) {}}
	if err := next.Take(context.Background(), config.Flags{StateDir: &stateDir}); err != nil {
		t.Fatalf("Take after a release: %v", err)
	}
	if err := next.Release(); err != nil {
		t.Errorf("second Release: %v", err)
	}
}

// Release runs on the way out of a run that never got as far as taking a claim -- an
// elevation that handed off, a start that failed first -- so it cannot depend on one.
func TestGivingUpAClaimThatWasNeverTakenIsHarmless(t *testing.T) {
	claim := &singleInstance{getenv: func(string) string { return "" }, logf: func(string, ...any) {}}

	if err := claim.Release(); err != nil {
		t.Errorf("Release before any claim was taken: %v", err)
	}
}

// A typo must exit 2 and a real failure 1, so a wrapper script can tell them apart.
func TestExitCodesDistinguishMisuseFromFailure(t *testing.T) {
	cases := []struct {
		name string
		args []string
		env  cli.Env
		want int
	}{
		{"success", []string{"version"}, cli.Env{Version: "test"}, exitOK},
		{"unknown command", []string{"frobnicate"}, cli.Env{}, exitUsage},
		// Asking for help is what the usage text tells people to do, so it succeeds.
		{"top-level help flag", []string{"--help"}, cli.Env{}, exitOK},
		{"subcommand help flag", []string{"add", "--help"}, cli.Env{}, exitOK},
		{"unknown flag", []string{"add", "--nope"}, cli.Env{}, exitUsage},
		{
			name: "agent failure",
			args: []string{"run"},
			env: cli.Env{Claim: noClaim{}, RunAgent: func(context.Context, config.Flags) error {
				return errors.New("the dashboard port is in use")
			}},
			want: exitFailure,
		},
		{
			name: "interrupted",
			args: []string{"run"},
			env: cli.Env{Claim: noClaim{}, RunAgent: func(context.Context, config.Flags) error {
				return context.Canceled
			}},
			want: exitOK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			env := tc.env
			env.Stdout = &out
			env.Stderr = &errOut

			if got := run(context.Background(), tc.args, env); got != tc.want {
				t.Errorf("exit code = %d, want %d (stderr: %s)", got, tc.want, errOut.String())
			}
		})
	}
}

// A command run through `app-tail exec` chose its own exit status, and a shell script
// branching on it has to see that number rather than app-tail's own 1. Nothing may be
// written either: a line of ours on stderr is output the invoked command did not produce,
// which is what breaks a caller parsing it.
func TestAChildCommandsExitStatusIsPassedThroughUntouched(t *testing.T) {
	var out, errOut bytes.Buffer
	env := cli.Env{
		Stdout: &out,
		Stderr: &errOut,
		Claim:  noClaim{},
		RunAgent: func(context.Context, config.Flags) error {
			return &cli.ExitError{Code: 42}
		},
	}

	// An empty state directory and no elevation: on Windows the run command otherwise reads
	// this machine's own config, and a developer's copy with the interface mode on makes it
	// explain on stderr why it is not asking for rights.
	if got := run(context.Background(), []string{"run", "--state-dir", t.TempDir(), "--no-elevate"}, env); got != 42 {
		t.Errorf("exit code = %d, want the child's own 42", got)
	}
	if errOut.Len() != 0 {
		t.Errorf("app-tail wrote %q for a status it only passed on", errOut.String())
	}
}

// A missing config means a first run; anything else must not, or the browser would
// open on every start.
func TestFirstRunDetectionOnlyFiresForAMissingConfig(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "config.json")

	if fileExists(missing) {
		t.Error("a path that was never written reported as existing")
	}
	if err := os.WriteFile(missing, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !fileExists(missing) {
		t.Error("an existing config reported as missing, which would reopen the browser every start")
	}
}

// The URL alone is not enough: the listener binds before the node is built, so a
// watcher that only waited for an address would open a dashboard whose status panel
// has nothing to show, on a first run where that panel is the entire point.
func TestTheDashboardWatcherWaitsForTheNodeAndNotJustTheAddress(t *testing.T) {
	agent := &fakeAgent{forwards: &fakeForwards{}, dashboardURL: "http://127.0.0.1:9999"}
	rec := &recorder{}
	opener := dashboardOpener{
		agent: agent, open: rec.open, logger: discardLogger(),
		firstRun: true, window: 60 * time.Millisecond, interval: time.Millisecond,
	}

	opener.run(context.Background())

	if opened := rec.opened(); len(opened) != 0 {
		t.Fatalf("opened %v with an address but no node yet", opened)
	}

	// With the node present the same watcher fires, so the wait above is a wait and
	// not a permanent refusal.
	agent.setNode(&fakeNode{status: tsnode.Status{BackendState: tsnode.StateStarting}})
	opener.window = 2 * time.Second
	opener.run(context.Background())

	if opened := rec.opened(); len(opened) != 1 {
		t.Errorf("opened %v once the node existed, want exactly one", opened)
	}
}

// A machine with no browser -- a headless desktop session, a locked-down container --
// must not leave the watcher retrying for its whole window. The failure is logged and
// the watcher gives up, because a second attempt would fail identically.
func TestABrowserThatWillNotLaunchStopsTheWatcherRatherThanRetrying(t *testing.T) {
	agent := &fakeAgent{
		node:         &fakeNode{status: tsnode.Status{BackendState: tsnode.StateStarting}},
		forwards:     &fakeForwards{},
		dashboardURL: "http://127.0.0.1:8377",
	}
	rec := &recorder{err: errors.New("exec: \"xdg-open\": executable file not found in $PATH")}
	opener := dashboardOpener{
		agent: agent, open: rec.open, logger: discardLogger(),
		firstRun: true, window: 5 * time.Second, interval: time.Millisecond,
	}

	started := time.Now()
	opener.run(context.Background())

	if elapsed := time.Since(started); elapsed >= opener.window {
		t.Errorf("the watcher ran for %s; it retried a launcher that cannot succeed "+
			"instead of giving up", elapsed)
	}
	if opened := rec.opened(); len(opened) != 1 {
		t.Errorf("attempted %d opens, want exactly one", len(opened))
	}
}

// The tray is where a user sees that something is wrong without opening anything. A
// control-plane complaint the node recorded has to reach the menu, or the only symptom
// is forwards that never start and no explanation anywhere.
func TestANodeProblemBecomesTheTraysLastError(t *testing.T) {
	const problem = "tag:app-tail is not defined in the tailnet policy file"
	agent := &fakeAgent{
		node: &fakeNode{status: tsnode.Status{
			BackendState: tsnode.StateNeedsLogin,
			Hostname:     "workstation",
			Problem:      problem,
		}},
		forwards: &fakeForwards{},
	}
	controller, _ := newTestController(agent, func() {})

	snapshot := controller.Snapshot()

	if snapshot.LastError != problem {
		t.Errorf("LastError = %q, want the node's own problem", snapshot.LastError)
	}
	if snapshot.State != tsnode.StateNeedsLogin {
		t.Errorf("State = %q, want %q", snapshot.State, tsnode.StateNeedsLogin)
	}
	if snapshot.DeviceName != "workstation" {
		t.Errorf("DeviceName = %q, want the node's hostname", snapshot.DeviceName)
	}
}

// A node with nothing to complain about must leave LastError empty, or the tray shows
// a permanent warning badge on a healthy agent.
func TestAHealthyNodeLeavesTheTrayWithNoError(t *testing.T) {
	agent := &fakeAgent{
		node:     &fakeNode{status: tsnode.Status{BackendState: tsnode.StateRunning, Hostname: "workstation"}},
		forwards: &fakeForwards{},
	}
	controller, _ := newTestController(agent, func() {})

	if got := controller.Snapshot().LastError; got != "" {
		t.Errorf("LastError = %q on a healthy node, want empty", got)
	}
}

// A menu-bar-only user sees no dashboard and no log. When the settings behind every switch
// in the menu are defaults rather than what this machine was set up with, the menu is the
// only place that can say so.
func TestAReplacedConfigurationBecomesTheTraysLastError(t *testing.T) {
	agent := &fakeAgent{
		node:     &fakeNode{status: tsnode.Status{BackendState: tsnode.StateRunning, Hostname: "workstation"}},
		forwards: &fakeForwards{},
		quarantine: &httpapi.ConfigQuarantineView{
			Path:   "/tmp/config.json.unusable-20240101-000000",
			Reason: "config.json could not be read as JSON",
		},
	}
	controller, _ := newTestController(agent, func() {})

	got := controller.Snapshot().LastError
	if !strings.Contains(got, "defaults") {
		t.Errorf("LastError = %q, want it to say the app is running on the defaults", got)
	}
}

// Both problems reach the menu, and the configuration comes first: it is what explains why
// the node is being started with settings nobody chose.
func TestTheReplacedConfigurationIsNamedBeforeTheNodesOwnProblem(t *testing.T) {
	const problem = "tag:app-tail is not defined in the tailnet policy file"
	agent := &fakeAgent{
		node: &fakeNode{status: tsnode.Status{
			BackendState: tsnode.StateNeedsLogin,
			Problem:      problem,
		}},
		forwards:   &fakeForwards{},
		quarantine: &httpapi.ConfigQuarantineView{Path: "/tmp/kept", Reason: "not JSON"},
	}
	controller, _ := newTestController(agent, func() {})

	got := controller.Snapshot().LastError
	if !strings.Contains(got, problem) {
		t.Errorf("LastError = %q, want the node's problem kept alongside", got)
	}
	if strings.Index(got, "defaults") > strings.Index(got, problem) {
		t.Errorf("LastError = %q, want the configuration named first", got)
	}
}

// Every other test builds the controller struct directly, so the constructor the
// binary actually calls is the one thing never exercised. A missing field here is a
// nil open func: the first "Open Dashboard" click panics in the menu goroutine.
func TestTheTrayControllerConstructorWiresEveryFieldTheMenuUses(t *testing.T) {
	agent := &fakeAgent{
		node:         &fakeNode{status: tsnode.Status{BackendState: tsnode.StateRunning}},
		forwards:     &fakeForwards{},
		dashboardURL: "http://127.0.0.1:8377",
	}
	stopped := false

	controller := newTrayController(agent, func() { stopped = true })

	if controller.agent == nil {
		t.Error("the controller has no agent; every menu item would report nothing")
	}
	if controller.open == nil {
		t.Fatal("the controller has no launcher; opening the dashboard would panic")
	}
	if controller.stop == nil {
		t.Fatal("the controller has no stop func; Quit would panic")
	}
	controller.Shutdown()
	if !stopped {
		t.Error("Quit did not reach the cancel func the constructor was given")
	}

	// The snapshot has to read through the wired agent rather than a zero value.
	if got := controller.Snapshot().State; got != tsnode.StateRunning {
		t.Errorf("Snapshot().State = %q, want the agent's own state", got)
	}
}

// A setting with a fixed set of values carries its value, not a checkbox position. Reading
// it as a boolean would leave the menu marking whichever value happened to be first.
func TestSnapshotCarriesTheValueOfASettingWithASetOfThem(t *testing.T) {
	settings := newFakeSettings(map[string]any{"showTray": true, "proxy.scope": "all"})
	settings.schema = append(settings.schema, config.FieldSchema{
		Key: "proxy.scope", ViewKey: "proxy.scope", Kind: config.KindEnum,
		Write: config.WritePatch, Label: "What the proxy will reach", Tray: true,
	})
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings}
	controller, _ := newTestController(agent, func() {})

	got := controller.Snapshot()
	state, ok := got.Settings["proxy.scope"]
	if !ok {
		t.Fatal("the snapshot carries no state for proxy.scope, so its row paints as unavailable")
	}
	if state.Value != "all" || !state.Available {
		t.Errorf("proxy.scope = %+v, want the stored value and available", state)
	}
	if got.LastError != "" {
		t.Errorf("reading a value the document holds reported %q", got.LastError)
	}
}

// A menu showing a value the document does not hold would be inventing one, so the read
// has to fail where the user can see it.
func TestASettingWithASetOfValuesThatReadsWrongIsReportedNotGuessed(t *testing.T) {
	settings := newFakeSettings(map[string]any{"showTray": true, "proxy.scope": 42})
	settings.schema = append(settings.schema, config.FieldSchema{
		Key: "proxy.scope", ViewKey: "proxy.scope", Kind: config.KindEnum,
		Write: config.WritePatch, Label: "What the proxy will reach", Tray: true,
	})
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings}
	controller, _ := newTestController(agent, func() {})

	got := controller.Snapshot()
	if _, ok := got.Settings["proxy.scope"]; ok {
		t.Error("a value the document does not hold as text was painted anyway")
	}
	if !strings.Contains(got.LastError, "proxy.scope") {
		t.Errorf("LastError = %q, want it to name the setting that could not be read", got.LastError)
	}
}

// The registry decides what the menu may write. A caller naming something else -- a
// setting that is not in the tray, or one with no fixed set of values -- is refused here
// rather than trusted because the menu supposedly built it.
func TestAChoiceTheRegistryDoesNotOfferIsRefused(t *testing.T) {
	cases := []struct{ name, key string }{
		{"not a setting at all", "nothing.like.this"},
		{"a setting with no fixed set of values", "showTray"},
		// proxy.scope has a fixed set of values and is not offered in the menu: it reads
		// back what one instance's rules amount to, and writing it would round a rule list
		// to the nearest of two presets -- a permission change nobody asked for.
		{"a set of values the menu does not offer", "proxy.scope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			settings := newFakeSettings(map[string]any{})
			agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings}
			controller, _ := newTestController(agent, func() {})

			if err := controller.SetChoice(tc.key, "all"); err == nil {
				t.Fatalf("SetChoice(%q) was accepted", tc.key)
			}
			if got := settings.recordedPatches(); len(got) != 0 {
				t.Errorf("a refused choice still reached the store: %v", got)
			}
		})
	}
}

// The picker writes the same setting the dashboard's does, so the schedule, the warning
// and the card all see the change the way they see any other.
func TestSelectingAnExitNodeWritesTheSettingTheDashboardWrites(t *testing.T) {
	settings := newFakeSettings(map[string]any{})
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings}
	controller, _ := newTestController(agent, func() {})

	if err := controller.SetExitNode("nodekey-abc"); err != nil {
		t.Fatalf("SetExitNode: %v", err)
	}
	patches := settings.recordedPatches()
	if len(patches) != 1 {
		t.Fatalf("patches = %v, want exactly one", patches)
	}
	if got := string(patches[0]["exitNode.nodeId"]); got != `"nodekey-abc"` {
		t.Errorf("patched exitNode.nodeId with %s", got)
	}
}

// The devices the picker fills its slots from are the module's own, in its own order, so
// the menu and the dashboard never disagree about which device is in use.
func TestTheSnapshotCarriesTheDevicesTheExitNodeModuleOffers(t *testing.T) {
	agent := &fakeAgent{
		forwards: &fakeForwards{},
		settings: newFakeSettings(map[string]any{}),
		exitNode: &fakeExitNode{view: httpapi.ExitNodeView{
			Enabled: true,
			Candidates: []httpapi.ExitNodeCandidate{
				{ID: "a", Display: "gpu-box (Berlin)", Online: true},
				{ID: "b", Display: "laptop", Current: true},
			},
		}},
	}
	controller, _ := newTestController(agent, func() {})

	got := controller.Snapshot().ExitNodeCandidates
	want := []tray.ExitNodeChoice{
		{ID: "a", Label: "gpu-box (Berlin)", Online: true},
		{ID: "b", Label: "laptop", Current: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("candidates = %+v\nwant %+v", got, want)
	}
}

// With the module off the picker is under a switch that is off, so offering devices there
// would be offering a choice that does nothing.
func TestNoDevicesAreOfferedWhileTheExitNodeModuleIsOff(t *testing.T) {
	agent := &fakeAgent{
		forwards: &fakeForwards{},
		settings: newFakeSettings(map[string]any{}),
		exitNode: &fakeExitNode{view: httpapi.ExitNodeView{
			Candidates: []httpapi.ExitNodeCandidate{{ID: "a", Display: "gpu-box", Online: true}},
		}},
	}
	controller, _ := newTestController(agent, func() {})

	if got := controller.Snapshot().ExitNodeCandidates; len(got) != 0 {
		t.Errorf("candidates = %+v while the module is off", got)
	}
}

// proxyModuleSettings is a settings document whose proxy module switch the menu can read,
// which is what decides whether the instances are worth offering at all.
func proxyModuleSettings(on bool) *fakeSettings {
	settings := newFakeSettings(map[string]any{"showTray": true, proxyModuleKey: on})
	settings.schema = append(settings.schema, config.FieldSchema{
		Key: proxyModuleKey, ViewKey: proxyModuleKey, Kind: config.KindBool,
		Write: config.WritePatch, Label: "Tailnet proxy", Tray: true,
	})
	return settings
}

// The instances the picker fills its slots from are the agent's own, in its own order, so
// the menu and the dashboard never disagree about which proxy is running or what it reaches.
func TestTheSnapshotCarriesTheProxyInstancesTheAgentRuns(t *testing.T) {
	agent := &fakeAgent{
		forwards: &fakeForwards{},
		settings: proxyModuleSettings(true),
		proxies: &fakeProxies{list: []httpapi.ProxyInstanceView{
			{ID: "px_default", Name: "Default", Enabled: true, Listening: "127.0.0.1:1080",
				Reach: []string{"everything on tailnet"}},
			{ID: "px_psql", Name: "psql", Reach: []string{"db.corp.internal on port 5432 over TCP"}},
		}},
	}
	controller, _ := newTestController(agent, func() {})

	got := controller.Snapshot().Proxies
	want := []tray.ProxyChoice{
		{ID: "px_default", Label: "Default", Enabled: true, Listening: "127.0.0.1:1080",
			Reach: []string{"everything on tailnet"}},
		{ID: "px_psql", Label: "psql", Reach: []string{"db.corp.internal on port 5432 over TCP"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("proxies = %+v\nwant %+v", got, want)
	}
}

// With the module off no instance listens whatever its own switch says, and the state each
// one reports folds that in -- so every checkbox would read as off however it was really
// left, and clicking one would write a value that changes nothing on screen.
func TestNoProxyInstancesAreOfferedWhileTheModuleIsOff(t *testing.T) {
	agent := &fakeAgent{
		forwards: &fakeForwards{},
		settings: proxyModuleSettings(false),
		proxies: &fakeProxies{list: []httpapi.ProxyInstanceView{
			{ID: "px_default", Name: "Default"},
		}},
	}
	controller, _ := newTestController(agent, func() {})

	if got := controller.Snapshot().Proxies; len(got) != 0 {
		t.Errorf("proxies = %+v while the module that runs them is off", got)
	}
}

// The menu writes the instance's own field through the proxies API, so a click inherits the
// validation and the rebinding a dashboard save gets. Writing the module switch instead
// would take every other instance down with it.
func TestSwitchingOneProxyOffWritesThatInstanceAndNothingElse(t *testing.T) {
	settings := proxyModuleSettings(true)
	proxies := &fakeProxies{list: []httpapi.ProxyInstanceView{
		{ID: "px_psql", Name: "psql", Enabled: true},
	}}
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings, proxies: proxies}
	controller, _ := newTestController(agent, func() {})

	if err := controller.SetProxyEnabled("px_psql", false); err != nil {
		t.Fatalf("SetProxyEnabled: %v", err)
	}

	updates := proxies.recordedUpdates()
	if len(updates) != 1 || updates[0].id != "px_psql" {
		t.Fatalf("updates = %+v, want exactly one for px_psql", updates)
	}
	if got := string(updates[0].patch["enabled"]); got != "false" {
		t.Errorf("patched enabled with %s, want false", got)
	}
	if got := settings.recordedPatches(); len(got) != 0 {
		t.Errorf("switching one instance off also wrote the settings document: %v", got)
	}
}

// A refusal from the agent has to reach the caller, or the menu repaints with the instance
// still on and nothing saying the click was rejected.
func TestAProxyTheAgentRefusesToSwitchIsReportedRatherThanSwallowed(t *testing.T) {
	proxies := &fakeProxies{updateErr: errors.New("that port is already in use")}
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: proxyModuleSettings(true), proxies: proxies}
	controller, _ := newTestController(agent, func() {})

	err := controller.SetProxyEnabled("px_psql", true)
	if err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Errorf("SetProxyEnabled error = %v, want the agent's own refusal", err)
	}
}

// Before the agent has built the proxies there is nothing to write to, and a silent success
// would leave a ticked checkbox beside a listener that was never started.
func TestSwitchingAProxyBeforeTheAgentHasBuiltThemFailsLoudly(t *testing.T) {
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: proxyModuleSettings(true)}
	controller, _ := newTestController(agent, func() {})

	if err := controller.SetProxyEnabled("px_psql", true); err == nil {
		t.Error("SetProxyEnabled succeeded with no proxies behind it")
	}
	if got := controller.Snapshot().Proxies; len(got) != 0 {
		t.Errorf("proxies = %+v with none built yet", got)
	}
}

// An instance is a name, an address and a list of rules, none of which a menu can take, so
// the entry hands over to the one surface that can -- landing on the proxies section rather
// than at the top of a page the reader then has to navigate.
func TestOpeningTheProxiesLandsOnTheSectionThatHoldsThem(t *testing.T) {
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: newFakeSettings(map[string]any{})}
	controller, rec := newTestController(agent, func() {})

	if err := controller.OpenProxies(); err == nil {
		t.Fatal("OpenProxies succeeded before the dashboard existed")
	}
	if len(rec.opened()) != 0 {
		t.Errorf("a browser was launched at %v with no dashboard bound", rec.opened())
	}

	agent.setDashboardURL("http://127.0.0.1:8377")
	if err := controller.OpenProxies(); err != nil {
		t.Fatalf("OpenProxies: %v", err)
	}
	want := []string{"http://127.0.0.1:8377/?launch=L1&" + strings.TrimPrefix(proxiesQuery, "?")}
	if got := rec.opened(); !reflect.DeepEqual(got, want) {
		t.Errorf("opened %v, want %v", got, want)
	}
}

// The connections the picker fills its slots from are the agent's own, in its own order and
// with its own words for what each one is doing, so the menu and the connections page never
// describe the same network differently.
func TestTheSnapshotCarriesTheConnectionsTheAgentHolds(t *testing.T) {
	agent := &fakeAgent{
		forwards: &fakeForwards{},
		settings: newFakeSettings(map[string]any{}),
		tunnels: &fakeTunnels{list: []httpapi.TunnelView{
			{ID: "tn_office", Name: "Office", TypeLabel: "WireGuard", Enabled: true, Live: true,
				State: "connected", StateLabel: "Connected"},
			{ID: "tn_lab", Name: "Lab", TypeLabel: "OpenVPN", Enabled: true,
				State: "error", StateLabel: "Failed", Detail: "no route to host"},
		}},
	}
	controller, _ := newTestController(agent, func() {})

	got := controller.Snapshot().Connections
	want := []tray.ConnectionChoice{
		{ID: "tn_office", Label: "Office", Enabled: true, Live: true, State: "Connected", Kind: "WireGuard"},
		{ID: "tn_lab", Label: "Lab", Enabled: true, State: "Failed", Detail: "no route to host", Kind: "OpenVPN"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("connections = %+v\nwant %+v", got, want)
	}
}

// The menu writes the connection's own field through the connections API, so a click
// inherits the validation and the reconcile a dashboard save gets rather than being a
// second way to bring a network up.
func TestSwitchingOneConnectionOffWritesThatConnectionAndNothingElse(t *testing.T) {
	settings := newFakeSettings(map[string]any{})
	tunnels := &fakeTunnels{list: []httpapi.TunnelView{
		{ID: "tn_office", Name: "Office", Enabled: true},
	}}
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings, tunnels: tunnels}
	controller, _ := newTestController(agent, func() {})

	if err := controller.SetConnectionEnabled("tn_office", false); err != nil {
		t.Fatalf("SetConnectionEnabled: %v", err)
	}

	updates := tunnels.recordedUpdates()
	if len(updates) != 1 || updates[0].id != "tn_office" {
		t.Fatalf("updates = %+v, want exactly one for tn_office", updates)
	}
	if got := string(updates[0].patch["enabled"]); got != "false" {
		t.Errorf("patched enabled with %s, want false", got)
	}
	if got := settings.recordedPatches(); len(got) != 0 {
		t.Errorf("switching one connection off also wrote the settings document: %v", got)
	}
}

// A refusal from the agent has to reach the caller, or the menu repaints with the connection
// still ticked and nothing saying the click was rejected.
func TestAConnectionTheAgentRefusesToSwitchIsReportedRatherThanSwallowed(t *testing.T) {
	tunnels := &fakeTunnels{updateErr: errors.New("that connection has no server to dial")}
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: newFakeSettings(map[string]any{}), tunnels: tunnels}
	controller, _ := newTestController(agent, func() {})

	err := controller.SetConnectionEnabled("tn_office", true)
	if err == nil || !strings.Contains(err.Error(), "no server to dial") {
		t.Errorf("SetConnectionEnabled error = %v, want the agent's own refusal", err)
	}
}

// Before the agent has built the connections there is nothing to write to, and a silent
// success would leave a ticked checkbox beside a network that was never brought up.
func TestSwitchingAConnectionBeforeTheAgentHasBuiltThemFailsLoudly(t *testing.T) {
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: newFakeSettings(map[string]any{})}
	controller, _ := newTestController(agent, func() {})

	if err := controller.SetConnectionEnabled("tn_office", true); err == nil {
		t.Error("SetConnectionEnabled succeeded with no connections behind it")
	}
	if got := controller.Snapshot().Connections; len(got) != 0 {
		t.Errorf("connections = %+v with none built yet", got)
	}
}

// A connection is a server, a key and a set of addresses, none of which a menu can take, so
// the entry hands over to the one surface that can -- landing on the connections list rather
// than at the top of a page the reader then has to navigate.
func TestOpeningTheConnectionsLandsOnTheSectionThatHoldsThem(t *testing.T) {
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: newFakeSettings(map[string]any{})}
	controller, rec := newTestController(agent, func() {})

	if err := controller.OpenConnections(); err == nil {
		t.Fatal("OpenConnections succeeded before the dashboard existed")
	}
	if len(rec.opened()) != 0 {
		t.Errorf("a browser was launched at %v with no dashboard bound", rec.opened())
	}

	agent.setDashboardURL("http://127.0.0.1:8377")
	if err := controller.OpenConnections(); err != nil {
		t.Fatalf("OpenConnections: %v", err)
	}
	want := []string{"http://127.0.0.1:8377/?launch=L1&" + strings.TrimPrefix(connectionsQuery, "?")}
	if got := rec.opened(); !reflect.DeepEqual(got, want) {
		t.Errorf("opened %v, want %v", got, want)
	}
}

// The menu switches resolvers with one write, the same one `app-tail dns use` sends, and it
// arranges the rights first: the click is somebody asking for the feature, which is the one
// moment a password prompt is expected rather than mysterious.
func TestSwitchingResolverProfilesArrangesTheMachineThenWritesTheSwitchAndTheProfile(t *testing.T) {
	settings := newFakeSettings(map[string]any{})
	dns := &fakeDNS{}
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings, dns: dns}
	controller, _ := newTestController(agent, func() {})

	if err := controller.SetDNSProfile("cloudflare"); err != nil {
		t.Fatalf("SetDNSProfile: %v", err)
	}

	if dns.setupCount() != 1 {
		t.Errorf("the machine was arranged %d times, want exactly once", dns.setupCount())
	}
	patches := settings.recordedPatches()
	if len(patches) != 1 {
		t.Fatalf("patches = %v, want both keys in one write", patches)
	}
	if got := string(patches[0]["systemDns.enabled"]); got != "true" {
		t.Errorf("systemDns.enabled = %s, want the switch turned on by the same write", got)
	}
	if got := string(patches[0]["systemDns.profile"]); got != `"cloudflare"` {
		t.Errorf("systemDns.profile = %s", got)
	}
}

// System default is the way back, and it has to mean "change nothing about this machine",
// not "keep the override installed pointing at a profile with no servers".
func TestChoosingTheSystemDefaultSwitchesTheModuleOffWithoutArrangingAnything(t *testing.T) {
	settings := newFakeSettings(map[string]any{})
	dns := &fakeDNS{}
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings, dns: dns}
	controller, _ := newTestController(agent, func() {})

	if err := controller.SetDNSProfile("system"); err != nil {
		t.Fatalf("SetDNSProfile: %v", err)
	}

	if dns.setupCount() != 0 {
		t.Errorf("the machine was arranged for the profile that changes nothing: %d calls", dns.setupCount())
	}
	patches := settings.recordedPatches()
	if len(patches) != 1 {
		t.Fatalf("patches = %v, want exactly one", patches)
	}
	if got := string(patches[0]["systemDns.enabled"]); got != "false" {
		t.Errorf("systemDns.enabled = %s, want the module switched off", got)
	}
	// The agent refuses a setting whose module the same write turns off, and turning it off
	// already puts the stored profile back to System default. Naming it here is a refused
	// write, which is this menu entry failing to do the one thing it is for.
	if _, named := patches[0]["systemDns.profile"]; named {
		t.Errorf("the undo names the profile as well as the switch: %v", patches[0])
	}
}

// A declined password prompt leaves the machine as it was, so storing the profile anyway
// would leave the menu checking a resolver nothing is resolving through.
func TestAResolverTheMachineRefusesToArrangeIsNotStoredAnyway(t *testing.T) {
	settings := newFakeSettings(map[string]any{})
	dns := &fakeDNS{setErr: errors.New("the administrator prompt was declined")}
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings, dns: dns}
	controller, _ := newTestController(agent, func() {})

	err := controller.SetDNSProfile("cloudflare")
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("err = %v, want the refusal carried through to the menu", err)
	}
	if patches := settings.recordedPatches(); len(patches) != 0 {
		t.Errorf("the profile was stored despite the machine refusing: %v", patches)
	}
}

// On Windows the rights arrive with a restart that storing the profile performs, so the
// machine answering that it is set up that way is the go-ahead to store it -- refusing there
// is the menu entry that never asks for the rights it needs.
func TestAResolverWhoseRightsArriveWithARestartIsStored(t *testing.T) {
	settings := newFakeSettings(map[string]any{})
	dns := &fakeDNS{setErr: fmt.Errorf("arrange: %w", app.ErrRightsAtRestart)}
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings, dns: dns}
	controller, _ := newTestController(agent, func() {})

	if err := controller.SetDNSProfile("cloudflare"); err != nil {
		t.Fatalf("SetDNSProfile = %v, want the profile stored so the save restarts app-tail for the rights", err)
	}
	patches := settings.recordedPatches()
	if len(patches) != 1 || string(patches[0]["systemDns.enabled"]) != "true" ||
		string(patches[0]["systemDns.profile"]) != `"cloudflare"` {
		t.Fatalf("patches = %v, want one write turning the resolver on with cloudflare", patches)
	}
}

// The picker is filled whether or not the module is on: switching it on is what the picker
// is for, so a catalog that appeared only afterwards would be a menu with no way in.
func TestTheSnapshotOffersEveryProfileAndMarksTheOneInForce(t *testing.T) {
	agent := &fakeAgent{
		forwards: &fakeForwards{},
		settings: newFakeSettings(map[string]any{}),
		dns: &fakeDNS{view: httpapi.DNSView{System: &httpapi.DNSSystemView{
			Enabled: true, Applied: true, Profile: "cloudflare", ProfileLabel: "Cloudflare",
		}}},
		profiles: &fakeDNSProfiles{list: []config.DNSProfile{
			{ID: "system", Name: "System default"},
			{ID: "cloudflare", Name: "Cloudflare", Servers: []string{"1.1.1.1", "1.0.0.1"}},
		}},
	}
	controller, _ := newTestController(agent, func() {})

	snapshot := controller.Snapshot()
	want := []tray.DNSProfileChoice{
		{ID: "system", Label: "System default"},
		{ID: "cloudflare", Label: "Cloudflare", Servers: []string{"1.1.1.1", "1.0.0.1"}, Current: true},
	}
	if !reflect.DeepEqual(snapshot.DNSProfiles, want) {
		t.Errorf("profiles = %+v\nwant %+v", snapshot.DNSProfiles, want)
	}
	if snapshot.SystemDNS != "Cloudflare" {
		t.Errorf("state line = %q, want the resolver in force named plainly", snapshot.SystemDNS)
	}
}

// Every one of these states looks like the others from the menu, and each one has a
// different answer: nothing to do, wait, or go and look at why.
func TestTheResolverLineTellsApartOffNotInForceAndNotAnswering(t *testing.T) {
	cases := []struct {
		name string
		view httpapi.DNSSystemView
		want string
	}{
		{
			name: "off",
			view: httpapi.DNSSystemView{Profile: "system", ProfileLabel: "System default"},
			want: "this machine's own resolver",
		},
		{
			name: "in force",
			view: httpapi.DNSSystemView{Enabled: true, Applied: true, ProfileLabel: "NextDNS"},
			want: "NextDNS",
		},
		{
			name: "in force but the upstream is unreachable",
			view: httpapi.DNSSystemView{
				Enabled: true, Applied: true, ProfileLabel: "NextDNS",
				Unreachable: "no reply from https://dns.nextdns.io/abc",
			},
			want: "NextDNS (not answering)",
		},
		{
			// The switch worked and the answers still come from this network. A line that
			// named the profile alone would be the last surface claiming otherwise.
			name: "in force but this network answers the queries itself",
			view: httpapi.DNSSystemView{
				Enabled: true, Applied: true, ProfileLabel: "Router",
				Intercepted: "This network answers plain DNS itself",
			},
			want: "Router (this network is answering)",
		},
		{
			// In force, answering, and the resolvers behind it were found by asking this
			// network where they live. The switch worked; who chose the server did not.
			name: "in force but this network found the resolvers",
			view: httpapi.DNSSystemView{
				Enabled: true, Applied: true, ProfileLabel: "NextDNS",
				Bootstrap:         "dns.nextdns.io was looked up through this network's own resolvers",
				BootstrapDegraded: true,
			},
			want: "NextDNS (found through this network)",
		},
		{
			name: "on but the machine refused it",
			view: httpapi.DNSSystemView{
				Enabled: true, ProfileLabel: "NextDNS", Error: "the helper is not installed",
			},
			want: "NextDNS (not in force: the helper is not installed)",
		},
		{
			name: "on and not applied yet",
			view: httpapi.DNSSystemView{Enabled: true, ProfileLabel: "NextDNS"},
			want: "NextDNS (not in force yet)",
		},
		{
			name: "a profile with no label falls back to its id",
			view: httpapi.DNSSystemView{Enabled: true, Applied: true, Profile: "work"},
			want: "work",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := systemDNSLine(&tc.view); got != tc.want {
				t.Errorf("line = %q, want %q", got, tc.want)
			}
		})
	}
}

// The picker offers this machine's own network first and then every stored connection, from
// the same list the dashboard's picker reads. Offering only the connections would leave the
// menu able to move the traffic and unable to move it back.
func TestTheSnapshotOffersThisMachineAndEveryConnectionForInternetTraffic(t *testing.T) {
	agent := &fakeAgent{
		forwards: &fakeForwards{},
		settings: egressSettings(
			config.EnumOption{Value: "tn_office", Label: "Office", Help: "A wireguard connection."},
			config.EnumOption{Value: "tn_lab", Label: "Lab", Help: "A wireguard connection."},
		),
		egress: &fakeEgress{view: httpapi.EgressView{
			Mode: string(config.EgressTunnel), TunnelID: "tn_office", TunnelName: "Office", Carrying: true,
		}},
	}
	controller, _ := newTestController(agent, func() {})

	snapshot := controller.Snapshot()
	want := []tray.EgressChoice{
		{
			Label:  "Out of this machine",
			Detail: "Anything your connections do not carry leaves the way it always has.",
		},
		{ID: "tn_office", Label: "Office", Detail: "A wireguard connection.", Current: true},
		{ID: "tn_lab", Label: "Lab", Detail: "A wireguard connection."},
	}
	if !reflect.DeepEqual(snapshot.EgressChoices, want) {
		t.Errorf("choices = %+v\nwant %+v", snapshot.EgressChoices, want)
	}
	if snapshot.Egress != "Office" {
		t.Errorf("state line = %q, want the connection carrying it named plainly", snapshot.Egress)
	}
}

// Every one of these states looks the same from anywhere but this line: traffic leaving the
// machine directly is what a connection that is set and not carrying looks like too, and
// only one of the two is what somebody asked for.
func TestTheInternetLineTellsApartDirectCarryingAndSetButNotCarrying(t *testing.T) {
	cases := []struct {
		name string
		view httpapi.EgressView
		want string
	}{
		{
			name: "out of this machine",
			view: httpapi.EgressView{Mode: string(config.EgressDirect), TunnelID: "tn_office", TunnelName: "Office"},
			want: "out of this machine",
		},
		{
			name: "carrying it",
			view: httpapi.EgressView{
				Mode: string(config.EgressTunnel), TunnelID: "tn_office", TunnelName: "Office", Carrying: true,
			},
			want: "Office",
		},
		{
			name: "set to a connection that is down",
			view: httpapi.EgressView{
				Mode: string(config.EgressTunnel), TunnelID: "tn_office", TunnelName: "Office",
				Reason: "Office is not running, so internet traffic is leaving this machine the way it always has",
			},
			want: "Office (not carrying it: Office is not running, so internet traffic is leaving " +
				"this machine the way it always has)",
		},
		{
			name: "the mode is set and no connection is named",
			view: httpapi.EgressView{
				Mode: string(config.EgressTunnel), Reason: "no connection is chosen to carry it",
			},
			want: "no connection chosen, so it is leaving this machine",
		},
		{
			name: "a connection with no name falls back to its id",
			view: httpapi.EgressView{Mode: string(config.EgressTunnel), TunnelID: "tn_office", Carrying: true},
			want: "tn_office",
		},
		{
			name: "not carrying and nothing said why",
			view: httpapi.EgressView{
				Mode: string(config.EgressTunnel), TunnelID: "tn_office", TunnelName: "Office",
			},
			want: "Office (not carrying it)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := egressLine(tc.view); got != tc.want {
				t.Errorf("line = %q, want %q", got, tc.want)
			}
		})
	}
}

// Choosing a connection is two settings in one write: the connection is refused while the
// mode still says the traffic leaves this machine, so a write that sent them separately
// would fail on the half that matters.
func TestChoosingAConnectionWritesTheModeAndTheConnectionTogether(t *testing.T) {
	settings := egressSettings(config.EnumOption{Value: "tn_office", Label: "Office"})
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings, egress: &fakeEgress{}}
	controller, _ := newTestController(agent, func() {})

	if err := controller.SetEgress("tn_office"); err != nil {
		t.Fatalf("SetEgress: %v", err)
	}

	patches := settings.recordedPatches()
	if len(patches) != 1 {
		t.Fatalf("patches = %v, want both keys in one write", patches)
	}
	if got := string(patches[0]["egress.mode"]); got != `"tunnel"` {
		t.Errorf("egress.mode = %s, want the mode moved by the same write", got)
	}
	if got := string(patches[0]["egress.tunnelId"]); got != `"tn_office"` {
		t.Errorf("egress.tunnelId = %s", got)
	}
}

// The way back writes only the mode. The connection stays named, which is what lets somebody
// switch back and forth without picking again -- and it carries nothing while the mode says
// the traffic leaves this machine.
func TestChoosingThisMachineLeavesTheRememberedConnectionAlone(t *testing.T) {
	settings := egressSettings(config.EnumOption{Value: "tn_office", Label: "Office"})
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings, egress: &fakeEgress{}}
	controller, _ := newTestController(agent, func() {})

	if err := controller.SetEgress(""); err != nil {
		t.Fatalf("SetEgress: %v", err)
	}

	patches := settings.recordedPatches()
	if len(patches) != 1 {
		t.Fatalf("patches = %v, want exactly one", patches)
	}
	if got := string(patches[0]["egress.mode"]); got != `"direct"` {
		t.Errorf("egress.mode = %s, want the traffic sent back out of this machine", got)
	}
	if _, named := patches[0]["egress.tunnelId"]; named {
		t.Errorf("the way back rewrites the connection as well as the mode: %v", patches[0])
	}
}

// Before the agent has built the egress module there is nothing to read, and a snapshot that
// invented "out of this machine" would show a menu claiming the traffic is going somewhere
// nobody has established yet.
func TestTheInternetPickerIsEmptyBeforeTheAgentCanSayWhereTrafficGoes(t *testing.T) {
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: egressSettings()}
	controller, _ := newTestController(agent, func() {})

	snapshot := controller.Snapshot()
	if snapshot.Egress != "" || len(snapshot.EgressChoices) != 0 {
		t.Errorf("line = %q with choices %+v, want nothing until the module exists",
			snapshot.Egress, snapshot.EgressChoices)
	}
}

// Turning the mode on is three things: arrange the machine, store the mode, rebuild the
// node onto it. Doing only the middle one would report success beside a node running
// exactly as it was.
func TestTurningTheInterfaceOnArrangesTheMachineThenRebuildsTheNode(t *testing.T) {
	settings := newFakeSettings(map[string]any{})
	iface := &fakeInterfaceSetup{}
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings, iface: iface}
	controller, _ := newTestController(agent, func() {})

	if err := controller.SetNetworkMode(true); err != nil {
		t.Fatalf("SetNetworkMode: %v", err)
	}
	if got := iface.setupCount(); got != 1 {
		t.Errorf("SetUpInterface called %d times, want 1", got)
	}
	patches := settings.recordedPatches()
	if len(patches) != 1 || string(patches[0]["interface.mode"]) != `"tun"` {
		t.Fatalf("patches = %v, want one setting interface.mode to tun", patches)
	}
	if got := agent.restartCount(); got != 1 {
		t.Errorf("RestartNode called %d times, want 1", got)
	}
}

// Coming back off the interface changes nothing about the machine, so asking for
// administrator rights to do it would be asking for nothing.
func TestTurningTheInterfaceOffDoesNotArrangeTheMachine(t *testing.T) {
	settings := newFakeSettings(map[string]any{})
	iface := &fakeInterfaceSetup{}
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings, iface: iface}
	controller, _ := newTestController(agent, func() {})

	if err := controller.SetNetworkMode(false); err != nil {
		t.Fatalf("SetNetworkMode: %v", err)
	}
	if got := iface.setupCount(); got != 0 {
		t.Errorf("SetUpInterface called %d times while switching the mode off", got)
	}
	patches := settings.recordedPatches()
	if len(patches) != 1 || string(patches[0]["interface.mode"]) != `"userspace"` {
		t.Fatalf("patches = %v, want one setting interface.mode to userspace", patches)
	}
	if got := agent.restartCount(); got != 1 {
		t.Errorf("RestartNode called %d times, want 1", got)
	}
}

// A machine that refuses to be arranged must not have the mode stored anyway: the node
// would be rebuilt onto an interface it cannot create and fall back, which reads as the
// mode being broken rather than as the setup having failed.
func TestAMachineThatCannotBeArrangedIsNotSwitchedOverAnyway(t *testing.T) {
	settings := newFakeSettings(map[string]any{})
	iface := &fakeInterfaceSetup{setupErr: errors.New("the privileged helper refused to install")}
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings, iface: iface}
	controller, _ := newTestController(agent, func() {})

	err := controller.SetNetworkMode(true)
	if err == nil || !strings.Contains(err.Error(), "refused to install") {
		t.Fatalf("SetNetworkMode = %v, want the machine's own refusal", err)
	}
	if got := settings.recordedPatches(); len(got) != 0 {
		t.Errorf("the mode was stored despite the machine refusing: %v", got)
	}
	if got := agent.restartCount(); got != 0 {
		t.Errorf("the node was rebuilt %d times despite the machine refusing", got)
	}
}

// Where the rights arrive with a restart, storing the mode is what restarts the process, and
// the node that start builds is already on the stored mode. Rebuilding this one as well would
// race that shutdown for nothing.
func TestAnInterfaceWhoseRightsArriveWithARestartIsStoredWithoutARebuild(t *testing.T) {
	settings := newFakeSettings(map[string]any{})
	iface := &fakeInterfaceSetup{setupErr: app.ErrRightsAtRestart}
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings, iface: iface}
	controller, _ := newTestController(agent, func() {})

	if err := controller.SetNetworkMode(true); err != nil {
		t.Fatalf("SetNetworkMode = %v, want the mode stored so the save restarts app-tail for the rights", err)
	}
	patches := settings.recordedPatches()
	if len(patches) != 1 || string(patches[0]["interface.mode"]) != `"tun"` {
		t.Fatalf("patches = %v, want one setting interface.mode to tun", patches)
	}
	if got := agent.restartCount(); got != 0 {
		t.Errorf("RestartNode called %d times, want none while the process restarts", got)
	}
}

// A refusal from the agent has to stop the sequence: rebuilding the node after a write
// that did not land would interrupt every forward to put the node back exactly where it
// already was.
func TestAModeTheAgentRefusesDoesNotRebuildTheNode(t *testing.T) {
	settings := newFakeSettings(map[string]any{})
	settings.err = errors.New("interface.mode: needs the network-interface module turned on")
	iface := &fakeInterfaceSetup{}
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings, iface: iface}
	controller, _ := newTestController(agent, func() {})

	err := controller.SetNetworkMode(true)
	if err == nil || !strings.Contains(err.Error(), "needs the network-interface module") {
		t.Fatalf("SetNetworkMode = %v, want the agent's own refusal", err)
	}
	if got := agent.restartCount(); got != 0 {
		t.Errorf("the node was rebuilt %d times for a mode that was never stored", got)
	}
}

// A click that lands before the agent has finished starting must not store the mode on
// its own: the node would be rebuilt asking for an interface nothing has arranged.
func TestSwitchingOntoTheInterfaceBeforeTheAgentIsReadyStoresNothing(t *testing.T) {
	settings := newFakeSettings(map[string]any{})
	agent := &fakeAgent{forwards: &fakeForwards{}, settings: settings}
	controller, _ := newTestController(agent, func() {})

	err := controller.SetNetworkMode(true)
	if err == nil || !strings.Contains(err.Error(), "not available yet") {
		t.Fatalf("SetNetworkMode = %v, want a refusal naming the agent as not ready", err)
	}
	if got := settings.recordedPatches(); len(got) != 0 {
		t.Errorf("the mode was stored with nothing able to arrange the machine: %v", got)
	}
	if got := agent.restartCount(); got != 0 {
		t.Errorf("the node was rebuilt %d times with nothing able to arrange the machine", got)
	}
}

// The menu says whether the mode could be turned on right now, which is a different
// question from the sentence the dashboard card leads with: a machine fully ready for the
// mode with the mode switched off is ready here and degraded there.
func TestTheMenuReadsWhetherTheModeCouldBeTurnedOnRightNow(t *testing.T) {
	cases := []struct {
		name string
		view httpapi.InterfaceView
		want tray.NetworkState
	}{
		{
			name: "ready and off",
			view: httpapi.InterfaceView{Ready: true, Capability: httpapi.Capability{Available: true, Degraded: true,
				Reason: "the mode is set to keep the tailnet inside app-tail"}},
			want: tray.NetworkState{Available: true},
		},
		{
			name: "in force",
			view: httpapi.InterfaceView{Ready: true, InForce: true},
			want: tray.NetworkState{Available: true, InForce: true},
		},
		{
			name: "the helper is missing",
			view: httpapi.InterfaceView{Blocker: "the privileged helper is not installed"},
			want: tray.NetworkState{Reason: "the privileged helper is not installed"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agent := &fakeAgent{
				forwards: &fakeForwards{},
				settings: newFakeSettings(map[string]any{}),
				iface:    &fakeInterfaceSetup{view: tc.view},
			}
			controller, _ := newTestController(agent, func() {})
			if got := controller.Snapshot().NetworkInterface; got != tc.want {
				t.Errorf("NetworkInterface = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// The order is what makes the list usable: this machine first because its own address is
// what the submenu is most often opened for, then the machines that can actually be
// reached, then by name. Sorting by name alone buries the reachable ones.
func TestTheDeviceListLeadsWithThisMachineThenWhatCanBeReached(t *testing.T) {
	node := &fakeNode{
		status: tsnode.Status{
			BackendState: tsnode.StateRunning,
			Hostname:     "laptop",
			DNSName:      "laptop.tail1a2b3c.ts.net",
			TailscaleIPs: []string{"100.64.0.1"},
		},
		peers: []tsnode.Peer{
			{HostName: "zeta", IPs: []string{"100.64.0.9"}, Online: true},
			{HostName: "attic", IPs: []string{"100.64.0.7"}, Online: false},
			{HostName: "Beta", IPs: []string{"100.64.0.8"}, Online: true},
		},
	}
	agent := &fakeAgent{node: node, forwards: &fakeForwards{}, settings: newFakeSettings(map[string]any{"showTray": true})}
	controller, _ := newTestController(agent, func() {})

	got := controller.Snapshot().Devices

	want := []string{"laptop", "Beta", "zeta", "attic"}
	names := make([]string, 0, len(got))
	for _, d := range got {
		names = append(names, d.Name)
	}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("devices listed %q, want %q", names, want)
	}
	if !got[0].Self {
		t.Error("the first device is not marked as this machine, so the menu will not say so")
	}
	if got[len(got)-1].Online {
		t.Error("the offline device is not last")
	}
}

// "Reachable" is the sort's own word for what it puts first, and the tailnet calling a
// device online is not that: the control plane keeps listing a device this node has lost
// every path to. Sorting on online alone lifts a machine nothing reaches above one that
// works, which is the ordering a person trusts to pick a device to connect to.
func TestTheDeviceListSinksAMachineTheTailnetListsButNothingReaches(t *testing.T) {
	node := &fakeNode{
		status: tsnode.Status{BackendState: tsnode.StateRunning, Hostname: "laptop"},
		peers: []tsnode.Peer{
			{
				HostName: "aaa-gone", IPs: []string{"100.64.0.9"}, Online: true,
				Reach: tsnode.PeerReach{State: tsnode.PeerNoPath},
			},
			{
				HostName: "zzz-works", IPs: []string{"100.64.0.8"}, Online: true,
				Reach: tsnode.PeerReach{State: tsnode.PeerReady},
			},
			{
				HostName: "mmm-relayed", IPs: []string{"100.64.0.7"}, Online: true,
				Reach: tsnode.PeerReach{State: tsnode.PeerRelayed},
			},
		},
	}
	agent := &fakeAgent{node: node, forwards: &fakeForwards{}, settings: newFakeSettings(map[string]any{"showTray": true})}
	controller, _ := newTestController(agent, func() {})

	got := controller.Snapshot().Devices

	// Name order alone would run aaa, mmm, zzz. A relayed device is slow, not broken,
	// so it stays in the reachable half; only the one with no path sinks.
	want := []string{"laptop", "mmm-relayed", "zzz-works", "aaa-gone"}
	names := make([]string, 0, len(got))
	for _, d := range got {
		names = append(names, d.Name)
	}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("devices listed %q, want %q", names, want)
	}
	if last := got[len(got)-1]; last.State != tsnode.PeerNoPath {
		t.Errorf("the sunk device carries state %q, want %q so the row can say why",
			last.State, tsnode.PeerNoPath)
	}
}

// A device carries both an IPv4 and an IPv6 address. The IPv4 one is what fits in the
// places people paste it, so it is the one the row offers whichever order they arrive in.
func TestTheAddressOfferedIsTheIPv4One(t *testing.T) {
	node := &fakeNode{
		status: tsnode.Status{BackendState: tsnode.StateRunning, Hostname: "laptop"},
		peers: []tsnode.Peer{
			{HostName: "htpc", IPs: []string{"fd7a:115c:a1e0::1", "100.64.0.2"}, Online: true},
		},
	}
	agent := &fakeAgent{node: node, forwards: &fakeForwards{}, settings: newFakeSettings(map[string]any{"showTray": true})}
	controller, _ := newTestController(agent, func() {})

	devices := controller.Snapshot().Devices
	if len(devices) != 2 {
		t.Fatalf("got %d devices, want this machine and one peer", len(devices))
	}
	if devices[1].Address != "100.64.0.2" {
		t.Errorf("the row offers %q, want the IPv4 address", devices[1].Address)
	}
}

// A device with no IPv4 still has an address worth pasting, and an address the tailnet
// reports in a shape that will not parse is not one: offering it would hand the user a
// string that fails wherever they paste it.
func TestADeviceWithNoIPv4OffersWhatItDoesHave(t *testing.T) {
	cases := []struct {
		name string
		ips  []string
		want string
	}{
		{"only IPv6", []string{"fd7a:115c:a1e0::1"}, "fd7a:115c:a1e0::1"},
		{"an unusable address ahead of a good one", []string{"not-an-address", "100.64.0.7"}, "100.64.0.7"},
		{"nothing that parses", []string{"not-an-address"}, ""},
		{"no addresses at all", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := &fakeNode{
				status: tsnode.Status{BackendState: tsnode.StateRunning, Hostname: "laptop"},
				peers:  []tsnode.Peer{{HostName: "htpc", IPs: tc.ips, Online: true}},
			}
			agent := &fakeAgent{node: node, forwards: &fakeForwards{}, settings: newFakeSettings(map[string]any{"showTray": true})}
			controller, _ := newTestController(agent, func() {})

			devices := controller.Snapshot().Devices
			if len(devices) != 2 {
				t.Fatalf("got %d devices, want this machine and one peer", len(devices))
			}
			if devices[1].Address != tc.want {
				t.Errorf("the row offers %q, want %q", devices[1].Address, tc.want)
			}
		})
	}
}

// The copy action is the one whose whole result is outside app-tail, so the guard in front
// of it has to hold at the controller: a value the clipboard cannot usefully take must be
// refused here rather than reported as a copy that happened.
func TestTheControllerRefusesACopyThereIsNothingBehind(t *testing.T) {
	node := &fakeNode{status: tsnode.Status{BackendState: tsnode.StateRunning, Hostname: "laptop"}}
	agent := &fakeAgent{node: node, forwards: &fakeForwards{}, settings: newFakeSettings(map[string]any{"showTray": true})}
	controller, _ := newTestController(agent, func() {})

	err := controller.CopyToClipboard("")
	if err == nil {
		t.Fatal("copying nothing was reported as a successful copy")
	}
	if !strings.Contains(err.Error(), "nothing to copy") {
		t.Errorf("the refusal is %q, want it to say there was nothing to copy", err)
	}
}

// Before login there is no tailnet to list. That is a state, not a fault, and reporting
// it as one would put an error in the menu on every machine that has not logged in yet.
func TestATailnetThatIsNotUpYetListsNoDevicesAndReportsNoError(t *testing.T) {
	node := &fakeNode{status: tsnode.Status{BackendState: tsnode.StateNeedsLogin}, peersErr: tsnode.ErrNotRunning}
	agent := &fakeAgent{node: node, forwards: &fakeForwards{}, settings: newFakeSettings(map[string]any{"showTray": true})}
	controller, _ := newTestController(agent, func() {})

	snapshot := controller.Snapshot()
	if len(snapshot.Devices) != 0 {
		t.Errorf("listed %d devices with no tailnet up", len(snapshot.Devices))
	}
	if snapshot.LastError != "" {
		t.Errorf("the menu reports %q for a node that has simply not logged in", snapshot.LastError)
	}
}

// Any other reason the peers could not be read has to reach the menu: a submenu that is
// silently empty on a running node is indistinguishable from a tailnet of one.
func TestATailnetThatCouldNotBeReadSaysSoInTheMenu(t *testing.T) {
	node := &fakeNode{
		status:   tsnode.Status{BackendState: tsnode.StateRunning, Hostname: "laptop"},
		peersErr: errors.New("fetch tailnet status: connection refused"),
	}
	agent := &fakeAgent{node: node, forwards: &fakeForwards{}, settings: newFakeSettings(map[string]any{"showTray": true})}
	controller, _ := newTestController(agent, func() {})

	snapshot := controller.Snapshot()
	if !strings.Contains(snapshot.LastError, "connection refused") {
		t.Errorf("the menu reports %q, want the reason the devices could not be read", snapshot.LastError)
	}
}

// The node's own problem is both more specific and the likely reason the peer read
// failed, so it leads. The symptom is kept behind it rather than dropped: a menu that
// names one of two faults has told its reader everything else is fine, and they find the
// second one only by coming back.
func TestTheNodesOwnProblemLeadsTheDeviceListFailingBecauseOfIt(t *testing.T) {
	node := &fakeNode{
		status: tsnode.Status{
			BackendState: tsnode.StateStopped,
			Hostname:     "laptop",
			Problem:      "the auth key was rejected",
		},
		peersErr: errors.New("fetch tailnet status: connection refused"),
	}
	agent := &fakeAgent{node: node, forwards: &fakeForwards{}, settings: newFakeSettings(map[string]any{"showTray": true})}
	controller, _ := newTestController(agent, func() {})

	got := controller.Snapshot().LastError
	if !strings.HasPrefix(got, "the auth key was rejected") {
		t.Errorf("the menu reports %q, want the node's own problem first", got)
	}
	if !strings.Contains(got, "connection refused") {
		t.Errorf("the menu reports %q, dropping the device list that could not be read", got)
	}
}

// The tray offers the approval only while something waits, so the snapshot has to carry how
// many changes are waiting, and nothing when none are.
func TestTheSnapshotCountsTheChangesWaitingForAnAdministrator(t *testing.T) {
	waiting := &httpapi.ApprovalsView{Needs: []grants.PendingNeed{
		{Need: grants.Need{Kind: grants.KindRoute, Value: "203.0.113.0/24", Reason: "r"}},
		{Need: grants.Need{Kind: grants.KindSystemDNS, Reason: "r"}},
	}}
	agent := &fakeAgent{forwards: &fakeForwards{}, approvals: &fakeApprovals{pending: waiting}}
	controller, _ := newTestController(agent, func() {})
	if got := controller.Snapshot().ApprovalsPending; got != 2 {
		t.Errorf("ApprovalsPending = %d, want the 2 waiting changes", got)
	}

	idle, _ := newTestController(&fakeAgent{forwards: &fakeForwards{}, approvals: &fakeApprovals{}}, func() {})
	if got := idle.Snapshot().ApprovalsPending; got != 0 {
		t.Errorf("ApprovalsPending = %d with nothing waiting, want 0", got)
	}
}

func TestApprovingFromTheTrayRunsTheAgentsApproval(t *testing.T) {
	approvals := &fakeApprovals{pending: &httpapi.ApprovalsView{Needs: []grants.PendingNeed{
		{Need: grants.Need{Kind: grants.KindFullTunnel, Reason: "r"}},
	}}}
	controller, _ := newTestController(&fakeAgent{forwards: &fakeForwards{}, approvals: approvals}, func() {})

	if err := controller.ApproveNetworkChanges(); err != nil {
		t.Fatalf("ApproveNetworkChanges: %v", err)
	}
	if got := approvals.approveCount(); got != 1 {
		t.Errorf("the approval ran %d times, want once", got)
	}
}

// A dismissed prompt is reported, not swallowed: the tray shows the error, and the change
// stays waiting for the next try.
func TestADismissedPromptFromTheTrayReachesTheMenu(t *testing.T) {
	approvals := &fakeApprovals{err: httpapi.ErrApprovalDeclined}
	controller, _ := newTestController(&fakeAgent{forwards: &fakeForwards{}, approvals: approvals}, func() {})

	if err := controller.ApproveNetworkChanges(); !errors.Is(err, httpapi.ErrApprovalDeclined) {
		t.Errorf("ApproveNetworkChanges = %v, want the dismissal", err)
	}
}

func TestApprovingBeforeTheAgentHasStartedSaysSo(t *testing.T) {
	controller, _ := newTestController(&fakeAgent{forwards: &fakeForwards{}}, func() {})
	if err := controller.ApproveNetworkChanges(); err == nil || !strings.Contains(err.Error(), "not available yet") {
		t.Errorf("ApproveNetworkChanges = %v, want an error saying it is not available yet", err)
	}
}
