// SPDX-License-Identifier: MIT

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/access"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsblock"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/ipsfeed"
	"github.com/sellitus/app-tail/internal/peeraccount"
	"github.com/sellitus/app-tail/internal/presets"
	"github.com/sellitus/app-tail/internal/routing"
	"github.com/sellitus/app-tail/internal/sysproxy"
	"github.com/sellitus/app-tail/internal/telemetry"
	"github.com/sellitus/app-tail/internal/tsnode"
	"github.com/sellitus/app-tail/internal/tsproxy"
)

// fakeNode stands in for the tailnet identity. It records calls so tests can assert
// the handler did the work rather than replaying cached state.
type fakeNode struct {
	status     tsnode.Status
	peers      []tsnode.Peer
	peersErr   error
	loginErr   error
	logoutErr  error
	loginCalls int
	logoutCall int
}

func (f *fakeNode) Status() tsnode.Status { return f.status }

func (f *fakeNode) StartLogin(context.Context) error {
	f.loginCalls++
	if f.loginErr != nil {
		return f.loginErr
	}
	f.status.BackendState = tsnode.StateNeedsLogin
	f.status.AuthURL = fmt.Sprintf("https://login.example/auth/%d", f.loginCalls)
	return nil
}

func (f *fakeNode) Logout(context.Context) error {
	f.logoutCall++
	if f.logoutErr != nil {
		return f.logoutErr
	}
	f.status = tsnode.Status{BackendState: tsnode.StateNeedsLogin}
	return nil
}

func (f *fakeNode) Peers(context.Context) ([]tsnode.Peer, error) {
	if f.peersErr != nil {
		return nil, f.peersErr
	}
	return f.peers, nil
}

// fakeForwards is an in-memory forward registry with the same error contract as the
// real one: validation errors, ErrNotFound, and ConflictError.
type fakeForwards struct {
	items      []ForwardView
	allRunning bool

	suggestPort  int
	suggestErr   error
	lastSuggest  suggestArgs
	createCalled int
}

type suggestArgs struct {
	protocol  config.Protocol
	bindAddr  string
	preferred int
}

func (f *fakeForwards) List() []ForwardView { return f.items }

func (f *fakeForwards) index(id string) int {
	for i, v := range f.items {
		if v.ID == id {
			return i
		}
	}
	return -1
}

func (f *fakeForwards) Get(id string) (ForwardView, error) {
	i := f.index(id)
	if i < 0 {
		return ForwardView{}, fmt.Errorf("forward %q: %w", id, config.ErrNotFound)
	}
	return f.items[i], nil
}

func (f *fakeForwards) Create(_ context.Context, spec ForwardSpec) (ForwardView, error) {
	f.createCalled++
	fwd := config.Forward{
		ID:       fmt.Sprintf("fwd_%d", len(f.items)+1),
		BindAddr: config.DefaultBindAddr,
		Enabled:  true,
	}
	applySpec(&fwd, spec)
	if err := config.ValidateForward(fwd); err != nil {
		return ForwardView{}, err
	}
	for _, existing := range f.items {
		if existing.Enabled && fwd.Enabled &&
			existing.Protocol == fwd.Protocol && existing.ListenPort == fwd.ListenPort &&
			existing.BindAddr == fwd.BindAddr {
			return ForwardView{}, &config.ConflictError{
				Endpoint:  config.Endpoint(fwd),
				OtherID:   existing.ID,
				OtherName: existing.Name,
			}
		}
	}
	view := viewOf(fwd)
	f.items = append(f.items, view)
	return view, nil
}

func (f *fakeForwards) Update(_ context.Context, id string, spec ForwardSpec) (ForwardView, error) {
	i := f.index(id)
	if i < 0 {
		return ForwardView{}, fmt.Errorf("forward %q: %w", id, config.ErrNotFound)
	}
	fwd := f.items[i].Forward
	applySpec(&fwd, spec)
	if err := config.ValidateForward(fwd); err != nil {
		return ForwardView{}, err
	}
	f.items[i] = viewOf(fwd)
	return f.items[i], nil
}

func (f *fakeForwards) Delete(_ context.Context, id string) error {
	i := f.index(id)
	if i < 0 {
		return fmt.Errorf("forward %q: %w", id, config.ErrNotFound)
	}
	f.items = append(f.items[:i], f.items[i+1:]...)
	return nil
}

func (f *fakeForwards) SetEnabled(_ context.Context, id string, enabled bool) (ForwardView, error) {
	i := f.index(id)
	if i < 0 {
		return ForwardView{}, fmt.Errorf("forward %q: %w", id, config.ErrNotFound)
	}
	f.items[i].Enabled = enabled
	return f.items[i], nil
}

func (f *fakeForwards) SuggestPort(protocol config.Protocol, bindAddr string, preferred int) (int, error) {
	f.lastSuggest = suggestArgs{protocol: protocol, bindAddr: bindAddr, preferred: preferred}
	if f.suggestErr != nil {
		return 0, f.suggestErr
	}
	return f.suggestPort, nil
}

func (f *fakeForwards) AllRunning() bool { return f.allRunning }

func applySpec(fwd *config.Forward, spec ForwardSpec) {
	if spec.Name != nil {
		fwd.Name = *spec.Name
	}
	if spec.TunnelID != nil {
		fwd.TunnelID = *spec.TunnelID
	}
	if spec.Direction != nil {
		fwd.Direction = *spec.Direction
	}
	if spec.Protocol != nil {
		fwd.Protocol = *spec.Protocol
	}
	if spec.BindAddr != nil {
		fwd.BindAddr = *spec.BindAddr
	}
	if spec.ListenPort != nil {
		fwd.ListenPort = *spec.ListenPort
	}
	if spec.Target != nil {
		fwd.Target = *spec.Target
	}
	if spec.Enabled != nil {
		fwd.Enabled = *spec.Enabled
	}
	if spec.UDPTimeoutSec != nil {
		fwd.UDPTimeoutSec = *spec.UDPTimeoutSec
	}
}

func viewOf(fwd config.Forward) ForwardView {
	return ForwardView{Forward: fwd, State: "stopped", Endpoint: config.Endpoint(fwd)}
}

// fakePresets is an in-memory catalog that refuses to delete built-ins, matching
// the real store's contract.
type fakePresets struct {
	user []config.Preset
}

func (f *fakePresets) List() []config.Preset { return presets.Catalog(f.user) }

func (f *fakePresets) Create(p config.Preset) (config.Preset, error) {
	if strings.TrimSpace(p.Name) == "" {
		return config.Preset{}, &config.ValidationError{Field: "name", Message: "is required"}
	}
	p.ID = fmt.Sprintf("user-%d", len(f.user)+1)
	f.user = append(f.user, p)
	return p, nil
}

func (f *fakePresets) Delete(id string) error {
	for i, p := range f.user {
		if p.ID == id {
			f.user = append(f.user[:i], f.user[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("preset %q: %w", id, config.ErrNotFound)
}

// fakeSettings drives the real registry so HTTP-layer tests exercise genuine
// redaction and patch-apply logic; it only stubs the resolved restart impact.
type fakeSettings struct {
	// The whole document, because some settings keys name a field of the primary
	// connection now. A fake holding only the settings half would serve and accept a
	// narrower surface than the agent does, and every redirect test would pass against a
	// fake that never exercised the redirect.
	doc          *config.Config
	nodeRestart  bool
	uiRelisten   bool
	appRestart   bool
	adminRestart bool
	deferred     []DeferredField
	err          error
}

func newFakeSettings() *fakeSettings { return &fakeSettings{doc: config.Defaults()} }

// stored is the settings half of the document, for a test naming a key that stayed there.
func (f *fakeSettings) stored() *config.Settings { return &f.doc.Settings }

// tailnet is the primary connection's tailnet block, for a test naming a key that moved
// onto it. It is a pointer into the document, so a test writes through it.
func (f *fakeSettings) tailnet(t *testing.T) *config.TailscaleTunnel {
	t.Helper()
	for i := range f.doc.Tunnels {
		if f.doc.Tunnels[i].ID != config.PrimaryTunnelID {
			continue
		}
		if f.doc.Tunnels[i].Tailscale == nil {
			f.doc.Tunnels[i].Tailscale = &config.TailscaleTunnel{}
		}
		return f.doc.Tunnels[i].Tailscale
	}
	t.Fatalf("the fake document carries no %q connection", config.PrimaryTunnelID)
	return nil
}

// proxyInstance is the default proxy instance, for a test naming a key that moved onto it.
// It is a pointer into the document, so a test writes through it.
func (f *fakeSettings) proxyInstance(t *testing.T) *config.ProxyInstance {
	t.Helper()
	for i := range f.doc.Proxies {
		if f.doc.Proxies[i].ID == config.DefaultProxyID {
			return &f.doc.Proxies[i]
		}
	}
	t.Fatalf("the fake document carries no %q proxy", config.DefaultProxyID)
	return nil
}

func (f *fakeSettings) Get() map[string]any {
	return config.SettingsViewOf(f.doc)
}

func (f *fakeSettings) Schema() []config.FieldSchema {
	schema := config.SettingsSchemaFor(f.doc.Settings)
	schema = append(schema, config.LegacyTailnetSchema(&f.doc.Settings)...)
	return append(schema, config.LegacyProxySchema(&f.doc.Settings)...)
}

func (f *fakeSettings) Update(_ context.Context, patch map[string]json.RawMessage) (map[string]any, SettingsUpdateResult, error) {
	if f.err != nil {
		return nil, SettingsUpdateResult{}, f.err
	}
	if err := config.ApplyPatchTo(f.doc, patch); err != nil {
		return nil, SettingsUpdateResult{}, err
	}
	return f.Get(), SettingsUpdateResult{
		NodeRestart:  f.nodeRestart,
		UIRelisten:   f.uiRelisten,
		AppRestart:   f.appRestart,
		AdminRestart: f.adminRestart,
		Deferred:     f.deferred,
	}, nil
}

// fakePrefs serves a fixed mirror, so the HTTP layer is tested on the shape it puts on
// the wire rather than on how the agent decides what goes in it.
type fakePrefs struct{ view PrefsView }

func (f *fakePrefs) View() PrefsView { return f.view }

// fakeRestarter records restart calls and can simulate a rebuild failure.
type fakeRestarter struct {
	calls int
	err   error
}

func (f *fakeRestarter) RestartNode(context.Context) error {
	f.calls++
	return f.err
}

// fakeTraffic answers the rolling activity view.
type fakeTraffic struct {
	view TrafficView
	// lanes are the breakdowns this fake knows, keyed by lane name. A lane that is not in it
	// is answered the way the real one answers a name it does not know.
	lanes          map[string]TrafficBreakdown
	calls          int
	breakdownCalls int
}

func (f *fakeTraffic) View(context.Context) TrafficView {
	f.calls++
	return f.view
}

func (f *fakeTraffic) Breakdown(_ context.Context, lane string) (TrafficBreakdown, error) {
	f.breakdownCalls++
	out, ok := f.lanes[lane]
	if !ok {
		return TrafficBreakdown{}, fmt.Errorf("traffic breakdown %q: %w", lane, config.ErrNotFound)
	}
	return out, nil
}

// fakeLifecycle records process-restart and process-stop requests and can simulate an agent
// that is already on its way down.
type fakeLifecycle struct {
	calls     int
	stopCalls int
	err       error
	stopErr   error
}

func (f *fakeLifecycle) RestartProcess() error {
	f.calls++
	return f.err
}

func (f *fakeLifecycle) StopProcess() error {
	f.stopCalls++
	return f.stopErr
}

// fakeAutostart models the login item, including a platform that cannot provide it.
type fakeAutostart struct {
	enabled    bool
	problem    string
	setCalls   int
	setErr     error
	queryErr   error
	lastWanted bool
}

func (f *fakeAutostart) Enabled() (bool, error) {
	if f.queryErr != nil {
		return false, f.queryErr
	}
	return f.enabled, nil
}

func (f *fakeAutostart) SetEnabled(enabled bool) error {
	f.setCalls++
	f.lastWanted = enabled
	if f.setErr != nil {
		return f.setErr
	}
	f.enabled = enabled
	return nil
}

func (f *fakeAutostart) Problem() string { return f.problem }

// fakePolicy records the request it receives so a test can prove the handler
// forwarded the OAuth credential to the facade without the HTTP response ever
// echoing it back.
type fakePolicy struct {
	lastReq      PolicyBootstrapRequest
	previewCalls int
	applyCalls   int
	view         PolicyPlanView
	err          error
}

func (f *fakePolicy) Preview(_ context.Context, req PolicyBootstrapRequest) (PolicyPlanView, error) {
	f.previewCalls++
	f.lastReq = req
	if f.err != nil {
		return PolicyPlanView{}, f.err
	}
	return f.view, nil
}

func (f *fakePolicy) Apply(_ context.Context, req PolicyBootstrapRequest) (PolicyPlanView, error) {
	f.applyCalls++
	f.lastReq = req
	if f.err != nil {
		return PolicyPlanView{}, f.err
	}
	return f.view, nil
}

// panickingForwards is the handler bug the panic barrier exists for: a dependency that
// blows up mid-request rather than returning an error.
type panickingForwards struct {
	Forwards
	panicOn string
}

func (p *panickingForwards) List() []ForwardView {
	panic("forward registry exploded with secret=" + p.panicOn)
}

func (p *panickingForwards) AllRunning() bool {
	panic("readiness probe exploded")
}

// brokenFS fails Open with something other than fs.ErrNotExist, which is the difference
// between "this asset is not embedded" and "the embedded filesystem is damaged".
type brokenFS struct {
	fs.FS
	err error
}

func (b brokenFS) Open(name string) (fs.File, error) {
	if name == "index.html" {
		return b.FS.Open(name)
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: b.err}
}

// unseekableFile is a file that reads but cannot seek, which http.ServeContent requires.
type unseekableFile struct {
	fs.File
}

// unseekableFS serves files that cannot Seek.
type unseekableFS struct {
	fs.FS
}

func (u unseekableFS) Open(name string) (fs.File, error) {
	f, err := u.FS.Open(name)
	if err != nil {
		return nil, err
	}
	if name == "index.html" {
		return f, nil
	}
	return unseekableFile{File: f}, nil
}

// testServer builds a Server over the given deps with all fakes wired by default.
// fakeProxy stands in for the tailnet proxy. Its status is a field so a test can put
// the proxy into each of the states the capability logic distinguishes.
type fakeProxy struct {
	status tsproxy.Status
	script string
	probe  ProxyProbeResult
	// pacErr and probeErr make the two live-state reads fail, which is the difference
	// between a broken proxy and a destination that simply cannot be reached.
	pacErr   error
	probeErr error
	probed   []string
}

func (f *fakeProxy) Status() tsproxy.Status { return f.status }

func (f *fakeProxy) PAC(context.Context) (string, error) {
	if f.pacErr != nil {
		return "", f.pacErr
	}
	return f.script, nil
}

func (f *fakeProxy) Probe(_ context.Context, address string) (ProxyProbeResult, error) {
	f.probed = append(f.probed, address)
	if f.probeErr != nil {
		return ProxyProbeResult{}, f.probeErr
	}
	result := f.probe
	result.Address = address
	return result, nil
}

type fakeExitNode struct {
	view       ExitNodeView
	suggestion ExitNodeSuggestion
	// suggestErr is the refusal a control-plane round trip comes back with, which is a
	// different situation from a tailnet that simply has nothing to suggest.
	suggestErr error
	suggested  int
}

func (f *fakeExitNode) View() ExitNodeView { return f.view }

func (f *fakeExitNode) Suggest(context.Context) (ExitNodeSuggestion, error) {
	f.suggested++
	if f.suggestErr != nil {
		return ExitNodeSuggestion{}, f.suggestErr
	}
	return f.suggestion, nil
}

// fakeTunnels holds connections as a slice, because their order is what every surface
// lists them in and a map would lose it.
type fakeTunnels struct {
	held []TunnelView
	// updateErr is the refusal a write comes back with, which is how a rename onto a slug
	// another connection already answers for reaches this layer.
	updateErr error
	patched   map[string]json.RawMessage
	// created is the last connection this was asked to add, and createErr the refusal
	// instead -- an unknown protocol is refused before anything is stored.
	created   *TunnelSpec
	createErr error
	// deleted is every connection this was asked to remove, in order.
	deleted []string
	// peers is the device list per connection, and peersErr the refusal a connection that
	// is not running comes back with.
	peers    map[string][]tsnode.Peer
	peersErr error
	// imported is the last configuration file this was asked to read, and importErr the
	// refusal instead -- a file naming a directive this app cannot honour is refused whole.
	imported  string
	importErr error
	// retried is every connection this was asked to build again, in order, and retryErr the
	// refusal instead.
	retried  []string
	retryErr error
}

func newFakeTunnels() *fakeTunnels {
	return &fakeTunnels{held: []TunnelView{{
		ID: config.PrimaryTunnelID, Type: config.TunnelTailscale, TypeLabel: "Tailscale",
		Name: "Tailnet", Slug: config.PrimaryTunnelSlug, Enabled: true,
		Settings:   map[string]any{"name": "Tailnet", "slug": config.PrimaryTunnelSlug, "type": "tailscale"},
		State:      "connected",
		StateLabel: "Connected",
		Live:       true,
		Addrs:      []string{"100.64.0.1"},
		Names:      []string{"workstation.example.ts.net"},
	}}}
}

func (f *fakeTunnels) List() []TunnelView { return f.held }

func (f *fakeTunnels) Get(id string) (TunnelView, error) {
	for _, held := range f.held {
		if held.ID == id {
			return held, nil
		}
	}
	return TunnelView{}, fmt.Errorf("connection %q: %w", id, config.ErrNotFound)
}

func (f *fakeTunnels) Schema() []config.FieldSchema {
	s := config.Defaults().Settings
	return config.TunnelSchema(&s)
}

func (f *fakeTunnels) Peers(_ context.Context, id string) ([]tsnode.Peer, error) {
	if _, err := f.Get(id); err != nil {
		return nil, err
	}
	if f.peersErr != nil {
		return nil, f.peersErr
	}
	return f.peers[id], nil
}

func (f *fakeTunnels) Types() []TunnelTypeInfo {
	return []TunnelTypeInfo{{Value: config.TunnelTailscale, Label: "Tailscale"}}
}

func (f *fakeTunnels) Create(_ context.Context, spec TunnelSpec) (TunnelView, error) {
	f.created = &spec
	if f.createErr != nil {
		return TunnelView{}, f.createErr
	}
	name := spec.Name
	if name == "" {
		name = spec.Type.Label()
	}
	slug := spec.Slug
	if slug == "" {
		slug = config.SuggestSlug(name, nil)
	}
	added := TunnelView{
		ID: "tn_added", Type: spec.Type, TypeLabel: spec.Type.Label(),
		Name: name, Slug: slug, Enabled: true,
		Settings:   map[string]any{"name": name, "slug": slug, "type": string(spec.Type)},
		State:      "off",
		StateLabel: "Off",
	}
	f.held = append(f.held, added)
	return added, nil
}

func (f *fakeTunnels) Import(_ context.Context, id, file string) (TunnelView, error) {
	f.imported = file
	if f.importErr != nil {
		return TunnelView{}, f.importErr
	}
	return f.Get(id)
}

func (f *fakeTunnels) Retry(_ context.Context, id string) (TunnelView, error) {
	f.retried = append(f.retried, id)
	if f.retryErr != nil {
		return TunnelView{}, f.retryErr
	}
	return f.Get(id)
}

func (f *fakeTunnels) Delete(_ context.Context, id string) error {
	f.deleted = append(f.deleted, id)
	for i, held := range f.held {
		if held.ID == id {
			f.held = append(f.held[:i], f.held[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("connection %q: %w", id, config.ErrNotFound)
}

func (f *fakeTunnels) Update(_ context.Context, id string, patch map[string]json.RawMessage) (TunnelView, error) {
	f.patched = patch
	if f.updateErr != nil {
		return TunnelView{}, f.updateErr
	}
	for i := range f.held {
		if f.held[i].ID != id {
			continue
		}
		if raw, ok := patch["name"]; ok {
			var name string
			if err := json.Unmarshal(raw, &name); err != nil {
				return TunnelView{}, err
			}
			f.held[i].Name = name
			f.held[i].Settings["name"] = name
		}
		return f.held[i], nil
	}
	return TunnelView{}, fmt.Errorf("connection %q: %w", id, config.ErrNotFound)
}

// fakeProxies holds instances as a slice, because their order is what every surface lists
// them in and a map would lose it.
type fakeProxies struct {
	held []ProxyInstanceView
	// created is the last instance this was asked to add, and createErr the refusal instead
	// -- an unnamed instance is refused before anything is stored.
	created   *ProxyInstanceSpec
	createErr error
	patched   map[string]json.RawMessage
	// updateErr is the refusal a write comes back with, which is how a move onto a port
	// another instance already asked for reaches this layer.
	updateErr error
	// rules is the last ordered list this was asked to store, and rulesErr the refusal
	// instead -- a rule naming a connection that is not configured is refused whole.
	rules    []access.Rule
	rulesErr error
	deleted  []string
	// verdict is what a test says an instance would do, and tested every destination it was
	// asked about.
	verdict   ProxyTestResult
	testErr   error
	tested    []ProxyTestRequest
	deleteErr error
}

func newFakeProxies() *fakeProxies {
	return &fakeProxies{held: []ProxyInstanceView{{
		ID: config.DefaultProxyID, Name: "Default", Slug: config.DefaultProxySlug,
		Enabled: true, Removable: false, Default: true,
		Settings: map[string]any{
			"name": "Default", "slug": config.DefaultProxySlug,
			"proxy.listenAddr": "127.0.0.1:1080",
		},
		Rules: []access.Rule{{
			ID: "ar_connection", Action: access.Allow, Tunnel: config.PrimaryTunnelID,
			Note: "Everything on this connection.",
		}},
		Reach:          []string{"allows any port anywhere, over Tailnet"},
		Listening:      "127.0.0.1:1080",
		ConfiguredAddr: "127.0.0.1:1080",
		Capability:     Capability{Available: true},
	}}}
}

func (f *fakeProxies) List() []ProxyInstanceView { return f.held }

func (f *fakeProxies) Get(id string) (ProxyInstanceView, error) {
	for _, held := range f.held {
		if held.ID == id {
			return held, nil
		}
	}
	return ProxyInstanceView{}, fmt.Errorf("proxy %q: %w", id, config.ErrNotFound)
}

func (f *fakeProxies) Schema() []config.FieldSchema {
	s := config.Defaults().Settings
	return config.ProxySchema(&s)
}

func (f *fakeProxies) Create(_ context.Context, spec ProxyInstanceSpec) (ProxyInstanceView, error) {
	f.created = &spec
	if f.createErr != nil {
		return ProxyInstanceView{}, f.createErr
	}
	slug := spec.Slug
	if slug == "" {
		slug = config.SuggestSlug(spec.Name, nil)
	}
	added := ProxyInstanceView{
		ID: "px_added", Name: spec.Name, Slug: slug, Enabled: true, Removable: true,
		Settings: map[string]any{"name": spec.Name, "slug": slug},
		Rules:    []access.Rule{},
		Reach:    []string{"nothing: this proxy has no rules, and it carries only what a rule allows"},
		// Bound somewhere of its own, which is what an added instance is: the commands offered
		// for it are only meaningful against an address something can actually be pointed at.
		Listening:      "127.0.0.1:1081",
		ConfiguredAddr: "127.0.0.1:1081",
		Capability:     Capability{Available: true},
	}
	f.held = append(f.held, added)
	return added, nil
}

func (f *fakeProxies) Update(_ context.Context, id string, patch map[string]json.RawMessage) (ProxyInstanceView, error) {
	f.patched = patch
	if f.updateErr != nil {
		return ProxyInstanceView{}, f.updateErr
	}
	return f.Get(id)
}

func (f *fakeProxies) SetRules(_ context.Context, id string, rules []access.Rule) (ProxyInstanceView, error) {
	f.rules = rules
	if f.rulesErr != nil {
		return ProxyInstanceView{}, f.rulesErr
	}
	for i := range f.held {
		if f.held[i].ID != id {
			continue
		}
		f.held[i].Rules = rules
		return f.held[i], nil
	}
	return ProxyInstanceView{}, fmt.Errorf("proxy %q: %w", id, config.ErrNotFound)
}

func (f *fakeProxies) Delete(_ context.Context, id string) error {
	f.deleted = append(f.deleted, id)
	if f.deleteErr != nil {
		return f.deleteErr
	}
	for i, held := range f.held {
		if held.ID == id {
			f.held = append(f.held[:i], f.held[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("proxy %q: %w", id, config.ErrNotFound)
}

func (f *fakeProxies) Test(_ context.Context, id string, req ProxyTestRequest) (ProxyTestResult, error) {
	if _, err := f.Get(id); err != nil {
		return ProxyTestResult{}, err
	}
	f.tested = append(f.tested, req)
	if f.testErr != nil {
		return ProxyTestResult{}, f.testErr
	}
	result := f.verdict
	result.Address = req.Address
	return result, nil
}

// fakeRouting is the per-destination rules. It keeps the list it was given rather than a
// canned view, because the endpoint's whole job is that a caller reads back what it wrote.
type fakeRouting struct {
	view     RoutingView
	setErr   error
	written  [][]routing.Rule
	check    RoutingCheckResult
	checkErr error
}

func (f *fakeRouting) View() RoutingView { return f.view }

func (f *fakeRouting) SetRules(_ context.Context, rules []routing.Rule) (RoutingView, error) {
	f.written = append(f.written, rules)
	if f.setErr != nil {
		return RoutingView{}, f.setErr
	}
	f.view.Rules = rules
	return f.view, nil
}

func (f *fakeRouting) Check(req RoutingCheckRequest) (RoutingCheckResult, error) {
	if f.checkErr != nil {
		return RoutingCheckResult{}, f.checkErr
	}
	result := f.check
	result.Destination = req.Destination
	return result, nil
}

type fakeRoutes struct {
	view RoutesView
	// check is what probing the devices carrying each accepted route found, and checkErr
	// the refusal instead -- a different situation from a tailnet with no routes to check.
	check    RouteCheckResult
	checkErr error
	checked  int
}

func (f *fakeRoutes) View(context.Context) RoutesView { return f.view }

func (f *fakeRoutes) Check(context.Context) (RouteCheckResult, error) {
	f.checked++
	if f.checkErr != nil {
		return RouteCheckResult{}, f.checkErr
	}
	return f.check, nil
}

type fakeLock struct {
	view LockView
	// log is the key authority's history, and logErr the refusal instead -- a tailnet whose
	// history could not be read is not one that never changed.
	log    []LockUpdate
	logErr error
	reads  int

	signErr    error
	signed     [][2]string
	disableErr error
	disabled   int
}

func (f *fakeLock) View(context.Context) LockView { return f.view }

func (f *fakeLock) Log(context.Context) ([]LockUpdate, error) {
	f.reads++
	if f.logErr != nil {
		return nil, f.logErr
	}
	return f.log, nil
}

func (f *fakeLock) Sign(_ context.Context, nodeKey, rotationKey string) error {
	if f.signErr != nil {
		return f.signErr
	}
	f.signed = append(f.signed, [2]string{nodeKey, rotationKey})
	// The view a client renders afterwards is taken after the signature lands, so the
	// fake has to move too rather than answer with the state it held before.
	f.view.Signed = true
	return nil
}

func (f *fakeLock) DisableLocal(context.Context) error {
	f.disabled++
	if f.disableErr != nil {
		return f.disableErr
	}
	f.view.Enabled = false
	return nil
}

type fakeDNS struct {
	view DNSView
	// setups counts the arrangements asked for, and setupErr is the refusal instead: a
	// machine that declined the password prompt is the state the route exists to report.
	setups   int
	setupErr error
}

func (f *fakeDNS) View(context.Context) DNSView { return f.view }

func (f *fakeDNS) SetUpSystem(context.Context) error {
	f.setups++
	return f.setupErr
}

// fakeProfiles is the resolver catalog, with the same rules the real one enforces about
// what a client may not do: mint a built-in, edit one, or delete one.
type fakeProfiles struct {
	user []config.DNSProfile
	// deletes records the ids removed, so a test can tell a refusal from a silent no-op.
	deletes []string
}

func (f *fakeProfiles) List() []config.DNSProfile { return dnsprofiles.Catalog(f.user) }

func (f *fakeProfiles) Create(p config.DNSProfile) (config.DNSProfile, error) {
	if err := dnsprofiles.Validate(p); err != nil {
		return config.DNSProfile{}, &config.ValidationError{Field: "dnsProfile", Message: err.Error()}
	}
	p.ID = fmt.Sprintf("user-%d", len(f.user)+1)
	f.user = append(f.user, p)
	return p, nil
}

func (f *fakeProfiles) Update(id string, p config.DNSProfile) (config.DNSProfile, error) {
	if dnsprofiles.IsBuiltIn(id) {
		return config.DNSProfile{}, &config.ValidationError{
			Field: "dnsProfile", Message: fmt.Sprintf("%q is a built-in resolver profile and cannot be edited", id),
		}
	}
	if err := dnsprofiles.Validate(p); err != nil {
		return config.DNSProfile{}, &config.ValidationError{Field: "dnsProfile", Message: err.Error()}
	}
	for i, existing := range f.user {
		if existing.ID == id {
			p.ID = id
			f.user[i] = p
			return p, nil
		}
	}
	return config.DNSProfile{}, fmt.Errorf("resolver profile %q: %w", id, config.ErrNotFound)
}

func (f *fakeProfiles) Delete(_ context.Context, id string) error {
	if dnsprofiles.IsBuiltIn(id) {
		return &config.ValidationError{
			Field: "dnsProfile", Message: fmt.Sprintf("%q is a built-in resolver profile and cannot be deleted", id),
		}
	}
	for i, p := range f.user {
		if p.ID == id {
			f.user = append(f.user[:i], f.user[i+1:]...)
			f.deletes = append(f.deletes, id)
			return nil
		}
	}
	return fmt.Errorf("resolver profile %q: %w", id, config.ErrNotFound)
}

// fakeIPS is traffic inspection as the routes see it: a view a test can pose, a record of
// the controls that are not settings, and the same rules the real one enforces about a
// shipped feed -- it may be switched on and off, and nothing else.
type fakeIPS struct {
	view IPSView
	// refreshes counts the downloads asked for, and refreshErr is the refusal instead: a
	// feed that would not download is the state the button exists to report.
	refreshes  int
	refreshErr error
	// paused is the duration last asked for, and resumes counts the ends.
	paused  time.Duration
	resumes int
	// checked is the last destination asked about, so a test can prove the query reached
	// the agent rather than only that something answered.
	checked string
	user    []config.IPSFeed
	deletes []string
	// applied is the last rung of the ladder asked for, so a test can prove the level the
	// request named is the one the agent was given.
	applied string
	// rootRemovals counts the removals that reached the agent, and removeErr is the refusal
	// instead.
	rootRemovals int
	removeErr    error
}

func (f *fakeIPS) View() IPSView { return f.view }

func (f *fakeIPS) RemoveInterceptRoot() error {
	if f.removeErr != nil {
		return f.removeErr
	}
	f.rootRemovals++
	f.view.Intercept.Fingerprint = ""
	return nil
}

func (f *fakeIPS) Refresh(context.Context) error {
	f.refreshes++
	return f.refreshErr
}

func (f *fakeIPS) CreateFeed(feed config.IPSFeed) (config.IPSFeed, error) {
	if err := ipsfeed.Validate(feed); err != nil {
		return config.IPSFeed{}, &config.ValidationError{Field: "ipsFeed", Message: err.Error()}
	}
	feed.ID = fmt.Sprintf("user-%d", len(f.user)+1)
	f.user = append(f.user, feed)
	return feed, nil
}

func (f *fakeIPS) UpdateFeed(id string, feed config.IPSFeed) (config.IPSFeed, error) {
	if ipsfeed.IsBuiltIn(id) {
		return config.IPSFeed{}, &config.ValidationError{
			Field: "ipsFeed", Message: fmt.Sprintf("%q ships with app-tail and cannot be edited", id),
		}
	}
	if err := ipsfeed.Validate(feed); err != nil {
		return config.IPSFeed{}, &config.ValidationError{Field: "ipsFeed", Message: err.Error()}
	}
	for i, existing := range f.user {
		if existing.ID == id {
			feed.ID = id
			f.user[i] = feed
			return feed, nil
		}
	}
	return config.IPSFeed{}, fmt.Errorf("inspection feed %q: %w", id, config.ErrNotFound)
}

func (f *fakeIPS) DeleteFeed(_ context.Context, id string) error {
	if ipsfeed.IsBuiltIn(id) {
		return &config.ValidationError{
			Field: "ipsFeed", Message: fmt.Sprintf("%q ships with app-tail and cannot be deleted", id),
		}
	}
	for i, feed := range f.user {
		if feed.ID == id {
			f.user = append(f.user[:i], f.user[i+1:]...)
			f.deletes = append(f.deletes, id)
			return nil
		}
	}
	return fmt.Errorf("inspection feed %q: %w", id, config.ErrNotFound)
}

func (f *fakeIPS) ApplyPreset(_ context.Context, id string) error {
	preset, ok := ipsfeed.PresetByID(id)
	if !ok {
		return &config.ValidationError{Field: "preset", Message: fmt.Sprintf("%q is not one of the levels", id)}
	}
	f.applied = preset.ID
	f.view.Preset = preset.ID
	return nil
}

func (f *fakeIPS) Pause(d time.Duration) time.Time {
	f.paused = d
	return time.Date(2026, 8, 31, 12, 15, 0, 0, time.UTC)
}

func (f *fakeIPS) Resume() { f.resumes++ }

func (f *fakeIPS) Check(dest string) IPSCheckView {
	f.checked = dest
	if dest == "10.1.2.9" {
		return IPSCheckView{
			Destination: dest, Matched: true, Refused: true,
			Signal: "destination", Value: "10.1.2.0/24", Source: "your own entries",
			Reason: "the address is in 10.1.2.0/24, which is named by your own entries, and is refused",
		}
	}
	return IPSCheckView{Destination: dest, Reason: "No rule names this, so it is carried."}
}

// fakeDNSBlock is name blocking, with the rules the real one enforces about a shipped
// list: it may be switched on and off, and nothing else.
type fakeDNSBlock struct {
	view DNSBlockView
	// refreshes counts the downloads asked for, and refreshErr is the refusal instead: a
	// list that would not download is the state the button exists to report.
	refreshes  int
	refreshErr error
	// paused is the duration last asked for, and resumes counts the ends.
	paused  time.Duration
	resumes int
	user    []config.Blocklist
	deletes []string
	// applied is the last level asked for, which is what a preset request has to carry
	// through to the agent for the switch to mean anything.
	applied string
}

func (f *fakeDNSBlock) View() DNSBlockView { return f.view }

func (f *fakeDNSBlock) Refresh(context.Context) error {
	f.refreshes++
	return f.refreshErr
}

func (f *fakeDNSBlock) Pause(d time.Duration) time.Time {
	f.paused = d
	return time.Date(2026, 8, 31, 12, 15, 0, 0, time.UTC)
}

func (f *fakeDNSBlock) Resume() { f.resumes++ }

func (f *fakeDNSBlock) Check(name string) DNSBlockCheckView {
	if name == "doubleclick.net" {
		return DNSBlockCheckView{Name: name, Blocked: true, List: "Hagezi Pro", Reason: "on Hagezi Pro"}
	}
	return DNSBlockCheckView{Name: name, Reason: "not on any of the names the lists you turned on hold"}
}

func (f *fakeDNSBlock) ApplyPreset(_ context.Context, id string) error {
	preset, ok := dnsblock.PresetByID(id)
	if !ok {
		return &config.ValidationError{Field: "preset", Message: fmt.Sprintf("%q is not one of the levels", id)}
	}
	f.applied = preset.ID
	f.view.Preset = preset.ID
	return nil
}

func (f *fakeDNSBlock) CreateList(l config.Blocklist) (config.Blocklist, error) {
	if err := dnsblock.Validate(l); err != nil {
		return config.Blocklist{}, &config.ValidationError{Field: "blocklist", Message: err.Error()}
	}
	l.ID = fmt.Sprintf("user-%d", len(f.user)+1)
	f.user = append(f.user, l)
	return l, nil
}

func (f *fakeDNSBlock) UpdateList(id string, l config.Blocklist) (config.Blocklist, error) {
	if dnsblock.IsBuiltIn(id) {
		return config.Blocklist{}, &config.ValidationError{
			Field: "blocklist", Message: fmt.Sprintf("%q ships with app-tail and cannot be edited", id),
		}
	}
	if err := dnsblock.Validate(l); err != nil {
		return config.Blocklist{}, &config.ValidationError{Field: "blocklist", Message: err.Error()}
	}
	for i, existing := range f.user {
		if existing.ID == id {
			l.ID = id
			f.user[i] = l
			return l, nil
		}
	}
	return config.Blocklist{}, fmt.Errorf("blocklist %q: %w", id, config.ErrNotFound)
}

func (f *fakeDNSBlock) DeleteList(_ context.Context, id string) error {
	if dnsblock.IsBuiltIn(id) {
		return &config.ValidationError{
			Field: "blocklist", Message: fmt.Sprintf("%q ships with app-tail and cannot be deleted", id),
		}
	}
	for i, l := range f.user {
		if l.ID == id {
			f.user = append(f.user[:i], f.user[i+1:]...)
			f.deletes = append(f.deletes, id)
			return nil
		}
	}
	return fmt.Errorf("blocklist %q: %w", id, config.ErrNotFound)
}

type fakeSysProxy struct{ view SystemProxyView }

func (f *fakeSysProxy) View() SystemProxyView { return f.view }

type fakeAutoMap struct {
	view AutoMapView
	// removed is how many assignments forgetting drops, and forgetErr the refusal
	// instead -- a module that could not write the file is not one with nothing to
	// forget, and reporting the two the same way hides a failing disk.
	removed   int
	forgetErr error
	forgets   int
}

func (f *fakeAutoMap) View() AutoMapView { return f.view }

func (f *fakeAutoMap) Forget(context.Context) (int, error) {
	f.forgets++
	if f.forgetErr != nil {
		return 0, f.forgetErr
	}
	// The view a client renders afterwards is the one taken after the drop, so the
	// fake has to move too rather than answer with what it held before.
	f.view.Stored -= f.removed
	return f.removed, nil
}

// fakeTelemetry stands in for the agent's log. It records the query it was asked, which
// is what lets a test assert that a filter arriving as a query string reached the store
// as the filter it names rather than as an empty one.
type fakeTelemetry struct {
	view TelemetryView
	page telemetry.EventPage
	err  error

	asked   telemetry.EventQuery
	queries int
}

func (f *fakeTelemetry) View(context.Context) TelemetryView { return f.view }

func (f *fakeTelemetry) Events(_ context.Context, q telemetry.EventQuery) (telemetry.EventPage, error) {
	f.asked = q
	f.queries++
	if f.err != nil {
		return telemetry.EventPage{}, f.err
	}
	return f.page, nil
}

type harness struct {
	server    *Server
	node      *fakeNode
	tunnels   *fakeTunnels
	forwards  *fakeForwards
	presets   *fakePresets
	settings  *fakeSettings
	autostart *fakeAutostart
	iface     *fakeInterfaceSetup
	policy    *fakePolicy
	restart   *fakeRestarter
	lifecycle *fakeLifecycle
	traffic   *fakeTraffic
	proxy     *fakeProxy
	proxies   *fakeProxies
	sysProxy  *fakeSysProxy
	prefs     *fakePrefs
	exitNode  *fakeExitNode
	routes    *fakeRoutes
	routing   *fakeRouting
	autoMap   *fakeAutoMap
	lock      *fakeLock
	dns       *fakeDNS
	dnsBlock  *fakeDNSBlock
	ips       *fakeIPS
	profiles  *fakeProfiles
	telemetry *fakeTelemetry
	// callerAccount answers the server's account check on a sign-in link; it is the real
	// check unless a test replaces it.
	callerAccount func(peer, server netip.AddrPort) error
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		node:      &fakeNode{status: tsnode.Status{BackendState: tsnode.StateRunning}},
		tunnels:   newFakeTunnels(),
		forwards:  &fakeForwards{allRunning: true, suggestPort: 18100},
		presets:   &fakePresets{},
		settings:  newFakeSettings(),
		autostart: &fakeAutostart{},
		iface:     &fakeInterfaceSetup{},
		policy:    &fakePolicy{view: PolicyPlanView{Summary: "add tagOwners entry", AddTagOwner: true, Changed: true}},
		restart:   &fakeRestarter{},

		lifecycle: &fakeLifecycle{},

		traffic: &fakeTraffic{},
		prefs: &fakePrefs{view: PrefsView{
			NodeUp: true, Known: true,
			Fields: []PrefFieldView{{
				Key:    "routes.accept",
				Label:  "Reach networks other devices advertise",
				Stored: true, Live: false, InForce: false,
			}},
			Conflict:   []string{"routes.accept"},
			Capability: Capability{Available: true, Degraded: true, Reason: "something keeps changing it back"},
		}},
		proxy: &fakeProxy{
			status: tsproxy.Status{
				Enabled:        true,
				Listening:      "127.0.0.1:1080",
				NetworksUp:     true,
				Rules:          1,
				Scope:          config.ScopeTailnet,
				ResolveVia:     config.ResolveViaNetmap,
				ConfiguredAddr: "127.0.0.1:1080",
			},
			script: "function FindProxyForURL(url, host) { return \"DIRECT\"; }\n",
		},
		proxies: newFakeProxies(),
		sysProxy: &fakeSysProxy{view: SystemProxyView{
			Enabled: true, Platform: "darwin", Supported: false, Applied: false,
			AutoConfigURL: "http://127.0.0.1:8377/proxy.pac",
			Manual: []sysproxy.Command{{
				Label:   "Point this Mac at the proxy",
				Command: "networksetup -setautoproxyurl Wi-Fi http://127.0.0.1:8377/proxy.pac",
			}},
			Capability: Capability{
				Available: true, Degraded: true,
				Reason: "changing it on macOS needs an administrator, so run the command yourself",
			},
		}},
		exitNode: &fakeExitNode{
			view: ExitNodeView{
				Enabled: true, Current: "nABC", CurrentLabel: "gateway",
				LiveID: "nABC", LiveOnline: true,
				Reason:  "Traffic is leaving through gateway.",
				Warning: "Changing the exit node drops every connection going through the old one.",
				Candidates: []ExitNodeCandidate{
					{ID: "nABC", Label: "gateway", Display: "gateway", Online: true, Current: true},
				},
				Capability: Capability{Available: true},
			},
			suggestion: ExitNodeSuggestion{ID: "nXYZ", Label: "mullvad-berlin", Country: "Germany", City: "Berlin"},
		},
		routing: &fakeRouting{
			view: RoutingView{
				Rules: []routing.Rule{{
					ID: "rt_1", Action: routing.Via, Tunnel: "tn_office", Host: "**.corp.example",
				}},
				Describe:   []string{"**.corp.example goes through Office"},
				Actions:    routing.Actions,
				Tunnels:    []RoutingTunnel{{ID: "tn_office", Name: "Office", Running: true}},
				Limits:     RoutingLimits(),
				Capability: Capability{Available: true, Limits: RoutingLimits()},
			},
			check: RoutingCheckResult{
				Decided: true, Action: string(routing.Via),
				Tunnel: "tn_office", TunnelName: "Office",
				Rule: "rt_1", RuleIndex: 1,
				Reason: "rule 1 **.corp.example goes through tn_office",
			},
		},
		routes: &fakeRoutes{
			view: RoutesView{
				Enabled:    true,
				Accepting:  true,
				Reaching:   []string{"192.168.1.0/24"},
				Advertised: []string{"10.20.0.0/24"},
				Approved:   []string{"10.20.0.0/24"},
				Serving:    true,
				Carried:    3,
				Capability: Capability{Available: true, Limits: RouteLimits()},
			},
			check: RouteCheckResult{Routes: []RouteCheckEntry{
				{Prefix: "192.168.1.0/24", Via: []string{"gateway"}, Reachable: true},
			}},
		},
		autoMap: &fakeAutoMap{
			view: AutoMapView{
				Enabled: true, Ports: []int{22}, Limit: 32, Mapped: 2, Stored: 3,
				Truncated: 1, Reason: "one device was left out by the limit of 32",
			},
			removed: 1,
		},
		lock: &fakeLock{
			view: LockView{
				Enabled: true, Signed: false,
				NodeKey:     "nodekey:abc",
				LockKey:     "nlpub:def",
				SignCommand: "tailscale lock sign nodekey:abc nlpub:def",
				Trusted: []LockKeyView{
					{ID: "tlpub:aaa", Kind: "person", Votes: 1, Label: "tlpub:aaa"},
				},
				Visible:  4,
				Filtered: []LockPeerView{{ID: "n1", Name: "laptop", NodeKey: "nodekey:zzz"}},
				Head:     "abcdef",
				Capability: Capability{
					Available: true, Degraded: true,
					Reason: "this device is not signed for tailnet lock yet",
				},
			},
			log: []LockUpdate{{Hash: "abcdef", Change: "added key tlpub:aaa"}},
		},
		dns: &fakeDNS{
			view: DNSView{
				Enabled: true, Using: true, MagicDNS: true,
				Resolvers:     []string{"100.100.100.100"},
				SearchDomains: []string{"tail1a2b3c.ts.net"},
				Routes:        []DNSRouteView{{Suffix: "corp.example.com", Resolvers: []string{"10.0.0.53"}}},
				Records:       []DNSRecordView{{Name: "wiki", Type: "A", Value: "100.64.0.9"}},
				MachineReason: "app-tail does not manage this machine's DNS configuration",
				System: &DNSSystemView{
					Enabled: true, Applied: true, Ready: true,
					Profile: "cloudflare", ProfileLabel: "Cloudflare",
					Servers:   []string{"1.1.1.1", "1.0.0.1"},
					Protocols: []string{"plain"},
					Listen:    "127.0.0.153:53",
					Base: &DNSBaseView{
						Nameservers:   []string{"192.168.6.1"},
						SearchDomains: []string{"lan"},
					},
					LocalSuffixes: []string{"lan"},
					Queries:       DNSSystemStats{Total: 42, ToProfile: 39, ToLocal: 3},
					Capability:    Capability{Available: true},
				},
				Capability: Capability{Available: true},
			},
		},
		dnsBlock: &fakeDNSBlock{
			view: DNSBlockView{
				Enabled: true, Own: true, System: true,
				Answer: "nxdomain", Rules: 152403, RefreshHours: 24, Blocked: 87,
				CompiledAt: "2026-08-31T11:00:00Z",
				Lists: []DNSBlockListView{
					{
						ID: "hagezi-pro", Name: "Hagezi Pro", URL: "https://lists.example/pro.txt",
						Format: "abp", BuiltIn: true, Enabled: true, Rules: 152403, Skipped: 12,
						UpdatedAt: "2026-08-31T11:00:00Z",
					},
				},
				Capability: Capability{Available: true},
			},
		},
		ips: &fakeIPS{
			view: IPSView{
				Enabled: true, Mode: "prevent", Names: true, Destinations: true,
				Rules: 3, CompiledAt: "2026-08-31T11:00:00Z", Matched: 4, Refused: 2,
				Deny: []string{"bad.example", "10.1.2.0/24"},
				Feeds: []IPSFeedView{{
					ID: ipsfeed.DefaultFeedID, Provider: "FireHOL", Name: "FireHOL level 1",
					URL: "https://feeds.example/level1.netset", BuiltIn: true, Enabled: true,
					Rules: 4231, Skipped: 18, UpdatedAt: "2026-08-31T10:00:00Z",
				}},
				RefreshHours: 24, NextRefresh: "2026-09-01T10:00:00Z",
				Recent: []IPSDetectionView{{
					At: "2026-08-31T11:04:00Z", Signal: "name", Value: "bad.example",
					Source: "your own entries", Reason: "bad.example is named by your own entries",
					Where: "the proxy", Protocol: "tcp", Refused: true,
				}},
				Capability: Capability{Available: true},
			},
		},
		profiles: &fakeProfiles{},
		telemetry: func() *fakeTelemetry {
			codes, categories, severities := TelemetryFilterVocabulary()
			return &fakeTelemetry{
				view: TelemetryView{
					Enabled: true, SwitchKey: "telemetry.enabled",
					Stats: telemetry.Stats{
						Events: 2, EventsRecorded: 2, EventCapacity: 1000, RetentionSec: 2592000,
					},
					Codes: codes, Categories: categories, Severities: severities,
					Capability: Capability{
						Available: true,
						Limits: []string{
							"The log is held in this app's memory, so it starts empty every " +
								"time app-tail is started.",
						},
					},
				},
				page: telemetry.EventPage{
					Events: []telemetry.Event{{
						Seq: 2, At: time.Date(2026, 8, 23, 12, 1, 0, 0, time.UTC),
						Code: telemetry.CodeProxyUp, Category: telemetry.CategoryNetwork,
						Severity: telemetry.SeverityInfo,
						Message:  "The tailnet proxy is listening on 127.0.0.1:1080.",
						Fields:   map[string]string{"address": "127.0.0.1:1080"},
					}, {
						Seq: 1, At: time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
						Code: telemetry.CodeAppStart, Category: telemetry.CategorySystem,
						Severity: telemetry.SeverityInfo,
						Message:  "app-tail started.",
					}},
					Total: 2,
				},
			}
		}(),
	}
	h.callerAccount = peeraccount.Check
	h.server = New(Options{
		Auth: testKeys,
		CallerAccount: func(peer, server netip.AddrPort) error {
			return h.callerAccount(peer, server)
		},
		Deps: Deps{
			Node:      h.node,
			Tunnels:   h.tunnels,
			Forwards:  h.forwards,
			Presets:   h.presets,
			Settings:  h.settings,
			Interface: h.iface,
			Autostart: h.autostart,
			Policy:    h.policy,
			Restart:   h.restart,
			Lifecycle: h.lifecycle,
			Traffic:   h.traffic,
			Proxy:     h.proxy,
			Proxies:   h.proxies,
			SysProxy:  h.sysProxy,
			Prefs:     h.prefs,
			ExitNode:  h.exitNode,
			Routes:    h.routes,
			Routing:   h.routing,
			AutoMap:   h.autoMap,
			Lock:      h.lock,
			DNS:       h.dns,
			DNSBlock:  h.dnsBlock,
			IPS:       h.ips,
			Profiles:  h.profiles,
			Telemetry: h.telemetry,
			Version:   "test",
		},
	})
	return h
}

// testHost is the Host every request carries unless a test is specifically
// exercising the Host guard. httptest.NewRequest defaults to "example.com", which
// the guard refuses, so every request built here goes through newAPIRequest.
const testHost = "127.0.0.1:8377"

// newAPIRequest builds a request the way a signed-in browser on the loopback dashboard
// would: it carries the shared test token, so a test about anything but authentication
// reaches its handler. A test about authentication removes or replaces the header.
func newAPIRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.Host = testHost
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, net.TCPAddrFromAddrPort(netip.MustParseAddrPort(testHost))))
	req.Header.Set("Authorization", "Bearer "+testToken)
	return req
}

// do issues a request against the routed handler. body may be nil.
func (h *harness) do(t *testing.T, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = strings.NewReader(string(raw))
	}
	req := newAPIRequest(method, target, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)
	return rec
}

// doRaw issues a request with a literal body, for malformed-JSON cases.
func (h *harness) doRaw(t *testing.T, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := newAPIRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)
	return rec
}

// decode unmarshals a recorder body, failing the test on malformed JSON.
func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return v
}

func requireStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, want, rec.Body.String())
	}
}

func requireError(t *testing.T, rec *httptest.ResponseRecorder, want int, mustContain string) errorBody {
	t.Helper()
	requireStatus(t, rec, want)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("error response Content-Type = %q, want JSON", ct)
	}
	body := decode[errorBody](t, rec)
	if body.Error == "" {
		t.Fatalf("error response has an empty error field: %s", rec.Body.String())
	}
	if mustContain != "" && !strings.Contains(body.Error, mustContain) {
		t.Fatalf("error %q does not mention %q", body.Error, mustContain)
	}
	return body
}

// fakeInterfaceSetup stands in for the machine arrangement, which on a real one raises the
// system's password dialog. Substituting it is what lets the route be exercised at all: a
// suite must never prompt, and the prompt is the whole of what the real one does.
type fakeInterfaceSetup struct {
	calls int
	err   error
	view  InterfaceView
}

var _ InterfaceSetup = (*fakeInterfaceSetup)(nil)

func (f *fakeInterfaceSetup) SetUpInterface(context.Context) error {
	f.calls++
	return f.err
}

func (f *fakeInterfaceSetup) View(context.Context) InterfaceView { return f.view }
