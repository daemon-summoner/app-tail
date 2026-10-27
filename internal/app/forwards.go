// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/forward"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/ports"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// forwardNets answers which network carries a forward, out of the connections that are
// running right now.
//
// It reads the live registry rather than the stored document on purpose: a forward whose
// connection is configured but down has nothing to run over, and one whose connection was
// rebuilt has to be rebuilt with it. Both are the same question, and the registry is the
// only place that knows the answer.
type forwardNets struct{ tunnels *tunnel.Registry }

var _ forward.Tailnets = forwardNets{}

func (n forwardNets) Tailnet(id string) (forward.Tailnet, bool) {
	held, running := n.tunnels.Get(id)
	if !running || !held.Status().State.Live() {
		return nil, false
	}
	return held, true
}

// forwardsAPI presents the agent as the management API's forward registry: stored
// configuration joined with the manager's live counters. It is a separate type
// because Forwards, Presets and SettingsAPI all declare List/Get/Create/Update/
// Delete, so one type cannot satisfy all three.
type forwardsAPI struct{ a *Agent }

var _ httpapi.Forwards = forwardsAPI{}

// Forwards exposes the agent as the management API's forward registry.
func (a *Agent) Forwards() httpapi.Forwards { return forwardsAPI{a: a} }

func (f forwardsAPI) List() []httpapi.ForwardView {
	stored := f.a.store.Get().Forwards
	derived, _, _ := f.a.autoMap.snapshot()
	live := f.a.statusIndex()

	out := make([]httpapi.ForwardView, 0, len(stored)+len(derived))
	for _, fwd := range stored {
		out = append(out, f.a.withSelfTargetRefusal(fwd, mergeView(fwd, live[fwd.ID], f.a.shieldsUpOn(fwd))))
	}
	for _, fwd := range derived {
		view := mergeView(fwd, live[fwd.ID], f.a.shieldsUpOn(fwd))
		view.Source = httpapi.SourceAuto
		out = append(out, view)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (f forwardsAPI) Get(id string) (httpapi.ForwardView, error) {
	if stored, ok := f.a.store.Get().FindForward(id); ok {
		return f.a.viewOf(stored), nil
	}
	if derived, ok := f.a.findAutoForward(id); ok {
		view := f.a.viewOf(derived)
		view.Source = httpapi.SourceAuto
		return view, nil
	}
	return httpapi.ForwardView{}, fmt.Errorf("forward %q: %w", id, config.ErrNotFound)
}

func (f forwardsAPI) Create(ctx context.Context, spec httpapi.ForwardSpec) (httpapi.ForwardView, error) {
	id, err := config.NewForwardID()
	if err != nil {
		return httpapi.ForwardView{}, fmt.Errorf("generate forward id: %w", err)
	}

	// A new forward is enabled and loopback-bound unless the client says otherwise.
	created := config.Forward{
		ID: id, Enabled: true, BindAddr: config.DefaultBindAddr,
		TunnelID: config.PrimaryTunnelID,
	}
	applySpec(&created, spec)
	if created.Name == "" {
		created.Name = config.SuggestName(created)
	}
	if err := f.a.checkForwardTarget(ctx, created); err != nil {
		return httpapi.ForwardView{}, err
	}

	if _, err := f.a.store.Update(func(c *config.Config) error {
		c.Forwards = append(c.Forwards, created)
		return nil
	}); err != nil {
		return httpapi.ForwardView{}, err
	}

	f.a.reconcileNow(ctx)
	return f.Get(id)
}

func (f forwardsAPI) Update(ctx context.Context, id string, spec httpapi.ForwardSpec) (httpapi.ForwardView, error) {
	// Refused before the store is touched. A derived forward is not in the stored list
	// at all, so without this the write would report "not found" -- which reads as the
	// forward the user is looking at not existing, rather than as it not being theirs.
	if isAutoForward(id) {
		return httpapi.ForwardView{}, autoForwardRefusal(id)
	}
	// The target is checked against the forward as this write leaves it, before the store
	// is touched: the check may look a name up, which is not something to do while holding
	// the store's lock.
	held, ok := f.a.store.Get().FindForward(id)
	if !ok {
		return httpapi.ForwardView{}, fmt.Errorf("forward %q: %w", id, config.ErrNotFound)
	}
	applySpec(&held, spec)
	if err := f.a.checkForwardTarget(ctx, held); err != nil {
		return httpapi.ForwardView{}, err
	}
	if _, err := f.a.store.Update(func(c *config.Config) error {
		for i := range c.Forwards {
			if c.Forwards[i].ID != id {
				continue
			}
			applySpec(&c.Forwards[i], spec)
			return nil
		}
		return fmt.Errorf("forward %q: %w", id, config.ErrNotFound)
	}); err != nil {
		return httpapi.ForwardView{}, err
	}

	f.a.reconcileNow(ctx)
	return f.Get(id)
}

func (f forwardsAPI) Delete(ctx context.Context, id string) error {
	if isAutoForward(id) {
		return autoForwardRefusal(id)
	}
	if _, err := f.a.store.Update(func(c *config.Config) error {
		for i, fwd := range c.Forwards {
			if fwd.ID == id {
				c.Forwards = append(c.Forwards[:i], c.Forwards[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("forward %q: %w", id, config.ErrNotFound)
	}); err != nil {
		return err
	}

	f.a.reconcileNow(ctx)
	return nil
}

func (f forwardsAPI) SetEnabled(ctx context.Context, id string, enabled bool) (httpapi.ForwardView, error) {
	if isAutoForward(id) {
		return f.setDerivedEnabled(ctx, id, enabled)
	}
	return f.Update(ctx, id, httpapi.ForwardSpec{Enabled: &enabled})
}

// setDerivedEnabled switches one derived mapping off, or back on.
//
// It is the one write a derived forward accepts, because it is the only one that is not
// an edit to what the module derived: it says this machine should not open that port,
// which is a choice the module has nowhere else to record. Without it the only lever is
// the module's own switch, so not wanting one port open costs every mapping on the
// machine.
//
// The assignment is left alone. The number is still owed to that device, and handing it
// to another one while this mapping is off is the moved-port failure the whole module is
// built to rule out.
func (f forwardsAPI) setDerivedEnabled(ctx context.Context, id string, enabled bool) (httpapi.ForwardView, error) {
	if _, ok := f.a.findAutoForward(id); !ok {
		return httpapi.ForwardView{}, fmt.Errorf("forward %q: %w", id, config.ErrNotFound)
	}
	if _, err := f.a.store.Update(func(c *config.Config) error {
		c.AutoMapOff = autoMapOffWith(c.AutoMapOff, id, !enabled)
		return nil
	}); err != nil {
		return httpapi.ForwardView{}, err
	}

	f.a.reconcileNow(ctx)
	return f.Get(id)
}

// SuggestPort finds a local port that is both bindable right now and not already
// claimed by another forward, so the wizard never proposes an endpoint that would
// be rejected on save.
func (f forwardsAPI) SuggestPort(protocol config.Protocol, bindAddr string, preferred int) (int, error) {
	if bindAddr == "" {
		bindAddr = config.DefaultBindAddr
	}
	claimed := f.a.claimedPorts(protocol, bindAddr)
	return ports.Suggest(protocol, bindAddr, preferred, func(p int) bool { return claimed[p] })
}

// AllRunning backs the readiness probe: false unless every enabled forward is
// listening.
func (f forwardsAPI) AllRunning() bool {
	manager := f.a.currentManager()
	if manager == nil {
		return false
	}
	return manager.AllRunning()
}

// claimedPorts collects the local ports configured forwards already own, including
// disabled ones: suggesting a stopped forward's port would make re-enabling it fail.
func (a *Agent) claimedPorts(protocol config.Protocol, bindAddr string) map[int]bool {
	claimed := make(map[int]bool)
	for _, f := range a.store.Get().Forwards {
		// A forward claims the port for the requested protocol when the transports
		// they carry overlap, so a "both" forward blocks a tcp-only suggestion and
		// vice versa.
		if f.Direction != config.ToLocal || !config.ProtocolsOverlap(f.Protocol, protocol) {
			continue
		}
		if f.BindAddr == bindAddr || f.BindAddr == "" {
			claimed[f.ListenPort] = true
		}
	}
	// The dashboard's own port is not a forward, but taking it would cut the user
	// off from the app. It is a TCP listener, so it only blocks TCP-bearing forwards.
	if addr := a.UIAddr(); addr != nil && protocol.CarriesTCP() {
		if port := portOf(addr.String()); port != 0 {
			claimed[port] = true
		}
	}
	return claimed
}

func (a *Agent) statusIndex() map[string]forward.Status {
	index := make(map[string]forward.Status)
	manager := a.currentManager()
	if manager == nil {
		return index
	}
	for _, st := range manager.Statuses() {
		index[st.ID] = st
	}
	return index
}

func (a *Agent) viewOf(f config.Forward) httpapi.ForwardView {
	var live forward.Status
	if manager := a.currentManager(); manager != nil {
		live = manager.Status(f.ID)
	}
	return a.withSelfTargetRefusal(f, mergeView(f, live, a.shieldsUpOn(f)))
}

func mergeView(f config.Forward, live forward.Status, shieldsUp bool) httpapi.ForwardView {
	return httpapi.ForwardView{
		Forward:   f,
		State:     live.State,
		Error:     live.Error,
		ActiveTCP: live.ActiveTCP,
		ActiveUDP: live.ActiveUDP,
		BytesUp:   live.BytesUp,
		BytesDown: live.BytesDown,
		Listening: live.Listening,
		Endpoint:  config.Endpoint(f),
		Warning:   forwardWarning(f, shieldsUp),
	}
}

// forwardWarning is what is true about a forward that its own state cannot show.
//
// Blocking incoming connections is a preference on the node, not a fault in the forward:
// a forward publishing a local service on the tailnet still binds and still reports
// itself running, and every connection another device makes to it is dropped. The write
// is not rejected -- someone turning shields on may well mean exactly that -- but the
// forward it silences has to say so, or the only way to find out is for a connection from
// another device to fail with no explanation anywhere.
func forwardWarning(f config.Forward, shieldsUp bool) string {
	if f.Direction == config.ToLocal {
		return bindWarning(f)
	}
	if !shieldsUp {
		return ""
	}
	return "Blocking incoming connections is on, so this forward refuses every connection " +
		"from your tailnet however your access rules read. Turn it off in Security to let " +
		"other devices reach this one."
}

// bindWarning names a forward that listens somewhere other than on this machine alone.
//
// Every other listener app-tail opens is refused a non-loopback address; a forward is
// allowed one deliberately, because publishing a tailnet service to the rest of the house is
// a real thing to want. What it must not do is look the same as a forward only this machine
// can reach: the port answers everything that can reach this machine over any network it is
// attached to -- a hotel wifi included -- with no authentication in front of it, and nothing
// in the forward's own state says so.
func bindWarning(f config.Forward) string {
	host := f.BindAddr
	if host == "" {
		host = config.DefaultBindAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.IsLoopback() {
		// An address that does not parse never reached the stored document: ValidateForward
		// refuses it, and a warning about it would be a warning about nothing.
		return ""
	}
	where := "the address " + host
	if addr.IsUnspecified() {
		where = "every address this machine has"
	}
	return fmt.Sprintf("This forward listens on %s, so anything that can reach this machine over "+
		"the networks it is on can use it, not only programs running here. Set the listen address "+
		"to %s to keep it to this machine.", where, config.DefaultBindAddr)
}

// shieldsUpOn reports whether the connection this forward crosses is refusing incoming
// connections. It is read per forward because shields are a preference of one node: with
// two networks configured, one may be refusing while the other answers, and a single
// answer for the machine would put the warning on the wrong forwards.
func (a *Agent) shieldsUpOn(f config.Forward) bool {
	return a.tunnelPrefs(f.Connection()).ShieldsUp
}

// applySpec overlays the fields a request actually carried. An absent pointer means
// "leave this alone", which is what lets a client patch one field at a time.
func applySpec(f *config.Forward, spec httpapi.ForwardSpec) {
	if spec.Name != nil {
		f.Name = *spec.Name
	}
	if spec.TunnelID != nil {
		f.TunnelID = *spec.TunnelID
	}
	if spec.Direction != nil {
		f.Direction = *spec.Direction
	}
	if spec.Protocol != nil {
		f.Protocol = *spec.Protocol
	}
	if spec.BindAddr != nil {
		f.BindAddr = *spec.BindAddr
	}
	if spec.ListenPort != nil {
		f.ListenPort = *spec.ListenPort
	}
	if spec.Target != nil {
		f.Target = *spec.Target
	}
	if spec.Enabled != nil {
		f.Enabled = *spec.Enabled
	}
	if spec.UDPTimeoutSec != nil {
		f.UDPTimeoutSec = *spec.UDPTimeoutSec
	}
	if spec.ExposeToNetwork != nil {
		f.ExposeToNetwork = *spec.ExposeToNetwork
	}
}
