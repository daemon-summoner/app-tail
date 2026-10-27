// SPDX-License-Identifier: MIT

package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

// SettingsFunc supplies the current global settings. It is a function so the
// manager always reads live values rather than a copy taken at construction.
type SettingsFunc func() config.Settings

// Manager owns every running forward. Listener lifetimes, proxy goroutines and
// live counters all hang off the entries in its registry.
type Manager struct {
	nets     Tailnets
	settings SettingsFunc
	logger   *slog.Logger

	// janitorInterval controls how often idle UDP sessions are swept. Tests
	// shorten it so eviction can be asserted without waiting.
	janitorInterval time.Duration

	// inspector reads the opening bytes of what these forwards carry. It is held as a
	// pointer to the interface so the empty case is one nil comparison on the path that
	// carries bytes, and it is read without the lock because it is read per connection.
	inspector atomic.Pointer[Inspector]

	// guard judges each address a forward connects to on this machine's own stack. It is
	// held like the inspector, and for the same reason: it is read per connection.
	guard atomic.Pointer[DialGuard]

	mu      sync.Mutex
	entries map[string]*entry
	desired []config.Forward

	// applied distinguishes "no forwards are wanted" from "nothing has been asked
	// for yet"; both leave desired empty, but only the first can report readiness.
	applied bool
}

// entry is one forward's registry record: its configuration, its live counters,
// and the machinery to stop it.
type entry struct {
	fwd      config.Forward
	counters *counters

	// net is the network this forward was started over, kept so a connection that has
	// been rebuilt underneath is noticed: the running forward would otherwise keep
	// dialling through a node nothing is attached to any more.
	net Tailnet

	// Set only while the forward is actually running.
	cancel context.CancelFunc
	closer io.Closer
	wg     *sync.WaitGroup
}

func (e *entry) active() bool { return e.cancel != nil }

// NewManager builds a manager over the connections nets resolves. A forward stays
// stopped while the connection it names is not carrying.
func NewManager(nets Tailnets, settings SettingsFunc, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		nets:            nets,
		settings:        settings,
		logger:          logger,
		janitorInterval: defaultJanitorInterval,
		entries:         make(map[string]*entry),
	}
}

// DialGuard judges an address a forward is about to connect to on this machine's own
// network stack, once any name in its target has been looked up; network is the dialer's,
// such as "tcp4" or "udp6". An error refuses that connection. It is asked on every
// connection because what a name resolves to can change after the forward was written.
type DialGuard func(network string, addr netip.AddrPort) error

// SetDialGuard replaces what judges the addresses forwards connect to. Nil lets every
// connection through.
func (m *Manager) SetDialGuard(g DialGuard) {
	if g == nil {
		m.guard.Store(nil)
		return
	}
	m.guard.Store(&g)
}

// RefusedDialError is a connection the dial guard would not let a forward make.
type RefusedDialError struct {
	Addr netip.AddrPort
	Err  error
}

func (e *RefusedDialError) Error() string {
	return fmt.Sprintf("refused to connect to %s: %v", e.Addr, e.Err)
}

func (e *RefusedDialError) Unwrap() error { return e.Err }

// localDialer is what a forward reaches a service on this machine's own stack with. The
// guard sits in Control, which runs on the address actually being connected to after the
// lookup, so a name cannot be pointed somewhere else between a check and the connection.
func (m *Manager) localDialer() *net.Dialer {
	held := m.guard.Load()
	if held == nil {
		return &net.Dialer{}
	}
	guard := *held
	return &net.Dialer{Control: func(network, address string, _ syscall.RawConn) error {
		addr, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("read the address being connected to, %q: %w", address, err)
		}
		if err := guard(network, addr); err != nil {
			return &RefusedDialError{Addr: addr, Err: err}
		}
		return nil
	}}
}

// Apply sets the desired forward set and reconciles the running set to match.
// Forwards whose configuration is unchanged are left running untouched, so
// editing one never disturbs the others.
//
// It is also how a connection coming up or going down reaches the forwards on it: every
// reconcile re-asks which network carries each one, so a caller that runs this whenever
// anything moves needs no separate signal for it.
func (m *Manager) Apply(forwards []config.Forward) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.desired = append([]config.Forward(nil), forwards...)
	m.applied = true
	m.reconcileLocked()
}

// reconcileLocked converges the running set on the desired set. The caller must
// hold m.mu.
func (m *Manager) reconcileLocked() {
	desired := make(map[string]config.Forward, len(m.desired))
	// carrier is the network each wanted forward can run over right now. A forward whose
	// connection is down is absent from it, which is what stops it: resolving once per
	// pass is also what keeps the stop half and the start half below deciding from one
	// answer rather than from two reads that could disagree.
	carrier := make(map[string]Tailnet, len(m.desired))
	for _, f := range m.desired {
		desired[f.ID] = f
		if tn, up := m.nets.Tailnet(f.Connection()); up {
			carrier[f.ID] = tn
		}
	}

	// Drop entries that are gone, disabled, reconfigured, or whose connection is no
	// longer the one they were started over.
	for id, e := range m.entries {
		want, keep := desired[id]
		switch {
		case !keep:
			m.stopLocked(id)
			delete(m.entries, id)
		case !want.Enabled || carrier[id] == nil:
			// Only on the way down: the entry stays here reporting stopped for as long as
			// its connection is off, and a line per reconcile would bury everything else.
			if e.active() && carrier[id] == nil {
				m.logger.Info("stopping a forward because its connection is not carrying",
					"id", id, "name", want.Name, "connection", want.Connection())
			}
			m.stopLocked(id)
			e.fwd = want
			e.counters.setStopped()
		case sameEndpoint(e.fwd, want) && e.net == carrier[id]:
			// Only cosmetic fields changed; keep the listener as it is.
			e.fwd = want
		default:
			m.stopLocked(id)
			e.fwd = want
		}
	}

	for _, f := range m.desired {
		if !f.Enabled {
			continue
		}
		tn, carrying := carrier[f.ID]
		if !carrying {
			continue
		}
		e, ok := m.entries[f.ID]
		if !ok {
			e = &entry{fwd: f, counters: newCounters()}
			m.entries[f.ID] = e
		}
		if e.active() {
			continue
		}
		e.net = tn
		if err := m.startLocked(e); err != nil {
			// A forward that cannot bind stays visible with its reason rather
			// than vanishing; the rest of the set keeps running.
			m.logger.Error("forward failed to start",
				"id", f.ID, "name", f.Name, "endpoint", config.Endpoint(f), "error", err)
			e.counters.setError(err)
		}
	}
}

// sameEndpoint reports whether two revisions of a forward describe the same
// listener and target, meaning the running one need not be restarted.
func sameEndpoint(a, b config.Forward) bool {
	return a.Direction == b.Direction &&
		a.Protocol == b.Protocol &&
		a.BindAddr == b.BindAddr &&
		a.ListenPort == b.ListenPort &&
		a.Target == b.Target &&
		a.UDPTimeoutSec == b.UDPTimeoutSec
}

// startLocked brings one forward up. The caller must hold m.mu.
func (m *Manager) startLocked(e *entry) error {
	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}

	var (
		closer io.Closer
		err    error
	)
	switch e.fwd.Protocol {
	case config.TCP:
		closer, err = m.startTCP(ctx, e, wg)
	case config.UDP:
		closer, err = m.startUDP(ctx, e, wg)
	case config.Both:
		closer, err = m.startBoth(ctx, e, cancel, wg)
	default:
		err = fmt.Errorf("unsupported protocol %q", e.fwd.Protocol)
	}
	if err != nil {
		cancel()
		return err
	}

	e.cancel = cancel
	e.closer = closer
	e.wg = wg
	return nil
}

// startBoth runs a forward's TCP and UDP engines together so one rule carries both
// transports on the same endpoint. If the second engine cannot bind, the first is
// rolled back so the forward fails whole rather than half-listening.
func (m *Manager) startBoth(ctx context.Context, e *entry, cancel context.CancelFunc, wg *sync.WaitGroup) (io.Closer, error) {
	tcpCloser, err := m.startTCP(ctx, e, wg)
	if err != nil {
		return nil, err
	}
	udpCloser, err := m.startUDP(ctx, e, wg)
	if err != nil {
		// Cancel before closing so the TCP accept loop reads the closed listener as
		// a deliberate stop, not a listener failure, then wait it out.
		cancel()
		closeErr := tcpCloser.Close()
		wg.Wait()
		// A TCP listener that would not close keeps the port bound, so the next start
		// attempt fails with a bare "address already in use". Joining it here is what
		// puts the cause next to the effect.
		return nil, errors.Join(err, closeErr)
	}
	return multiCloser{tcpCloser, udpCloser}, nil
}

// multiCloser closes several listeners as one, so a both-protocol forward stops
// through the same single-closer path every other forward uses.
type multiCloser []io.Closer

func (mc multiCloser) Close() error {
	var errs []error
	for _, c := range mc {
		if c != nil {
			errs = append(errs, c.Close())
		}
	}
	return errors.Join(errs...)
}

// stopLocked tears one forward down and waits for its goroutines. The caller must
// hold m.mu.
func (m *Manager) stopLocked(id string) {
	e, ok := m.entries[id]
	if !ok || !e.active() {
		return
	}
	// Cancel first so loops can tell a deliberate stop from a real failure, then
	// close the listener to unblock Accept/ReadFrom.
	e.cancel()
	if e.closer != nil {
		// Teardown has no caller that could act on this, but a listener that will not
		// close keeps its port bound and the next start reports only "address already
		// in use". Logging is what leaves that diagnosable.
		if err := e.closer.Close(); err != nil {
			m.logger.Error("forward listener failed to close", "id", id, "error", err)
		}
	}
	e.wg.Wait()

	e.cancel = nil
	e.closer = nil
	e.wg = nil
	e.counters.setStopped()
}

// StopAll stops every forward and waits for their goroutines to finish.
//
// Stopping is prompt by construction rather than by deadline: stopLocked cancels
// each forward's context before closing it, and a live proxied connection is torn
// down by the AfterFunc that cancellation fires. The context here bounds only how
// long StopAll stays quiet about it -- returning early would abandon goroutines
// still holding the listeners, so a replacement manager could not rebind the ports.
func (m *Manager) StopAll(ctx context.Context) {
	m.mu.Lock()
	ids := make([]string, 0, len(m.entries))
	for id := range m.entries {
		ids = append(ids, id)
	}
	m.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, id := range ids {
			m.stopLocked(id)
		}
		m.desired = nil
		m.applied = false
		m.entries = make(map[string]*entry)
	}()

	started := time.Now()
	select {
	case <-done:
	case <-ctx.Done():
		m.logger.Warn("forwards are taking longer than the shutdown budget; still waiting",
			"forwards", len(ids), "elapsed", time.Since(started))
		<-done
	}
}

// Statuses returns a snapshot of every known forward's live status, ordered by id
// so the dashboard does not reshuffle between polls.
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	out := make([]Status, 0, len(m.entries))
	for id, e := range m.entries {
		out = append(out, e.counters.snapshot(id))
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Status returns one forward's live status. Forwards that are not running report
// as stopped rather than being absent.
func (m *Manager) Status(id string) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.entries[id]; ok {
		return e.counters.snapshot(id)
	}
	return Status{ID: id, State: StateStopped}
}

// AllRunning reports whether every enabled forward is listening. It backs the
// readiness probe, so a forward in error state makes the whole agent unready.
//
// A manager that has never reconciled reports false: readiness is a claim about a
// desired set that was actually applied, and an empty set would otherwise satisfy
// the loop below vacuously.
func (m *Manager) AllRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.applied {
		return false
	}
	for _, f := range m.desired {
		if !f.Enabled {
			continue
		}
		e, ok := m.entries[f.ID]
		if !ok || !e.active() || e.counters.snapshot(f.ID).State != StateRunning {
			return false
		}
	}
	return true
}

// udpTimeout resolves a forward's idle timeout from its own value or the global default.
func (m *Manager) udpTimeout(f config.Forward) time.Duration {
	if f.UDPTimeoutSec > 0 {
		return time.Duration(f.UDPTimeoutSec) * time.Second
	}
	if s := m.settings(); s.UDPSessionTimeoutSec > 0 {
		return time.Duration(s.UDPSessionTimeoutSec) * time.Second
	}
	return time.Duration(config.DefaultUDPTimeoutSec) * time.Second
}

// bufferSize resolves the UDP read buffer size from settings.
func (m *Manager) bufferSize() int { return m.settings().UDPBufferSize() }
