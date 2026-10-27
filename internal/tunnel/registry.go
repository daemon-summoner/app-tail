// SPDX-License-Identifier: MIT

package tunnel

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/sellitus/app-tail/internal/routing"
	"github.com/sellitus/app-tail/internal/spread"
)

// Registry is the set of live tunnels, keyed by the id the stored configuration names
// them by. It is what turns "which connection carries this" from a question about the
// running node into a lookup, which is the whole difference between one network and many.
//
// It holds the running tunnels only. What the user configured lives in the stored
// document; reconciling the two is the agent's job, and keeping them in separate places
// is what makes "configured but not started" a state that can be reported rather than one
// that is indistinguishable from a bug.
type Registry struct {
	mu sync.RWMutex
	// order is declaration order, which is the order every surface lists connections in.
	// A map alone would reorder the list on every poll.
	order []string
	byID  map[string]Tunnel
	// hostAddrs resolves a destination no tunnel carries. Nil means this machine's own
	// resolver; see SetHostResolver.
	hostAddrs hostResolver
	// names is which connection a suffixed name belongs to. It comes from the stored
	// document rather than from the running tunnels, so a name keeps naming its
	// connection while that connection is down -- which is what makes "office is not
	// running" an answer rather than a name that quietly resolves somewhere else.
	names Naming
	// egressIDs are the connections this machine's internet traffic leaves through, in the
	// order they were chosen, or empty for the machine's own network. They are ids rather
	// than tunnels so that naming a connection that is not running is a connection that is
	// not running, rather than a setting that quietly stops applying the moment it goes down.
	egressIDs []string
	// egressSeed is what a destination is hashed with when several of them carry it.
	egressSeed uint64
	// egressHeld refuses a destination no connection carries when none of the connections
	// above is running, rather than letting it out of this machine. See SetEgressMembers.
	egressHeld bool
	// routes are the per-destination exceptions to the connections above, in the order
	// the user wrote them. An empty list is the ordinary install: every destination no
	// connection carries leaves the way the egress setting says.
	routes []routing.Rule
	// blocklist refuses a name that is on a list the user switched on. Nil blocks nothing.
	blocklist Blocklist
}

// Blocklist reports the list that stops a name, and whether one does. It is declared here
// rather than imported so this package keeps knowing nothing about where a list came from
// or how it is compiled.
type Blocklist interface {
	Blocks(name string) (list string, ok bool)
}

// ErrEgressHeld is what a destination no connection carries fails with while the connections
// carrying this machine's internet traffic are all down and the traffic is held.
//
// It is an error rather than a route because there is nothing to dial: the whole point of the
// setting is that this machine's own network is not an answer, so a caller that fell back to
// it would undo the choice at the one moment the choice matters.
var ErrEgressHeld = errors.New("this machine's internet traffic goes out through the " +
	"connections chosen for it, and none of them is running, so it is held here rather than " +
	"sent out over this machine's own network")

func NewRegistry() *Registry {
	return &Registry{byID: make(map[string]Tunnel)}
}

// Add registers a tunnel. A duplicate id is refused rather than replaced: two tunnels
// answering to one id means whichever was registered last silently receives traffic
// intended for the other, and nothing anywhere would report it.
func (r *Registry) Add(t Tunnel) error {
	id := t.ID()
	if id == "" {
		return errors.New("a connection with no id cannot be registered")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byID[id]; exists {
		return fmt.Errorf("connection %q is already registered", id)
	}
	r.byID[id] = t
	r.order = append(r.order, id)
	return nil
}

// Remove takes a tunnel out of the registry and hands it back so the caller can close
// it. Removing does not close: a caller that is replacing a tunnel wants the old one
// closed after the new one is in place, and one that is shutting down closes everything
// itself.
func (r *Registry) Remove(id string) (Tunnel, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.byID[id]
	if !ok {
		return nil, false
	}
	delete(r.byID, id)
	for i, held := range r.order {
		if held == id {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
	return t, true
}

// Get returns the tunnel registered under id.
func (r *Registry) Get(id string) (Tunnel, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.byID[id]
	return t, ok
}

// All returns every registered tunnel in declaration order.
func (r *Registry) All() []Tunnel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tunnel, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.byID[id])
	}
	return out
}

// SetNaming replaces which connection each name suffix belongs to.
func (r *Registry) SetNaming(n Naming) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names = n
}

// Naming is the current suffix map, for the callers that resolve a name themselves rather
// than through Resolve -- the proxy asking a network's own resolver, and the surfaces that
// show a connection the suffix it answers under.
func (r *Registry) Naming() Naming {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.names
}

// SetEgress names the connection this machine's internet traffic leaves through. An empty
// id sends it out of the machine's own network, which is where it goes by default.
//
// What is chosen here is a route: a connection that is down leaves the machine on the network
// it was already on, which is what it was on before the setting was touched.
func (r *Registry) SetEgress(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.egressIDs, r.egressSeed, r.egressHeld = nil, 0, false
	if id != "" {
		r.egressIDs = []string{id}
	}
}

// SetEgressMembers names the connections sharing this machine's internet traffic between
// them, and the seed this machine spreads by. An empty list carries nothing until connections
// are chosen; the caller resolves "every connection that is running" into the list it passes.
//
// Unlike SetEgress this is held rather than a route: with none of these connections running,
// a destination no connection carries fails with ErrEgressHeld instead of leaving through
// this machine's own network. Choosing several connections is a statement about who may see
// the traffic, and the ISP link is the one answer that statement excludes.
func (r *Registry) SetEgressMembers(ids []string, seed uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.egressIDs, r.egressSeed, r.egressHeld = slices.Clone(ids), seed, true
}

// Egress is the connection carrying this machine's internet traffic, and whether there is
// one. It is absent when nothing was chosen and equally when what was chosen is not
// running: a destination is either going through a connection that exists or it is going
// out of this machine, and a caller has no third thing to do about the difference. Which
// of the two it is stays visible in the settings and in what the agent reports.
func (r *Registry) Egress() (Tunnel, bool) { return r.EgressFor(netip.Addr{}) }

// EgressFor is the connection carrying this machine's traffic to one destination.
//
// With several connections carrying it, the destination decides which -- by the block it is
// in rather than by the address, so a page and everything it loads leave the same way. An
// invalid address is the caller that has no destination to speak for, and is answered with
// whichever of them an unkeyed choice lands on, always the same one.
func (r *Registry) EgressFor(to netip.Addr) (Tunnel, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var key uint64
	if to.IsValid() {
		key = spread.Key(r.egressSeed, to)
	}
	return r.egressAmong(key)
}

// egressAmong picks between the chosen connections that are actually running. Callers hold
// the lock.
func (r *Registry) egressAmong(key uint64) (Tunnel, bool) {
	var up []string
	for _, id := range r.egressIDs {
		if _, running := r.byID[id]; running {
			up = append(up, id)
		}
	}
	if len(up) == 0 {
		return nil, false
	}
	t, ok := r.byID[spread.Pick(up, key)]
	return t, ok
}

// EgressForName is the connection carrying this machine's traffic to a destination named
// rather than addressed. See spread.KeyName for why the whole name is not the key.
func (r *Registry) EgressForName(host string) (Tunnel, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.egressAmong(spread.KeyName(r.egressSeed, host))
}

// EgressHeld reports that a destination no connection carries must not go out over this
// machine's own network. It is the fail-closed half of SetEgressMembers.
func (r *Registry) EgressHeld() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.egressHeld
}

// SetRoutes replaces the per-destination exceptions to where this machine's internet
// traffic goes. An empty list restores "everything the egress setting says".
func (r *Registry) SetRoutes(rules []routing.Rule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes = routing.Clone(rules)
}

// Routes is the current exception list, for the surfaces that read it back.
func (r *Registry) Routes() []routing.Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return routing.Clone(r.routes)
}

// SetBlocklist replaces the list of names app-tail refuses to resolve for itself. Nil
// blocks nothing, which is the switch being off and every state before the first list has
// been read.
func (r *Registry) SetBlocklist(b Blocklist) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blocklist = b
}

// blocks reports the list a name is on, and whether one is.
func (r *Registry) blocks(name string) (string, bool) {
	r.mu.RLock()
	b := r.blocklist
	r.mu.RUnlock()
	if b == nil || name == "" {
		return "", false
	}
	return b.Blocks(name)
}

// RouteFor is which way one destination goes by the rules alone, undecided when no rule
// names it. It is exported because the dashboard and the CLI answer "which way would this
// go" with the same function a real dial uses, rather than with a second implementation
// that can disagree with it.
func (r *Registry) RouteFor(req routing.Request) routing.Decision {
	r.mu.RLock()
	rules := r.routes
	r.mu.RUnlock()
	return routing.Decide(rules, req)
}

// Len is how many tunnels are registered.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.order)
}

// Close closes every tunnel and empties the registry. Every close is attempted even
// after one fails, because leaving the rest running would hold interfaces and listeners
// open with nothing left holding a reference to them; the failures are reported together.
func (r *Registry) Close() error {
	r.mu.Lock()
	held := make([]Tunnel, 0, len(r.order))
	for _, id := range r.order {
		held = append(held, r.byID[id])
	}
	r.order = nil
	r.byID = make(map[string]Tunnel)
	r.mu.Unlock()

	var failures []error
	for _, t := range held {
		if err := t.Close(); err != nil {
			failures = append(failures, fmt.Errorf("closing %s: %w", t.ID(), err))
		}
	}
	return errors.Join(failures...)
}
