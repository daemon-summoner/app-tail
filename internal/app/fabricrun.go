// SPDX-License-Identifier: MIT

package app

// Running every connected network on one interface on this machine.
//
// The other machine-level module -- the tailnet's own interface -- puts one network on the
// machine and hands the whole job to the tailnet engine. This one is app-tail's: it creates
// the interface, decides which connection each address belongs to, and re-dials every flow
// that arrives. What it owns is therefore the whole loop, and the loop has to survive every
// way the machine can change underneath it: connections coming and going, a network's
// addresses colliding with another's, and the interface disappearing while traffic is on it.
//
// Everything here runs on the lifecycle goroutine except the view, which request goroutines
// read, so the mutex guards the whole runner rather than one field.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/sellitus/app-tail/internal/bytecount"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fabric"
	"github.com/sellitus/app-tail/internal/routing"
	"github.com/sellitus/app-tail/internal/spread"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// fabricLive is a fabric that is up, as this module drives it.
//
// It is an interface because the real one creates a network interface on this machine, which
// needs administrator rights: substituting it is not mocking this app's own code, it is
// standing in for the machine, and everything above this line is what the suite is for.
type fabricLive interface {
	Name() string
	Addrs() []netip.Prefix
	SetTable(t *fabric.Table, names map[string]string)
	SetInspector(in fabric.Inspector)
	Carry(ctx context.Context, routes, exclude []netip.Prefix, mtu int) error
	Withdraw(ctx context.Context) error
	MTU() int
	Done() <-chan struct{}
	Status() fabric.Status
	// Ports is what each port and transport carried, apart from Status because only the
	// activity graphs ask for it: every other reader of the interface polls Status.
	Ports() ([]bytecount.Row, bytecount.Row, int)
	Close() error
}

// fabricRunner owns the interface and the stack behind it.
type fabricRunner struct {
	logger *slog.Logger
	// logf is where the privileged side's own logging goes.
	logf func(format string, args ...any)
	// carriers is where the connection an address belongs to is looked up. It is the live
	// registry rather than a snapshot: a flow arriving a moment after a connection came up
	// has to find it.
	carriers fabric.Carriers
	// open creates the interface and starts carrying. It is the seam described above.
	open func(ctx context.Context, opts fabric.LiveOptions) (fabricLive, error)
	// poke asks the lifecycle loop for another reconcile. The dead-man's switch below runs on
	// its own goroutine and can only take the machine's networks back off it; rebuilding the
	// interface happens in a pass, and this is what asks for one.
	poke func()

	mu sync.Mutex

	live fabricLive
	// built is what the running interface was created with. The packet size and the pool are
	// fixed at creation -- the stack's buffers are sized from one and the interface's own
	// address comes out of the other -- so a change to either is a rebuild rather than an
	// update, and this is what notices.
	built fabricBuild
	// carrying is the routing last installed, so an unchanged reconcile does not send a
	// privileged call every few seconds.
	carrying string
	// addressing is the addressing last handed to the interface, for the same reason and a
	// sharper one: replacing it walks every open flow to find the ones whose answer changed,
	// and a reconcile runs on every event the tailnet reports.
	addressing string
	// table is the addressing behind that routing. It is kept because it is what a name
	// lookup is answered from -- a resolver inside a moved network answers with the network's
	// own address, and this is what turns that into the address this machine reaches it at --
	// and it is set only once the routing is installed, since until then there is nowhere on
	// this machine an answer could point.
	table *fabric.Table
	// inspecting is what examines the flows the interface carries. It is held here as well
	// as handed to the interface because the interface is rebuilt whenever its name, pool or
	// packet size changes, and a replacement built without it would carry traffic nothing
	// was looking at.
	inspecting fabric.Inspector
	// stopWatch ends the goroutine watching for the interface going away.
	stopWatch context.CancelFunc
	// withdrawn records the stack having stopped underneath a live interface, which is what
	// the watchdog leaves behind: the ranges are off the interface and the next pass rebuilds.
	withdrawn bool

	// reason is why the machine is not on its connections, and failure the last thing that
	// went wrong trying. They are separate because a mode that is switched off is not a
	// failure, and reporting it as one teaches the reader to ignore the ones that are.
	reason  string
	failure string
	// unreachable are the connections the addressing could not place anywhere, and conflicts
	// the ranges two connections both carry. Both are reported rather than resolved: the
	// first is a pool with no room left, the second is what the pool is for.
	unreachable []fabric.Placement
	conflicts   []fabric.Collision
}

// fabricBuild is what an interface was created with, and the test for whether the one that
// is running still matches what the settings ask for.
type fabricBuild struct {
	name string
	pool string
	mtu  int
}

// fabricTarget is what the settings and the running connections ask for.
type fabricTarget struct {
	on     bool
	reason string

	name string
	pool []netip.Prefix
	mtu  int
	// seed is what a destination is hashed with when several connections share this
	// machine's internet traffic. It comes from the install's own identity, so the same
	// site keeps the same connection across restarts.
	seed uint64

	table *fabric.Table
	names map[string]string
	// routes are the ranges this machine sends to the interface, and exclude the ones that
	// must keep leaving through the machine's own network.
	routes  []netip.Prefix
	exclude []netip.Prefix

	unreachable []fabric.Placement
	conflicts   []fabric.Collision
}

// fabricSessionBudget is how many flows one connection may hold at once. It is per
// connection rather than machine-wide because a shared budget makes one busy network able to
// take every other network off the machine, which is the failure this mode must not have.
const fabricSessionBudget = 2048

func newFabricRunner(logger *slog.Logger, logf func(format string, args ...any), carriers fabric.Carriers,
	open func(ctx context.Context, opts fabric.LiveOptions) (fabricLive, error), poke func()) *fabricRunner {
	if open == nil {
		open = openFabric
	}
	if poke == nil {
		// A runner with no loop behind it, which is a test: the withdrawal below still happens
		// and is still readable in the status, there is just nobody to ask for the rebuild.
		poke = func() {}
	}
	return &fabricRunner{logger: logger, logf: logf, carriers: carriers, open: open, poke: poke}
}

// SetInspector replaces what examines the flows the interface carries, and applies it to
// the interface that is up. It is recorded whether or not one is, so an interface built
// later starts inspecting rather than waiting for the next settings edit.
func (r *fabricRunner) SetInspector(in fabric.Inspector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inspecting = in
	if r.live != nil {
		r.live.SetInspector(in)
	}
}

// registryCarriers is where the fabric looks up the connection an address belongs to.
//
// It holds the registry rather than a snapshot of it, because a flow arriving a moment after
// a connection came up has to find that connection: the table naming it is installed by the
// reconcile, and a copy taken then would be a list of connections that were running when the
// addressing was decided.
type registryCarriers struct{ registry *tunnel.Registry }

func (c registryCarriers) Carrier(id string) (fabric.Carrier, bool) {
	live, ok := c.registry.Get(id)
	if !ok {
		return nil, false
	}
	return live, true
}

// openFabric is the real seam: an interface on this machine, made through the privileged
// side.
func openFabric(ctx context.Context, opts fabric.LiveOptions) (fabricLive, error) {
	return fabric.Open(ctx, opts)
}

// applyFabric brings the interface into line with the settings and the running connections.
// It runs from the reconcile, after the connections have been started, because what the
// interface carries is decided from what they say they reach.
func (a *Agent) applyFabric(ctx context.Context) {
	runner := a.currentFabric()
	if runner == nil {
		return
	}
	runner.apply(ctx, a.fabricTarget(ctx))
}

func (a *Agent) currentFabric() *fabricRunner {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.fabric
}

// fabricTarget reads the settings and every running connection into what the interface
// should be doing.
func (a *Agent) fabricTarget(ctx context.Context) fabricTarget {
	s := a.settings()
	target := fabricTarget{
		name: s.InterfaceName,
		pool: slices.Clone(s.InterfaceVirtualPool),
		seed: spread.SeedFrom(s.MachineID),
	}
	if len(target.pool) == 0 {
		target.pool = slices.Clone(fabric.DefaultPool)
	}
	if !s.InterfaceEnabled {
		target.reason = "the network-interface module is off, so app-tail changes nothing about this machine"
		return target
	}
	if !s.FabricSelected() {
		target.reason = "this machine is set to reach your connections some other way, so no interface carrying all of them is created"
		return target
	}

	stored := a.runtimeTunnels()
	networks, names, anchors, mtu := a.fabricInputs(ctx, stored)

	// The interface's own addresses are claimed alongside this machine's, so nothing is ever
	// presented at an address the interface itself answers for.
	host, err := a.hostNetworks()
	if err != nil {
		// Said out loud and carried on: without them a connection carrying the addresses of
		// the network this machine is sitting on is placed there rather than moved, which is
		// the one wrong answer this module can give, and the alternative is no interface at
		// all.
		a.logger.Warn("this machine's own networks could not be read, so a connection carrying "+
			"addresses this machine already uses may not be moved out of the way", "error", err)
	}
	host = append(host, fabric.InterfaceAddrs(target.pool)...)

	plan := fabric.Allocate(networks, host, target.pool)
	mapped, unreachable := fabric.MappingsOf(plan)
	// Declaration order rather than map order: an unordered member list would produce a
	// different table on every pass, and replacing the addressing walks every open flow.
	var up []string
	for _, held := range stored {
		if _, running := names[held.ID]; running {
			up = append(up, held.ID)
		}
	}
	// The per-destination exceptions sit between the two: narrower than the catch-all that
	// carries everything else, and never over a range a connection already reaches.
	routed, direct := routeMappings(a.routes(), mapped, up)
	mapped = append(mapped, routed...)
	anchors = append(anchors, direct...)
	mapped = append(mapped, egressMappings(s, up)...)
	table, err := fabric.NewTable(mapped)
	if err != nil {
		// The allocator produced addressing this table refuses, which is a disagreement
		// between two parts of this app rather than anything the user did. Carrying on with
		// the previous table would leave the interface routing ranges the report says are
		// somewhere else, so it stops instead and says so.
		target.reason = fmt.Sprintf("the addressing for your connections could not be built: %v", err)
		return target
	}

	target.on = true
	target.mtu = mtu
	target.table = table
	target.names = names
	target.routes = table.Routes()
	target.exclude = anchors
	target.unreachable = unreachable
	target.conflicts = plan.Collisions
	return target
}

// everything is the two ranges that mean every address there is. They are what a machine
// sends to when nothing more specific covers a destination, which is the shape "send my
// internet traffic through this connection" takes on an interface.
var everything = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/0"),
	netip.MustParsePrefix("::/0"),
}

// egressMappings put this machine's internet traffic on the connection or connections
// carrying it. running is every connection that is up, in the order they are stored.
//
// They sort last of everything in the table, since every other entry covers a narrower
// range, so a network a connection actually reaches is still reached through that
// connection. Only what nothing else claims lands here.
//
// The modes differ in exactly one place, and it is the failure. One chosen connection that is
// not running maps nothing: what was chosen there is a route, and a route that is down leaves
// the machine on the network it was already on. Several chosen connections with none of them
// running -- and one chosen connection with the kill switch on -- map the route to nothing
// that can carry it, so the interface goes on claiming the traffic and refuses it. Choosing
// several is a statement about who may see the traffic, and the kill switch is that statement
// made about one; quietly answering either with the ISP link is the outcome they exclude.
//
// A connection that is running and not currently connected keeps its share either way: that
// is a connection on its way back, and letting traffic out around it in the meantime is the
// leak the setting exists to prevent.
func egressMappings(s config.Settings, running []string) []fabric.Mapping {
	chosen, held := egressCarriers(s, running)
	if len(chosen) == 0 && !held {
		return nil
	}
	out := make([]fabric.Mapping, 0, len(everything))
	for _, prefix := range everything {
		if held && len(chosen) == 0 {
			out = append(out, fabric.Mapping{TunnelID: fabric.Blocked, Prefix: prefix})
			continue
		}
		if len(chosen) == 1 {
			out = append(out, fabric.Mapping{TunnelID: chosen[0], Prefix: prefix})
			continue
		}
		out = append(out, fabric.Mapping{Members: chosen, Prefix: prefix})
	}
	return out
}

// routeMappings turn the per-destination exceptions into what an interface can carry: the
// ranges to send through one connection or refuse, and the ranges that must keep leaving
// through this machine's own network.
//
// Only ranges. A rule about a host cannot apply here, because a packet arriving on the
// interface carries an address and nothing else -- routing.Prefixes drops those, and the
// surfaces say so against the rule rather than leaving it looking like it applies.
//
// A range a connection already reaches is left alone, exactly as it is on the proxy path: a
// rule is about where this machine's own traffic goes, and letting one move a private
// network would break every one of them the moment somebody wrote a rule about 10.0.0.0/8.
//
// A rule naming a connection that is not running is refused rather than left out. Leaving
// it out would drop the destination through to whatever carries everything else, which is
// the leak the rule was written to prevent.
func routeMappings(rules []routing.Rule, carried []fabric.Mapping, running []string) (mapped []fabric.Mapping, direct []netip.Prefix) {
	for _, route := range routing.Prefixes(rules) {
		if slices.ContainsFunc(carried, func(m fabric.Mapping) bool {
			here := m.Here()
			return here.Bits() <= route.Prefix.Bits() && here.Contains(route.Prefix.Addr())
		}) {
			continue
		}
		switch {
		case route.Action == routing.Direct:
			direct = append(direct, route.Prefix)
		case route.Action == routing.Via && slices.Contains(running, route.Tunnel):
			mapped = append(mapped, fabric.Mapping{TunnelID: route.Tunnel, Prefix: route.Prefix})
		default:
			mapped = append(mapped, fabric.Mapping{TunnelID: fabric.Blocked, Prefix: route.Prefix})
		}
	}
	return mapped, direct
}

// egressCarriers are the running connections this machine's internet traffic is to leave
// through, and whether it is held here rather than sent out of this machine when there are
// none.
//
// An empty chosen list while the traffic is spread means every connection that is running,
// which is what somebody who switched the mode on without picking anything means by it.
func egressCarriers(s config.Settings, running []string) (chosen []string, held bool) {
	members, spread := s.EgressSpread()
	if !spread {
		// A chain leaves through its last connection: everything before it is carrying the
		// hop after it and nothing of this machine's own. The traffic is still held when that
		// last connection is down, which is what makes a chain a chain rather than a route.
		if exit := s.EgressExit(); exit != "" {
			if !slices.Contains(running, exit) {
				return nil, true
			}
			return []string{exit}, true
		}
		// One chosen connection is a route unless the kill switch is on, and the switch is the
		// difference between a route and a promise: with it on, the connection being down stops
		// the traffic here instead of leaving the machine on the network it was already on.
		one := s.EgressTunnel()
		if one == "" || !slices.Contains(running, one) {
			return nil, s.EgressHeld()
		}
		return []string{one}, s.EgressHeld()
	}
	if len(members) == 0 {
		return slices.Clone(running), true
	}
	for _, id := range members {
		if slices.Contains(running, id) {
			chosen = append(chosen, id)
		}
	}
	return chosen, true
}

// fabricInputs asks every running connection what it carries, what it is called, where its
// own packets go, and how big a packet it takes.
//
// The stored list is walked rather than the registry's, because declaration order is what
// decides who keeps a contested range: two connections carrying 10.0.0.0/8 have to be placed
// the same way on every pass, and map order is not that.
func (a *Agent) fabricInputs(ctx context.Context, stored []config.Tunnel) (networks []fabric.Network, names map[string]string, anchors []netip.Prefix, mtu int) {
	names = make(map[string]string, len(stored))
	for _, held := range stored {
		live, running := a.tunnels.Get(held.ID)
		if !running {
			continue
		}
		names[held.ID] = held.Name

		routes, err := live.Routes(ctx)
		if err != nil {
			// A connection that is up and cannot say what it reaches is a range missing from
			// an interface that otherwise looks complete, which is a host that resolves and
			// then never answers. It is said out loud; the connection's own card carries the
			// failure.
			a.logger.Warn("a connection could not say what it reaches, so its networks are not "+
				"on the interface", "connection", held.Handle(), "error", err)
		}
		// The ranges the network addresses its own members from come first, because they are
		// the network: a tailnet's devices live in its own allocation and no route is ever
		// published for it, so an interface built from carried routes alone reaches every
		// connection except the one this app has always had.
		if addressed, ok := live.(tunnel.Addressed); ok {
			networks = append(networks, presentedNetworks(held.ID, held.Name, addressed.Networks())...)
		}
		networks = append(networks, presentedNetworks(held.ID, held.Name, routes)...)

		// Every address this connection's own packets go to has to keep leaving through the
		// machine's own network. See tunnel.Anchored for what happens when one does not.
		if anchored, ok := live.(tunnel.Anchored); ok {
			for _, addr := range anchored.Anchors() {
				anchors = append(anchors, netip.PrefixFrom(addr, addr.BitLen()))
			}
		}

		// Only from a connection that is actually carrying traffic. The packet size is the
		// smallest any connected network takes, and a connection that is off or still coming
		// up is not one of them: letting it decide would shrink every other network's packets
		// for a network nothing is crossing.
		if sized, ok := live.(tunnel.Sized); ok && live.Status().State.Live() {
			if size := sized.MTU(); size > 0 && (mtu == 0 || size < mtu) {
				mtu = size
			}
		}
	}
	if mtu == 0 {
		// Nothing running says how big a packet it takes. The smallest a link is allowed to
		// carry is the only answer that is right for every network, and it is what the
		// interface is set to until something says otherwise.
		mtu = fabricFloorMTU
	}
	return networks, names, anchors, mtu
}

// fabricFloorMTU is the smallest packet size IPv6 requires a link to carry, used when no
// running connection states one. It is a floor rather than a guess: too small costs
// throughput, and too large silently drops datagrams.
const fabricFloorMTU = 1280

// apply brings the machine to the target state.
func (r *fabricRunner) apply(ctx context.Context, target fabricTarget) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !target.on {
		r.release(target.reason)
		return
	}

	r.unreachable, r.conflicts = target.unreachable, target.conflicts

	want := fabricBuild{name: target.name, pool: prefixKey(target.pool), mtu: target.mtu}
	if r.live != nil && (r.built != want || r.withdrawn) {
		// The interface is running on something the settings no longer ask for, or the stack
		// behind it stopped. Either way what is up cannot become what is wanted, so it goes
		// and the rest of this pass builds the replacement.
		r.teardown("")
	}
	if r.live == nil {
		live, err := r.open(ctx, fabric.LiveOptions{
			Name:          target.name,
			Pool:          target.pool,
			Carriers:      r.carriers,
			MTU:           target.mtu,
			SessionBudget: fabricSessionBudget,
			Seed:          target.seed,
			Logger:        r.logger,
			Logf:          r.logf,
		})
		if err != nil {
			r.failure = err.Error()
			r.reason = fmt.Sprintf("the interface carrying your connections could not be created: %v", err)
			return
		}
		r.live, r.built, r.carrying, r.addressing = live, want, "", ""
		live.SetInspector(r.inspecting)
		r.watch(live)
		r.logger.Info("every connection is now on one interface", "interface", live.Name(), "mtu", target.mtu)
	}

	// The addressing before the routes, always: a range routed to an interface whose table
	// does not carry it yet is a destination that fails while it is being set up, and this
	// runs on every reconcile.
	if addressing := tableKey(target.table, target.names); addressing != r.addressing {
		r.live.SetTable(target.table, target.names)
		r.addressing = addressing
	}

	key := routingKey(target.routes, target.exclude, target.mtu)
	if key != r.carrying {
		if err := r.live.Carry(ctx, target.routes, target.exclude, target.mtu); err != nil {
			r.logger.Warn("pointing this machine at the interface failed", "error", err)
			r.failure = err.Error()
			r.reason = fmt.Sprintf("this machine's routing table could not be pointed at the interface: %v", err)
			return
		}
		r.carrying = key
	}
	r.table = target.table
	r.failure, r.reason = "", ""
}

// needsAnotherPass reports whether the interface is in a state only another reconcile can
// get it out of: the stack behind it stopped and its networks were taken back off this
// machine, or the last pass could not build or point at it. Both are recoverable -- apply
// tears down what is left and builds the replacement -- so what they need is to be asked
// again rather than to be reported and left.
func (r *fabricRunner) needsAnotherPass() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.withdrawn || r.failure != ""
}

// watch withdraws the routes if the stack stops carrying traffic.
//
// It is the half of the dead-man's switch the privileged side cannot cover. That one fires
// when this process dies; this one fires when the process is alive and the thing behind the
// interface is not, which leaves the machine sending whole networks at an interface that
// answers nothing -- indistinguishable from a network being slow, for as long as nobody
// looks. Taking the ranges back off makes every one of those destinations fail immediately,
// the same way they fail when app-tail is not running at all.
func (r *fabricRunner) watch(live fabricLive) {
	ctx, cancel := context.WithCancel(context.Background())
	r.stopWatch = cancel
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-live.Done():
		}
		if !r.withdrawStopped(ctx, live) {
			return
		}
		// Outside the lock, and only where a withdrawal actually happened: the pass this asks
		// for is what tears down what is left and builds the replacement. A machine with its
		// networks taken back off it is the state that most needs the next pass to come, and
		// without this it would wait for an unrelated event to bring one.
		r.poke()
	}()
}

// withdrawStopped takes the machine back off the networks an interface that has stopped was
// carrying, and reports whether it was this runner's interface that stopped.
func (r *fabricRunner) withdrawStopped(ctx context.Context, live fabricLive) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.live != live {
		// Already replaced by a later pass, which took the routes with it.
		return false
	}
	r.withdrawn = true
	status := live.Status()
	r.failure = status.Error
	if r.failure == "" {
		r.failure = "the interface stopped carrying traffic"
	}
	r.reason = "the interface carrying your connections stopped: " + r.failure
	r.logger.Error("the interface carrying your connections stopped; taking its networks "+
		"back off this machine", "interface", live.Name(), "error", r.failure)
	if err := live.Withdraw(ctx); err != nil {
		r.logger.Error("taking the networks back off this machine failed, so they are still "+
			"being sent to an interface that answers nothing", "error", err)
		r.failure = err.Error()
	}
	// The addressing goes with the routing: with the ranges off this machine, a name answered
	// with an address inside one of them is a destination that fails slowly instead of a name
	// that fails.
	r.carrying, r.table, r.addressing = "", nil, ""
	return true
}

// release takes the machine back off its connections and lets go of the interface.
func (r *fabricRunner) release(reason string) {
	r.teardown(reason)
	r.unreachable, r.conflicts = nil, nil
}

// teardown closes what is running. The routes go with the interface: the privileged side
// undoes everything it installed when the session ends, which is what closing it is.
func (r *fabricRunner) teardown(reason string) {
	if r.stopWatch != nil {
		r.stopWatch()
		r.stopWatch = nil
	}
	var failed string
	if r.live != nil {
		if err := r.live.Close(); err != nil {
			r.logger.Warn("closing the interface carrying your connections failed", "error", err)
			failed = err.Error()
		}
	}
	r.live, r.built, r.carrying, r.withdrawn, r.table = nil, fabricBuild{}, "", false, nil
	r.reason = reason
	// A stated reason replaces whatever went wrong before it, because the mode being switched
	// off is not a failure. What went wrong on the way down is one, and it survives the
	// reason: an interface that would not close leaves this machine's routes pointing at
	// something the process no longer owns, which is the one thing the next attempt to switch
	// the mode on has to know.
	if reason != "" || failed != "" {
		r.failure = failed
	}
}

// close stops carrying and takes the machine back off its connections. It is the shutdown
// path, and it runs whether or not the mode is on.
func (r *fabricRunner) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.live == nil {
		return nil
	}
	r.release("app-tail is stopping")
	if r.failure != "" {
		return errors.New(r.failure)
	}
	return nil
}

// fabricSnapshot is what the API reports. It is a copy: the caller is a request goroutine
// and everything above runs on the lifecycle one.
type fabricSnapshot struct {
	running     bool
	status      fabric.Status
	reason      string
	failure     string
	unreachable []fabric.Placement
	conflicts   []fabric.Collision
}

func (r *fabricRunner) snapshot() fabricSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := fabricSnapshot{
		reason:      r.reason,
		failure:     r.failure,
		unreachable: slices.Clone(r.unreachable),
		conflicts:   slices.Clone(r.conflicts),
	}
	if r.live != nil {
		out.running, out.status = true, r.live.Status()
	}
	return out
}

// ports is what each port the interface carried has moved, and nothing when the interface is
// not up. Read straight off the live interface rather than through the snapshot: it is only
// ever asked for by the traffic sampler, and the snapshot is on every dashboard poll.
func (r *fabricRunner) ports() ([]bytecount.Row, bytecount.Row, int) {
	r.mu.Lock()
	live := r.live
	r.mu.Unlock()
	if live == nil {
		return nil, bytecount.Row{}, 0
	}
	return live.Ports()
}

// carriedTable is the addressing this machine is really reaching its connections by, and is
// nil when it is reaching none of them that way. The routing is what makes it real, so a
// table installed on a stack whose ranges never reached the routing table is not reported.
func (r *fabricRunner) carriedTable() *fabric.Table {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.carrying == "" {
		return nil
	}
	return r.table
}

// routingKey is what was last installed on the machine. Two passes with the same key install
// nothing, which matters because installing it is a privileged call and the reconcile runs
// every few seconds.
func routingKey(routes, exclude []netip.Prefix, mtu int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d\x00", mtu)
	b.WriteString(prefixKey(routes))
	b.WriteString("\x01")
	b.WriteString(prefixKey(exclude))
	return b.String()
}

// tableKey renders the addressing as one comparable string: which connection carries which
// network, where this machine reaches it, and what each connection is called, since the name
// is what a refusal names the connection by.
func tableKey(t *fabric.Table, names map[string]string) string {
	var b strings.Builder
	for _, m := range t.Mappings() {
		fmt.Fprintf(&b, "%s\x00%s\x00%s\x01", m.TunnelID, m.Prefix, m.PresentedAs)
	}
	b.WriteString("\x02")
	for _, id := range slices.Sorted(maps.Keys(names)) {
		fmt.Fprintf(&b, "%s\x00%s\x01", id, names[id])
	}
	return b.String()
}

// prefixKey renders a prefix list as one comparable string, in the order it was given: the
// order is part of what changed, since the allocator's order is what decides who keeps a
// contested range.
func prefixKey(in []netip.Prefix) string {
	var b strings.Builder
	for _, p := range in {
		b.WriteString(p.String())
		b.WriteString(",")
	}
	return b.String()
}
