// SPDX-License-Identifier: MIT

package tunnel

// Which connection carries a destination.
//
// With one network the question was "does this go via the tailnet", and the node itself
// could answer it. With several it is "which of these carries it, if any", and no single
// tunnel can answer that -- so it is asked of the registry, which is the only thing that
// holds them all.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/sellitus/app-tail/internal/access"
	"github.com/sellitus/app-tail/internal/routing"
)

// What a routing rule refuses a destination with. Each is a distinct fault with a distinct
// fix, which is why they are three errors rather than one: a rule the user wrote to refuse
// this destination, a rule pointing at a connection that is down, and a stored rule this
// build cannot read.
var (
	// ErrRouteBlocked is a destination a rule refuses outright.
	ErrRouteBlocked = errors.New("a routing rule refuses this destination")
	// ErrRouteDown is a destination whose rule names a connection that is not running.
	// It is a refusal rather than a fall back: sending it somewhere else would be exactly
	// the leak the rule was written to prevent.
	ErrRouteDown = errors.New("a routing rule sends this destination through a connection that is not running")
	// ErrRouteUnknown is a stored rule carrying an action this build does not know.
	ErrRouteUnknown = errors.New("a routing rule carries an instruction this version does not understand")
	// ErrNameBlocked is a name on one of the blocklists the user switched on. It is its
	// own error rather than a routing refusal because the fix is a different one: a rule
	// is edited where it was written, and this is undone by an allowlist entry or by
	// switching the list off.
	ErrNameBlocked = errors.New("this name is on a blocklist you turned on")
)

// ThisMachine is the connection id a route carries when no tunnel carries the
// destination: it leaves through the machine's own network, which is a grant of its own
// rather than an absence of one.
const ThisMachine = access.ThisMachine

// Reach is where a destination is, from one tunnel's point of view.
type Reach struct {
	// Addr is what the destination resolved to. It is what a caller dials: resolving the
	// name a second time invites the answer to change in between, and the direction it
	// changes is the permissive one.
	Addr netip.AddrPort
	// Carried reports that a dial to Addr would leave through this tunnel rather than
	// through the machine's own network.
	Carried bool
}

// Reaching is a tunnel that can say where a destination would go without dialling it. It
// is a capability because the answer is the tunnel's own routing table and its own
// resolver, and what those are differs entirely by kind.
type Reaching interface {
	Reach(ctx context.Context, network, address string) (Reach, error)
}

// Route is which connection carries a destination, and the address to dial.
type Route struct {
	// TunnelID is the connection carrying Addr, or ThisMachine when nothing does. It is
	// what an access rule is matched against, so the two readings are never conflated:
	// "no tunnel carries this" is a destination on this machine, not an unknown one.
	TunnelID string
	// Tunnel is the connection itself, and is nil for ThisMachine.
	Tunnel Tunnel
	Addr   netip.AddrPort
	// Egress is the connection this machine's internet traffic was set to leave through,
	// present only on a route no connection carries. It is deliberately not TunnelID:
	// carrying internet traffic is a transport, and reading it as the destination being on
	// that connection would turn a rule granting one connection into a grant of the whole
	// internet the moment somebody pointed egress at it.
	Egress Tunnel
}

// Direct reports that no connection carries this destination, so an access rule about it
// is a rule about this machine's own network. What actually carries the packets may still
// be a connection -- see Via -- and that is the distinction the two methods keep apart.
func (r Route) Direct() bool { return r.TunnelID == ThisMachine }

// Via is the tunnel to dial through, or nil for this machine's own network. A destination
// a connection carries goes through that connection; everything else goes through the
// egress connection when one is set, which is what "send my internet traffic through this"
// means at the point a dial is made.
func (r Route) Via() Tunnel {
	if r.Tunnel != nil {
		return r.Tunnel
	}
	return r.Egress
}

// hostResolver resolves a destination no tunnel knows about, through the machine's own
// network. It is a field on the registry rather than a package function so a test can
// answer without a network.
type hostResolver func(ctx context.Context, network, address string) (netip.AddrPort, error)

// SetHostResolver replaces how the registry resolves a destination no tunnel carries.
// Nothing but a test should need it: the default is this machine's own resolver, which is
// exactly what a destination outside every tunnel goes through.
func (r *Registry) SetHostResolver(fn func(ctx context.Context, network, address string) (netip.AddrPort, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hostAddrs = fn
}

// Resolve says which connection carries a destination, and what to dial.
//
// Tunnels are asked in declaration order and the first that carries the destination wins.
// That order is the tie-break for two networks whose address ranges overlap, and it is a
// deliberate one: the list is the user's own, so the network they put first is the one
// they meant. Nothing here silently merges two answers.
//
// A tunnel that cannot answer -- one that is not up yet -- is passed over rather than
// failing the whole question: the other connections may well carry the destination, and a
// connection coming up should not make every other one unreachable.
func (r *Registry) Resolve(ctx context.Context, network, address string) (Route, error) {
	if route, named, err := r.resolveNamed(ctx, network, address); named {
		return route, err
	}

	var (
		refusals []error
		// resolved is the first address any tunnel produced for a destination none of
		// them carries. It is kept because a rule about this machine is still matched on
		// the address, and re-resolving it below would be a second lookup that can differ.
		resolved netip.AddrPort
		haveAddr bool
	)

	// The routing rules on the destination as it was asked for. A rule refusing it is
	// answered before anything is resolved, so a blocked destination leaks neither the
	// traffic nor the query about it.
	host, asked := askedAbout(address)
	if decided := r.RouteFor(asked); decided.Decided && decided.Action == routing.Block {
		return Route{}, blockedBy(decided)
	}
	// Beside the rule check and for the same reason: a name that is not going to be reached
	// must not be looked up either, or the query itself tells the resolver what was wanted.
	// After resolveNamed above, so a name on one of app-tail's own connections is never
	// subject to a list downloaded off the internet.
	if list, blocked := r.blocks(host); blocked {
		return Route{}, fmt.Errorf("%w: on %s", ErrNameBlocked, list)
	}

	// The connection carrying internet traffic is chosen once, from the destination as it
	// was asked for. Choosing it again per lookup would let a name be resolved through one
	// connection and dialled through another, which is the split that makes a site load its
	// page from one country and its API from another.
	out := r.egressFor(address)

	for _, t := range r.All() {
		asker, ok := t.(Reaching)
		if !ok {
			continue
		}
		reach, err := asker.Reach(ctx, network, address)
		if err != nil {
			refusals = append(refusals, fmt.Errorf("%s: %w", t.ID(), err))
			continue
		}
		if reach.Carried {
			return Route{TunnelID: t.ID(), Tunnel: t, Addr: reach.Addr}, nil
		}
		if !haveAddr && reach.Addr.IsValid() {
			resolved, haveAddr = reach.Addr, true
		}
	}
	if haveAddr {
		return r.here(host, resolved, out)
	}

	addr, err := r.resolveHere(ctx, network, address, out)
	if err != nil {
		if errors.Is(err, ErrEgressHeld) {
			// On its own, because it is the answer rather than one candidate among the
			// connections that could not resolve: the destination is being held here on
			// purpose, and burying that under a list of lookup failures reads as a
			// resolver problem.
			return Route{}, err
		}
		// Both halves, because they fail for opposite reasons and the reader needs to
		// know which: a connection that is down is a temporary fault, and a name nothing
		// can resolve is a destination that does not exist.
		return Route{}, errors.Join(append(refusals, err)...)
	}
	return r.here(host, addr, out)
}

// askedAbout is the destination as the routing rules see it before anything resolves it:
// the name that was asked for, or the address when the destination was already one.
func askedAbout(address string) (host string, req routing.Request) {
	host, _, ok := splitHostPort(address)
	if !ok {
		return "", routing.Request{}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return "", routing.Request{Addr: addr.Unmap()}
	}
	return host, routing.Request{Host: host}
}

// blockedBy is the refusal a rule that blocks a destination produces. It names the rule,
// because a destination that simply stops working is one a user debugs as a network fault
// rather than as the line they wrote.
func blockedBy(decided routing.Decision) error {
	return fmt.Errorf("%w: %s", ErrRouteBlocked, decided.Reason)
}

// here is a route to a destination no connection carries: through whichever connection a
// routing rule names, out of this machine when a rule says so, and otherwise through
// whichever connection this machine's internet traffic was set to leave by.
//
// The rules are consulted again here, now that the address is known. A rule about an
// address range could not be matched against a name before it resolved, and leaving it
// unapplied would mean a range rule that works for an address literal quietly does nothing
// for a name that lands in the same range. What the second pass cannot undo is the lookup:
// the name was already resolved by whichever connection was chosen before it, so a range
// rule moves the traffic and never the query.
//
// With the traffic held and no connection carrying it, there is no route at all: this
// machine's own network is the one answer the setting exists to exclude, so the destination
// fails here rather than leaving.
func (r *Registry) here(host string, addr netip.AddrPort, out egressChoice) (Route, error) {
	if decided := r.RouteFor(routing.Request{Host: host, Addr: addr.Addr()}); decided.Decided {
		out = r.chosenBy(decided)
	}
	switch {
	case out.err != nil:
		return Route{}, out.err
	case out.tunnel != nil:
		return Route{TunnelID: ThisMachine, Addr: addr, Egress: out.tunnel}, nil
	case out.direct:
		// On purpose rather than for want of a connection, so the hold does not apply:
		// a rule saying this destination leaves the machine directly is the user naming
		// the exception the hold exists to have.
		return Route{TunnelID: ThisMachine, Addr: addr}, nil
	}
	if r.EgressHeld() {
		return Route{}, ErrEgressHeld
	}
	return Route{TunnelID: ThisMachine, Addr: addr}, nil
}

// egressChoice is where a destination no connection carries leaves through, and why. The
// three states are distinct answers rather than degrees of one: a connection to send it
// through, this machine's own network on purpose, or a refusal.
type egressChoice struct {
	// tunnel is the connection to send it through, nil when there is none.
	tunnel Tunnel
	// direct reports that it leaves through this machine's own network because something
	// said so, rather than because nothing else was available.
	direct bool
	// err refuses the destination outright.
	err error
}

// egressFor is the connection this machine's traffic to one destination leaves through.
//
// The destination decides which, so everything one site is made of leaves the same way. A
// name is keyed on the site rather than on the host, because a page and the API it calls are
// routinely different hosts under one name, and a provider that sees them arrive from two
// countries treats them as two visitors.
func (r *Registry) egressFor(address string) egressChoice {
	host, asked := askedAbout(address)
	if decided := r.RouteFor(asked); decided.Decided {
		return r.chosenBy(decided)
	}
	if host != "" {
		t, ok := r.EgressForName(host)
		return egressChoice{tunnel: pick(t, ok)}
	}
	t, ok := r.EgressFor(asked.Addr)
	return egressChoice{tunnel: pick(t, ok)}
}

// chosenBy turns a rule's decision into where the destination goes.
//
// A rule naming a connection that is not running is a refusal rather than a fall back to
// anything else: the rule is the user saying this destination goes one way, and quietly
// sending it another is the leak the whole feature exists to prevent.
func (r *Registry) chosenBy(decided routing.Decision) egressChoice {
	switch decided.Action {
	case routing.Block:
		return egressChoice{err: blockedBy(decided)}
	case routing.Direct:
		return egressChoice{direct: true}
	case routing.Via:
		t, running := r.Get(decided.Tunnel)
		if !running {
			return egressChoice{err: fmt.Errorf("%w: %s, and that connection is not running",
				ErrRouteDown, decided.Reason)}
		}
		return egressChoice{tunnel: t}
	default:
		// Validation refuses an action this build does not know, so this is a document
		// edited past it. Refusing is the safe reading: an unknown instruction about where
		// traffic goes must not resolve to "wherever it would have gone anyway".
		return egressChoice{err: fmt.Errorf("%w: %s", ErrRouteUnknown, decided.Reason)}
	}
}

// pick reduces a lookup that may have found nothing to the tunnel or nil, so an
// egressChoice is built the same way wherever it comes from. A nil Tunnel interface value
// is what "no connection" means here, and the two-value form would otherwise have to be
// carried through every caller.
func pick(t Tunnel, ok bool) Tunnel {
	if !ok {
		return nil
	}
	return t
}

// resolveNamed resolves a destination whose name says which connection it is on.
//
// named reports that the name carried a connection's suffix, and it is the whole point of
// the return: a name that named a connection is answered by that connection or not at all.
// Falling through to the other connections would undo what the suffix is for, since the
// networks that need it are the ones carrying each other's addresses -- the fall-through
// would reach the wrong network's host at the right address and report success.
func (r *Registry) resolveNamed(ctx context.Context, network, address string) (route Route, named bool, err error) {
	names := r.Naming()
	if names.Len() == 0 {
		return Route{}, false, nil
	}
	host, port, ok := splitHostPort(address)
	if !ok {
		return Route{}, false, nil
	}
	id, bare, named := names.Match(host)
	if !named {
		return Route{}, false, nil
	}

	if bare == "" {
		return Route{}, true, fmt.Errorf("%s names a connection rather than a host on it: "+
			"put the host in front of it, as db.%s", host, host)
	}
	t, running := r.Get(id)
	if !running {
		return Route{}, true, fmt.Errorf("%s is on a connection that is not running", host)
	}
	asker, canAsk := t.(Reaching)
	if !canAsk {
		return Route{}, true, fmt.Errorf("%s is on a connection that cannot resolve names", host)
	}
	reach, reachErr := asker.Reach(ctx, network, net.JoinHostPort(bare, port))
	if reachErr != nil {
		// The suffix rather than the whole name, so the sentence names the connection the
		// lookup was put to rather than repeating the name that was asked about.
		return Route{}, true, fmt.Errorf("resolving %s on %s: %w", bare, names.SuffixOf(id), reachErr)
	}
	if !reach.Addr.IsValid() {
		// The connection was asked and had no address for the name. It is the only
		// connection that can answer for this name, so this is the whole answer.
		return Route{}, true, fmt.Errorf("that connection knows no host called %s", bare)
	}
	if !reach.Carried {
		// The connection answered and does not carry what it answered with. Dialling it
		// anyway would leave through this machine's own network, to an address that means
		// something else there -- which is the wrong-network-right-address failure the
		// suffix exists to prevent, arrived at by a different road.
		return Route{}, true, fmt.Errorf("%s resolved to %s, which that connection does not carry",
			host, reach.Addr)
	}
	return Route{TunnelID: t.ID(), Tunnel: t, Addr: reach.Addr}, true, nil
}

// splitHostPort is net.SplitHostPort with the failure reduced to what a naming decision
// needs from it: a destination that is not a host and a port carries no name to match on,
// which is a fact about the destination rather than a failure to look at it. Resolve
// reports the shape itself, in the terms its caller already handles.
func splitHostPort(address string) (host, port string, ok bool) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", false
	}
	return host, port, true
}

// portNumber is a destination's port as a number, and whether it has one. It is the same
// reduction splitHostPort makes, for the same caller: a destination nothing can dial is a
// fact about the destination, and the arm that reports it is the one that reports every
// other malformed destination.
func portNumber(port string) (uint16, bool) {
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(n), true
}

// resolveHere resolves a destination no connection carries.
//
// When this machine's internet traffic leaves through a connection, the lookup goes
// through that connection's own resolver too. Otherwise every name dialled through it
// would first be asked of this network's resolver, which is the leak the setting exists to
// close: the traffic would be hidden and the list of what it was for would not be. A
// connection with no resolver of its own cannot close it, and the agent says so rather
// than pretending otherwise.
func (r *Registry) resolveHere(ctx context.Context, network, address string, out egressChoice) (netip.AddrPort, error) {
	switch {
	case out.err != nil:
		return netip.AddrPort{}, out.err
	case out.tunnel != nil:
		if addr, resolved, err := r.resolveThroughEgress(ctx, network, address, out.tunnel); resolved {
			return addr, err
		}
	case !out.direct && r.EgressHeld():
		// Before the lookup, not after: this machine's resolver would be asked for the
		// name, and a name asked on this network is the leak the setting closes even
		// when nothing is ever dialled.
		return netip.AddrPort{}, ErrEgressHeld
	}
	r.mu.RLock()
	fn := r.hostAddrs
	r.mu.RUnlock()
	if fn == nil {
		fn = lookupOnThisMachine
	}
	return fn(ctx, network, address)
}

// resolveThroughEgress resolves a name through the connection carrying internet traffic.
//
// resolved reports that the egress connection was the one asked, so a name it does not
// serve fails here rather than falling back: falling back would send the lookup to this
// network's resolver, which is exactly what asking the egress connection was for.
func (r *Registry) resolveThroughEgress(ctx context.Context, network, address string, out Tunnel) (addr netip.AddrPort, resolved bool, err error) {
	resolver, canResolve := out.(Resolving)
	if !canResolve {
		return netip.AddrPort{}, false, nil
	}
	host, portStr, splitOK := splitHostPort(address)
	if !splitOK {
		return netip.AddrPort{}, false, nil
	}
	if _, isLiteral := netip.ParseAddr(host); isLiteral == nil {
		// An address needs no resolver, so there is nothing here to leak.
		return netip.AddrPort{}, false, nil
	}
	port, portOK := portNumber(portStr)
	if !portOK {
		// A destination whose port is not a number is malformed rather than leaky, and the
		// ordinary path rejects it in the same words it rejects every other malformed
		// destination. Reporting it here instead would name the egress connection in a
		// failure that has nothing to do with where the traffic goes.
		return netip.AddrPort{}, false, nil
	}
	lookup, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return netip.AddrPort{}, true, fmt.Errorf("resolve %s through %s: %w", host, out.ID(), err)
	}
	if !lookup.Served() {
		return netip.AddrPort{}, true, fmt.Errorf(
			"%s carries this machine's internet traffic and its resolver knows no host called %s", out.ID(), host)
	}
	want := ipNetwork(network)
	for _, a := range lookup.Addrs {
		a = a.Unmap()
		if want == "ip4" && !a.Is4() {
			continue
		}
		if want == "ip6" && a.Is4() {
			continue
		}
		return netip.AddrPortFrom(a, port), true, nil
	}
	return netip.AddrPort{}, true, fmt.Errorf(
		"%s gave no %s address for %s", out.ID(), want, host)
}

// lookupOnThisMachine resolves a destination the way any other program on the machine
// would. An address literal is returned as it stands: there is no name to look up, and
// asking a resolver about one is a query that can only fail.
func lookupOnThisMachine(ctx context.Context, network, address string) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%q is not an address and port: %w", address, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%q is not a port: %w", portStr, err)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
	}

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, ipNetwork(network), host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve %s on this machine: %w", host, err)
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("this machine's resolver returned no address for %s", host)
	}
	return netip.AddrPortFrom(addrs[0].Unmap(), uint16(port)), nil
}

// ipNetwork narrows a dial network to the address family a lookup takes.
func ipNetwork(network string) string {
	switch network {
	case "tcp4", "udp4", "ip4":
		return "ip4"
	case "tcp6", "udp6", "ip6":
		return "ip6"
	}
	return "ip"
}
