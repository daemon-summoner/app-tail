// SPDX-License-Identifier: MIT

package tsproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sellitus/app-tail/internal/access"
	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/netpipe"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// Refusals a proxy answers with. They are distinguished because they mean opposite things
// to whoever is debugging: one says nothing could work out where the destination is, the
// other says it worked that out and this instance is deliberately not allowed to go there.
var (
	// ErrUnreachable means no connection could say where the destination is -- typically
	// because the connection carrying it is not up yet.
	ErrUnreachable = errors.New("no connection could work out where that is")
	// ErrRefused means the destination is real and this instance's rules do not carry it.
	ErrRefused = errors.New("this proxy is not allowed to reach that")
)

// dialThisMachine opens connections that leave through this machine's own network, which is
// what a route to ThisMachine is. The dialer carries no timeout of its own: every dial here
// already runs under the instance's configured deadline.
func dialThisMachine(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// Inspector examines a destination before it is dialled. It is declared here rather than
// imported so this package keeps knowing nothing about where a rule came from or how it is
// compiled.
type Inspector interface {
	// Refuse reports why a destination must not be dialled, and whether it must not. A
	// destination that matched while inspection is only recording answers false: the match
	// is already recorded, and dialling it is what recording means.
	Refuse(f inspect.Flow) (reason string, refuse bool)
	// Watch reads the opening bytes of a tunnel this proxy carries, and answers nil for one
	// it has nothing to read. It is asked as well as Refuse because the two see different
	// names: a CONNECT names the host the client typed, and the handshake inside the tunnel
	// names the server the client is really reaching, which need not be the same one.
	Watch(f inspect.Flow) netpipe.Stream
	// Open decides whether an encrypted tunnel is opened so that Watch has something to read,
	// and answers the pair of connections to carry it between either way. For almost every
	// tunnel that is the pair it was handed, untouched.
	//
	// An error means this tunnel was going to be opened and could not be, which is a tunnel
	// that must not be carried: its opening bytes are gone, and the reason is usually that the
	// far end could not be verified. Nothing comes back with the error -- the caller cuts the
	// two ends it already holds.
	Open(ctx context.Context, f inspect.Flow, client, upstream net.Conn) (net.Conn, net.Conn, error)
}

// SetInspector replaces what examines the destinations these proxies dial. Nil inspects
// nothing, which is the switch being off and every state before the first compile.
func (s *Set) SetInspector(in Inspector) {
	if in == nil {
		s.inspector.Store(nil)
		return
	}
	s.inspector.Store(&in)
}

// inspects asks the inspector, and reports dialling the destination when there is none.
func (s *Set) inspects(flow inspect.Flow) (string, bool) {
	held := s.inspector.Load()
	if held == nil {
		return "", false
	}
	return (*held).Refuse(flow)
}

// watches asks for a reader of one tunnel's opening bytes, and answers none when there is no
// inspector.
func (s *Set) watches(flow inspect.Flow) netpipe.Stream {
	held := s.inspector.Load()
	if held == nil {
		return nil
	}
	return (*held).Watch(flow)
}

// opens asks whether one tunnel is opened, and answers the pair to carry it between. No
// inspector is the pair it was handed.
func (s *Set) opens(ctx context.Context, flow inspect.Flow, client, upstream net.Conn) (net.Conn, net.Conn, error) {
	held := s.inspector.Load()
	if held == nil {
		return client, upstream, nil
	}
	return (*held).Open(ctx, flow, client, upstream)
}

// dial resolves one destination, refuses it unless a rule allows it, and dials the address
// that was resolved rather than the name it was given.
//
// Dialing the name again would re-run DNS, which resolves in the permissive direction: the
// permission check would have passed on one address and the connection be made to another.
func (p *Instance) dial(ctx context.Context, network, address string) (net.Conn, error) {
	cfg := p.current()

	// socks5.Conn.handleTCP hands this call a context with a hardcoded five-second
	// deadline, which a first connection to a cold peer routinely exceeds while a path is
	// negotiated and a relay is settled for. Detaching from it is the only way the
	// configured timeout is the one that applies.
	dialCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.DialTimeout)
	defer cancel()

	route, err := p.set.resolve(dialCtx, network, address, cfg)
	if err != nil {
		p.stats.refuse()
		p.dests.entry(address).refused.Add(1)
		return nil, fmt.Errorf("%w: %s: %w", ErrUnreachable, address, err)
	}

	// Both the name the program asked for and the address it resolved to, because this is
	// the one path in the app that has both: everything else has lost the name by the time
	// it sees a connection.
	if reason, refuse := p.set.inspects(inspect.Flow{
		Name:     nameAsked(address),
		Addr:     route.Addr.Addr(),
		Port:     portAsked(address),
		Where:    "the proxy",
		Protocol: string(protocolOf(network)),
	}); refuse {
		p.stats.refuse()
		p.dests.entry(address).refused.Add(1)
		return nil, fmt.Errorf("%w: %s resolves to %s -- %s", ErrRefused, address, route.Addr, reason)
	}

	decision := access.Decide(cfg.Rules, requestFor(network, address, route))
	if !decision.Allowed {
		p.stats.refuse()
		p.dests.entry(address).refused.Add(1)
		// The reason names the rule that decided, or says that none did. A refusal a user
		// cannot trace to a line they can edit is a refusal they can only work around.
		return nil, fmt.Errorf("%w: %s resolves to %s on %s -- %s",
			ErrRefused, address, route.Addr, route.TunnelID, decision.Reason)
	}

	conn, err := p.dialRoute(dialCtx, network, route)
	if err != nil {
		p.stats.fail()
		p.dests.entry(address).failed.Add(1)
		return nil, fmt.Errorf("dialing %s (%s): %w", address, route.Addr, err)
	}
	return p.track(conn, address, route.TunnelID, string(protocolOf(network))), nil
}

// Verdict is what an instance would do with one destination, worked out without opening
// anything.
//
// It exists because a permission model nobody can question is one nobody trusts: the only
// way to know which rule governs a destination is to ask, and asking must not require
// pointing a program at the proxy and reading a failure out of its logs. Every input is
// the one a real dial uses -- the same resolver, the same rule list, the same matcher --
// so an answer here that disagreed with a dial would be a bug rather than an approximation.
type Verdict struct {
	// Address is what was asked about, verbatim.
	Address string
	// Allowed is the answer. It is false both for a destination the rules refuse and for
	// one nothing could locate; Resolved and Reason are what separate the two.
	Allowed bool
	// Resolved is the address the destination resolved to, empty when nothing could say.
	Resolved string
	// TunnelID is the connection that would carry it, ThisMachine when it would leave
	// through this machine's own network, and empty when nothing could say.
	TunnelID string
	// EgressID is the connection this machine's internet traffic leaves through, present
	// only on a destination no connection carries. It is what would actually move the
	// packets, while TunnelID stays what the rules were matched against.
	EgressID string
	// Rule is the id of the rule that decided and Index its position in the list, -1 when
	// no rule matched. Naming the line is the point of the endpoint.
	Rule   string
	Index  int
	Reason string
}

// Would reports what this instance would do with a destination, without dialling it.
func (p *Instance) Would(ctx context.Context, network, address string) Verdict {
	return p.set.Would(ctx, p.current(), network, address)
}

// Would reports what a configuration would do with a destination, without dialling it.
//
// It takes the configuration rather than a running instance so an instance that is stored
// but not listening -- switched off, or inside a module that is off -- can still be asked
// what it would reach. That is the case the question matters most in: somebody setting an
// instance up wants to know what they have granted before they point a program at it.
//
// A destination nothing can locate is an answer rather than an error: "no connection could
// work out where that is" is exactly what the person asking needs to see, and it is the
// same sentence a real dial would refuse with.
func (s *Set) Would(ctx context.Context, cfg Config, network, address string) Verdict {
	out := Verdict{Address: address, Index: -1}

	route, err := s.resolve(ctx, network, address, cfg)
	if err != nil {
		out.Reason = fmt.Sprintf("%s: %s", ErrUnreachable, err)
		return out
	}
	out.Resolved, out.TunnelID = route.Addr.String(), route.TunnelID
	if route.Egress != nil {
		out.EgressID = route.Egress.ID()
	}

	decision := access.Decide(cfg.Rules, requestFor(network, address, route))
	out.Allowed, out.Rule, out.Index, out.Reason =
		decision.Allowed, decision.Rule, decision.Index, decision.Reason
	return out
}

// requestFor is the destination as the rules see it: the name the program asked for, the
// address it resolved to, and the connection that carries it.
// nameAsked is the host half of a dial address when it is a name, and empty when the
// program dialled an address. An address returned here would be matched against the rules
// written as names, where it can only ever fail: the address half of a flow is carried
// separately and is what an entry about a network matches on.
func nameAsked(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	return host
}

// portAsked is the port half of a dial address, zero when there is none. It is what the
// program asked for rather than what the destination resolved to, because a run of
// connections to many ports is read as a scan and it is the asking that makes it one.
func portAsked(address string) uint16 {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

func requestFor(network, address string, route tunnel.Route) access.Request {
	req := access.Request{
		Addr:     route.Addr.Addr(),
		Port:     route.Addr.Port(),
		Protocol: protocolOf(network),
		Tunnel:   route.TunnelID,
	}
	// The host half only when it is a name. An address written into the request's Host
	// would be matched against host patterns, where it can only ever fail to match --
	// leaving a rule about a prefix looking as though it does not cover an address in it.
	if host, _, err := net.SplitHostPort(address); err == nil {
		if _, err := netip.ParseAddr(host); err != nil {
			req.Host = host
		}
	}
	return req
}

// protocolOf is the transport a dial network names, in the words a rule uses. Anything
// else is left unnamed rather than guessed: a rule about tcp must not silently cover a
// transport nobody classified.
func protocolOf(network string) access.Protocol {
	switch {
	case strings.HasPrefix(network, "tcp"):
		return access.TCP
	case strings.HasPrefix(network, "udp"):
		return access.UDP
	default:
		return access.AnyProtocol
	}
}

// dialRoute opens the connection the route decided on: through the connection carrying it,
// through the one this machine's internet traffic leaves by, or out of this machine when
// neither applies.
//
// The rules were matched before this, against the destination rather than against the
// transport, so pointing internet traffic at a connection changes where the packets go and
// changes nothing about what this instance is allowed to reach.
func (p *Instance) dialRoute(ctx context.Context, network string, route tunnel.Route) (net.Conn, error) {
	via := route.Via()
	if via == nil {
		return p.set.direct(ctx, network, route.Addr.String())
	}
	return via.Dial(ctx, network, route.Addr.String())
}

// track counts an established connection, keeps counting its bytes against both the
// proxy's totals and the destination it was opened to, and registers it so stopping the
// proxy can end it.
//
// The connection that carried it and the transport it went over are recorded here rather
// than derived later: which connection reaches an address is a routing decision that can
// change, and only the dial that just happened knows what it was this time.
func (p *Instance) track(conn net.Conn, address, tunnelID, protocol string) net.Conn {
	p.stats.opened.Add(1)
	p.stats.active.Add(1)

	dest := p.dests.entry(address)
	dest.opened.Add(1)
	dest.active.Add(1)
	dest.route.Store(&destRoute{tunnelID: tunnelID, protocol: protocol})
	p.dests.touch(dest)

	counted := &countedConn{Conn: conn, stats: &p.stats, dest: dest, dests: &p.dests, set: &p.conns}
	p.conns.add(counted)
	return counted
}

// liveConns is every upstream connection the proxy currently holds open.
//
// Switching the module off has to end them. The SOCKS5 server copies bytes on its own
// goroutines and closing the listener does not reach a connection already accepted, so
// without this a proxy that has been turned off keeps carrying tailnet traffic for as
// long as each connection happens to last -- indefinitely, for an SSH session.
type liveConns struct {
	mu    sync.Mutex
	conns map[*countedConn]struct{}
}

func (l *liveConns) add(c *countedConn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conns == nil {
		l.conns = make(map[*countedConn]struct{})
	}
	l.conns[c] = struct{}{}
}

func (l *liveConns) remove(c *countedConn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.conns, c)
}

// closeAll ends every tracked connection and reports the closes that failed for a
// reason other than the connection already being gone. Each Close removes its own
// entry, so the set is copied first rather than mutated while it is being walked.
func (l *liveConns) closeAll() error {
	l.mu.Lock()
	open := make([]*countedConn, 0, len(l.conns))
	for c := range l.conns {
		open = append(open, c)
	}
	l.mu.Unlock()

	var errs []error
	for _, c := range open {
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// counters are the proxy's live totals. They are read by the dashboard on a different
// goroutine from every connection that updates them, so each is atomic rather than
// guarded: a counter is never read together with another as one consistent pair.
type counters struct {
	opened  atomic.Int64
	active  atomic.Int64
	refused atomic.Int64
	failed  atomic.Int64
	upBytes atomic.Int64
	rxBytes atomic.Int64
}

func (c *counters) refuse() { c.refused.Add(1) }
func (c *counters) fail()   { c.failed.Add(1) }

func (c *counters) snapshot() Counters {
	return Counters{
		Opened:    c.opened.Load(),
		Active:    c.active.Load(),
		Refused:   c.refused.Load(),
		Failed:    c.failed.Load(),
		BytesUp:   c.upBytes.Load(),
		BytesDown: c.rxBytes.Load(),
	}
}

// countersOf is the proxy's totals together with where they went. The two are read
// separately -- the totals are atomics, the table takes a lock -- so they are a
// consistent pair only to the extent anything on a live dashboard is.
func (p *Instance) countersOf() Counters {
	out := p.stats.snapshot()
	out.Destinations, out.Other, out.Folded = p.dests.snapshot()
	return out
}

// Counters is the proxy's traffic as a value, for the API and the dashboard.
type Counters struct {
	Opened    int64 `json:"opened"`
	Active    int64 `json:"active"`
	Refused   int64 `json:"refused"`
	Failed    int64 `json:"failed"`
	BytesUp   int64 `json:"bytesUp"`
	BytesDown int64 `json:"bytesDown"`
	// Destinations is where that traffic went, busiest first, capped at maxDestinations.
	Destinations []DestCounters `json:"destinations,omitempty"`
	// Other is everything the cap left unnamed, and Folded how many distinct destinations
	// are summed into it. Both are zero on the ordinary install that never hit the cap.
	Other  DestCounters `json:"other,omitzero"`
	Folded int          `json:"folded,omitempty"`
}

// countedConn totals the bytes crossing one proxied connection. It counts at the
// upstream end so the numbers hold for every front end -- SOCKS5 copies bytes itself
// and never tells us how many.
type countedConn struct {
	net.Conn
	stats *counters
	// dest is this connection's share of the destination table. It is never nil: a
	// destination the table had no room to name is answered with the shared bucket, so
	// the byte path has no branch and no traffic goes uncounted.
	dest  *destEntry
	dests *destTable
	set   *liveConns
	// done makes the active count fall exactly once, however many times the conn is
	// closed: the SOCKS5 server closes its own, and so does whatever wraps it.
	done atomic.Bool
}

func (c *countedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.stats.rxBytes.Add(int64(n))
	c.dest.rxBytes.Add(int64(n))
	return n, err
}

func (c *countedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.stats.upBytes.Add(int64(n))
	c.dest.upBytes.Add(int64(n))
	return n, err
}

func (c *countedConn) Close() error {
	if c.done.CompareAndSwap(false, true) {
		c.stats.active.Add(-1)
		c.dest.active.Add(-1)
		c.dests.touch(c.dest)
		c.set.remove(c)
	}
	return c.Conn.Close()
}

// CloseWrite forwards the half close netpipe.Copy propagates. Without it the embedded
// net.Conn's method is hidden by this wrapper, every tunnel falls back to a full close,
// and a protocol that signals end-of-request by shutting down one direction -- an HTTP
// request body, say -- never receives its response.
func (c *countedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}
