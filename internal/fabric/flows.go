// SPDX-License-Identifier: MIT

package fabric

// One flow at a time: taken off the interface, decided against the address it arrived on,
// and re-dialled inside the network that address belonged to.
//
// A flow is decided once and is never re-judged while it runs, which is what makes several
// networks carrying the same addresses safe: the address that named the network was the one
// the program dialled, and re-deciding halfway through could only ever move a live
// connection to a different network at the same address.
//
// A flow whose answer no longer stands -- its network moved to another connection, the
// connection stopped carrying it, the connection carrying this machine's internet traffic
// changed -- is ended instead, by openFlows below. The program dials again and is answered
// by the addressing now in force.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/netpipe"
	"github.com/sellitus/app-tail/internal/spread"
)

// Carrier is one connection the fabric re-dials through. It is the one method of
// tunnel.Tunnel this module needs, taken as an interface so the whole of it is exercised
// without a private network to connect to.
type Carrier interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// Carriers is where the fabric finds the connection an address belongs to. A connection
// that has gone away is absent rather than an error: the flow is refused either way, and
// "not connected" is the ordinary state of a connection that is switched off.
type Carriers interface {
	Carrier(id string) (Carrier, bool)
}

// dialTimeout bounds one dial into a private network. The program on this machine is
// already waiting by then, so an address that is not answering should fail while it is
// still interested rather than hold the flow open for the operating system's own timeout.
const dialTimeout = 15 * time.Second

// udpIdle is how long a UDP flow is kept after the last datagram crossed it.
//
// UDP has no close, so without this every datagram to a new port would hold a socket and a
// goroutine for as long as the interface is up. It is generous enough for a DNS query and
// its answer, a QUIC connection between keepalives, and a VoIP call on hold.
const udpIdle = 2 * time.Minute

// udpSlack is how much longer than udpIdle a flow may be kept, in exchange for arming the
// read deadline once per that interval instead of once per datagram. A flow is cut after
// somewhere between udpIdle and udpIdle+udpSlack of quiet.
const udpSlack = time.Minute

// datagramBuffers holds the relay buffers between flows.
//
// One is taken per direction per open UDP flow, and at 64 KB each with a budget of 2048
// flows per connection that is memory worth reusing rather than allocating and discarding.
// They are the protocol's maximum rather than the interface's MTU because the far side of a
// connection is not bound by this interface's MTU, and a datagram read into a buffer too
// small for it is delivered truncated with nothing reporting the loss.
var datagramBuffers sync.Pool

// datagramBuffer takes a buffer from the pool, or makes one when it is empty.
func datagramBuffer() *[]byte {
	if held, ok := datagramBuffers.Get().(*[]byte); ok {
		return held
	}
	buf := make([]byte, maxPacket)
	return &buf
}

// sessionBudget is how many flows one connection may hold at once.
//
// Per connection rather than in total, and that is the whole point: a machine-wide cap
// would let one chatty network use up the budget and take every other network down with it,
// which is the failure a hub of several networks has and a single VPN does not.
const sessionBudget = 2048

// sessions counts what each connection is holding, and refuses past the budget.
type sessions struct {
	budget int
	mu     sync.Mutex
	held   map[string]int
}

func newSessions(budget int) *sessions {
	if budget <= 0 {
		budget = sessionBudget
	}
	return &sessions{budget: budget, held: make(map[string]int)}
}

// take claims one flow for a connection, reporting false when that connection is already
// holding its budget.
func (s *sessions) take(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.held[id] >= s.budget {
		return false
	}
	s.held[id]++
	return true
}

// release gives one flow back.
func (s *sessions) release(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.held[id] <= 1 {
		delete(s.held, id)
		return
	}
	s.held[id]--
}

// counts is what every connection is carrying.
func (s *sessions) counts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.held))
	for id, n := range s.held {
		out[id] = n
	}
	return out
}

// carriedFlow is one flow being carried: the address on this machine it arrived at, the
// answer the table gave for that address, and the way to end it.
type carriedFlow struct {
	at   netip.Addr
	dest Destination
	stop context.CancelFunc
}

// openFlows is every flow being carried right now, so a change of addressing can end the
// ones it answers differently.
//
// Separate from sessions, which counts flows per connection for the budget: this one has to
// name the address each flow was decided against, and the count is read on every dashboard
// poll while this is walked only when the addressing changes.
type openFlows struct {
	mu   sync.Mutex
	next uint64
	held map[uint64]carriedFlow
}

func newOpenFlows() *openFlows { return &openFlows{held: make(map[uint64]carriedFlow)} }

// add registers one flow and returns the handle it is removed by.
func (o *openFlows) add(at netip.Addr, dest Destination, stop context.CancelFunc) uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.next++
	o.held[o.next] = carriedFlow{at: at, dest: dest, stop: stop}
	return o.next
}

// remove forgets a flow that has ended on its own.
func (o *openFlows) remove(id uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.held, id)
}

// endWhatMoved ends every flow the given addressing answers differently, and reports how
// many that was.
//
// A flow whose address still resolves to the same connection and the same destination is
// left running: the addressing is replaced on every pass over the connections, most of which
// change nothing, and cutting live flows each time would be an interface that drops every
// connection every few seconds.
func (o *openFlows) endWhatMoved(t *Table) int {
	o.mu.Lock()
	var stops []context.CancelFunc
	for _, held := range o.held {
		if t.Still(held.at, held.dest) {
			continue
		}
		stops = append(stops, held.stop)
	}
	o.mu.Unlock()

	// Outside the lock: cancelling closes both sides of the flow, and the goroutine that
	// unwinds comes back here to remove itself.
	for _, stop := range stops {
		stop()
	}
	return len(stops)
}

// Inspector examines a flow before it is carried. It is declared here rather than imported
// so this package keeps knowing nothing about where a rule came from or how it is compiled.
type Inspector interface {
	// Refuse reports why a flow must not be carried, and whether it must not. A flow that
	// matched while inspection is only recording answers false: the match is already
	// recorded, and carrying it is what recording means.
	Refuse(f inspect.Flow) (reason string, refuse bool)
	// Watch reads the opening bytes of a flow that is being carried, and answers nil for a
	// flow it has nothing to read. It is separate from Refuse because it answers a question
	// Refuse cannot: what arrived here is packets addressed to an address, and the name the
	// program actually asked for is inside those first bytes and nowhere else.
	Watch(f inspect.Flow) netpipe.Stream
	// WatchDatagrams reads the datagrams of a flow that is being carried, and answers nil
	// for a flow it has nothing to read. It is separate from Watch because a datagram flow
	// has no opening to accumulate: what is readable is whole inside one datagram, and the
	// next datagram is a fresh message rather than the rest of this one.
	WatchDatagrams(f inspect.Flow) netpipe.Stream
	// Open decides whether an encrypted flow is opened so that Watch has something to read,
	// and answers the pair of connections to carry it between either way. For almost every
	// flow that is the pair it was handed, untouched.
	//
	// An error means this flow was going to be opened and could not be, which is a flow that
	// must not be carried: its opening bytes are gone, and the reason is usually that the far
	// end could not be verified. Nothing comes back with the error -- the caller cuts the two
	// ends it already holds.
	Open(ctx context.Context, f inspect.Flow, client, upstream net.Conn) (net.Conn, net.Conn, error)
}

// SetInspector replaces what examines the flows this interface carries. Nil inspects
// nothing, which is the switch being off and every state before the first compile.
func (f *Fabric) SetInspector(in Inspector) {
	if in == nil {
		f.inspector.Store(nil)
		return
	}
	f.inspector.Store(&in)
}

// inspects asks the inspector, and reports carrying the flow when there is none.
func (f *Fabric) inspects(flow inspect.Flow) (string, bool) {
	held := f.inspector.Load()
	if held == nil {
		return "", false
	}
	return (*held).Refuse(flow)
}

// opens asks whether a flow is opened, and answers the pair to carry it between. No inspector
// is the pair it was handed.
func (f *Fabric) opens(ctx context.Context, flow inspect.Flow, local, upstream net.Conn) (net.Conn, net.Conn, error) {
	held := f.inspector.Load()
	if held == nil {
		return local, upstream, nil
	}
	return (*held).Open(ctx, flow, local, upstream)
}

// carriedConn is the interface end of a carried connection, able to be cut rather than shut
// down.
//
// The endpoint lives in a userspace stack, so there is no socket underneath and no linger
// option to set: closing it sends a FIN, which is the shape of a request that ran to
// completion. Aborting it sends a reset, which is the shape of a filter -- and a filter is
// what happened when inspection stopped the connection.
type carriedConn struct {
	*gonet.TCPConn
	ep tcpip.Endpoint
}

// Cut tears the connection down the way a socket with its linger set to zero does. The close
// still runs, because the endpoint being torn down does not release what gonet holds around
// it.
func (c carriedConn) Cut() {
	c.ep.Abort()
	c.TCPConn.Close()
}

// watches asks for a reader of a flow's opening bytes, and answers none when there is no
// inspector.
func (f *Fabric) watches(flow inspect.Flow) netpipe.Stream {
	held := f.inspector.Load()
	if held == nil {
		return nil
	}
	return (*held).Watch(flow)
}

// watchesDatagrams asks for a reader of a datagram flow, and answers none when there is no
// inspector.
func (f *Fabric) watchesDatagrams(flow inspect.Flow) netpipe.Stream {
	held := f.inspector.Load()
	if held == nil {
		return nil
	}
	return (*held).WatchDatagrams(flow)
}

// destinationOf decides where a flow arriving at an address goes, or why it cannot go
// anywhere. The reason is a sentence rather than a code because it is what the dashboard
// shows and what the log line says, and there is nothing else anywhere that knows it.
// The destination is returned alongside a failure whenever the table answered, so a refusal
// is counted against the connection it was for rather than against none.
func (f *Fabric) destinationOf(at netip.AddrPort, protocol string) (Destination, Carrier, error) {
	dest, ok := f.Table().Choose(at.Addr(), spread.Key(f.seed, at.Addr()))
	if !ok {
		return Destination{}, nil, fmt.Errorf("%s is not on a network any connection carries", at.Addr())
	}
	// Before the carrier is looked up, so a flow that is refused here is refused whether or
	// not the connection carrying it happens to be running. The interface never has a name:
	// the program that opened this resolved one somewhere else, and what arrived is packets
	// addressed to an address.
	if reason, refuse := f.inspects(inspect.Flow{
		Addr:     at.Addr(),
		Port:     at.Port(),
		Where:    "the network interface",
		Protocol: protocol,
	}); refuse {
		return dest, nil, fmt.Errorf("%s %s", at.Addr(), reason)
	}
	if dest.TunnelID == Blocked {
		// The route is installed and the carrier is deliberately absent. Saying which of the
		// two it is matters: the traffic is being held here on purpose, and the alternative
		// the user would otherwise assume -- that it quietly went out over this machine's own
		// network -- is exactly what this state exists to prevent.
		return dest, nil, fmt.Errorf("%s leaves through the connections chosen for internet "+
			"traffic and none of them is running, so it is held here rather than sent out "+
			"over this machine's own network", at.Addr())
	}
	carrier, ok := f.carriers.Carrier(dest.TunnelID)
	if !ok {
		return dest, nil, fmt.Errorf("%s is on %s, which is not running", at.Addr(), f.nameOf(dest.TunnelID))
	}
	return dest, carrier, nil
}

// handleTCP takes one TCP connection off the interface.
//
// The dial happens before the handshake is completed, so a destination that refuses the
// connection is refused here too rather than accepted and then dropped -- which a program
// reads as "connected, then the server hung up" and spends a long time looking into. The
// forwarder's own in-flight cap is what bounds how many of these can be waiting at once.
func (f *Fabric) handleTCP(req *tcp.ForwarderRequest) {
	id := req.ID()
	at, from := localAddr(id), remoteAddr(id)

	dest, carrier, err := f.destinationOf(at, "tcp")
	if err != nil {
		f.refuse(dest, from, at, "tcp", err)
		req.Complete(true)
		return
	}
	if !f.sessions.take(dest.TunnelID) {
		f.refuse(dest, from, at, "tcp", fmt.Errorf("%s is already carrying %d connections, which is all it may hold at once",
			f.nameOf(dest.TunnelID), f.sessions.budget))
		req.Complete(true)
		return
	}

	go f.carryTCP(req, dest, at, from, carrier)
}

// carryTCP dials the destination and joins the two connections.
func (f *Fabric) carryTCP(req *tcp.ForwarderRequest, dest Destination, at, from netip.AddrPort, carrier Carrier) {
	defer f.sessions.release(dest.TunnelID)

	// Registered before the dial, so a flow whose network moves while it is still waiting on
	// a connection is ended there rather than completing into a network it no longer belongs
	// to.
	ctx, stop := context.WithCancel(f.ctx)
	defer stop()
	held := f.open.add(at.Addr(), dest, stop)
	defer f.open.remove(held)

	target := addressOf(dest.Addr, at.Port())
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	upstream, err := carrier.Dial(dialCtx, "tcp", target)
	if err != nil {
		f.refuse(dest, from, at, "tcp", fmt.Errorf("reaching %s on %s: %w", target, f.nameOf(dest.TunnelID), err))
		req.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, epErr := req.CreateEndpoint(&wq)
	if epErr != nil {
		closeQuietly(upstream)
		f.refuse(dest, from, at, "tcp", fmt.Errorf("accept the connection to %s: %v", at, epErr))
		req.Complete(true)
		return
	}
	// The request is finished with either way: the connection it produced is the endpoint,
	// and leaving it uncompleted holds one of the forwarder's in-flight slots forever.
	req.Complete(false)

	local := carriedConn{TCPConn: gonet.NewTCPConn(&wq, ep), ep: ep}
	counting := f.begin(dest.TunnelID, at.Port(), "tcp")
	defer counting.done()
	// The same flow the table was asked about, asked again for its opening bytes: what the
	// address alone could not answer is in them.
	inspecting := inspect.Flow{
		Addr:     at.Addr(),
		Port:     at.Port(),
		Where:    "the network interface",
		Protocol: "tcp",
	}
	watch := f.watches(inspecting)
	client, opened, err := f.opens(ctx, inspecting, local, upstream)
	if err != nil {
		// The ends this already holds are cut, rather than closed: a flow that was going to be
		// read and could not be is being stopped on purpose, and a reset is what tells the
		// program that rather than leaving it reading a connection that finished.
		netpipe.Reset(local)
		netpipe.Reset(upstream)
		// The window this flow was given back, on the one path that never reaches the copy that
		// would otherwise return it.
		if watch != nil {
			watch.Close()
		}
		f.logger.Warn("a carried connection was stopped rather than carried unread",
			"from", from.String(), "to", target, "connection", dest.TunnelID, "error", err)
		return
	}
	if err := netpipe.CopyWith(ctx, client, opened, counting.up, counting.down, watch); err != nil && ctx.Err() == nil {
		f.logger.Debug("a carried connection ended with an error",
			"from", from.String(), "to", target, "connection", dest.TunnelID, "error", err)
	}
}

// handleUDP takes one UDP flow off the interface.
//
// Unlike TCP there is no handshake to hold, so the endpoint is made first and the dial
// happens behind it: a datagram to a destination that is not there produces no answer,
// which is what a datagram to a destination that is not there produces anyway.
//
// A refusal is reported as unhandled, which is what makes the stack answer with "no such
// port" rather than silence. A program that gets it fails at once instead of waiting out its
// own timeout on a network nothing here carries.
func (f *Fabric) handleUDP(req *udp.ForwarderRequest) bool {
	id := req.ID()
	at, from := localAddr(id), remoteAddr(id)

	dest, carrier, err := f.destinationOf(at, "udp")
	if err != nil {
		f.refuse(dest, from, at, "udp", err)
		return false
	}
	if !f.sessions.take(dest.TunnelID) {
		f.refuse(dest, from, at, "udp", fmt.Errorf("%s is already carrying %d flows, which is all it may hold at once",
			f.nameOf(dest.TunnelID), f.sessions.budget))
		return false
	}

	var wq waiter.Queue
	ep, epErr := req.CreateEndpoint(&wq)
	if epErr != nil {
		f.sessions.release(dest.TunnelID)
		f.refuse(dest, from, at, "udp", fmt.Errorf("accept the flow to %s: %v", at, epErr))
		return false
	}
	go f.carryUDP(gonet.NewUDPConn(&wq, ep), dest, at, from, carrier)
	return true
}

// carryUDP dials the destination and moves datagrams both ways until neither side has sent
// one for long enough.
func (f *Fabric) carryUDP(local *gonet.UDPConn, dest Destination, at, from netip.AddrPort, carrier Carrier) {
	defer f.sessions.release(dest.TunnelID)
	defer closeQuietly(local)

	ctx, stop := context.WithCancel(f.ctx)
	defer stop()
	held := f.open.add(at.Addr(), dest, stop)
	defer f.open.remove(held)

	target := addressOf(dest.Addr, at.Port())
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	upstream, err := carrier.Dial(dialCtx, "udp", target)
	cancel()
	if err != nil {
		f.refuse(dest, from, at, "udp", fmt.Errorf("reaching %s on %s: %w", target, f.nameOf(dest.TunnelID), err))
		return
	}
	defer closeQuietly(upstream)

	// Both directions are cut when the interface goes down or the flow's network moves, so a
	// flow that nothing is sending on does not outlive the answer it was given.
	stopWatch := context.AfterFunc(ctx, func() {
		closeQuietly(local)
		closeQuietly(upstream)
	})
	defer stopWatch()

	counting := f.begin(dest.TunnelID, at.Port(), "udp")
	defer counting.done()
	// Only the outbound side is read: what a datagram flow says in the clear, it says on the
	// way out, and the answers coming back repeat the question that was already read.
	watch := f.watchesDatagrams(inspect.Flow{
		Addr:     at.Addr(),
		Port:     at.Port(),
		Where:    "the network interface",
		Protocol: "udp",
	})
	if watch != nil {
		defer watch.Close()
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		f.noteFlowEnd(ctx, dest, target, relayDatagrams(local, upstream, counting.up, watch))
		closeQuietly(upstream)
	}()
	go func() {
		defer wg.Done()
		f.noteFlowEnd(ctx, dest, target, relayDatagrams(upstream, local, counting.down, nil))
		closeQuietly(local)
	}()
	wg.Wait()
}

// noteFlowEnd records why one direction of a flow stopped, for the ends that are not the
// ordinary ones.
//
// Going quiet for udpIdle, and being cut because the interface went down or the flow's
// network moved, are how nearly every flow ends and say nothing. Anything else is what
// somebody asking why a program stopped getting answers needs, and this is the only place
// that knows it.
func (f *Fabric) noteFlowEnd(ctx context.Context, dest Destination, target string, err error) {
	if err == nil || ctx.Err() != nil {
		return
	}
	// A flow inspection stopped is already in the detection log, with the reason it was
	// stopped for. Repeating it here as a transport fault would say the opposite.
	if errors.Is(err, errStoppedByInspection) {
		return
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return
	}
	f.logger.Debug("a carried flow ended with an error",
		"to", target, "connection", dest.TunnelID, "error", err)
}

// errStoppedByInspection ends a datagram flow that inspection refused. It is a sentinel
// rather than a message because the caller has to tell it from a transport fault: one is a
// decision this app made and already recorded, the other is something that went wrong.
var errStoppedByInspection = errors.New("stopped by traffic inspection")

// relayDatagrams moves datagrams from one side to the other until the source has been quiet
// for udpIdle or either side has gone, reporting what ended it.
//
// Datagram boundaries are preserved, which a stream copy would not do: a single read is a
// single write, so a program that sent two datagrams never receives them joined into one.
//
// watch reads each datagram before it is passed on and is nil when nothing is reading them.
// Before, not after: a datagram offered once it has already been sent could be reported on
// but never stopped.
func relayDatagrams(src, dst net.Conn, report func(int64), watch netpipe.Stream) error {
	held := datagramBuffer()
	defer datagramBuffers.Put(held)
	buf := *held

	// The deadline is re-armed on a schedule rather than per datagram: setting it takes a
	// lock and reschedules a timer, and on a busy flow that is paid on every datagram to
	// move a deadline two minutes out. Arming it further out than udpIdle by the same amount
	// as the gap between arms is what keeps the promise exact in the direction that matters
	// -- a flow is never cut before it has been quiet for udpIdle, only up to udpSlack after.
	var rearmAfter time.Time
	for {
		if now := time.Now(); !now.Before(rearmAfter) {
			if err := src.SetReadDeadline(now.Add(udpIdle + udpSlack)); err != nil {
				return fmt.Errorf("arm the idle deadline on the flow: %w", err)
			}
			rearmAfter = now.Add(udpSlack)
		}
		n, err := src.Read(buf)
		if n > 0 {
			if watch != nil && watch.Up(buf[:n]) {
				return errStoppedByInspection
			}
			written, werr := dst.Write(buf[:n])
			if written > 0 && report != nil {
				report(int64(written))
			}
			if werr != nil {
				return fmt.Errorf("pass a datagram on: %w", werr)
			}
		}
		if err != nil {
			return err
		}
	}
}

// addressOf renders a destination inside a network the way a dial takes it.
func addressOf(addr netip.Addr, port uint16) string {
	return net.JoinHostPort(addr.Unmap().String(), strconv.Itoa(int(port)))
}

// closeQuietly ends one side of a flow that is already over.
//
// Both directions of a flow close the same pair, and the interface going down closes them a
// third time, so a failure here is almost always "already closed" -- and there is no caller
// left to report the rest to: the flow's outcome was decided before this ran.
func closeQuietly(closers ...io.Closer) {
	for _, c := range closers {
		if c != nil {
			c.Close()
		}
	}
}
