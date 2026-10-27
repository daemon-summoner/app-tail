// SPDX-License-Identifier: MIT

package hostnet

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/dns"
)

// sessionHandover bounds the wait for a session another connection is holding.
//
// It is a wait rather than an immediate refusal because of one sequence: switching modes
// rebuilds the node, and the replacement asks for the interface while the connection the
// old one held is still being torn down -- routes removed, resolver files restored -- which
// takes real time. It is short because past that handover the holder is a second app-tail,
// and a caller parked behind an invisible lock is indistinguishable from one that is hung.
const sessionHandover = 5 * time.Second

// maxConnections bounds what one account can make this root process hold open at once. One
// of them is the session and the rest are scans, which are short; the cap is here because a
// privileged process whose memory an unprivileged caller can grow is not one worth having.
const maxConnections = 8

// tooManyConnections is what a caller over that cap is told, so it reports something better
// than a socket that accepted it and said nothing.
const tooManyConnections = "the privileged helper is already holding as many connections as it will"

// The four things a session can hold. They are separate because they have separate
// lifetimes: the interface comes and goes with the node -- every mode switch, every
// sign-out, every restart rebuilds it -- while the machine's resolver stays pointed at
// app-tail across all of that. One gate for all of them would mean a node restart dropping
// the connection that holds the override, and the machine's DNS reverting for as long as the
// restart takes.
//
// gateOpenVPN is a third rather than part of gateInterface for a reason that is the whole
// point of the feature: a machine may hold VPN connections and put itself on a tailnet at
// the same time, and folding the two into one gate would make them alternatives.
//
// gateTailnetRoutes is a fourth because what it covers is not app-tail's at all: it is the
// route belonging to whichever tailnet client this machine is running. Nothing app-tail holds
// is involved, so folding it into any of the others would make a repair wait on -- or block --
// a session about something else entirely.
const (
	gateInterface     = "interface"
	gateResolver      = "resolver"
	gateOpenVPN       = "openvpn"
	gateTailnetRoutes = "tailnet-routes"
)

// sessionGate is the right to change this machine, held by one connection at a time per
// thing changed. The helper owns a single network interface and a single machine-wide
// resolver setting, and two agents commanding either at once would each believe they held
// it.
type sessionGate struct {
	// held is fixed at construction and never written afterwards, so it is read from
	// every connection's goroutine without a lock.
	held map[string]chan struct{}
	wait time.Duration
}

func newSessionGate(wait time.Duration) *sessionGate {
	return &sessionGate{
		held: map[string]chan struct{}{
			gateInterface:     make(chan struct{}, 1),
			gateResolver:      make(chan struct{}, 1),
			gateOpenVPN:       make(chan struct{}, 1),
			gateTailnetRoutes: make(chan struct{}, 1),
		},
		wait: wait,
	}
}

// take claims one of the sessions, reporting whether it got it. It waits only for as long
// as a handover takes; past that the answer is no, and the caller is told so.
func (g *sessionGate) take(ctx context.Context, name string) bool {
	slot, ok := g.held[name]
	if !ok {
		// A gate nobody defined is nobody's to hand out. Reaching this means an operation
		// names a session this helper does not have, which is a programming error rather
		// than a busy machine, and refusing is the safe half of it.
		return false
	}
	select {
	case slot <- struct{}{}:
		return true
	default:
	}
	timer := time.NewTimer(g.wait)
	defer timer.Stop()
	select {
	case slot <- struct{}{}:
		return true
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	}
}

// tryTake claims one of the sessions only if nobody holds it, without waiting.
func (g *sessionGate) tryTake(name string) bool {
	slot, ok := g.held[name]
	if !ok {
		return false
	}
	select {
	case slot <- struct{}{}:
		return true
	default:
		return false
	}
}

// release hands one session on. It runs after the holder's teardown, never before, so the
// next holder does not install an interface into a machine still being restored.
func (g *sessionGate) release(name string) {
	if slot, ok := g.held[name]; ok {
		<-slot
	}
}

// Serve answers helper requests on ln until ctx is cancelled or the listener is closed,
// without the resolver watch RunHelper adds.
func Serve(ctx context.Context, ln *net.UnixListener, logf func(format string, args ...any)) error {
	return serve(ctx, ln, newSessionGate(sessionHandover), machineGrantPolicy(), logf)
}

// serve runs the helper until ctx is cancelled or the listener is closed. The gate is passed
// in because the helper's resolver watch shares it with every connection.
//
// Connections are served alongside each other, and the session -- everything that changes
// this machine -- is held by one of them at a time. Reading what the machine can do changes
// nothing and is answered on any connection: that is what lets the doctor report on a
// machine whose node is running, and what lets an agent find out whether the interface mode
// is available before it gives up the node that is holding the session.
func serve(ctx context.Context, ln *net.UnixListener, gate *sessionGate, policy grantPolicy, logf func(format string, args ...any)) error {
	return serveWith(ctx, ln, gate, func(check openvpnAddressCheck) commanded {
		host := NewLocal(logf)
		host.openvpnAddrs = check
		return host
	}, policy, logf)
}

// serveWith is serve with the privileged side each connection commands passed in, and the
// approvals each request that moves the machine is held to. newHost is given the session's
// check for the addresses an OpenVPN server hands out, which the host applies as connections
// come up.
//
// It is a seam rather than a call to NewLocal because the thing worth pinning about this
// helper is what a dropped connection does to the machine -- routes removed, this machine's
// resolver put back -- and that is exactly what a suite cannot produce with the real one: it
// would need root, a network interface and a machine whose DNS the suite is willing to
// change.
func serveWith(ctx context.Context, ln *net.UnixListener, gate *sessionGate, newHost func(check openvpnAddressCheck) commanded, policy grantPolicy, logf func(format string, args ...any)) error {
	if logf == nil {
		return errors.New("hostnet: the helper needs a log function; a privileged process that cannot report a failure is worse than one that will not start")
	}
	live := &liveConnections{logf: logf}
	// Closing the listener is what unblocks Accept, which has no context of its own, and
	// closing the accepted connections is what unblocks the sessions, whose read has no
	// deadline of its own. Without the second one a helper told to stop while an agent is
	// connected waits on that agent forever, gets killed by its service manager, and takes
	// none of the teardowns below with it.
	go func() {
		<-ctx.Done()
		if err := ln.Close(); err != nil {
			logf("could not close the helper socket while shutting down: %v", err)
		}
		live.closeAll()
	}()

	// A session's teardown is this helper's whole promise, so the loop does not return
	// while one is still undoing what it did.
	var open sync.WaitGroup
	defer open.Wait()
	slots := make(chan struct{}, maxConnections)

	for {
		conn, err := ln.AcceptUnix()
		// Checked first, because a cancelled context is a clean stop however Accept came
		// back: the goroutine above closes the listener, which is how the cancellation
		// reaches this call, and a connection accepted in the same moment belongs to a
		// helper that is going away.
		if ctx.Err() != nil {
			if err == nil {
				if cerr := conn.Close(); cerr != nil {
					logf("could not close a connection accepted while shutting down: %v", cerr)
				}
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("accept a connection on the helper socket: %w", err)
		}
		select {
		case slots <- struct{}{}:
		default:
			refuse(conn, tooManyConnections, logf)
			continue
		}
		open.Add(1)
		live.add(conn)
		go func() {
			defer open.Done()
			defer func() { <-slots }()
			defer live.remove(conn)
			approved := newApprovals(policy)
			serveConnection(ctx, conn, gate, newHost(approved.openVPNAddresses), approved, logf)
		}()
	}
}

// liveConnections is the set of connections the helper has accepted, so that a stop can end
// them rather than wait on them.
type liveConnections struct {
	mu     sync.Mutex
	closed bool
	conns  map[*net.UnixConn]struct{}
	logf   func(format string, args ...any)
}

// add takes a connection into the set, or closes it when the set is already shut: a
// connection accepted in the same moment the helper was told to stop belongs to a helper that
// is going away.
func (l *liveConnections) add(conn *net.UnixConn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		l.close(conn)
		return
	}
	if l.conns == nil {
		l.conns = make(map[*net.UnixConn]struct{}, maxConnections)
	}
	l.conns[conn] = struct{}{}
}

func (l *liveConnections) remove(conn *net.UnixConn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.conns, conn)
}

func (l *liveConnections) closeAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	for conn := range l.conns {
		l.close(conn)
	}
	clear(l.conns)
}

// close reports every failure except the one that is this design working: the session owning
// the connection closes it too, on its own way out, and one of the two closes loses the race.
func (l *liveConnections) close(conn *net.UnixConn) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		l.logf("could not close an agent's connection while shutting down: %v", err)
	}
}

// refuse turns a connection away with a reason and closes it.
func refuse(conn *net.UnixConn, why string, logf func(format string, args ...any)) {
	// The reason is sent so the caller reports something better than a closed socket: a
	// caller that cannot say why it was refused sends people looking in the wrong place.
	if err := writeMessage(conn, response{Error: why}); err != nil {
		logf("could not tell a caller why it was refused: %v", err)
	}
	if err := conn.Close(); err != nil {
		logf("could not close a refused connection: %v", err)
	}
}

// serveConnection runs one caller's whole connection, and undoes everything it changed when
// it ends.
//
// The teardown on the way out is the dead-man's switch, and it is the reason a session is a
// connection rather than a series of calls: it runs when the agent closes the connection,
// when the agent is killed, and when the agent's machine loses the process for any other
// reason -- all of which the kernel reports the same way, as this read returning. There is
// nothing the agent has to remember to do.
func serveConnection(ctx context.Context, conn *net.UnixConn, gate *sessionGate, host commanded, approved *approvals, logf func(format string, args ...any)) {
	defer func() {
		if err := conn.Close(); err != nil {
			logf("could not close the agent's connection: %v", err)
		}
	}()

	// Authenticated before anything is registered to be undone. A refused connection
	// changed nothing, so running a teardown pass for it would be this side doing work on
	// behalf of a caller it just turned away -- and every one of those passes touches the
	// machine's routes and resolver files.
	//
	// The owner's account is not enough on its own: every program that account runs shares
	// it, so the connecting process also has to be running this program. Root is not asked,
	// for the reason it passes the owner check.
	asRoot, err := peerIsOwner(conn)
	if err == nil && !asRoot {
		err = peerRunsThisProgram(conn)
	}
	if err != nil {
		logf("refused a connection: %v", err)
		if err := writeMessage(conn, response{Error: err.Error()}); err != nil {
			logf("could not tell the caller why it was refused: %v", err)
		}
		return
	}

	holding := make(map[string]bool, 2)
	// Registered before the teardown so it runs after it: neither session is free until
	// the machine this one changed has been put back.
	defer func() {
		for name, held := range holding {
			if held {
				gate.release(name)
			}
		}
	}()

	// Every path out of here runs this, including a panic in a handler: the whole purpose
	// of the helper is that the machine does not keep app-tail's routes, resolver files or
	// DNS override after app-tail is gone. A connection that only read is closing something
	// that opened nothing.
	defer func() {
		if err := host.Close(); err != nil {
			logf("could not undo this session's changes: %v", err)
		}
	}()

	r := bufio.NewReader(conn)
	for {
		var req request
		if err := readMessage(r, &req); err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				logf("the session ended: %v", err)
			}
			return
		}
		if err := respond(ctx, conn, host, req, gate, holding, approved, logf); err != nil {
			logf("could not answer %s: %v", req.Op, err)
			return
		}
	}
}

// respond claims the session an operation needs and performs it, or tells the caller that
// session is somebody else's. What this connection holds is recorded in holding, which its
// teardown reads. Only a failure to reply at all is returned; a failure of the operation is
// a reply carrying the reason.
func respond(ctx context.Context, conn *net.UnixConn, host commanded, req request, gate *sessionGate, holding map[string]bool, approved *approvals, logf func(format string, args ...any)) error {
	if name := needsSession(req.Op); name != "" && !holding[name] {
		if !gate.take(ctx, name) {
			logf("refused %s: another connection holds the %s session", req.Op, name)
			return writeMessage(conn, response{Error: ErrHelperBusy.Error()})
		}
		holding[name] = true
	}
	return answer(ctx, conn, host, req, approved, logf)
}

// needsSession reports which session an operation belongs to, empty for one that belongs to
// none.
//
// Everything that changes this machine holds one, and so does everything that reads through
// the interface a session opened. What is left is a scan of the machine itself, which
// changes nothing and costs the holder nothing, so any connection may ask for it -- that is
// what lets the doctor report on a machine whose node is running. An operation this helper
// does not have claims nothing: it is answered as unknown.
func needsSession(op string) string {
	switch op {
	case opOpenTUN, opRouterUp, opSetRoutes, opSetHostRoutes, opSetDNS, opBaseDNS, opSplitDNS,
		opScopeHostDefault, opUnscopeHostDefault:
		return gateInterface
	case opOpenResolver, opSetSystemDNS:
		return gateResolver
	case opRunOpenVPN, opStopOpenVPN, opScopeOpenVPN, opUnscopeOpenVPN:
		return gateOpenVPN
	case opRepairTailnetRoutes:
		return gateTailnetRoutes
	}
	return ""
}

// commanded is the privileged side a session commands: the boundary's two interfaces, plus
// the one thing only a helper does with an interface it created -- keep a reference to it,
// so the session's teardown can take it back from the agent it was handed to.
type commanded interface {
	Host
	SystemResolver
	OpenVPNRunner
	TailnetRouteRepairer
	Retain(dev tun.Device)
}

// answer performs one operation and replies. A failure of the operation is a reply
// carrying the reason; only a failure to reply at all ends the session.
//
// An operation that moves the machine is checked against what an administrator approved
// after it is checked for shape: a request that is malformed is refused for that, whatever
// it would have needed.
func answer(ctx context.Context, conn *net.UnixConn, host commanded, req request, approved *approvals, logf func(format string, args ...any)) error {
	refuseUnapproved := func(err error) error {
		logf("refused %s: %v", req.Op, err)
		return writeMessage(conn, grantRefusal(err))
	}
	switch req.Op {
	case opCapabilities:
		caps, err := host.Capabilities(ctx)
		if err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		return writeMessage(conn, response{Capabilities: &caps})

	case opOpenTUN:
		// The name is the one value in this request the caller chooses, and it travels on
		// into interface creation as root, so it is held to the shape an interface name
		// on this platform can have before anything is created.
		if err := validTUNName(req.Name, runtime.GOOS); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		dev, name, err := host.OpenTUN(ctx, req.Name)
		if err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		handed, err := handOver(conn, name, dev, logf)
		if err != nil || !handed {
			return err
		}
		// The descriptor is now open in both processes, and both references have to be
		// dropped for the interface to go away. This one is kept for exactly that
		// reason: it is what the teardown closes, and closing it here instead would
		// leave the agent holding the only reference to an interface this helper is
		// supposed to be able to take back.
		host.Retain(dev)
		return nil

	case opRouterUp:
		if err := host.RouterUp(ctx); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		return writeMessage(conn, response{})

	case opSetRoutes:
		// Checked here for the same reason set-host-routes is: this side holds the rights
		// and the caller does not, and where this machine's traffic goes is the one thing
		// an unprivileged caller must not be able to move.
		if err := validateRouterConfig(req.Router); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		if err := approved.routerConfig(req.Router); err != nil {
			return refuseUnapproved(err)
		}
		if err := host.SetRoutes(ctx, req.Router); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		return writeMessage(conn, response{})

	case opSetHostRoutes:
		var routes Routes
		if req.Host != nil {
			routes = *req.Host
		}
		// Checked here rather than only in the caller: this side holds the rights, the
		// caller does not, and a check that only runs before the message is sent is a check
		// on the well-behaved.
		if err := routes.Validate(); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		if err := approved.hostRoutes(&routes); err != nil {
			return refuseUnapproved(err)
		}
		if err := host.SetHostRoutes(ctx, routes); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		return writeMessage(conn, response{})

	case opScopeHostDefault:
		if err := host.ScopeHostDefault(ctx); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		return writeMessage(conn, response{})

	case opRepairTailnetRoutes:
		repaired, err := host.RepairTailnetRoutes(ctx, req.Interface)
		if err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		return writeMessage(conn, response{Repaired: repaired})

	case opUnscopeHostDefault:
		if err := host.UnscopeHostDefault(ctx); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		return writeMessage(conn, response{})

	case opBaseDNS:
		cfg, err := host.BaseDNS(ctx)
		if err != nil {
			// The platform's "will not say" sentinel travels as its own sentence and is
			// matched on the other side, because the caller acts on it differently from
			// a real failure: it takes over resolution entirely instead of giving up.
			return writeMessage(conn, response{Error: err.Error()})
		}
		return writeMessage(conn, response{DNS: &cfg})

	case opSplitDNS:
		ok, err := host.SplitDNS(ctx)
		if err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		return writeMessage(conn, response{SplitDNS: ok})

	case opSetDNS:
		var cfg dns.OSConfig
		if req.DNS != nil {
			cfg = *req.DNS
		}
		if err := checkInterfaceDNS(cfg); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		if err := approved.interfaceDNS(cfg); err != nil {
			return refuseUnapproved(err)
		}
		if err := host.SetDNS(ctx, cfg); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		return writeMessage(conn, response{})

	case opOpenResolver:
		want, err := requestedListen(req.Listen)
		if err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		return openResolver(ctx, conn, host, req.Proto, want, logf)

	case opSetSystemDNS:
		resolvers, err := parseResolvers(req.Resolvers)
		if err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		if err := approved.systemDNS(resolvers); err != nil {
			return refuseUnapproved(err)
		}
		if err := host.SetSystemDNS(ctx, resolvers); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		return writeMessage(conn, response{})

	case opBaseSystemDNS:
		base, err := host.BaseSystemDNS(ctx)
		if err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		return writeMessage(conn, response{SystemDNS: &base})

	case opRunOpenVPN:
		if req.OpenVPN == nil {
			return writeMessage(conn, response{Error: "no connection was given to run"})
		}
		// Checked here as well as in StartOpenVPN, and deliberately: this is the operation
		// that starts a program holding administrator rights, so the refusal sits at the
		// point where the message arrives rather than only where it is acted on.
		if err := req.OpenVPN.Validate(); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		if err := approved.openVPN(*req.OpenVPN); err != nil {
			return refuseUnapproved(err)
		}
		if err := host.StartOpenVPN(ctx, *req.OpenVPN); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		approved.startedOpenVPN(*req.OpenVPN)
		return writeMessage(conn, response{})

	case opScopeOpenVPN:
		if req.Scope == nil {
			return writeMessage(conn, response{Error: "no connection was given to route"})
		}
		// Checked here as well as in ScopeOpenVPN, for the reason the run is: this side holds
		// the rights, and the refusal sits at the point where the message arrives rather than
		// only where it is acted on.
		if err := req.Scope.Validate(); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		if err := approved.scopeOpenVPN(req.Scope.ID); err != nil {
			return refuseUnapproved(err)
		}
		if err := host.ScopeOpenVPN(ctx, *req.Scope); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		return writeMessage(conn, response{})

	case opUnscopeOpenVPN:
		if !validConnectionID(req.ID) {
			return writeMessage(conn, response{Error: fmt.Sprintf("%q is not a connection identifier", req.ID)})
		}
		if err := host.UnscopeOpenVPN(ctx, req.ID); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		return writeMessage(conn, response{})

	case opStopOpenVPN:
		if !validConnectionID(req.ID) {
			return writeMessage(conn, response{Error: fmt.Sprintf("%q is not a connection identifier", req.ID)})
		}
		if err := host.StopOpenVPN(ctx, req.ID); err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		approved.stoppedOpenVPN(req.ID)
		return writeMessage(conn, response{})

	default:
		// An unknown operation is answered rather than ignored, and the session goes
		// on: it means the two sides disagree about the protocol, which the version
		// check should already have caught, and saying so is how that gets diagnosed.
		logf("refused an operation this helper does not have: %q", req.Op)
		return writeMessage(conn, response{Error: fmt.Sprintf("this helper has no operation called %q", req.Op)})
	}
}

// openResolver binds one half of the resolver socket and hands its descriptor over.
//
// A socket whose descriptor cannot be reached is closed here rather than replied around: the
// caller has nothing to close it with, and a listening socket on port 53 that nothing is
// reading from answers every query on this machine with silence.
func openResolver(ctx context.Context, conn *net.UnixConn, host commanded, proto string, want netip.AddrPort, logf func(format string, args ...any)) error {
	switch proto {
	case protoUDP:
		pc, err := host.OpenResolverPacket(ctx, want)
		if err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		sock, ok := pc.(socketFile)
		if !ok {
			closeQuietly(pc)
			return writeMessage(conn, response{Error: fmt.Sprintf("a %T has no descriptor to hand over", pc)})
		}
		return handOverResolver(conn, sock, pc.LocalAddr().String(), logf)

	case protoTCP:
		ln, err := host.OpenResolverStream(ctx, want)
		if err != nil {
			return writeMessage(conn, response{Error: err.Error()})
		}
		sock, ok := ln.(socketFile)
		if !ok {
			closeQuietly(ln)
			return writeMessage(conn, response{Error: fmt.Sprintf("a %T has no descriptor to hand over", ln)})
		}
		return handOverResolver(conn, sock, ln.Addr().String(), logf)
	}
	return writeMessage(conn, response{Error: fmt.Sprintf("this helper has no resolver socket of kind %q", proto)})
}

// handOver sends the interface's name and its open descriptor together, and reports whether
// the interface is now the caller's. Everything the agent does with the interface afterwards
// is ordinary unprivileged I/O on a descriptor it had no right to create, so this is the
// whole of what the privileged side hands out.
//
// An interface that could not be handed over is closed here: the caller has nothing to close
// it with, and one left open holds a network interface on the machine with nothing driving
// it.
func handOver(conn *net.UnixConn, name string, dev tun.Device, logf func(format string, args ...any)) (bool, error) {
	file := dev.File()
	if file == nil {
		closeInterface(logf, dev)
		return false, writeMessage(conn, response{Error: "this platform's interface has no descriptor to hand over"})
	}
	if err := writeWithFile(conn, response{Interface: name}, file); err != nil {
		closeInterface(logf, dev)
		return false, err
	}
	return true, nil
}

// closeInterface releases an interface the helper opened and could not hand over. The
// reply carries the reason it could not; a close that also fails goes to the log, where it
// is the one record that the machine may still be carrying the interface.
func closeInterface(logf func(format string, args ...any), dev tun.Device) {
	if err := dev.Close(); err != nil {
		logf("could not close the interface that could not be handed over: %v", err)
	}
}

// RunHelper is the helper's whole entry point: listen, serve, and exit when told to.
//
// It refuses to run unprivileged. A helper without the rights would accept connections,
// answer every one with a permission failure, and look from the agent's side exactly like
// a machine where the interface mode does not work -- when the real problem is that it
// was started the wrong way.
func RunHelper(ctx context.Context, socketPath string, logf func(format string, args ...any)) error {
	if !Supported() {
		return ErrUnsupported
	}
	if !HasHelper() {
		return errNoHelperOnThisPlatform
	}
	if !Privileged() {
		return errors.New("the helper must run with administrator rights: it exists to do what the agent cannot")
	}
	// The caller check accepts whatever runs this program's code, so a build other programs
	// could inject code into would accept them too.
	if err := refuseInjectableHelper(); err != nil {
		return err
	}
	// Before the socket is open, so it happens whether or not an agent ever connects.
	//
	// This is the pass that covers the machine nothing else can: one that was pointed at
	// app-tail's resolver and then lost the process without running any of its own code --
	// a kill, a panic, a power cut. launchd starts this helper at boot, before any login,
	// so the repair happens before anyone is looking at a machine that resolves nothing.
	//
	// It is the first pass of a watch that keeps going, because one pass at boot can miss:
	// the network may not be up yet, and a service the record lost is pointed at app-tail
	// with nothing saying so. Without the later passes such a machine resolved nothing until
	// somebody opened app-tail.
	gate := newSessionGate(sessionHandover)
	watch := newResolverWatch(gate, logf)
	watch.pass(ctx)
	// The rest of what a previous run may have left, for the same reason and on the same terms:
	// a routing table entry nothing is tracking and a root openvpn nothing is supervising are
	// the same kind of leftover as a resolver pointed at a process that is gone. It runs before
	// the socket is open, so no agent can be part way through asking for any of it.
	reclaimPreviousRun(ctx, newRootState(DefaultRootStatePath(), logf), logf)
	ln, err := ListenHelper(socketPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := ln.Close(); err != nil {
			logf("could not close the helper socket: %v", err)
		}
		if err := os.Remove(ln.Addr().String()); err != nil && !errors.Is(err, os.ErrNotExist) {
			logf("could not remove the helper socket %s: %v", ln.Addr(), err)
		}
	}()
	logf("app-tail helper listening on %s", ln.Addr())
	ticker := time.NewTicker(resolverWatchInterval)
	defer ticker.Stop()
	go watch.run(ctx, ticker.C)
	return serve(ctx, ln, gate, machineGrantPolicy(), logf)
}
