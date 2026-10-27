// SPDX-License-Identifier: MIT

//go:build unix

package hostnet

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/dns"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/router"

	"github.com/sellitus/app-tail/internal/sysdns"
)

// These exercise the real socket, the real framing and the real access check, with a real
// helper on the other end. Only the operations that change nothing are called: the rest
// need root, and a test that ran them would either be skipped everywhere or would install
// routes on the machine running it.

// startHelper runs a helper on a temporary socket and returns its path.
func startHelper(t *testing.T) string {
	t.Helper()
	path := shortSocketPath(t)
	ln, err := ListenHelper(path)
	if err != nil {
		t.Fatalf("listen on the helper socket: %v", err)
	}
	return servedBy(t, ln)
}

// startPlainHelper runs a helper on a socket opened without the ownership ListenHelper
// applies, and returns its path. It reaches the one state a correctly opened socket makes
// unreachable: a connection from an account the helper does not serve, which on a real
// machine the socket's owner stops before the helper ever sees it.
func startPlainHelper(t *testing.T) string {
	t.Helper()
	path := shortSocketPath(t)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("listen on a socket for the helper: %v", err)
	}
	return servedBy(t, ln)
}

// quickHandover is the window the tests that exercise a held session wait for it. The real
// one is a teardown's worth of seconds; here there is nothing to tear down, and waiting the
// real window would put those seconds into every run.
const quickHandover = 50 * time.Millisecond

// startBusyHelper runs a helper whose session is handed over quickly, for the tests that
// have to reach the answer a caller gets when it is not handed over at all.
func startBusyHelper(t *testing.T) string {
	t.Helper()
	path := shortSocketPath(t)
	ln, err := ListenHelper(path)
	if err != nil {
		t.Fatalf("listen on the helper socket: %v", err)
	}
	return servedByGate(t, ln, newSessionGate(quickHandover))
}

// servedBy runs a helper on an open listener until the test ends.
func servedBy(t *testing.T, ln *net.UnixListener) string {
	t.Helper()
	return served(t, ln, func(ctx context.Context) error {
		return serve(ctx, ln, newSessionGate(sessionHandover), machineGrantPolicy(), func(string, ...any) {})
	})
}

// servedByGate runs one with the session's handover window chosen by the test.
func servedByGate(t *testing.T, ln *net.UnixListener, gate *sessionGate) string {
	t.Helper()
	return served(t, ln, func(ctx context.Context) error {
		return serve(ctx, ln, gate, approvingEverything(t), func(string, ...any) {})
	})
}

func served(t *testing.T, ln *net.UnixListener, run func(context.Context) error) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := run(ctx); err != nil {
			t.Errorf("the helper stopped: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	return ln.Addr().String()
}

// shortSocketPath keeps the path inside the length a unix socket address allows, which is
// about a hundred bytes and which t.TempDir's name-derived path can exceed on its own.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "aths")
	if err != nil {
		t.Fatalf("make a directory for the socket: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "h.sock")
}

// ownedByThisUser records this test process as the account the helper serves, which is
// what the installer writes into the helper's launch configuration.
func ownedByThisUser(t *testing.T) {
	t.Helper()
	t.Setenv(ownerEnv, strconv.Itoa(os.Getuid()))
}

// The whole point of the split is that an unprivileged process can ask a privileged one
// what the machine can do. This is that path end to end: socket, access check, framing,
// operation, and the version handshake Dial does on the way in.
func TestAnUnprivilegedClientReachesTheHelperOverTheSocket(t *testing.T) {
	ownedByThisUser(t)
	path := startHelper(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("dial the helper: %v", err)
	}
	defer client.Close()

	caps, err := client.Capabilities(ctx)
	if err != nil {
		t.Fatalf("ask the helper what it can do: %v", err)
	}
	if caps.Version != Version {
		t.Errorf("the helper reported version %q, want this build's %q", caps.Version, Version)
	}
	if caps.Interface != DefaultInterfaceName() {
		t.Errorf("the helper named interface %q, want %q", caps.Interface, DefaultInterfaceName())
	}
}

// The socket's mode already stops another user connecting. The helper checks anyway,
// because it is the piece of this app holding root: a mode set wrongly by an installer,
// or a directory swapped between creation and bind, would otherwise hand root-level
// network control to whoever got there first.
func TestTheHelperRefusesAConnectionFromAnotherAccount(t *testing.T) {
	// Recorded as an account this process is not, which is what a connection from a
	// different user looks like from the helper's side.
	t.Setenv(ownerEnv, strconv.Itoa(os.Getuid()+1))
	path := startPlainHelper(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	closeIfOpen(t, client)
	if err == nil {
		t.Fatal("the helper accepted a connection from an account it does not serve")
	}
	if !strings.Contains(err.Error(), "takes commands from user") {
		t.Errorf("the refusal said %q, which does not name the mismatch", err)
	}
}

// closeIfOpen releases a session the test did not expect to get.
//
// It exists because the helper holds a connection open for its whole life and does not
// return from serving until every one of them is gone: a test that leaks an accepted
// connection leaves the helper blocked reading from it, and the test binary then hangs in
// cleanup rather than failing. That turns "the access check stopped working" -- which is the
// whole point of these tests -- into a timeout with no message.
func closeIfOpen(t *testing.T, client *Client) {
	t.Helper()
	if client == nil {
		return
	}
	if err := client.Close(); err != nil {
		t.Errorf("release the session: %v", err)
	}
}

// The helper refuses a connection by writing why and dropping it in one motion, so this
// side's first request routinely reaches a socket that is already gone. The reason has to
// survive that: "broken pipe" sends someone looking at the socket, when what is wrong is
// the account the helper was installed to serve. Arranged in the only order that makes it
// certain rather than likely -- the refusal is complete before anything is sent.
func TestAReasonWrittenBeforeTheCloseIsStillReported(t *testing.T) {
	path := shortSocketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on a socket for the stand-in helper: %v", err)
	}
	defer ln.Close()

	const reason = "this helper takes commands from user 501"
	refused := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			refused <- err
			return
		}
		err = writeMessage(conn, response{Error: reason})
		if cerr := conn.Close(); err == nil {
			err = cerr
		}
		refused <- err
	}()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("connect to the stand-in helper: %v", err)
	}
	defer conn.Close()
	if err := <-refused; err != nil {
		t.Fatalf("the stand-in helper could not refuse the connection: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := &Client{conn: conn, r: bufio.NewReader(conn)}
	if _, err := client.Capabilities(ctx); err == nil {
		t.Fatal("a refused connection answered as though it worked")
	} else if !strings.Contains(err.Error(), reason) {
		t.Errorf("the failure said %q, which is not the reason the helper gave", err)
	}
}

// A helper installed without an owner recorded has no expected answer to compare a
// connection against. Defaulting to "anyone" there would hand out root, so it refuses
// everything -- which has to be a refusal with a sentence, not a silently dead socket.
func TestAHelperWithNoRecordedOwnerRefusesEveryone(t *testing.T) {
	t.Setenv(ownerEnv, "")
	path := startHelper(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	closeIfOpen(t, client)
	if err == nil {
		t.Fatal("a helper with no recorded owner accepted a connection")
	}
	if !strings.Contains(err.Error(), ownerEnv) {
		t.Errorf("the refusal said %q, which does not name the setting that is missing", err)
	}
}

// A helper left behind by an older release speaks the same wire protocol only by
// coincidence, and it holds root while doing it. The handshake refuses it, and the refusal
// has to be one a caller can recognise: the sentence saying what to run is added where the
// platform is known, and it is chosen by this sentinel.
func TestDialRefusesAHelperFromAnotherBuild(t *testing.T) {
	path, _ := standInHelper(t, response{Capabilities: &Capabilities{
		Version:   Version + "-other",
		Interface: DefaultInterfaceName(),
	}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	closeIfOpen(t, client)
	if err == nil {
		t.Fatal("Dial accepted a helper from another build")
	}
	if !errors.Is(err, ErrHelperFromAnotherBuild) {
		t.Errorf("the refusal said %q, which no caller can recognise as a helper from another build", err)
	}
}

// standInHelper answers one request with the given reply, and reports what it was asked.
//
// It reaches the states a real helper cannot be put into from a test: one from another
// build, and one that would have to create a network interface to answer at all.
func standInHelper(t *testing.T, reply response) (string, <-chan request) {
	t.Helper()
	path := shortSocketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on a socket for the stand-in helper: %v", err)
	}
	asked := make(chan request, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(asked)
		conn, err := ln.Accept()
		if err != nil {
			// A listener closed with nobody connecting is the test having failed
			// before it got here, and that failure carries its own message.
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("the stand-in helper could not accept a connection: %v", err)
			}
			return
		}
		defer func() {
			if err := conn.Close(); err != nil {
				t.Errorf("close the stand-in helper's connection: %v", err)
			}
		}()
		var req request
		if err := readMessage(bufio.NewReader(conn), &req); err != nil {
			t.Errorf("the stand-in helper could not read the request: %v", err)
			return
		}
		asked <- req
		if err := writeMessage(conn, reply); err != nil {
			t.Errorf("the stand-in helper could not answer: %v", err)
		}
	}()
	t.Cleanup(func() {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close the stand-in helper's listener: %v", err)
		}
		wg.Wait()
	})
	return path, asked
}

// takeSession claims the helper's session on a connection the test keeps open, the way an
// agent does when it asks for an interface.
//
// Bringing one up is what claims it here: creating an interface needs root, and this is the
// operation whose refusal arrives after the session has already been claimed, which is the
// state these tests are about.
func takeSession(ctx context.Context, t *testing.T, path string) *Client {
	t.Helper()
	client, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("dial the helper: %v", err)
	}
	t.Cleanup(func() { closeIfOpen(t, client) })
	if err := client.RouterUp(ctx); err == nil {
		t.Fatal("the helper brought up an interface that was never created")
	} else if errors.Is(err, ErrHelperBusy) {
		t.Fatalf("the session was not free: %v", err)
	}
	return client
}

// The dead-man's switch is the reason a session is one connection rather than a series of
// calls: the helper undoes everything when the connection drops, for any reason including
// the agent being killed. The session becoming available again is the observable proof that
// the first one's teardown ran, because it is released only once that teardown is done.
func TestDroppingTheConnectionEndsTheSession(t *testing.T) {
	ownedByThisUser(t)
	path := startBusyHelper(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	first := takeSession(ctx, t, path)
	if err := first.Close(); err != nil {
		t.Fatalf("close the first session: %v", err)
	}

	second, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("dial the helper again: %v", err)
	}
	defer closeIfOpen(t, second)
	if err := second.RouterUp(ctx); errors.Is(err, ErrHelperBusy) {
		t.Error("the helper still holds the first session, so its teardown never ran")
	}
}

// A scan of the machine changes nothing, so it is answered whoever else is commanding the
// helper. Both callers that ask for one arrive exactly when a session is held: the doctor,
// run because something is wrong with a node that is up, and an agent finding out whether
// the interface mode is available before it gives up the node holding the session. Queued
// behind that session they would wait for a node that is not going anywhere.
func TestTheMachineCanBeScannedWhileAnotherConnectionHoldsTheSession(t *testing.T) {
	ownedByThisUser(t)
	path := startBusyHelper(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	takeSession(ctx, t, path)

	// Dial asks for the version, so a helper that queued this would not answer at all.
	client, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("dial a helper whose session is held: %v", err)
	}
	defer closeIfOpen(t, client)

	caps, err := client.Capabilities(ctx)
	if err != nil {
		t.Fatalf("ask a helper whose session is held what the machine can do: %v", err)
	}
	if caps.Interface != DefaultInterfaceName() {
		t.Errorf("the helper named interface %q, want %q", caps.Interface, DefaultInterfaceName())
	}
}

// Commanding the machine is what the single session keeps to one caller, and a second one
// is told so rather than left waiting: the two are indistinguishable from outside, and only
// one of them can be acted on.
func TestASecondCallerIsToldTheHelperIsBusyRatherThanLeftWaiting(t *testing.T) {
	ownedByThisUser(t)
	path := startBusyHelper(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	takeSession(ctx, t, path)

	client, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("dial a helper whose session is held: %v", err)
	}
	defer closeIfOpen(t, client)

	_, _, err = client.OpenTUN(ctx, "")
	if err == nil {
		t.Fatal("a helper whose session is held created an interface for a second caller")
	}
	if !errors.Is(err, ErrHelperBusy) {
		t.Errorf("the refusal said %q, which no caller can recognise as a helper that is already in use", err)
	}
}

// Putting the route to the tailnet back holds a session of its own, and that is the whole
// point of it being a fourth rather than part of the interface's: the agent holds the interface
// session for as long as its node runs, and a repair queued behind it would wait for a node that
// is not going anywhere. What comes back may well be a refusal -- the machine a test runs on has
// no tailnet to mend -- but it has to be the machine's refusal, not the helper's.
func TestTheRouteToTheTailnetCanBePutBackWhileAnotherConnectionHoldsTheSession(t *testing.T) {
	ownedByThisUser(t)
	path := startBusyHelper(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	takeSession(ctx, t, path)

	client, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("dial a helper whose session is held: %v", err)
	}
	defer closeIfOpen(t, client)

	if _, err := client.RepairTailnetRoutes(ctx, "utun5"); errors.Is(err, ErrHelperBusy) {
		t.Errorf("the repair was queued behind the interface session: %v", err)
	}
}

// The helper reads from an unprivileged peer, and since it serves connections alongside each
// other that peer decides how many this root process holds at once. Past the cap they are
// turned away with a sentence, not accepted and left to accumulate.
func TestTheHelperWillNotHoldMoreConnectionsThanItsCap(t *testing.T) {
	ownedByThisUser(t)
	path := startHelper(t)

	for range maxConnections {
		holdConnection(t, path)
	}

	conn := holdConnection(t, path)
	var resp response
	if err := readMessage(bufio.NewReader(conn), &resp); err != nil {
		t.Fatalf("read what the helper said to a connection over its cap: %v", err)
	}
	if resp.Error != tooManyConnections {
		t.Errorf("the helper said %q to a connection over its cap, want %q", resp.Error, tooManyConnections)
	}
}

// Switching modes rebuilds the node, and the replacement asks for the interface while the
// connection the old one held is still being torn down. Refusing there would drop a machine
// that is set up for the interface mode into the contained one every time a setting changed.
func TestASessionAskedForDuringAHandoverIsWaitedForRatherThanRefused(t *testing.T) {
	ownedByThisUser(t)
	// The real window, because what is under test is that the wait happens at all, and a
	// shortened one could pass by finishing before the waiting caller ever started.
	path := startHelper(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	holder := takeSession(ctx, t, path)

	waiting, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("dial a helper whose session is held: %v", err)
	}
	defer closeIfOpen(t, waiting)

	// Released while the second caller is inside the wait, which is the handover: the
	// operation is already on the wire and has nowhere to go until this happens.
	asked := make(chan error, 1)
	go func() { asked <- waiting.RouterUp(ctx) }()
	time.Sleep(quickHandover)
	if err := holder.Close(); err != nil {
		t.Fatalf("close the session being handed over: %v", err)
	}

	if err := <-asked; errors.Is(err, ErrHelperBusy) {
		t.Error("the helper refused a caller that was waiting out a handover")
	}
}

// openingHost is a privileged side that hands over an interface. Creating a real one needs
// root, so what stands in here is the operating system rather than any of this app's code:
// what is under test is what the helper does with the interface it was given.
type openingHost struct {
	Host
	// Embedded and never called: the resolver and OpenVPN halves of the boundary are
	// separate features with their own tests, and a session commands all of them.
	SystemResolver
	OpenVPNRunner
	TailnetRouteRepairer
	dev  tun.Device
	name string
	kept tun.Device
}

func (h *openingHost) OpenTUN(context.Context, string) (tun.Device, string, error) {
	return h.dev, h.name, nil
}

func (h *openingHost) Retain(dev tun.Device) { h.kept = dev }

// The reply and the descriptor travel together, and they are the whole of what the agent
// gets: everything it does afterwards is ordinary I/O on a descriptor it had no right to
// create. The helper keeps a reference of its own, because the interface goes away only when
// both are dropped and the teardown has to be able to take it back.
func TestTheInterfaceIsHandedOverWithTheNameTheKernelGaveIt(t *testing.T) {
	held, sent, err := os.Pipe()
	if err != nil {
		t.Fatalf("make a descriptor to hand over: %v", err)
	}
	defer held.Close()
	dev := &countingDevice{file: sent}
	host := &openingHost{dev: dev, name: "utun7"}
	server, client := unixPair(t)

	answered := make(chan error, 1)
	go func() {
		answered <- answer(context.Background(), server, host,
			request{Op: opOpenTUN, Name: "utun"}, newApprovals(approvingEverything(t)), func(string, ...any) {})
	}()

	resp, file, err := readWithFile(client, bufio.NewReader(client))
	if err != nil {
		t.Fatalf("read the reply the interface travels in: %v", err)
	}
	if err := <-answered; err != nil {
		t.Fatalf("hand the interface over: %v", err)
	}
	if resp.Interface != "utun7" {
		t.Errorf("the reply named interface %q, want the one the kernel made", resp.Interface)
	}
	if file == nil {
		t.Fatal("the reply arrived without the descriptor, so the agent has nothing to drive")
	}
	defer file.Close()

	// The same descriptor, open in both processes: what makes it the interface rather than
	// a number is that writing to this end comes out of the one the helper kept.
	if _, err := file.WriteString("through\n"); err != nil {
		t.Fatalf("write to the descriptor that was handed over: %v", err)
	}
	line, err := bufio.NewReader(held).ReadString('\n')
	if err != nil || line != "through\n" {
		t.Errorf("the descriptor carried %q (%v), so it is not the one that was sent", line, err)
	}
	if host.kept != dev {
		t.Error("the helper let go of the interface, so its teardown has nothing to take back")
	}
	if dev.closes != 0 {
		t.Errorf("the interface was closed %d times after being handed over", dev.closes)
	}
}

// A platform whose interface has no descriptor cannot be served this way at all, and the
// interface it did create has to go: the caller was given nothing to close it with, and one
// left behind holds a network interface on the machine with nothing driving it.
func TestAnInterfaceWithNoDescriptorIsRefusedAndClosed(t *testing.T) {
	dev := &countingDevice{}
	server, client := unixPair(t)

	handed := make(chan error, 1)
	go func() {
		ok, err := handOver(server, "utun7", dev, func(string, ...any) {})
		if err == nil && ok {
			err = errors.New("an interface with no descriptor was reported as handed over")
		}
		handed <- err
	}()

	var resp response
	if err := readMessage(bufio.NewReader(client), &resp); err != nil {
		t.Fatalf("read the refusal: %v", err)
	}
	if err := <-handed; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.Error, "no descriptor") {
		t.Errorf("the refusal said %q, which does not say what could not be handed over", resp.Error)
	}
	if dev.closes != 1 {
		t.Errorf("the interface that could not be handed over was closed %d times, want once", dev.closes)
	}
}

// The descriptor arrives already open, and whatever wraps it owns it from that moment: the
// caller has no second reference to close, so a wrapper that failed and left it open would
// leak an interface, and one that both closed it and reported a failure the caller closed
// again would close a descriptor this process has since reused.
func TestWrappingADescriptorTakesOwnershipOfIt(t *testing.T) {
	received, other, err := os.Pipe()
	if err != nil {
		t.Fatalf("make a descriptor: %v", err)
	}
	defer other.Close()

	// A pipe is not an interface, which is the failing half of that contract and the only
	// half reachable without the rights to create a real one.
	dev, err := deviceFromFile(received)
	if err == nil {
		dev.Close()
		t.Fatal("a pipe was wrapped as a network interface")
	}
	if err := received.Close(); err == nil {
		t.Error("the descriptor was left open, so nothing owns it and nothing will close it")
	}
}

// unixPair returns the two ends of a unix connection. It is a real one because the descriptor
// travels as out-of-band data on it, which no other kind of connection carries.
func unixPair(t *testing.T) (server, client *net.UnixConn) {
	t.Helper()
	addr := &net.UnixAddr{Name: shortSocketPath(t), Net: "unix"}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatalf("listen for the other end: %v", err)
	}
	defer ln.Close()

	accepted := make(chan *net.UnixConn, 1)
	go func() {
		conn, err := ln.AcceptUnix()
		if err != nil {
			t.Errorf("accept the other end: %v", err)
		}
		accepted <- conn
	}()
	client, err = net.DialUnix("unix", nil, addr)
	if err != nil {
		t.Fatalf("connect the two ends: %v", err)
	}
	server = <-accepted
	if server == nil {
		t.Fatal("the other end was never accepted")
	}
	t.Cleanup(func() {
		server.Close()
		client.Close()
	})
	return server, client
}

// holdConnection opens a connection and keeps it open until the test ends, which is what
// makes it count against the helper's cap.
func holdConnection(t *testing.T, path string) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("connect to the helper: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close a connection to the helper: %v", err)
		}
	})
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}
	return conn
}

// Every call after Close has to fail as a closed connection rather than as a write to a
// dead socket, because a caller that gets a generic I/O error will retry.
func TestACallAfterCloseSaysTheConnectionIsClosed(t *testing.T) {
	ownedByThisUser(t)
	path := startHelper(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("dial the helper: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}

	_, err = client.Capabilities(ctx)
	if err == nil {
		t.Fatal("a call on a closed connection was accepted")
	}
	if !strings.Contains(err.Error(), "closed") {
		t.Errorf("the failure said %q, which does not say the connection is gone", err)
	}
}

// An operation this helper does not have is answered rather than ignored, and the session
// survives it. The two sides disagreeing about the protocol is what the version check is
// for; saying so here is how a disagreement that slipped past it gets diagnosed instead of
// looking like a hang.
func TestAnUnknownOperationIsAnsweredAndTheSessionSurvives(t *testing.T) {
	ownedByThisUser(t)
	path := startHelper(t)

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("connect to the helper: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}

	client := &Client{conn: conn, r: bufio.NewReader(conn)}
	ctx := context.Background()
	_, _, err = client.call(ctx, request{Op: "delete-everything"}, false)
	if err == nil {
		t.Fatal("the helper accepted an operation it does not have")
	}
	if !strings.Contains(err.Error(), "delete-everything") {
		t.Errorf("the refusal said %q, which does not name what was asked for", err)
	}

	// The session going on is the point: a protocol disagreement is not a reason to drop
	// a connection whose loss tears down the machine's configuration.
	caps, err := client.Capabilities(ctx)
	if err != nil {
		t.Fatalf("the session did not survive an unknown operation: %v", err)
	}
	if caps.Version != Version {
		t.Errorf("the helper reported version %q after the refusal, want %q", caps.Version, Version)
	}
}

// The helper reads from an unprivileged peer, so a frame length is a memory budget that
// peer controls. A message over the cap is refused rather than buffered.
func TestAnOversizedMessageIsRefusedRatherThanBuffered(t *testing.T) {
	ownedByThisUser(t)
	path := startHelper(t)

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("connect to the helper: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}

	err = writeMessage(conn, request{Op: opOpenTUN, Name: strings.Repeat("u", maxMessage+1)})
	if err == nil {
		t.Fatal("a message over the size limit was sent")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("the refusal said %q, which does not say a limit was passed", err)
	}
}

// The reader on the other side has the same cap, and reaches it by a different path: a
// peer that never sends a newline would otherwise grow the buffer without bound.
func TestAnOversizedFrameIsRefusedOnTheWayIn(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(strings.Repeat("x", maxMessage+2)))
	_, err := readLine(r)
	if err == nil {
		t.Fatal("a frame over the size limit was read")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("the refusal said %q, which does not say a limit was passed", err)
	}
}

// A frame that is the right size and not a message at all is what a helper from another
// build, or one that wrote a diagnostic to the wrong stream, puts on the wire. It has to
// come back as a failure naming the step: decoded into a zero value it would read as a
// helper that answered with nothing enabled and nothing wrong.
func TestAFrameThatIsNotAMessageIsAFailureRatherThanAZeroValue(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("helper: cannot open /dev/net/tun\n"))
	var resp response
	err := readMessage(r, &resp)
	if err == nil {
		t.Fatal("a line that is not a message was accepted")
	}
	if !strings.Contains(err.Error(), "read the message") {
		t.Errorf("the failure said %q, which does not name the step that could not be completed", err)
	}
}

// The helper is a separately installed binary, so an empty name is a request for whichever
// default that binary was built with. One from an earlier build answers with a name this
// platform will not create, and the interface fails after the contained node is already
// down. The name is this app's choice, so it has to travel as one.
func TestTheClientNamesTheInterfaceRatherThanLeavingItToTheHelper(t *testing.T) {
	// Refused rather than served: creating an interface needs root, and the name under
	// test has already crossed the socket by the time the refusal is written.
	path, asked := standInHelper(t, response{Error: "this stand-in creates nothing"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := openTUNThrough(t, ctx, path, ""); err == nil {
		t.Fatal("the stand-in helper reported an interface it did not create")
	}
	if got := (<-asked).Name; got != DefaultInterfaceName() {
		t.Errorf("the helper was asked to create interface %q, want %q", got, DefaultInterfaceName())
	}
}

// A name that was configured is the whole of what configuring it does, so it travels as it
// stands. Substituting the default over it would leave the setting doing nothing.
func TestANamedInterfaceIsAskedForByThatName(t *testing.T) {
	path, asked := standInHelper(t, response{Error: "this stand-in creates nothing"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := openTUNThrough(t, ctx, path, "utun9"); err == nil {
		t.Fatal("the stand-in helper reported an interface it did not create")
	}
	if got := (<-asked).Name; got != "utun9" {
		t.Errorf("the helper was asked to create interface %q, want the one that was configured", got)
	}
}

// openTUNThrough asks for an interface over a connection to the given socket, skipping the
// version handshake Dial performs: what is under test is the request that goes out, and a
// stand-in that had to pass the handshake first could answer only one of the two.
func openTUNThrough(t *testing.T, ctx context.Context, path, name string) (tun.Device, string, error) {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("connect to the stand-in helper: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close the connection to the stand-in helper: %v", err)
		}
	})
	client := &Client{conn: conn, r: bufio.NewReader(conn)}
	return client.OpenTUN(ctx, name)
}

// resolverSessionHost is a privileged side that writes down what it was asked to do instead of
// doing it. What it stands in for is the machine itself: the case under test is what a
// dropped connection does to this machine's resolver, which the real one can only show on a
// machine with root, an interface, and a DNS setting the suite is willing to change.
type resolverSessionHost struct {
	Host
	// Embedded and never called: this case is about the resolver, and a session commands
	// every half of the boundary.
	OpenVPNRunner
	TailnetRouteRepairer
	mu       sync.Mutex
	applied  bool
	restored bool
	closed   bool
}

func (h *resolverSessionHost) Capabilities(ctx context.Context) (Capabilities, error) {
	return capabilities(ctx, BuildID, "")
}

func (h *resolverSessionHost) RouterUp(context.Context) error {
	return errors.New("no interface is open, so there is nothing to bring up")
}

func (h *resolverSessionHost) SetSystemDNS(_ context.Context, resolvers []netip.Addr) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(resolvers) == 0 {
		h.applied, h.restored = false, true
		return nil
	}
	h.applied = true
	return nil
}

func (h *resolverSessionHost) OpenResolverPacket(context.Context, netip.AddrPort) (net.PacketConn, error) {
	return nil, errors.New("this stand-in binds no sockets")
}

func (h *resolverSessionHost) OpenResolverStream(context.Context, netip.AddrPort) (net.Listener, error) {
	return nil, errors.New("this stand-in binds no sockets")
}

func (h *resolverSessionHost) BaseSystemDNS(context.Context) (sysdns.Base, error) {
	return sysdns.Base{}, nil
}

func (h *resolverSessionHost) Retain(tun.Device) {}

func (h *resolverSessionHost) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	if h.applied {
		h.applied, h.restored = false, true
	}
	return nil
}

func (h *resolverSessionHost) state() (applied, restored, closed bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.applied, h.restored, h.closed
}

// The two sessions are separate so that the machine's resolver survives everything the node
// does. This is the other half of that: losing the connection that holds the resolver puts
// this machine's DNS back and leaves the interface exactly where it was.
func TestDroppingTheResolverConnectionRestoresDNSAndLeavesTheInterfaceAlone(t *testing.T) {
	ownedByThisUser(t)

	var mu sync.Mutex
	var hosts []*resolverSessionHost
	path := shortSocketPath(t)
	ln, err := ListenHelper(path)
	if err != nil {
		t.Fatalf("listen on the helper socket: %v", err)
	}
	served(t, ln, func(ctx context.Context) error {
		return serveWith(ctx, ln, newSessionGate(quickHandover), func(openvpnAddressCheck) commanded {
			host := &resolverSessionHost{}
			mu.Lock()
			defer mu.Unlock()
			hosts = append(hosts, host)
			return host
		}, approvingEverything(t), func(string, ...any) {})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resolver, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("dial the helper for the resolver session: %v", err)
	}
	if err := resolver.SetSystemDNS(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.153")}); err != nil {
		t.Fatalf("point this machine's resolver at app-tail: %v", err)
	}

	iface, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("dial the helper for the interface session: %v", err)
	}
	defer closeIfOpen(t, iface)
	// Takes the interface session: the operation fails because no interface is open, and
	// the session is claimed before the operation runs.
	if err := iface.RouterUp(ctx); errors.Is(err, ErrHelperBusy) {
		t.Fatalf("the interface session was refused while only the resolver's was held: %v", err)
	}

	mu.Lock()
	if len(hosts) != 2 {
		mu.Unlock()
		t.Fatalf("the helper served %d connections, want one per client", len(hosts))
	}
	resolverHost, ifaceHost := hosts[0], hosts[1]
	mu.Unlock()
	if applied, _, _ := resolverHost.state(); !applied {
		t.Fatal("the resolver session never pointed this machine anywhere, so the teardown has nothing to undo")
	}

	if err := resolver.Close(); err != nil {
		t.Fatalf("drop the resolver connection: %v", err)
	}
	awaitTeardown(t, resolverHost)

	if _, restored, _ := resolverHost.state(); !restored {
		t.Error("dropping the resolver connection left this machine pointed at an app-tail that is gone")
	}
	if _, _, closed := ifaceHost.state(); closed {
		t.Error("dropping the resolver connection tore down the interface session as well")
	}

	// The resolver session is free again and the interface session is not, which is the
	// whole reason there are two.
	next, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("dial the helper after the resolver session was released: %v", err)
	}
	defer closeIfOpen(t, next)
	if err := next.SetSystemDNS(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.153")}); err != nil {
		t.Errorf("the resolver session was not released when its connection dropped: %v", err)
	}
	if err := next.RouterUp(ctx); !errors.Is(err, ErrHelperBusy) {
		t.Errorf("the interface session was handed out while another connection holds it: %v", err)
	}
}

// awaitTeardown waits for a session's teardown to run. It is a poll because the teardown
// happens in the helper's own goroutine, after the kernel reports the connection gone.
func awaitTeardown(t *testing.T, host *resolverSessionHost) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, closed := host.state(); closed {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the session's teardown never ran after its connection dropped")
}

// The fabric's one privileged call has to cross the socket like every other, and it has to
// claim the interface the way the tailnet's own configuration does. Without the claim, the
// fabric and the interface mode would both be configuring one machine's routing table.
func TestInstallingThisAppsOwnRoutesClaimsTheInterface(t *testing.T) {
	ownedByThisUser(t)
	path := startBusyHelper(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("dial the helper: %v", err)
	}
	defer closeIfOpen(t, client)

	routes := Routes{
		LocalAddrs: []netip.Prefix{netip.MustParsePrefix("198.18.0.0/32")},
		Routes:     []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		MTU:        1380,
	}
	// Refused because no interface exists to route to, which is the privileged side's own
	// sentence and therefore proof the request reached it rather than being answered here.
	err = client.SetHostRoutes(ctx, routes)
	if err == nil {
		t.Fatal("the helper routed ranges to an interface that was never created")
	}
	if errors.Is(err, ErrHelperBusy) {
		t.Fatalf("the session was not free: %v", err)
	}
	if !strings.Contains(err.Error(), "no interface is open") {
		t.Errorf("the refusal said %q, want the privileged side's own reason", err)
	}

	second, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("dial the helper again: %v", err)
	}
	defer closeIfOpen(t, second)
	if err := second.RouterUp(ctx); !errors.Is(err, ErrHelperBusy) {
		t.Errorf("a second caller was handed the interface after this app's routes claimed it: %v", err)
	}
}

// The ranges are what the call is, so they have to arrive as they were given. A slice
// silently dropped in the framing would install a routing table missing exactly the network
// the caller was adding, and the call would report success.
func TestThisAppsRoutesTravelAsTheyWereGiven(t *testing.T) {
	path, asked := standInHelper(t, response{Error: "this stand-in routes nothing"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	want := Routes{
		LocalAddrs:  []netip.Prefix{netip.MustParsePrefix("198.18.0.0/32")},
		Routes:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.7.0/24")},
		LocalRoutes: []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")},
		MTU:         1380,
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("connect to the stand-in helper: %v", err)
	}
	defer conn.Close()
	client := &Client{conn: conn, r: bufio.NewReader(conn)}
	if err := client.SetHostRoutes(ctx, want); err == nil {
		t.Fatal("the stand-in helper reported routes it never installed")
	}

	req := <-asked
	if req.Op != opSetHostRoutes {
		t.Fatalf("the helper was asked for %q, want %q", req.Op, opSetHostRoutes)
	}
	if req.Host == nil {
		t.Fatal("the request carried no addressing at all")
	}
	got := *req.Host
	if !slices.Equal(got.LocalAddrs, want.LocalAddrs) {
		t.Errorf("the interface's own addresses arrived as %v, want %v", got.LocalAddrs, want.LocalAddrs)
	}
	if !slices.Equal(got.Routes, want.Routes) {
		t.Errorf("the ranges arrived as %v, want %v", got.Routes, want.Routes)
	}
	if !slices.Equal(got.LocalRoutes, want.LocalRoutes) {
		t.Errorf("the ranges kept off the interface arrived as %v, want %v", got.LocalRoutes, want.LocalRoutes)
	}
	if got.MTU != want.MTU {
		t.Errorf("the packet size arrived as %d, want %d", got.MTU, want.MTU)
	}
}

// The connection and the interface are what the request is, so both have to arrive as they
// were given. A connection identifier dropped in the framing would have the privileged side
// route an interface against whichever connection it read instead.
func TestARouteRequestTravelsAsItWasGiven(t *testing.T) {
	path, asked := standInHelper(t, response{Error: "this stand-in routes nothing"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("connect to the stand-in helper: %v", err)
	}
	defer conn.Close()
	client := &Client{conn: conn, r: bufio.NewReader(conn)}

	want := OpenVPNScope{ID: "tn_ovpn01", Interface: "utun9"}
	if err := client.ScopeOpenVPN(ctx, want); err == nil {
		t.Fatal("the stand-in helper reported a route it never installed")
	}

	req := <-asked
	if req.Op != opScopeOpenVPN {
		t.Fatalf("the helper was asked for %q, want %q", req.Op, opScopeOpenVPN)
	}
	if req.Scope == nil {
		t.Fatal("the request carried no connection and no interface at all")
	}
	if *req.Scope != want {
		t.Errorf("the request arrived as %+v, want %+v", *req.Scope, want)
	}
}

// Taking the route back names only the connection, and that name has to arrive as it was given
// for the same reason installing it does: the privileged side would otherwise take the route
// off whichever connection it read instead, leaving this machine's traffic pointed at an
// interface with no route and another connection's route removed under it.
func TestTakingARouteBackTravelsAsItWasGiven(t *testing.T) {
	path, asked := standInHelper(t, response{Error: "this stand-in routes nothing"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("connect to the stand-in helper: %v", err)
	}
	defer conn.Close()
	client := &Client{conn: conn, r: bufio.NewReader(conn)}

	if err := client.UnscopeOpenVPN(ctx, "tn_ovpn01"); err == nil {
		t.Fatal("the stand-in helper reported taking back a route it never had")
	}

	req := <-asked
	if req.Op != opUnscopeOpenVPN {
		t.Fatalf("the helper was asked for %q, want %q", req.Op, opUnscopeOpenVPN)
	}
	if req.ID != "tn_ovpn01" {
		t.Errorf("the request named %q, want the connection it was given", req.ID)
	}
	if err := client.UnscopeOpenVPN(ctx, "not an id"); err == nil {
		t.Error("a request naming something that is not a connection identifier was sent")
	}
}

// The client checks before it sends, but the caller is the unprivileged side and the check it
// runs is one it can skip. What decides is the check on the side holding the rights, so a
// request naming something that is not an interface still has to be refused by the second.
func TestARouteOnSomethingThatIsNotAnInterfaceIsRefusedByThePrivilegedSide(t *testing.T) {
	ownedByThisUser(t)
	path := startHelper(t)

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("connect to the helper: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}

	client := &Client{conn: conn, r: bufio.NewReader(conn)}
	ctx := context.Background()
	// Straight onto the wire, skipping Client.ScopeOpenVPN and the check it runs.
	scope := OpenVPNScope{ID: "tn_ovpn01", Interface: "utun9 -ifscope en0"}
	_, _, err = client.call(ctx, request{Op: opScopeOpenVPN, Scope: &scope}, false)
	if err == nil {
		t.Fatal("the helper put a route on a name that would have been two arguments")
	}
	if !strings.Contains(err.Error(), "interface") {
		t.Errorf("the refusal said %q, want the reason the name is not an interface", err)
	}

	// The session survives it, for the reason every refused request does: a caller's mistake is
	// not a reason to drop a connection whose loss tears down the machine's configuration.
	if _, err := client.Capabilities(ctx); err != nil {
		t.Errorf("the session ended over a refused request: %v", err)
	}
}

// The client checks before it sends, but the caller is the unprivileged side and the check
// it runs is one it can skip. What decides is the check on the side holding the rights, so
// a request that never passed the first one still has to be refused by the second.
func TestAddressingTheMachineCannotGiveAwayIsRefusedByThePrivilegedSide(t *testing.T) {
	ownedByThisUser(t)
	path := startHelper(t)

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("connect to the helper: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}

	client := &Client{conn: conn, r: bufio.NewReader(conn)}
	ctx := context.Background()
	// Straight onto the wire, skipping Client.SetHostRoutes and the check it runs.
	loopback := Routes{Routes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	_, _, err = client.call(ctx, request{Op: opSetHostRoutes, Host: &loopback}, false)
	if err == nil {
		t.Fatal("the helper sent this machine's loopback range to an interface")
	}
	if !strings.Contains(err.Error(), "reaches itself") {
		t.Errorf("the refusal said %q, want the reason loopback cannot be routed away", err)
	}

	// The session survives it: a refused request is a caller's mistake, not a reason to drop
	// a connection whose loss tears down the machine's configuration.
	caps, err := client.Capabilities(ctx)
	if err != nil {
		t.Fatalf("the session did not survive a refused request: %v", err)
	}
	if caps.Version != Version {
		t.Errorf("the helper reported version %q after the refusal, want %q", caps.Version, Version)
	}
}

// The engine's configuration reaches the privileged side as JSON from an unprivileged
// process, and nothing on the way in re-reads it: the client sends what it was handed. So the
// check that matters is this one, on the side holding the rights, and these go straight onto
// the wire to prove it is there rather than in the caller.
func TestTheEngineConfigurationIsCheckedOnThePrivilegedSide(t *testing.T) {
	refused := []struct {
		name string
		cfg  router.Config
		says string
	}{
		{
			name: "this machine's loopback range sent to an interface",
			cfg:  router.Config{Routes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}},
			says: "reaches itself",
		},
		{
			name: "a firewall the caller named, which reaches a root command lookup",
			cfg:  router.Config{NetfilterKind: "nft; curl example.com"},
			says: "not a firewall this app knows how to drive",
		},
		{
			name: "a packet size no link carries",
			cfg:  router.Config{NewMTU: maxMTU + 1},
			says: "outside the",
		},
	}

	ownedByThisUser(t)
	path := startHelper(t)
	client, done := rawSession(t, path)
	defer done()
	ctx := context.Background()

	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := client.call(ctx, request{Op: opSetRoutes, Router: &tt.cfg}, false)
			if err == nil {
				t.Fatal("the helper installed a configuration an unprivileged caller chose")
			}
			if !strings.Contains(err.Error(), tt.says) {
				t.Errorf("the refusal said %q, want the reason %q", err, tt.says)
			}
		})
	}

	// A refused request is a caller's mistake, not a reason to drop a connection whose loss
	// tears down the machine's configuration.
	if _, err := client.Capabilities(ctx); err != nil {
		t.Fatalf("the session did not survive a refused request: %v", err)
	}
}

// A domain crossing this boundary is not a string the privileged side prints: on macOS it is
// a line inside a root-owned file under /etc/resolver and the name of the file itself. The
// type it arrives as validates nothing, so a caller that gets to put a newline in one gets to
// write its own nameserver directive into that file.
func TestAResolverDomainThatWouldWriteItsOwnLineIsRefusedByThePrivilegedSide(t *testing.T) {
	refused := []struct {
		name string
		cfg  dns.OSConfig
		says string
	}{
		{
			name: "a search domain carrying a nameserver directive on its own line",
			cfg:  dns.OSConfig{SearchDomains: []dnsname.FQDN{"a\nnameserver 6.6.6.6."}},
			says: "as its own line",
		},
		{
			name: "a match domain carrying a slash, which is the file it is written to",
			cfg:  dns.OSConfig{MatchDomains: []dnsname.FQDN{"etc/resolver/evil.example.com."}},
			says: "decides which file",
		},
		{
			name: "a resolver address that names no resolver",
			cfg:  dns.OSConfig{Nameservers: []netip.Addr{netip.MustParseAddr("0.0.0.0")}},
			says: "names no resolver",
		},
	}

	ownedByThisUser(t)
	path := startHelper(t)
	client, done := rawSession(t, path)
	defer done()
	ctx := context.Background()

	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := client.call(ctx, request{Op: opSetDNS, DNS: &tt.cfg}, false)
			if err == nil {
				t.Fatal("the helper wrote a caller's own lines into this machine's resolver configuration")
			}
			if !strings.Contains(err.Error(), tt.says) {
				t.Errorf("the refusal said %q, want the reason %q", err, tt.says)
			}
		})
	}

	if _, err := client.Capabilities(ctx); err != nil {
		t.Fatalf("the session did not survive a refused request: %v", err)
	}
}

// rawSession is a client that skips the checks Client's own methods run, so what a test
// reaches is the privileged side's copy of them and nothing else.
func rawSession(t *testing.T, path string) (client *Client, done func()) {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("connect to the helper: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		conn.Close()
		t.Fatalf("set a deadline: %v", err)
	}
	return &Client{conn: conn, r: bufio.NewReader(conn)}, func() { conn.Close() }
}

// The teardown is the dead-man's switch: on the way out of a session it puts this machine's
// routes, resolver files and DNS override back. A connection that was turned away opened
// none of that, so running the pass for it would be a process holding root doing work on
// behalf of a caller it just refused -- once per attempt, for as long as the attempts keep
// coming.
func TestAConnectionTheHelperRefusesUndoesNothing(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is allowed through the access check, so there is no refusal to observe")
	}
	// The helper is recorded as serving somebody else, which is what makes this connection
	// the one it turns away.
	t.Setenv(ownerEnv, strconv.Itoa(os.Getuid()+1))

	host := &resolverSessionHost{}
	server, client := unixPair(t)
	served := make(chan struct{})
	go func() {
		defer close(served)
		serveConnection(context.Background(), server, newSessionGate(quickHandover), host, newApprovals(approvingEverything(t)), func(string, ...any) {})
	}()

	var resp response
	if err := readMessage(bufio.NewReader(client), &resp); err != nil {
		t.Fatalf("read the refusal: %v", err)
	}
	if !strings.Contains(resp.Error, "takes commands from user") {
		t.Errorf("the refusal said %q, which does not say the connection came from the wrong account", resp.Error)
	}
	<-served

	if _, _, closed := host.state(); closed {
		t.Error("the helper ran a teardown pass for a connection it refused, so a refused caller reaches this machine's configuration")
	}
}

// Stopping one connection names only that connection, and the name has to arrive as given:
// the privileged side would otherwise stop whichever connection it read instead. A name that
// is not a connection identifier is refused on this side and never crosses to the root
// process at all, which is the cheap check standing in front of the one that matters.
func TestStoppingOneConnectionTravelsAsItWasGivenAndNonsenseNeverCrosses(t *testing.T) {
	path, asked := standInHelper(t, response{Error: "this stand-in runs nothing"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("connect to the stand-in helper: %v", err)
	}
	defer conn.Close()
	client := &Client{conn: conn, r: bufio.NewReader(conn)}

	if err := client.StopOpenVPN(ctx, "tn_ovpn01"); err == nil {
		t.Fatal("the stand-in helper reported stopping a connection it never ran")
	}
	req := <-asked
	if req.Op != opStopOpenVPN || req.ID != "tn_ovpn01" {
		t.Errorf("the helper was asked for %q on %q, want %q on the connection it was given", req.Op, req.ID, opStopOpenVPN)
	}

	// The stand-in has hung up by now, so a request that crossed would come back as a write
	// to a closed socket, and the refusal has to be this side's own words instead.
	err = client.StopOpenVPN(ctx, "../etc/passwd")
	if err == nil || !strings.Contains(err.Error(), "not a connection identifier") {
		t.Fatalf("StopOpenVPN(nonsense) = %v, want it refused on this side as not an identifier", err)
	}
	if req, crossed := <-asked; crossed {
		t.Errorf("a request naming %q reached the privileged side", req.ID)
	}
}
