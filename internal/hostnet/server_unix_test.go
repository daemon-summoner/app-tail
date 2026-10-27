// SPDX-License-Identifier: MIT

//go:build unix

package hostnet

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
)

// unixConnPair is both ends of one unix socket connection, so a close on the helper's end
// can be observed from the agent's.
func unixConnPair(t *testing.T) (helperEnd, agentEnd *net.UnixConn) {
	t.Helper()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: shortSocketPath(t), Net: "unix"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan *net.UnixConn, 1)
	go func() {
		conn, err := ln.AcceptUnix()
		if err != nil {
			t.Errorf("accept: %v", err)
		}
		accepted <- conn
	}()
	agentEnd, err = net.DialUnix("unix", nil, ln.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	helperEnd = <-accepted
	if helperEnd == nil {
		t.FailNow()
	}
	t.Cleanup(func() { helperEnd.Close(); agentEnd.Close() })
	return helperEnd, agentEnd
}

// closedFromTheOtherEnd is whether a read on conn reports the far end gone within a second.
func closedFromTheOtherEnd(conn net.Conn) bool {
	conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := conn.Read(make([]byte, 1))
	return err != nil && !errors.Is(err, net.ErrClosed) && !isTimeout(err)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// A connection accepted in the same moment the helper was told to stop belongs to a helper
// that is going away, and it is closed on arrival rather than served: served, it would hold
// the stop until the agent on it hung up, which is the wait the stop exists to end.
func TestAConnectionAcceptedAfterTheStopIsClosedOnArrival(t *testing.T) {
	live := &liveConnections{logf: func(string, ...any) {}}
	before, beforeAgent := unixConnPair(t)
	live.add(before)

	live.closeAll()

	if !closedFromTheOtherEnd(beforeAgent) {
		t.Error("the connection open at the stop was not closed by it")
	}
	after, afterAgent := unixConnPair(t)
	live.add(after)
	if !closedFromTheOtherEnd(afterAgent) {
		t.Error("a connection accepted after the stop was kept open, so the stop now waits on it")
	}
	live.mu.Lock()
	held := len(live.conns)
	live.mu.Unlock()
	if held != 0 {
		t.Errorf("%d connections are still tracked after the stop", held)
	}
}

// The session owning a connection closes it on its own way out, so the stop's close of the
// same connection loses that race routinely. That loss is the design working and is not
// reported; any other close failure is, since a helper that cannot let go of a socket is a
// socket the next helper cannot have.
func TestTheStopDoesNotReportLosingTheCloseRaceToTheSession(t *testing.T) {
	var logged []string
	live := &liveConnections{logf: func(format string, args ...any) {
		logged = append(logged, strings.TrimSpace(format))
	}}
	conn, _ := unixConnPair(t)
	live.add(conn)
	if err := conn.Close(); err != nil {
		t.Fatalf("the session's own close: %v", err)
	}

	live.closeAll()

	if len(logged) != 0 {
		t.Errorf("the stop reported %v for a connection the session had already closed", logged)
	}
}

// A helper told to stop has to stop, connected agent or not. Its read has no deadline, so
// closing only the listener leaves it waiting on the agent forever: launchd waits out its own
// twenty seconds and then SIGKILLs, which runs no defers -- and the teardown that SIGKILL
// skips is the one this whole file exists for, the one that puts this machine's resolver back.
// An upgrade, a `tun uninstall-helper` or a shutdown then leaves a static override behind with
// the helper that would have undone it now gone.
func TestTheHelperStopsWhileAnAgentIsStillConnected(t *testing.T) {
	ownedByThisUser(t)

	path := shortSocketPath(t)
	ln, err := ListenHelper(path)
	if err != nil {
		t.Fatalf("listen on the helper socket: %v", err)
	}

	host := &resolverSessionHost{}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() {
		stopped <- serveWith(ctx, ln, newSessionGate(quickHandover), func(openvpnAddressCheck) commanded { return host }, approvingEverything(t), func(string, ...any) {})
	}()

	agent, err := Dial(t.Context(), Options{SocketPath: path, Logf: func(string, ...any) {}})
	if err != nil {
		cancel()
		t.Fatalf("dial the helper: %v", err)
	}
	defer closeIfOpen(t, agent)
	if err := agent.SetSystemDNS(t.Context(), []netip.Addr{netip.MustParseAddr("127.0.0.153")}); err != nil {
		cancel()
		t.Fatalf("point this machine's resolver at app-tail: %v", err)
	}

	cancel()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("the helper stopped with %v, want a clean stop", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the helper is still waiting on a connected agent, so its service manager is what ends it -- and a killed helper undoes nothing")
	}

	if _, restored, _ := host.state(); !restored {
		t.Error("this machine's resolver was never put back, so the override outlives the helper that wrote it")
	}
}

// namingHost records the names OpenTUN was asked for, so a test can tell a request that was
// refused at the socket from one that reached the code that creates interfaces as root.
type namingHost struct {
	openingHost
	asked []string
}

func (h *namingHost) OpenTUN(_ context.Context, name string) (tun.Device, string, error) {
	h.asked = append(h.asked, name)
	return nil, "", errors.New("no interface is created in this test")
}

// The interface name in an open-tun request is the one value in it the agent chooses, and it
// goes to the root side's interface creation and from there into the system's own tools.
// Only a name an interface can actually have is passed on; anything else -- a path, a word
// with a shell's punctuation in it, an option, a name past the kernel's length -- is refused
// with a reply before anything is created. On macOS the kernel names tunnels itself, so the
// only names a request may carry there are utun, utun with a number, or none.
func TestOpenTUNRefusesANameThatIsNotAnInterfaceName(t *testing.T) {
	refused := []string{
		"../../etc/hosts",
		"utun0; rm -rf /",
		"utun 1",
		"-utun",
		"utun\n0",
		strings.Repeat("u", maxInterfaceName+1),
	}
	if runtime.GOOS == "darwin" {
		refused = append(refused, "app-tail0", "en0", "utunx")
	}
	for _, name := range refused {
		t.Run(name, func(t *testing.T) {
			host := &namingHost{}
			server, client := unixPair(t)
			answered := make(chan error, 1)
			go func() {
				answered <- answer(context.Background(), server, host,
					request{Op: opOpenTUN, Name: name}, newApprovals(approvingEverything(t)), func(string, ...any) {})
			}()
			var resp response
			if err := readMessage(bufio.NewReader(client), &resp); err != nil {
				t.Fatalf("read the reply: %v", err)
			}
			if err := <-answered; err != nil {
				t.Fatalf("answer the request: %v", err)
			}
			if resp.Error == "" {
				t.Errorf("the request for %q was answered without an error", name)
			}
			if len(host.asked) != 0 {
				t.Errorf("the request for %q reached interface creation: %q", name, host.asked)
			}
		})
	}

	// The names an honest agent sends still reach it, so the refusals above are about the
	// names and not about every request.
	for _, name := range []string{"", DefaultInterfaceName()} {
		host := &namingHost{}
		server, client := unixPair(t)
		answered := make(chan error, 1)
		go func() {
			answered <- answer(context.Background(), server, host,
				request{Op: opOpenTUN, Name: name}, newApprovals(approvingEverything(t)), func(string, ...any) {})
		}()
		var resp response
		if err := readMessage(bufio.NewReader(client), &resp); err != nil {
			t.Fatalf("read the reply: %v", err)
		}
		if err := <-answered; err != nil {
			t.Fatalf("answer the request for %q: %v", name, err)
		}
		if len(host.asked) != 1 || host.asked[0] != name {
			t.Errorf("the request for %q did not reach interface creation: %q", name, host.asked)
		}
	}
}
