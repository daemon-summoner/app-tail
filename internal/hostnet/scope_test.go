// SPDX-License-Identifier: MIT

package hostnet

// What the privileged side will and will not put a route on.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

// The interface name becomes an argument to a program running as root. A name carrying a space,
// a line break or a leading dash is how one argument becomes two, so the shape of the name is
// what is checked rather than what it is escaped into.
func TestAnInterfaceNameThatCouldBeASecondArgumentIsRefused(t *testing.T) {
	for _, name := range []string{
		"",
		"utun 5",
		"utun5\n-ifscope",
		"utun5;route",
		"utun5\x00",
		"a-very-long-interface-name",
		"../../etc/passwd",
	} {
		if err := validInterfaceName(name); err == nil {
			t.Errorf("%q was accepted as a network interface name", name)
		}
	}
	for _, name := range []string{"utun5", "tun0", "eth0", "en0", "wg_home", "br-0.100"} {
		if err := validInterfaceName(name); err != nil {
			t.Errorf("%q was refused as a network interface name: %v", name, err)
		}
	}
}

// A request naming a connection identifier this side would not have started is refused before
// anything reaches the routing table: the connection is the whole of what makes the interface
// this side's to route.
func TestARouteRequestIsCheckedAsAWholeBeforeItIsActedOn(t *testing.T) {
	if err := (OpenVPNScope{ID: "tn_ok0001", Interface: "utun5"}).Validate(); err != nil {
		t.Errorf("an ordinary request was refused: %v", err)
	}
	if err := (OpenVPNScope{ID: "tn ok", Interface: "utun5"}).Validate(); err == nil {
		t.Error("a request naming something that is not a connection identifier was accepted")
	}
	if err := (OpenVPNScope{ID: "tn_ok0001"}).Validate(); err == nil {
		t.Error("a request naming no interface was accepted")
	}
}

// The connection has to be one this side started and is still running. Without that check the
// operation would be "put a route on whichever interface you name", which is a different thing
// to grant an unprivileged caller than "the connection you already agreed to run reaches the
// network through its own interface".
func TestOnlyAConnectionThisSideIsRunningCanBeGivenARoute(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections")
	}
	local := testLocal(t)

	err := local.ScopeOpenVPN(context.Background(), OpenVPNScope{ID: "tn_ghost1", Interface: loopbackName(t)})
	if err == nil {
		t.Fatal("a connection this side never started was given a route on an interface it named")
	}
	if !strings.Contains(err.Error(), "tn_ghost1") {
		t.Errorf("err = %q, want it to name the connection that is not running", err)
	}
}

// The check on the request runs on the privileged side as well as in the caller, because a
// check that only runs before the message is sent is a check on the well-behaved.
func TestTheRouteRequestIsCheckedAgainWhereItIsActedOn(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections")
	}
	local := testLocal(t)

	err := local.ScopeOpenVPN(context.Background(), OpenVPNScope{ID: "tn_ok0001", Interface: "utun5; rm -rf /"})
	if err == nil {
		t.Fatal("a request naming something that is not an interface was acted on")
	}
	if !strings.Contains(err.Error(), "interface") {
		t.Errorf("err = %q, want it to say what was wrong with the interface name", err)
	}
}

// Taking the route back is held to the same rule as installing it, and for the same reason:
// the connection is what makes the interface this side's, so a request naming one this side is
// not running has nothing behind it to act on.
func TestOnlyAConnectionThisSideIsRunningCanHaveItsRouteTakenBack(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections")
	}
	local := testLocal(t)

	err := local.UnscopeOpenVPN(context.Background(), "tn_ghost1")
	if err == nil {
		t.Fatal("a connection this side never started had a route taken back for it")
	}
	if !strings.Contains(err.Error(), "tn_ghost1") {
		t.Errorf("err = %q, want it to name the connection that is not running", err)
	}
	if err := local.UnscopeOpenVPN(context.Background(), "not an id"); err == nil {
		t.Error("a request naming something that is not a connection identifier was acted on")
	}
}

// An interface holding no address in a family gets no route for that family: the route would be
// one nothing could send from, and asking for it fails on both platforms this runs on. Loopback
// is the one interface every machine has both families on.
func TestOnlyTheFamiliesAnInterfaceHoldsAreRouted(t *testing.T) {
	carries, err := interfaceCarriesV6(loopbackName(t))
	if err != nil {
		t.Fatalf("read the loopback interface: %v", err)
	}
	if carries {
		t.Error("loopback was read as holding an address the rest of the internet can be reached from")
	}
	if _, err := interfaceCarriesV6("utun-nothing"); err == nil {
		t.Error("an interface that does not exist was read as holding addresses")
	}
}

// A platform with no way to scope a route says so rather than reporting a connection as
// carrying traffic it would drop. On the two platforms that can, the program that does it has
// to be a root-owned one -- the same requirement openvpn's own binary is held to.
func TestAMachineThatCannotScopeARouteSaysSo(t *testing.T) {
	err := ScopedRoutesSupported()
	if err == nil {
		return
	}
	if !errors.Is(err, ErrScopedRoutesUnsupported) {
		t.Errorf("err = %v, want the refusal to carry the sentinel a caller matches on", err)
	}
}

// runningConnection records a connection as one this side started, without starting a program.
// What the route operations do with it is decided by the connection being present and by the
// interface it was last given a route on, so that is the whole of what has to be there.
func runningConnection(t *testing.T, l *Local, id, scoped string) *openvpnProcess {
	t.Helper()
	proc := &openvpnProcess{done: make(chan struct{})}
	proc.setScopedInterface(scoped)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.openvpn == nil {
		l.openvpn = make(map[string]*openvpnProcess)
	}
	l.openvpn[id] = proc
	return proc
}

// goneInterface is a name no interface on this machine has, which is what an OpenVPN interface
// becomes the moment its program exits.
//
// It has to be shaped like one openvpn opens, or scopableInterface refuses it for that reason
// and the request never reaches the lookup this stands in for.
func goneInterface(t *testing.T) string {
	t.Helper()
	name := openvpnDevice() + "9993"
	if _, err := net.InterfaceByName(name); err == nil {
		t.Skipf("this machine has an interface called %s, so it cannot stand in for one that is gone", name)
	}
	goneInterfaceRouting(t, name)
	return name
}

// A connection that is running but whose interface has gone is the ordinary case, not an
// exception: openvpn opens a fresh interface every time it reconnects. Asking the routing table
// about a name no interface has fails with nothing behind it, so the request has to be refused
// before it becomes a root-owned command rather than after.
func TestAnInterfaceThatIsNotThereIsRefusedBeforeAnythingIsRouted(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections")
	}
	local := testLocal(t)
	runningConnection(t, local, "tn_gone001", "")

	err := local.ScopeOpenVPN(context.Background(), OpenVPNScope{ID: "tn_gone001", Interface: goneInterface(t)})
	if err == nil {
		t.Fatal("a route was asked for on an interface this machine does not have")
	}
	if !strings.Contains(err.Error(), "read the network interface") {
		t.Errorf("err = %q, want it to name the interface that could not be read", err)
	}
}

// The caller names the interface, so the name is the whole of what stands between a running
// connection and a root-owned default route on this machine's own way out. A caller holding one
// connection it was allowed to start must not be able to spend it on en0.
func TestARouteIsRefusedOnAnInterfaceNoConnectionCouldHaveOpened(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections")
	}
	tunnel := openvpnDevice()
	const notATunnel = "is not a tunnel interface openvpn opens"
	for _, tc := range []struct {
		name    string
		iface   string
		driving string
		want    string
	}{
		{"a physical interface", "en0", "", notATunnel},
		{"the loopback", "lo0", "", notATunnel},
		{"a bridge", "bridge100", "", notATunnel},
		{"a tunnel name with no number", tunnel, "", notATunnel},
		{"a tunnel name with something after the number", tunnel + "0x", "", notATunnel},
		{"a name that merely starts the same way", tunnel + "nel0", "", notATunnel},
		{"the interface app-tail opened itself", tunnel + "7", tunnel + "7", "is the interface app-tail opened"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local := testLocal(t)
			local.mu.Lock()
			local.tunName = tc.driving
			local.mu.Unlock()
			runningConnection(t, local, "tn_scope01", "")

			err := local.ScopeOpenVPN(context.Background(), OpenVPNScope{ID: "tn_scope01", Interface: tc.iface})
			if err == nil {
				t.Fatalf("a root default route was installed on %s for the asking", tc.iface)
			}
			// The exact refusal, not merely some error: letting the name through reaches an
			// interface lookup and then a route command, either of which can fail on its own
			// and would leave this passing while the interface was never refused at all.
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want it to refuse %s with %q", err, tc.iface, tc.want)
			}
		})
	}
}

// The refusal has to leave the interfaces openvpn really does open, or it would refuse the
// whole feature rather than the misuse of it.
func TestATunnelInterfaceIsStillScopable(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections")
	}
	for _, name := range []string{openvpnDevice() + "0", openvpnDevice() + "12"} {
		if err := scopableInterface(name, openvpnDevice()+"99"); err != nil {
			t.Errorf("scopableInterface(%q) = %v, want the interface openvpn opens to be allowed", name, err)
		}
	}
}

// Taking back a route the interface already took with it is the outcome the caller asked for.
// Reported as a failure it would leave the connection recorded as still holding a route, and the
// teardown would go on trying to remove one that nothing has.
func TestARouteOnAnInterfaceThatIsGoneIsAlreadyTakenBack(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections")
	}
	local := testLocal(t)
	proc := runningConnection(t, local, "tn_gone002", goneInterface(t))

	if err := local.UnscopeOpenVPN(context.Background(), "tn_gone002"); err != nil {
		t.Fatalf("take back a route from an interface that is gone: %v", err)
	}
	if got := proc.scopedInterface(); got != "" {
		t.Errorf("the connection is still recorded as holding a route on %q", got)
	}

	// Asked for again, it is the same answer: the caller wants the route gone, and it is.
	if err := local.UnscopeOpenVPN(context.Background(), "tn_gone002"); err != nil {
		t.Errorf("take back a route a connection does not have: %v", err)
	}
}

// The connection ending is the case with nobody to report to: the caller may be the thing that
// went away, and a route left on this machine has to be taken back by this side rather than
// asked for. Failure keeps the state, so the session teardown tries again.
func TestAConnectionThatEndedHasItsRouteTakenBackWithNoCallerToReportTo(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections")
	}
	local := testLocal(t)
	proc := runningConnection(t, local, "tn_gone003", goneInterface(t))

	local.unscopeOpenVPN("tn_gone003", proc)
	if got := proc.scopedInterface(); got != "" {
		t.Errorf("the connection is still recorded as holding a route on %q", got)
	}
	// A connection that was never given one reaches the routing table not at all.
	local.unscopeOpenVPN("tn_gone003", proc)
}

// loopbackName is the name of this machine's loopback interface, which is the one interface a
// test can name on every platform without knowing anything about the machine.
func loopbackName(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("read this machine's interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return iface.Name
		}
	}
	t.Fatal("this machine has no loopback interface")
	return ""
}

// tunnelInterface is a name of the shape openvpn opens on this platform. Nothing here reaches
// the machine's routing table or its interfaces, so it does not have to be one this machine has.
func tunnelInterface(suffix string) string { return openvpnDevice() + suffix }

// scopingLocal is a privileged side whose route changes and interface reads are counted rather
// than made. Installing a scoped default route needs root, and the branches worth pinning are
// the ones where it fails or is never reached at all.
func scopingLocal(t *testing.T, id string, v6 bool) (*Local, *openvpnProcess) {
	t.Helper()
	local := NewLocal(func(string, ...any) {})
	local.carriesV6 = func(string) (bool, error) { return v6, nil }
	return local, runningConnection(t, local, id, "")
}

// The record is written before the route goes in, so a record that cannot be written is a route
// that is not installed. A root default route on this machine with nothing recording it is what
// the record exists to prevent, and installing it anyway would reach that state by the very
// path that is supposed to prevent it.
func TestNoConnectionRouteIsInstalledWhenTheRecordOfItCannotBeWritten(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections, so it routes none")
	}
	local, proc := scopingLocal(t, "tn_scope01", false)
	local.state = closedRootState(t)
	changed := 0
	local.scopeRoute = func(context.Context, string, string, bool) error { changed++; return nil }
	local.unscopeRoute = func(context.Context, string, string, bool) error { changed++; return nil }
	iface := tunnelInterface("9998")

	err := local.ScopeOpenVPN(t.Context(), OpenVPNScope{ID: "tn_scope01", Interface: iface})

	if err == nil {
		t.Fatal("a route was installed on this machine with nothing recording it")
	}
	if !strings.Contains(err.Error(), "record") {
		t.Errorf("the reason given is %q, want it to say the record could not be written", err)
	}
	if changed != 0 {
		t.Errorf("%d route changes were made on this machine before the record of them was written", changed)
	}
	if held := proc.scopedInterface(); held != "" {
		t.Errorf("the connection holds %q, and no route was ever installed for it", held)
	}
}

// A connection that reconnects on a different interface has its old route taken back first. The
// record still names the old interface while that happens, so a run that ends in the middle
// leaves the next one the interface to finish on -- which means a record that will not take the
// change stops the move rather than being passed over.
func TestAConnectionMovingInterfaceKeepsTheOldOneRecordedUntilItIsOff(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections, so it routes none")
	}
	iface := tunnelInterface("9998")
	old := tunnelInterface("9996")
	state, seal := closableRootState(t)
	local, proc := scopingLocal(t, "tn_scope02", false)
	local.state = state
	if err := state.setScope("tn_scope02", old); err != nil {
		t.Fatalf("record the interface a connection already holds a route on: %v", err)
	}
	proc.setScopedInterface(old)
	seal()
	installed := 0
	local.scopeRoute = func(context.Context, string, string, bool) error { installed++; return nil }
	local.unscopeRoute = func(context.Context, string, string, bool) error { return nil }

	err := local.ScopeOpenVPN(t.Context(), OpenVPNScope{ID: "tn_scope02", Interface: iface})

	if err == nil {
		t.Fatal("a connection moved interface with the record of the move never written")
	}
	if installed != 0 {
		t.Errorf("%d routes were installed for a connection whose record could not be changed", installed)
	}
	rec, err := state.read()
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if rec.Scoped["tn_scope02"] != old {
		t.Errorf("the record holds %q for this connection, want %s -- the interface the next start has to finish on",
			rec.Scoped["tn_scope02"], old)
	}
}

// A connection that has ended has nobody left to hand a failure to, so this side's log is the
// only place a record that still names a route taken back is visible at all.
func TestARouteTakenBackAfterAConnectionEndedIsReportedWhenTheRecordWillNotSaySo(t *testing.T) {
	var said []string
	local := NewLocal(func(format string, args ...any) { said = append(said, fmt.Sprintf(format, args...)) })
	state, seal := closableRootState(t)
	local.state = state
	if err := state.setScope("tn_scope03", "utun9997"); err != nil {
		t.Fatalf("record the interface a connection holds a route on: %v", err)
	}
	seal()
	local.unscopeRoute = func(context.Context, string, string, bool) error { return nil }
	proc := &openvpnProcess{}
	proc.setScopedInterface("utun9997")

	local.unscopeOpenVPN("tn_scope03", proc)

	joined := strings.Join(said, "\n")
	if !strings.Contains(joined, "could not forget the default route") {
		t.Errorf("this side reported %q, want it to say the record still names a route that is gone", said)
	}
	if !strings.Contains(joined, "utun9997") {
		t.Errorf("this side reported %q, want it to name the interface the record still holds", said)
	}
}

// A route on one family and not the other is a connection that carries half of what it holds
// an address for, and the half that is missing fails outright rather than falling back.
func TestAConnectionsRouteGoesOnEveryFamilyItsInterfaceHolds(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections, so it routes none")
	}
	iface := tunnelInterface("9998")
	local, proc := scopingLocal(t, "tn_scope04", true)
	local.state = testRootState(t)
	var families []bool
	local.scopeRoute = func(_ context.Context, name, _ string, v6 bool) error {
		if name != iface {
			t.Errorf("a route was installed on %q, want %q", name, iface)
		}
		families = append(families, v6)
		return nil
	}

	if err := local.ScopeOpenVPN(t.Context(), OpenVPNScope{ID: "tn_scope04", Interface: iface}); err != nil {
		t.Fatalf("give a connection's interface a default route: %v", err)
	}

	if len(families) != 2 || families[0] || !families[1] {
		t.Errorf("routes were installed for %v, want one for each family the interface holds", families)
	}
	if held := proc.scopedInterface(); held != iface {
		t.Errorf("the connection holds %q, want %s", held, iface)
	}
	rec, err := local.state.read()
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if rec.Scoped["tn_scope04"] != iface {
		t.Errorf("the record holds %q for this connection, want %s", rec.Scoped["tn_scope04"], iface)
	}
}

// Half a pair is worse than none: the connection carries one family and not the other, and the
// route that did go in is one more place this machine's routing is wrong. So the first is taken
// back when the second will not install, and the reason for both is reported.
func TestTheFirstFamilysRouteIsTakenBackWhenTheSecondWillNotInstall(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections, so it routes none")
	}
	iface := tunnelInterface("9998")
	local, proc := scopingLocal(t, "tn_scope05", true)
	local.state = testRootState(t)
	local.scopeRoute = func(_ context.Context, _, _ string, v6 bool) error {
		if v6 {
			return errors.New("the routing table would not have it")
		}
		return nil
	}
	var takenBack []bool
	local.unscopeRoute = func(_ context.Context, _, _ string, v6 bool) error {
		takenBack = append(takenBack, v6)
		return nil
	}

	err := local.ScopeOpenVPN(t.Context(), OpenVPNScope{ID: "tn_scope05", Interface: iface})

	if err == nil {
		t.Fatal("a connection routed on one family and not the other was reported as routed")
	}
	if !strings.Contains(err.Error(), "would not have it") {
		t.Errorf("the reason given is %q, want it to carry why the second route failed", err)
	}
	if len(takenBack) != 1 || takenBack[0] {
		t.Errorf("%v was taken back, want the first family's route and nothing else", takenBack)
	}
	if held := proc.scopedInterface(); held != "" {
		t.Errorf("the connection holds %q after a route it never got", held)
	}
}
