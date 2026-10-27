// SPDX-License-Identifier: MIT

package ports

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
)

// occupyTCP binds a TCP port for the duration of the test and returns it.
func occupyTCP(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy tcp port: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// occupyUDP binds a UDP port for the duration of the test and returns it.
func occupyUDP(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy udp port: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// addressThisMachineCannotBind returns a local address no interface owns, for the
// tests that need every bind against it to fail.
//
// The candidates are the RFC 5737 documentation ranges, which are never routed -- but
// "never assigned" does not hold on a developer machine: a VPN tunnel can carry one on
// a utun interface, and Tailscale's own does, which makes it locally bindable. So each
// candidate is probed and the first genuinely unbindable one is used; a machine that
// binds all of them cannot exercise the failure and skips rather than reporting a
// production defect that is really a local network configuration.
func addressThisMachineCannotBind(t *testing.T) string {
	t.Helper()
	candidates := []string{"192.0.2.1", "198.51.100.1", "203.0.113.1"}
	for _, addr := range candidates {
		ln, err := net.Listen("tcp", net.JoinHostPort(addr, "0"))
		if err != nil {
			return addr
		}
		ln.Close()
	}
	t.Skipf("every candidate address (%v) is bindable here, so no bind failure can be provoked", candidates)
	return ""
}

func TestFreeReportsFalseForAnOccupiedTCPPort(t *testing.T) {
	port := occupyTCP(t)
	if Free(config.TCP, "127.0.0.1", port) {
		t.Fatalf("port %d is bound by this test but Free reported it available", port)
	}
}

func TestFreeReportsTrueAfterThePortIsReleased(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if Free(config.TCP, "127.0.0.1", port) {
		t.Fatalf("port %d should be reported busy while still bound", port)
	}
	ln.Close()
	if !Free(config.TCP, "127.0.0.1", port) {
		t.Fatalf("port %d should be reported free once released", port)
	}
}

// A TCP bind says nothing about UDP: the two are independent namespaces, and
// conflating them would make suggestions collide.
func TestFreeDistinguishesTCPFromUDP(t *testing.T) {
	tcpPort := occupyTCP(t)
	if !Free(config.UDP, "127.0.0.1", tcpPort) {
		t.Fatalf("udp/%d should be free even though tcp/%d is bound", tcpPort, tcpPort)
	}

	udpPort := occupyUDP(t)
	if !Free(config.TCP, "127.0.0.1", udpPort) {
		t.Fatalf("tcp/%d should be free even though udp/%d is bound", udpPort, udpPort)
	}
}

// A "both" forward needs the port free on each stack, so occupying either one alone
// must make Free(Both) report the port as taken.
func TestFreeForBothRequiresEveryStack(t *testing.T) {
	tcpBusy := occupyTCP(t)
	if Free(config.Both, "127.0.0.1", tcpBusy) {
		t.Fatalf("both/%d should be busy: its tcp stack is occupied", tcpBusy)
	}

	udpBusy := occupyUDP(t)
	if Free(config.Both, "127.0.0.1", udpBusy) {
		t.Fatalf("both/%d should be busy: its udp stack is occupied", udpBusy)
	}
}

// The port is one both stacks just handed out and gave back, not a TCP-assigned number
// alone: Windows reserves blocks of UDP ports that TCP still assigns from, and a number
// in one of those is not free on both however little is bound.
func TestFreeForBothIsTrueWhenNeitherStackIsBound(t *testing.T) {
	port := releasedOnBothStacks(t)
	if !Free(config.Both, "127.0.0.1", port) {
		t.Fatalf("both/%d should be free: nothing is bound on either stack", port)
	}
}

// releasedOnBothStacks returns a port that was bound on TCP and UDP together a moment
// ago and is held on neither now.
func releasedOnBothStacks(t *testing.T) int {
	t.Helper()
	var held []net.Listener
	defer func() {
		for _, ln := range held {
			ln.Close()
		}
	}()
	for range bothStackAttempts {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			held = append(held, ln)
			continue
		}
		pc.Close()
		ln.Close()
		return port
	}
	t.Fatalf("no port was bindable on both stacks in %d tries", bothStackAttempts)
	return 0
}

// stackAlwaysCollides makes one stack's OS-assigned port always a number the other
// stack holds, the way a Windows port-exclusion block sits under a run of assignments.
// The collision is real: the port is bound on the other stack for the test's duration.
func stackAlwaysCollides(t *testing.T, protocol config.Protocol) {
	t.Helper()
	tcpWas, udpWas := listenTCP, listenUDP
	t.Cleanup(func() { listenTCP, listenUDP = tcpWas, udpWas })
	switch protocol {
	case config.TCP:
		listenTCP = func(string) (net.Listener, int, error) {
			port := occupyUDP(t)
			ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				return nil, 0, err
			}
			return ln, port, nil
		}
	case config.UDP:
		listenUDP = func(string) (net.PacketConn, int, error) {
			port := occupyTCP(t)
			pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				return nil, 0, err
			}
			return pc, port, nil
		}
	}
}

// Windows assigns ephemeral ports in sequence and reserves blocks of hundreds of
// consecutive UDP ports that TCP still assigns from, so every TCP-assigned number in a
// run can be one UDP refuses. The other stack's assignments come from a cursor of their
// own, and a both forward has to ask it rather than report the machine out of ports.
func TestABothForwardStillFindsAPortWhenOneStacksAssignmentsAllCollide(t *testing.T) {
	for _, captured := range []config.Protocol{config.TCP, config.UDP} {
		t.Run(string(captured), func(t *testing.T) {
			stackAlwaysCollides(t, captured)
			got, err := ephemeral(config.Both, "127.0.0.1")
			if err != nil {
				t.Fatalf("ephemeral gave up while the other stack's assignments were all free: %v", err)
			}
			if !Free(config.Both, "127.0.0.1", got) {
				t.Fatalf("ephemeral returned %d, which is not bindable on both stacks", got)
			}
		})
	}
}

// With both stacks' assignments colliding there is no port to find, and the search has
// to end in an error rather than run on: the alternative is a dashboard that hangs on
// port-conflict recovery.
func TestABothForwardReportsWhenEveryAssignmentOnBothStacksCollides(t *testing.T) {
	stackAlwaysCollides(t, config.TCP)
	stackAlwaysCollides(t, config.UDP)
	_, err := ephemeral(config.Both, "127.0.0.1")
	if err == nil {
		t.Fatal("ephemeral returned a port while every assignment on both stacks collided")
	}
	if !strings.Contains(err.Error(), "both tcp and udp") {
		t.Errorf("the error does not say what was searched for: %v", err)
	}
}

func TestFreeRejectsOutOfRangePorts(t *testing.T) {
	for _, port := range []int{-1, 0, 65536, 100000} {
		if Free(config.TCP, "127.0.0.1", port) {
			t.Errorf("port %d is not a valid port number but Free accepted it", port)
		}
	}
}

func TestSuggestReturnsThePreferredPortWhenItIsAvailable(t *testing.T) {
	// Take an ephemeral port and release it, so we have one very likely to be free.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	preferred := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	got, err := Suggest(config.TCP, "127.0.0.1", preferred, nil)
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if got != preferred {
		t.Fatalf("Suggest returned %d, want the preferred port %d", got, preferred)
	}
}

// The headline case from the design doc: the port the user would naturally want is
// already taken, so the suggestion must walk past it rather than fail.
func TestSuggestWalksPastAnOccupiedPreferredPort(t *testing.T) {
	preferred := occupyTCP(t)

	got, err := Suggest(config.TCP, "127.0.0.1", preferred, nil)
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if got == preferred {
		t.Fatalf("Suggest returned the occupied port %d", got)
	}
	if !Free(config.TCP, "127.0.0.1", got) {
		t.Fatalf("Suggest returned port %d, which is not actually bindable", got)
	}
}

func TestSuggestSkipsPortsTheCallerHasReserved(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	preferred := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	// The preferred port is bindable, but a configured-yet-stopped forward owns it.
	reserved := map[int]bool{preferred: true, preferred + 1: true}
	got, err := Suggest(config.TCP, "127.0.0.1", preferred, func(p int) bool { return reserved[p] })
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if reserved[got] {
		t.Fatalf("Suggest returned reserved port %d", got)
	}
}

func TestSuggestFallsBackToAnEphemeralPortWhenTheWholeScanRangeIsReserved(t *testing.T) {
	const preferred = 20000
	reserved := func(p int) bool { return p >= preferred && p < preferred+scanLimit }

	got, err := Suggest(config.TCP, "127.0.0.1", preferred, reserved)
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if reserved(got) {
		t.Fatalf("Suggest returned %d, which is inside the fully reserved range", got)
	}
	if !Free(config.TCP, "127.0.0.1", got) {
		t.Fatalf("Suggest returned port %d, which is not actually bindable", got)
	}
}

func TestSuggestReturnsAUDPPortForUDPForwards(t *testing.T) {
	got, err := Suggest(config.UDP, "127.0.0.1", 0, nil)
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if !Free(config.UDP, "127.0.0.1", got) {
		t.Fatalf("Suggest returned udp port %d, which is not actually bindable", got)
	}
}

// A both forward's suggested port must be bindable on TCP and UDP together, so a
// port free on TCP but taken on UDP has to be walked past, not returned.
func TestSuggestForBothSkipsAPortTakenOnOnlyOneStack(t *testing.T) {
	// Occupy a port on UDP; its TCP side stays free, so a naive tcp-only check
	// would wrongly hand it out for a both forward.
	preferred := occupyUDP(t)

	got, err := Suggest(config.Both, "127.0.0.1", preferred, nil)
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if got == preferred {
		t.Fatalf("Suggest returned %d, which is bound on udp", preferred)
	}
	if !Free(config.Both, "127.0.0.1", got) {
		t.Fatalf("Suggest returned %d, which is not bindable on both stacks", got)
	}
}

func TestSuggestForBothReturnsAPortBindableOnBothStacks(t *testing.T) {
	got, err := Suggest(config.Both, "127.0.0.1", 0, nil)
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if !Free(config.Both, "127.0.0.1", got) {
		t.Fatalf("Suggest returned %d, which is not bindable on both stacks", got)
	}
}

func TestSuggestUsesTheDefaultBindAddrWhenNoneIsGiven(t *testing.T) {
	got, err := Suggest(config.TCP, "", 0, nil)
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	addr := net.JoinHostPort(config.DefaultBindAddr, strconv.Itoa(got))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("suggested port %d is not bindable on the default addr: %v", got, err)
	}
	ln.Close()
}

func TestTargetPortExtractsThePortFromAHostPortTarget(t *testing.T) {
	tests := []struct {
		target string
		want   int
	}{
		{"100.64.0.5:8100", 8100},
		{"llm-box:8100", 8100},
		{"[fd7a:115c:a1e0::1]:443", 443},
		{"host:0", 0},
		{"no-port", 0},
		{"host:notanumber", 0},
		{"", 0},
	}
	for _, tt := range tests {
		if got := TargetPort(tt.target); got != tt.want {
			t.Errorf("TargetPort(%q) = %d, want %d", tt.target, got, tt.want)
		}
	}
}

// The OS hands out TCP and UDP ephemeral ports from one shared range but tracks the
// two independently, so a TCP-assigned number is regularly already bound on UDP. A
// both forward has to walk past that rather than give up: on a machine holding many
// UDP sockets -- mDNS, DNS clients, the tailnet itself -- giving up on the first
// collision turns the dashboard's port-conflict recovery into an error most of the
// time.
//
// The pressure below is what makes the collision likely enough to observe; without
// it the fault is invisible on an idle machine, which is exactly why it shipped.
func TestSuggestForBothSurvivesUDPPressure(t *testing.T) {
	const (
		heldSockets = 2048
		iterations  = 150
	)

	var held []net.PacketConn
	t.Cleanup(func() {
		for _, pc := range held {
			pc.Close()
		}
	})
	for i := 0; i < heldSockets; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			break
		}
		held = append(held, pc)
	}
	if len(held) < heldSockets/2 {
		t.Skipf("could only hold %d udp sockets; not enough pressure to exercise the retry", len(held))
	}

	for i := 0; i < iterations; i++ {
		got, err := Suggest(config.Both, "127.0.0.1", 0, nil)
		if err != nil {
			t.Fatalf("Suggest gave up on iteration %d instead of asking for another port: %v", i, err)
		}
		if !Free(config.Both, "127.0.0.1", got) {
			t.Fatalf("Suggest returned %d, which is not bindable on both stacks", got)
		}
	}
}

// A bind address the machine does not own -- a stale forward whose interface went
// away, or a typo'd address -- makes every bind fail, including the OS-assigned
// fallback. Suggest has to report that rather than return a port number nothing can
// actually listen on, which would leave the forward failing at start with no clue why.
func TestSuggestReportsABindAddressTheMachineDoesNotOwn(t *testing.T) {
	unassigned := addressThisMachineCannotBind(t)

	for _, protocol := range []config.Protocol{config.TCP, config.UDP, config.Both} {
		t.Run(string(protocol), func(t *testing.T) {
			// preferred 0 is out of range, so the scan is skipped and the OS-assigned
			// path -- the only one that can report a bind failure -- is taken directly.
			port, err := Suggest(protocol, unassigned, 0, nil)
			if err == nil {
				t.Fatalf("Suggest returned port %d for an address this machine cannot bind", port)
			}
			if port != 0 {
				t.Errorf("Suggest returned port %d alongside an error, want 0", port)
			}
		})
	}
}
