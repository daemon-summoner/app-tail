// SPDX-License-Identifier: MIT

package subnets

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

// The whole feature: a peer connects to an address on a network this device carries,
// and reaches the real host on that network.
func TestAConnectionToAnApprovedNetworkReachesTheHostOnIt(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	h := newHarness(t, tn, newSettings())
	h.apply(t)

	got := h.carry(t, netip.MustParseAddrPort("10.20.0.7:80"), "hello from the tailnet")

	if got != "hello from the tailnet" {
		t.Errorf("the carried connection returned %q, want the bytes it sent back", got)
	}
	if dialed := h.dials(); len(dialed) != 1 || dialed[0] != "10.20.0.7:80" {
		t.Errorf("dialed %v, want exactly the address the peer asked for", dialed)
	}

	st := h.router.Status()
	if !st.Serving {
		t.Error("the router reports it is not serving, but it just carried a connection")
	}
	if st.Carried != 1 || st.Refused != 0 {
		t.Errorf("carried %d and refused %d, want 1 carried and none refused", st.Carried, st.Refused)
	}
	if st.BytesIn == 0 || st.BytesOut == 0 {
		t.Errorf("counted %d bytes in and %d out, want both sides of a completed transfer",
			st.BytesIn, st.BytesOut)
	}
}

// This is the only place in app-tail that sees a port and the device that reached it at the
// same time -- every other seam carries this machine's own outbound traffic, where there is no
// device to name. Keying by port alone would throw away the answer to "which device is
// hammering that port", which is the whole reason the port graph offers a device filter.
func TestACarriedFlowIsCountedAgainstItsPortAndTheDeviceThatReachedIt(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	h := newHarness(t, tn, newSettings())
	h.apply(t)

	h.carry(t, netip.MustParseAddrPort("10.20.0.7:80"), "hello from the tailnet")

	named, _, folded := h.router.Ports()
	if len(named) != 1 || folded != 0 {
		t.Fatalf("the router reported %d ports and folded %d, want the one port it carried",
			len(named), folded)
	}
	got := named[0]
	if got.Label != "80" || got.Detail != "tcp" {
		t.Errorf("the port drew as %q over %q, want 80 over tcp", got.Label, got.Detail)
	}
	// The address rather than a name: naming it needs the peer list, which this package
	// deliberately does not hold.
	if got.Peer != "100.64.0.9" {
		t.Errorf("the port was reached by %q, want the address the flow came from", got.Peer)
	}
	// What the device sent to the routed network is what this machine received, so it is the
	// row's down. Swapping them draws every upload from the tailnet as a download.
	if got.Down == 0 || got.Up == 0 {
		t.Errorf("the port counted %d up and %d down, want both sides of a completed transfer",
			got.Up, got.Down)
	}
}

// The distinction the whole policy rests on. Advertising is a request; only an admin's
// approval routes a network here. Serving what was asked for would answer connections
// the tailnet never sent, on networks nobody agreed this device may reach.
func TestAConnectionToAnAdvertisedButUnapprovedNetworkIsRefused(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	h := newHarness(t, tn, newSettings(func(_ *config.Settings, p *config.TailnetPrefs) {
		p.RoutesAdvertise = mustPrefixes(t, "10.20.0.0/24", "192.168.50.0/24")
	}))
	h.apply(t)

	if _, ok := tn.deliver(t, netip.MustParseAddrPort("192.168.50.4:22")); ok {
		t.Fatal("a connection to an advertised network nobody approved was carried")
	}
	if dialed := h.dials(); len(dialed) != 0 {
		t.Errorf("dialed %v, want nothing dialed for a refused flow", dialed)
	}

	st := h.router.Status()
	if st.Refused != 1 || st.Carried != 0 {
		t.Errorf("carried %d and refused %d, want the flow counted as refused", st.Carried, st.Refused)
	}
}

// Defence in depth against an approval that should never have been granted. A route
// covering one of these classes would turn a subnet route into a way to reach services
// bound to this machine's own loopback, or an address that names a different machine on
// every network it is used on.
func TestAddressesNoRouteMayCarryAreRefusedEvenWhenApproved(t *testing.T) {
	cases := []struct {
		name string
		dst  string
	}{
		{"loopback", "127.0.0.1:8080"},
		{"IPv6 loopback", "[::1]:8080"},
		{"link-local unicast", "169.254.1.5:80"},
		{"IPv6 link-local", "[fe80::1]:80"},
		{"multicast", "224.0.0.251:5353"},
		{"IPv6 multicast", "[ff02::fb]:5353"},
		{"unspecified", "0.0.0.0:80"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Approved as widely as the tailnet could possibly approve, so the refusal
			// can only come from the address class itself.
			tn := newFakeTailnet(mustPrefixes(t, "0.0.0.0/0", "::/0")...)
			h := newHarness(t, tn, newSettings())
			h.apply(t)

			if _, ok := tn.deliver(t, netip.MustParseAddrPort(tc.dst)); ok {
				t.Fatalf("a connection to %s was carried", tc.dst)
			}
			if dialed := h.dials(); len(dialed) != 0 {
				t.Errorf("dialed %v, want nothing dialed for %s", dialed, tc.dst)
			}
		})
	}
}

// Nothing about the hook promises a destination that parses. The zero value reads as the
// unspecified address on port zero, so a refusal that only classified real addresses
// would send this one to the dialer and let the operating system decide what it meant.
func TestAFlowWithNoDestinationAtAllIsRefused(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "0.0.0.0/0", "::/0")...)
	h := newHarness(t, tn, newSettings())
	h.apply(t)

	if _, ok := tn.deliver(t, netip.AddrPort{}); ok {
		t.Fatal("a connection with no destination was carried")
	}
	if dialed := h.dials(); len(dialed) != 0 {
		t.Errorf("dialed %v, want nothing dialed for a destination that is not an address", dialed)
	}
	// The reason it was refused, not just that it was: read as an address this is a host
	// outside every approved network, and reporting it that way sends a user to the
	// admin console over a flow the tailnet stack should never have handed over.
	if !strings.Contains(h.logs.String(), "the destination is not an address") {
		t.Errorf("the refusal was logged as %q, want it named as an unusable destination",
			h.logs.String())
	}
}

// A peer that connects and says nothing is an ordinary thing -- a health check, a port
// scan, a client that gave up. It is still a carried connection, and it moved no bytes,
// so the two facts on the card have to stay separate.
func TestAConnectionThatMovedNoBytesIsStillCountedAsCarried(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	h := newHarness(t, tn, newSettings())
	h.apply(t)

	handle, ok := tn.deliver(t, netip.MustParseAddrPort("10.20.0.7:80"))
	if !ok {
		t.Fatal("a connection to an approved network was refused")
	}
	peer, far := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handle(far)
	}()
	if err := peer.Close(); err != nil {
		t.Fatalf("close the test connection: %v", err)
	}
	<-done

	st := h.router.Status()
	if st.Carried != 1 {
		t.Errorf("carried = %d, want the connection counted", st.Carried)
	}
	if st.BytesIn != 0 || st.BytesOut != 0 {
		t.Errorf("bytes in=%d out=%d, want nothing counted for a connection that moved nothing",
			st.BytesIn, st.BytesOut)
	}
}

// Every other component here takes a logger and this one is built beside them, so a
// caller that has none to hand must get a working router rather than a nil dereference on
// the first flow -- which would take down the tailnet stack's own goroutine.
func TestARouterBuiltWithoutALoggerStillCarriesTraffic(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	r := New(tn, newSettings().get, nil)
	t.Cleanup(r.Close)
	r.SetNodeUp(true)
	if err := r.Apply(); err != nil {
		t.Fatalf("reconcile the subnet router: %v", err)
	}

	if handle, _ := tn.deliver(t, netip.MustParseAddrPort("10.20.0.7:80")); handle == nil {
		t.Error("a connection to an approved network was refused by a router built with no logger")
	}
	// The refusal path is the one that logs on every flow, so it is the one a nil logger
	// takes down.
	if _, ok := tn.deliver(t, netip.MustParseAddrPort("127.0.0.1:80")); ok {
		t.Error("a connection to loopback was carried")
	}
}

// An IPv4 address arriving mapped into IPv6 is the same address, and netip refuses to
// match one against an IPv4 prefix: read as it arrives it would fall outside every
// approved network on a dual-stack path, so an approved route would refuse its own
// traffic.
func TestAnIPv4AddressWrittenAsIPv6IsTreatedAsTheAddressItIs(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	h := newHarness(t, tn, newSettings())
	h.apply(t)

	got := h.carry(t, netip.MustParseAddrPort("[::ffff:10.20.0.7]:80"), "mapped")

	if got != "mapped" {
		t.Errorf("the carried connection returned %q, want the bytes it sent back", got)
	}
	if dialed := h.dials(); len(dialed) != 1 || dialed[0] != "10.20.0.7:80" {
		t.Errorf("dialed %v, want the address in the form the destination's network uses", dialed)
	}
}

// Turning the setting off has to stop connections being carried, not merely stop new
// ones being counted: the hook stays installed until it is removed, and a router that
// left it there would keep answering flows the user switched off.
func TestSwitchingTheSettingOffRemovesTheHook(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	box := newSettings()
	h := newHarness(t, tn, box)
	h.apply(t)

	if !tn.installed() {
		t.Fatal("no hook was installed while the setting is on")
	}

	box.set(func(_ *config.Settings, p *config.TailnetPrefs) { p.RoutesServe = false })
	h.apply(t)

	if tn.installed() {
		t.Error("the hook is still installed after the setting was switched off")
	}
	if _, stops, _ := tn.counts(); stops != 1 {
		t.Errorf("the hook was removed %d times, want exactly once", stops)
	}
	if st := h.router.Status(); st.Serving {
		t.Error("the router reports it is serving after the setting was switched off")
	}
}

// The module switch governs everything under it. A user who turns the routing module off
// expects the same result as turning each of its settings off one by one.
func TestSwitchingTheModuleOffRemovesTheHook(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	box := newSettings()
	h := newHarness(t, tn, box)
	h.apply(t)

	box.set(func(app *config.Settings, _ *config.TailnetPrefs) { app.RoutesEnabled = false })
	h.apply(t)

	if tn.installed() {
		t.Error("the hook is still installed after the routing module was switched off")
	}
}

// The reconcile loop calls Apply on every pass. Re-installing each time would leave a
// growing pile of hooks on the node, only the last of which any deregistration reaches.
func TestReconcilingAgainLeavesAnEstablishedHookAlone(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	h := newHarness(t, tn, newSettings())

	h.apply(t)
	h.apply(t)
	h.apply(t)

	installs, stops, _ := tn.counts()
	if installs != 1 || stops != 0 {
		t.Errorf("installed %d hooks and removed %d, want one install and no removals",
			installs, stops)
	}
}

// The hook belongs to the node's own network stack, so there is nothing to keep alive
// while the node is down -- and a user looking at this card wants the reason, not a
// silently idle router.
func TestARouterWhoseNodeIsDownCarriesNothingAndSaysWhy(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	h := newHarness(t, tn, newSettings())
	h.apply(t)

	h.router.SetNodeUp(false)
	h.apply(t)

	if tn.installed() {
		t.Error("the hook is still installed while the node is down")
	}
	st := h.router.Status()
	if st.Serving {
		t.Error("the router reports it is serving while the node is down")
	}
	if st.Error != "the tailnet node is not running" {
		t.Errorf("the router reports %q, want the reason it is carrying nothing", st.Error)
	}

	// And it comes back on its own once the node does, without anything being rebuilt.
	h.router.SetNodeUp(true)
	h.apply(t)
	if !tn.installed() {
		t.Error("the hook was not reinstalled after the node came back")
	}
	if st := h.router.Status(); st.Error != "" {
		t.Errorf("the router still reports %q after the node came back", st.Error)
	}
}

// A hook that could not be installed is the one case where an advertised, approved and
// switched-on route carries nothing for a reason nothing else on screen explains.
func TestAHookThatCouldNotBeInstalledIsReported(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	tn.serveErr = errors.New("the tailnet node is not running")
	h := newHarness(t, tn, newSettings())

	if err := h.router.Apply(); err == nil {
		t.Fatal("reconciling reported success although the hook could not be installed")
	}
	st := h.router.Status()
	if st.Serving {
		t.Error("the router reports it is serving although no hook was installed")
	}
	if st.Error != "the tailnet node is not running" {
		t.Errorf("the router reports %q, want the reason the hook could not be installed", st.Error)
	}
}

// Reading the approved set is a round trip to the backend. Doing it per connection would
// put that round trip in front of every flow, so the answer is reused -- but only for as
// long as the cache is meant to live, or a route approved minutes ago stays refused.
func TestTheApprovedSetIsReusedBetweenConnectionsAndReadAgainWhenItAges(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	h := newHarness(t, tn, newSettings())
	h.apply(t)

	h.carry(t, netip.MustParseAddrPort("10.20.0.7:80"), "one")
	h.carry(t, netip.MustParseAddrPort("10.20.0.8:80"), "two")
	if _, _, reads := tn.counts(); reads != 1 {
		t.Errorf("the approved set was read %d times for two connections, want it reused", reads)
	}

	// An admin approves another network while the app is running.
	tn.approve(mustPrefixes(t, "10.20.0.0/24", "192.168.50.0/24")...)
	if _, ok := tn.deliver(t, netip.MustParseAddrPort("192.168.50.4:22")); ok {
		t.Fatal("a newly approved network was carried before the cached set aged out")
	}

	h.clock.advance(approvedTTL)
	h.carry(t, netip.MustParseAddrPort("192.168.50.4:22"), "three")
	if _, _, reads := tn.counts(); reads != 2 {
		t.Errorf("the approved set was read %d times, want it read again once it aged out", reads)
	}
}

// Refusing every connection is far better than carrying one to a network that may not be
// approved at all: an unreadable approved set is not permission.
func TestAnUnreadableApprovedSetRefusesRatherThanGuesses(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	tn.approvedErr = errors.New("the control plane is not answering")
	h := newHarness(t, tn, newSettings())
	h.apply(t)

	if _, ok := tn.deliver(t, netip.MustParseAddrPort("10.20.0.7:80")); ok {
		t.Fatal("a connection was carried although the approved set could not be read")
	}
	if st := h.router.Status(); st.Refused != 1 {
		t.Errorf("refused %d connections, want the flow counted as refused", st.Refused)
	}
}

// A destination that does not answer must not leave the peer's connection hanging: the
// peer is waiting on a router that already knows the answer is no.
func TestAConnectionToAHostThatIsNotAnsweringIsClosedRatherThanLeftOpen(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	h := newHarness(t, tn, newSettings())
	h.apply(t)
	h.failDials(errors.New("connection refused"))

	handle, ok := tn.deliver(t, netip.MustParseAddrPort("10.20.0.7:80"))
	if !ok {
		t.Fatal("the flow was refused before the destination was even dialed")
	}

	peer, far := readablePipe(t)
	handle(far)

	// io.EOF specifically, and not the deadline: a deadline would also end the read,
	// which is exactly the outcome this test exists to tell apart from a closed peer.
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("reading the peer's connection ended with %v, want it closed", err)
	}
}

// A destination that does not answer and a peer connection that will not close are two
// separate failures, and the second one hides the first if it is swallowed. The status
// counts this flow as carried either way, so the log is where the reason lives.
func TestBothFailuresAreNamedWhenAnUnreachedConnectionAlsoWillNotClose(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	h := newHarness(t, tn, newSettings())
	h.apply(t)
	h.failDials(errors.New("connection refused"))

	handle, ok := tn.deliver(t, netip.MustParseAddrPort("10.20.0.7:80"))
	if !ok {
		t.Fatal("the flow was refused before the destination was even dialed")
	}
	_, far := readablePipe(t)
	handle(faultyConn{Conn: far, closeErr: errors.New("the stack already tore this down")})

	logs := h.logs.String()
	if !strings.Contains(logs, "connection refused") {
		t.Errorf("the logs read %q, want the reason the destination was not reached", logs)
	}
	if !strings.Contains(logs, "the stack already tore this down") {
		t.Errorf("the logs read %q, want the reason the connection would not close", logs)
	}
}

// A route that is approved and installed and still drops connections part-way through is
// the hardest thing here to diagnose: the status counts the flow as carried, so the only
// place the reason appears is the log, named with the destination it was carrying to.
func TestAConnectionThatEndedBadlyIsNamedWithWhereItWasGoing(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	h := newHarness(t, tn, newSettings())
	h.apply(t)

	handle, ok := tn.deliver(t, netip.MustParseAddrPort("10.20.0.7:80"))
	if !ok {
		t.Fatal("a connection to an approved network was refused")
	}
	// The read fails while the router is still running, so the error is one the router
	// neither caused nor was shut down for -- the case its own cancellation must not be
	// confused with.
	_, far := readablePipe(t)
	handle(faultyConn{Conn: far, readErr: errors.New("the tailnet flow died mid-transfer")})

	logs := h.logs.String()
	if !strings.Contains(logs, "the tailnet flow died mid-transfer") {
		t.Errorf("the logs read %q, want the reason the connection ended", logs)
	}
	if !strings.Contains(logs, "10.20.0.7:80") {
		t.Errorf("the logs read %q, want the connection named with the destination it was carrying to", logs)
	}
}

// Switching the router back on is the moment a user is watching for it to work, and the
// approved set they were refused against a moment ago is the one thing that must not
// decide the answer now.
func TestTurningTheRouterBackOnReadsTheApprovedSetAgain(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	box := newSettings()
	h := newHarness(t, tn, box)
	h.apply(t)
	h.carry(t, netip.MustParseAddrPort("10.20.0.7:80"), "before")

	box.set(func(_ *config.Settings, p *config.TailnetPrefs) { p.RoutesServe = false })
	h.apply(t)
	tn.approve(mustPrefixes(t, "192.168.50.0/24")...)
	box.set(func(_ *config.Settings, p *config.TailnetPrefs) { p.RoutesServe = true })
	h.apply(t)

	if got := h.carry(t, netip.MustParseAddrPort("192.168.50.4:22"), "after"); got != "after" {
		t.Errorf("the carried connection returned %q, want the bytes it sent back", got)
	}
	if _, ok := tn.deliver(t, netip.MustParseAddrPort("10.20.0.7:80")); ok {
		t.Error("a network that is no longer approved was still carried")
	}
}

// A connection to this device's own tailnet address, on a machine whose services are shared.
func incomingHarness(t *testing.T, box *settingsBox) (*harness, netip.AddrPort) {
	t.Helper()
	tn := newFakeTailnet()
	tn.own = []netip.Addr{netip.MustParseAddr("100.65.45.58")}
	h := newHarness(t, tn, box)
	h.router.hostAddrs = func() ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.168.6.201")}, nil
	}
	h.apply(t)
	return h, netip.MustParseAddrPort("100.65.45.58:8080")
}

func routesOff(_ *config.Settings, p *config.TailnetPrefs) { p.RoutesServe = false }

func incomingOff(_ *config.Settings, p *config.TailnetPrefs) {
	off := false
	p.IncomingAllow = &off
}

// The whole feature, and the privacy boundary with it: the service is dialed at this
// machine's network address, so one listening only on localhost is never reached.
func TestAConnectionToThisDeviceIsDialedAtItsNetworkAddressNotLoopback(t *testing.T) {
	h, self := incomingHarness(t, newSettings(routesOff))

	got := h.carry(t, self, "hello from a peer")

	if got != "hello from a peer" {
		t.Errorf("the connection returned %q, want the bytes the service sent back", got)
	}
	if dialed := h.dials(); len(dialed) != 1 || dialed[0] != "192.168.6.201:8080" {
		t.Errorf("dialed %v, want only this machine's network address at the port asked for", dialed)
	}
}

func TestSharingDoesNotShowUpAsRoutesBeingServed(t *testing.T) {
	h, _ := incomingHarness(t, newSettings(routesOff))

	if !h.tailnet.installed() {
		t.Fatal("the hook is not installed, so no connection to this device could arrive")
	}
	if h.router.Status().Serving {
		t.Error("the router reports serving routes while routes are switched off")
	}
}

// Sharing installs the same hook routes use, on every device by default. Letting an approved
// flow through here would turn routing back on for a user who switched it off.
func TestSharingDoesNotCarryRoutesThatAreSwitchedOff(t *testing.T) {
	h, _ := incomingHarness(t, newSettings(routesOff))
	h.tailnet.approve(mustPrefixes(t, "10.20.0.0/24")...)

	if _, ok := h.tailnet.deliver(t, netip.MustParseAddrPort("10.20.0.7:80")); ok {
		t.Error("carried a flow for an approved network with routes switched off")
	}
}

func TestSwitchingIncomingOffRefusesConnectionsToThisDevice(t *testing.T) {
	box := newSettings(incomingOff)
	h, self := incomingHarness(t, box)

	if _, ok := h.tailnet.deliver(t, self); ok {
		t.Error("carried a connection to this device with incoming connections off")
	}
}

func TestSwitchingIncomingOffRemovesAHookOnlySharingNeeded(t *testing.T) {
	h, _ := incomingHarness(t, newSettings(routesOff, incomingOff))

	if h.tailnet.installed() {
		t.Error("the hook is installed with both routes and incoming connections off")
	}
}

// On the interface stack ContainedAddrs is empty, and the hook claims every flow it sees, so
// installing it there would break subnet routes the operating system stack is carrying.
func TestNoHookIsInstalledWhenTheOperatingSystemHoldsTheAddress(t *testing.T) {
	h := newHarness(t, newFakeTailnet(), newSettings(routesOff))
	h.apply(t)

	if h.tailnet.installed() {
		t.Error("installed the hook on a node whose addresses the operating system holds")
	}
}

// A device not yet connected is the ordinary state of every install, and it has nothing to
// do with routing, which it has not been asked to do.
func TestADownNodeReportsNoRoutingFaultForSharingAlone(t *testing.T) {
	h, _ := incomingHarness(t, newSettings(routesOff))
	h.router.SetNodeUp(false)
	h.apply(t)

	if got := h.router.Status().Error; got != "" {
		t.Errorf("a device only sharing services reports the routing fault %q", got)
	}
}

func TestAPortAppTailOwnsIsNeverDialed(t *testing.T) {
	h, self := incomingHarness(t, newSettings(routesOff))
	h.router.SetDialGuard(func(string, netip.AddrPort) error { return errors.New("the proxy") })
	handle, ok := h.tailnet.deliver(t, self)
	if !ok {
		t.Fatal("refused the flow before the guard could judge it")
	}

	peer, far := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handle(far)
	}()

	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set the test connection's deadline: %v", err)
	}
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Error("the peer's connection stayed open on a port the guard refused")
	}
	peer.Close()
	<-done
	if dialed := h.dials(); len(dialed) != 0 {
		t.Errorf("dialed %v past a guard that refused the port", dialed)
	}
}

// A service bound to one of several addresses refuses on the others, and that must not read
// as there being no service.
func TestEveryNetworkAddressIsTriedBeforeGivingUp(t *testing.T) {
	h, self := incomingHarness(t, newSettings(routesOff))
	h.router.hostAddrs = func() ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("192.168.6.201")}, nil
	}
	h.failDialsTo("10.0.0.5:8080", errors.New("connection refused"))

	if got := h.carry(t, self, "second address"); got != "second address" {
		t.Errorf("the connection returned %q", got)
	}
	if dialed := h.dials(); len(dialed) != 2 {
		t.Errorf("dialed %v, want both addresses in turn", dialed)
	}
}

func TestTakingTheGuardAwayLetsConnectionsThrough(t *testing.T) {
	h, self := incomingHarness(t, newSettings(routesOff))
	h.router.SetDialGuard(func(string, netip.AddrPort) error { return errors.New("the proxy") })
	h.router.SetDialGuard(nil)

	if got := h.carry(t, self, "unguarded"); got != "unguarded" {
		t.Errorf("the connection returned %q", got)
	}
}

func TestInspectionCanRefuseAConnectionToThisDevice(t *testing.T) {
	h, self := incomingHarness(t, newSettings(routesOff))
	seen := &fakeInspector{refuse: true}
	h.router.SetInspector(seen)

	if _, ok := h.tailnet.deliver(t, self); ok {
		t.Error("carried a connection inspection refused")
	}
	if dialed := h.dials(); len(dialed) != 0 {
		t.Errorf("dialed %v for a connection inspection refused", dialed)
	}
	if len(seen.seen) != 1 || seen.seen[0].Where != whereThisDevice {
		t.Errorf("inspection saw %+v, want the one flow labelled %q", seen.seen, whereThisDevice)
	}
}

func TestAMachineWhoseAddressesCannotBeReadSaysWhy(t *testing.T) {
	h, _ := incomingHarness(t, newSettings(routesOff))
	cause := errors.New("no permission")
	h.router.hostAddrs = func() ([]netip.Addr, error) { return nil, cause }

	if _, _, err := h.router.dialHost(8080); !errors.Is(err, cause) {
		t.Errorf("error = %v, want the reason the addresses could not be read", err)
	}
	if dialed := h.dials(); len(dialed) != 0 {
		t.Errorf("dialed %v with no address to dial", dialed)
	}
}

func ipNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	p := netip.MustParsePrefix(cidr)
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// A tunnel's own address is the dangerous entry here: on this machine the route to app-tail's
// utun address points back into the tunnel, so dialing it never reaches a local service.
func TestOnlyAddressesOnRealNetworksAreDialed(t *testing.T) {
	up := net.FlagUp
	ifaces := []net.Interface{
		{Name: "en9"},
		{Name: "lo0", Flags: up | net.FlagLoopback},
		{Name: "utun4", Flags: up | net.FlagPointToPoint},
		{Name: "en0", Flags: up},
		{Name: "en1", Flags: up},
	}
	held := map[string][]net.Addr{
		"en9":   {ipNet(t, "192.168.99.1/24")},
		"lo0":   {ipNet(t, "127.0.0.1/8")},
		"utun4": {ipNet(t, "198.18.0.1/30")},
		"en0": {
			ipNet(t, "192.168.6.201/24"), ipNet(t, "2001:db8::5/64"), ipNet(t, "fe80::1/64"),
			&net.IPAddr{IP: net.ParseIP("10.9.9.9")},
		},
		"en1": {ipNet(t, "10.0.0.5/24"), ipNet(t, "2001:db8::6/64")},
	}

	got, err := usableAddrs(
		func() ([]net.Interface, error) { return ifaces, nil },
		func(i *net.Interface) ([]net.Addr, error) { return held[i.Name], nil },
	)
	if err != nil {
		t.Fatalf("usableAddrs: %v", err)
	}

	want := []netip.Addr{
		netip.MustParseAddr("192.168.6.201"), netip.MustParseAddr("10.0.0.5"),
		netip.MustParseAddr("2001:db8::5"), netip.MustParseAddr("2001:db8::6"),
	}
	if !slices.Equal(got, want) {
		t.Errorf("usableAddrs = %v, want %v", got, want)
	}
}

func TestAddressesThatCannotBeReadAreAnError(t *testing.T) {
	cause := errors.New("no permission")
	one := []net.Interface{{Name: "en0", Flags: net.FlagUp}}

	_, err := usableAddrs(
		func() ([]net.Interface, error) { return nil, cause },
		func(*net.Interface) ([]net.Addr, error) { return nil, nil },
	)
	if !errors.Is(err, cause) {
		t.Errorf("listing interfaces failed, and usableAddrs answered %v", err)
	}

	_, err = usableAddrs(
		func() ([]net.Interface, error) { return one, nil },
		func(*net.Interface) ([]net.Addr, error) { return nil, cause },
	)
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "en0") {
		t.Errorf("reading en0 failed, and usableAddrs answered %v", err)
	}
}

func TestAMachineWithNoNetworkAddressCutsTheConnection(t *testing.T) {
	h, self := incomingHarness(t, newSettings(routesOff))
	h.router.hostAddrs = func() ([]netip.Addr, error) { return nil, nil }
	handle, ok := h.tailnet.deliver(t, self)
	if !ok {
		t.Fatal("refused the flow before it could look for an address")
	}

	peer, far := net.Pipe()
	defer peer.Close()
	go handle(far)

	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Error("the peer's connection stayed open with nothing to reach")
	}
	if dialed := h.dials(); len(dialed) != 0 {
		t.Errorf("dialed %v with no address to dial", dialed)
	}
}

// Against real sockets, because which listener accepts which address is the kernel's answer
// and the entire privacy boundary rests on it.
func TestRealSocketsKeepLocalhostServicesPrivate(t *testing.T) {
	addrs, err := networkAddrs()
	if err != nil {
		t.Fatalf("read this machine's network addresses: %v", err)
	}
	if len(addrs) == 0 {
		t.Skip("this machine has no network address to dial")
	}
	for _, addr := range addrs {
		if addr.IsLoopback() {
			t.Errorf("networkAddrs offered the loopback address %s", addr)
		}
	}

	localhost, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on localhost: %v", err)
	}
	defer localhost.Close()
	everywhere, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen on every address: %v", err)
	}
	defer everywhere.Close()

	router := New(newFakeTailnet(), newSettings().get, nil)
	defer router.Close()

	port := func(ln net.Listener) uint16 { return uint16(ln.Addr().(*net.TCPAddr).Port) }
	if conn, target, err := router.dialHost(port(localhost)); err == nil {
		conn.Close()
		t.Errorf("reached a localhost-only service at %s", target)
	}
	conn, _, err := router.dialHost(port(everywhere))
	if err != nil {
		t.Fatalf("could not reach a service listening on every address: %v", err)
	}
	conn.Close()
}
