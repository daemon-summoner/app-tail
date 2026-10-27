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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/dns"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/router"

	"github.com/sellitus/app-tail/internal/sysdns"
)

// These drive every operation the agent has across the socket against a privileged side that
// writes down what it was asked instead of doing it. What they pin is the seam itself: an
// argument that does not survive the crossing, or an answer that does not survive the way
// back, is a privileged operation performed on something other than what the caller chose --
// and neither side's own tests can see it, because each is right about its own half.

// commandedHost stands in for the machine. Everything it is asked to change it records; the
// answers it gives back are the ones the test set.
type commandedHost struct {
	mu sync.Mutex

	routerCfg    *router.Config
	routerSeen   bool
	hostRoutes   Routes
	brought      int
	scopedHost   int
	unscopedHost int
	interfaceDNS dns.OSConfig
	interfaceSet bool
	systemDNS    []netip.Addr
	systemDNSSet bool
	wantResolver netip.AddrPort
	started      []OpenVPNRun
	stopped      []string
	scopedVPN    []OpenVPNScope
	unscopedVPN  []string
	// repairedTailnet is every interface a tailnet-route repair was asked for, in order.
	repairedTailnet []string
	kept            tun.Device
	closed          bool

	// The answers this side gives. A nil error field means the operation reports success.
	dev          tun.Device
	name         string
	base         dns.OSConfig
	baseErr      error
	split        bool
	systemBase   sysdns.Base
	hostScopeErr error
	packet       func() (net.PacketConn, error)
	stream       func() (net.Listener, error)
	// tailnetRepaired is the ranges a repair reports having put back, and tailnetRepairErr
	// what it reports instead.
	tailnetRepaired  []netip.Prefix
	tailnetRepairErr error
}

func (h *commandedHost) Capabilities(ctx context.Context) (Capabilities, error) {
	return capabilities(ctx, BuildID, "")
}

func (h *commandedHost) OpenTUN(_ context.Context, name string) (tun.Device, string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.dev == nil {
		return nil, "", errors.New("this stand-in creates no interfaces")
	}
	if h.name == "" {
		h.name = name
	}
	return h.dev, h.name, nil
}

func (h *commandedHost) Retain(dev tun.Device) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.kept = dev
}

func (h *commandedHost) RouterUp(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.brought++
	return nil
}

func (h *commandedHost) SetRoutes(_ context.Context, cfg *router.Config) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.routerCfg, h.routerSeen = cfg, true
	return nil
}

func (h *commandedHost) SetHostRoutes(_ context.Context, r Routes) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hostRoutes = r
	return nil
}

func (h *commandedHost) ScopeHostDefault(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.scopedHost++
	return h.hostScopeErr
}

func (h *commandedHost) UnscopeHostDefault(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.unscopedHost++
	return h.hostScopeErr
}

func (h *commandedHost) SetDNS(_ context.Context, cfg dns.OSConfig) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.interfaceDNS, h.interfaceSet = cfg, true
	return nil
}

func (h *commandedHost) BaseDNS(context.Context) (dns.OSConfig, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.baseErr != nil {
		return dns.OSConfig{}, h.baseErr
	}
	return h.base, nil
}

func (h *commandedHost) SplitDNS(context.Context) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.split, nil
}

func (h *commandedHost) OpenResolverPacket(_ context.Context, want netip.AddrPort) (net.PacketConn, error) {
	h.mu.Lock()
	h.wantResolver = want
	open := h.packet
	h.mu.Unlock()
	if open == nil {
		return nil, errors.New("this stand-in binds no sockets")
	}
	return open()
}

func (h *commandedHost) OpenResolverStream(_ context.Context, want netip.AddrPort) (net.Listener, error) {
	h.mu.Lock()
	h.wantResolver = want
	open := h.stream
	h.mu.Unlock()
	if open == nil {
		return nil, errors.New("this stand-in binds no sockets")
	}
	return open()
}

func (h *commandedHost) SetSystemDNS(_ context.Context, resolvers []netip.Addr) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.systemDNS, h.systemDNSSet = resolvers, true
	return nil
}

func (h *commandedHost) BaseSystemDNS(context.Context) (sysdns.Base, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.systemBase, nil
}

func (h *commandedHost) StartOpenVPN(_ context.Context, run OpenVPNRun) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.started = append(h.started, run)
	return nil
}

func (h *commandedHost) StopOpenVPN(_ context.Context, id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopped = append(h.stopped, id)
	return nil
}

func (h *commandedHost) ScopeOpenVPN(_ context.Context, scope OpenVPNScope) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.scopedVPN = append(h.scopedVPN, scope)
	return nil
}

func (h *commandedHost) UnscopeOpenVPN(_ context.Context, id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.unscopedVPN = append(h.unscopedVPN, id)
	return nil
}

func (h *commandedHost) RepairTailnetRoutes(_ context.Context, iface string) ([]netip.Prefix, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.repairedTailnet = append(h.repairedTailnet, iface)
	return h.tailnetRepaired, h.tailnetRepairErr
}

func (h *commandedHost) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	return nil
}

// servedByHost runs a helper commanding the given stand-in until the test ends, with
// everything the suite sends approved.
func servedByHost(t *testing.T, host commanded) string {
	t.Helper()
	return servedByHostUnder(t, host, approvingEverything(t))
}

// servedByHostUnder is servedByHost held to the approvals policy gives.
func servedByHostUnder(t *testing.T, host commanded, policy grantPolicy) string {
	t.Helper()
	ownedByThisUser(t)
	path := shortSocketPath(t)
	ln, err := ListenHelper(path)
	if err != nil {
		t.Fatalf("listen on the helper socket: %v", err)
	}
	return served(t, ln, func(ctx context.Context) error {
		return serveWith(ctx, ln, newSessionGate(quickHandover), func(openvpnAddressCheck) commanded { return host }, policy, func(string, ...any) {})
	})
}

// dialTo opens a session on the helper and closes it when the test ends.
func dialTo(t *testing.T, ctx context.Context, path string) *Client {
	t.Helper()
	client, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("dial the helper: %v", err)
	}
	t.Cleanup(func() { closeIfOpen(t, client) })
	return client
}

// testContext bounds every round trip in one test, so a seam that stops answering fails with
// the case's own message rather than by running the package's clock out.
func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// The engine's configuration, this app's own addressing, the resolver settings, the machine's
// DNS and every OpenVPN request are what the calls are. Each is carried as JSON to a process
// holding root, which acts on what arrives rather than on what was sent.
func TestEveryOperationReachesThePrivilegedSideCarryingWhatItWasGiven(t *testing.T) {
	host := &commandedHost{}
	client := dialTo(t, testContext(t), servedByHost(t, host))
	ctx := testContext(t)

	engine := &router.Config{
		LocalAddrs:  []netip.Prefix{netip.MustParsePrefix("100.64.0.7/32")},
		Routes:      []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		LocalRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")},
		NewMTU:      1280,
	}
	ours := Routes{
		LocalAddrs: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")},
		Routes:     []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		MTU:        1380,
	}
	resolvers := dns.OSConfig{
		Nameservers:   []netip.Addr{netip.MustParseAddr("100.100.100.100")},
		SearchDomains: []dnsname.FQDN{"example.ts.net."},
		MatchDomains:  []dnsname.FQDN{"corp.example.com."},
	}
	machine := []netip.Addr{netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("::1")}
	run := workingRun(t)
	scope := OpenVPNScope{ID: "tn_a1b2c3", Interface: "utun9"}

	for _, tc := range []struct {
		what  string
		call  func() error
		check func() string
	}{
		{
			what: "bringing the interface up",
			call: func() error { return client.RouterUp(ctx) },
			check: func() string {
				if host.brought != 1 {
					return "the interface was brought up " + strconv.Itoa(host.brought) + " times, want once"
				}
				return ""
			},
		},
		{
			what: "the engine's own configuration",
			call: func() error { return client.SetRoutes(ctx, engine) },
			check: func() string {
				if !host.routerSeen || host.routerCfg == nil {
					return "the privileged side was given no configuration at all"
				}
				if !slices.Equal(host.routerCfg.Routes, engine.Routes) {
					return "the ranges arrived as " + prefixes(host.routerCfg.Routes) + ", want " + prefixes(engine.Routes)
				}
				if !slices.Equal(host.routerCfg.LocalAddrs, engine.LocalAddrs) {
					return "the interface's own addresses arrived as " + prefixes(host.routerCfg.LocalAddrs)
				}
				if host.routerCfg.NewMTU != engine.NewMTU {
					return "the packet size arrived as " + strconv.Itoa(host.routerCfg.NewMTU)
				}
				return ""
			},
		},
		{
			what: "a configuration that removes everything",
			call: func() error { return client.SetRoutes(ctx, nil) },
			check: func() string {
				if host.routerCfg != nil {
					return "a teardown arrived as a configuration to install"
				}
				return ""
			},
		},
		{
			what: "this app's own addressing",
			call: func() error { return client.SetHostRoutes(ctx, ours) },
			check: func() string {
				if !slices.Equal(host.hostRoutes.Routes, ours.Routes) {
					return "the ranges arrived as " + prefixes(host.hostRoutes.Routes)
				}
				if host.hostRoutes.MTU != ours.MTU {
					return "the packet size arrived as " + strconv.Itoa(host.hostRoutes.MTU)
				}
				return ""
			},
		},
		{
			what: "keeping this machine's own way out reachable",
			call: func() error { return client.ScopeHostDefault(ctx) },
			check: func() string {
				if host.scopedHost != 1 {
					return "this machine's way out was copied " + strconv.Itoa(host.scopedHost) + " times, want once"
				}
				return ""
			},
		},
		{
			what: "taking those copies back",
			call: func() error { return client.UnscopeHostDefault(ctx) },
			check: func() string {
				if host.unscopedHost != 1 {
					return "the copies were taken back " + strconv.Itoa(host.unscopedHost) + " times, want once"
				}
				return ""
			},
		},
		{
			what: "the interface's resolver settings",
			call: func() error { return client.SetDNS(ctx, resolvers) },
			check: func() string {
				if !host.interfaceSet {
					return "the privileged side was never given a resolver configuration"
				}
				if !slices.Equal(host.interfaceDNS.Nameservers, resolvers.Nameservers) {
					return "the resolvers arrived as " + addrs(host.interfaceDNS.Nameservers)
				}
				if !slices.Equal(host.interfaceDNS.SearchDomains, resolvers.SearchDomains) {
					return "the search domains did not arrive as they were given"
				}
				if !slices.Equal(host.interfaceDNS.MatchDomains, resolvers.MatchDomains) {
					return "the domains resolved through the tailnet did not arrive as they were given"
				}
				return ""
			},
		},
		{
			what: "this machine's own resolvers",
			call: func() error { return client.SetSystemDNS(ctx, machine) },
			check: func() string {
				if !slices.Equal(host.systemDNS, machine) {
					return "this machine was pointed at " + addrs(host.systemDNS) + ", want " + addrs(machine)
				}
				return ""
			},
		},
		{
			what: "putting this machine's resolvers back",
			call: func() error { return client.SetSystemDNS(ctx, nil) },
			check: func() string {
				if len(host.systemDNS) != 0 {
					return "a restore arrived as " + addrs(host.systemDNS) + ", which is a setting to install"
				}
				return ""
			},
		},
		{
			what: "running a connection",
			call: func() error { return client.StartOpenVPN(ctx, run) },
			check: func() string {
				if len(host.started) != 1 {
					return "the privileged side was asked to run " + strconv.Itoa(len(host.started)) + " connections, want one"
				}
				got := host.started[0]
				if got.ID != run.ID || got.Remote != run.Remote || got.Proto != run.Proto {
					return "the connection arrived as " + got.ID + " to " + got.Remote + " over " + got.Proto
				}
				if got.Key != run.Key || got.CA != run.CA {
					return "the key material did not arrive as it was given"
				}
				if !slices.Equal(got.Routes, run.Routes) {
					return "the networks the connection carries arrived as " + prefixes(got.Routes)
				}
				return ""
			},
		},
		{
			what: "giving a connection's interface a route of its own",
			call: func() error { return client.ScopeOpenVPN(ctx, scope) },
			check: func() string {
				if len(host.scopedVPN) != 1 || host.scopedVPN[0] != scope {
					return "the request to route an interface did not arrive as it was given"
				}
				return ""
			},
		},
		{
			what: "taking that route back",
			call: func() error { return client.UnscopeOpenVPN(ctx, scope.ID) },
			check: func() string {
				if !slices.Equal(host.unscopedVPN, []string{scope.ID}) {
					return "the route was taken back from " + strings.Join(host.unscopedVPN, ", ")
				}
				return ""
			},
		},
		{
			what: "putting the route to the tailnet back",
			call: func() error {
				_, err := client.RepairTailnetRoutes(ctx, "utun5")
				return err
			},
			check: func() string {
				if !slices.Equal(host.repairedTailnet, []string{"utun5"}) {
					return "the repair was asked for on " + strings.Join(host.repairedTailnet, ", ") + `, want "utun5"`
				}
				return ""
			},
		},
		{
			what: "stopping a connection",
			call: func() error { return client.StopOpenVPN(ctx, scope.ID) },
			check: func() string {
				if !slices.Equal(host.stopped, []string{scope.ID}) {
					return "the connections stopped were " + strings.Join(host.stopped, ", ")
				}
				return ""
			},
		},
	} {
		t.Run(tc.what, func(t *testing.T) {
			if err := tc.call(); err != nil {
				t.Fatalf("%s: %v", tc.what, err)
			}
			host.mu.Lock()
			defer host.mu.Unlock()
			if complaint := tc.check(); complaint != "" {
				t.Error(complaint)
			}
		})
	}
}

// The three operations that report on the machine are read through the same socket, and the
// caller acts on what they say: a machine that cannot split its resolution, or a base
// configuration that arrived short, is a resolver pointed at the wrong place.
func TestWhatThePrivilegedSideReportsReachesTheCaller(t *testing.T) {
	host := &commandedHost{
		base: dns.OSConfig{
			Nameservers:   []netip.Addr{netip.MustParseAddr("192.168.1.1")},
			SearchDomains: []dnsname.FQDN{"lan."},
		},
		split: true,
		systemBase: sysdns.Base{
			Nameservers:   []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("1.1.1.1")},
			SearchDomains: []string{"lan"},
		},
	}
	client := dialTo(t, testContext(t), servedByHost(t, host))
	ctx := testContext(t)

	base, err := client.BaseDNS(ctx)
	if err != nil {
		t.Fatalf("ask what this machine resolves names with: %v", err)
	}
	if !slices.Equal(base.Nameservers, host.base.Nameservers) {
		t.Errorf("the base resolvers arrived as %v, want %v", base.Nameservers, host.base.Nameservers)
	}
	if !slices.Equal(base.SearchDomains, host.base.SearchDomains) {
		t.Errorf("the base search domains arrived as %v, want %v", base.SearchDomains, host.base.SearchDomains)
	}

	split, err := client.SplitDNS(ctx)
	if err != nil {
		t.Fatalf("ask whether this machine can split its resolution: %v", err)
	}
	if !split {
		t.Error("a machine that can resolve one domain through the tailnet was reported as one that cannot")
	}

	system, err := client.BaseSystemDNS(ctx)
	if err != nil {
		t.Fatalf("ask what this machine resolves names with underneath app-tail: %v", err)
	}
	if !slices.Equal(system.Nameservers, host.systemBase.Nameservers) {
		t.Errorf("this machine's own resolvers arrived as %v, want %v", system.Nameservers, host.systemBase.Nameservers)
	}
	if !slices.Equal(system.SearchDomains, host.systemBase.SearchDomains) {
		t.Errorf("this machine's own search domains arrived as %v, want %v", system.SearchDomains, host.systemBase.SearchDomains)
	}
}

// The ranges a repair put back come home over the socket, and they are the only record that it
// happened: they are what the agent logs, so a repair that reported none would leave a machine
// silently mended and one that reported ranges it never installed would say a tailnet is
// reachable while it is not.
func TestTheRangesARepairPutBackReachTheCaller(t *testing.T) {
	put := []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
	}
	host := &commandedHost{tailnetRepaired: put}
	client := dialTo(t, testContext(t), servedByHost(t, host))

	repaired, err := client.RepairTailnetRoutes(testContext(t), "utun5")
	if err != nil {
		t.Fatalf("put the route to the tailnet back: %v", err)
	}
	if !slices.Equal(repaired, put) {
		t.Errorf("the ranges arrived as %v, want %v", repaired, put)
	}
}

// A repair the privileged side refused arrives as a failure rather than as an empty list, which
// is the difference between the agent reporting a tailnet it could not mend and reporting one it
// mended by doing nothing.
func TestARefusedRepairArrivesAsAFailure(t *testing.T) {
	host := &commandedHost{tailnetRepairErr: errors.New("utun5 is not carrying a tailnet on this machine")}
	client := dialTo(t, testContext(t), servedByHost(t, host))

	repaired, err := client.RepairTailnetRoutes(testContext(t), "utun5")
	if err == nil {
		t.Fatalf("a refused repair reported success, installing %v", repaired)
	}
	if !strings.Contains(err.Error(), "not carrying a tailnet") {
		t.Errorf("the refusal arrived as %q, which does not say what was refused", err)
	}
	if len(repaired) != 0 {
		t.Errorf("a refused repair reported %v as installed", repaired)
	}
}

// Two answers are documented rather than failures, and the caller acts on each differently
// from a failure: it takes over resolution entirely, and it carries traffic while saying the
// machine will not scope a route. Both cross the socket as sentences, so the sentinel has to
// be rebuilt on this side or both become "something went wrong".
func TestADocumentedAnswerArrivesAsThatRatherThanAsAFailure(t *testing.T) {
	host := &commandedHost{
		baseErr:      dns.ErrGetBaseConfigNotSupported,
		hostScopeErr: ErrScopedRoutesUnsupported,
	}
	client := dialTo(t, testContext(t), servedByHost(t, host))
	ctx := testContext(t)

	if _, err := client.BaseDNS(ctx); !errors.Is(err, dns.ErrGetBaseConfigNotSupported) {
		t.Errorf("a machine that will not say what it resolves with reported %q, which no caller can recognise", err)
	}

	err := client.ScopeHostDefault(ctx)
	if !errors.Is(err, ErrScopedRoutesUnsupported) {
		t.Errorf("a machine that cannot scope a route reported %q, which no caller can recognise", err)
	}
	// The helper's own wording survives the rebuild: it is the only side that knows why.
	if err != nil && !strings.Contains(err.Error(), ErrScopedRoutesUnsupported.Error()) {
		t.Errorf("the sentinel replaced the helper's reason, which is %q", err)
	}
	if err := client.UnscopeHostDefault(ctx); !errors.Is(err, ErrScopedRoutesUnsupported) {
		t.Errorf("taking the copies back on such a machine reported %q, which no caller can recognise", err)
	}
}

// The resolver socket is the other thing the helper hands out: a socket bound to a port this
// process could not have bound. What proves it crossed is not the reply but the socket
// working -- a descriptor that arrived closed, or belonging to something else, answers every
// query on this machine with silence.
func TestTheResolverSocketIsHandedOverOpen(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind a socket for the helper to hand over: %v", err)
	}
	defer closeQuietly(packet)
	stream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind a listener for the helper to hand over: %v", err)
	}
	defer stream.Close()

	host := &commandedHost{
		packet: func() (net.PacketConn, error) { return packet, nil },
		stream: func() (net.Listener, error) { return stream, nil },
	}
	client := dialTo(t, testContext(t), servedByHost(t, host))
	ctx := testContext(t)

	want := netip.MustParseAddrPort("127.0.0.1:0")
	pc, err := client.OpenResolverPacket(ctx, want)
	if err != nil {
		t.Fatalf("take over the resolver's datagram socket: %v", err)
	}
	defer closeQuietly(pc)
	host.mu.Lock()
	asked := host.wantResolver
	host.mu.Unlock()
	if asked != want {
		t.Errorf("the helper was asked to bind %v, want %v", asked, want)
	}

	peer, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("send to the socket that was handed over: %v", err)
	}
	defer peer.Close()
	if _, err := peer.Write([]byte("query")); err != nil {
		t.Fatalf("write to the socket that was handed over: %v", err)
	}
	if err := pc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set a deadline on the socket that was handed over: %v", err)
	}
	buf := make([]byte, 16)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read from the socket that was handed over: %v", err)
	}
	if got := string(buf[:n]); got != "query" {
		t.Errorf("the socket carried %q, so it is not the one the helper bound", got)
	}

	ln, err := client.OpenResolverStream(ctx, want)
	if err != nil {
		t.Fatalf("take over the resolver's stream socket: %v", err)
	}
	defer ln.Close()
	dialed := make(chan error, 1)
	go func() {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			conn.Close()
		}
		dialed <- err
	}()
	accepted, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept on the listener that was handed over: %v", err)
	}
	accepted.Close()
	if err := <-dialed; err != nil {
		t.Fatalf("connect to the listener that was handed over: %v", err)
	}
}

// noDescriptor is a socket the helper cannot hand over, which is what a platform whose
// listener is not an OS socket produces.
// It is closed on the helper's own goroutine and read on the test's, so the record of it is
// one both can reach.
type noDescriptor struct {
	net.PacketConn
	closed atomic.Bool
}

func (n *noDescriptor) Close() error {
	n.closed.Store(true)
	return n.PacketConn.Close()
}

// A socket that cannot be handed over has to be closed on the privileged side: the caller was
// given nothing to close it with, and one left bound on port 53 with nothing reading from it
// answers every query on this machine with silence.
func TestAResolverSocketThatCannotBeHandedOverIsClosed(t *testing.T) {
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind a socket: %v", err)
	}
	opaque := &noDescriptor{PacketConn: inner}

	host := &commandedHost{packet: func() (net.PacketConn, error) { return opaque, nil }}
	client := dialTo(t, testContext(t), servedByHost(t, host))

	_, err = client.OpenResolverPacket(testContext(t), netip.AddrPort{})
	if err == nil {
		t.Fatal("a socket with no descriptor was reported as handed over")
	}
	if !strings.Contains(err.Error(), "no descriptor to hand over") {
		t.Errorf("the refusal said %q, which does not say what could not be handed over", err)
	}
	if !opaque.closed.Load() {
		t.Error("the socket that could not be handed over was left bound with nothing reading from it")
	}
}

// The kind and the address are the caller's, and the caller is unprivileged. Both are checked
// where the message arrives, because a check that runs only before it is sent is a check on
// the well-behaved.
func TestAResolverSocketTheHelperCannotBindIsRefused(t *testing.T) {
	host := &commandedHost{}
	path := servedByHost(t, host)
	client, done := rawSession(t, path)
	defer done()
	ctx := context.Background()

	_, _, err := client.call(ctx, request{Op: opOpenResolver, Proto: "sctp"}, true)
	if err == nil {
		t.Fatal("the helper bound a socket of a kind it does not have")
	}
	if !strings.Contains(err.Error(), "sctp") {
		t.Errorf("the refusal said %q, which does not name what was asked for", err)
	}

	_, _, err = client.call(ctx, request{Op: opOpenResolver, Proto: protoUDP, Listen: "the resolver"}, true)
	if err == nil {
		t.Fatal("the helper was sent an address that is not one")
	}
	if !strings.Contains(err.Error(), "the resolver") {
		t.Errorf("the refusal said %q, which does not name what could not be read as an address", err)
	}

	// A refused request is a caller's mistake, not a reason to drop a connection whose loss
	// tears down the machine's configuration.
	if _, err := client.Capabilities(ctx); err != nil {
		t.Fatalf("the session did not survive a refused request: %v", err)
	}
}

// The interface arrives as an open descriptor, and this side owns it from that moment. The
// helper keeps a reference of its own because the interface goes away only when both are
// dropped, and its teardown has to be able to take it back from an agent that stopped
// answering.
func TestTheInterfaceCrossesTheSocketAndTheHelperKeepsItsOwnReference(t *testing.T) {
	held, sent, err := os.Pipe()
	if err != nil {
		t.Fatalf("make a descriptor to hand over: %v", err)
	}
	defer held.Close()
	dev := &countingDevice{file: sent}

	host := &commandedHost{dev: dev, name: "utun7"}
	client := dialTo(t, testContext(t), servedByHost(t, host))

	// A pipe is not an interface, so this side refuses it -- which is the only outcome
	// reachable without the rights to create a real one, and it is reached after the
	// descriptor has already crossed.
	_, _, err = client.OpenTUN(testContext(t), "utun7")
	if err == nil {
		t.Fatal("a pipe was taken over as a network interface")
	}
	if !strings.Contains(err.Error(), "take over the interface") {
		t.Errorf("the failure said %q, which does not name the step that could not be completed", err)
	}
	// The helper keeps its reference after the descriptor is on its way, so the agent can see
	// the failure first. A session answers one request at a time, so the reply to the next one
	// is what says the helper has finished with this one.
	if _, err := client.SplitDNS(testContext(t)); err != nil {
		t.Fatalf("the session did not answer after the hand-over: %v", err)
	}

	host.mu.Lock()
	defer host.mu.Unlock()
	if host.kept != dev {
		t.Error("the helper let go of the interface it handed over, so its teardown has nothing to take back")
	}
	if dev.closes != 0 {
		t.Errorf("the interface was closed %d times on the helper's side after being handed over", dev.closes)
	}
}

// An answer that carries none of what was asked for is what a helper that half-answered
// sends. Read as a zero value it would be a machine reporting no resolvers and nothing
// wrong, which is the shape that gets acted on.
func TestAnAnswerMissingWhatWasAskedForIsAFailure(t *testing.T) {
	for _, tc := range []struct {
		what string
		ask  func(*Client) error
		says string
	}{
		{
			what: "what this machine can do",
			ask: func(c *Client) error {
				_, err := c.Capabilities(context.Background())
				return err
			},
			says: "without saying what it can do",
		},
		{
			what: "what this machine resolves names with",
			ask: func(c *Client) error {
				_, err := c.BaseSystemDNS(context.Background())
				return err
			},
			says: "without saying what this machine resolves names with",
		},
		{
			what: "an interface with no descriptor beside it",
			ask: func(c *Client) error {
				_, _, err := c.OpenTUN(context.Background(), "utun7")
				return err
			},
			says: "carried no interface descriptor",
		},
	} {
		t.Run(tc.what, func(t *testing.T) {
			path, _ := standInHelper(t, response{Interface: "utun7"})
			conn, err := net.Dial("unix", path)
			if err != nil {
				t.Fatalf("connect to the stand-in helper: %v", err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("set a deadline: %v", err)
			}

			err = tc.ask(&Client{conn: conn, r: bufio.NewReader(conn)})
			if err == nil {
				t.Fatalf("an answer carrying no %s was accepted", tc.what)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("the failure said %q, want the reason %q", err, tc.says)
			}
		})
	}
}

// A connection identifier is a directory name and a socket name on the privileged side, so
// one that is a path is refused before it is sent as well as when it arrives. The caller's
// check is the one that keeps a mistake out of the round trip; this pins that it is there.
func TestAnIdentifierThatIsNotOneNeverReachesTheHelper(t *testing.T) {
	host := &commandedHost{}
	client := dialTo(t, testContext(t), servedByHost(t, host))
	ctx := testContext(t)

	for _, id := range []string{"../../etc/openvpn", "tn a1b2c3", ""} {
		if err := client.StopOpenVPN(ctx, id); err == nil {
			t.Errorf("%q was sent as a connection to stop", id)
		}
		if err := client.UnscopeOpenVPN(ctx, id); err == nil {
			t.Errorf("%q was sent as a connection to take a route back from", id)
		}
	}

	host.mu.Lock()
	defer host.mu.Unlock()
	if len(host.stopped) != 0 || len(host.unscopedVPN) != 0 {
		t.Errorf("the privileged side was asked about %v and %v, want nothing", host.stopped, host.unscopedVPN)
	}
}

// The machine's resolver is claimed on a connection of its own, so that rebuilding the node --
// every mode switch, every sign-out -- does not drop this machine's DNS for as long as the
// rebuild takes. What proves it is the same claim the node's own session makes is that it
// arrives at the privileged side through the same socket and is acted on there.
func TestTheResolverIsClaimedOnItsOwnConnection(t *testing.T) {
	if Privileged() {
		t.Skip("this process holds the rights already, so the resolver is claimed in-process rather than over the socket")
	}
	host := &commandedHost{}
	path := servedByHost(t, host)
	ctx := testContext(t)

	session, err := OpenSystemResolver(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatalf("claim this machine's name resolution: %v", err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			t.Errorf("release the resolver session: %v", err)
		}
	}()

	want := []netip.Addr{netip.MustParseAddr("127.0.0.153")}
	if err := session.SetSystemDNS(ctx, want); err != nil {
		t.Fatalf("point this machine at app-tail's resolver: %v", err)
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if !slices.Equal(host.systemDNS, want) {
		t.Errorf("this machine was pointed at %v, want %v", host.systemDNS, want)
	}
}

// prefixes and addrs keep the complaints above readable without pulling formatting into the
// assertions themselves.
func prefixes(list []netip.Prefix) string {
	parts := make([]string, 0, len(list))
	for _, p := range list {
		parts = append(parts, p.String())
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func addrs(list []netip.Addr) string {
	parts := make([]string, 0, len(list))
	for _, a := range list {
		parts = append(parts, a.String())
	}
	return "[" + strings.Join(parts, " ") + "]"
}
