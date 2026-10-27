// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"

	"tailscale.com/net/dns"
	"tailscale.com/util/dnsname"

	"github.com/sellitus/app-tail/internal/sysdns"
)

// The one operation that would otherwise be "redirect this machine's name resolution
// anywhere". Loopback bounds the worst an unprivileged caller gets out of a process holding
// root to pointing the machine at another port on its own loopback -- which it could already
// arrange by binding one. Widening this is the difference between a feature and a hole.
func TestTheHelperRefusesToPointThisMachineAtAnAddressThatIsNotLoopback(t *testing.T) {
	refused := []struct {
		name string
		addr netip.Addr
	}{
		{"a resolver on the local network", netip.MustParseAddr("192.168.6.1")},
		{"one on the internet", netip.MustParseAddr("8.8.8.8")},
		{"a tailnet address", netip.MustParseAddr("100.100.100.100")},
		{"the unspecified address", netip.MustParseAddr("0.0.0.0")},
		{"an IPv6 address off this machine", netip.MustParseAddr("2001:4860:4860::8888")},
		{"an address that is not one", netip.Addr{}},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			err := checkSystemResolvers([]netip.Addr{tt.addr})
			if err == nil {
				t.Fatalf("the helper accepted %v as a resolver to point this machine at", tt.addr)
			}
		})
	}

	// A loopback address is the whole of what it does accept, over both families.
	allowed := []netip.Addr{
		netip.MustParseAddr("127.0.0.153"),
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("::1"),
	}
	if err := checkSystemResolvers(allowed); err != nil {
		t.Errorf("the helper refused loopback resolvers %v: %v", allowed, err)
	}
	// Empty is the restore, not a machine pointed at nothing.
	if err := checkSystemResolvers(nil); err != nil {
		t.Errorf("the helper refused the empty list, which is what asks it to restore: %v", err)
	}
}

// The other half of the same bound. Without the port rule, "bind a loopback socket" reads as
// "bind any port under 1024 on loopback", and an unprivileged caller could take 88, 443 or
// 631 through a process holding root and answer for whatever this machine sends there.
func TestTheHelperOnlyBindsDNSPortsOnLoopback(t *testing.T) {
	refused := []struct {
		name, addr string
	}{
		{"a privileged port that is not DNS", "127.0.0.1:443"},
		{"another one", "127.0.0.1:88"},
		{"port 53 off loopback", "0.0.0.0:53"},
		{"port 53 on a real address", "192.168.6.1:53"},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkResolverListen(netip.MustParseAddrPort(tt.addr)); err == nil {
				t.Fatalf("the helper agreed to listen on %s", tt.addr)
			}
		})
	}
	for _, addr := range []string{"127.0.0.153:53", "[::1]:53", "127.0.0.1:5353", "127.0.0.1:0"} {
		if err := checkResolverListen(netip.MustParseAddrPort(addr)); err != nil {
			t.Errorf("the helper refused to listen on %s: %v", addr, err)
		}
	}
	if err := checkResolverListen(netip.AddrPort{}); err == nil {
		t.Error("the helper agreed to listen on an address that is not one")
	}
}

// Both halves of the resolver socket land on one address. Split across two, the machine
// resolves short answers at one address and gets nothing for long ones at the other, which
// looks like a resolver that works until somebody asks for a name with many records.
func TestBothHalvesOfTheResolverSocketLandOnOneAddress(t *testing.T) {
	local := NewLocal(func(string, ...any) {})
	defer closeLocal(t, local)
	ctx := context.Background()

	// Port 0 on loopback needs no rights, and is where the two halves would come apart if
	// each walked the ladder on its own.
	want := netip.MustParseAddrPort("127.0.0.1:0")
	pc, err := local.OpenResolverPacket(ctx, want)
	if err != nil {
		t.Fatalf("bind the resolver's UDP half: %v", err)
	}
	defer pc.Close()
	ln, err := local.OpenResolverStream(ctx, want)
	if err != nil {
		t.Fatalf("bind the resolver's TCP half: %v", err)
	}
	defer ln.Close()

	if pc.LocalAddr().String() != ln.Addr().String() {
		t.Errorf("the resolver answers UDP on %s and TCP on %s", pc.LocalAddr(), ln.Addr())
	}

	// Each half is handed over once: asking again binds a new pair. The same socket handed
	// to a second caller would be two readers taking each other's queries off one descriptor.
	nextPC, err := local.OpenResolverPacket(ctx, want)
	if err != nil {
		t.Fatalf("bind a second resolver socket in the same session: %v", err)
	}
	defer nextPC.Close()
	nextLn, err := local.OpenResolverStream(ctx, want)
	if err != nil {
		t.Fatalf("bind the second socket's TCP half: %v", err)
	}
	defer nextLn.Close()

	if nextPC.LocalAddr().String() == pc.LocalAddr().String() {
		t.Error("the UDP half was handed over twice")
	}
	if nextLn.Addr().String() == ln.Addr().String() {
		t.Error("the TCP half was handed over twice")
	}
	if nextPC.LocalAddr().String() != nextLn.Addr().String() {
		t.Errorf("the second resolver answers UDP on %s and TCP on %s", nextPC.LocalAddr(), nextLn.Addr())
	}
}

// The agent moves this machine between two resolver addresses to empty every cache on it,
// so one session hands over a second socket. A caller that took a UDP half and asked for
// another before taking its TCP partner has moved on from that pair, and the partner left
// behind is closed: kept, it would hold the address with nothing reading from it.
func TestAHalfLeftBehindByTheNextRequestIsReleased(t *testing.T) {
	local := NewLocal(func(string, ...any) {})
	defer closeLocal(t, local)
	ctx := context.Background()
	want := netip.MustParseAddrPort("127.0.0.1:0")

	first, err := local.OpenResolverPacket(ctx, want)
	if err != nil {
		t.Fatalf("bind the first resolver socket: %v", err)
	}
	defer first.Close()
	second, err := local.OpenResolverPacket(ctx, want)
	if err != nil {
		t.Fatalf("a session that had handed over one UDP half refused to bind another: %v", err)
	}
	defer second.Close()

	ln, err := net.Listen("tcp", first.LocalAddr().String())
	if err != nil {
		t.Fatalf("the TCP half nobody took is still held after the next pair was bound: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Errorf("close the listener: %v", err)
	}
}

// A caller that asks for an address it may not have is refused rather than quietly given one
// of the fallbacks: it asked for something specific, and a resolver on an address the caller
// does not know about is one nothing will ever point the machine at.
func TestAnAddressTheHelperWillNotBindIsRefusedRatherThanSubstituted(t *testing.T) {
	local := NewLocal(func(string, ...any) {})
	defer closeLocal(t, local)

	_, err := local.OpenResolverPacket(context.Background(), netip.MustParseAddrPort("192.168.6.1:53"))
	if err == nil {
		t.Fatal("the helper bound a resolver socket on an address off this machine's loopback")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("the refusal was %q, which does not say what was wrong with the address", err)
	}
}

// A session that never pointed this machine anywhere must not put anything back on its way
// out: the record belongs to whichever session did, and clearing it from another would
// restore a machine that is currently using app-tail's resolver.
func TestASessionThatChangedNoResolverRestoresNothing(t *testing.T) {
	local := NewLocal(func(string, ...any) {})
	if local.systemDNSApplied {
		t.Fatal("a fresh session claims to have changed this machine's resolver")
	}
	if err := local.Close(); err != nil {
		t.Fatalf("close a session that changed nothing: %v", err)
	}
	// The manager is never built either, so the teardown reads no root-owned file and
	// shells out to nothing.
	if local.sysdns != nil {
		t.Error("a session that changed no resolver built one to change it with")
	}
}

// The fallbacks are what the helper picks from when the caller's address is taken. They are
// loopback and they are port 53, which is the same bound the caller's own address is held to
// -- a fallback that was not would be the bound with a door in it.
func TestEveryResolverFallbackIsOneTheHelperWouldAccept(t *testing.T) {
	if len(resolverFallbacks) == 0 {
		t.Fatal("there are no fallbacks, so a machine with port 53 taken has nowhere to listen")
	}
	seen := map[netip.AddrPort]bool{}
	for _, addr := range resolverFallbacks {
		if err := checkResolverListen(addr); err != nil {
			t.Errorf("the fallback %s is one the helper would refuse from a caller: %v", addr, err)
		}
		if addr.Addr() == netip.MustParseAddr("127.0.0.1") {
			t.Errorf("127.0.0.1 is a fallback, which displaces whatever else on this machine already answers there")
		}
		if seen[addr] {
			t.Errorf("%s is listed twice, so the ladder is shorter than it looks", addr)
		}
		seen[addr] = true
	}
}

// The caller's address is tried first and never tried again further down: a ladder that
// repeated it would spend a second bind failing the same way.
func TestTheCallersAddressIsTriedFirstAndOnlyOnce(t *testing.T) {
	want := resolverFallbacks[1]
	order := resolverCandidates(want)
	if order[0] != want {
		t.Errorf("the ladder starts at %s, want the caller's own %s", order[0], want)
	}
	count := 0
	for _, addr := range order {
		if addr == want {
			count++
		}
	}
	if count != 1 {
		t.Errorf("the caller's address appears %d times in the ladder", count)
	}
	if len(resolverCandidates(netip.AddrPort{})) != len(resolverFallbacks) {
		t.Error("a caller with no preference got a ladder of a different length than the fallbacks")
	}
}

// A machine with something else on every address app-tail would use has to say so, and say
// it as a busy port rather than as a broken feature. A permission failure is neither: it
// means this side does not hold the rights, which is what the helper exists to hold.
func TestABusyResolverPortIsReportedAndAPermissionFailureIsNot(t *testing.T) {
	ctx := context.Background()
	busy := DetectResolverBusy(ctx)
	if busy == "" {
		return
	}
	// Port 53 needs rights this suite does not have, so anything reported here has to be a
	// real address-in-use rather than the refusal that comes from being unprivileged.
	if strings.Contains(strings.ToLower(busy), "permission denied") {
		t.Errorf("a permission failure was reported as a busy port: %q", busy)
	}
	if !strings.Contains(busy, "already in use") {
		t.Errorf("the report %q does not say what is wrong", busy)
	}
}

// An address this machine does not carry is the normal state of every address app-tail
// listens on, on macOS: it assigns 127.0.0.1 and refuses the rest of 127/8 until an alias
// exists. Reporting that as a busy port would tell a user something else holds an address
// nothing holds, and would make the feature unusable on every Mac.
func TestAnUnassignedAddressIsNotReportedAsABusyPort(t *testing.T) {
	if needsLoopbackAlias(syscall.EADDRINUSE) {
		t.Error("an address already in use was read as one this machine does not carry")
	}
	if !needsLoopbackAlias(&net.OpError{Op: "listen", Err: os.NewSyscallError("bind", errAddrNotAvail)}) {
		t.Error("a bind refused with EADDRNOTAVAIL was not read as an address this machine does not carry")
	}
}

// The ladder adds the address to this machine's loopback and tries once more, because that
// is the whole reason the first bind failed. Without it, every Mac reports the feature as
// unavailable while nothing is holding anything.
func TestAnUnassignedAddressIsAddedToTheLoopbackAndTriedAgain(t *testing.T) {
	ctx := context.Background()
	want := resolverFallbacks[0]
	var held []netip.Addr
	attempts := 0

	pc, ln, bound, err := bindResolverLadder(ctx, []netip.AddrPort{want},
		func(ctx context.Context, addr netip.AddrPort) (net.PacketConn, net.Listener, error) {
			attempts++
			if len(held) == 0 {
				return nil, nil, &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", errAddrNotAvail)}
			}
			return bindLoopbackPair(ctx)
		},
		func(_ context.Context, addr netip.Addr) error {
			held = append(held, addr)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("bindResolverLadder: %v", err)
	}
	defer closeQuietly(pc, ln)

	if !slices.Equal(held, []netip.Addr{want.Addr()}) {
		t.Errorf("the ladder added %v to this machine's loopback, want %s", held, want.Addr())
	}
	if attempts != 2 {
		t.Errorf("the address was tried %d times, want one failure and one retry", attempts)
	}
	if !bound.IsValid() {
		t.Error("the ladder reported no address for a socket it bound")
	}
}

// Once per candidate. A second refusal after the address was added is a fact about the
// address, and asking again would loop on a machine that will never let it bind.
func TestTheLadderAsksForOneAddressOnceAndMovesOn(t *testing.T) {
	unavailable := &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", errAddrNotAvail)}
	var held []netip.Addr
	attempts := map[netip.AddrPort]int{}

	_, _, _, err := bindResolverLadder(context.Background(), resolverCandidates(netip.AddrPort{}),
		func(_ context.Context, addr netip.AddrPort) (net.PacketConn, net.Listener, error) {
			attempts[addr]++
			return nil, nil, unavailable
		},
		func(_ context.Context, addr netip.Addr) error {
			held = append(held, addr)
			return nil
		},
	)
	if err == nil {
		t.Fatal("bindResolverLadder = nil error although every candidate refused")
	}
	for addr, count := range attempts {
		if count != 2 {
			t.Errorf("%s was tried %d times, want one failure and one retry", addr, count)
		}
	}
	if len(attempts) != len(resolverFallbacks) {
		t.Errorf("the ladder stopped after %d of %d candidates", len(attempts), len(resolverFallbacks))
	}
}

// A machine that refuses to carry the address is a machine this cannot listen on, and the
// reason it gave is the one worth reading -- so it travels with the bind failure rather
// than replacing it.
func TestAMachineThatWillNotCarryTheAddressReportsBothReasons(t *testing.T) {
	_, _, _, err := bindResolverLadder(context.Background(), []netip.AddrPort{resolverFallbacks[0]},
		func(context.Context, netip.AddrPort) (net.PacketConn, net.Listener, error) {
			return nil, nil, &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", errAddrNotAvail)}
		},
		func(context.Context, netip.Addr) error {
			return errors.New("ifconfig refused")
		},
	)
	if err == nil {
		t.Fatal("bindResolverLadder = nil error although the address could not be carried")
	}
	for _, want := range []string{"ifconfig refused", "bind"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure %q does not mention %q", err, want)
		}
	}
}

func TestParsingResolverAddressesRefusesOneThatIsNotAnAddress(t *testing.T) {
	if _, err := parseResolvers([]string{"127.0.0.153", "not-an-address"}); err == nil {
		t.Fatal("a list with one unreadable address was accepted, which points this machine somewhere shorter than asked")
	}
	got, err := parseResolvers([]string{"127.0.0.153", "::1"})
	if err != nil {
		t.Fatalf("parse a list of resolver addresses: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d addresses from two", len(got))
	}
	round := formatResolvers(got)
	if len(round) != 2 || round[0] != "127.0.0.153" || round[1] != "::1" {
		t.Errorf("the addresses came back as %v", round)
	}
}

func TestAnAbsentListenAddressIsNotAFailure(t *testing.T) {
	addr, err := requestedListen("")
	if err != nil {
		t.Fatalf("read an absent listen address: %v", err)
	}
	if addr.IsValid() {
		t.Errorf("an absent listen address read as %s", addr)
	}
	if _, err := requestedListen("127.0.0.153"); err == nil {
		t.Error("an address with no port was accepted as one to listen on")
	}
}

func closeLocal(t *testing.T, local *Local) {
	t.Helper()
	if err := local.Close(); err != nil {
		t.Errorf("close the session: %v", err)
	}
}

// The two gates are what let the machine's resolver stay put across a node restart. One gate
// for both would mean every mode switch, sign-out and rebuild dropping the connection that
// holds the override, and this machine's DNS reverting for as long as the restart takes.
func TestTheInterfaceAndTheResolverAreHeldSeparately(t *testing.T) {
	for _, op := range []string{opOpenTUN, opRouterUp, opSetRoutes, opSetDNS, opBaseDNS, opSplitDNS} {
		if got := needsSession(op); got != gateInterface {
			t.Errorf("%s belongs to the %q session, want the interface's", op, got)
		}
	}
	for _, op := range []string{opOpenResolver, opSetSystemDNS} {
		if got := needsSession(op); got != gateResolver {
			t.Errorf("%s belongs to the %q session, want the resolver's", op, got)
		}
	}
	// Reading changes nothing and costs the holder nothing, which is what lets the doctor
	// report on a machine whose agent holds both sessions.
	for _, op := range []string{opCapabilities, opBaseSystemDNS, "something-else"} {
		if got := needsSession(op); got != "" {
			t.Errorf("%s claims the %q session although it changes nothing", op, got)
		}
	}

	gate := newSessionGate(0)
	ctx := context.Background()
	if !gate.take(ctx, gateInterface) {
		t.Fatal("the interface session was refused to the first caller")
	}
	if !gate.take(ctx, gateResolver) {
		t.Error("holding the interface session withheld the resolver's, so a node restart would drop this machine's DNS")
	}
	if gate.take(ctx, gateInterface) {
		t.Error("the interface session was handed to two callers at once")
	}
	gate.release(gateInterface)
	if !gate.take(ctx, gateInterface) {
		t.Error("the interface session was not handed on after its holder released it")
	}
	if gate.take(ctx, "a-session-this-helper-does-not-have") {
		t.Error("a session nobody defined was handed out")
	}
}

// The interface's own resolvers are not bounded to loopback the way the machine's are: the
// tailnet legitimately hands out ordinary internet resolvers, and refusing them would break
// name resolution over the tailnet. What is bounded instead is the shape, because a domain
// here is written into a root-owned file on this machine -- as a line inside it on macOS, and
// as the name of the file itself.
func TestTheResolverConfigurationInstalledOnTheInterfaceIsChecked(t *testing.T) {
	tests := []struct {
		name string
		cfg  dns.OSConfig
		says string
	}{
		{
			name: "nothing at all",
			cfg:  dns.OSConfig{},
		},
		{
			name: "the shape the tailnet actually sends, internet resolvers included",
			cfg: dns.OSConfig{
				Nameservers:   []netip.Addr{netip.MustParseAddr("100.100.100.100"), netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []dnsname.FQDN{"tail0000.ts.net."},
				MatchDomains:  []dnsname.FQDN{"corp.example.com."},
			},
		},
		{
			name: "a resolver address that is not an address",
			cfg:  dns.OSConfig{Nameservers: []netip.Addr{{}}},
			says: "not an address",
		},
		{
			name: "the unspecified address, which names no resolver",
			cfg:  dns.OSConfig{Nameservers: []netip.Addr{netip.MustParseAddr("0.0.0.0")}},
			says: "names no resolver",
		},
		{
			name: "a multicast address, which no resolver answers on",
			cfg:  dns.OSConfig{Nameservers: []netip.Addr{netip.MustParseAddr("224.0.0.251")}},
			says: "multicast",
		},
		{
			name: "a search domain carrying a second directive on its own line",
			cfg:  dns.OSConfig{SearchDomains: []dnsname.FQDN{"a\nnameserver 6.6.6.6."}},
			says: "as its own line",
		},
		{
			name: "a match domain carrying a space, which ends the domain early",
			cfg:  dns.OSConfig{MatchDomains: []dnsname.FQDN{"corp.example.com nameserver 6.6.6.6."}},
			says: "as its own line",
		},
		{
			name: "a match domain carrying a slash, which decides the file it is written to",
			cfg:  dns.OSConfig{MatchDomains: []dnsname.FQDN{"etc/resolver/evil.example.com."}},
			says: "decides which file",
		},
		{
			name: "a label longer than a domain name allows",
			cfg:  dns.OSConfig{SearchDomains: []dnsname.FQDN{dnsname.FQDN(strings.Repeat("a", 64) + ".example.com.")}},
			says: "is not a domain name",
		},
		{
			name: "more resolvers than a machine has",
			cfg:  dns.OSConfig{Nameservers: slices.Repeat([]netip.Addr{netip.MustParseAddr("1.1.1.1")}, maxDNSEntries+1)},
			says: "more than this machine will be given",
		},
		{
			name: "more domains than a machine has, counted across both lists",
			cfg: dns.OSConfig{
				SearchDomains: slices.Repeat([]dnsname.FQDN{"one.example.com."}, maxDNSEntries),
				MatchDomains:  slices.Repeat([]dnsname.FQDN{"two.example.com."}, 1),
			},
			says: "more than this machine will be given",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkInterfaceDNS(tt.cfg)
			if tt.says == "" {
				if err != nil {
					t.Fatalf("checkInterfaceDNS() = %v, want it accepted", err)
				}
				return
			}
			if err == nil {
				t.Fatal("checkInterfaceDNS() accepted a resolver configuration a root process must not write out")
			}
			if !strings.Contains(err.Error(), tt.says) {
				t.Errorf("checkInterfaceDNS() said %q, which does not say %q", err, tt.says)
			}
		})
	}
}

// The check that bounds this operation has to run before anything is built to change the
// machine with, not inside whatever performs the change: the manager reads and rewrites the
// machine's network services, and one built for a request that was going to be refused is a
// root process reading them on behalf of a caller it just turned away.
func TestARefusedResolverNeverReachesTheMachine(t *testing.T) {
	local := NewLocal(func(string, ...any) {})
	defer closeLocal(t, local)

	err := local.SetSystemDNS(context.Background(), []netip.Addr{netip.MustParseAddr("8.8.8.8")})
	if err == nil {
		t.Fatal("this machine was pointed at a resolver off its own loopback")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("the refusal said %q, which does not say what was wrong with the address", err)
	}
	if err := local.SetSystemDNS(context.Background(), []netip.Addr{{}}); err == nil {
		t.Error("this machine was pointed at something that is not an address")
	}

	if local.sysdns != nil {
		t.Error("a refused request built the thing that changes this machine's resolver")
	}
	if local.systemDNSApplied {
		t.Error("a refused request left the session believing it had changed this machine's resolver")
	}
}

// Everything this session holds is released on the way out, and a call that arrives after that
// has to say so rather than build it all again: a socket bound by a torn-down session belongs
// to nobody, and a resolver setting applied by one would never be put back.
func TestASessionThatHasEndedChangesNothingMore(t *testing.T) {
	local := NewLocal(func(string, ...any) {})
	if err := local.Close(); err != nil {
		t.Fatalf("end the session: %v", err)
	}

	err := local.SetSystemDNS(context.Background(), []netip.Addr{netip.MustParseAddr("127.0.0.53")})
	if err == nil {
		t.Fatal("a session that had ended pointed this machine at a resolver")
	}
	if !strings.Contains(err.Error(), "torn down") {
		t.Errorf("the refusal said %q, which does not say the session is gone", err)
	}
	if _, err := local.OpenResolverPacket(context.Background(), netip.MustParseAddrPort("127.0.0.1:0")); err == nil {
		t.Error("a session that had ended bound a resolver socket")
	}
}

// Both halves are bound together and handed over one at a time, so the half nobody asked for is
// still this session's when it ends. Left behind it would hold port 53 with nothing reading from
// it, which answers every query on this machine with silence.
func TestTheHalfOfTheResolverSocketNobodyTookIsReleased(t *testing.T) {
	t.Run("the stream half, when only the datagram half was taken", func(t *testing.T) {
		local := NewLocal(func(string, ...any) {})
		pc, err := local.OpenResolverPacket(context.Background(), netip.MustParseAddrPort("127.0.0.1:0"))
		if err != nil {
			t.Fatalf("bind the resolver socket: %v", err)
		}
		defer closeQuietly(pc)

		addr := pc.LocalAddr().String()
		if err := local.Close(); err != nil {
			t.Fatalf("end the session: %v", err)
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("the stream half is still held after the session ended: %v", err)
		}
		if err := ln.Close(); err != nil {
			t.Errorf("close the listener: %v", err)
		}
	})

	t.Run("the datagram half, when only the stream half was taken", func(t *testing.T) {
		local := NewLocal(func(string, ...any) {})
		ln, err := local.OpenResolverStream(context.Background(), netip.MustParseAddrPort("127.0.0.1:0"))
		if err != nil {
			t.Fatalf("bind the resolver socket: %v", err)
		}
		defer closeQuietly(ln)

		addr := ln.Addr().String()
		if err := local.Close(); err != nil {
			t.Fatalf("end the session: %v", err)
		}
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			t.Fatalf("the datagram half is still held after the session ended: %v", err)
		}
		if err := pc.Close(); err != nil {
			t.Errorf("close the socket: %v", err)
		}
	})
}

// The helper's answer crosses the socket as a sentence and arrives as a plain error, so the
// type is gone by the time the agent reads it. Telling a partial restore from a failed one is
// what decides whether an ordinary quit exits non-zero, so the sentinel has to survive the
// crossing on macOS and Linux exactly as it does on Windows.
func TestAPartialRestoreIsStillTellableApartAfterCrossingTheHelperSocket(t *testing.T) {
	partial := &sysdns.PartialRestoreError{Services: []string{"Ethernet", "Wi-Fi"}}
	// What the client is handed: the helper's sentence, rebuilt from JSON with no type left.
	crossed := partialRestoreErr(errors.New(partial.Error()))

	if !PartialSystemDNSRestore(crossed) {
		t.Fatalf("a partial restore came back as %v, which every caller reads as a teardown that went wrong", crossed)
	}
	if !strings.Contains(crossed.Error(), "Ethernet") {
		t.Errorf("the answer says %q, want the helper's own list of the services still to put back", crossed)
	}
	if PartialSystemDNSRestore(partialRestoreErr(errors.New("the resolver settings could not be written"))) {
		t.Error("a restore that failed outright was read as a partial one, so a machine still pointed at app-tail would report a clean shutdown")
	}
	if partialRestoreErr(nil) != nil {
		t.Error("a restore that reached everything came back as an error")
	}
}

// bindLoopbackPair stands in for a bind that succeeds: a resolver socket pair on a port of
// the OS's choosing. The pair puts its TCP half on whatever port the UDP half was given, and
// with the rest of the suite binding ports beside this test that number is now and then held
// on TCP already, which is a fact about the machine rather than about the ladder under test.
func bindLoopbackPair(ctx context.Context) (net.PacketConn, net.Listener, error) {
	var err error
	for range 8 {
		var pc net.PacketConn
		var ln net.Listener
		pc, ln, err = bindResolverPair(ctx, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0))
		if err == nil {
			return pc, ln, nil
		}
	}
	return nil, nil, err
}
