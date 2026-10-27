// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/sysdns"
)

// fakeResolverSession stands in for the privileged side of the resolver boundary, which
// binds port 53 and rewrites every network service. It binds real loopback sockets so what
// happens to the one already open when the other half is refused can be observed.
type fakeResolverSession struct {
	streamErr error
	packet    net.PacketConn
	set       [][]netip.Addr
	closed    int
}

func (f *fakeResolverSession) OpenResolverPacket(_ context.Context, _ netip.AddrPort) (net.PacketConn, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f.packet = pc
	return pc, nil
}

func (f *fakeResolverSession) OpenResolverStream(_ context.Context, _ netip.AddrPort) (net.Listener, error) {
	if f.streamErr != nil {
		return nil, f.streamErr
	}
	return net.Listen("tcp", f.packet.LocalAddr().String())
}

func (f *fakeResolverSession) SetSystemDNS(_ context.Context, resolvers []netip.Addr) error {
	f.set = append(f.set, slices.Clone(resolvers))
	return nil
}

func (f *fakeResolverSession) BaseSystemDNS(context.Context) (sysdns.Base, error) {
	return sysdns.Base{Nameservers: []netip.Addr{netip.MustParseAddr("192.168.6.1")}, SearchDomains: []string{"lan"}}, nil
}

func (f *fakeResolverSession) Close() error {
	f.closed++
	return nil
}

// The two halves are one socket to the caller. When the second cannot be bound, the first
// goes with the failure: a UDP socket holding port 53 with nothing reading from it answers
// every query on this machine with silence, which is worse than the failure itself.
func TestTheHalfThatWasBoundGoesWithTheHalfThatWasRefused(t *testing.T) {
	session := &fakeResolverSession{streamErr: errors.New("port 53/tcp is taken")}
	rights := systemDNSRights{session: session}

	pc, ln, bound, err := rights.OpenResolver(context.Background(), netip.MustParseAddrPort("127.0.0.153:53"))

	if err == nil || !strings.Contains(err.Error(), "port 53/tcp is taken") {
		t.Fatalf("OpenResolver = %v, want the refusal of the stream half", err)
	}
	if pc != nil || ln != nil || bound.IsValid() {
		t.Errorf("OpenResolver handed back %v, %v, %v with the failure, want nothing", pc, ln, bound)
	}
	if session.packet == nil {
		t.Fatal("the packet half was never bound, so this is a different failure")
	}
	// Bindable again is what closed means: a socket still held would refuse the same address.
	again, err := net.ListenPacket("udp", session.packet.LocalAddr().String())
	if err != nil {
		t.Fatalf("the packet half is still held after the stream half was refused: %v", err)
	}
	again.Close()
}

// The address the machine is pointed at is the one the socket ended up on, read back from
// the socket: the privileged side walks its own list when the asked-for address is taken.
func TestTheBoundAddressIsReadBackFromTheSocketRatherThanAssumed(t *testing.T) {
	session := &fakeResolverSession{}
	rights := systemDNSRights{session: session}

	pc, ln, bound, err := rights.OpenResolver(context.Background(), netip.MustParseAddrPort("127.0.0.153:53"))
	if err != nil {
		t.Fatalf("OpenResolver: %v", err)
	}
	defer pc.Close()
	defer ln.Close()

	if want := netip.MustParseAddrPort(pc.LocalAddr().String()); bound != want {
		t.Errorf("bound = %s, want the address the socket really took, %s", bound, want)
	}
	if bound.Port() == 53 {
		t.Error("the fake bound port 53, so this proves nothing about reading the address back")
	}
}

// Restore is the empty list on the wire, and only the empty list: pointing a machine at no
// resolver is not something app-tail offers, so the boundary spells "put it back" that way.
func TestRestoreCrossesTheBoundaryAsAnEmptyList(t *testing.T) {
	session := &fakeResolverSession{}
	rights := systemDNSRights{session: session}
	ctx := context.Background()

	if err := rights.Apply(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.153")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := rights.Restore(ctx); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if err := rights.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if len(session.set) != 2 || len(session.set[0]) != 1 || len(session.set[1]) != 0 {
		t.Errorf("the machine was told %v, want the address and then the empty list", session.set)
	}
	if session.closed != 1 {
		t.Errorf("the session was closed %d times, want once", session.closed)
	}
	base, err := rights.Base(ctx)
	if err != nil {
		t.Fatalf("Base: %v", err)
	}
	if len(base.Nameservers) != 1 || base.Nameservers[0] != netip.MustParseAddr("192.168.6.1") || !slices.Equal(base.SearchDomains, []string{"lan"}) {
		t.Errorf("base = %+v, want what the machine reported carried across whole", base)
	}
}
