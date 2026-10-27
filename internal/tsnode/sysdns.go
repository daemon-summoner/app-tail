// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/hostnet"
)

// The machine-wide resolver's privilege boundary, in this package's own types.
//
// It is here for the same reason the node is: internal/hostnet is what holds -- or talks to
// what holds -- administrator rights, and the set of packages that may reach it is part of
// the design. So the app asks this package, which takes stdlib types and hands back stdlib
// types, and nothing about the boundary reaches any further.
//
// Nothing in this file is about the tailnet. The machine's resolver works with no tailnet at
// all: signed out, every module off, in either mode.

// SystemDNSRights is a held claim on how this machine resolves names.
//
// Closing it puts the machine back. On macOS and Linux that happens because the connection to
// the helper drops, which is the one signal delivered whether the agent exits cleanly, is
// killed, or dies with the machine; on Windows the elevated process restores before it
// returns.
type SystemDNSRights interface {
	// OpenResolver binds both halves of a DNS socket on a loopback address and hands them
	// back, along with the address they landed on -- which is not always the one asked for,
	// because something else on this machine may already hold it. Every call opens a new
	// socket, so one claim can answer on several addresses at once. The zero address asks
	// for whichever of the helper's own addresses is free.
	OpenResolver(ctx context.Context, want netip.AddrPort) (net.PacketConn, net.Listener, netip.AddrPort, error)
	// Apply points this machine's network services at the addresses, every one of which
	// must be on this machine's own loopback.
	Apply(ctx context.Context, resolvers []netip.Addr) error
	// Restore puts back what the machine resolved names with before Apply.
	Restore(ctx context.Context) error
	// Base reports what this machine resolves names with underneath app-tail, which is
	// where names the chosen resolver does not answer for go.
	Base(ctx context.Context) (BaseResolvers, error)
	// Close releases the claim, restoring the machine on the way out.
	Close() error
}

// PartialSystemDNSRestore reports a Restore that put this machine back everywhere it could
// reach and recorded the network services it could not. The caller acts on it differently
// from a failure: the machine is as restored as it can be until those services come back, and
// the run that ends on one has not gone wrong.
func PartialSystemDNSRestore(err error) bool {
	return hostnet.PartialSystemDNSRestore(err)
}

// BaseResolvers is what this machine's own networks told it to resolve names with: the
// router on a home network, the DHCP server in an office. app-tail's own addresses and any
// tailnet resolver are already filtered out, because forwarding to either is a query that
// comes back here.
type BaseResolvers struct {
	Nameservers   []netip.Addr
	SearchDomains []string
}

// OpenSystemDNSRights claims this machine's name resolution.
//
// It is a separate claim from the node's, held for as long as the machine-wide resolver is
// switched on. Sharing the node's would mean every mode switch, sign-out and rebuild dropping
// this machine's DNS for as long as the restart takes. observer, when set, hears whether each
// change the helper was asked for was refused for a missing approval.
func OpenSystemDNSRights(ctx context.Context, logf func(format string, args ...any), observer grants.Observer) (SystemDNSRights, error) {
	session, err := hostnet.OpenSystemResolver(ctx, hostnet.Options{Logf: logf, Grants: observer})
	if err != nil {
		return nil, err
	}
	return systemDNSRights{session: session}, nil
}

// systemDNSRights is the adapter. It holds no state of its own: everything it does is one
// call across the boundary, and the state that matters -- what this machine resolved names
// with before -- lives on the privileged side, where it survives this process.
type systemDNSRights struct {
	session hostnet.ResolverSession
}

func (r systemDNSRights) OpenResolver(ctx context.Context, want netip.AddrPort) (net.PacketConn, net.Listener, netip.AddrPort, error) {
	pc, err := r.session.OpenResolverPacket(ctx, want)
	if err != nil {
		return nil, nil, netip.AddrPort{}, err
	}
	ln, err := r.session.OpenResolverStream(ctx, want)
	if err != nil {
		// The half that was opened goes with the failure: a socket holding port 53 with
		// nothing reading from it answers every query on this machine with silence.
		return nil, nil, netip.AddrPort{}, closeAlso(err, pc.Close())
	}
	// Read back rather than assumed: the privileged side walks its own list when the asked
	// for address is taken, and the address the machine gets pointed at is whichever one it
	// ended up on.
	bound, err := netip.ParseAddrPort(pc.LocalAddr().String())
	if err != nil {
		return nil, nil, netip.AddrPort{}, closeAlso(err, pc.Close(), ln.Close())
	}
	return pc, ln, bound, nil
}

func (r systemDNSRights) Apply(ctx context.Context, resolvers []netip.Addr) error {
	return r.session.SetSystemDNS(ctx, resolvers)
}

// Restore is Apply with nothing to apply, which is how the boundary spells it: pointing a
// machine at no resolver at all is not something app-tail offers, so the empty list is free
// to mean the other thing.
func (r systemDNSRights) Restore(ctx context.Context) error {
	return r.session.SetSystemDNS(ctx, nil)
}

func (r systemDNSRights) Base(ctx context.Context) (BaseResolvers, error) {
	base, err := r.session.BaseSystemDNS(ctx)
	if err != nil {
		return BaseResolvers{}, err
	}
	return BaseResolvers{Nameservers: base.Nameservers, SearchDomains: base.SearchDomains}, nil
}

func (r systemDNSRights) Close() error { return r.session.Close() }

// closeAlso joins the failure being returned with whatever went wrong cleaning up after it.
// The first is the one worth acting on, and the rest belong in the same error rather than in
// a log nobody reads: a socket that would not close is a port this machine still cannot use.
func closeAlso(err error, cleanup ...error) error {
	return errors.Join(append([]error{err}, cleanup...)...)
}
