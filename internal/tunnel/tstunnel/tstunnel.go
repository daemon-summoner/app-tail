// SPDX-License-Identifier: MIT

// Package tstunnel presents a Tailscale node as a tunnel.
//
// It is a translation and nothing else: every method delegates to the node, and the only
// judgement it makes is turning the backend's own state words into the one status
// vocabulary every kind of tunnel reports in. Keeping that judgement here rather than in
// each consumer is what stops the dashboard and the tray from disagreeing about what
// "starting" means.
//
// It imports internal/tsnode and nothing else from the tailnet side, which keeps the
// boundary internal/archtest enforces at exactly one package.
package tstunnel

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// Node is the part of a Tailscale node this wrapper drives. tsnode.Node satisfies it,
// and so does the agent's own controller, which is what lets the agent hand the tunnel
// the node it already built rather than starting a second one.
type Node interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
	Listen(network string, port uint16) (net.Listener, error)
	ListenPacket(network string, port uint16) (net.PacketConn, error)

	Start(ctx context.Context) error
	Close() error
	Status() tsnode.Status
	Events() <-chan struct{}

	Reach(ctx context.Context, network, address string) (tsnode.Reach, error)
	Routes(ctx context.Context) ([]netip.Prefix, error)
	ApprovedRoutes(ctx context.Context) ([]netip.Prefix, error)
	Peers(ctx context.Context) ([]tsnode.Peer, error)
	LookupTailnet(ctx context.Context, host string) (tsnode.TailnetLookup, error)
	PingPeer(ctx context.Context, ip netip.Addr) (time.Duration, error)
}

// Tunnel is a Tailscale node behind the tunnel seam.
type Tunnel struct {
	id   string
	node Node
}

// New wraps a node as the tunnel identified by id.
func New(id string, node Node) *Tunnel { return &Tunnel{id: id, node: node} }

// Every capability a tailnet actually has, asserted at compile time. A method dropped
// from one of these interfaces would otherwise show up as a feature quietly missing from
// the dashboard rather than as a build failure.
var (
	_ tunnel.Tunnel       = (*Tunnel)(nil)
	_ tunnel.Reaching     = (*Tunnel)(nil)
	_ tunnel.Resolving    = (*Tunnel)(nil)
	_ tunnel.Pinger       = (*Tunnel)(nil)
	_ tunnel.Peered       = (*Tunnel)(nil)
	_ tunnel.SubnetServer = (*Tunnel)(nil)
	_ tunnel.ExitCarrier  = (*Tunnel)(nil)
	_ tunnel.Addressed    = (*Tunnel)(nil)
)

func (t *Tunnel) ID() string              { return t.id }
func (t *Tunnel) Kind() tunnel.Kind       { return tunnel.KindTailscale }
func (t *Tunnel) Close() error            { return t.node.Close() }
func (t *Tunnel) Events() <-chan struct{} { return t.node.Events() }

func (t *Tunnel) Start(ctx context.Context) error { return t.node.Start(ctx) }

func (t *Tunnel) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return t.node.Dial(ctx, network, address)
}

func (t *Tunnel) Listen(network string, port uint16) (net.Listener, error) {
	return t.node.Listen(network, port)
}

func (t *Tunnel) ListenPacket(network string, port uint16) (net.PacketConn, error) {
	return t.node.ListenPacket(network, port)
}

func (t *Tunnel) Routes(ctx context.Context) ([]netip.Prefix, error) {
	return t.node.Routes(ctx)
}

// Networks are the ranges a tailnet addresses its devices from.
//
// They are deliberately not among the routes above, and cannot be: Routes reports what peers
// carry traffic for on behalf of somewhere else, and no peer ever advertises the tailnet's
// own allocation because every member already reaches every other by being a member. Anything
// building a route to the tailnet -- the one interface carrying every connection is the whole
// of it -- has to be told them here, or it carries every device on the tailnet nowhere.
func (t *Tunnel) Networks() []netip.Prefix { return tsnode.TailnetRanges() }

// Reach says where a destination would go, using the node's own dial plan -- the same
// resolution and the same routing table a dial would use, asked ahead of time. Nothing
// here consults Routes: a tailnet carries far more than its advertised subnets, and the
// node is the only thing that knows the whole of it.
func (t *Tunnel) Reach(ctx context.Context, network, address string) (tunnel.Reach, error) {
	reach, err := t.node.Reach(ctx, network, address)
	if err != nil {
		return tunnel.Reach{}, err
	}
	return tunnel.Reach{Addr: reach.Addr, Carried: reach.ViaTailnet}, nil
}

// Addrs are this device's own tailnet addresses.
func (t *Tunnel) Addrs() []netip.Addr {
	var out []netip.Addr
	for _, s := range t.node.Status().TailscaleIPs {
		if addr, err := netip.ParseAddr(s); err == nil {
			out = append(out, addr)
		}
	}
	return out
}

// MTU is the largest packet this tailnet carries. It is the backend's own default rather
// than a per-peer measurement: the interface mode needs one number for the whole network, and
// the smallest path in a tailnet is not knowable from here.
func (t *Tunnel) MTU() int { return tsnode.DefaultMTU() }

// Status translates the backend's own state into the shared vocabulary.
func (t *Tunnel) Status() tunnel.Status {
	s := t.node.Status()
	out := tunnel.Status{
		State:   stateOf(s),
		Detail:  s.Problem,
		AuthURL: s.AuthURL,
		Addrs:   s.TailscaleIPs,
		Limits:  limitsOf(s),
	}
	if s.DNSName != "" {
		out.Names = []string{s.DNSName}
	}
	// A selected exit node that is offline is the case worth naming: the backend
	// blackholes everything rather than falling back to a direct route, so the machine
	// looks like it has no connectivity and nothing else explains why.
	if out.State == tunnel.StateDegraded && out.Detail == "" && s.ExitNodeActive && !s.ExitNodeOnline {
		out.Detail = "the selected exit node is offline, so traffic through it is going nowhere"
	}
	return out
}

func stateOf(s tsnode.Status) tunnel.State {
	switch s.BackendState {
	case tsnode.StateRunning:
		if s.Problem != "" || (s.ExitNodeActive && !s.ExitNodeOnline) {
			return tunnel.StateDegraded
		}
		return tunnel.StateConnected
	case tsnode.StateStarting:
		return tunnel.StateConnecting
	case tsnode.StateNeedsLogin, tsnode.StateNeedsMachineAuth:
		return tunnel.StateNeedsLogin
	case tsnode.StateStopped:
		return tunnel.StateOff
	case tsnode.StateNoState:
		// The backend reports NoState both before it has started and after a failure it
		// could diagnose. The diagnosis is the only thing that tells them apart, and
		// reporting a failure as "off" would present a broken tunnel as a configured one.
		if s.Problem != "" {
			return tunnel.StateFailed
		}
		return tunnel.StateStarting
	default:
		return tunnel.StateStarting
	}
}

// The two things a tailnet in userspace mode does not do, stated up front rather than
// discovered. In interface mode neither applies, so the list is empty.
func limitsOf(s tsnode.Status) []string {
	if s.Network == config.NetworkTUN {
		return nil
	}
	return []string{
		"Only app-tail's own forwards and proxy reach this network; other programs on " +
			"this machine do not.",
		"Names on this network resolve for app-tail, not for the rest of the machine.",
	}
}

// LookupHost resolves through the tailnet's own resolver, which is the only one that
// knows a domain the tailnet points at a private nameserver.
func (t *Tunnel) LookupHost(ctx context.Context, host string) (tunnel.Lookup, error) {
	answer, err := t.node.LookupTailnet(ctx, host)
	if err != nil {
		return tunnel.Lookup{}, err
	}
	return tunnel.Lookup{Addrs: answer.Addrs, TTL: answer.TTL}, nil
}

// Ping measures the round trip to a peer.
func (t *Tunnel) Ping(ctx context.Context, addr netip.Addr) (tunnel.Reachability, error) {
	rtt, err := t.node.PingPeer(ctx, addr)
	if err != nil {
		return tunnel.Reachability{}, err
	}
	return tunnel.Reachability{LatencyMs: float64(rtt) / float64(time.Millisecond), OK: true}, nil
}

// Peers are the other devices on the tailnet.
func (t *Tunnel) Peers(ctx context.Context) ([]tunnel.Peer, error) {
	peers, err := t.node.Peers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]tunnel.Peer, 0, len(peers))
	for _, p := range peers {
		out = append(out, tunnel.Peer{
			ID:      p.ID,
			Name:    peerName(p),
			Addrs:   p.IPs,
			RxBytes: p.RxBytes,
			TxBytes: p.TxBytes,
			Online:  p.Online,
			// A peer with a current address is reached without a relay. The pair is one
			// fact: an empty CurAddr with a Relay set is reachable but paying for it.
			Direct: p.CurAddr != "",
			Relay:  p.Relay,
		})
	}
	return out, nil
}

// peerName prefers the short hostname, because that is what a person typed into the
// admin console and what they will look for in a list.
func peerName(p tsnode.Peer) string {
	if p.HostName != "" {
		return p.HostName
	}
	return p.DNSName
}

// Advertised are the networks this device offers to carry for the tailnet.
func (t *Tunnel) Advertised(ctx context.Context) ([]netip.Prefix, error) {
	return t.node.Routes(ctx)
}

// Approved are the ones the tailnet actually routes here.
func (t *Tunnel) Approved(ctx context.Context) ([]netip.Prefix, error) {
	return t.node.ApprovedRoutes(ctx)
}

// CanCarryExit reports whether this tailnet has an exit node in use right now.
func (t *Tunnel) CanCarryExit(context.Context) (bool, string) {
	s := t.node.Status()
	switch {
	case !s.Running():
		return false, "the connection is not up"
	case !s.ExitNodeActive:
		return false, "no exit node is selected on this connection"
	case !s.ExitNodeOnline:
		return false, "the selected exit node is offline"
	default:
		return true, ""
	}
}
