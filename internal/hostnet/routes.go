// SPDX-License-Identifier: MIT

package hostnet

// The addressing a caller that is not the tailnet engine installs on the interface.
//
// The engine hands the privileged side its own router.Config, which carries Linux firewall
// mode, a stateful-filtering switch and a subnet-routing flag beside the routes. A caller
// that only wants "send these ranges to this interface" has no business setting any of
// those, and widening who may send a router.Config would give it all of them at once. This
// is the narrow shape instead: three lists of address ranges and a packet size.

import (
	"fmt"
	"net/netip"
	"slices"

	"go4.org/netipx"
	"tailscale.com/types/preftype"
	"tailscale.com/wgengine/router"
)

// Routes is where traffic goes and how big a packet may be.
type Routes struct {
	// LocalAddrs are the addresses the interface itself holds.
	LocalAddrs []netip.Prefix `json:"localAddrs,omitempty"`
	// Routes are the ranges this machine sends to the interface.
	Routes []netip.Prefix `json:"routes,omitempty"`
	// LocalRoutes are the ranges that must keep leaving through the machine's own
	// network. They are what keeps a connection's own server reachable: a tunnel whose
	// server address falls inside a range this interface carries would have its encrypted
	// packets sent back into the interface that produced them, and the machine would lose
	// every network it has -- including whatever was going to switch this off.
	LocalRoutes []netip.Prefix `json:"localRoutes,omitempty"`
	// MTU is the largest packet the interface carries, zero to leave it alone.
	MTU int `json:"mtu,omitempty"`
}

// Installed is the address ranges this machine's routing table is actually given, which is
// Routes rewritten twice over.
//
// A default route is sent as its two halves. A routing table holds one route per
// destination, and this machine already has a default: asking for a second is refused, and
// on some systems refused so quietly that the interface ends up carrying nothing at all
// while everything above it reports success. Each half is a different destination, so both
// are accepted, and each is more specific than the default it sits beside -- which is what
// makes them win. It is the same shape openvpn's own `redirect-gateway def1` installs, and
// for the same reason.
//
// Then LocalRoutes are cut out of what is left. Those are the ranges that must keep leaving
// through the machine's own network -- every connection's own server among them -- and an
// interface carrying every address would otherwise carry a connection's encrypted packets
// straight back into the interface that produced them. Cutting them out leaves those
// addresses with no route here at all, so they fall through to the machine's own default,
// which is where they have to go. They are still passed to the OS as local routes as well:
// the systems that have a way to state the exclusion directly are told it directly.
func (r Routes) Installed() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, prefix := range r.Routes {
		for _, part := range splitDefault(prefix) {
			kept, err := without(part, r.LocalRoutes)
			if err != nil {
				return nil, err
			}
			out = append(out, kept...)
		}
	}
	return out, nil
}

// splitDefault is one range as the routing table will take it: a default route as its two
// halves, anything else as itself.
func splitDefault(prefix netip.Prefix) []netip.Prefix {
	if prefix.Bits() != 0 {
		return []netip.Prefix{prefix}
	}
	if prefix.Addr().BitLen() == 32 {
		return []netip.Prefix{
			netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 1),
			netip.PrefixFrom(netip.AddrFrom4([4]byte{0x80}), 1),
		}
	}
	return []netip.Prefix{
		netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 1),
		netip.PrefixFrom(netip.AddrFrom16([16]byte{0x80}), 1),
	}
}

// without is one range with some addresses taken out of it, as the prefixes that remain.
func without(prefix netip.Prefix, cut []netip.Prefix) ([]netip.Prefix, error) {
	if len(cut) == 0 {
		return []netip.Prefix{prefix}, nil
	}
	var b netipx.IPSetBuilder
	b.AddPrefix(prefix)
	for _, one := range cut {
		b.RemovePrefix(one)
	}
	set, err := b.IPSet()
	if err != nil {
		return nil, fmt.Errorf("take %v out of %s: %w", cut, prefix, err)
	}
	return set.Prefixes(), nil
}

// maxMTU is the largest packet size this will set. It is the largest an Ethernet jumbo frame
// carries; past it the number is a mistake rather than a configuration, and it reaches a
// privileged call.
const maxMTU = 9000

// minMTU is the smallest packet size IPv6 requires a link to carry. Below it a machine
// cannot send an IPv6 packet at all, and the interface would be up and useless.
const minMTU = 1280

// Validate refuses addressing the privileged side must not install.
//
// The refusals are the ranges no interface may take over rather than a policy about which
// networks are allowed: loopback is how every program on this machine reaches itself, and a
// link-local address names a different machine on every network it is used on. Sending
// either into an interface breaks things that have nothing to do with app-tail, and the
// caller asking is unprivileged.
func (r Routes) Validate() error {
	for _, prefix := range slices.Concat(r.LocalAddrs, r.Routes, r.LocalRoutes) {
		if !prefix.IsValid() {
			return fmt.Errorf("%q is not an address range", prefix)
		}
	}
	for _, prefix := range slices.Concat(r.LocalAddrs, r.Routes) {
		addr := prefix.Masked().Addr()
		switch {
		case addr.IsLoopback():
			return fmt.Errorf("%s is how this machine reaches itself and cannot be sent to an interface", prefix)
		case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
			return fmt.Errorf("%s names a different machine on every network and cannot be sent to an interface", prefix)
		case addr.IsMulticast():
			return fmt.Errorf("%s is multicast, which an interface carrying connections cannot deliver", prefix)
		}
	}
	if r.MTU != 0 && (r.MTU < minMTU || r.MTU > maxMTU) {
		return fmt.Errorf("a packet size of %d is outside the %d to %d an interface can carry", r.MTU, minMTU, maxMTU)
	}
	return nil
}

// validateRouterConfig refuses a tailnet engine configuration the privileged side must not
// install.
//
// The engine's own shape is wider than Routes: beside the same three lists it carries the
// packet size, the subnets this node advertises, and on Linux the firewall mode and kind
// that decide which command this process runs as root. Everything the caller sends crosses
// the boundary as JSON, so every one of those is a value an unprivileged caller chose, and
// this side holds the rights. The address rules are Routes.Validate's, for the reasons
// stated there; the firewall fields are bounded to the values the engine itself defines,
// because a name outside that set reaches a root command lookup.
func validateRouterConfig(cfg *router.Config) error {
	if cfg == nil {
		// A nil configuration removes everything, which is how the engine tears its own
		// addressing down. There is nothing in it to check.
		return nil
	}
	routes := Routes{
		LocalAddrs:  cfg.LocalAddrs,
		Routes:      cfg.Routes,
		LocalRoutes: cfg.LocalRoutes,
		MTU:         cfg.NewMTU,
	}
	if err := routes.Validate(); err != nil {
		return err
	}
	for _, prefix := range cfg.SubnetRoutes {
		if !prefix.IsValid() {
			return fmt.Errorf("%q is not an address range", prefix)
		}
	}
	switch cfg.NetfilterMode {
	case preftype.NetfilterOff, preftype.NetfilterNoDivert, preftype.NetfilterOn:
	default:
		return fmt.Errorf("%d is not a firewall mode this app knows", cfg.NetfilterMode)
	}
	switch cfg.NetfilterKind {
	case "", "nftables", "iptables":
	default:
		return fmt.Errorf("%q is not a firewall this app knows how to drive", cfg.NetfilterKind)
	}
	return nil
}
