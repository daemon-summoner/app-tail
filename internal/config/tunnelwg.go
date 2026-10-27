// SPDX-License-Identifier: MIT

package config

// What a WireGuard connection stores.
//
// A WireGuard connection is a key pair, the addresses this device holds inside the
// network, and one server to dial. It carries no identity the network hands out and no
// login: the server either has this device's public key or it does not, which is why there
// is nothing here resembling the tailnet's enrollment.
//
// One server per connection, deliberately. WireGuard's own configuration format allows
// several peers because it also describes meshes and servers; a client dialling one
// gateway is the shape this app connects, and two gateways are two connections -- each
// with its own name, its own addresses and its own place in the addressing report. A
// pasted configuration carrying a second peer is refused by name rather than silently
// losing it.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// WireGuardKeyLen is the length of every WireGuard key in bytes, private, public and
// pre-shared alike.
const WireGuardKeyLen = 32

// DefaultWireGuardMTU is the MTU a connection uses when the configuration names none.
//
// 1420 is what wg-quick picks for an IPv4 endpoint over a 1500-byte link: 1500 less 20
// bytes of outer IPv4 header, 8 of UDP and 32 of WireGuard's own. A larger value is not an
// error here -- the far side may be on a larger link -- but it is what fragments.
const DefaultWireGuardMTU = 1420

// MinWireGuardMTU is the smallest MTU worth accepting: below the IPv6 minimum of 1280 a
// great deal of the internet simply stops working, and a typo is far likelier than a
// network that needs it.
const MinWireGuardMTU = 1280

// MaxWireGuardMTU bounds the other end. Anything above a jumbo frame is a typo.
const MaxWireGuardMTU = 9000

// DefaultWireGuardKeepaliveSec is what a connection behind NAT needs to stay reachable:
// without a packet every so often the gateway's mapping expires and the server can no
// longer start a conversation. 25 seconds is WireGuard's own recommendation, comfortably
// inside the shortest mappings in the wild.
const DefaultWireGuardKeepaliveSec = 25

// MaxWireGuardKeepaliveSec is the protocol's own limit: the field is 16 bits of seconds.
const MaxWireGuardKeepaliveSec = 65535

// WireGuardTunnel is one WireGuard connection's own keys, addresses and server.
type WireGuardTunnel struct {
	// PrivateKey is this device's key, base64 as every WireGuard tool writes it.
	// Write-only across the API: it is the whole of this device's identity on the network.
	PrivateKey string `json:"privateKey"`
	// Addresses are the addresses this device holds inside the network, with the prefix
	// the configuration gave them. The prefix is kept rather than reduced to the address
	// because it is what the network says this device is part of.
	Addresses []netip.Prefix `json:"addresses"`
	// DNS are the resolvers reachable inside the network. They are used for the names
	// this connection resolves and for nothing else on this machine.
	DNS []netip.Addr `json:"dns"`
	// MTU is the largest packet this connection carries. Zero means DefaultWireGuardMTU.
	MTU int `json:"mtu"`
	// Peer is the server this connection dials.
	Peer WireGuardPeer `json:"peer"`
}

// WireGuardPeer is the server one connection dials.
type WireGuardPeer struct {
	// PublicKey is the server's key, base64. It is not a secret: it is what the server
	// publishes, and it is checked rather than hidden.
	PublicKey string `json:"publicKey"`
	// PresharedKey is the optional symmetric key mixed into the handshake, base64. It is
	// a secret and is write-only across the API.
	PresharedKey string `json:"presharedKey"`
	// Endpoint is where the server answers, as host:port. A name is allowed and is
	// resolved when the connection starts, which is what lets a server on a dynamic
	// address be reached at all.
	Endpoint string `json:"endpoint"`
	// AllowedIPs are the addresses this connection carries, which is both what the
	// server is trusted to send from and what this app routes through it. A 0.0.0.0/0
	// entry is how a configuration says "everything", and it is kept: whether this
	// machine's other traffic actually leaves through it is a separate choice.
	AllowedIPs []netip.Prefix `json:"allowedIPs"`
	// KeepaliveSec is how often to send a packet with nothing in it so a NAT in the way
	// keeps its mapping. Zero sends none, which is right for a server that never has to
	// start a conversation and wrong for almost everything else.
	KeepaliveSec int `json:"keepaliveSec"`
}

// WG returns this connection's WireGuard settings, and a zero value for a connection that
// has none, for the reason TS does: a caller reading through it never has to decide what a
// missing block means.
func (t Tunnel) WG() WireGuardTunnel {
	if t.WireGuard == nil {
		return WireGuardTunnel{}
	}
	return *t.WireGuard
}

// wg returns the WireGuard block to write into, creating it on the first write.
func (t *Tunnel) wg() *WireGuardTunnel {
	if t.WireGuard == nil {
		t.WireGuard = &WireGuardTunnel{}
	}
	return t.WireGuard
}

// clone returns a copy sharing no slice with w.
func (w WireGuardTunnel) clone() WireGuardTunnel {
	w.Addresses = append([]netip.Prefix(nil), w.Addresses...)
	w.DNS = append([]netip.Addr(nil), w.DNS...)
	w.Peer.AllowedIPs = append([]netip.Prefix(nil), w.Peer.AllowedIPs...)
	return w
}

// SameAs reports whether two stored WireGuard connections would build the same device.
//
// Every value the device is configured from is compared, because that is the question this
// answers: a connection whose settings still render to this is left running, and one whose
// settings do not is torn down and rebuilt. A field missed here is an edit that is saved,
// reported as applied, and never reaches the device.
func (w WireGuardTunnel) SameAs(other WireGuardTunnel) bool {
	return w.PrivateKey == other.PrivateKey &&
		w.EffectiveMTU() == other.EffectiveMTU() &&
		slices.Equal(w.Addresses, other.Addresses) &&
		slices.Equal(w.DNS, other.DNS) &&
		w.Peer.PublicKey == other.Peer.PublicKey &&
		w.Peer.PresharedKey == other.Peer.PresharedKey &&
		w.Peer.Endpoint == other.Peer.Endpoint &&
		w.Peer.KeepaliveSec == other.Peer.KeepaliveSec &&
		slices.Equal(w.Peer.AllowedIPs, other.Peer.AllowedIPs)
}

// EffectiveMTU is the packet size this connection actually uses.
func (w WireGuardTunnel) EffectiveMTU() int {
	if w.MTU <= 0 {
		return DefaultWireGuardMTU
	}
	return w.MTU
}

// InterfaceAddrs are the addresses this device answers at inside the network, without the
// prefix they were configured with. They are what the connection's own stack is given.
func (w WireGuardTunnel) InterfaceAddrs() []netip.Addr {
	out := make([]netip.Addr, 0, len(w.Addresses))
	for _, prefix := range w.Addresses {
		out = append(out, prefix.Addr())
	}
	return out
}

// CarriedRoutes are the networks reachable through this connection: its allowed addresses
// without the default routes.
//
// A default route is dropped because it is not a route to a network -- it is the statement
// that everything this machine sends should leave here, which is a choice about this
// machine made elsewhere. Reporting it as a network this connection reaches would have it
// claim every address in existence in the addressing report, colliding with each of the
// others.
func (w WireGuardTunnel) CarriedRoutes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(w.Peer.AllowedIPs))
	for _, prefix := range w.Peer.AllowedIPs {
		if prefix.Bits() == 0 {
			continue
		}
		out = append(out, prefix)
	}
	return out
}

// CarriesDefault reports that the server is set up to take everything this machine sends:
// a default route among the peer's allowed addresses is what tells the device to hand it
// packets for addresses no other route covers. It is the WireGuard half of the question an
// exit node answers on a tailnet.
func (w WireGuardTunnel) CarriesDefault() bool {
	for _, prefix := range w.Peer.AllowedIPs {
		if prefix.Bits() == 0 {
			return true
		}
	}
	return false
}

// PublicKey is the key this device presents to the server, derived from its private key.
//
// It is derived rather than stored because the two cannot be allowed to disagree: a stored
// public key that no longer matches the private key is a configuration that looks right in
// every form and never completes a handshake, with nothing on screen saying why. It is
// empty when there is no usable private key, which is the state a connection is in before
// anything has been configured.
func (w WireGuardTunnel) PublicKey() string {
	raw, err := ParseWireGuardKey(w.PrivateKey)
	if err != nil {
		return ""
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// ParseWireGuardKey decodes a base64 key and checks its length. The error is bare: the
// caller names the field it came from.
func ParseWireGuardKey(s string) ([]byte, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil, fmt.Errorf("must not be empty")
	}
	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("must be a base64 key as wg(8) writes it")
	}
	if len(raw) != WireGuardKeyLen {
		return nil, fmt.Errorf("must decode to %d bytes, got %d", WireGuardKeyLen, len(raw))
	}
	return raw, nil
}

// ValidWireGuardEndpoint reports whether s is a server address this connection can dial,
// and why not when it is not.
//
// A name is allowed beside a literal address: a great many WireGuard servers are named
// rather than numbered, and refusing one would refuse the configuration the server's own
// administrator handed out.
func ValidWireGuardEndpoint(s string) (bool, string) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return false, "must not be empty"
	}
	host, port, err := splitHostPort(trimmed)
	if err != nil {
		return false, "must be the server's address and port, as host:port"
	}
	if host == "" {
		return false, "must name the server before the port"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false, "must end in a port between 1 and 65535"
	}
	return true, ""
}

// splitHostPort splits host:port, accepting the bracketed form a literal IPv6 address
// needs. It is here rather than net.SplitHostPort so a bare IPv6 address -- which that
// function reads as a host and a port -- is refused with the message above.
func splitHostPort(s string) (host, port string, err error) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 || end+2 > len(s) || s[end+1] != ':' {
			return "", "", fmt.Errorf("not host:port")
		}
		return s[1:end], s[end+2:], nil
	}
	host, port, found := strings.Cut(s, ":")
	if !found || strings.Contains(port, ":") {
		return "", "", fmt.Errorf("not host:port")
	}
	return host, port, nil
}

// The registry's validators. Each accepts an empty value: a connection is added before it
// is configured, and refusing the empty state would make an unfinished connection
// unsavable rather than unstarted. What a connection needs before it can actually come up
// is checked where it comes up, with the whole of it in view.

// optionalWireGuardKey checks a base64 key, if one was given.
func optionalWireGuardKey(v any) error {
	key := strings.TrimSpace(typed[string](v))
	if key == "" {
		return nil
	}
	_, err := ParseWireGuardKey(key)
	return err
}

// optionalWireGuardEndpoint checks a server address, if one was given.
func optionalWireGuardEndpoint(v any) error {
	endpoint := strings.TrimSpace(typed[string](v))
	if endpoint == "" {
		return nil
	}
	if ok, why := ValidWireGuardEndpoint(endpoint); !ok {
		return errors.New(why)
	}
	return nil
}

// distinctInterfaceAddrs refuses a repeated address. Two entries for one address is not a
// second address: it is one, entered twice, and the network would carry no more of this
// device's traffic for it.
func distinctInterfaceAddrs(v any) error {
	seen := make(map[netip.Addr]bool)
	for _, prefix := range typed[[]netip.Prefix](v) {
		if seen[prefix.Addr()] {
			return fmt.Errorf("%s is listed twice", prefix.Addr())
		}
		seen[prefix.Addr()] = true
	}
	return nil
}

// carriedNetworks refuses a list of carried networks that could not be acted on.
//
// A default route is allowed here, unlike a route this device offers the tailnet: for a
// server it is the ordinary way a configuration says the server carries everything. What
// is refused is a repeat, which makes the list ambiguous about which entry a later
// decision -- an address map, an egress choice -- was made against.
func carriedNetworks(v any) error {
	seen := make(map[netip.Prefix]bool)
	for _, prefix := range typed[[]netip.Prefix](v) {
		if seen[prefix] {
			return fmt.Errorf("%s is listed twice", prefix)
		}
		seen[prefix] = true
	}
	return nil
}

// reachableResolvers refuses a repeated resolver, which would be asked twice and answer
// once.
func reachableResolvers(v any) error {
	seen := make(map[netip.Addr]bool)
	for _, addr := range typed[[]netip.Addr](v) {
		if seen[addr] {
			return fmt.Errorf("%s is listed twice", addr)
		}
		seen[addr] = true
	}
	return nil
}
