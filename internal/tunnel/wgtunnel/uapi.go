// SPDX-License-Identifier: MIT

package wgtunnel

// Rendering one connection's stored settings as the text a WireGuard device is configured
// with.
//
// It is pure and separate from the device for one reason: this is where every value that
// could be wrong turns into a refusal with a sentence, and a refusal is worth testing
// without a network, a socket or a key exchange. The device below only ever receives text
// that already parsed.
//
// The wire format is WireGuard's own cross-platform configuration protocol: one key=value
// per line, device keys first, then a public_key line opening each peer's block. Keys are
// hex here and base64 everywhere a person handles them, which is the one conversion this
// file exists to keep in a single place.

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
)

// Device is what one WireGuard device is configured with, with everything already
// resolved: the server is an address rather than a name, because the device's own
// configuration protocol accepts nothing else and a name looked up here would be looked up
// through whatever this machine currently resolves with.
type Device struct {
	// PrivateKey is base64, as every WireGuard tool writes it.
	PrivateKey string
	Peer       Peer
}

// Peer is the one server a connection dials.
type Peer struct {
	// PublicKey and PresharedKey are base64. PresharedKey is optional.
	PublicKey    string
	PresharedKey string
	// Endpoint is where the server answers, already resolved to an address.
	Endpoint netip.AddrPort
	// AllowedIPs are the addresses this peer may send from and this connection routes to
	// it. An empty list is refused: a device configured with none would complete a
	// handshake and then drop every packet in both directions.
	AllowedIPs   []netip.Prefix
	KeepaliveSec int
}

// UAPI renders the device's configuration protocol text.
//
// It replaces rather than merges -- replace_peers and replace_allowed_ips -- so applying
// it to a device that is already configured leaves exactly what is written here. A merge
// would leave a peer or a route the user has since deleted still carrying traffic, which
// is the one outcome a settings screen must not be able to produce.
func (d Device) UAPI() (string, error) {
	privateKey, err := hexKey(d.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("this connection's private key %w", err)
	}
	publicKey, err := hexKey(d.Peer.PublicKey)
	if err != nil {
		return "", fmt.Errorf("the server's public key %w", err)
	}
	if !d.Peer.Endpoint.IsValid() {
		return "", fmt.Errorf("the server's address has not been resolved to something to dial")
	}
	if len(d.Peer.AllowedIPs) == 0 {
		return "", fmt.Errorf("no networks are configured for this connection to carry, so it " +
			"would connect and then drop everything sent through it")
	}

	var b strings.Builder
	// No listen_port: the device binds an ephemeral one, which is what a client wants.
	// Naming a port would make two connections on this machine able to collide, and would
	// invite a firewall rule for something that never has to be reachable from outside.
	fmt.Fprintf(&b, "private_key=%s\n", privateKey)
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", publicKey)
	if strings.TrimSpace(d.Peer.PresharedKey) != "" {
		presharedKey, err := hexKey(d.Peer.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("the pre-shared key %w", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", presharedKey)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", d.Peer.Endpoint)
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", d.Peer.KeepaliveSec)
	b.WriteString("replace_allowed_ips=true\n")
	for _, prefix := range d.Peer.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", prefix)
	}
	return b.String(), nil
}

// MoveEndpoint renders the text that points an already-configured peer at a new address.
//
// It carries the peer's key, the new address and nothing else, because everything else
// about the connection is unchanged: a full render would replace the peer, and replacing a
// peer discards the session keys the two sides already agreed on, turning a server that
// merely moved into a fresh handshake and a gap in traffic.
//
// update_only, so a peer that is somehow no longer on the device is not quietly created
// here with no allowed addresses -- which would connect and then drop everything.
func MoveEndpoint(publicKey string, endpoint netip.AddrPort) (string, error) {
	key, err := hexKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("the server's public key %w", err)
	}
	if !endpoint.IsValid() {
		return "", fmt.Errorf("the server's address has not been resolved to something to dial")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", key)
	b.WriteString("update_only=true\n")
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	return b.String(), nil
}

// hexKey converts a base64 key to the hex the configuration protocol uses. The error is a
// clause, so the caller reads as "this connection's private key must not be empty".
func hexKey(key string) (string, error) {
	raw, err := config.ParseWireGuardKey(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
