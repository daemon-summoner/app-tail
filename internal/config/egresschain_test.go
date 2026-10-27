// SPDX-License-Identifier: MIT

package config

// A chain of connections carrying this machine's internet traffic one inside the next: what
// the document says it is, and the orders it refuses to hold.

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// chainable is a WireGuard connection whose server takes everything this machine sends, which
// is what a hop has to do: carry the next hop's server, or the internet at the end.
func chainable(id, slug, name string) Tunnel {
	held := NewTunnel(id, slug, name, TunnelWireGuard)
	held.WireGuard = &WireGuardTunnel{
		PrivateKey: "aBhtG18wo5eIJXAkl7L4L3RyKNwzZuBAK1zSHnRRRXc=",
		Addresses:  []netip.Prefix{netip.MustParsePrefix("10.9.9.4/24")},
		MTU:        DefaultWireGuardMTU,
		Peer: WireGuardPeer{
			PublicKey:  "vGKFmWU/gzcgTHFI9DMBGaGqjRWTKJhCXV/2NAB6dHM=",
			Endpoint:   "one.example.com:51820",
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		},
	}
	return held
}

// chainOf is a document whose internet traffic is chained through the connections given.
func chainOf(hops ...Tunnel) *Config {
	cfg := Defaults()
	cfg.Settings.EgressMode = EgressMulti
	cfg.Settings.EgressMultiShape = EgressCascade
	for _, held := range hops {
		cfg.Tunnels = append(cfg.Tunnels, held)
		cfg.Settings.EgressMultiTunnelIDs = append(cfg.Settings.EgressMultiTunnelIDs, held.ID)
	}
	return cfg
}

// The three questions the rest of the app asks a chained document, answered from one stored
// list: who the hops are, which one the internet sees, and what each one travels inside.
func TestAChainIsReadAsHopsAnExitAndACarrierForEach(t *testing.T) {
	app := Settings{
		EgressMode:           EgressMulti,
		EgressMultiShape:     EgressCascade,
		EgressMultiTunnelIDs: []string{"tn_one", "tn_two", "tn_three"},
	}

	hops, chained := app.EgressChain()
	if !chained {
		t.Fatal("EgressChain says the traffic is not chained while the shape says it is")
	}
	if got := strings.Join(hops, ","); got != "tn_one,tn_two,tn_three" {
		t.Errorf("hops = %q, want them in the order they were stored -- the order is the setting", got)
	}
	if got := app.EgressExit(); got != "tn_three" {
		t.Errorf("EgressExit = %q, want the last hop -- that is the address the internet sees", got)
	}
	if got := app.EgressCarrierOf("tn_two"); got != "tn_one" {
		t.Errorf("EgressCarrierOf(tn_two) = %q, want the hop before it", got)
	}
	if got := app.EgressCarrierOf("tn_one"); got != "" {
		t.Errorf("EgressCarrierOf on the first hop = %q, want nothing -- it leaves this machine "+
			"the ordinary way, and anything else is a connection carrying itself", got)
	}
	if got := app.EgressCarrierOf("tn_elsewhere"); got != "" {
		t.Errorf("EgressCarrierOf on a connection outside the chain = %q, want nothing", got)
	}

	// The two shapes read the same stored list, so each has to refuse the other's reading of
	// it. Spreading traffic across the hops of a chain would send it out of all of them at
	// once, which is the opposite of the route that was asked for.
	if _, spread := app.EgressSpread(); spread {
		t.Error("EgressSpread is true for a chain, so the traffic would leave through every hop")
	}
	members, shared := app.EgressShared()
	if !shared || len(members) != 3 {
		t.Errorf("EgressShared = %v, %v, want the whole set -- it is what both shapes have in "+
			"common, and it decides which connections may not be removed", members, shared)
	}
}

// A chain with nothing in it is an order with no order. It is refused rather than read as
// "every connection", because the set that means every connection is the spread one: chaining
// through connections in an order nobody chose is not something anyone asked for.
func TestAChainWithNoConnectionsIsRefused(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.EgressMode = EgressMulti
	cfg.Settings.EgressMultiShape = EgressCascade

	err := cfg.Validate()

	if err == nil {
		t.Fatal("a chain through no connections at all was accepted")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "egress.multi.tunnelIds" {
		t.Errorf("error = %T %v, want it to name egress.multi.tunnelIds", err, err)
	}
}

// One connection cannot carry its own packets, so a chain naming it twice is a loop that
// would never complete a handshake.
func TestAChainCannotNameTheSameConnectionTwice(t *testing.T) {
	one := chainable("tn_one", "one", "One")
	cfg := chainOf(one)
	cfg.Settings.EgressMultiTunnelIDs = append(cfg.Settings.EgressMultiTunnelIDs, one.ID)

	err := cfg.Validate()

	if err == nil {
		t.Fatal("a chain naming one connection twice was accepted")
	}
	if !strings.Contains(err.Error(), "tn_one") {
		t.Errorf("error = %v, want the connection named", err)
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "egress.multi.tunnelIds" {
		t.Errorf("error = %T %v, want it to name egress.multi.tunnelIds", err, err)
	}
}

// A hop after the first has its own packets carried inside the hop before it. A tailnet
// chooses its own path between relays and peers, so nothing here can put its packets
// anywhere. Refused where it is written: the run-time symptom is a handshake that never
// completes, which reads as a broken server.
func TestATailnetConnectionCannotBeCarriedByAnotherOne(t *testing.T) {
	ts := NewTunnel("tn_ts", "work", "Work", TunnelTailscale)

	err := chainOf(chainable("tn_one", "one", "One"), ts).Validate()

	if err == nil {
		t.Fatal("a tailnet connection was accepted as a hop after the first")
	}
	if !strings.Contains(err.Error(), "first connection in the chain") {
		t.Errorf("error = %v, want it to say where such a connection can go instead", err)
	}

	// First is a position it can hold: as hop one it sends its own packets over this machine's
	// own network, which is what it does anyway.
	if err := chainOf(ts, chainable("tn_one", "one", "One")).Validate(); err != nil {
		t.Errorf("a tailnet connection was refused as the first hop: %v", err)
	}
}

// An OpenVPN connection is a separate program that cannot be told where to send its packets,
// but it can be told what address to dial -- so a carried one is pointed at a listener this
// app owns and its stream is carried on. A stream is the TCP transport: the same connection
// set to reach its server over datagrams has nothing to be carried.
func TestAnOpenVPNConnectionIsCarriedOnlyWhenItReachesItsServerOverAStream(t *testing.T) {
	over := func(proto string) Tunnel {
		held := NewTunnel("tn_ovpn", "vpn", "Provider", TunnelOpenVPN)
		held.OpenVPN = &OpenVPNTunnel{
			Remote: "vpn.example.com:1194",
			Proto:  proto,
			CA:     "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
			Routes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}
		return held
	}

	if err := chainOf(chainable("tn_one", "one", "One"), over(OpenVPNProtoTCP)).Validate(); err != nil {
		t.Errorf("an OpenVPN connection reaching its server over a stream was refused as a hop: %v", err)
	}

	err := chainOf(chainable("tn_one", "one", "One"), over(OpenVPNProtoUDP)).Validate()
	if err == nil {
		t.Fatal("an OpenVPN connection reaching its server over datagrams was accepted as a hop")
	}
	if !strings.Contains(err.Error(), OpenVPNProtoTCP) {
		t.Errorf("error = %v, want it to name the transport such a connection has to use", err)
	}

	// First is a position it holds over either transport: as hop one it dials its server over
	// this machine's own network, which is what it does anyway.
	if err := chainOf(over(OpenVPNProtoUDP), chainable("tn_one", "one", "One")).Validate(); err != nil {
		t.Errorf("an OpenVPN connection over datagrams was refused as the first hop: %v", err)
	}
}

// Every hop carries something to an address of somebody else's choosing -- the next hop's
// server, or the internet at the end -- so a connection whose server routes nothing on cannot
// hold a place in one.
func TestAConnectionThatCarriesOnlyItsOwnNetworkCannotBeAHop(t *testing.T) {
	narrow := chainable("tn_narrow", "narrow", "Narrow")
	wg := narrow.WG()
	wg.Peer.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.9.9.0/24")}
	narrow.WireGuard = &wg

	err := chainOf(chainable("tn_one", "one", "One"), narrow).Validate()

	if err == nil {
		t.Fatal("a connection carrying only its own network was accepted as the last hop")
	}
	if !strings.Contains(err.Error(), "internet traffic") {
		t.Errorf("error = %v, want it to say what that hop would have had to carry", err)
	}

	// The same connection in the middle is refused for a different thing it would have had to
	// carry, and the refusal has to say which -- "add a default route" is the same fix, but
	// what is being asked of the connection is not the same.
	err = chainOf(chainable("tn_one", "one", "One"), narrow, chainable("tn_end", "end", "End")).Validate()
	if err == nil {
		t.Fatal("a connection carrying only its own network was accepted as a middle hop")
	}
	if !strings.Contains(err.Error(), "the connection after it") {
		t.Errorf("error = %v, want it to name the hop that connection would have had to carry", err)
	}
}

// A hop that is not in the document at all is the same quiet failure a single chosen
// connection is: a dial to a connection that is not there.
func TestAChainCannotNameAConnectionThatIsNotThere(t *testing.T) {
	cfg := chainOf(chainable("tn_one", "one", "One"))
	cfg.Settings.EgressMultiTunnelIDs = append(cfg.Settings.EgressMultiTunnelIDs, "tn_removed")

	err := cfg.Validate()

	if err == nil {
		t.Fatal("a chain through a connection that does not exist was accepted")
	}
	if !strings.Contains(err.Error(), "tn_removed") {
		t.Errorf("error = %v, want the connection named", err)
	}
}

// A chain that can be built is accepted, which is what makes every refusal above a statement
// about that order rather than about chains.
func TestAChainOfConnectionsThatCanCarryEachOtherIsAccepted(t *testing.T) {
	cfg := chainOf(chainable("tn_one", "one", "One"), chainable("tn_two", "two", "Two"))
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a chain of two connections that each carry everything was refused: %v", err)
	}
}
