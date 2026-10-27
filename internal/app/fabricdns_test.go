// SPDX-License-Identifier: MIT

package app

// What a name on a connected network resolves to, once one interface is carrying every
// connection. This is the half of the interface mode that makes it usable without any
// per-program setup, and the half where a wrong answer is silent: the name resolves, the
// program connects, and it reaches the other network's host of the same address.

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsfwd"
)

// suffixFor is what names on one of the seeded connections end in.
func suffixFor(slug string) string { return slug + ".internal" }

// The answer a moved network's names have to come back with. Its own resolver says its own
// address; this machine reaches that host somewhere else entirely, and handing the program
// the network's own address would send it to whichever connection kept those addresses --
// which is the failure with no symptom the whole module exists to prevent.
func TestANameOnAMovedNetworkResolvesToWhereThisMachineReachesIt(t *testing.T) {
	// Both connections carry the same range, so the second one declared has to move.
	h, _ := carryingFabric(t, officeRange)

	inside := netip.MustParseAddr("172.30.99.5")
	h.wireguards.devicesFor(labTunnelID)[0].serves("db", inside)
	h.wireguards.devicesFor(wgTunnelID)[0].serves("db", inside)

	rules := h.agent.systemDNSTarget(context.Background()).rules
	moved := movedPrefix(t, h, labTunnelID)

	// The name goes to the connection rather than to a resolver outside this process.
	decision := dnsfwd.Route(dnsfwd.Question{
		Name: "db." + suffixFor("lab"), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
	}, rules)
	if decision.Target != dnsfwd.ToTunnel || decision.Tunnel != labTunnelID || decision.Host != "db" {
		t.Fatalf("routing = %s/%s/%q (%s), want the name asked of %s as \"db\"",
			decision.Target, decision.Tunnel, decision.Host, decision.Reason, labTunnelID)
	}

	got, err := fabricResolver{a: h.agent}.LookupTunnel(context.Background(), labTunnelID, "db")
	if err != nil {
		t.Fatalf("resolving inside the moved connection: %v", err)
	}
	if len(got) != 1 || !moved.Contains(got[0]) {
		t.Fatalf("db.lab.internal = %v, want an address inside %s -- the network's own %s is "+
			"somebody else's address on this machine", got, moved, inside)
	}
	// Every host bit is kept, so an address read off this machine is recognisable on the
	// network it came from.
	if got[0].As4()[3] != inside.As4()[3] {
		t.Errorf("db.lab.internal = %v, want the same host part as %s", got[0], inside)
	}

	// And the connection that kept its own addresses answers with them unchanged.
	kept, err := fabricResolver{a: h.agent}.LookupTunnel(context.Background(), wgTunnelID, "db")
	if err != nil {
		t.Fatalf("resolving inside the connection that did not move: %v", err)
	}
	if len(kept) != 1 || kept[0] != inside {
		t.Errorf("db.office.internal = %v, want %s unchanged -- nothing moved that network", kept, inside)
	}
}

// The two answers that are not addresses, told apart. A name the network does not serve is a
// fact about the name; a network that cannot be asked is a failure, and answering the second
// as the first would have the machine cache "no such name" for the length of an outage.
func TestANameTheNetworkDoesNotServeIsNotTheSameAsANetworkThatCannotBeAsked(t *testing.T) {
	h, _ := carryingFabric(t, labRange)
	resolver := fabricResolver{a: h.agent}

	addrs, err := resolver.LookupTunnel(context.Background(), labTunnelID, "nothing-here")
	if err != nil || len(addrs) != 0 {
		t.Errorf("a name that network does not serve = %v, %v; want no addresses and no failure", addrs, err)
	}

	h.wireguards.devicesFor(labTunnelID)[0].failsToResolve(errors.New("the resolver is unreachable"))
	if _, err := resolver.LookupTunnel(context.Background(), labTunnelID, "db"); err == nil {
		t.Error("a resolver that could not be reached was reported as a name that does not exist")
	}
}

// The three ways there is nothing to ask, told apart from each other. Each has a different
// right answer, and collapsing them into one would either cache "no such name" through an
// outage or leave a program waiting on a resolver that was never going to be reached.
func TestANameThatCannotBeAskedOfAnythingSaysWhichKindOfNothingItIs(t *testing.T) {
	h, _ := carryingFabric(t, labRange)
	resolver := fabricResolver{a: h.agent}

	// A connection that is configured and not running. The name may well exist; this machine
	// has no way to ask, and reporting it as "no such name" would be a fact it does not have.
	if _, err := resolver.LookupTunnel(context.Background(), "tn_not_running", "db"); err == nil {
		t.Error("a name on a connection that is not running was answered rather than reported")
	}

	// And the mode going off between the routing decision and the lookup, which is a machine
	// that has just stopped being able to reach the name rather than one saying it does not
	// exist.
	if err := h.agent.currentFabric().close(); err != nil {
		t.Fatalf("stop carrying the connections: %v", err)
	}
	if _, err := resolver.LookupTunnel(context.Background(), labTunnelID, "db"); err == nil {
		t.Error("a name was answered by a machine that is no longer reaching its connections")
	}
}

// A network that publishes no resolver of its own -- a WireGuard peer with no DNS= line.
// Nothing anywhere knows its names, so no name on it exists: an answer rather than a failure,
// and a failure here would have every program retrying a lookup that can never succeed.
func TestANameOnANetworkWithNoResolverOfItsOwnDoesNotExistRatherThanFails(t *testing.T) {
	h, _ := carryingFabricWith(t, labRange, func(c *config.Config) {
		for i := range c.Tunnels {
			if c.Tunnels[i].ID == labTunnelID {
				c.Tunnels[i].WireGuard.DNS = nil
			}
		}
	})

	addrs, err := fabricResolver{a: h.agent}.LookupTunnel(context.Background(), labTunnelID, "db")
	if err != nil || len(addrs) != 0 {
		t.Errorf("a name on a network with no resolver = %v, %v; want no addresses and no failure", addrs, err)
	}
}

// An address a network answered with and never said it carries has nowhere to go on this
// machine. Handing it back untranslated is the one thing that must not happen: those
// addresses belong to whichever connection kept them here.
func TestAnAddressTheNetworkDoesNotCarryIsRefusedRatherThanPassedThrough(t *testing.T) {
	h, _ := carryingFabric(t, labRange)
	h.wireguards.devicesFor(labTunnelID)[0].serves("db", netip.MustParseAddr("192.0.2.7"))

	got, err := fabricResolver{a: h.agent}.LookupTunnel(context.Background(), labTunnelID, "db")
	if err == nil {
		t.Fatalf("db.lab.internal = %v with no failure, want the answer refused", got)
	}
	if len(got) != 0 {
		t.Errorf("db.lab.internal = %v alongside a failure, want nothing", got)
	}
}

// A reverse lookup for an address app-tail invented must not leave this machine. Nothing
// anywhere holds a name for it, and both resolvers it would otherwise go to -- this
// network's own and the chosen profile -- are being told an address that only exists here.
func TestAReverseLookupForAMovedNetworkIsAnsweredHere(t *testing.T) {
	h, _ := carryingFabric(t, officeRange)

	rules := h.agent.systemDNSTarget(context.Background()).rules
	moved := movedPrefix(t, h, labTunnelID)
	if len(rules.VirtualPrefixes) != 1 || rules.VirtualPrefixes[0].Prefix != moved {
		t.Fatalf("the ranges app-tail invented = %v, want exactly %s", rules.VirtualPrefixes, moved)
	}
	if rules.VirtualPrefixes[0].Name != "Lab" {
		t.Errorf("the range stands for %q, want the connection's name", rules.VirtualPrefixes[0].Name)
	}

	addr := moved.Addr().Next()
	decision := dnsfwd.Route(dnsfwd.Question{
		Name: reverseName(addr), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET,
	}, rules)
	if decision.Target != dnsfwd.Here || decision.RCode != dnsmessage.RCodeNameError {
		t.Errorf("routing = %s/%s (%s), want answered here -- no resolver holds that name",
			decision.Target, decision.RCode, decision.Reason)
	}
}

// Which connections the resolver is told this machine reaches by address. It is what decides
// between answering a name on a connection and refusing it, so a connection missing from it
// is one whose names stop working while it is up.
func TestOnlyTheConnectionsOneInterfaceCarriesAreAnsweredFor(t *testing.T) {
	h, _ := carryingFabricWith(t, labRange, func(c *config.Config) {
		off := config.NewTunnel("tn_spare", "spare", "Spare", config.TunnelWireGuard)
		off.Enabled = false
		off.WireGuard = &config.WireGuardTunnel{
			PrivateKey: "majYatxGzfGESWHzcaf6Y+ldZ1CHNgfXsieg+falAgw=",
			Addresses:  []netip.Prefix{netip.MustParsePrefix("172.20.0.4/24")},
			MTU:        config.DefaultWireGuardMTU,
			Peer: config.WireGuardPeer{
				PublicKey:  "Ry0M2rNVGGQrrmJKKIY0F0EySFf9r0mAJvpDCkzQeGE=",
				Endpoint:   "spare.example.com:51820",
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("172.20.0.0/16")},
			},
		}
		c.Tunnels = append(c.Tunnels, off)
	})

	carried := map[string]bool{}
	for _, s := range h.agent.systemDNSTarget(context.Background()).rules.TunnelSuffixes {
		carried[s.ID] = s.Carried
	}
	// The tailnet is among them: the interface carries the ranges it addresses its devices
	// from, so a name on it resolves to an address this machine can reach.
	for _, id := range []string{wgTunnelID, labTunnelID, config.PrimaryTunnelID} {
		if !carried[id] {
			t.Errorf("%s is not answered for, so every name on it fails while it is up", id)
		}
	}
	// A connection that is switched off has no mapping on the interface, so its names have
	// nowhere to point and answering for them would resolve to an address that goes nowhere.
	if carried["tn_spare"] {
		t.Error("a connection that is switched off is answered for, so its names resolve to " +
			"addresses nothing carries")
	}
}

// movedPrefix is where this machine reaches one connection's network, and fails the test
// when that connection was not moved at all.
func movedPrefix(t *testing.T, h *harness, id string) netip.Prefix {
	t.Helper()
	table, _ := h.agent.fabricAddressing()
	if table == nil {
		t.Fatal("nothing is carrying the connections, so no addressing was installed")
	}
	for _, m := range table.Mappings() {
		if m.TunnelID == id && m.Moved() {
			return m.PresentedAs
		}
	}
	t.Fatalf("%s was not moved; the addressing is %v", id, table.Mappings())
	return netip.Prefix{}
}

// reverseName is the in-addr.arpa name a reverse lookup for one address asks for.
func reverseName(addr netip.Addr) string {
	octets := addr.As4()
	parts := make([]string, 0, 4)
	for i := len(octets) - 1; i >= 0; i-- {
		parts = append(parts, strconv.Itoa(int(octets[i])))
	}
	return strings.Join(parts, ".") + ".in-addr.arpa"
}
