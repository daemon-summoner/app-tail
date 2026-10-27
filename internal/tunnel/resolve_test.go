// SPDX-License-Identifier: MIT

package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// reachingTunnel is a fakeTunnel that also answers where a destination would go. What it
// carries is a fixed table, which is enough to reach every arm of Resolve without a socket.
type reachingTunnel struct {
	fakeTunnel
	carries map[string]netip.AddrPort
	// resolves is what this connection says an address is, whether or not it carries it.
	// It stands in for a connection with a resolver of its own.
	resolves map[string]netip.AddrPort
	err      error
	// reached is every destination this connection was asked about. Asking is not free of
	// consequence: a real connection answers by putting the name to the network's own
	// resolver, so a destination that reaches here has been disclosed to that network
	// whether or not anything is ever dialled.
	reached []string
}

func (r *reachingTunnel) Reach(_ context.Context, _, address string) (Reach, error) {
	r.reached = append(r.reached, address)
	if r.err != nil {
		return Reach{}, r.err
	}
	if addr, ok := r.carries[address]; ok {
		return Reach{Addr: addr, Carried: true}, nil
	}
	return Reach{Addr: r.resolves[address]}, nil
}

func reaching(id string, carries map[string]netip.AddrPort) *reachingTunnel {
	return &reachingTunnel{fakeTunnel: fakeTunnel{id: id}, carries: carries}
}

func mustAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return addr
}

// The whole reason the question moved off the tunnel and onto the registry: with several
// networks the answer is not "does this go via the tailnet" but "which of these carries it".
func TestResolveNamesTheConnectionThatCarriesTheDestination(t *testing.T) {
	r := NewRegistry()
	office := reaching("tn_office", map[string]netip.AddrPort{
		"db.corp:5432": mustAddrPort(t, "10.0.0.5:5432"),
	})
	lab := reaching("tn_lab", map[string]netip.AddrPort{
		"ci.lab:443": mustAddrPort(t, "10.9.9.9:443"),
	})
	mustAdd(t, r, office, lab)

	route, err := r.Resolve(context.Background(), "tcp", "ci.lab:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.TunnelID != "tn_lab" {
		t.Errorf("TunnelID = %q, want the connection that carries it", route.TunnelID)
	}
	if route.Tunnel != Tunnel(lab) {
		t.Error("the route does not carry the connection itself, so a caller cannot dial through it")
	}
	if route.Addr != mustAddrPort(t, "10.9.9.9:443") {
		t.Errorf("Addr = %v, want the address that connection resolved", route.Addr)
	}
	if route.Direct() {
		t.Error("a carried destination reads as leaving through this machine's own network")
	}
}

// Overlapping address space is the case the whole design exists for. Nothing here merges
// two answers or guesses: the connection the user listed first wins, so the tie-break is
// visible in the configuration rather than in this code.
func TestTwoConnectionsCarryingOneAddressAreDecidedByDeclarationOrder(t *testing.T) {
	contested := "10.0.0.5:5432"
	first := reaching("tn_first", map[string]netip.AddrPort{contested: mustAddrPort(t, contested)})
	second := reaching("tn_second", map[string]netip.AddrPort{contested: mustAddrPort(t, contested)})

	forward := NewRegistry()
	mustAdd(t, forward, first, second)
	route, err := forward.Resolve(context.Background(), "tcp", contested)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.TunnelID != "tn_first" {
		t.Errorf("TunnelID = %q, want the connection declared first", route.TunnelID)
	}

	// The same two, listed the other way round. If order were not the tie-break this would
	// answer identically, and a user reordering the list would change nothing.
	reverse := NewRegistry()
	mustAdd(t, reverse, second, first)
	route, err = reverse.Resolve(context.Background(), "tcp", contested)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.TunnelID != "tn_second" {
		t.Errorf("TunnelID = %q, want the connection declared first in this order", route.TunnelID)
	}
}

// A destination nothing carries is a destination on this machine, and it has to be named as
// such: a rule granting access to this machine's own network is matched on that id, so
// reporting an empty one would leave the grant unmatchable.
func TestADestinationNoConnectionCarriesIsThisMachine(t *testing.T) {
	r := NewRegistry()
	office := reaching("tn_office", nil)
	office.resolves = map[string]netip.AddrPort{"example.test:443": mustAddrPort(t, "93.184.216.34:443")}
	mustAdd(t, r, office)

	route, err := r.Resolve(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.TunnelID != ThisMachine {
		t.Errorf("TunnelID = %q, want the sentinel for this machine", route.TunnelID)
	}
	if !route.Direct() {
		t.Error("Direct is false for a destination nothing carries")
	}
	if route.Tunnel != nil {
		t.Error("a route to this machine names a connection, so a caller would dial through it")
	}
	if route.Addr != mustAddrPort(t, "93.184.216.34:443") {
		t.Errorf("Addr = %v, want the address that was already resolved", route.Addr)
	}
}

// A connection still coming up must not make every other one unreachable. Passing it over
// is what keeps a proxy working while one of several networks reconnects.
func TestAConnectionThatCannotAnswerIsPassedOver(t *testing.T) {
	r := NewRegistry()
	down := reaching("tn_down", nil)
	down.err = errors.New("this connection is not up")
	office := reaching("tn_office", map[string]netip.AddrPort{
		"db.corp:5432": mustAddrPort(t, "10.0.0.5:5432"),
	})
	mustAdd(t, r, down, office)

	route, err := r.Resolve(context.Background(), "tcp", "db.corp:5432")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.TunnelID != "tn_office" {
		t.Errorf("TunnelID = %q, want the connection that is up", route.TunnelID)
	}
}

// When nothing could answer and this machine cannot resolve it either, both halves are
// reported: a connection that is down is a temporary fault and a name that does not exist is
// not, and they are fixed in completely different places.
func TestAFailureNamesBothTheConnectionAndTheLookup(t *testing.T) {
	r := NewRegistry()
	down := reaching("tn_down", nil)
	down.err = errors.New("this connection is not up")
	mustAdd(t, r, down)
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		return netip.AddrPort{}, errors.New("no such host")
	})

	_, err := r.Resolve(context.Background(), "tcp", "nowhere.test:443")

	if err == nil {
		t.Fatal("a destination nothing could resolve came back without an error")
	}
	if !strings.Contains(err.Error(), "tn_down") {
		t.Errorf("the refusal does not name the connection that could not answer: %v", err)
	}
	if !strings.Contains(err.Error(), "no such host") {
		t.Errorf("the refusal does not carry this machine's own answer: %v", err)
	}
}

// A registry holding nothing still has to answer, because a proxy may be configured to
// reach this machine and nothing else -- which is a real, useful grant.
func TestWithNoConnectionsEverythingResolvesThroughThisMachine(t *testing.T) {
	r := NewRegistry()
	r.SetHostResolver(func(_ context.Context, _, address string) (netip.AddrPort, error) {
		if address != "printer.local:9100" {
			t.Errorf("this machine was asked about %q", address)
		}
		return mustAddrPort(t, "192.168.1.40:9100"), nil
	})

	route, err := r.Resolve(context.Background(), "tcp", "printer.local:9100")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.TunnelID != ThisMachine || route.Addr != mustAddrPort(t, "192.168.1.40:9100") {
		t.Errorf("route = %+v, want this machine's own answer", route)
	}
}

// A tunnel with no way to answer the question is not a tunnel that refuses it. Skipping it
// is what lets a kind of connection ship before it can classify addresses.
func TestATunnelThatCannotBeAskedIsNotConsulted(t *testing.T) {
	r := NewRegistry()
	mustAdd(t, r, &fakeTunnel{id: "tn_silent"})
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		return mustAddrPort(t, "10.1.1.1:22"), nil
	})

	route, err := r.Resolve(context.Background(), "tcp", "host.test:22")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.TunnelID != ThisMachine {
		t.Errorf("TunnelID = %q, want this machine: nothing could say otherwise", route.TunnelID)
	}
}

// The default resolver, with no name to look up. An address literal has to come back as it
// stands: asking a resolver about one is a query that can only fail.
func TestAnAddressLiteralNeedsNoLookup(t *testing.T) {
	got, err := lookupOnThisMachine(context.Background(), "tcp", "10.2.3.4:8080")
	if err != nil {
		t.Fatalf("lookupOnThisMachine: %v", err)
	}
	if got != mustAddrPort(t, "10.2.3.4:8080") {
		t.Errorf("got %v, want the address exactly as it was written", got)
	}
}

// An IPv4-mapped IPv6 literal is the same address written the other way. Left mapped, it
// compares unequal to the plain form in every rule that names a prefix.
func TestAMappedAddressComesBackInItsPlainForm(t *testing.T) {
	got, err := lookupOnThisMachine(context.Background(), "tcp", "[::ffff:10.2.3.4]:8080")
	if err != nil {
		t.Fatalf("lookupOnThisMachine: %v", err)
	}
	if got != mustAddrPort(t, "10.2.3.4:8080") {
		t.Errorf("got %v, want the same address in its plain form", got)
	}
}

func TestADestinationWithNoPortIsRefusedRatherThanGuessedAt(t *testing.T) {
	if _, err := lookupOnThisMachine(context.Background(), "tcp", "example.test"); err == nil {
		t.Fatal("a destination with no port was accepted")
	}
}

// twoOverlappingNetworks is the case this whole convention exists for: two connections
// that both carry 10.0.0.5 and both call it db. Every test below asks for one of them by
// name, which is the only thing that can tell them apart.
func twoOverlappingNetworks(t *testing.T) (*Registry, *reachingTunnel, *reachingTunnel) {
	t.Helper()
	contested := mustAddrPort(t, "10.0.0.5:5432")
	prod := reaching("tn_prod", map[string]netip.AddrPort{"db:5432": contested})
	staging := reaching("tn_staging", map[string]netip.AddrPort{"db:5432": contested})

	r := NewRegistry()
	mustAdd(t, r, prod, staging)
	r.SetNaming(NewNaming(map[string]string{
		"tn_prod":    "prod.internal",
		"tn_staging": "staging.internal",
	}))
	return r, prod, staging
}

// The headline of the whole feature: two networks carrying the same addresses, both
// reachable at once, with nothing switched between them. Declaration order decides an
// address; a name decides itself.
func TestTwoNetworksWithOneAddressAreBothReachableByName(t *testing.T) {
	r, prod, staging := twoOverlappingNetworks(t)

	toProd, err := r.Resolve(context.Background(), "tcp", "db.prod.internal:5432")
	if err != nil {
		t.Fatalf("resolving the production database: %v", err)
	}
	toStaging, err := r.Resolve(context.Background(), "tcp", "db.staging.internal:5432")
	if err != nil {
		t.Fatalf("resolving the staging database: %v", err)
	}

	if toProd.Tunnel != Tunnel(prod) {
		t.Errorf("db.prod.internal is carried by %q", toProd.TunnelID)
	}
	if toStaging.Tunnel != Tunnel(staging) {
		t.Errorf("db.staging.internal is carried by %q", toStaging.TunnelID)
	}
	if toProd.Addr != toStaging.Addr {
		t.Fatalf("the two resolved to %v and %v, so this test is no longer about overlapping addresses",
			toProd.Addr, toStaging.Addr)
	}
}

// A name that named a connection is answered by that connection or not at all. Falling
// through to the others would reach the wrong network at the right address and report
// success, which is precisely the failure the suffix exists to prevent.
func TestANamedConnectionThatCannotAnswerIsNotSubstituted(t *testing.T) {
	r, _, staging := twoOverlappingNetworks(t)
	prod, _ := r.Remove("tn_prod")
	if prod == nil {
		t.Fatal("the production connection was not registered")
	}
	// The other connection still answers for the bare name, so a fall-through would
	// silently succeed against the wrong network.
	if _, ok := staging.carries["db:5432"]; !ok {
		t.Fatal("the remaining connection does not carry the name, so this proves nothing")
	}
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		t.Error("a name on a connection that is not running was looked up on this machine")
		return netip.AddrPort{}, errors.New("unreachable")
	})

	_, err := r.Resolve(context.Background(), "tcp", "db.prod.internal:5432")

	if err == nil {
		t.Fatal("a name on a connection that is not running resolved anyway")
	}
	if !strings.Contains(err.Error(), "not running") {
		t.Errorf("error = %v, want it to say the connection is not running", err)
	}
}

// The other half of the same rule: a connection that answers with an address it does not
// carry has not answered. Dialling it would leave through this machine's own network, to
// an address that means something else there.
func TestANameResolvedToSomethingTheConnectionDoesNotCarryIsRefused(t *testing.T) {
	r, prod, _ := twoOverlappingNetworks(t)
	prod.resolves = map[string]netip.AddrPort{"web:443": mustAddrPort(t, "93.184.216.34:443")}

	_, err := r.Resolve(context.Background(), "tcp", "web.prod.internal:443")

	if err == nil {
		t.Fatal("an address the connection does not carry was returned as a route through it")
	}
	if !strings.Contains(err.Error(), "does not carry") {
		t.Errorf("error = %v, want it to say the connection does not carry that address", err)
	}
}

// The suffix on its own is a connection, not a host on one. Answering it as a host would
// mean asking the network about the empty name.
func TestTheSuffixOnItsOwnIsRefusedWithWhatToWriteInstead(t *testing.T) {
	r, _, _ := twoOverlappingNetworks(t)

	_, err := r.Resolve(context.Background(), "tcp", "prod.internal:5432")

	if err == nil {
		t.Fatal("a connection's own suffix resolved as if it were a host")
	}
	if !strings.Contains(err.Error(), "db.prod.internal") {
		t.Errorf("error = %v, want it to show the shape of a name that would work", err)
	}
}

// A connection asked about a name it does not have is the whole answer, because it is the
// only connection that can answer for that name. Falling back to this machine's resolver
// would ask the public internet about a name that only exists inside a private network.
func TestANameTheNamedConnectionDoesNotHaveIsTheWholeAnswer(t *testing.T) {
	r, _, _ := twoOverlappingNetworks(t)
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		t.Error("a name that named a connection was looked up on this machine as well")
		return netip.AddrPort{}, errors.New("unreachable")
	})

	_, err := r.Resolve(context.Background(), "tcp", "absent.prod.internal:443")

	if err == nil {
		t.Fatal("a name the connection does not have resolved anyway")
	}
	if !strings.Contains(err.Error(), "knows no host called absent") {
		t.Errorf("error = %v, want it to name the host the connection was asked about", err)
	}
}

// A connection that could not be asked at all names both the connection and the host, so a
// reader knows whether to look at the network or at the name. It is the only connection that
// can answer, so the failure is the whole answer rather than a reason to ask the others.
func TestANamedConnectionThatCouldNotBeAskedNamesItselfAndTheHost(t *testing.T) {
	r, prod, _ := twoOverlappingNetworks(t)
	prod.err = errors.New("the resolver inside that network is unreachable")
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		t.Error("a name on a connection that could not be asked was looked up on this machine")
		return netip.AddrPort{}, errors.New("unreachable")
	})

	_, err := r.Resolve(context.Background(), "tcp", "db.prod.internal:5432")

	if err == nil {
		t.Fatal("a connection that could not be asked resolved anyway")
	}
	for _, want := range []string{"db", "prod.internal", "resolver inside that network is unreachable"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to carry %q", err, want)
		}
	}
}

// A connection that names a suffix and cannot be asked about names is refused rather than
// passed over. Passing it over would send the lookup to the other connections, which is the
// wrong-network-right-address failure the suffix exists to prevent.
func TestANamedConnectionThatCannotResolveNamesIsRefusedRatherThanPassedOver(t *testing.T) {
	r := NewRegistry()
	// A plain connection, with no way to be asked where a destination goes.
	mustAdd(t, r, &fakeTunnel{id: "tn_prod"})
	r.SetNaming(NewNaming(map[string]string{"tn_prod": "prod.internal"}))
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		t.Error("a name on a connection that cannot resolve was looked up on this machine")
		return netip.AddrPort{}, errors.New("unreachable")
	})

	_, err := r.Resolve(context.Background(), "tcp", "db.prod.internal:5432")

	if err == nil {
		t.Fatal("a name on a connection that cannot resolve names resolved anyway")
	}
	if !strings.Contains(err.Error(), "cannot resolve names") {
		t.Errorf("error = %v, want it to say the connection cannot be asked", err)
	}
}

// A suffixed destination that is not a host and a port carries no name to match on, so it is
// handled as the shape it is rather than as a name. The refusal comes from the one place that
// reports the shape, which keeps one message for it instead of two that could disagree.
func TestASuffixedDestinationThatIsNotAHostAndAPortIsRefusedAsAShape(t *testing.T) {
	r, _, _ := twoOverlappingNetworks(t)

	for _, address := range []string{"db.prod.internal", "db.prod.internal:https"} {
		if _, err := r.Resolve(context.Background(), "tcp", address); err == nil {
			t.Errorf("%q was accepted as a destination", address)
		}
	}
}

// The machine's own resolver is what answers when nothing else was given, and the two shapes
// it must refuse rather than guess at: a destination with no port, and a port that is not a
// number. Guessing either turns a typo into a connection to somewhere nobody asked for.
func TestThisMachinesOwnResolverRefusesWhatIsNotAnAddressAndAPort(t *testing.T) {
	r := NewRegistry()

	for _, address := range []string{"db.corp", "db.corp:https", "10.0.0.5"} {
		if _, err := r.Resolve(context.Background(), "tcp", address); err == nil {
			t.Errorf("%q was accepted as a destination", address)
		}
	}

	// And an address literal is answered without a lookup at all, which is what makes the
	// registry usable with no resolver reachable.
	route, err := r.Resolve(context.Background(), "tcp", "10.0.0.5:5432")
	if err != nil {
		t.Fatalf("resolving an address literal: %v", err)
	}
	if route.Addr != mustAddrPort(t, "10.0.0.5:5432") || !route.Direct() {
		t.Errorf("route = %+v, want 10.0.0.5:5432 through this machine's own network", route)
	}
}

// The family a lookup asks for comes from the network being dialled. Asking for both when a
// program asked for one hands back an address of the wrong family, which fails on the dial
// with an error about the address rather than about the request.
func TestTheAddressFamilyAskedForComesFromTheNetworkBeingDialled(t *testing.T) {
	cases := []struct {
		network string
		want    string
	}{
		{"tcp4", "ip4"},
		{"udp4", "ip4"},
		{"ip4", "ip4"},
		{"tcp6", "ip6"},
		{"udp6", "ip6"},
		{"ip6", "ip6"},
		{"tcp", "ip"},
		{"udp", "ip"},
		{"", "ip"},
	}
	for _, c := range cases {
		if got := ipNetwork(c.network); got != c.want {
			t.Errorf("a %q dial looks up %q, want %q", c.network, got, c.want)
		}
	}
}

// Everything without a suffix keeps working exactly as it did. The convention adds a way
// to name a connection; it does not take away addresses, bare names or public ones.
func TestANameOnNoConnectionIsResolvedAsItAlwaysWas(t *testing.T) {
	r, prod, _ := twoOverlappingNetworks(t)
	prod.carries["ci.corp:443"] = mustAddrPort(t, "10.0.0.9:443")

	route, err := r.Resolve(context.Background(), "tcp", "ci.corp:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.TunnelID != "tn_prod" {
		t.Errorf("TunnelID = %q, want the connection that carries the unsuffixed name", route.TunnelID)
	}
}

func mustAdd(t *testing.T, r *Registry, tunnels ...Tunnel) {
	t.Helper()
	for _, tun := range tunnels {
		if err := r.Add(tun); err != nil {
			t.Fatalf("Add %s: %v", tun.ID(), err)
		}
	}
}
