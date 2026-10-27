// SPDX-License-Identifier: MIT

package dnsfwd

import (
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func question(name string, typ dnsmessage.Type) Question {
	return Question{ID: 1, Name: name, Type: typ, Class: dnsmessage.ClassINET}
}

func TestRouteSendsEachKindOfNameWhereItCanBeAnswered(t *testing.T) {
	rules := Rules{
		LocalSuffixes: []string{".corp.example.com."},
		SearchDomains: []string{"lan"},
		HaveLocal:     true,
	}
	tests := []struct {
		name  string
		q     Question
		want  Target
		about string
	}{
		{"ordinary name", question("example.com", dnsmessage.TypeA), ToProfile, "the whole point of the feature"},
		{"root", question("", dnsmessage.TypeNS), ToProfile, "the root is nobody's private zone"},
		{"single label", question("printer", dnsmessage.TypeA), ToLocal, "no resolver on the internet knows it"},
		{"mdns name", question("nas.local", dnsmessage.TypeA), ToLocal, "multicast DNS belongs to this link"},
		{"listed suffix", question("server.corp.example.com", dnsmessage.TypeA), ToLocal, "the user said so"},
		{"suffix lookalike", question("notcorp.example.com", dnsmessage.TypeA), ToProfile, "suffixes match by label"},
		{"search domain", question("nas.lan", dnsmessage.TypeA), ToLocal, "this network published it"},
		{"private reverse", question("1.6.168.192.in-addr.arpa", dnsmessage.TypePTR), ToLocal, "only the router knows"},
		{"partial private reverse", question("168.192.in-addr.arpa", dnsmessage.TypeNS), ToLocal, "a delegation walk"},
		{"tailnet reverse", question("1.0.64.100.in-addr.arpa", dnsmessage.TypePTR), ToLocal, "the tailnet range"},
		{"public reverse", question("8.8.8.8.in-addr.arpa", dnsmessage.TypePTR), ToProfile, "a public address"},
		{"ula reverse", question("0.0.d.f.ip6.arpa", dnsmessage.TypePTR), ToLocal, "a unique local address"},
		{"public v6 reverse", question("1.0.0.2.ip6.arpa", dnsmessage.TypePTR), ToProfile, "a public v6 address"},
		{"reverse apex", question("in-addr.arpa", dnsmessage.TypeSOA), ToProfile, "the zone itself is public"},
		{"apple captive check", question("captive.apple.com", dnsmessage.TypeA), ToLocal, "the portal answers it"},
		{"windows captive check", question("www.msftncsi.com", dnsmessage.TypeA), ToLocal, "the portal answers it"},
		{"localhost", question("localhost", dnsmessage.TypeA), Localhost, "RFC 6761"},
		{"under localhost", question("app.localhost", dnsmessage.TypeA), Localhost, "RFC 6761"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Route(tc.q, rules)
			if got.Target != tc.want {
				t.Errorf("Route(%s) = %s (%s), want %s -- %s", tc.q, got.Target, got.Reason, tc.want, tc.about)
			}
			if got.Reason == "" {
				t.Error("the decision carries no reason, and the reason is what a user asks for")
			}
		})
	}
}

func TestRouteAnswersHereWhatNoResolverCanAnswer(t *testing.T) {
	chaos := Question{ID: 1, Name: "version.bind", Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassCHAOS}
	got := Route(chaos, Rules{HaveLocal: true})
	if got.Target != Here || got.RCode != dnsmessage.RCodeNotImplemented {
		t.Errorf("Route(chaos) = %s/%s, want here/NOTIMP", got.Target, got.RCode)
	}

	bad := question("a..b", dnsmessage.TypeA)
	if got := Route(bad, Rules{HaveLocal: true}); got.Target != Here || got.RCode != dnsmessage.RCodeFormatError {
		t.Errorf("Route(empty label) = %s/%s, want here/FORMERR", got.Target, got.RCode)
	}
}

// With no resolver from the network, a private name has one remaining chance of being
// answered. Dropping it instead would make a machine mid-network-change resolve nothing.
func TestWithNoLocalResolverPrivateNamesGoToTheProfile(t *testing.T) {
	rules := Rules{SearchDomains: []string{"lan"}, HaveLocal: false}
	for _, name := range []string{"printer", "nas.lan", "1.6.168.192.in-addr.arpa", "nas.local"} {
		got := Route(question(name, dnsmessage.TypeA), rules)
		if got.Target != ToProfile {
			t.Errorf("Route(%s) = %s, want profile when this network published no resolver", name, got.Target)
		}
	}
	// The loopback zone is still not forwarded: it is answered here, resolver or not.
	if got := Route(question("app.localhost", dnsmessage.TypeA), rules); got.Target != Localhost {
		t.Errorf("Route(app.localhost) = %s, want localhost", got.Target)
	}
}

// A name on one of app-tail's own connections is answered here or not at all. The profile
// would answer it with somebody else's address, which is the failure the whole naming
// convention exists to prevent, so this pins that no such name ever leaves this machine.
func TestANameOnAConnectionIsAnsweredHereAndNeverForwarded(t *testing.T) {
	rules := Rules{
		LocalSuffixes:  []string{"office.internal"},
		SearchDomains:  []string{"lan"},
		TunnelSuffixes: []TunnelSuffix{{Suffix: "office.internal", Name: "Office"}},
		HaveLocal:      true,
	}
	tests := []struct {
		name  string
		q     Question
		want  Target
		about string
	}{
		{"host on it", question("db.office.internal", dnsmessage.TypeA), Here, "only app-tail reaches that network"},
		{"deeper host", question("db.eu.office.internal", dnsmessage.TypeA), Here, "every name under the suffix is on it"},
		{"the suffix itself", question("office.internal", dnsmessage.TypeA), Here, "the connection's own name is on it too"},
		{"a lookalike", question("notoffice.internal", dnsmessage.TypeA), ToProfile, "suffixes match by label"},
		{"the zone above it", question("internal", dnsmessage.TypeA), ToLocal, "no connection claims the zone itself"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Route(tc.q, rules)
			if got.Target != tc.want {
				t.Errorf("Route(%s) = %s (%s), want %s -- %s", tc.q, got.Target, got.Reason, tc.want, tc.about)
			}
			if tc.want != Here {
				return
			}
			if got.RCode != dnsmessage.RCodeNameError {
				t.Errorf("Route(%s) answered %s, want NXDOMAIN -- the name does not exist out here", tc.q, got.RCode)
			}
			if !strings.Contains(got.Reason, "Office") {
				t.Errorf("the reason %q does not name the connection, which is what a user asks for", got.Reason)
			}
		})
	}
}

// The fallback that sends a private name to the profile when this network published no
// resolver must not reach these names: there is no worse answer to fall back to, only a
// wrong one.
func TestAConnectionsNamesDoNotFallBackToTheProfile(t *testing.T) {
	rules := Rules{
		TunnelSuffixes: []TunnelSuffix{{Suffix: "office.internal", Name: "Office"}},
		HaveLocal:      false,
	}
	if got := Route(question("db.office.internal", dnsmessage.TypeA), rules); got.Target != Here {
		t.Errorf("Route = %s (%s), want here even with no local resolver", got.Target, got.Reason)
	}
}

// Both orders, because the answer must come from which suffix is more specific and not
// from where it sits in the list: taking the first match or the last one gets this right
// half the time, which is a connection reached under another connection's name.
func TestTheLongestConnectionSuffixNamesTheConnection(t *testing.T) {
	broad := TunnelSuffix{Suffix: "office.internal", Name: "Office"}
	narrow := TunnelSuffix{Suffix: "eu.office.internal", Name: "Office EU"}
	for _, order := range [][]TunnelSuffix{{broad, narrow}, {narrow, broad}} {
		t.Run(order[0].Name+" first", func(t *testing.T) {
			rules := Rules{TunnelSuffixes: order, HaveLocal: true}
			got := Route(question("db.eu.office.internal", dnsmessage.TypeA), rules)
			if !strings.Contains(got.Reason, narrow.Name) {
				t.Errorf("the reason %q does not name %s, so the more specific connection is unreachable",
					got.Reason, narrow.Name)
			}
		})
	}
}

func TestAConnectionSuffixIsReadWhateverItsCaseAndDots(t *testing.T) {
	rules := Rules{
		TunnelSuffixes: []TunnelSuffix{{Suffix: " .Office.Internal. "}},
		HaveLocal:      true,
	}
	got := Route(question("db.office.internal", dnsmessage.TypeA), rules)
	if got.Target != Here {
		t.Errorf("Route = %s, want here -- a suffix typed with dots and capitals is the same connection", got.Target)
	}
	if !strings.Contains(got.Reason, "office.internal") {
		t.Errorf("the reason %q names an unnamed connection by nothing; the suffix is what is left to name it by", got.Reason)
	}
}

// The difference the interface mode makes to a name. With one interface carrying the
// connection, an address on it means something to every program on this machine, so the name
// is answered instead of refused -- and the name asked inside the network is the one that
// network knows the host by, with app-tail's own suffix taken off. Asking it for the whole
// name would ask a private resolver about a zone app-tail invented, which it answers with
// nothing.
func TestANameOnACarriedConnectionIsResolvedInsideIt(t *testing.T) {
	rules := Rules{
		TunnelSuffixes: []TunnelSuffix{
			{Suffix: "office.internal", Name: "Office", ID: "tn_office", Carried: true},
			{Suffix: "lab.internal", Name: "Lab", ID: "tn_lab"},
		},
		HaveLocal: true,
	}
	tests := []struct {
		name       string
		q          Question
		want       Target
		wantTunnel string
		wantHost   string
		about      string
	}{
		{"host on a carried connection", question("db.office.internal", dnsmessage.TypeA), ToTunnel, "tn_office", "db",
			"the network is reachable here, so the name has an address to be answered with"},
		{"deeper host", question("db.eu.office.internal", dnsmessage.TypeAAAA), ToTunnel, "tn_office", "db.eu",
			"every label below the suffix belongs to the network's own name for the host"},
		{"host on a connection nothing carries", question("db.lab.internal", dnsmessage.TypeA), Here, "", "",
			"nothing on this machine routes it, so the name does not exist out here"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Route(tc.q, rules)
			if got.Target != tc.want {
				t.Fatalf("Route(%s) = %s (%s), want %s -- %s", tc.q, got.Target, got.Reason, tc.want, tc.about)
			}
			if got.Tunnel != tc.wantTunnel {
				t.Errorf("Route(%s) asks connection %q, want %q", tc.q, got.Tunnel, tc.wantTunnel)
			}
			if got.Host != tc.wantHost {
				t.Errorf("Route(%s) asks that network for %q, want %q -- %s", tc.q, got.Host, tc.wantHost, tc.about)
			}
			if tc.want == Here && got.RCode != dnsmessage.RCodeNameError {
				t.Errorf("Route(%s) answered %s, want NXDOMAIN", tc.q, got.RCode)
			}
		})
	}
}

// The connection's own suffix names the connection, not a host on it, so there is no host to
// ask its network about. Sending an empty name into a private resolver asks it for its own
// root, and whatever came back would be answered as if it were the connection.
func TestAConnectionsOwnNameIsNotResolvedInsideIt(t *testing.T) {
	rules := Rules{
		TunnelSuffixes: []TunnelSuffix{{Suffix: "office.internal", Name: "Office", ID: "tn_office", Carried: true}},
		HaveLocal:      true,
	}
	got := Route(question("office.internal", dnsmessage.TypeA), rules)
	if got.Target != Here || got.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("Route = %s/%s (%s), want here with NXDOMAIN", got.Target, got.RCode, got.Reason)
	}
	if got.Host != "" || got.Tunnel != "" {
		t.Errorf("Route asked %q of connection %q; the suffix alone names no host", got.Host, got.Tunnel)
	}
	if !strings.Contains(got.Reason, "Office") {
		t.Errorf("the reason %q does not name the connection, which is what a user asks for", got.Reason)
	}
}

// A moved network is reached at addresses app-tail invented, and a reverse lookup for one of
// them has exactly one true answer: nothing holds a name for it. The arm has to come first,
// because the pool is configurable -- inside 10.0.0.0/8 the private-reverse arm would send
// the question to this network's resolver, and in the default pool nothing calls the range
// private at all, so it would go to a public one. Both would be told an address that only
// exists on this machine.
func TestAReverseLookupForAMovedNetworkNeverLeavesThisMachine(t *testing.T) {
	rules := Rules{
		VirtualPrefixes: []VirtualPrefix{
			{Prefix: netip.MustParsePrefix("198.18.0.0/16"), Name: "Office"},
			{Prefix: netip.MustParsePrefix("10.80.0.0/16"), Name: "Lab"},
		},
		HaveLocal: true,
	}
	tests := []struct {
		name  string
		q     Question
		want  Target
		who   string
		about string
	}{
		{"an address in the default pool", question("5.4.18.198.in-addr.arpa", dnsmessage.TypePTR), Here, "Office",
			"nothing calls 198.18.0.0/15 private, so this would otherwise go to a public resolver"},
		{"an address inside a private range", question("5.4.80.10.in-addr.arpa", dnsmessage.TypePTR), Here, "Lab",
			"a pool inside 10.0.0.0/8 would otherwise be asked of this network's own resolver"},
		{"a private address that is nobody's virtual range", question("5.4.3.10.in-addr.arpa", dnsmessage.TypePTR), ToLocal, "",
			"the ordinary private reverse lookup still belongs to this network"},
		{"a public address", question("5.113.0.203.in-addr.arpa", dnsmessage.TypePTR), ToProfile, "",
			"an address nothing here claims is an ordinary question"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Route(tc.q, rules)
			if got.Target != tc.want {
				t.Fatalf("Route(%s) = %s (%s), want %s -- %s", tc.q, got.Target, got.Reason, tc.want, tc.about)
			}
			if tc.who == "" {
				return
			}
			if got.RCode != dnsmessage.RCodeNameError {
				t.Errorf("Route(%s) answered %s, want NXDOMAIN -- no resolver holds that name", tc.q, got.RCode)
			}
			if !strings.Contains(got.Reason, tc.who) {
				t.Errorf("the reason %q does not name %s, so a user reading it cannot tell which network the address stands for", got.Reason, tc.who)
			}
		})
	}
}

// A partial reverse name is what a resolver walks up while delegating, and it covers a whole
// range rather than one address. It must be caught by the same arm: sending the delegation
// question for a virtual range to a public resolver tells it the range exists here.
func TestAPartialReverseNameOverAMovedNetworkIsCaught(t *testing.T) {
	rules := Rules{
		VirtualPrefixes: []VirtualPrefix{{Prefix: netip.MustParsePrefix("198.18.0.0/16"), Name: "Office"}},
		HaveLocal:       true,
	}
	if got := Route(question("18.198.in-addr.arpa", dnsmessage.TypeNS), rules); got.Target != Here {
		t.Errorf("Route = %s (%s), want here -- the delegation question covers the moved range", got.Target, got.Reason)
	}
}

func TestSuffixRulesIgnoreCaseAndSurroundingDots(t *testing.T) {
	rules := Rules{LocalSuffixes: []string{"  .Corp.Example.COM. "}, HaveLocal: true}
	if got := Route(question("host.corp.example.com", dnsmessage.TypeA), rules); got.Target != ToLocal {
		t.Errorf("Route = %s, want local -- a suffix typed with dots and capitals is the same rule", got.Target)
	}
}
