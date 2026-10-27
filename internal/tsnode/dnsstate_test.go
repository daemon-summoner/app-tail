// SPDX-License-Identifier: MIT

package tsnode

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
)

// Split-DNS suffixes are the whole reason this panel exists: they are the names that
// resolve inside app-tail and nowhere else on the machine. A suffix claimed with no
// resolver of its own is a different thing from one pointed at a private nameserver --
// the first is answered by the tailnet, the second by a server on someone's network --
// and a panel that rendered them alike would answer the user's question wrongly.
func TestSplitDNSSuffixesArriveWithWhoeverAnswersForThem(t *testing.T) {
	got := tailnetDNSFrom(&tailcfg.DNSConfig{
		Proxied:   true,
		Resolvers: []*dnstype.Resolver{{Addr: "1.1.1.1"}, {Addr: "https://dns.example/dns-query"}},
		Domains:   []string{"tail1234.ts.net"},
		Routes: map[string][]*dnstype.Resolver{
			"corp.example.com": {{Addr: "10.0.0.53"}},
			"acme.internal":    nil,
		},
	})

	if !got.MagicDNS {
		t.Error("MagicDNS reports off for a tailnet that has it on, so peer names look unresolvable")
	}
	if len(got.Resolvers) != 2 || got.Resolvers[0] != "1.1.1.1" ||
		got.Resolvers[1] != "https://dns.example/dns-query" {
		t.Errorf("Resolvers = %v, want the tailnet's own two in order", got.Resolvers)
	}
	if len(got.Domains) != 1 || got.Domains[0] != "tail1234.ts.net" {
		t.Errorf("Domains = %v, want the tailnet's search domain", got.Domains)
	}

	// Sorted, so the panel does not reshuffle on every poll of a map.
	if len(got.Routes) != 2 {
		t.Fatalf("%d split-DNS routes reported, want both", len(got.Routes))
	}
	if got.Routes[0].Suffix != "acme.internal" || got.Routes[1].Suffix != "corp.example.com" {
		t.Errorf("routes = %q, %q, want them in a stable order",
			got.Routes[0].Suffix, got.Routes[1].Suffix)
	}
	if got.Routes[0].Resolvers != nil {
		t.Errorf("a suffix the tailnet answers for itself reports resolvers %v, want none",
			got.Routes[0].Resolvers)
	}
	if len(got.Routes[1].Resolvers) != 1 || got.Routes[1].Resolvers[0] != "10.0.0.53" {
		t.Errorf("Resolvers = %v, want the private nameserver the suffix points at",
			got.Routes[1].Resolvers)
	}
}

// The extra records are names the tailnet serves that are not peers, so a name that
// resolves without any device behind it is otherwise unexplainable.
func TestTheNamesTheTailnetServesBeyondItsPeersArriveWhole(t *testing.T) {
	got := tailnetDNSFrom(&tailcfg.DNSConfig{
		ExtraRecords: []tailcfg.DNSRecord{
			{Name: "wiki.example.com", Value: "100.64.0.4"},
			{Name: "mail.example.com", Type: "CNAME", Value: "box.tail1234.ts.net"},
		},
	})

	if len(got.Records) != 2 {
		t.Fatalf("%d extra records reported, want both", len(got.Records))
	}
	if got.Records[0].Name != "wiki.example.com" || got.Records[0].Value != "100.64.0.4" {
		t.Errorf("record = %+v, want the name and the address it answers with", got.Records[0])
	}
	if got.Records[0].Type != "" {
		t.Errorf("Type = %q for an address record, want it left empty", got.Records[0].Type)
	}
	if got.Records[1].Type != "CNAME" {
		t.Errorf("Type = %q, want the record type the tailnet gave", got.Records[1].Type)
	}
}

// A resolver entry the backend could not fill carries no address. Reporting it would put
// a blank nameserver on the panel, which reads as a configuration that failed to load
// rather than as one entry of several being unusable.
func TestAResolverWithNoAddressIsLeftOutRatherThanReportedBlank(t *testing.T) {
	got := tailnetDNSFrom(&tailcfg.DNSConfig{
		Resolvers: []*dnstype.Resolver{nil, {Addr: "1.1.1.1"}},
	})

	if len(got.Resolvers) != 1 || got.Resolvers[0] != "1.1.1.1" {
		t.Errorf("Resolvers = %q, want only the one that carries an address", got.Resolvers)
	}
}

// The configuration reaching the panel comes from the backend, not from a value the
// process already held: a read that returned the tailnet's own answer but dropped it on
// the way out would leave every panel empty on a working tailnet.
func TestTheTailnetsPublishedDNSArrivesFromTheBackend(t *testing.T) {
	n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/localapi/v0/dns-config" {
			t.Errorf("the tailnet's DNS was read from %s", r.URL.Path)
		}
		return jsonResponse(`{"Proxied":true,"Domains":["tail1234.ts.net"],
			"Resolvers":[{"Addr":"100.100.100.100"}]}`), nil
	})

	got, err := n.TailnetDNS(t.Context())
	if err != nil {
		t.Fatalf("read the tailnet's DNS configuration: %v", err)
	}
	if !got.MagicDNS {
		t.Error("MagicDNS reports off for a tailnet that published it on")
	}
	if len(got.Resolvers) != 1 || got.Resolvers[0] != "100.100.100.100" {
		t.Errorf("Resolvers = %q, want the tailnet's own", got.Resolvers)
	}
	if len(got.Domains) != 1 || got.Domains[0] != "tail1234.ts.net" {
		t.Errorf("Domains = %q, want the tailnet's search domain", got.Domains)
	}
}

// Before the first netmap there is no configuration at all. MagicDNS must read off there:
// claiming peer names resolve before the tailnet has said whether they do sends a user
// looking for a network fault instead of waiting for the node to finish connecting.
func TestNoTailnetConfigurationYetClaimsNothingResolves(t *testing.T) {
	got := tailnetDNSFrom(nil)

	if got.MagicDNS {
		t.Error("MagicDNS reports on before the tailnet has said anything")
	}
	if got.Resolvers != nil || got.Domains != nil || got.Routes != nil || got.Records != nil {
		t.Errorf("an absent configuration produced %+v, want nothing", got)
	}

	// A tailnet that published a configuration with MagicDNS turned off is the other way
	// to reach the same claim, and it is the one a user actually chooses in the admin
	// console. Reporting it on would tell them peer names resolve when they do not.
	off := tailnetDNSFrom(&tailcfg.DNSConfig{Resolvers: []*dnstype.Resolver{{Addr: "1.1.1.1"}}})
	if off.MagicDNS {
		t.Error("MagicDNS reports on for a tailnet that turned it off")
	}
}

// Userspace mode writes no resolv.conf, no scutil entry and no NRPT rule, so the backend
// reports it has no OS configuration to give. That is the expected answer and it has to
// arrive as the named condition -- a caller that saw a generic failure would render "DNS
// is broken" for the mode the app ships in by default.
func TestAMachineWhoseDNSAppTailDoesNotManageSaysSoRatherThanFailing(t *testing.T) {
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		return errorResponse(http.StatusInternalServerError, dns.ErrGetBaseConfigNotSupported.Error()), nil
	})

	_, err := n.MachineDNS(t.Context())

	if !errors.Is(err, ErrDNSNotManaged) {
		t.Errorf("reading unmanaged machine DNS = %v, want %v", err, ErrDNSNotManaged)
	}
}

// A backend that failed for any other reason is a real failure and must not be folded
// into "not managed" -- that would render a broken backend as the normal userspace state
// and hide it forever.
func TestARealDNSFailureIsNotMistakenForAnUnmanagedMachine(t *testing.T) {
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		return errorResponse(http.StatusInternalServerError, "the resolver process died"), nil
	})

	_, err := n.MachineDNS(t.Context())

	if err == nil {
		t.Fatal("a backend failure was reported as a readable configuration")
	}
	if errors.Is(err, ErrDNSNotManaged) {
		t.Errorf("error = %v, want a real failure rather than the unmanaged answer", err)
	}
}

// The machine's own configuration is the other half of the side-by-side panel: it is what
// every program other than app-tail resolves with, and the match domains are what say
// which names go to the tailnet instead.
func TestTheMachinesOwnResolverConfigurationArrivesWhole(t *testing.T) {
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		return jsonResponse(`{"Nameservers":["100.100.100.100","1.1.1.1"],
			"SearchDomains":["tail1234.ts.net"],"MatchDomains":["corp.example.com"]}`), nil
	})

	got, err := n.MachineDNS(t.Context())
	if err != nil {
		t.Fatalf("read this machine's DNS configuration: %v", err)
	}
	if len(got.Nameservers) != 2 || got.Nameservers[0] != "100.100.100.100" {
		t.Errorf("Nameservers = %v, want both in order", got.Nameservers)
	}
	if len(got.SearchDomains) != 1 || got.SearchDomains[0] != "tail1234.ts.net" {
		t.Errorf("SearchDomains = %v, want the tailnet's", got.SearchDomains)
	}
	if len(got.MatchDomains) != 1 || got.MatchDomains[0] != "corp.example.com" {
		t.Errorf("MatchDomains = %v, want the domain routed to the tailnet resolver", got.MatchDomains)
	}
}

// Whether the exit node answers DNS is the property people choose an exit node for: with
// it, a lookup does not reveal where the request came from. The claim must track the peer
// rather than the fact that some exit node is selected.
func TestOnlyAnExitNodeThatCanAnswerDNSIsReportedAsAnswering(t *testing.T) {
	tests := []struct {
		name string
		peer *tailcfg.Node
		want bool
	}{
		{"a current peer", &tailcfg.Node{Cap: 90}, true},
		{"exactly the first version that carries it", &tailcfg.Node{Cap: 26}, true},
		{"a peer too old to carry it", &tailcfg.Node{Cap: 25}, false},
		{"an old peer advertising the service", &tailcfg.Node{
			Cap:      25,
			Hostinfo: (&tailcfg.Hostinfo{Services: []tailcfg.Service{{Proto: tailcfg.PeerAPIDNS, Port: 1}}}).View(),
		}, true},
		{"an old peer advertising it on no port", &tailcfg.Node{
			Cap:      25,
			Hostinfo: (&tailcfg.Hostinfo{Services: []tailcfg.Service{{Proto: tailcfg.PeerAPIDNS}}}).View(),
		}, false},
		{"an old peer advertising something else", &tailcfg.Node{
			Cap:      25,
			Hostinfo: (&tailcfg.Hostinfo{Services: []tailcfg.Service{{Proto: tailcfg.TCP, Port: 80}}}).View(),
		}, false},
		{"no peer at all", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := peerAnswersDNS(tc.peer); got != tc.want {
				t.Errorf("peerAnswersDNS = %v, want %v", got, tc.want)
			}
		})
	}
}

// No exit node is not a failure, and it must not cost a backend round trip either: the
// dashboard asks on every poll and the ordinary case is no exit node at all.
func TestNoExitNodeAnswersNoDNSWithoutAskingTheBackend(t *testing.T) {
	n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
		t.Errorf("the backend was asked at %s about an exit node that is not in use", r.URL.Path)
		return errorResponse(http.StatusBadRequest, "unreachable"), nil
	})

	got, err := n.ExitNodeAnswersDNS(t.Context(), "")
	if err != nil {
		t.Fatalf("asking about no exit node: %v", err)
	}
	if got {
		t.Error("no exit node is in use and yet one is reported as answering DNS")
	}
}

// A selected exit node the netmap does not carry -- removed, unshared, or filtered by
// tailnet lock -- answers nothing. Reporting that as a failure would put an error on a
// panel whose honest reading is "the node you picked is not there".
func TestAnExitNodeMissingFromTheNetmapAnswersNothing(t *testing.T) {
	n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/localapi/v0/status" {
			return jsonResponse(`{"Peer":{}}`), nil
		}
		t.Errorf("a peer that is not in the netmap was still looked up at %s", r.URL.Path)
		return errorResponse(http.StatusNotFound, "no such peer"), nil
	})

	got, err := n.ExitNodeAnswersDNS(t.Context(), "nGone")
	if err != nil {
		t.Fatalf("asking about an exit node that is not in the netmap: %v", err)
	}
	if got {
		t.Error("an exit node that is not in the netmap is reported as answering DNS")
	}
}

// The selected node is named by its stable id, and the backend is looked up by the
// numeric one. Confusing the two reads another device's capabilities -- or none -- and
// the panel then reports the wrong answer about where lookups go.
func TestTheSelectedExitNodeIsTheOneWhoseCapabilitiesAreRead(t *testing.T) {
	status := fmt.Sprintf(`{"Peer":{
			%q:{"ID":"nOther","NodeID":11},
			%q:{"ID":"nWanted","NodeID":22}}}`, key.NewNode().Public(), key.NewNode().Public())
	var lookedUp string
	n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/localapi/v0/status" {
			return jsonResponse(status), nil
		}
		lookedUp = r.URL.Query().Get("id")
		return jsonResponse(`{"Cap":90}`), nil
	})

	got, err := n.ExitNodeAnswersDNS(t.Context(), "nWanted")
	if err != nil {
		t.Fatalf("asking about the selected exit node: %v", err)
	}
	if lookedUp != "22" {
		t.Errorf("peer %q was read, want the numeric id 22 belonging to nWanted", lookedUp)
	}
	if !got {
		t.Error("an exit node that answers DNS is reported as not answering")
	}
}

// Finding out where lookups go takes two backend reads, and either can fail. Folding a
// failure into "it does not answer DNS" would be indistinguishable from the true answer,
// so each read names itself and the node it was asked about.
func TestAFailedExitNodeReadNamesTheReadRatherThanAnsweringNo(t *testing.T) {
	tests := []struct {
		name    string
		refuse  string
		mention string
	}{
		{"the netmap could not be read", "/localapi/v0/status", "status"},
		{"the peer itself could not be read", "/localapi/v0/peer-by-id", "exit node nWanted"},
	}
	status := fmt.Sprintf(`{"Peer":{%q:{"ID":"nWanted","NodeID":22}}}`, key.NewNode().Public())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
				if strings.HasPrefix(r.URL.Path, tt.refuse) {
					return errorResponse(http.StatusServiceUnavailable, "the backend is not answering"), nil
				}
				return jsonResponse(status), nil
			})

			got, err := n.ExitNodeAnswersDNS(t.Context(), "nWanted")
			if err == nil {
				t.Fatalf("a refused read reported the exit node's DNS answer as %v", got)
			}
			for _, want := range []string{tt.mention, "the backend is not answering"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %v, want it to mention %q", err, want)
				}
			}
		})
	}
}

// Every DNS read must refuse before the node is up rather than panic on a nil client:
// the dashboard polls this whole panel during the window a restart opens.
func TestEveryDNSReadRefusesWhileTheNodeIsDown(t *testing.T) {
	n := newTestNode(t, AuthInteractive, newScriptedBus(), nil)

	if _, err := n.TailnetDNS(t.Context()); !errors.Is(err, ErrNotRunning) {
		t.Errorf("reading the tailnet's DNS while down = %v, want %v", err, ErrNotRunning)
	}
	if _, err := n.MachineDNS(t.Context()); !errors.Is(err, ErrNotRunning) {
		t.Errorf("reading this machine's DNS while down = %v, want %v", err, ErrNotRunning)
	}
	if _, err := n.ExitNodeAnswersDNS(t.Context(), "nSomething"); !errors.Is(err, ErrNotRunning) {
		t.Errorf("asking about an exit node while down = %v, want %v", err, ErrNotRunning)
	}
}

// The reason a read failed is what a user acts on, so it has to name what could not be
// read. A bare backend status leaves nothing to distinguish "the tailnet published no
// DNS" from "the backend is not answering".
func TestAFailedDNSReadNamesWhatCouldNotBeRead(t *testing.T) {
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		return errorResponse(http.StatusServiceUnavailable, "no netmap"), nil
	})

	_, err := n.TailnetDNS(t.Context())
	if err == nil {
		t.Fatal("a backend that has no netmap produced a configuration")
	}
	for _, want := range []string{"tailnet", "DNS", "no netmap"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
}
