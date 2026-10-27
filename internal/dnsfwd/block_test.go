// SPDX-License-Identifier: MIT

package dnsfwd

// Where a blocked name is decided, and what the machine is told about it.

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// blockList blocks the names it was built with and records every name it was asked about,
// which is what pins where in the routing switch the block check sits.
type blockList struct {
	names map[string]string
	asked []string
}

func blocking(names ...string) *blockList {
	list := &blockList{names: make(map[string]string, len(names))}
	for _, n := range names {
		list.names[n] = "Test list"
	}
	return list
}

func (b *blockList) Blocks(name string) (string, bool) {
	b.asked = append(b.asked, name)
	list, ok := b.names[name]
	return list, ok
}

// The placement rule, pinned: a name this network, the loopback zone or one of app-tail's
// own connections answers for is never subject to a list downloaded off the internet. A
// list carrying "router" or a local domain would otherwise take out the names this machine
// needs to reach the network it is on.
func TestALocalNameIsNeverBlockedHoweverTheListNamesIt(t *testing.T) {
	rules := carryingRules()
	rules.LocalSuffixes = []string{"corp.example.com"}
	rules.SearchDomains = []string{"lan"}
	rules.Block = blocking(
		"router", "nas.local", "server.corp.example.com", "printer.lan",
		"localhost", "app.localhost", "1.6.168.192.in-addr.arpa", "db.office.internal",
		"ads.example.com",
	)

	tests := []struct {
		name  string
		query string
		want  Target
		about string
	}{
		{"a single label", "router", ToLocal, "no resolver on the internet knows it"},
		{"a multicast-DNS name", "nas.local", ToLocal, "it belongs to this link"},
		{"a domain listed as local", "server.corp.example.com", ToLocal, "the user said so"},
		{"a search domain", "printer.lan", ToLocal, "this network published it"},
		{"localhost", "localhost", Localhost, "RFC 6761"},
		{"under localhost", "app.localhost", Localhost, "RFC 6761"},
		{"a private reverse lookup", "1.6.168.192.in-addr.arpa", ToLocal, "only the router knows"},
		{"a name on a carried connection", "db.office.internal", ToTunnel, "app-tail answers it itself"},
		{"an ordinary name", "ads.example.com", Blocked, "this is the one the list is for"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Route(question(tc.query, dnsmessage.TypeA), rules)

			if got.Target != tc.want {
				t.Errorf("Route(%s) = %s (%s), want %s -- %s", tc.query, got.Target, got.Reason, tc.want, tc.about)
			}
		})
	}
}

func TestABlockedNameSaysWhichListStoppedIt(t *testing.T) {
	rules := Rules{HaveLocal: true, Block: blocking("ads.example.com")}

	got := Route(question("ads.example.com", dnsmessage.TypeA), rules)

	if got.Target != Blocked {
		t.Fatalf("Route = %s (%s), want blocked", got.Target, got.Reason)
	}
	if got.List != "Test list" {
		t.Errorf("List = %q, want the list a card and a CLI can name", got.List)
	}
	if !strings.Contains(got.Reason, "Test list") {
		t.Errorf("Reason = %q, which does not say where the block came from", got.Reason)
	}
}

// Nil is the switch being off and also every moment before the first list has been read.
// Both have to route exactly as they did before this feature existed.
func TestNoBlocklistLeavesEveryDecisionExactlyWhereItWas(t *testing.T) {
	rules := Rules{HaveLocal: true}

	got := Route(question("ads.example.com", dnsmessage.TypeA), rules)

	if got.Target != ToProfile {
		t.Errorf("Route = %s (%s), want the profile: no list means nothing is blocked", got.Target, got.Reason)
	}
}

// Three shapes, one meaning. They differ in what the program that asked does next, which
// is why the shape is the user's choice.
func TestABlockedNameIsAnsweredInTheShapeTheUserChose(t *testing.T) {
	tests := []struct {
		name   string
		answer BlockAnswer
		typ    dnsmessage.Type
		code   dnsmessage.RCode
		addrs  []netip.Addr
	}{
		{"no such name", AnswerNXDomain, dnsmessage.TypeA, dnsmessage.RCodeNameError, nil},
		{"refused", AnswerRefused, dnsmessage.TypeA, dnsmessage.RCodeRefused, nil},
		{
			"a sinkhole for v4", AnswerSinkhole, dnsmessage.TypeA, dnsmessage.RCodeSuccess,
			[]netip.Addr{netip.MustParseAddr("0.0.0.0")},
		},
		{
			"a sinkhole for v6", AnswerSinkhole, dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess,
			[]netip.Addr{netip.IPv6Unspecified()},
		},
		{"a sinkhole for anything else", AnswerSinkhole, dnsmessage.TypeMX, dnsmessage.RCodeSuccess, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			profile := answering("profile", "203.0.113.5")
			f := newTestForwarder(t, Config{
				Rules: Rules{
					HaveLocal:   true,
					Block:       blocking("ads.example.com"),
					BlockAnswer: tc.answer,
				},
				Profile: NewPool([]Upstream{profile}, nil),
			})

			resp := f.Answer(context.Background(), buildQuery(t, "ads.example.com", tc.typ), false)

			if code, _ := rcode(resp); code != tc.code {
				t.Errorf("rcode = %s, want %s", code, tc.code)
			}
			if got := addressesIn(t, resp); len(got) != len(tc.addrs) {
				t.Errorf("addresses = %v, want %v", got, tc.addrs)
			} else {
				for i, addr := range got {
					if addr != tc.addrs[i] {
						t.Errorf("address %d = %s, want %s", i, addr, tc.addrs[i])
					}
				}
			}
			if asked := profile.questions(); len(asked) != 0 {
				t.Errorf("the profile was asked %v; a blocked name is answered here or it is not blocked", asked)
			}
		})
	}
}

func TestBlockedQueriesAreCountedSoTheCardCanSayTheyHappened(t *testing.T) {
	f := newTestForwarder(t, Config{
		Rules:   Rules{HaveLocal: true, Block: blocking("ads.example.com")},
		Profile: NewPool([]Upstream{answering("profile", "203.0.113.5")}, nil),
	})

	f.Answer(context.Background(), buildQuery(t, "ads.example.com", dnsmessage.TypeA), false)
	f.Answer(context.Background(), buildQuery(t, "ads.example.com", dnsmessage.TypeAAAA), false)
	f.Answer(context.Background(), buildQuery(t, "example.org", dnsmessage.TypeA), false)

	stats := f.Stats()
	if stats.Blocked != 2 {
		t.Errorf("Blocked = %d, want 2", stats.Blocked)
	}
	if stats.AnsweredHere < 2 {
		t.Errorf("AnsweredHere = %d; a blocked name was answered here and counts as such", stats.AnsweredHere)
	}
}

func TestParseBlockAnswerFallsBackToTheOneEveryFilteringResolverUses(t *testing.T) {
	tests := map[string]BlockAnswer{
		"nxdomain": AnswerNXDomain,
		"sinkhole": AnswerSinkhole,
		"refused":  AnswerRefused,
		"":         AnswerNXDomain,
		"nonsense": AnswerNXDomain,
	}
	for stored, want := range tests {
		if got := ParseBlockAnswer(stored); got != want {
			t.Errorf("ParseBlockAnswer(%q) = %s, want %s", stored, got, want)
		}
	}
}

// The reason a blocked name carries says which shape it was answered with, so the word has
// to be the one the setting is written with rather than a number.
func TestABlockAnswerSaysItselfInTheWordTheSettingUses(t *testing.T) {
	for _, want := range []string{"nxdomain", "sinkhole", "refused"} {
		if got := ParseBlockAnswer(want).String(); got != want {
			t.Errorf("ParseBlockAnswer(%q).String() = %q, want %q", want, got, want)
		}
	}
}
