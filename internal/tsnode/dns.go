// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TailnetLookup is what the tailnet's own resolver said about a name. No addresses means
// the tailnet does not serve that name -- a definite answer, not a failure.
type TailnetLookup struct {
	// Addrs are the addresses answered, in the order they arrived.
	Addrs []netip.Addr
	// TTL is the shortest time to live in the answer, which is how long the addresses
	// may be reused before asking again. Zero when nothing was answered.
	TTL time.Duration
}

// Served reports that the tailnet's resolver knows this name.
func (l TailnetLookup) Served() bool { return len(l.Addrs) > 0 }

// LookupTailnet resolves host through the tailnet's own resolver.
//
// This is the only resolver that knows about a split-DNS domain -- one the admin console
// points at a private nameserver -- and, once an exit node offering DoH is in use, the
// only one whose queries leave through that exit node. A name it does not serve comes
// back with no addresses rather than an error: the tailnet answering "not mine" is an
// answer, and the caller resolves it the ordinary way.
func (n *Node) LookupTailnet(ctx context.Context, host string) (TailnetLookup, error) {
	if !n.Status().Running() {
		return TailnetLookup{}, ErrNotRunning
	}
	lc := n.client()
	if lc == nil {
		return TailnetLookup{}, ErrNotRunning
	}
	return lookupAddrs(ctx, host, func(ctx context.Context, name, queryType string) ([]byte, error) {
		raw, _, err := lc.QueryDNS(ctx, name, queryType)
		return raw, err
	})
}

// lookupAddrs asks one resolver for a name's addresses. The resolver is a parameter so
// this holds the whole decision -- which questions, in which order, and what an
// unanswered name means -- without a tailnet behind it.
func lookupAddrs(ctx context.Context, host string, query func(ctx context.Context, name, queryType string) ([]byte, error)) (TailnetLookup, error) {
	// A and AAAA are separate questions on the wire. IPv4 is asked for first and taken
	// when it answers, so the common case is one round trip.
	for _, queryType := range []string{"A", "AAAA"} {
		raw, err := query(ctx, host, queryType)
		if err != nil {
			return TailnetLookup{}, fmt.Errorf("asking the tailnet's resolver for %s: %w", host, err)
		}
		lookup, err := addressAnswers(raw)
		if err != nil {
			return TailnetLookup{}, fmt.Errorf("reading the tailnet's answer for %s: %w", host, err)
		}
		if lookup.Served() {
			return lookup, nil
		}
	}
	return TailnetLookup{}, nil
}

// addressAnswers pulls the addresses out of a DNS response.
//
// A response carrying no addresses -- an empty answer section, NXDOMAIN, or the SERVFAIL
// the backend returns for a name no configured resolver covers -- is an answer of "not
// served here" rather than a parse failure, so it comes back as an empty lookup.
func addressAnswers(raw []byte) (TailnetLookup, error) {
	var parser dnsmessage.Parser
	if _, err := parser.Start(raw); err != nil {
		return TailnetLookup{}, err
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return TailnetLookup{}, err
	}

	var lookup TailnetLookup
	for {
		header, err := parser.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return lookup, nil
		}
		if err != nil {
			return TailnetLookup{}, err
		}

		var addr netip.Addr
		switch header.Type {
		case dnsmessage.TypeA:
			record, err := parser.AResource()
			if err != nil {
				return TailnetLookup{}, err
			}
			addr = netip.AddrFrom4(record.A)
		case dnsmessage.TypeAAAA:
			record, err := parser.AAAAResource()
			if err != nil {
				return TailnetLookup{}, err
			}
			addr = netip.AddrFrom16(record.AAAA)
		default:
			// A CNAME chain is answered alongside the address it leads to, so skipping
			// what is not an address still leaves the addresses.
			if err := parser.SkipAnswer(); err != nil {
				return TailnetLookup{}, err
			}
			continue
		}

		lookup.Addrs = append(lookup.Addrs, addr)
		ttl := time.Duration(header.TTL) * time.Second
		if lookup.TTL == 0 || ttl < lookup.TTL {
			lookup.TTL = ttl
		}
	}
}
