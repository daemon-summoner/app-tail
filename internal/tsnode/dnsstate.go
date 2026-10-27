// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

// ErrDNSNotManaged reports that this machine's own resolver configuration cannot be read
// because app-tail does not manage it.
//
// It is the expected answer in userspace mode, not a failure: nothing here writes
// resolv.conf, scutil or NRPT, so there is no managed configuration to report. A caller
// renders it as "app-tail does not change how this machine resolves names", which is the
// answer to why a browser cannot reach a name the tailnet serves.
var ErrDNSNotManaged = errors.New("app-tail does not manage this machine's DNS configuration")

// TailnetDNS is the DNS configuration the tailnet publishes, in stdlib types.
//
// It is what the tailnet's own resolver answers with, and -- in userspace mode -- it
// applies to nothing but the resolver inside this process. Showing it next to MachineDNS
// is what makes "why doesn't my browser resolve foo.corp" answerable.
type TailnetDNS struct {
	// MagicDNS reports the tailnet resolving peer names. Off means even the in-process
	// resolver only knows the names the tailnet's own nameservers serve.
	MagicDNS bool `json:"magicDNS"`
	// Resolvers are the tailnet's nameservers, in order of preference, as addresses or
	// DoH URLs.
	Resolvers []string `json:"resolvers,omitempty"`
	// Domains are the search domains the tailnet publishes.
	Domains []string `json:"domains,omitempty"`
	// Routes are the split-DNS suffixes: a domain the admin console points at a
	// particular nameserver. These are the names that resolve here and nowhere else on
	// the machine, which is exactly the surprise a DNS panel exists to explain. Sorted
	// by suffix so the list does not reshuffle between polls.
	Routes []DNSRoute `json:"routes,omitempty"`
	// Records are the extra names the tailnet serves beyond its peers.
	Records []DNSRecord `json:"records,omitempty"`
}

// DNSRoute is one split-DNS suffix and the nameservers that answer for it.
type DNSRoute struct {
	// Suffix is the domain, without a leading dot.
	Suffix string `json:"suffix"`
	// Resolvers answer for the suffix. Empty means the tailnet's own resolver answers,
	// which is how a suffix is claimed without redirecting it anywhere.
	Resolvers []string `json:"resolvers,omitempty"`
}

// DNSRecord is one name the tailnet serves in addition to its peers.
type DNSRecord struct {
	Name string `json:"name"`
	// Type is the record type; empty means an address record.
	Type  string `json:"type,omitempty"`
	Value string `json:"value"`
}

// MachineDNS is what this machine's own resolver is configured with.
type MachineDNS struct {
	Nameservers   []string `json:"nameservers,omitempty"`
	SearchDomains []string `json:"searchDomains,omitempty"`
	// MatchDomains are the domains routed to the tailnet resolver rather than to the
	// nameservers above.
	MatchDomains []string `json:"matchDomains,omitempty"`
}

// TailnetDNS reads the DNS configuration the tailnet publishes.
//
// It comes from the netmap the backend already holds, so it costs one local round trip
// and nothing is kept between calls.
func (n *Node) TailnetDNS(ctx context.Context) (TailnetDNS, error) {
	lc := n.client()
	if lc == nil {
		return TailnetDNS{}, ErrNotRunning
	}
	cfg, err := lc.DNSConfig(ctx)
	if err != nil {
		return TailnetDNS{}, fmt.Errorf("read the tailnet's DNS configuration: %w", err)
	}
	return tailnetDNSFrom(cfg), nil
}

// tailnetDNSFrom projects the backend's value; separate from the call so every decision
// it makes is reachable without a tailnet.
func tailnetDNSFrom(cfg *tailcfg.DNSConfig) TailnetDNS {
	if cfg == nil {
		// No netmap yet. Reporting an empty configuration is honest -- nothing is known
		// -- and MagicDNS must read off rather than on, or the panel claims peer names
		// resolve before the tailnet has said whether they do.
		return TailnetDNS{}
	}
	out := TailnetDNS{
		MagicDNS:  cfg.Proxied,
		Resolvers: resolverAddrs(cfg.Resolvers),
		Domains:   append([]string(nil), cfg.Domains...),
	}
	for suffix, resolvers := range cfg.Routes {
		out.Routes = append(out.Routes, DNSRoute{Suffix: suffix, Resolvers: resolverAddrs(resolvers)})
	}
	// Map iteration order is random, so an unsorted list would reshuffle on every poll
	// and the panel would never stop redrawing.
	sort.Slice(out.Routes, func(i, j int) bool { return out.Routes[i].Suffix < out.Routes[j].Suffix })
	for _, r := range cfg.ExtraRecords {
		out.Records = append(out.Records, DNSRecord{Name: r.Name, Type: r.Type, Value: r.Value})
	}
	return out
}

func resolverAddrs(resolvers []*dnstype.Resolver) []string {
	out := make([]string, 0, len(resolvers))
	for _, r := range resolvers {
		if r == nil {
			continue
		}
		out = append(out, r.Addr)
	}
	if len(out) == 0 {
		// A suffix with no resolvers means the tailnet's own resolver answers for it,
		// and that distinction is carried by the empty list rather than by a zero-length
		// non-nil one a caller cannot tell from "none were readable".
		return nil
	}
	return out
}

// MachineDNS reads what this machine's own resolver is configured with.
//
// It reports ErrDNSNotManaged when app-tail does not manage the machine's DNS, which is
// the case in userspace mode and is the expected answer rather than a failure.
func (n *Node) MachineDNS(ctx context.Context) (MachineDNS, error) {
	lc := n.client()
	if lc == nil {
		return MachineDNS{}, ErrNotRunning
	}
	cfg, err := lc.GetDNSOSConfig(ctx)
	if err != nil {
		// The backend reports this as text rather than a typed error across the local
		// API, so the sentinel's own message is what identifies it.
		if isDNSUnmanaged(err) {
			return MachineDNS{}, ErrDNSNotManaged
		}
		return MachineDNS{}, fmt.Errorf("read this machine's DNS configuration: %w", err)
	}
	return MachineDNS{
		Nameservers:   append([]string(nil), cfg.Nameservers...),
		SearchDomains: append([]string(nil), cfg.SearchDomains...),
		MatchDomains:  append([]string(nil), cfg.MatchDomains...),
	}, nil
}

// isDNSUnmanaged reports the backend saying it has no OS configuration to give. The
// error must be non-nil, which is the only way its caller reaches it.
//
// The local API carries the reason as a plain-text body, so the wrapped error is not the
// sentinel itself and errors.Is alone would miss it. The sentinel is still referenced by
// value rather than by a copied string, so a rename upstream fails this build.
func isDNSUnmanaged(err error) bool {
	return errors.Is(err, dns.ErrGetBaseConfigNotSupported) ||
		strings.Contains(err.Error(), dns.ErrGetBaseConfigNotSupported.Error())
}

// ExitNodeAnswersDNS reports whether the exit node with the given stable ID answers DNS
// for this device.
//
// This is the property people choose an exit node for: with it true, names that are not
// the tailnet's are resolved by the exit node rather than by this machine's resolver, so
// a lookup does not reveal where the request came from. An empty id -- no exit node in
// use -- reports false, which is the honest answer, not an error.
//
// It mirrors the backend's own peerCanProxyDNS test, which is what actually decides
// whether the dialer is pointed at the exit node's resolver.
func (n *Node) ExitNodeAnswersDNS(ctx context.Context, stableID string) (bool, error) {
	if stableID == "" {
		return false, nil
	}
	lc := n.client()
	if lc == nil {
		return false, ErrNotRunning
	}
	st, err := n.fullStatus(ctx)
	if err != nil {
		return false, fmt.Errorf("read the tailnet status to find exit node %s: %w", stableID, err)
	}
	var id tailcfg.NodeID
	for _, peer := range st.Peer {
		if string(peer.ID) == stableID {
			id = peer.NodeID
			break
		}
	}
	if id == 0 {
		// The selected exit node is not in this device's netmap -- shared out, removed,
		// or filtered by tailnet lock. It answers nothing, and saying so is the point.
		return false, nil
	}
	peer, err := lc.PeerByID(ctx, id)
	if err != nil {
		return false, fmt.Errorf("read exit node %s: %w", stableID, err)
	}
	return peerAnswersDNS(peer), nil
}

// peerAnswersDNS mirrors the backend's peerCanProxyDNS: capability version 26 and above
// carries the DNS proxy unconditionally, and older peers advertise it as a service.
func peerAnswersDNS(peer *tailcfg.Node) bool {
	if peer == nil {
		return false
	}
	if peer.Cap >= 26 {
		return true
	}
	if peer.Hostinfo.Valid() {
		for _, s := range peer.Hostinfo.Services().All() {
			if s.Proto == tailcfg.PeerAPIDNS && s.Port >= 1 {
				return true
			}
		}
	}
	return false
}
