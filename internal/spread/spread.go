// SPDX-License-Identifier: MIT

// Package spread decides which of several connections a destination leaves through.
//
// It is one package rather than one copy per mode because the answer has to be the same
// answer everywhere: the interface carrying every network, the proxy and the resolver all
// send this machine's internet traffic out through the same set of connections, and a
// destination that left through one connection under the interface and another under the
// proxy would present as a site that works in one mode and not the other.
//
// Nothing here dials, holds state, or knows what a connection is. It is a hash and a
// choice, so both callers can reach it without either reaching the other.
package spread

import (
	"net/netip"
	"strings"
)

// Pick is the connection a key lands on, by rendezvous hashing: every member is scored
// against the key and the highest score wins.
//
// Rendezvous rather than an index into the list, and that is the whole of the failure
// behaviour. With an index, one member of five going away would move four destinations in
// five to a different connection -- and a moved destination is a live connection cut -- so
// losing one member would cut everything on the machine. Here only the destinations that
// were on the lost member move.
//
// An empty list has no member to pick and returns "".
func Pick(members []string, key uint64) string {
	best, bestScore := "", uint64(0)
	for _, id := range members {
		// Ties are broken by id so the answer never depends on the order the list arrived in.
		if score := mix(key, id); score > bestScore || (score == bestScore && id < best) {
			best, bestScore = id, score
		}
	}
	return best
}

// Key is what a destination is pinned by: the block it is in rather than the address.
//
// A page opens a dozen connections to the addresses one origin resolves to, and giving each
// of them a different way out breaks the things that are pinned to where a session came from
// -- bot-management clearance, IP-bound logins, a site that adapts to the country it thinks
// you are in. Every one of those presents as "the app is flaky" rather than as anything to do
// with this setting. /24 and /48 are what a routing table already carries, so a block is the
// smallest unit that reliably belongs to one operator.
//
// The seed belongs to the machine and is persisted: without it every restart would reshuffle
// which site leaves where, and a session cookie outliving the agent is the ordinary case.
func Key(seed uint64, addr netip.Addr) uint64 {
	addr = addr.Unmap()
	// Sixteen bytes for both families, so an address written either way folds identically:
	// a v4 address sits in the last four, and zeroing from byte 15 drops its last octet for
	// a /24. A v6 address is zeroed from byte 6, which is its /48.
	block := addr.As16()
	from := 6
	if addr.Is4() {
		from = 15
	}
	for i := from; i < len(block); i++ {
		block[i] = 0
	}
	key := seed
	for _, b := range block {
		key = (key ^ uint64(b)) * prime
	}
	return key
}

// KeyName is what a destination reached by name is pinned by: the site rather than the host.
//
// The last two labels, because a page and the API it calls are routinely separate hosts under
// one name, and a provider that sees them arrive from two countries treats them as two
// visitors. Grouping too much only means fewer sites leave by different ways, which nothing
// notices; grouping too little breaks the site, so the coarse reading is the safe one. A name
// under a two-part public suffix groups with its neighbours under that suffix, which is the
// same harmless direction.
//
// The name is folded to lower case first: a host is case-insensitive, and two spellings of one
// site leaving by different ways would be the same breakage arrived at by a typo.
func KeyName(seed uint64, host string) uint64 {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if cut := strings.LastIndexByte(host, '.'); cut > 0 {
		if at := strings.LastIndexByte(host[:cut], '.'); at >= 0 {
			host = host[at+1:]
		}
	}
	key := seed
	for i := range len(host) {
		key = (key ^ uint64(host[i])) * prime
	}
	return key
}

// The FNV-1a constants, written out rather than taken from hash/fnv because the answer has to
// be identical across runs and builds -- a site that changed which connection it left through
// when the app restarted would log people out for no reason -- and because this way nothing
// here allocates.
const (
	offset = 14695981039346656037
	prime  = 1099511628211
)

// SeedFrom is the seed a machine spreads by, derived from its own install identity.
//
// Derived rather than stored, so there is one place the fact lives: the identity is already
// generated once per install and already persisted, and a second field holding a second
// random number would be a second thing that can be lost, copied between machines, or reset
// on its own -- each of which reshuffles which site leaves where.
func SeedFrom(machineID string) uint64 { return mix(0, machineID) }

// mix is the score one member gets for one key.
func mix(key uint64, id string) uint64 {
	h := uint64(offset)
	for i := range 8 {
		h = (h ^ ((key >> (8 * i)) & 0xff)) * prime
	}
	for i := range len(id) {
		h = (h ^ uint64(id[i])) * prime
	}
	return h
}
