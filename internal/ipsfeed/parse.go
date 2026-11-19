// SPDX-License-Identifier: MIT

package ipsfeed

import (
	"bytes"
	"net/netip"
	"strings"

	"github.com/sellitus/app-tail/internal/tsnode"
)

// Parse reads a downloaded feed into the entries the matcher takes, and reports how many
// lines yielded nothing.
//
// The shape it accepts is what every feed of this kind is: one address or one network per
// line, blank lines, and comments introduced by # or ;. Several of these files are served
// with CRLF line endings, so the carriage return is stripped rather than becoming part of an
// address that then fails to parse.
//
// Skipped counts the lines that produced no entry, whether they were junk, a network Reserved
// refused, or one too wide for a feed to carry. It is shown beside the entry count on the card, where the pair
// answers "is this feed pulling its weight here".
func Parse(body []byte) (entries []string, skipped int) {
	// maxEntryPrealloc is the most entry slots Parse guesses at before it has read a line.
	// It is the documented cap on what a hostile body -- a flood of comments, or of lines
	// too short to be a network -- can make this side allocate beyond the body itself.
	const maxEntryPrealloc = 1 << 12
	entries = make([]string, 0, min(bytes.Count(body, []byte("\n"))+1, maxEntryPrealloc))
	// The body is walked a line at a time and never split: a split costs a string header per
	// line, and a body of bare line endings would spend sixteen times the download cap on them.
	for line := range bytes.Lines(body) {
		text := string(bytes.TrimSpace(line))
		// The comment marker is honoured mid-line as well: FireHOL writes the reason for an
		// entry after it, and DShield writes the attack count.
		if cut := strings.IndexAny(text, "#;"); cut >= 0 {
			text = strings.TrimSpace(text[:cut])
		}
		if text == "" {
			continue
		}
		prefix, ok := parseLine(text)
		if !ok || Reserved(prefix) || tooWide(prefix) {
			skipped++
			continue
		}
		entries = append(entries, prefix.String())
	}
	return entries, skipped
}

// parseLine reads one line as a network. A bare address is the prefix holding only it, so
// "1.2.3.4" and "1.2.3.4/32" are one entry written two ways.
func parseLine(text string) (netip.Prefix, bool) {
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return canonical(prefix)
	}
	if addr, err := netip.ParseAddr(text); err == nil {
		at := addr.Unmap()
		return netip.PrefixFrom(at, at.BitLen()), true
	}
	return netip.Prefix{}, false
}

// canonical puts a parsed network in the one form the matcher looks up in: masked, and
// written as IPv4 where it is IPv4 wearing an IPv6 address.
//
// The second half matters because the lookup unmaps before it asks. A network left in the
// ::ffff: form would sit in the table where nothing ever looks, which is an entry that reads
// as applied and is not.
func canonical(prefix netip.Prefix) (netip.Prefix, bool) {
	addr := prefix.Addr()
	if addr.Is4In6() {
		if prefix.Bits() < 96 {
			// The network is wider than the IPv4 space it contains, so there is no IPv4
			// network that means the same thing.
			return netip.Prefix{}, false
		}
		prefix = netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked(), true
}

// The widest network a feed may put in force, as the fewest bits its prefix may have.
//
// A feed names hosts and the networks they sit in. The widest allocation any registry hands
// out is a /8 of IPv4 and a /16 of IPv6, so anything wider belongs to nobody a feed could be
// describing: it is a typing mistake or a feed somebody else now writes, and in prevent mode
// it refuses a slice of the internet.
const (
	minBitsV4 = 8
	minBitsV6 = 16
)

// tooWide reports a network wider than any a feed may put in force.
func tooWide(prefix netip.Prefix) bool {
	if prefix.Addr().Is4() {
		return prefix.Bits() < minBitsV4
	}
	return prefix.Bits() < minBitsV6
}

// reserved is every network a downloaded feed may not put in force.
//
// This is not tidiness. FireHOL level 1 and the bogon feeds legitimately contain the private
// ranges, the carrier-grade range and loopback, because they are lists of networks that must
// never appear on the public internet -- and app-tail carries traffic to exactly those
// networks. A feed applied literally in prevent mode would refuse the tailnet, the LAN this
// machine is on, and this machine talking to itself, within seconds of being switched on.
//
// The carrier-grade range is here twice over: it is where every tailnet address lives.
var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// Reserved reports a network no downloaded feed may put in force.
//
// Overlap rather than containment: a feed entry of 0.0.0.0/0 contains every reserved range
// without being inside any of them, and applying it would refuse every connection this
// machine makes.
func Reserved(prefix netip.Prefix) bool {
	if !prefix.IsValid() {
		return true
	}
	for _, r := range reserved {
		if r.Overlaps(prefix) {
			return true
		}
	}
	// Read from the library rather than written out above, so an upstream change to where
	// tailnet addresses live cannot leave a stale constant deciding what is refused here.
	for _, r := range tsnode.TailnetRanges() {
		if r.Overlaps(prefix) {
			return true
		}
	}
	return false
}
