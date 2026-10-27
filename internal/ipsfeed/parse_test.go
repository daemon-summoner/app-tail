// SPDX-License-Identifier: MIT

package ipsfeed

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// The shape of a real feed, which is what every one of these files is: comments at the top,
// networks and bare addresses mixed, and a reason written after some of the entries.
func TestAFeedIsReadIntoNetworksAndTheRestIsCounted(t *testing.T) {
	body := []byte("# FireHOL level 1\n" +
		"; another comment marker\n" +
		"\n" +
		"1.2.3.0/24\n" +
		"5.6.7.8\n" +
		"9.9.9.9 # seen attacking ssh\n" +
		"not-an-address\n" +
		"2001:db8::/32\n")

	entries, skipped := Parse(body)

	want := []string{"1.2.3.0/24", "5.6.7.8/32", "9.9.9.9/32", "2001:db8::/32"}
	if !slices.Equal(entries, want) {
		t.Errorf("entries = %v, want %v", entries, want)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (the line that is not an address)", skipped)
	}
}

// Several of these feeds are served with CRLF line endings. A carriage return left on the end
// makes every address fail to parse, which reads as a feed that downloaded and holds nothing.
func TestAFeedServedWithCarriageReturnsIsReadTheSameWay(t *testing.T) {
	entries, skipped := Parse([]byte("# a comment\r\n1.2.3.0/24\r\n5.6.7.8\r\n"))

	want := []string{"1.2.3.0/24", "5.6.7.8/32"}
	if !slices.Equal(entries, want) {
		t.Errorf("entries = %v, want %v", entries, want)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
}

// The reason Reserved exists. FireHOL level 1 and every bogon feed legitimately carry the
// private ranges, and app-tail carries traffic to exactly those networks: applied literally in
// prevent mode this feed would refuse the LAN, the tailnet and this machine talking to itself.
func TestTheRangesThisMachineCarriesTrafficToAreNeverPutInForce(t *testing.T) {
	body := []byte(strings.Join([]string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"1.2.3.0/24",
	}, "\n"))

	entries, skipped := Parse(body)

	if !slices.Equal(entries, []string{"1.2.3.0/24"}) {
		t.Errorf("entries = %v, want only the one network that is not reserved", entries)
	}
	if skipped != 12 {
		t.Errorf("skipped = %d, want 12", skipped)
	}
}

// The entry that contains every reserved range without being inside any of them. Containment
// would let it through; overlap is what catches it.
func TestAFeedThatNamesEverythingIsRefusedRatherThanApplied(t *testing.T) {
	entries, skipped := Parse([]byte("0.0.0.0/0\n::/0\n"))

	if len(entries) != 0 {
		t.Errorf("entries = %v, want none: a feed naming every address would refuse everything", entries)
	}
	if skipped != 2 {
		t.Errorf("skipped = %d, want 2", skipped)
	}
}

// A tailnet address in a feed is the same hazard as a private one, and where the tailnet lives
// is read from the library rather than written out here.
func TestATailnetAddressInAFeedIsNeverPutInForce(t *testing.T) {
	if !Reserved(netip.MustParsePrefix("100.100.100.100/32")) {
		t.Error("a tailnet address was accepted from a feed; it would refuse the tailnet itself")
	}
	if !Reserved(netip.MustParsePrefix("fd7a:115c:a1e0::/48")) {
		t.Error("a tailnet IPv6 network was accepted from a feed")
	}
	if Reserved(netip.MustParsePrefix("1.2.3.0/24")) {
		t.Error("an ordinary public network was refused")
	}
	if !Reserved(netip.Prefix{}) {
		t.Error("a network that did not parse was accepted")
	}
}

// The matcher unmaps before it looks anything up, so an entry left in the ::ffff: form would
// sit in the table where nothing ever asks: an entry that reads as applied and is not.
func TestAnIPv4NetworkWrittenAsIPv6IsStoredWhereTheMatcherLooks(t *testing.T) {
	entries, skipped := Parse([]byte("::ffff:1.2.3.0/120\n::ffff:5.6.7.8\n"))

	want := []string{"1.2.3.0/24", "5.6.7.8/32"}
	if !slices.Equal(entries, want) {
		t.Errorf("entries = %v, want %v", entries, want)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
}

// A network wider than the IPv4 space it contains means nothing as an IPv4 network, and
// keeping it would put a rule in force that covers far more than what was written.
func TestAMappedNetworkWiderThanTheAddressesItHoldsIsRefused(t *testing.T) {
	entries, skipped := Parse([]byte("::ffff:0:0/64\n"))

	if len(entries) != 0 {
		t.Errorf("entries = %v, want none", entries)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
}

// Host bits left set make two spellings of one network, and the matcher would then hold both.
func TestANetworkWithHostBitsSetIsStoredMasked(t *testing.T) {
	entries, _ := Parse([]byte("1.2.3.4/24\n"))

	if !slices.Equal(entries, []string{"1.2.3.0/24"}) {
		t.Errorf("entries = %v, want the masked form", entries)
	}
}

// Nothing downloaded is not the same as a feed of comments: both hold no entries, and only one
// of them is a body worth replacing the copy on disk with. Parse reports the difference through
// the counts rather than an error.
func TestABodyThatIsAllCommentsYieldsNothingAndCountsNothing(t *testing.T) {
	entries, skipped := Parse([]byte("# nothing here\n\n; nor here\n"))

	if len(entries) != 0 {
		t.Errorf("entries = %v, want none", entries)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0: a comment is not a line that failed", skipped)
	}
}

// A captive portal answers every request with a login page, which parses as a file full of
// junk rather than as a failure. Every line counting as skipped is what the caller reads to
// refuse it.
func TestAPageOfHTMLIsEveryLineSkippedAndNoEntries(t *testing.T) {
	entries, skipped := Parse([]byte("<html>\n<body>Sign in to continue</body>\n</html>\n"))

	if len(entries) != 0 {
		t.Errorf("entries = %v, want none", entries)
	}
	if skipped == 0 {
		t.Error("a page of HTML was read as an empty feed rather than as junk")
	}
}

// A hostile feed body is bounded on this side. A flood of comment lines yields no entries,
// so the entry slice's first guess is what it costs: the cap on that guess -- not the number
// of lines -- is what Parse may allocate beyond the lines the split already holds.
func TestACommentFloodAllocatesNoMoreThanTheCappedGuess(t *testing.T) {
	flood := strings.Repeat("# filler line a hostile server may send\n", 1<<20)
	entries, skipped := Parse([]byte(flood))

	if len(entries) != 0 {
		t.Errorf("entries = %v, want none", entries)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0: every line is a comment", skipped)
	}
	if cap(entries) > 1<<12 {
		t.Errorf("cap(entries) = %d, want at most the %d-slot documented cap: a body of "+
			"comments must not be paid for twice", cap(entries), 1<<12)
	}
}

// One huge line is the other shape a hostile body takes. It is one skipped line, not a
// blow-up: nothing in Parse holds a copy of the line beyond the split's own.
func TestOneHugeLineIsOneSkippedLine(t *testing.T) {
	huge := strings.Repeat("A", 16<<20)
	entries, skipped := Parse([]byte(huge))

	if len(entries) != 0 {
		t.Errorf("entries = %v, want none", entries)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
}
