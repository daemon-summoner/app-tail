// SPDX-License-Identifier: MIT

package dnsblock

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestParseHostsKeepsTheNamesAndDropsTheFilesOwnBoilerplate(t *testing.T) {
	body := []byte(`
# Title: a hosts file
127.0.0.1 localhost
255.255.255.255 broadcasthost
::1 ip6-localhost ip6-loopback
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.net # inline note
plain-name.example.org
*.wild.example.com
`)

	entries, skipped := ParseHosts(body)

	if skipped != 0 {
		t.Errorf("skipped = %d, want 0: every line here is one a resolver can act on", skipped)
	}
	want := map[string]Match{
		"ads.example.com":        Exact,
		"tracker.example.net":    Exact,
		"plain-name.example.org": Exact,
		"wild.example.com":       Subtree,
	}
	if len(entries) != len(want) {
		t.Fatalf("parsed %d entries (%v), want %d", len(entries), entries, len(want))
	}
	for _, e := range entries {
		match, ok := want[e.Name]
		if !ok {
			t.Errorf("parsed %q, which the file did not ask to block", e.Name)
			continue
		}
		if e.Match != match {
			t.Errorf("%q reaches %v, want %v", e.Name, e.Match, match)
		}
		if e.Allow {
			t.Errorf("%q parsed as an exception; a hosts file has no such thing", e.Name)
		}
	}
}

// A hosts file says what it wants stopped, exactly. Reading each line as though it also
// covered every subdomain would block names its author chose to leave alone.
func TestParseHostsBlocksTheNameWrittenAndNotItsChildren(t *testing.T) {
	entries, _ := ParseHosts([]byte("0.0.0.0 ads.example.com"))

	if len(entries) != 1 || entries[0].Match != Exact {
		t.Fatalf("parsed %v, want one exact rule", entries)
	}
}

func TestParseHostsCountsALineItCouldNotReadRatherThanIgnoringIt(t *testing.T) {
	entries, skipped := ParseHosts([]byte("0.0.0.0 http://example.com/path\n0.0.0.0 real.example.com\n"))

	if skipped != 1 {
		t.Errorf("skipped = %d, want 1: a URL is not a name", skipped)
	}
	if len(entries) != 1 || entries[0].Name != "real.example.com" {
		t.Errorf("parsed %v, want the one line that was a name", entries)
	}
}

func TestParseABPKeepsTheRulesAResolverCanExpress(t *testing.T) {
	body := []byte(`[Adblock Plus 2.0]
! a comment
||ads.example.com^
||tracker.example.net^$important
@@||safe.example.com^
example.org
`)

	entries, skipped := ParseABP(body)

	if skipped != 0 {
		t.Errorf("skipped = %d, want 0: every rule here maps onto a name", skipped)
	}
	type rule struct {
		match Match
		allow bool
	}
	want := map[string]rule{
		"ads.example.com":     {Subtree, false},
		"tracker.example.net": {Subtree, false},
		"safe.example.com":    {Subtree, true},
		"example.org":         {Subtree, false},
	}
	if len(entries) != len(want) {
		t.Fatalf("parsed %d entries (%v), want %d", len(entries), entries, len(want))
	}
	for _, e := range entries {
		w, ok := want[e.Name]
		if !ok {
			t.Errorf("parsed %q, which no rule named", e.Name)
			continue
		}
		if e.Match != w.match || e.Allow != w.allow {
			t.Errorf("%q parsed as %+v, want match %v allow %v", e.Name, e, w.match, w.allow)
		}
	}
}

// The rules a filter list carries for a browser are the majority of a list like EasyList.
// Applying one to a whole domain would block far more than its author wrote, so each is
// counted instead -- which is what lets a card say a list contributed almost nothing.
func TestParseABPCountsEveryRuleOnlyABrowserCouldApply(t *testing.T) {
	tests := []struct {
		name string
		rule string
	}{
		{"a URL path", "||example.com/ads/banner.gif"},
		{"an element-hiding rule", "example.com##.ad-banner"},
		{"an element-hiding exception", "example.com#@#.ad-banner"},
		{"an extended selector", "example.com#?#div:has(> .ad)"},
		{"a third-party scope", "||example.com^$third-party"},
		{"a request type", "||example.com^$script"},
		{"a page scope", "||example.com^$domain=other.example"},
		{"a pattern", "/ad[0-9]+\\.example\\.com/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entries, skipped := ParseABP([]byte(tc.rule))

			if len(entries) != 0 {
				t.Errorf("parsed %v; a resolver cannot express %s", entries, tc.name)
			}
			if skipped != 1 {
				t.Errorf("skipped = %d, want 1: a dropped rule that is not counted is invisible", skipped)
			}
		})
	}
}

func TestDetectReadsAFilesShapeSoAListNeedNotDeclareIt(t *testing.T) {
	tests := []struct {
		name string
		body string
		want Format
	}{
		{"an adblock header", "[Adblock Plus 2.0]\n||ads.example.com^\n", FormatABP},
		{"filter rules with no header", "! comment\n||ads.example.com^\n||more.example.net^\n", FormatABP},
		{"a hosts file", "# Title\n0.0.0.0 ads.example.com\n0.0.0.0 more.example.net\n", FormatHosts},
		{"bare names", "ads.example.com\nmore.example.net\n", FormatHosts},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Detect([]byte(tc.body)); got != tc.want {
				t.Errorf("Detect(%s) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

// A captive portal answers every request with its sign-in page, including the one that
// asked for a blocklist. Storing that as a list of no names would silently switch a list
// off; failing here is what keeps the copy already on disk in force.
func TestParseRefusesABodyThatIsNotAListAtAll(t *testing.T) {
	page := []byte("<!doctype html><html><body><h1>Sign in to use this network</h1></body></html>")

	if _, _, err := Parse(FormatAuto, page); !errors.Is(err, ErrNotAList) {
		t.Fatalf("Parse(a sign-in page) error = %v, want ErrNotAList", err)
	}
}

func TestParseRefusesAFormatItDoesNotKnow(t *testing.T) {
	_, _, err := Parse(Format("rpz"), []byte("0.0.0.0 ads.example.com"))

	if err == nil || !strings.Contains(err.Error(), "rpz") {
		t.Fatalf("Parse(unknown format) error = %v, want one naming the format", err)
	}
}

// Parse is what the fetcher calls, so the format arms and the count of what was dropped
// have to hold there and not only in the two parsers underneath it.
func TestParseReadsEitherFormatAndReportsWhatItCouldNotExpress(t *testing.T) {
	tests := []struct {
		name    string
		format  Format
		body    string
		want    string
		match   Match
		skipped int
	}{
		{"a hosts file", FormatHosts, "0.0.0.0 ads.example.com\n", "ads.example.com", Exact, 0},
		{"a filter list", FormatABP, "[Adblock Plus 2.0]\n||ads.example.com^\nexample.com##.ad\n",
			"ads.example.com", Subtree, 1},
		{"a file that says which it is", FormatAuto, "[Adblock Plus 2.0]\n||ads.example.com^\n",
			"ads.example.com", Subtree, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entries, skipped, err := Parse(tc.format, []byte(tc.body))

			if err != nil {
				t.Fatalf("Parse(%s): %v", tc.name, err)
			}
			if len(entries) != 1 || entries[0].Name != tc.want || entries[0].Match != tc.match {
				t.Errorf("parsed %v, want %q reaching %v", entries, tc.want, tc.match)
			}
			if skipped != tc.skipped {
				t.Errorf("skipped = %d, want %d: a dropped rule that is not counted is invisible",
					skipped, tc.skipped)
			}
		})
	}
}

// Detect reads the head of a file rather than all of it, and a list whose first rules are
// hosts lines is a hosts file however many megabytes follow.
func TestDetectStopsReadingOnceItHasSeenEnough(t *testing.T) {
	var body strings.Builder
	for i := 0; i < maxSniffLines*3; i++ {
		fmt.Fprintf(&body, "0.0.0.0 ads%d.example.com\n", i)
	}
	// Past the sniff limit, so a file that changes shape at the end does not change the
	// answer: the parser for the format detected here accepts both shapes anyway.
	body.WriteString("||late.example.net^\n")

	if got := Detect([]byte(body.String())); got != FormatHosts {
		t.Errorf("Detect = %q, want %q from the head of the file", got, FormatHosts)
	}
}

// Every one of these is a line a list really carries, and each would become a name the
// resolver is asked about if it were kept.
func TestALineThatIsNotANameIsCountedRatherThanBlocked(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{"a label longer than DNS allows", "0.0.0.0 " + strings.Repeat("a", 64) + ".example.com"},
		{"a name longer than DNS allows", "0.0.0.0 " + strings.Repeat("a.", 130) + "example.com"},
		{"an empty label", "0.0.0.0 ads..example.com"},
		{"a label starting with a hyphen", "0.0.0.0 -ads.example.com"},
		{"a label ending with a hyphen", "0.0.0.0 ads-.example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entries, skipped := ParseHosts([]byte(tc.line))

			if len(entries) != 0 {
				t.Errorf("parsed %v; %s is not a name a resolver could be asked about", entries, tc.name)
			}
			if skipped != 1 {
				t.Errorf("skipped = %d, want 1", skipped)
			}
		})
	}
}

// A rule carrying only modifiers a resolver can honour still maps onto a name, and an empty
// one between the commas is a list's own typo rather than a reason to drop the rule.
func TestAFilterRuleWithHarmlessModifiersStillBlocksItsName(t *testing.T) {
	entries, skipped := ParseABP([]byte("||ads.example.com^$important,,all\n"))

	if len(entries) != 1 || entries[0].Name != "ads.example.com" {
		t.Fatalf("parsed %v, want the name the rule carries", entries)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
}

func TestNormalizeMakesTheDotsAndCaseAroundANameStopMattering(t *testing.T) {
	for _, raw := range []string{"Doubleclick.NET", "doubleclick.net.", " .doubleclick.net. ", "DOUBLECLICK.net"} {
		if got := Normalize(raw); got != "doubleclick.net" {
			t.Errorf("Normalize(%q) = %q, want doubleclick.net", raw, got)
		}
	}
}

// A list is allowed to be tens of megabytes, and the body arrives as one slice. Splitting it
// into every line before reading any of them costs a large multiple of the body itself -- a
// string header per line against a line that may be a single newline -- so a body of newlines
// is a way to spend far more memory than the download cap allows. Walking the body holds one
// line at a time instead.
//
// The bound is what is asserted rather than a byte count: the point is that the cost stops
// tracking the number of lines.
func TestReadingAListDoesNotCostAMultipleOfTheListItself(t *testing.T) {
	const lines = 1 << 20
	body := bytes.Repeat([]byte("\n"), lines)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	format := Detect(body)
	entries, _ := ParseHosts(body)
	runtime.ReadMemStats(&after)

	if format != FormatHosts {
		t.Errorf("Detect(a body of newlines) = %v, want the format a body with nothing in it falls to", format)
	}
	if len(entries) != 0 {
		t.Errorf("a body of newlines parsed to %d entries, want none", len(entries))
	}
	// One string header per line would be around 16 MiB on top of the 1 MiB body. Four times
	// the body leaves room for the reader's own allocations while still failing the moment the
	// cost goes back to being per line.
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 4*uint64(len(body)) {
		t.Errorf("reading a %d-byte body allocated %d bytes, which is the per-line cost the walk exists to avoid", len(body), grew)
	}
}

// A list says a name the way a person reads it; the query says it the way the wire carries it.
// The entry has to end up in the wire's form or it blocks nothing, and a name the conversion
// cannot express is counted as one the list could not be read for rather than kept as text no
// query will ever equal.
func TestANameWrittenInItsOwnAlphabetBlocksTheQueryTheWireCarries(t *testing.T) {
	for _, raw := range []string{"münchen.example", "MÜNCHEN.Example.", "xn--mnchen-3ya.example"} {
		if got := Normalize(raw); got != "xn--mnchen-3ya.example" {
			t.Errorf("Normalize(%q) = %q, want the form a query arrives in", raw, got)
		}
	}

	hosts, skipped := ParseHosts([]byte("0.0.0.0 münchen.example\n0.0.0.0 москва.example www.münchen.example\n"))
	if skipped != 0 {
		t.Errorf("ParseHosts skipped %d names that are readable", skipped)
	}
	want := []string{"xn--mnchen-3ya.example", "xn--80adxhks.example", "www.xn--mnchen-3ya.example"}
	if len(hosts) != len(want) {
		t.Fatalf("ParseHosts read %v, want %v", hosts, want)
	}
	for i, entry := range hosts {
		if entry.Name != want[i] {
			t.Errorf("entry %d is %q, want %q", i, entry.Name, want[i])
		}
	}

	abp, skipped := ParseABP([]byte("||münchen.example^\n"))
	if skipped != 0 || len(abp) != 1 || abp[0].Name != "xn--mnchen-3ya.example" {
		t.Errorf("ParseABP read %v (skipped %d), want the wire form of the name", abp, skipped)
	}

	var b Builder
	if err := b.Add("l", "the list", hosts, 0); err != nil {
		t.Fatalf("Add: %v", err)
	}
	set := b.Build()
	for _, query := range []string{"xn--mnchen-3ya.example", "XN--MNCHEN-3YA.example.", "münchen.example"} {
		if _, blocked := set.Blocks(query); !blocked {
			t.Errorf("Blocks(%q) = false, want the name the list wrote", query)
		}
	}
	if _, blocked := set.Blocks("xn--mnchen-3ya.example.net"); blocked {
		t.Error("a different name under the same label was blocked")
	}

	// The replacement character is what a list decoded from a broken encoding carries in place
	// of the byte it could not read. No name may hold it, so the conversion refuses the name
	// and the line is counted rather than kept.
	_, skipped = ParseHosts([]byte("0.0.0.0 ads\uFFFD.example\n"))
	if skipped != 1 {
		t.Errorf("a name no query could carry was skipped %d times, want 1", skipped)
	}
}
