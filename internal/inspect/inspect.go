// SPDX-License-Identifier: MIT

// Package inspect decides whether traffic app-tail carries is something to report or to
// stop. It is the matcher half of the IPS: the runner owns the sources and the switches,
// and every flow the app is about to carry comes through Check first.
//
// The model is default-allow, which is the opposite of the proxy permissions in
// package access and has to be. Those rules are a grant: a listener nobody configured
// reaches nothing, and that is the safe reading there. This sits on the data path of a
// VPN, where the same reading would mean a matcher that recognises nothing stops
// everything -- so a flow no source names is carried, and every arm that cannot answer
// says "carried" rather than "refused".
//
// The decision is a pure function of the compiled sources and the flow, so every arm is
// reachable in a test without a socket, and the dashboard's "what would you do with this"
// gets the same answer a real flow would get without opening one.
//
// # What reading costs
//
// The budget, and the benchmark that checks each part of it. The figures are from an Apple
// M5; what matters is the shape rather than the exact number, and the shape is that the cost
// is paid once per connection and never per byte:
//
//   - Reading one connection's opening bytes: about 1-3 µs and five allocations, of which
//     three are the fingerprint and two are the strings the finding carries.
//     BenchmarkFlowOpen.
//   - Reading a client hello: about 2.5 µs and nothing allocated, because every field lands
//     in fixed room inside the returned struct rather than in something sized by what the
//     network sent. BenchmarkClientHelloParse, and TestReadingAHelloAllocatesNothing, which
//     makes the zero a checked claim rather than a number in a comment.
//   - Every chunk after the verdict: under 2 ns and nothing allocated -- one field
//     comparison. BenchmarkSteadyState and TestAChunkAfterTheVerdictAllocatesNothing.
//
// With inspection switched off the cost is one nil comparison per chunk in netpipe, which is
// what BenchmarkCopyThroughput against BenchmarkCopyThroughputInspected measures.
package inspect

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/gaissmai/bart"

	"github.com/sellitus/app-tail/internal/dnsblock"
)

// MaxSources bounds how many sources one compiled matcher carries, for the reason
// dnsblock.MaxLists does: which source matched is kept as a single byte beside the rule
// rather than as a pointer. Compile refuses a set larger than this.
const MaxSources = dnsblock.MaxLists

// Signal is what about a flow matched. It is the word the event carries and the word the
// card shows, so it names the evidence rather than the verdict: a user reading "the name
// it asked for" knows what to change, and a user reading "blocked" does not.
type Signal string

const (
	// SignalName is the name a program asked for, before resolution.
	SignalName Signal = "name"
	// SignalDestination is the address a flow is bound for.
	SignalDestination Signal = "destination"
	// SignalHandshake is the name inside the opening bytes of a connection: the server name
	// of a TLS hello, or the host of a plain web request. It is its own signal because it
	// was read off the wire rather than asked for, which is what makes it the one that
	// reaches a program that brought its own resolver.
	SignalHandshake Signal = "handshake"
	// SignalPayload is a byte pattern found in what a connection carries rather than in
	// anything about where it is going. It is the only signal here that describes the
	// contents, and the only one whose rules are written entirely by the user.
	SignalPayload Signal = "payload"
)

// Finding is one match: what matched, the value that matched, and which source says so.
//
// It deliberately does not say what happens next. Whether a match is reported or stopped
// is the mode, which the runner holds and this package does not: the same match has to
// read identically in the activity list whether or not prevention was on when it landed.
type Finding struct {
	Signal Signal `json:"signal"`
	// Value is what actually matched -- the name, or the prefix the address sits in.
	Value string `json:"value"`
	// Source is the source as the user sees it, and is what the reason says.
	Source string `json:"source"`
}

// Reason is the sentence the event and the log line carry.
func (f Finding) Reason() string {
	if f.Signal == SignalHandshake {
		// The name was never asked for here, so the sentence says where it came from: a
		// user who has not typed this name anywhere needs to know the connection carried it.
		return fmt.Sprintf("the connection is for %s, which is named by %s", f.Value, f.Source)
	}
	if f.Signal == SignalPayload {
		// The value is the signature's name rather than a name the connection asked for, so
		// the sentence says the connection carried it rather than that it was for it.
		return fmt.Sprintf("the connection carries %s, which is named by %s", f.Value, f.Source)
	}
	if f.Signal == SignalDestination {
		// The value is the network rather than the address that hit it, so the sentence has
		// to say which of the two it is naming.
		return fmt.Sprintf("the address is in %s, which is named by %s", f.Value, f.Source)
	}
	return fmt.Sprintf("%s is named by %s", f.Value, f.Source)
}

// Source is one set of rules under one name: the user's own entries, or a downloaded
// feed once there are feeds. Each entry is a domain, an address, or a prefix; which one
// it is is read from the text rather than declared, because a user typing into a list of
// things to stop should not have to sort them first.
type Source struct {
	ID   string
	Name string
	// Allow entries are never stopped, whatever any source says.
	Allow []string
	Deny  []string
}

// SourceStat is what one source contributed, for the card and for `app-tail ips`.
type SourceStat struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Names and Prefixes are how many of each the source contributed. Skipped is how
	// many of its entries parsed as neither -- the number that says whether a source is
	// pulling its weight or is mostly text this matcher has no use for.
	Names    int `json:"names"`
	Prefixes int `json:"prefixes"`
	Skipped  int `json:"skipped"`
}

// Flow is one connection app-tail is about to carry, as the path carrying it knows it.
//
// It is a struct rather than a parameter list because every carrying path passes the same
// four strings, and four strings in a row is an argument order nobody can check by reading
// the call. Which fields are filled differs by path and that is expected: the interface has
// the name a program asked for, the network interface has only an address, and only the
// subnet router knows which device on the tailnet asked.
type Flow struct {
	// Name is what the program asked for, empty when it dialled an address.
	Name string
	// Addr is where the connection is bound, invalid when nothing has resolved it yet.
	Addr netip.Addr
	// Port is what it is bound for, zero where the path has not decided one. No rule matches
	// on it: it is here because a series of connections to many ports of one address is a
	// port scan, and that is a shape only the ledger can see.
	Port uint16
	// Where names the path carrying it, in the words the card shows.
	Where string
	// Protocol is "tcp" or "udp" where the path distinguishes them.
	Protocol string
	// Peer is the device that asked, on the one path that knows.
	Peer string
}

// Rules is a compiled matcher. It is immutable once built and replaced whole, so the
// data path reads it without a lock and a flow in flight keeps the rules it started with.
type Rules struct {
	// names carries the deny and allow entries of every source in one dnsblock matcher,
	// so allow-beats-everything and the suffix semantics are the ones the resolver
	// already uses rather than a second set that drifts from them.
	names *dnsblock.Set
	// deny and allow are separate tables rather than one table with an action, because
	// a longest-prefix lookup would make an allow win only when it is more specific.
	// Allow has to win outright: it is what a false positive gets fixed with, and a fix
	// a broader deny could override would not be one.
	deny  *bart.Table[uint8]
	allow *bart.Table[struct{}]

	sources []SourceStat
}

// Check answers whether a flow matches anything, given what the program asked for and
// where the flow is bound. Either may be absent: the fabric knows only an address, and a
// name lookup happens before there is one.
//
// The name is asked first. A name that is stopped is stopped before it is resolved, so
// the reason a user reads names the thing they typed rather than an address they have
// never seen.
func (r *Rules) Check(name string, addr netip.Addr) (Finding, bool) {
	if r == nil {
		return Finding{}, false
	}
	if name != "" {
		if found, ok := r.Name(name); ok {
			return found, true
		}
	}
	if addr.IsValid() {
		return r.Destination(addr)
	}
	return Finding{}, false
}

// Name reports the source that names a domain, and whether one does.
func (r *Rules) Name(name string) (Finding, bool) {
	if r == nil {
		return Finding{}, false
	}
	source, ok := r.names.Blocks(name)
	if !ok {
		return Finding{}, false
	}
	return Finding{Signal: SignalName, Value: dnsblock.Normalize(name), Source: source}, true
}

// Destination reports the source that names the network an address sits in, and whether
// one does.
func (r *Rules) Destination(addr netip.Addr) (Finding, bool) {
	if r == nil {
		return Finding{}, false
	}
	// bart does not unmap, by design: it keeps the cost off the common path. So it is
	// done here, once, for the reason access.prefixHolds gives -- a resolver answering
	// ::ffff:10.0.0.5 would otherwise slip past an entry naming 10.0.0.0/8, the same
	// address carried or refused depending on which form the lookup happened to return.
	at := addr.Unmap()
	if r.allow != nil && r.allow.Contains(at) {
		return Finding{}, false
	}
	// LookupPrefixLPM rather than Lookup: the prefix that matched is what the reason
	// shows, and a user who wrote 10.0.0.0/8 needs to read that back rather than the
	// single address that happened to hit it.
	prefix, owner, ok := r.deny.LookupPrefixLPM(netip.PrefixFrom(at, at.BitLen()))
	if !ok {
		return Finding{}, false
	}
	return Finding{
		Signal: SignalDestination,
		Value:  prefix.String(),
		Source: r.sourceName(owner),
	}, true
}

// sourceName is what a match's reason calls the source. An owner with no entry is a build
// that went wrong rather than a runtime condition, and saying so beats a reason that
// names nothing.
func (r *Rules) sourceName(owner uint8) string {
	if int(owner) >= len(r.sources) {
		return "a source app-tail could not name"
	}
	if name := strings.TrimSpace(r.sources[owner].Name); name != "" {
		return name
	}
	return r.sources[owner].ID
}

// Sources reports what each source contributed, in the order they were compiled.
func (r *Rules) Sources() []SourceStat {
	if r == nil {
		return nil
	}
	return append([]SourceStat(nil), r.sources...)
}

// Count is how many entries the matcher holds: every name and every network that parsed,
// whether it stops a flow or carries one past a rule that would have stopped it. An entry
// two sources both carry is counted once per source, which is what the sources contributed.
func (r *Rules) Count() int {
	if r == nil {
		return 0
	}
	n := 0
	for _, s := range r.sources {
		n += s.Names + s.Prefixes
	}
	return n
}

// Compile builds the matcher from sources, in the order the user holds them. The first
// source to carry an entry is credited with it, so a reason names the source the user put
// first rather than whichever one happened to sort last.
//
// An entry that parses as neither a name nor an address is counted as skipped rather than
// refused: validation stops those where they are entered, so one here is a stored document
// edited past it, and refusing the whole compile would take every other entry down with it.
func Compile(sources []Source) (*Rules, error) {
	var (
		builder dnsblock.Builder
		deny    bart.Table[uint8]
		allow   bart.Table[struct{}]
		stats   = make([]SourceStat, 0, len(sources))
	)
	for i, src := range sources {
		owner := uint8(i)
		stat := SourceStat{ID: src.ID, Name: src.Name}
		var entries []dnsblock.Entry

		for _, raw := range src.Deny {
			switch prefix, name := parseEntry(raw); {
			case prefix.IsValid():
				deny.Insert(prefix, owner)
				stat.Prefixes++
			case name != "":
				// Subtree, not Exact: a user typing a domain into a list of things to
				// stop means that domain and what is under it. A hosts file means only
				// what it lists, and that distinction belongs to whoever wrote the file,
				// not to somebody typing one name.
				entries = append(entries, dnsblock.Entry{Name: name, Match: dnsblock.Subtree})
				stat.Names++
			default:
				stat.Skipped++
			}
		}
		for _, raw := range src.Allow {
			switch prefix, name := parseEntry(raw); {
			case prefix.IsValid():
				allow.Insert(prefix, struct{}{})
				stat.Prefixes++
			case name != "":
				entries = append(entries, dnsblock.Entry{Name: name, Match: dnsblock.Subtree, Allow: true})
				stat.Names++
			default:
				stat.Skipped++
			}
		}

		// The ceiling on how many sources a matcher holds is the name matcher's, and it is
		// enforced there rather than counted twice here: both attribute a match with the same
		// single owner byte, so a source the names would not take is one no match could name.
		if err := builder.Add(src.ID, src.Name, entries, stat.Skipped); err != nil {
			return nil, fmt.Errorf("compile the source %q: %w", src.ID, err)
		}
		stats = append(stats, stat)
	}

	return &Rules{names: builder.Build(), deny: &deny, allow: &allow, sources: stats}, nil
}

// parseEntry reads one entry as either a prefix or a name. A bare address is the prefix
// that holds only it, so "1.2.3.4" and "1.2.3.4/32" are one entry written two ways.
// Neither form returning anything means the text is neither, which the caller counts.
func parseEntry(raw string) (netip.Prefix, string) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return netip.Prefix{}, ""
	}
	if prefix, err := netip.ParsePrefix(text); err == nil {
		// An IPv4 network in its mapped form is that IPv4 network: Destination unmaps every
		// address before the lookup, so the mapped form itself would never match.
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		// Masked, so 10.0.0.5/8 is the network the user meant rather than an entry bart
		// refuses for carrying bits below its own prefix length.
		return prefix.Masked(), ""
	}
	if addr, err := netip.ParseAddr(text); err == nil {
		at := addr.Unmap()
		return netip.PrefixFrom(at, at.BitLen()), ""
	}
	if name := dnsblock.Normalize(text); name != "" && plausibleName(name) {
		return netip.Prefix{}, name
	}
	return netip.Prefix{}, ""
}

// plausibleName rejects text that is not a domain at all. It is deliberately loose --
// the cost of accepting something odd is one entry that never matches, and the cost of
// rejecting a real name is traffic that was meant to be stopped and was not.
func plausibleName(name string) bool {
	if strings.ContainsAny(name, " \t/\\?#@:") {
		return false
	}
	return strings.Contains(name, ".")
}
