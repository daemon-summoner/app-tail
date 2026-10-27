// SPDX-License-Identifier: MIT

package dnsfwd

import (
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// Target is where one query goes.
type Target int

const (
	// ToProfile sends the query to the resolvers the user chose, and their answer is
	// the answer -- including an answer of "no such name".
	ToProfile Target = iota
	// ToLocal sends the query to the resolvers this network handed out, which are the
	// only ones that know the names this network made up.
	ToLocal
	// Here answers without asking anyone, with the code in the decision.
	Here
	// Localhost answers the loopback zone from RFC 6761.
	Localhost
	// ToTunnel asks one of app-tail's own connections, and answers with the address this
	// machine reaches the result at -- which is not the address the connection's own
	// network gave, when that network had to be moved out of another's way.
	ToTunnel
	// Blocked answers without asking anyone, because the name is on a list the user
	// switched on. What it is answered with is BlockAnswer's business, not routing's.
	Blocked
)

func (t Target) String() string {
	switch t {
	case ToProfile:
		return "profile"
	case ToLocal:
		return "local"
	case Here:
		return "here"
	case Localhost:
		return "localhost"
	case ToTunnel:
		return "tunnel"
	case Blocked:
		return "blocked"
	}
	return "unknown"
}

// TunnelSuffix is one private network's own name suffix, and the connection it belongs to.
//
// It is plain data rather than the connection itself: routing is a pure function of what
// this machine's surroundings are, and a name suffix is all of a connection that a name
// decision depends on.
type TunnelSuffix struct {
	// Suffix is what names on that connection end in, without leading or trailing dots.
	Suffix string
	// Name is the connection as the user named it, which is what the reason says. Empty
	// falls back to the suffix, so a decision never refers to a connection by nothing.
	Name string
	// ID identifies the connection to whatever resolves the name inside it.
	ID string
	// Carried reports that this machine reaches that network by address, which is the whole
	// difference between answering a name on it and refusing one. Without it there is
	// nowhere on this machine an answer could point: the connection is held inside this
	// process, and only app-tail's own proxies and forwards go through it.
	Carried bool
}

// display is what a decision calls this connection: the user's name for it, or the suffix
// when they never gave it one, so a reason never refers to a connection by nothing.
func (t TunnelSuffix) display() string {
	if name := strings.TrimSpace(t.Name); name != "" {
		return name
	}
	return normalizeSuffix(t.Suffix)
}

// VirtualPrefix is a range this machine reaches one connection's network at.
//
// It exists here for the reverse lookups. The addresses in it belong to no network this
// machine is on -- app-tail made them up to keep two connections carrying the same
// addresses apart -- so asking anyone else what they are named answers with either nothing
// or somebody else's name.
type VirtualPrefix struct {
	Prefix netip.Prefix
	// Name is the connection the range stands for, for the reason.
	Name string
}

// Rules are everything routing needs to know about this machine's surroundings.
type Rules struct {
	// LocalSuffixes are the domains the user listed as belonging to their network.
	LocalSuffixes []string
	// SearchDomains are the suffixes this network handed out over DHCP.
	SearchDomains []string
	// TunnelSuffixes are the suffixes app-tail's own connections answer for. Every stored
	// connection is listed, including the ones that are switched off: a name under a
	// suffix belongs to that connection whatever state it is in, and dropping it from the
	// list while the connection is down would send the name to the profile, which answers
	// it with a public address or with nothing.
	TunnelSuffixes []TunnelSuffix
	// VirtualPrefixes are the ranges this machine reaches moved networks at. They are empty
	// unless one interface is carrying every connection, since nothing else on this machine
	// can route them.
	VirtualPrefixes []VirtualPrefix
	// HaveLocal reports that at least one of the network's own resolvers is reachable.
	// With none, a query that would have gone to the network goes to the profile
	// instead: a worse answer for a private name beats no answer at all.
	HaveLocal bool
	// Block reports the list a name is on. Nil blocks nothing, which is the switch being
	// off, blocking being paused, and every state before the first list has been read.
	Block Blocklist
	// BlockAnswer is what a blocked name is answered with.
	BlockAnswer BlockAnswer
}

// Blocklist reports the list that stops a name, and whether one does. It is declared here
// rather than imported so routing stays a pure function of plain data and this package
// keeps knowing nothing about where a list came from.
type Blocklist interface {
	Blocks(name string) (list string, ok bool)
}

// BlockAnswer is what a blocked name is answered with.
type BlockAnswer int

const (
	// AnswerNXDomain says the name does not exist, which is what every filtering resolver
	// answers and what the zero value has to be: a forwarder handed no answer setting
	// still has to say something.
	AnswerNXDomain BlockAnswer = iota
	// AnswerSinkhole answers with an address that goes nowhere: 0.0.0.0 for A, :: for
	// AAAA, and no answer at all for every other type.
	AnswerSinkhole
	// AnswerRefused says this resolver would not answer, which is the honest reply and the
	// one a client is most likely to take to a different resolver.
	AnswerRefused
)

// ParseBlockAnswer reads the stored setting. An unknown or empty value is the default
// rather than an error: this is downstream of the settings registry, which has already
// refused anything outside its declared set.
func ParseBlockAnswer(s string) BlockAnswer {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "sinkhole":
		return AnswerSinkhole
	case "refused":
		return AnswerRefused
	default:
		return AnswerNXDomain
	}
}

func (a BlockAnswer) String() string {
	switch a {
	case AnswerSinkhole:
		return "sinkhole"
	case AnswerRefused:
		return "refused"
	default:
		return "nxdomain"
	}
}

// Decision is where a query goes and why. The reason is one short phrase, and it exists
// because "why did that name resolve differently" is the question this feature generates.
type Decision struct {
	Target Target
	// RCode is what to answer with when Target is Here.
	RCode dnsmessage.RCode
	// Tunnel is the connection to ask when Target is ToTunnel, and Host is the name to ask
	// it for -- the name without the connection's own suffix, which is what that network
	// knows the host as.
	Tunnel string
	Host   string
	// List is the blocklist that stopped the name when Target is Blocked, so a caller can
	// name it without parsing the reason.
	List   string
	Reason string
}

// captiveSuffixes are the names an operating system looks up to decide whether it is
// behind a captive portal.
//
// They have to go to the network's own resolver: the portal answers them with its own
// address, which is how the machine knows to show the sign-in page. Sent to a public
// resolver they answer truthfully, the machine concludes it is online, and the user sits
// on a hotel network with no way in.
var captiveSuffixes = []string{
	"captive.apple.com",
	"msftncsi.com",
	"msftconnecttest.com",
	"connectivitycheck.gstatic.com",
	"connectivitycheck.android.com",
	"detectportal.firefox.com",
	"network-test.debian.org",
	"nmcheck.gnome.org",
}

// privateV4 are the address ranges whose reverse lookups only the local network can
// answer. A public resolver answers them with NXDOMAIN, which is how "the printer's name
// stopped working" starts.
var privateV4 = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	// The tailnet's own range. Its reverse lookups belong to the tailnet resolver, and
	// on every platform something in front of us claims them before we see them; when
	// nothing does, the network is a better guess than a public resolver.
	netip.MustParsePrefix("100.64.0.0/10"),
}

// privateV6 are the IPv6 equivalents: unique local addresses and link-local.
var privateV6 = []netip.Prefix{
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::1/128"),
}

// Route decides where one query goes.
//
// It is a pure function of the question and the machine's surroundings, so every arm is
// reachable in a test without a socket. The order is the meaning: the first arm that
// matches wins, and the last one -- everything else goes to the chosen profile, and its
// answer is final -- is the behaviour the whole feature exists for.
//
// The tailnet's own suffix is deliberately absent. On macOS a per-domain resolver file
// claims it before a query reaches this process; on Linux and Windows in network-interface
// mode the tailnet's resolver sits in front of us. Adding an arm for it here would be a
// second, disagreeing answer to a question already settled elsewhere.
func Route(q Question, r Rules) Decision {
	if q.Class != dnsmessage.ClassINET {
		// Chaosnet and Hesiod queries exist, and forwarding them to a resolver chosen
		// for internet names would ask a question nobody can answer.
		return Decision{Target: Here, RCode: dnsmessage.RCodeNotImplemented, Reason: "not an internet-class query"}
	}
	if !encodableName(q.Name) {
		return Decision{Target: Here, RCode: dnsmessage.RCodeFormatError, Reason: "not a usable name"}
	}

	local := func(reason string) Decision {
		if !r.HaveLocal {
			// Nothing local is known -- during a network change, or on a machine with
			// no DHCP resolver at all. Asking the profile is a worse answer for a
			// private name and a much better one than no answer.
			return Decision{Target: ToProfile, Reason: reason + ", but this network published no resolver"}
		}
		return Decision{Target: ToLocal, Reason: reason}
	}

	onTunnel, host, onCarried := tunnelSuffixOf(q.Name, r.TunnelSuffixes)
	presenting := virtualReverse(q.Name, r.VirtualPrefixes)

	switch {
	case presenting != "":
		// Ahead of every other reverse arm, because a moved network is presented from
		// whatever range had room -- which can be inside 10.0.0.0/8, where the arm below
		// would send the lookup to this network's resolver, or inside a range no rule here
		// calls private, where it would go to a public one. Neither has ever heard of the
		// address: app-tail made it up.
		return Decision{
			Target: Here,
			RCode:  dnsmessage.RCodeNameError,
			Reason: "a reverse lookup for an address app-tail presents " + presenting +
				" at, which no resolver holds a name for",
		}
	case isPrivateReverse(q.Name):
		return local("a reverse lookup for a private address")
	case hasSuffix(q.Name, captiveSuffixes):
		return local("a captive-portal check")
	case q.Name == "localhost" || strings.HasSuffix(q.Name, ".localhost"):
		// RFC 6761: the name means this machine. Sending it anywhere is the mistake,
		// and an upstream that answered it with a public address would be handing this
		// machine's own browser a way past its same-origin checks. Ahead of the
		// single-label arm, because bare "localhost" is a single label and must not be
		// asked of the network either.
		return Decision{Target: Localhost, Reason: "the loopback zone"}
	case onCarried && host != "":
		// A name on a connection this machine reaches by address. The connection's own
		// resolver knows the name; what it answers with is the address inside that network,
		// which is translated into the one this machine reaches it at before it goes back to
		// whoever asked.
		return Decision{
			Target: ToTunnel,
			Tunnel: onTunnel.ID,
			Host:   host,
			Reason: "a name on " + onTunnel.display() + ", which this machine reaches over the interface app-tail carries it on",
		}
	case onTunnel.Suffix != "" && host == "":
		// The connection's own name. It names the connection rather than a host on it, in
		// every mode, so there is no address to answer with and nowhere else worth asking:
		// the suffix belongs to app-tail and a public resolver would answer for it with
		// whoever registered the domain.
		return Decision{
			Target: Here,
			RCode:  dnsmessage.RCodeNameError,
			Reason: onTunnel.display() + "'s own name, which names the connection and not a host on it",
		}
	case onTunnel.Suffix != "":
		// A name on one of app-tail's own connections that nothing out here can route -- the
		// connection is held inside this process -- so the honest answer is that the name
		// does not exist. Sending it to the profile would be worse than useless: a public
		// resolver answers a private name with somebody else's address, and the machine
		// would connect to it.
		return Decision{
			Target: Here,
			RCode:  dnsmessage.RCodeNameError,
			Reason: "a name on " + onTunnel.display() + ", which only app-tail's own proxies and forwards reach",
		}
	case q.Name != "" && !strings.Contains(q.Name, "."):
		// A single label is a name off this network -- a machine, a printer, a router's
		// own hostname. No resolver on the internet knows it. The root is not one of
		// these: it has no labels at all and belongs to the public hierarchy.
		return local("a single-label name")
	case q.Name == "local" || strings.HasSuffix(q.Name, ".local"):
		return local("a multicast-DNS name")
	case hasSuffix(q.Name, normalizeSuffixes(r.LocalSuffixes)):
		return local("a domain you listed as local")
	case hasSuffix(q.Name, normalizeSuffixes(r.SearchDomains)):
		return local("a search domain this network published")
	}
	// Last, and that position is the rule: a name this network, the loopback zone or one of
	// app-tail's own connections answers for is never subject to a list downloaded off the
	// internet, and everything that would otherwise leave to the chosen profile is. A list
	// carrying "router" or a local domain would otherwise take out the names this machine
	// needs to reach the network it is on.
	if r.Block != nil {
		if list, ok := r.Block.Blocks(q.Name); ok {
			return Decision{Target: Blocked, List: list, Reason: "on " + list}
		}
	}
	return Decision{Target: ToProfile, Reason: "an ordinary name"}
}

// encodableName reports that a name can be put back on the wire. The parser accepts
// shapes the builder will not encode, and a query we cannot echo is one we cannot answer.
func encodableName(name string) bool {
	if name == "" {
		return true // the root, which is encodable and is nobody's private name
	}
	fqdn := name + "."
	if _, err := dnsmessage.NewName(fqdn); err != nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return false
		}
	}
	return true
}

// hasSuffix reports whether name is the suffix or sits under it. Matching is by label, so
// "notexample.com" does not match "example.com".
func hasSuffix(name string, suffixes []string) bool {
	for _, s := range suffixes {
		if s == "" {
			continue
		}
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// tunnelSuffixOf says which connection a name belongs to, what that connection's own
// network knows the host as -- the name with the suffix taken off, empty when the name is
// the suffix exactly -- and whether this machine reaches that connection by address.
//
// A zero TunnelSuffix comes back when no connection claims the name. The longest matching
// suffix wins, so a connection whose suffix sits under another's is reached by its own name
// rather than swallowed by the shorter one.
func tunnelSuffixOf(name string, suffixes []TunnelSuffix) (TunnelSuffix, string, bool) {
	var (
		best   TunnelSuffix
		host   string
		length int
	)
	for _, t := range suffixes {
		suffix := normalizeSuffix(t.Suffix)
		if suffix == "" || len(suffix) <= length {
			continue
		}
		switch {
		case name == suffix:
			host = ""
		case strings.HasSuffix(name, "."+suffix):
			host = strings.TrimSuffix(name, "."+suffix)
		default:
			continue
		}
		best, length = t, len(suffix)
	}
	return best, host, best.Carried
}

// virtualReverse names the connection a reverse lookup is asking about, when the address it
// covers is one app-tail presents a moved network at. It is empty for every other name.
func virtualReverse(name string, virtual []VirtualPrefix) string {
	if len(virtual) == 0 {
		return ""
	}
	asked, ok := reversePrefix(name)
	if !ok {
		return ""
	}
	for _, v := range virtual {
		if !v.Prefix.IsValid() || v.Prefix.Addr().BitLen() != asked.Addr().BitLen() {
			continue
		}
		if v.Prefix.Overlaps(asked) {
			if name := strings.TrimSpace(v.Name); name != "" {
				return name
			}
			return "one of your connections"
		}
	}
	return ""
}

// normalizeSuffix lowercases a suffix and strips the dots people type around one, so
// ".Office.Internal." and "office.internal" are one connection.
func normalizeSuffix(s string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(s), "."))
}

// normalizeSuffixes lowercases and strips the dots people type around a domain, so
// ".corp.example.com." and "corp.example.com" are one rule.
func normalizeSuffixes(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = normalizeSuffix(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// isPrivateReverse reports that a name is a reverse lookup for an address only this
// network can name. Partial names -- the ones a resolver walks up while delegating -- are
// matched by the prefix they cover, so "168.192.in-addr.arpa" counts.
func isPrivateReverse(name string) bool {
	prefix, ok := reversePrefix(name)
	if !ok {
		return false
	}
	if prefix.Addr().Is4() {
		return overlapsAny(prefix, privateV4)
	}
	return overlapsAny(prefix, privateV6)
}

// reversePrefix is the range of addresses a reverse lookup covers, and reports false for a
// name that is not one. Partial names -- the ones a resolver walks up while delegating --
// come back as the wider prefix they stand for, so "168.192.in-addr.arpa" is 192.168.0.0/16.
func reversePrefix(name string) (netip.Prefix, bool) {
	switch {
	case name == "in-addr.arpa" || name == "ip6.arpa":
		// The zone apex itself. No address is being asked about.
		return netip.Prefix{}, false
	case strings.HasSuffix(name, ".in-addr.arpa"):
		return reverseV4Prefix(strings.TrimSuffix(name, ".in-addr.arpa"))
	case strings.HasSuffix(name, ".ip6.arpa"):
		return reverseV6Prefix(strings.TrimSuffix(name, ".ip6.arpa"))
	}
	return netip.Prefix{}, false
}

// reverseV4Prefix turns "1.6.168.192" into 192.168.6.1/32, and the shorter forms into the
// shorter prefixes they stand for.
func reverseV4Prefix(labels string) (netip.Prefix, bool) {
	parts := strings.Split(labels, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return netip.Prefix{}, false
	}
	var octets [4]byte
	for i, p := range parts {
		n, ok := parseOctet(p)
		if !ok {
			return netip.Prefix{}, false
		}
		octets[len(parts)-1-i] = n
	}
	return netip.PrefixFrom(netip.AddrFrom4(octets), 8*len(parts)), true
}

func parseOctet(s string) (byte, bool) {
	if s == "" || len(s) > 3 {
		return 0, false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	if n > 255 {
		return 0, false
	}
	return byte(n), true
}

// reverseV6Prefix turns a run of reversed nibbles into the prefix it covers.
func reverseV6Prefix(labels string) (netip.Prefix, bool) {
	parts := strings.Split(labels, ".")
	if len(parts) == 0 || len(parts) > 32 {
		return netip.Prefix{}, false
	}
	var addr [16]byte
	for i, p := range parts {
		if len(p) != 1 {
			return netip.Prefix{}, false
		}
		n, ok := parseNibble(p[0])
		if !ok {
			return netip.Prefix{}, false
		}
		pos := len(parts) - 1 - i
		if pos%2 == 0 {
			addr[pos/2] |= n << 4
		} else {
			addr[pos/2] |= n
		}
	}
	return netip.PrefixFrom(netip.AddrFrom16(addr), 4*len(parts)), true
}

func parseNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// overlapsAny reports whether a prefix names addresses inside one of the ranges. A
// partial reverse name covers a range wider than any single private block, and it still
// counts: "10.in-addr.arpa" is the private zone itself.
func overlapsAny(p netip.Prefix, ranges []netip.Prefix) bool {
	for _, r := range ranges {
		if r.Addr().BitLen() != p.Addr().BitLen() {
			continue
		}
		if r.Overlaps(p) {
			return true
		}
	}
	return false
}
