// SPDX-License-Identifier: MIT

package tsproxy

import (
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pacDriver evaluates the generated script the way a browser does and reports what
// FindProxyForURL returned for each host.
//
// The two stubs that matter are the ones that model what a browser can and cannot do.
// dnsResolve throws unconditionally, because a browser's own resolver cannot resolve a
// MagicDNS name in userspace mode -- a rule that reached it would never fire, and would
// leak the name to whatever public DNS the machine uses. isInNet throws for a
// non-literal host for the same reason: it resolves internally.
const pacDriver = `
const fs = require('fs')
const src = fs.readFileSync(process.argv[2], 'utf8')
const hosts = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'))

function shExpMatch(str, shexp) {
  let out = '^'
  for (const c of String(shexp)) {
    if (c === '*') out += '.*'
    else if (c === '?') out += '.'
    else out += c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  }
  return new RegExp(out + '$').test(String(str))
}

function dnsResolve(host) {
  throw new Error('dnsResolve was called for ' + host)
}

function isInNet(host, pattern, mask) {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(String(host))) {
    throw new Error('isInNet was called for the non-literal host ' + host)
  }
  const num = (s) => String(s).split('.').reduce((a, o) => (a * 256) + (Number(o) & 255), 0)
  return ((num(host) & num(mask)) >>> 0) === ((num(pattern) & num(mask)) >>> 0)
}

function myIpAddress() { return '127.0.0.1' }

const build = new Function('shExpMatch', 'isInNet', 'dnsResolve', 'myIpAddress',
  src + '\nreturn FindProxyForURL;')
const FindProxyForURL = build(shExpMatch, isInNet, dnsResolve, myIpAddress)

const out = hosts.map((host) => {
  const url = host.indexOf(':') >= 0 ? 'http://[' + host + ']/' : 'http://' + host + '/'
  try {
    return { host: host, result: String(FindProxyForURL(url, host)) }
  } catch (e) {
    return { host: host, error: String((e && e.message) || e) }
  }
})
process.stdout.write(JSON.stringify(out))
`

// runPAC evaluates script against each host and returns what the browser would be told.
//
// A thrown exception is a failure, not a result: a browser that hits one abandons the
// script and sends everything direct, silently. That is the worst outcome the file has,
// so it is reported rather than folded into the returned map.
func runPAC(t *testing.T, script string, hosts []string) map[string]string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		// The static tests below cover the rules themselves without node; this layer
		// adds the proof the script parses and evaluates, which only a JS engine gives.
		t.Skip("PAC-EXECUTION: N/A -- node is not installed, so the script cannot be evaluated")
	}

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "proxy.pac.js")
	driverPath := filepath.Join(dir, "driver.js")
	hostsPath := filepath.Join(dir, "hosts.json")

	encoded, err := json.Marshal(hosts)
	if err != nil {
		t.Fatalf("encode the hosts to try: %v", err)
	}
	for path, content := range map[string][]byte{
		scriptPath: []byte(script),
		driverPath: []byte(pacDriver),
		hostsPath:  encoded,
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("write %s: %v", filepath.Base(path), err)
		}
	}

	out, err := exec.Command(node, driverPath, scriptPath, hostsPath).CombinedOutput()
	if err != nil {
		t.Fatalf("evaluate the generated script: %v\n%s\n--- script ---\n%s", err, out, script)
	}

	var results []struct {
		Host   string `json:"host"`
		Result string `json:"result"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("decode the driver's output: %v\n%s", err, out)
	}

	answers := make(map[string]string, len(results))
	for _, r := range results {
		if r.Error != "" {
			t.Errorf("the script failed for host %q: %s", r.Host, r.Error)
			continue
		}
		answers[r.Host] = r.Result
	}
	return answers
}

// tailnetPAC is a config shaped like a real tailnet: the ranges Tailscale allocates from,
// one advertised IPv4 subnet and one IPv6 subnet.
func tailnetPAC() PACConfig {
	return PACConfig{
		ProxyAddr:      "127.0.0.1:1080",
		MagicDNSSuffix: "tail1a2b3c.ts.net",
		Ranges: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.0/10"),
			netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
		},
		Routes: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("2001:db8::/32"),
		},
	}
}

// The routing table is the whole product of this file. Each row is a destination a user
// will actually type, and getting any of them backwards means either traffic that cannot
// reach the tailnet or traffic leaving the machine that was meant to stay on it.
func TestTheScriptSendsEachKindOfDestinationTheRightWay(t *testing.T) {
	const proxy = "SOCKS5 127.0.0.1:1080; PROXY 127.0.0.1:1080"

	tests := []struct {
		host string
		want string
		why  string
	}{
		{"files.tail1a2b3c.ts.net", proxy, "a MagicDNS name, which only the proxy can resolve"},
		{"tail1a2b3c.ts.net", proxy, "the tailnet's own domain"},
		{"100.64.1.5", proxy, "a literal tailnet address"},
		{"100.127.255.254", proxy, "the top of the range Tailscale allocates from"},
		{"fd7a:115c:a1e0:ab12::1", proxy, "a tailnet IPv6 address"},
		{"10.1.2.3", proxy, "a subnet this tailnet routes"},
		{"2001:db8:1::5", proxy, "an IPv6 subnet this tailnet routes"},

		// The allocation is 100.64.0.0/10, not /8. A rule written for /8 would send a
		// quarter of the CGNAT space -- carrier NAT addresses that are not ours -- into
		// the tailnet, where they do not resolve.
		{"100.128.0.1", "DIRECT", "inside 100/8 but outside the /10 Tailscale allocates"},
		{"8.8.8.8", "DIRECT", "a public address"},
		{"example.com", "DIRECT", "a public name"},
		{"2606:4700:4700::1111", "DIRECT", "a public IPv6 address"},

		// The suffix rule is "*.tail1a2b3c.ts.net", which requires the separating dot.
		// Without it a name an attacker can register would be routed into the tailnet.
		{"eviltail1a2b3c.ts.net", "DIRECT", "a lookalike with no separating dot"},
	}

	hosts := make([]string, 0, len(tests))
	for _, tt := range tests {
		hosts = append(hosts, tt.host)
	}
	got := runPAC(t, PAC(tailnetPAC()), hosts)

	for _, tt := range tests {
		if got[tt.host] != tt.want {
			t.Errorf("FindProxyForURL(%q) = %q, want %q -- %s", tt.host, got[tt.host], tt.want, tt.why)
		}
	}
}

// A name on one of app-tail's own connections resolves nowhere but inside this process, so
// a browser that sent it direct would reach nothing at all. It is matched on the name for
// the same reason a MagicDNS name is: there is no address for the browser to test.
func TestANameOnAConnectionIsSentToTheProxy(t *testing.T) {
	const proxy = "SOCKS5 127.0.0.1:1080; PROXY 127.0.0.1:1080"

	cfg := tailnetPAC()
	cfg.TunnelSuffixes = []string{"office.internal", " .Lab.Internal. "}

	tests := []struct {
		host string
		want string
		why  string
	}{
		{"db.office.internal", proxy, "a host on a connection"},
		{"office.internal", proxy, "the connection's own name"},
		{"db.eu.office.internal", proxy, "every name under the suffix is on it"},
		{"nas.lab.internal", proxy, "a suffix typed with dots and capitals is the same connection"},
		{"notoffice.internal", "DIRECT", "a lookalike with no separating dot"},
		{"office.internal.example.com", "DIRECT", "a name that merely contains the suffix"},
	}

	hosts := make([]string, 0, len(tests))
	for _, tt := range tests {
		hosts = append(hosts, tt.host)
	}
	got := runPAC(t, PAC(cfg), hosts)

	for _, tt := range tests {
		if got[tt.host] != tt.want {
			t.Errorf("FindProxyForURL(%q) = %q, want %q -- %s", tt.host, got[tt.host], tt.want, tt.why)
		}
	}
}

// Selecting an exit node means public traffic is meant to leave through it. A direct
// fallback would quietly bypass the exit node for everything the tailnet rules did not
// match, which is the opposite of what selecting one is for.
func TestWithAnExitNodeSelectedNothingIsSentDirect(t *testing.T) {
	cfg := tailnetPAC()
	cfg.ExitNode = true

	hosts := []string{"example.com", "8.8.8.8", "files.tail1a2b3c.ts.net"}
	got := runPAC(t, PAC(cfg), hosts)

	for _, host := range hosts {
		if got[host] == "DIRECT" {
			t.Errorf("FindProxyForURL(%q) = DIRECT, want the proxy while an exit node is selected", host)
		}
		if !strings.HasPrefix(got[host], "SOCKS5 ") {
			t.Errorf("FindProxyForURL(%q) = %q, want a proxy result", host, got[host])
		}
	}
}

// A browser fetches this file whether or not the proxy is up. Sending traffic at a port
// nothing is listening on would break every site the browser loads, so the script has to
// degrade to direct -- and say why, since a user reading it otherwise concludes the
// feature is broken.
func TestWithNothingListeningEverythingGoesDirectAndTheFileSaysWhy(t *testing.T) {
	script := PAC(PACConfig{Reason: "the proxy module is switched off"})

	if !strings.Contains(script, "the proxy module is switched off") {
		t.Errorf("the all-direct script does not say why:\n%s", script)
	}

	got := runPAC(t, script, []string{"files.tail1a2b3c.ts.net", "100.64.1.5", "example.com"})
	for host, result := range got {
		if result != "DIRECT" {
			t.Errorf("FindProxyForURL(%q) = %q with nothing listening, want DIRECT", host, result)
		}
	}
}

// Without a reason the file still has to explain itself, or it reads as a bug.
func TestAnAllDirectScriptAlwaysCarriesAnExplanation(t *testing.T) {
	script := PAC(PACConfig{})
	if !strings.Contains(script, "not listening") {
		t.Errorf("an all-direct script with no reason given explains nothing:\n%s", script)
	}
	if got := runPAC(t, script, []string{"example.com"}); got["example.com"] != "DIRECT" {
		t.Errorf("FindProxyForURL = %q, want DIRECT", got["example.com"])
	}
}

// dnsResolve uses the browser's own resolver, which knows nothing about the tailnet in
// userspace mode. A rule built on it would never match a MagicDNS name, and would hand
// the name to whatever public DNS the machine uses on the way to not matching.
func TestTheScriptNeverAsksTheBrowserToResolveAName(t *testing.T) {
	script := PAC(tailnetPAC())
	for _, line := range strings.Split(script, "\n") {
		// The comments name dnsResolve to explain why no rule uses it, so only the code
		// is inspected -- the alternative would be a test that forbids saying why.
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		if strings.Contains(line, "dnsResolve") {
			t.Errorf("the generated script calls dnsResolve, which cannot resolve a tailnet name: %s", line)
		}
	}
}

// isInNet resolves a non-literal host internally, which is the same leak by another
// route. Every call has to sit behind the literal-address guard.
func TestEveryAddressRuleIsBehindTheLiteralGuard(t *testing.T) {
	for _, line := range strings.Split(PAC(tailnetPAC()), "\n") {
		if !strings.Contains(line, "isInNet(") {
			continue
		}
		if !strings.Contains(line, "literal &&") {
			t.Errorf("an address rule is not guarded against a name being resolved: %s", line)
		}
	}
}

// A prefix no rule could be written for is invisible in the output, which reads exactly
// like a prefix that is covered. Saying so is the difference between a documented limit
// and a user watching traffic go the wrong way with no explanation.
func TestAPrefixThatCannotBeMatchedIsReportedRatherThanDropped(t *testing.T) {
	cfg := tailnetPAC()
	// A /33 does not end on a hextet boundary, so a textual wildcard for it would also
	// match addresses outside it.
	cfg.Routes = append(cfg.Routes, netip.MustParsePrefix("2001:db8:8000::/33"))

	script := PAC(cfg)
	if !strings.Contains(script, "2001:db8:8000::/33") {
		t.Errorf("a route that cannot be matched is not mentioned anywhere:\n%s", script)
	}
	if !strings.Contains(script, "Not covered") {
		t.Errorf("the script does not say the route is uncovered:\n%s", script)
	}

	// It still has to be a working script -- the note is a comment, not a broken rule.
	if got := runPAC(t, script, []string{"100.64.1.5"}); got["100.64.1.5"] == "DIRECT" {
		t.Error("an uncoverable route broke the rules around it")
	}
}

// The ranges are reported the same way, since writeRule emits nothing for them either.
func TestARangeThatCannotBeMatchedIsAlsoReported(t *testing.T) {
	cfg := tailnetPAC()
	cfg.Ranges = append(cfg.Ranges, netip.MustParsePrefix("fd00:1234:5678:9abc:def0::/72"))

	if script := PAC(cfg); !strings.Contains(script, "fd00:1234:5678:9abc:de00::/72") &&
		!strings.Contains(script, "fd00:1234:5678:9abc:def0::/72") {
		t.Errorf("a range that cannot be matched is not mentioned anywhere:\n%s", script)
	}
}

// The mask is what isInNet compares against, so an off-by-one here silently widens or
// narrows every address rule in the file.
func TestAPrefixLengthBecomesTheMaskIsInNetExpects(t *testing.T) {
	tests := []struct {
		bits int
		want string
	}{
		{0, "0.0.0.0"},
		{8, "255.0.0.0"},
		{10, "255.192.0.0"},
		{16, "255.255.0.0"},
		{24, "255.255.255.0"},
		{32, "255.255.255.255"},
	}
	for _, tt := range tests {
		if got := v4Netmask(tt.bits); got != tt.want {
			t.Errorf("v4Netmask(%d) = %q, want %q", tt.bits, got, tt.want)
		}
	}
}

// A textual wildcard is only exact on a hextet boundary. Anything else would match
// addresses outside the prefix, so it has to be refused rather than approximated.
func TestAnIPv6PrefixOnlyBecomesAWildcardWhenThatIsExact(t *testing.T) {
	tests := []struct {
		prefix string
		want   string
		ok     bool
	}{
		{"fd7a:115c:a1e0::/48", "fd7a:115c:a1e0:*", true},
		{"2001:db8::/32", "2001:db8:*", true},
		{"2001:db8:abcd::/64", "2001:db8:abcd:0:*", true},
		{"2001:db8:8000::/33", "", false},
		{"2001:db8::/31", "", false},
		{"::/0", "", false},
		// An IPv4 prefix reaching here is a caller mistake, and the wildcard it would
		// produce -- "100.64.*" from a dotted-quad split on colons -- matches nothing a
		// browser ever asks about, which reads as the rule silently not applying.
		{"100.64.0.0/10", "", false},
		{"192.0.2.1/32", "", false},
	}
	for _, tt := range tests {
		got, ok := v6Glob(netip.MustParsePrefix(tt.prefix))
		if ok != tt.ok {
			t.Errorf("v6Glob(%s) matched = %v, want %v", tt.prefix, ok, tt.ok)
			continue
		}
		if got != tt.want {
			t.Errorf("v6Glob(%s) = %q, want %q", tt.prefix, got, tt.want)
		}
	}
}
