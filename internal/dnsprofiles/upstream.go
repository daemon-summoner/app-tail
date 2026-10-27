// SPDX-License-Identifier: MIT

package dnsprofiles

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Protocol is how a query reaches one upstream resolver.
type Protocol string

const (
	// Plain is DNS over UDP with a TCP retry, port 53 unless the address says otherwise.
	Plain Protocol = "plain"
	// DoT is DNS over TLS (RFC 7858), port 853 unless the address says otherwise.
	DoT Protocol = "tls"
	// DoH is DNS over HTTPS (RFC 8484), always port 443 unless the URL says otherwise.
	DoH Protocol = "https"
)

// Upstream is one parsed resolver address: everything a dialer needs and nothing about
// how the query is carried.
//
// Exactly one of Addr and Host is set. A literal address is usable immediately; a Host
// has to be resolved first, and it is resolved once through the machine's own base
// resolvers when the profile is applied, never through this forwarder. Asking ourselves
// where our upstream lives is a deadlock, and it is why a plain upstream may not be a
// hostname at all: there would be nothing left to ask.
type Upstream struct {
	Protocol Protocol
	// Text is the string this was parsed from, kept for messages and for the dashboard,
	// which shows the user what they typed rather than a normalised rewrite of it.
	Text string
	// Addr is the literal endpoint, with the protocol's default port filled in. Zero
	// when Host is set.
	Addr netip.AddrPort
	// Host is the name to resolve. Empty when Addr is set.
	Host string
	// Port is the port to use once Host resolves. Zero when Addr is set.
	Port uint16
	// ServerName is the name to verify the certificate against, for DoT and DoH. Empty
	// for Plain.
	ServerName string
	// URL is the DoH endpoint, path included. Empty for Plain and DoT.
	URL string
}

// Endpoint reports the literal endpoint and whether there is one. A false means Host
// still has to be resolved.
func (u Upstream) Endpoint() (netip.AddrPort, bool) {
	return u.Addr, u.Addr.IsValid()
}

// WithAddr returns a copy of u pinned to a resolved address, which is how a Host
// upstream becomes dialable. The Host and ServerName are kept: the certificate is still
// verified against the name the user wrote, not against whatever address answered for it.
func (u Upstream) WithAddr(addr netip.Addr) Upstream {
	u.Addr = netip.AddrPortFrom(addr, u.Port)
	return u
}

// ParseUpstream reads one upstream address in the grammar the profile editor accepts:
//
//	1.1.1.1                      plain DNS on port 53
//	1.1.1.1:5353                 plain DNS on another port
//	2606:4700:4700::1111         plain DNS over IPv6
//	[2606:4700:4700::1111]:5353  plain DNS over IPv6 on another port
//	tls://dns.google             DNS over TLS on port 853
//	tls://1.1.1.1:853            DNS over TLS at a literal address
//	https://dns.google/dns-query DNS over HTTPS
//
// Every refusal names the mistake rather than the grammar, because the person typing
// this is copying an address out of their resolver's documentation and the useful thing
// to say is which of the three forms they wanted.
func ParseUpstream(s string) (Upstream, error) {
	text := strings.TrimSpace(s)
	if text == "" {
		return Upstream{}, fmt.Errorf("a resolver address is required")
	}
	// The scheme is matched without case because URL schemes are case-insensitive and a
	// pasted TLS:// is the same address, not a different one.
	lower := strings.ToLower(text)
	switch {
	case strings.HasPrefix(lower, "tls://"):
		return parseDoT(text)
	case strings.HasPrefix(lower, "https://"):
		return parseDoH(text)
	case strings.HasPrefix(lower, "http://"):
		// Named on its own because it is the mistake people make, and because it is the
		// one that quietly costs them the privacy they switched resolvers to get.
		return Upstream{}, fmt.Errorf("DNS over HTTPS must be https://, not http:// -- plain http would send every name you look up in the clear")
	case strings.Contains(text, "://"):
		scheme, _, _ := strings.Cut(text, "://")
		return Upstream{}, fmt.Errorf("%q is not a resolver address app-tail can use; write an IP address for plain DNS, tls:// for DNS over TLS, or https:// for DNS over HTTPS", scheme+"://")
	}
	return parsePlain(text)
}

func parsePlain(text string) (Upstream, error) {
	if addr, err := netip.ParseAddr(text); err == nil {
		return Upstream{
			Protocol: Plain,
			Text:     text,
			Addr:     netip.AddrPortFrom(addr, 53),
		}, nil
	}
	if ap, err := netip.ParseAddrPort(text); err == nil {
		if ap.Port() == 0 {
			return Upstream{}, fmt.Errorf("%q has no port; leave the port off to use 53", text)
		}
		return Upstream{Protocol: Plain, Text: text, Addr: ap}, nil
	}
	// Everything that is not an address lands here, and the overwhelmingly common case
	// is a hostname pasted from a DoH or DoT provider's page.
	return Upstream{}, fmt.Errorf("%q is not an IP address -- plain DNS needs one, because app-tail is the thing that would have to resolve the name. For a provider that gives you a hostname, write tls://%s for DNS over TLS or https://%s/dns-query for DNS over HTTPS", text, text, text)
}

func parseDoT(text string) (Upstream, error) {
	rest := strings.TrimSuffix(text[len("tls://"):], "/")
	if rest == "" {
		return Upstream{}, fmt.Errorf("%q names no server; write tls:// followed by the resolver's hostname or address", text)
	}
	if strings.ContainsAny(rest, "/?#") {
		return Upstream{}, fmt.Errorf("%q has a path -- DNS over TLS is a host and a port, with no URL. A provider that gave you a URL is offering DNS over HTTPS: write it as https://%s", text, rest)
	}
	host, port, err := splitHostPort(rest, 853)
	if err != nil {
		return Upstream{}, fmt.Errorf("%q: %w", text, err)
	}
	host = strings.ToLower(host)
	u := Upstream{Protocol: DoT, Text: text, Port: port, ServerName: host}
	if addr, err := netip.ParseAddr(host); err == nil {
		u.Addr = netip.AddrPortFrom(addr, port)
		return u, nil
	}
	if err := checkHostname(host); err != nil {
		return Upstream{}, fmt.Errorf("%q: %w", text, err)
	}
	u.Host = host
	return u, nil
}

func parseDoH(text string) (Upstream, error) {
	parsed, err := url.Parse(text)
	if err != nil {
		return Upstream{}, fmt.Errorf("%q is not a URL: %w", text, err)
	}
	if parsed.Host == "" {
		return Upstream{}, fmt.Errorf("%q names no server; write https:// followed by the resolver's hostname and path", text)
	}
	if parsed.User != nil {
		return Upstream{}, fmt.Errorf("%q carries a username -- DNS over HTTPS providers identify you with the path, not with credentials", text)
	}
	host, port, err := splitHostPort(parsed.Host, 443)
	if err != nil {
		return Upstream{}, fmt.Errorf("%q: %w", text, err)
	}
	host = strings.ToLower(host)
	if parsed.Path == "" || parsed.Path == "/" {
		// Every provider serves the RFC 8484 endpoint here, and a URL with no path is
		// what someone writes when they copied only the hostname.
		parsed.Path = "/dns-query"
	}
	u := Upstream{Protocol: DoH, Text: text, Port: port, ServerName: host, URL: parsed.String()}
	if addr, err := netip.ParseAddr(host); err == nil {
		u.Addr = netip.AddrPortFrom(addr, port)
		return u, nil
	}
	if err := checkHostname(host); err != nil {
		return Upstream{}, fmt.Errorf("%q: %w", text, err)
	}
	u.Host = host
	return u, nil
}

// splitHostPort accepts a bare host, a host:port, or a bracketed IPv6 literal with or
// without a port, and fills in the protocol's default. The host comes back unbracketed.
func splitHostPort(s string, defaultPort uint16) (string, uint16, error) {
	if !strings.Contains(s, ":") {
		return s, defaultPort, nil
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return strings.Trim(s, "[]"), defaultPort, nil
	}
	// A bare IPv6 literal is all colons and no brackets; treating its last group as a
	// port is the confusing failure this catches.
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.String(), defaultPort, nil
	}
	host, portText, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("cannot tell the host from the port in %q; put an IPv6 address in brackets, as [%s]:%d", s, s, defaultPort)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("%q is not a port number", portText)
	}
	return host, uint16(port), nil
}

// checkHostname refuses the shapes that would fail much later, at dial or certificate
// time, where the message would name a Go library rather than the address the user typed.
func checkHostname(host string) error {
	if host == "" {
		return fmt.Errorf("the hostname is empty")
	}
	// Characters before shape: a typo like a stray space is the actual mistake, and
	// reporting it as "a single label" would send the reader looking for the wrong thing.
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return fmt.Errorf("%q is not a hostname: %q does not belong in one", host, string(r))
		}
	}
	if !strings.Contains(host, ".") {
		return fmt.Errorf("%q is a single label; a resolver's hostname has a domain, as in dns.example.com", host)
	}
	return nil
}
