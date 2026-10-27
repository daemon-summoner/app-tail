// SPDX-License-Identifier: MIT

package dnsprofiles

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseUpstreamReadsTheThreeForms(t *testing.T) {
	tests := []struct {
		in         string
		protocol   Protocol
		addr       string
		host       string
		port       uint16
		serverName string
		url        string
	}{
		{in: "1.1.1.1", protocol: Plain, addr: "1.1.1.1:53"},
		{in: "8.8.4.4:5353", protocol: Plain, addr: "8.8.4.4:5353"},
		{in: "2606:4700:4700::1111", protocol: Plain, addr: "[2606:4700:4700::1111]:53"},
		{in: "[2606:4700:4700::1111]:5353", protocol: Plain, addr: "[2606:4700:4700::1111]:5353"},
		{in: "tls://dns.google", protocol: DoT, host: "dns.google", port: 853, serverName: "dns.google"},
		{in: "tls://dns.google:8853", protocol: DoT, host: "dns.google", port: 8853, serverName: "dns.google"},
		{in: "tls://1.1.1.1", protocol: DoT, addr: "1.1.1.1:853", port: 853, serverName: "1.1.1.1"},
		{in: "tls://[2606:4700:4700::1111]", protocol: DoT, addr: "[2606:4700:4700::1111]:853", port: 853, serverName: "2606:4700:4700::1111"},
		{in: "tls://2606:4700:4700::1111", protocol: DoT, addr: "[2606:4700:4700::1111]:853", port: 853, serverName: "2606:4700:4700::1111"},
		{
			in: "https://dns.nextdns.io/abc123", protocol: DoH, host: "dns.nextdns.io", port: 443,
			serverName: "dns.nextdns.io", url: "https://dns.nextdns.io/abc123",
		},
		{
			// A hostname with no path is what someone writes when they copied only the
			// hostname; every provider serves the RFC 8484 endpoint at /dns-query.
			in: "https://cloudflare-dns.com", protocol: DoH, host: "cloudflare-dns.com", port: 443,
			serverName: "cloudflare-dns.com", url: "https://cloudflare-dns.com/dns-query",
		},
		{
			in: "https://1.1.1.1/dns-query", protocol: DoH, addr: "1.1.1.1:443", port: 443,
			serverName: "1.1.1.1", url: "https://1.1.1.1/dns-query",
		},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseUpstream(tc.in)
			if err != nil {
				t.Fatalf("ParseUpstream(%q) = %v", tc.in, err)
			}
			if got.Protocol != tc.protocol {
				t.Errorf("protocol = %q, want %q", got.Protocol, tc.protocol)
			}
			if got.Text != tc.in {
				t.Errorf("Text = %q, want %q", got.Text, tc.in)
			}
			var wantAddr netip.AddrPort
			if tc.addr != "" {
				wantAddr = netip.MustParseAddrPort(tc.addr)
			}
			if got.Addr != wantAddr {
				t.Errorf("Addr = %v, want %v", got.Addr, wantAddr)
			}
			if got.Host != tc.host {
				t.Errorf("Host = %q, want %q", got.Host, tc.host)
			}
			if got.ServerName != tc.serverName {
				t.Errorf("ServerName = %q, want %q", got.ServerName, tc.serverName)
			}
			if got.URL != tc.url {
				t.Errorf("URL = %q, want %q", got.URL, tc.url)
			}
			if tc.port != 0 && got.Port != tc.port {
				t.Errorf("Port = %d, want %d", got.Port, tc.port)
			}
			if _, ok := got.Endpoint(); ok != (tc.addr != "") {
				t.Errorf("Endpoint() ok = %v, want %v", ok, tc.addr != "")
			}
		})
	}
}

// Exactly one of the two is set, or a dialer that checks the wrong one silently skips
// the upstream and the profile looks like it has fewer servers than it does.
func TestAParsedUpstreamIsEitherLiteralOrANameNeverBoth(t *testing.T) {
	for _, in := range []string{"1.1.1.1", "tls://dns.google", "tls://1.1.1.1", "https://dns.google/dns-query", "https://8.8.8.8/dns-query"} {
		u, err := ParseUpstream(in)
		if err != nil {
			t.Fatalf("ParseUpstream(%q) = %v", in, err)
		}
		literal := u.Addr.IsValid()
		named := u.Host != ""
		if literal == named {
			t.Errorf("%q: Addr valid = %v, Host = %q -- exactly one must be set", in, literal, u.Host)
		}
	}
}

// The certificate is verified against the name the user wrote, not against whatever
// address answered for it, or resolving the name through the base servers would be a way
// to hand someone else's certificate to the dialer.
func TestPinningAnAddressKeepsTheNameTheCertificateIsCheckedAgainst(t *testing.T) {
	u, err := ParseUpstream("tls://dns.google")
	if err != nil {
		t.Fatalf("ParseUpstream: %v", err)
	}
	pinned := u.WithAddr(netip.MustParseAddr("8.8.8.8"))
	if got, ok := pinned.Endpoint(); !ok || got != netip.MustParseAddrPort("8.8.8.8:853") {
		t.Errorf("Endpoint() = %v, %v, want 8.8.8.8:853, true", got, ok)
	}
	if pinned.ServerName != "dns.google" {
		t.Errorf("ServerName = %q, want %q", pinned.ServerName, "dns.google")
	}
	if pinned.Host != "dns.google" {
		t.Errorf("Host = %q, want %q", pinned.Host, "dns.google")
	}
}

func TestParseUpstreamRefusalsNameTheMistake(t *testing.T) {
	tests := []struct {
		in   string
		says string
	}{
		{"", "required"},
		{"   ", "required"},
		// The whole point of the refusal: a bare hostname is what someone pastes when
		// they meant DoH, and the message has to tell them which form they wanted.
		{"dns.nextdns.io", "https://dns.nextdns.io/dns-query"},
		{"dns.nextdns.io", "tls://dns.nextdns.io"},
		{"http://dns.google/dns-query", "in the clear"},
		{"udp://1.1.1.1", "udp://"},
		{"sdns://AgcAAAA", "sdns://"},
		{"tls://", "names no server"},
		{"tls://dns.google/dns-query", "https://dns.google/dns-query"},
		{"tls://localhost", "single label"},
		{"tls://dns.google:0", "not a port number"},
		{"tls://dns google", "not a hostname"},
		{"https://", "names no server"},
		{"https://user:pw@dns.google/dns-query", "username"},
	}
	for _, tc := range tests {
		t.Run(tc.in+"/"+tc.says, func(t *testing.T) {
			_, err := ParseUpstream(tc.in)
			if err == nil {
				t.Fatalf("ParseUpstream(%q) = nil error", tc.in)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("ParseUpstream(%q) = %q, want it to mention %q", tc.in, err, tc.says)
			}
		})
	}
}
