// SPDX-License-Identifier: MIT

package grants

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// What app-tail may do without anybody's approval, and what it may not.
//
// The line is drawn at addresses that never leave a private network. A route into one of
// those reaches a tailnet peer, a subnet behind one, or a network app-tail moved out of the
// way of this machine's own -- none of which is the public internet, and none of which takes
// traffic away from where it was going. Two things push a route across the line: a public
// destination, and a private one this machine is already attached to, because a route there
// takes the machine's own LAN away from it.

// freeRanges are the ranges a route may sit inside without approval.
var freeRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),     // RFC 1918
	netip.MustParsePrefix("172.16.0.0/12"),  // RFC 1918
	netip.MustParsePrefix("192.168.0.0/16"), // RFC 1918
	netip.MustParsePrefix("100.64.0.0/10"),  // shared address space, which is also the tailnet's
	// Set aside for benchmarking and routed nowhere on the internet. It is the default pool
	// the one-interface mode moves every connected network into, so without it every such
	// setup would need an approval for a range that reaches nothing public.
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("fc00::/7"), // unique local, which holds the tailnet's IPv6 range
}

// tailnetRanges are the addresses a tailnet hands out, its own resolver among them.
var tailnetRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

// tailnetDomain is the zone every tailnet's names live under.
const tailnetDomain = "ts.net."

// within reports whether every address in p is inside outer.
func within(p, outer netip.Prefix) bool {
	return outer.Bits() <= p.Bits() && outer.Contains(p.Addr())
}

func withinAny(p netip.Prefix, outers []netip.Prefix) bool {
	return slices.ContainsFunc(outers, func(outer netip.Prefix) bool { return within(p, outer) })
}

// RouteNeeds is what sending these ranges to app-tail needs that this document does not
// approve. attached are the networks on this machine's own interfaces.
//
// A default route counts whole or as the two halves that stand in for one, because the two
// halves are how a default route is installed beside the machine's own -- the same shape
// openvpn's redirect-gateway uses.
func (d Document) RouteNeeds(routes, attached []netip.Prefix) []Need {
	masked := make([]netip.Prefix, 0, len(routes))
	for _, p := range routes {
		if p.IsValid() {
			masked = append(masked, p.Masked())
		}
	}
	halves := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"),
		netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1"),
	}
	splitV4 := slices.Contains(masked, halves[0]) && slices.Contains(masked, halves[1])
	splitV6 := slices.Contains(masked, halves[2]) && slices.Contains(masked, halves[3])

	var needs []Need
	full := splitV4 || splitV6
	for _, p := range masked {
		if p.Bits() == 0 {
			full = true
			continue
		}
		if (splitV4 && (p == halves[0] || p == halves[1])) || (splitV6 && (p == halves[2] || p == halves[3])) {
			continue
		}
		reason := ""
		switch {
		case !withinAny(p, freeRanges):
			reason = fmt.Sprintf("send traffic for %s, which includes public addresses, through app-tail", p)
		default:
			for _, lan := range attached {
				if lan.IsValid() && lan.Overlaps(p) {
					reason = fmt.Sprintf("send traffic for %s through app-tail, which takes over %s, a network this machine is on", p, lan.Masked())
					break
				}
			}
		}
		if reason == "" || withinAny(p, d.Routes) {
			continue
		}
		needs = appendNeed(needs, Need{Kind: KindRoute, Value: p.String(), Reason: reason})
	}
	if full && !d.FullTunnel {
		needs = slices.Insert(needs, 0, Need{Kind: KindFullTunnel, Reason: "carry all of this machine's internet traffic through app-tail"})
	}
	return needs
}

// InterfaceDNSNeeds is what a resolver configuration for app-tail's interface needs that this
// document does not approve.
//
// Resolvers on this machine's own loopback or inside the tailnet, answering only for the
// tailnet's names, need nothing. A resolver anywhere else, a configuration with no domains --
// which makes it the resolver for every lookup this machine makes -- or a domain outside the
// tailnet's needs an approval.
func (d Document) InterfaceDNSNeeds(nameservers []netip.Addr, matchDomains []string) []Need {
	var needs []Need
	for _, addr := range nameservers {
		if addr.IsLoopback() || tailnetAddr(addr) {
			continue
		}
		needs = appendNeed(needs, Need{Kind: KindSystemDNS,
			Reason: fmt.Sprintf("send this machine's name lookups to %s, a resolver outside the tailnet", addr)})
	}
	if len(nameservers) > 0 && len(matchDomains) == 0 {
		needs = appendNeed(needs, Need{Kind: KindSystemDNS,
			Reason: "answer every name lookup this machine makes, rather than only the tailnet's"})
	}
	for _, domain := range matchDomains {
		fqdn, err := NormalizeDomain(domain)
		if err != nil {
			fqdn = domain
		}
		if tailnetZone(fqdn) || d.domainApproved(fqdn) {
			continue
		}
		needs = appendNeed(needs, Need{Kind: KindDNSDomain, Value: fqdn,
			Reason: fmt.Sprintf("answer this machine's lookups for %s, which is outside the tailnet", fqdn)})
	}
	if d.SystemDNS {
		return nil
	}
	return needs
}

// SystemDNSNeeds is what pointing this machine's own name resolution at app-tail needs. Any
// list of resolvers does: that is the machine's primary resolver changing hands. An empty list
// puts back what the machine had, which needs nothing.
func (d Document) SystemDNSNeeds(resolvers []netip.Addr) []Need {
	if len(resolvers) == 0 || d.SystemDNS {
		return nil
	}
	return []Need{{Kind: KindSystemDNS, Reason: "make app-tail the resolver this machine sends every name lookup to"}}
}

// OpenVPNNeeds is what starting an OpenVPN connection to remote, trusting the certificate
// authority in caPEM, needs that this document does not approve. A certificate authority that
// is not a list of certificates is an error rather than a need: nothing could approve it.
func (d Document) OpenVPNNeeds(remote, caPEM string) ([]Need, error) {
	pins, err := CAPins(caPEM)
	if err != nil {
		return nil, err
	}
	need := Need{Kind: KindOpenVPNRemote, Value: remote, CASHA256: pins}
	for _, approved := range d.OpenVPN {
		if !strings.EqualFold(approved.Remote, remote) {
			continue
		}
		missing := slices.DeleteFunc(slices.Clone(pins), func(pin string) bool { return slices.Contains(approved.CASHA256, pin) })
		if len(missing) == 0 {
			return nil, nil
		}
		need.Reason = fmt.Sprintf("start an OpenVPN connection to %s trusting a certificate authority it was not approved with", remote)
		return []Need{need}, nil
	}
	need.Reason = fmt.Sprintf("start an OpenVPN connection to %s, a server nobody has approved", remote)
	return []Need{need}, nil
}

// TLSInterceptionNeeds is what opening encrypted connections to read them needs.
func (d Document) TLSInterceptionNeeds() []Need {
	if d.TLSInterception {
		return nil
	}
	return []Need{{Kind: KindTLSInterception, Reason: "open encrypted connections so what they carry can be inspected"}}
}

// CAPins is the SHA-256 of every certificate in a PEM bundle, as lowercase hex, in the order
// they appear. The digest is over each certificate's DER bytes, which is what
// `openssl x509 -outform der | shasum -a 256` prints for one certificate.
func CAPins(caPEM string) ([]string, error) {
	rest := []byte(caPEM)
	var pins []string
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("the certificate authority holds a %q block, and only certificates can be approved", block.Type)
		}
		sum := sha256.Sum256(block.Bytes)
		pins = append(pins, hex.EncodeToString(sum[:]))
		rest = next
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("the certificate authority holds something besides certificates")
	}
	if len(pins) == 0 {
		return nil, errors.New("the certificate authority holds no certificate")
	}
	return pins, nil
}

func (d Document) domainApproved(fqdn string) bool {
	return slices.ContainsFunc(d.DNSDomains, func(approved string) bool { return under(fqdn, approved) })
}

// under reports whether fqdn is zone or a name inside it. Both end in a dot.
func under(fqdn, zone string) bool {
	return fqdn == zone || strings.HasSuffix(fqdn, "."+zone)
}

func tailnetAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	return slices.ContainsFunc(tailnetRanges, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// tailnetZone reports whether a domain belongs to the tailnet: its own zone, or the reverse
// zone of one of its address ranges, which is what a lookup of a tailnet address asks for.
func tailnetZone(fqdn string) bool {
	if under(fqdn, tailnetDomain) {
		return true
	}
	prefix, ok := reverseZone(fqdn)
	return ok && withinAny(prefix, tailnetRanges)
}

// reverseZone reads the range an in-addr.arpa or ip6.arpa zone covers.
func reverseZone(fqdn string) (netip.Prefix, bool) {
	if labels, ok := strings.CutSuffix(fqdn, ".in-addr.arpa."); ok {
		parts := strings.Split(labels, ".")
		if len(parts) == 0 || len(parts) > 4 {
			return netip.Prefix{}, false
		}
		var octets [4]byte
		for i, part := range parts {
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 || n > 255 || strconv.Itoa(n) != part {
				return netip.Prefix{}, false
			}
			octets[len(parts)-1-i] = byte(n)
		}
		return netip.PrefixFrom(netip.AddrFrom4(octets), 8*len(parts)), true
	}
	if labels, ok := strings.CutSuffix(fqdn, ".ip6.arpa."); ok {
		parts := strings.Split(labels, ".")
		if len(parts) == 0 || len(parts) > 32 {
			return netip.Prefix{}, false
		}
		var addr [16]byte
		for i, part := range parts {
			n, err := strconv.ParseUint(part, 16, 8)
			if err != nil || len(part) != 1 {
				return netip.Prefix{}, false
			}
			nibble := len(parts) - 1 - i
			if nibble%2 == 0 {
				addr[nibble/2] |= byte(n) << 4
			} else {
				addr[nibble/2] |= byte(n)
			}
		}
		return netip.PrefixFrom(netip.AddrFrom16(addr), 4*len(parts)), true
	}
	return netip.Prefix{}, false
}
