// SPDX-License-Identifier: MIT

package tlsmint

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/sellitus/app-tail/internal/dnsblock"
)

// Constraints are the destinations a root may sign for, written into the root itself as X.509
// name constraints.
//
// They are what makes the root's key worth less to whoever steals it. A root with no
// constraints signs for every site on the internet, so its key in the wrong hands is every
// site; a root limited to the list interception was switched on for is that list and nothing
// else, because every verifier that honours the constraint refuses a certificate outside it
// whatever key signed it.
type Constraints struct {
	// Mode is which way the list is read. ModeOnly is "these and nothing else", ModeExcept is
	// "anything but these", and ModeOff is a root carrying no constraint at all, which only a
	// root made before roots were limited can be.
	Mode Mode
	// Domains are names, each covering itself and everything under it, the way the scope's
	// own list reads them. Networks are address ranges. Both are sorted and hold no repeats,
	// so two Constraints made from the same list compare equal.
	Domains  []string
	Networks []netip.Prefix
}

// probeDomain is permitted by every ModeOnly root on top of the user's list, so the check that
// asks the trust store whether the root is installed has a name it may mint for.
//
// It is under .invalid, which RFC 6761 reserves so that no name in it ever resolves: permitting
// it lets the root sign for nothing a real site could be.
const probeDomain = "app-tail.invalid"

// installedProbe is the name the installed check mints a certificate for.
const installedProbe = "installed-check." + probeDomain

// ConstraintsFor are the constraints a root made for one interception scope carries: in ModeOnly
// the destinations named, in ModeExcept everything but them.
//
// Entries are read the way the scope reads them -- a name covers its subtree, an address is the
// network holding only it -- and a leading "*." is dropped, since the name under it already
// covers its subtree. An entry the constraints cannot express is refused, naming it: in
// ModeExcept a root without it would sign for the destination the person asked to have left
// alone. A list with nothing usable left is refused too: in ModeOnly the root would sign for
// nothing, and in ModeExcept it would sign for everything, which is the root this exists to stop
// making.
func ConstraintsFor(mode Mode, entries []string) (Constraints, error) {
	if mode == ModeOff {
		return Constraints{}, errors.New("interception is off, so there is no list to limit a root to")
	}
	c := Constraints{Mode: mode}
	for _, raw := range entries {
		text := strings.TrimSpace(raw)
		if text == "" {
			continue
		}
		if prefix, ok := entryPrefix(text); ok {
			if !slices.Contains(c.Networks, prefix) {
				c.Networks = append(c.Networks, prefix)
			}
			continue
		}
		name := constraintName(strings.TrimPrefix(text, "*."))
		if name == "" {
			return Constraints{}, fmt.Errorf("%q is neither a domain name of two or more labels nor an "+
				"address or network, so a root cannot be limited by it", text)
		}
		if !slices.Contains(c.Domains, name) {
			c.Domains = append(c.Domains, name)
		}
	}
	if len(c.Domains) == 0 && len(c.Networks) == 0 {
		return Constraints{}, errors.New("none of the destinations listed is a name or a network a root can be limited to")
	}
	slices.Sort(c.Domains)
	slices.SortFunc(c.Networks, func(a, b netip.Prefix) int { return a.Compare(b) })
	return c, nil
}

// entryPrefix reads an entry as a network, the way the scope's matcher does: a bare address is
// the network holding only it, and a network is masked to the one its length names.
//
// A network inside IPv6's IPv4-mapped range is the IPv4 network it maps. A verifier compares an
// IPv4 address only with IPv4 ranges, so left in its mapped form it would constrain nothing.
func entryPrefix(text string) (netip.Prefix, bool) {
	if prefix, err := netip.ParsePrefix(text); err == nil {
		if addr := prefix.Addr(); addr.Is4In6() && prefix.Bits() >= 96 {
			return netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96).Masked(), true
		}
		return prefix.Masked(), true
	}
	if addr, err := netip.ParseAddr(text); err == nil {
		at := addr.Unmap()
		return netip.PrefixFrom(at, at.BitLen()), true
	}
	return netip.Prefix{}, false
}

// constraintName is an entry as the name a constraint carries, or empty when it cannot be one.
// It is narrower than the scope's matcher on purpose: a name a certificate cannot be minted for
// gains nothing by being permitted, and one the constraint parser would refuse would make the
// root itself unreadable.
func constraintName(text string) string {
	name := dnsblock.Normalize(text)
	labels := strings.Split(name, ".")
	if len(labels) < 2 || len(name) > 253 {
		return ""
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return ""
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return ""
			}
		}
	}
	return name
}

// apply writes the constraints into a root's template.
//
// A ModeOnly root with no network listed excludes every address rather than permitting none:
// X.509 reads an empty permitted list as no constraint at all, so leaving it empty would let
// the root sign for any address.
//
// The extension is critical in both modes, as RFC 5280 requires of a CA, so a verifier that
// cannot read it refuses the root instead of ignoring the limit.
func (c Constraints) apply(template *x509.Certificate) {
	switch c.Mode {
	case ModeOnly:
		template.PermittedDNSDomains = append(slices.Clone(c.Domains), probeDomain)
		if len(c.Networks) > 0 {
			template.PermittedIPRanges = ipNets(c.Networks)
		} else {
			template.ExcludedIPRanges = ipNets([]netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			})
		}
	case ModeExcept:
		template.ExcludedDNSDomains = slices.Clone(c.Domains)
		template.ExcludedIPRanges = ipNets(c.Networks)
	}
	template.PermittedDNSDomainsCritical = true
}

// constraintsOf reads the constraints back off a parsed root. A root with a permitted list was
// made in ModeOnly, one with only an excluded list in ModeExcept, and one with neither predates
// roots being limited.
func constraintsOf(cert *x509.Certificate) Constraints {
	switch {
	case len(cert.PermittedDNSDomains) > 0 || len(cert.PermittedIPRanges) > 0:
		c := Constraints{Mode: ModeOnly, Networks: prefixes(cert.PermittedIPRanges)}
		for _, d := range cert.PermittedDNSDomains {
			if name := strings.ToLower(d); name != probeDomain {
				c.Domains = append(c.Domains, name)
			}
		}
		return c
	case len(cert.ExcludedDNSDomains) > 0 || len(cert.ExcludedIPRanges) > 0:
		c := Constraints{Mode: ModeExcept, Networks: prefixes(cert.ExcludedIPRanges)}
		for _, d := range cert.ExcludedDNSDomains {
			c.Domains = append(c.Domains, strings.ToLower(d))
		}
		return c
	}
	return Constraints{}
}

// Permits reports whether a certificate for one name or address falls inside the constraints,
// which is whether a client that honours them would accept it. It is the same reading the
// verifier makes, kept here so the answer is known before a certificate is minted rather than
// after a client has refused one.
func (c Constraints) Permits(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if addr, err := netip.ParseAddr(name); err == nil {
		at := addr.Unmap()
		in := slices.ContainsFunc(c.Networks, func(p netip.Prefix) bool { return p.Contains(at) })
		switch c.Mode {
		case ModeOnly:
			return in
		case ModeExcept:
			return !in
		}
		return true
	}
	under := slices.ContainsFunc(c.Domains, func(d string) bool { return withinDomain(name, d) })
	switch c.Mode {
	case ModeOnly:
		return under || withinDomain(name, probeDomain)
	case ModeExcept:
		return !under
	}
	return true
}

// Covers reports whether a root carrying c can sign for every destination a scope limited to
// want would open. False is a root that has to be replaced for the scope to work in full: a
// destination outside it would be handed a certificate every client trusting the root refuses.
func (c Constraints) Covers(want Constraints) bool {
	switch {
	case c.Mode == ModeOff || want.Mode == ModeOff:
		return true
	case c.Mode == ModeOnly:
		if want.Mode != ModeOnly {
			return false
		}
		for _, d := range want.Domains {
			if !slices.ContainsFunc(c.Domains, func(held string) bool { return withinDomain(d, held) }) {
				return false
			}
		}
		for _, p := range want.Networks {
			if !slices.ContainsFunc(c.Networks, func(held netip.Prefix) bool { return holds(held, p) }) {
				return false
			}
		}
		return true
	case want.Mode == ModeOnly:
		// An except root covers a list of names when nothing on that list reaches into what the
		// root leaves out, in either direction: a name under an excluded one is refused, and so
		// is an excluded name under a listed one, because the list covers its subtree.
		for _, d := range want.Domains {
			if slices.ContainsFunc(c.Domains, func(left string) bool {
				return withinDomain(d, left) || withinDomain(left, d)
			}) {
				return false
			}
		}
		for _, p := range want.Networks {
			if slices.ContainsFunc(c.Networks, func(left netip.Prefix) bool { return left.Overlaps(p) }) {
				return false
			}
		}
		return true
	default:
		// Two except lists: the root covers the new one when everything it leaves out is still
		// left out, so the new list may grow but not lose an entry.
		for _, left := range c.Domains {
			if !slices.ContainsFunc(want.Domains, func(d string) bool { return withinDomain(left, d) }) {
				return false
			}
		}
		for _, left := range c.Networks {
			if !slices.ContainsFunc(want.Networks, func(p netip.Prefix) bool { return holds(p, left) }) {
				return false
			}
		}
		return true
	}
}

// Describe says what a root carrying these constraints can sign for, as the end of a sentence
// beginning "This root can sign for".
func (c Constraints) Describe() string {
	entries := make([]string, 0, len(c.Domains)+len(c.Networks))
	entries = append(entries, c.Domains...)
	for _, p := range c.Networks {
		entries = append(entries, p.String())
	}
	switch c.Mode {
	case ModeOnly:
		if len(entries) <= 4 {
			return "only " + joinWords(entries)
		}
		return fmt.Sprintf("only the %d destinations it was made for", len(entries))
	case ModeExcept:
		return fmt.Sprintf("any site except the %d %s it was made to leave alone",
			len(entries), plural(len(entries), "destination", "destinations"))
	}
	return "any site, because it was made before app-tail limited its roots"
}

// withinDomain reports whether name is domain or under it.
func withinDomain(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// holds reports whether outer contains every address in inner.
func holds(outer, inner netip.Prefix) bool {
	return outer.Addr().Is4() == inner.Addr().Is4() && outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

func ipNets(prefixes []netip.Prefix) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, &net.IPNet{
			IP:   net.IP(p.Addr().AsSlice()),
			Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
		})
	}
	return out
}

// prefixes reads a certificate's address ranges back. A range that does not convert is dropped:
// the parser has already refused a certificate whose ranges are malformed, so one reaching here
// is one Go read, and there is no shape of it this could misread into a wider range.
func prefixes(nets []*net.IPNet) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(nets))
	for _, n := range nets {
		addr, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ones, _ := n.Mask.Size()
		addr = addr.Unmap()
		if addr.Is4() && ones > 32 {
			ones -= 96
		}
		out = append(out, netip.PrefixFrom(addr, ones).Masked())
	}
	return out
}

func joinWords(words []string) string {
	switch len(words) {
	case 0:
		return "nothing"
	case 1:
		return words[0]
	}
	return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
