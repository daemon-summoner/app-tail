// SPDX-License-Identifier: MIT

package hostnet

import (
	"tailscale.com/net/dns"
	"tailscale.com/util/dnsname"
)

// magicDNSZone is the parent of every tailnet's own suffix: a tailnet's names live at
// <tailnet>.ts.net and nowhere else. It is what tells the tailnet's domains apart from the
// machine's, which matters because the two arrive in one list.
var magicDNSZone = dnsname.FQDN("ts.net.")

// matchTailnetDomains points the machine at the tailnet's resolver for the tailnet's own
// names, on the platforms that install a resolver per domain rather than one for everything.
//
// macOS installs a resolver by writing a file per domain it is for, so a configuration that
// names a resolver and no domains installs nothing at all: the tailnet's resolver answers on
// the interface and the machine never asks it. What that leaves is a node reaching every
// peer by address and none by name, and the address is the part a person does not have.
//
// Only the tailnet's own suffixes are taken. The search domains carry the machine's as well,
// and sending those to the tailnet's resolver would take the local network's names with it.
//
// perDomain is passed in rather than read here so both answers are reachable from any
// machine.
func matchTailnetDomains(cfg dns.OSConfig, perDomain bool) dns.OSConfig {
	// A configuration that already names its domains is one the platform can install as it
	// stands, and one naming no resolver is a machine being left alone.
	if !perDomain || len(cfg.Nameservers) == 0 || len(cfg.MatchDomains) > 0 {
		return cfg
	}
	for _, domain := range cfg.SearchDomains {
		if magicDNSZone.Contains(domain) {
			cfg.MatchDomains = append(cfg.MatchDomains, domain)
		}
	}
	return cfg
}
