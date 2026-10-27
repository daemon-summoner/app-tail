// SPDX-License-Identifier: MIT

package dnsfwd

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// interceptProbeTimeout bounds the probe. Nothing is waiting on it -- it runs beside a
// profile that is already answering -- and the only outcome that takes the whole budget is
// the good one, where the packet goes nowhere and nothing comes back.
const interceptProbeTimeout = 2 * time.Second

// interceptProbeAddr is the address the probe asks. 192.0.2.0/24 is TEST-NET-1 (RFC 5737),
// reserved for documentation: it is allocated to nobody, routed nowhere, and no resolver
// has ever lived there. That is the whole design -- a query sent here cannot be answered by
// its addressee, so an answer is not an answer, it is a device on the path replying on
// somebody else's behalf.
var interceptProbeAddr = netip.MustParseAddrPort("192.0.2.1:53")

// interceptProbeName is what the probe asks for. A name that resolves everywhere is used
// deliberately: a redirecting device answers it with a real address, which is exactly the
// packet this looks for.
const interceptProbeName = "example.com"

// PlainDNSIntercepted reports whether this network answers plain DNS itself.
//
// It matters because a profile of plain addresses cannot be trusted on a network that
// redirects port 53: every query the user believes is going to Cloudflare is answered by
// the router or the ISP instead, the machine's resolution does not change in any way the
// user can see, and app-tail would be claiming to resolve through a server it never
// reached. Encrypted profiles are unaffected -- DNS over TLS and DNS over HTTPS either
// reach the resolver that was picked or fail loudly.
//
// A true here is proof, not a guess. A false is the ordinary case and is not proof of the
// opposite: a device that redirects port 53 without answering for unrouted addresses would
// go unseen, so this is reported when it fires and never used to certify that plain DNS is
// safe.
func PlainDNSIntercepted(ctx context.Context) (bool, error) {
	return plainDNSIntercepted(ctx, interceptProbeAddr)
}

func plainDNSIntercepted(ctx context.Context, probe netip.AddrPort) (bool, error) {
	query, err := encodeQuery(Question{
		ID:    randomID(),
		Name:  interceptProbeName,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	})
	if err != nil {
		return false, err
	}
	up := plainAt(probe, probe.String())

	ctx, cancel := context.WithTimeout(ctx, interceptProbeTimeout)
	defer cancel()
	answer, err := up.exchangeUDP(ctx, query)
	if err != nil {
		// Every failure means the same thing here: nothing answered for an address nothing
		// lives at, which is the network behaving. The error is returned rather than
		// swallowed so a caller that cannot even send -- no route, a blocked socket -- can
		// tell that apart from a probe that ran and found nothing.
		return false, fmt.Errorf("ask %s, which nothing should answer: %w", probe, err)
	}
	if !isResponse(answer) {
		return false, fmt.Errorf("%s sent something that is not a DNS response", probe)
	}
	return true, nil
}
