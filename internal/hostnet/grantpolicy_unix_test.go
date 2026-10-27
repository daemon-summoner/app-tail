// SPDX-License-Identifier: MIT

//go:build unix

package hostnet

import (
	"bufio"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tailscale.com/net/dns"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/router"

	"github.com/sellitus/app-tail/internal/grants"
)

// approvingEverything is a policy under which nothing the suite sends lacks an approval:
// every route, every resolver, and the server and certificate authority workingRun uses.
// The machine is described as attached to no network, so no route depends on where the
// suite happens to run.
func approvingEverything(t *testing.T) grantPolicy {
	t.Helper()
	pins, err := grants.CAPins(workingRunCA)
	if err != nil {
		t.Fatalf("pin the test certificate authority: %v", err)
	}
	doc := grants.Document{
		Version:         grants.Version,
		FullTunnel:      true,
		Routes:          []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		SystemDNS:       true,
		TLSInterception: true,
		OpenVPN:         []grants.OpenVPNRemote{{Remote: "vpn.example.com:1194", CASHA256: pins}},
	}
	return grantPolicy{
		load:     func() (grants.Document, error) { return doc, nil },
		attached: func() ([]netip.Prefix, error) { return nil, nil },
	}
}

// approving is a policy that reads doc fresh on every request, as the real one reads the file,
// on a machine attached to the networks given.
func approving(doc *grants.Document, attached ...string) grantPolicy {
	var lans []netip.Prefix
	for _, s := range attached {
		lans = append(lans, netip.MustParsePrefix(s))
	}
	return grantPolicy{
		load:     func() (grants.Document, error) { return *doc, nil },
		attached: func() ([]netip.Prefix, error) { return lans, nil },
	}
}

// ask sends one request through answer and returns the reply.
func ask(t *testing.T, host commanded, approved *approvals, req request) response {
	t.Helper()
	server, client := unixPair(t)
	answered := make(chan error, 1)
	go func() { answered <- answer(context.Background(), server, host, req, approved, func(string, ...any) {}) }()
	var resp response
	if err := readMessage(bufio.NewReader(client), &resp); err != nil {
		t.Fatalf("read the reply to %s: %v", req.Op, err)
	}
	if err := <-answered; err != nil {
		t.Fatalf("answer %s: %v", req.Op, err)
	}
	return resp
}

func needKinds(resp response) []grants.Kind {
	var out []grants.Kind
	for _, n := range resp.NeedsGrant {
		out = append(out, n.Kind)
	}
	return out
}

func hostRoutes(ss ...string) *Routes {
	r := &Routes{}
	for _, s := range ss {
		r.Routes = append(r.Routes, netip.MustParsePrefix(s))
	}
	return r
}

func TestADefaultRouteIsRefusedWithoutAFullTunnelGrant(t *testing.T) {
	doc := grants.None()
	host := &commandedHost{}
	resp := ask(t, host, newApprovals(approving(&doc)), request{Op: opSetHostRoutes, Host: hostRoutes("0.0.0.0/0")})
	if !slices.Equal(needKinds(resp), []grants.Kind{grants.KindFullTunnel}) {
		t.Fatalf("got %+v, want a refusal needing the full-tunnel approval", resp)
	}
	if !strings.Contains(resp.Error, "app-tail tun grant --full-tunnel") {
		t.Fatalf("the refusal %q does not say how to approve it", resp.Error)
	}
	if len(host.hostRoutes.Routes) != 0 {
		t.Fatalf("the refused routes reached the privileged side: %v", host.hostRoutes.Routes)
	}
}

func TestADefaultRouteIsAcceptedWithAFullTunnelGrant(t *testing.T) {
	doc := grants.Document{Version: grants.Version, FullTunnel: true}
	host := &commandedHost{}
	resp := ask(t, host, newApprovals(approving(&doc)), request{Op: opSetHostRoutes, Host: hostRoutes("0.0.0.0/0")})
	if resp.Error != "" {
		t.Fatalf("refused: %s", resp.Error)
	}
	if len(host.hostRoutes.Routes) != 1 {
		t.Fatalf("the approved route did not reach the privileged side: %v", host.hostRoutes.Routes)
	}
}

func TestTheEnginesExitNodeRouteIsRefusedWithoutAFullTunnelGrant(t *testing.T) {
	doc := grants.None()
	host := &commandedHost{}
	cfg := &router.Config{
		LocalAddrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.7/32")},
		Routes:     []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("::/0")},
	}
	resp := ask(t, host, newApprovals(approving(&doc)), request{Op: opSetRoutes, Router: cfg})
	if !slices.Equal(needKinds(resp), []grants.Kind{grants.KindFullTunnel}) {
		t.Fatalf("got %+v, want a refusal needing the full-tunnel approval", resp)
	}
	if host.routerSeen {
		t.Fatal("the refused configuration reached the privileged side")
	}
}

func TestAPrivateRouteThatOverlapsTheLANNeedsAGrant(t *testing.T) {
	doc := grants.None()
	host := &commandedHost{}
	approved := newApprovals(approving(&doc, "192.168.1.0/24"))
	resp := ask(t, host, approved, request{Op: opSetHostRoutes, Host: hostRoutes("192.168.0.0/16")})
	if !slices.Equal(needKinds(resp), []grants.Kind{grants.KindRoute}) || resp.NeedsGrant[0].Value != "192.168.0.0/16" {
		t.Fatalf("got %+v, want a refusal needing a route approval for 192.168.0.0/16", resp)
	}
	doc.Routes = []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	if resp := ask(t, host, approved, request{Op: opSetHostRoutes, Host: hostRoutes("192.168.0.0/16")}); resp.Error != "" {
		t.Fatalf("refused once approved: %s", resp.Error)
	}
}

func TestATailnetRouteNeedsNoGrant(t *testing.T) {
	host := &commandedHost{}
	policy := grantPolicy{
		load: func() (grants.Document, error) {
			return grants.Document{}, errors.New("the approvals must not be read for this")
		},
		attached: func() ([]netip.Prefix, error) { return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, nil },
	}
	cfg := &router.Config{
		LocalAddrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.7/32"), netip.MustParsePrefix("fd7a:115c:a1e0::7/128")},
		Routes:     []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")},
	}
	if resp := ask(t, host, newApprovals(policy), request{Op: opSetRoutes, Router: cfg}); resp.Error != "" {
		t.Fatalf("the tailnet's own routes were refused: %s", resp.Error)
	}
	if !host.routerSeen {
		t.Fatal("the tailnet's own routes did not reach the privileged side")
	}
}

func TestAnApprovalsFileThatCannotBeReadRefusesWhatNeedsAnApproval(t *testing.T) {
	host := &commandedHost{}
	policy := grantPolicy{
		load: func() (grants.Document, error) {
			return grants.Document{}, errors.New("the approvals file is writable by everyone")
		},
		attached: func() ([]netip.Prefix, error) { return nil, nil },
	}
	resp := ask(t, host, newApprovals(policy), request{Op: opSetHostRoutes, Host: hostRoutes("203.0.113.0/24")})
	if !strings.Contains(resp.Error, "writable by everyone") {
		t.Fatalf("got %+v, want a refusal carrying why the approvals could not be read", resp)
	}
	if len(host.hostRoutes.Routes) != 0 {
		t.Fatal("a route was installed with the approvals unreadable")
	}
}

func TestAnApprovalTakenBackStopsCountingAtTheNextRequest(t *testing.T) {
	doc := grants.Document{Version: grants.Version, FullTunnel: true}
	approved := newApprovals(approving(&doc))
	host := &commandedHost{}
	if resp := ask(t, host, approved, request{Op: opSetHostRoutes, Host: hostRoutes("0.0.0.0/0")}); resp.Error != "" {
		t.Fatalf("refused while approved: %s", resp.Error)
	}
	doc.FullTunnel = false
	if resp := ask(t, host, approved, request{Op: opSetHostRoutes, Host: hostRoutes("0.0.0.0/0")}); len(resp.NeedsGrant) == 0 {
		t.Fatalf("accepted after the approval was taken back: %+v", resp)
	}
}

func TestPointingTheMachineAtAppTailIsRefusedWithoutASystemDNSGrant(t *testing.T) {
	doc := grants.None()
	host := &commandedHost{}
	approved := newApprovals(approving(&doc))
	resp := ask(t, host, approved, request{Op: opSetSystemDNS, Resolvers: []string{"127.0.0.53"}})
	if !slices.Equal(needKinds(resp), []grants.Kind{grants.KindSystemDNS}) {
		t.Fatalf("got %+v, want a refusal needing the system DNS approval", resp)
	}
	if host.systemDNSSet {
		t.Fatal("the refused resolver reached the privileged side")
	}
	// Putting the machine's own resolver back needs nothing.
	if resp := ask(t, host, approved, request{Op: opSetSystemDNS}); resp.Error != "" {
		t.Fatalf("restoring the machine's resolver was refused: %s", resp.Error)
	}
	doc.SystemDNS = true
	if resp := ask(t, host, approved, request{Op: opSetSystemDNS, Resolvers: []string{"127.0.0.53"}}); resp.Error != "" {
		t.Fatalf("refused once approved: %s", resp.Error)
	}
}

func TestTailnetDNSForTailnetNamesNeedsNoGrant(t *testing.T) {
	doc := grants.None()
	host := &commandedHost{}
	cfg := &dns.OSConfig{
		Nameservers:  []netip.Addr{netip.MustParseAddr("100.100.100.100")},
		MatchDomains: []dnsname.FQDN{"example-tailnet.ts.net.", "64.100.in-addr.arpa."},
	}
	if resp := ask(t, host, newApprovals(approving(&doc)), request{Op: opSetDNS, DNS: cfg}); resp.Error != "" {
		t.Fatalf("the tailnet's resolver for its own names was refused: %s", resp.Error)
	}
	if !host.interfaceSet {
		t.Fatal("the tailnet's resolver did not reach the privileged side")
	}
}

func TestAResolverForEveryLookupIsRefusedWithoutASystemDNSGrant(t *testing.T) {
	doc := grants.None()
	host := &commandedHost{}
	cfg := &dns.OSConfig{Nameservers: []netip.Addr{netip.MustParseAddr("100.100.100.100")}}
	resp := ask(t, host, newApprovals(approving(&doc)), request{Op: opSetDNS, DNS: cfg})
	if !slices.Equal(needKinds(resp), []grants.Kind{grants.KindSystemDNS}) {
		t.Fatalf("got %+v, want a refusal needing the system DNS approval", resp)
	}
	if host.interfaceSet {
		t.Fatal("the refused resolver reached the privileged side")
	}
}

func TestAnOpenVPNServerThatIsNotGrantedIsRefused(t *testing.T) {
	run := workingRun(t)
	doc := grants.None()
	host := &commandedHost{}
	resp := ask(t, host, newApprovals(approving(&doc)), request{Op: opRunOpenVPN, OpenVPN: &run})
	if !slices.Equal(needKinds(resp), []grants.Kind{grants.KindOpenVPNRemote}) || resp.NeedsGrant[0].Value != run.Remote {
		t.Fatalf("got %+v, want a refusal needing an approval for %s", resp, run.Remote)
	}
	if len(host.started) != 0 {
		t.Fatal("openvpn was started for a server nobody approved")
	}
}

func TestAGrantedOpenVPNServerWithTheWrongCAPinIsRefused(t *testing.T) {
	run := workingRun(t)
	otherPins, err := grants.CAPins("-----BEGIN CERTIFICATE-----\nb3RoZXI=\n-----END CERTIFICATE-----")
	if err != nil {
		t.Fatal(err)
	}
	doc := grants.Document{Version: grants.Version, OpenVPN: []grants.OpenVPNRemote{{Remote: run.Remote, CASHA256: otherPins}}}
	host := &commandedHost{}
	approved := newApprovals(approving(&doc))
	resp := ask(t, host, approved, request{Op: opRunOpenVPN, OpenVPN: &run})
	if !slices.Equal(needKinds(resp), []grants.Kind{grants.KindOpenVPNRemote}) {
		t.Fatalf("got %+v, want a refusal for the certificate authority", resp)
	}
	if len(host.started) != 0 {
		t.Fatal("openvpn was started trusting a certificate authority nobody approved")
	}
	rightPins, err := grants.CAPins(workingRunCA)
	if err != nil {
		t.Fatal(err)
	}
	doc.OpenVPN[0].CASHA256 = rightPins
	if resp := ask(t, host, approved, request{Op: opRunOpenVPN, OpenVPN: &run}); resp.Error != "" {
		t.Fatalf("refused with the right certificate authority approved: %s", resp.Error)
	}
	if len(host.started) != 1 {
		t.Fatal("the approved connection was not started")
	}
}

func TestAnOpenVPNConnectionCarryingEverythingNeedsTheFullTunnelGrantToo(t *testing.T) {
	run := workingRun(t)
	run.RedirectGateway = true
	pins, err := grants.CAPins(workingRunCA)
	if err != nil {
		t.Fatal(err)
	}
	doc := grants.Document{Version: grants.Version, OpenVPN: []grants.OpenVPNRemote{{Remote: run.Remote, CASHA256: pins}}}
	host := &commandedHost{}
	resp := ask(t, host, newApprovals(approving(&doc)), request{Op: opRunOpenVPN, OpenVPN: &run})
	if !slices.Equal(needKinds(resp), []grants.Kind{grants.KindFullTunnel}) {
		t.Fatalf("got %+v, want a refusal needing the full-tunnel approval", resp)
	}
}

func TestScopingAnOpenVPNConnectionWhoseApprovalWasTakenBackIsRefused(t *testing.T) {
	run := workingRun(t)
	pins, err := grants.CAPins(workingRunCA)
	if err != nil {
		t.Fatal(err)
	}
	doc := grants.Document{Version: grants.Version, OpenVPN: []grants.OpenVPNRemote{{Remote: run.Remote, CASHA256: pins}}}
	host := &commandedHost{}
	approved := newApprovals(approving(&doc))
	if resp := ask(t, host, approved, request{Op: opRunOpenVPN, OpenVPN: &run}); resp.Error != "" {
		t.Fatalf("start: %s", resp.Error)
	}
	scope := &OpenVPNScope{ID: run.ID, Interface: "utun9"}
	if resp := ask(t, host, approved, request{Op: opScopeOpenVPN, Scope: scope}); resp.Error != "" {
		t.Fatalf("scope while approved: %s", resp.Error)
	}
	doc.OpenVPN = nil
	if resp := ask(t, host, approved, request{Op: opScopeOpenVPN, Scope: scope}); len(resp.NeedsGrant) == 0 {
		t.Fatalf("scoped after the approval was taken back: %+v", resp)
	}
	if len(host.scopedVPN) != 1 {
		t.Fatalf("the privileged side was asked to scope %d times, want once", len(host.scopedVPN))
	}
}

// A client sees a refusal for a missing approval as grants.ErrNeedsGrant, carrying what is
// missing, so it can offer the command that approves it rather than report a failure.
func TestAClientSeesAMissingApprovalAsErrNeedsGrant(t *testing.T) {
	doc := grants.None()
	host := &commandedHost{}
	client := dialTo(t, testContext(t), servedByHostUnder(t, host, approving(&doc)))
	err := client.SetHostRoutes(testContext(t), Routes{Routes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}})
	if !errors.Is(err, grants.ErrNeedsGrant) {
		t.Fatalf("got %v, want an error matching grants.ErrNeedsGrant", err)
	}
	var missing *grants.MissingGrants
	if !errors.As(err, &missing) || len(missing.Needs) != 1 || missing.Needs[0].Value != "203.0.113.0/24" {
		t.Fatalf("the refusal carried %+v", missing)
	}
	want := []string{"tun", "grant", "--route=203.0.113.0/24"}
	if got := grants.GrantArgs(missing.Needs); !slices.Equal(got, want) {
		t.Fatalf("the approving command is %v, want %v", got, want)
	}
	if err := client.SetHostRoutes(testContext(t), Routes{}); err != nil {
		t.Fatalf("removing every route was refused: %v", err)
	}
}

// A client told who is listening reports each refused change under the feature that asked
// for it, and clears it when the same change goes through once approved. An empty change
// proves nothing about the approval, so it clears nothing.
func TestAClientReportsARefusedChangeAndClearsItOnceItGoesThrough(t *testing.T) {
	doc := grants.None()
	host := &commandedHost{}
	pending := grants.NewPending()
	path := servedByHostUnder(t, host, approving(&doc))
	client, err := Dial(testContext(t), Options{SocketPath: path, Logf: func(string, ...any) {}, Grants: pending})
	if err != nil {
		t.Fatalf("dial the helper: %v", err)
	}
	t.Cleanup(func() { closeIfOpen(t, client) })

	public := Routes{Routes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}
	if err := client.SetHostRoutes(testContext(t), public); !errors.Is(err, grants.ErrNeedsGrant) {
		t.Fatalf("got %v, want the route refused", err)
	}
	waiting := pending.Needs()
	if len(waiting) != 1 || waiting[0].Value != "203.0.113.0/24" || !slices.Equal(waiting[0].Features, []grants.Feature{grants.FeatureFabric}) {
		t.Fatalf("waiting = %+v, want the route, for the fabric", waiting)
	}

	if err := client.SetHostRoutes(testContext(t), Routes{}); err != nil {
		t.Fatalf("removing every route was refused: %v", err)
	}
	if len(pending.Needs()) != 1 {
		t.Fatal("removing every route cleared the refusal, though it says nothing about whether the route is approved")
	}

	doc.Routes = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	if err := client.SetHostRoutes(testContext(t), public); err != nil {
		t.Fatalf("the approved route was refused: %v", err)
	}
	if got := pending.Needs(); len(got) != 0 {
		t.Errorf("waiting = %+v after the route went through, want nothing", got)
	}
}

// A failure that is not a missing approval is not something an administrator can answer by
// approving, so it is never reported as waiting.
func TestAClientDoesNotReportAFailureThatIsNotAMissingApproval(t *testing.T) {
	host := &commandedHost{}
	pending := grants.NewPending()
	broken := grantPolicy{
		load: func() (grants.Document, error) {
			return grants.Document{}, errors.New("the approvals file is owned by someone else")
		},
		attached: func() ([]netip.Prefix, error) { return nil, nil },
	}
	path := servedByHostUnder(t, host, broken)
	client, err := Dial(testContext(t), Options{SocketPath: path, Logf: func(string, ...any) {}, Grants: pending})
	if err != nil {
		t.Fatalf("dial the helper: %v", err)
	}
	t.Cleanup(func() { closeIfOpen(t, client) })

	err = client.SetHostRoutes(testContext(t), Routes{Routes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}})
	if err == nil || errors.Is(err, grants.ErrNeedsGrant) {
		t.Fatalf("got %v, want a failure to read the approvals", err)
	}
	if got := pending.Needs(); len(got) != 0 {
		t.Errorf("waiting = %+v, want nothing", got)
	}
}

// A server approved by its address and certificate authority still chooses the address it
// hands the connection, and a wide netmask on that address is a route for the whole range. So
// what the interface ends up with is held to the approvals like any route: a host inside a
// private range beside the LAN needs nothing, a public range or one over the LAN is refused,
// and the refused range is remembered so the next start asks for its approval up front.
func TestAnAddressAnOpenVPNServerHandsOutIsHeldToTheApprovals(t *testing.T) {
	run := workingRun(t)
	pins, err := grants.CAPins(workingRunCA)
	if err != nil {
		t.Fatal(err)
	}
	doc := grants.Document{Version: grants.Version, OpenVPN: []grants.OpenVPNRemote{{Remote: run.Remote, CASHA256: pins}}}
	host := &commandedHost{}
	approved := newApprovals(approving(&doc, "192.168.1.0/24"))
	if resp := ask(t, host, approved, request{Op: opRunOpenVPN, OpenVPN: &run}); resp.Error != "" {
		t.Fatalf("start: %s", resp.Error)
	}

	if err := approved.openVPNAddresses(run.ID, []netip.Prefix{netip.MustParsePrefix("10.8.0.6/24")}); err != nil {
		t.Errorf("a private address beside the LAN was refused: %v", err)
	}
	for _, wide := range []string{"203.0.113.7/8", "192.168.1.9/24"} {
		err := approved.openVPNAddresses(run.ID, []netip.Prefix{netip.MustParsePrefix(wide)})
		if !errors.Is(err, grants.ErrNeedsGrant) {
			t.Errorf("the server's address %s was accepted with nothing approving its range: %v", wide, err)
		}
	}

	if resp := ask(t, host, approved, request{Op: opStopOpenVPN, ID: run.ID}); resp.Error != "" {
		t.Fatalf("stop: %s", resp.Error)
	}
	resp := ask(t, host, approved, request{Op: opRunOpenVPN, OpenVPN: &run})
	if !slices.Equal(needKinds(resp), []grants.Kind{grants.KindRoute}) || resp.NeedsGrant[0].Value != "192.168.1.0/24" {
		t.Fatalf("restarting the connection got %+v, want a refusal needing the range the server handed out", resp)
	}
	if len(host.started) != 1 {
		t.Fatalf("openvpn was started %d times, want once: the restart should have been refused", len(host.started))
	}

	doc.Routes = []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	if resp := ask(t, host, approved, request{Op: opRunOpenVPN, OpenVPN: &run}); resp.Error != "" {
		t.Fatalf("refused once the range was approved: %s", resp.Error)
	}
}
