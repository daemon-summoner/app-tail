// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsfwd"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// serveNames runs a plain-DNS resolver on a loopback port that answers every A question with
// one address, so a caller can tell which of two resolvers answered it. AAAA is answered with
// no records, which is what a name with no IPv6 address looks like.
func serveNames(t *testing.T, answer string) (netip.AddrPort, *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	var calls atomic.Int32
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			calls.Add(1)
			resp, err := answerA(buf[:n], answer)
			if err != nil {
				continue
			}
			pc.WriteTo(resp, from)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String()), &calls
}

func answerA(query []byte, answer string) ([]byte, error) {
	var p dnsmessage.Parser
	header, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	header.Response, header.RecursionAvailable = true, true
	b := dnsmessage.NewBuilder(nil, header)
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	if q.Type == dnsmessage.TypeA {
		addr := netip.MustParseAddr(answer)
		if err := b.AResource(
			dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			dnsmessage.AResource{A: addr.As4()},
		); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

// plainPoolAt builds a pool of plain resolvers at literal addresses, which is what a
// bootstrap profile and this network's own resolvers both come down to.
func plainPoolAt(t *testing.T, addrs ...netip.AddrPort) *dnsfwd.Pool {
	t.Helper()
	ups := make([]dnsfwd.Upstream, 0, len(addrs))
	for _, addr := range addrs {
		parsed, err := dnsprofiles.ParseUpstream(addr.String())
		if err != nil {
			t.Fatalf("parse %s: %v", addr, err)
		}
		built, err := dnsfwd.NewUpstream(parsed, nil)
		if err != nil {
			t.Fatalf("build %s: %v", addr, err)
		}
		ups = append(ups, built)
	}
	pool := dnsfwd.NewPool(ups, nil)
	t.Cleanup(func() { pool.Close() })
	return pool
}

func lookupContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// The lookup that turns tls://dns.example.com into an address is the one query the chosen
// resolver cannot answer for itself, and sending it to this network's own resolver leaves the
// network deciding which address answers for that name -- which on a network that answers
// port 53 itself is the chosen resolver taken off the air before the first real query.
func TestAResolverHostnameIsLookedUpThroughTheBootstrapAndNotThroughTheNetwork(t *testing.T) {
	bootAddr, bootCalls := serveNames(t, "203.0.113.10")
	localAddr, localCalls := serveNames(t, "198.51.100.10")
	b := &bootstrap{
		name:  "Quad9",
		pool:  plainPoolAt(t, bootAddr),
		local: plainPoolAt(t, localAddr),
	}

	addrs, err := b.lookup(lookupContext(t), "dns.example.com")

	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "203.0.113.10" {
		t.Fatalf("dns.example.com resolved to %v, want the address the bootstrap resolver gave", addrs)
	}
	if localCalls.Load() != 0 {
		t.Errorf("this network's resolvers were asked %d times, want never", localCalls.Load())
	}
	if bootCalls.Load() == 0 {
		t.Error("the bootstrap resolver was never asked")
	}
	if !strings.Contains(b.note, "Quad9") {
		t.Errorf("note = %q, want it to name the resolver that did the lookup", b.note)
	}
}

// A network that wants you to sign in first answers only its own resolver, so a bootstrap
// that cannot be reached has to give way or the machine resolves nothing at all. What it must
// not do is give way quietly: the address then came from the network, and the card is the
// only place that can say so.
func TestABootstrapThatCannotBeReachedFallsBackToTheNetworkAndSaysSo(t *testing.T) {
	localAddr, localCalls := serveNames(t, "198.51.100.10")
	b := &bootstrap{
		name:  "Quad9",
		pool:  deadPool(t),
		local: plainPoolAt(t, localAddr),
	}

	addrs, err := b.lookup(lookupContext(t), "dns.example.com")

	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "198.51.100.10" {
		t.Fatalf("dns.example.com resolved to %v, want the address this network's resolvers gave", addrs)
	}
	if localCalls.Load() == 0 {
		t.Error("this network's resolvers were never asked after the bootstrap failed")
	}
	if !strings.Contains(b.note, "this network's own resolvers") || !strings.Contains(b.note, "Quad9") {
		t.Errorf("note = %q, want it to say the network answered because Quad9 did not", b.note)
	}
}

// When the bootstrap and the network's own resolvers both fail, the card has to say both.
// Reporting the network's alone reads as the network's resolver being the one asked, and
// sends the user to their router over a machine that could reach nothing at all.
func TestALookupThatBothPathsFailedNamesBothOfThem(t *testing.T) {
	b := &bootstrap{
		name:  "Quad9",
		pool:  deadPool(t),
		local: deadPool(t),
	}

	_, err := b.lookup(lookupContext(t), "dns.example.com")

	if err == nil {
		t.Fatal("a lookup neither path could answer came back without an error")
	}
	for _, want := range []string{"Quad9 did not answer", "no route to host", "this network's own resolvers"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to carry %q", err, want)
		}
	}
}

// A connection this machine's own firewall or antivirus refused reads, resolver by resolver,
// like a network that is down, and that sends the user to their router. The card names what
// to allow instead, with the detail still behind it, and only for that cause: a resolver that
// is plainly unreachable keeps its own story.
func TestAConnectionThisMachineRefusedIsNamedAsSuchOnTheCard(t *testing.T) {
	refused := dnsfwd.NewPool([]dnsfwd.Upstream{refusedResolver{}}, nil)
	t.Cleanup(func() { refused.Close() })
	b := &bootstrap{name: "Quad9", pool: refused, local: deadPool(t)}

	_, err := b.lookup(lookupContext(t), "dns.example.com")
	if err == nil {
		t.Fatal("a lookup neither path could answer came back without an error")
	}

	got := resolverFailure(err)
	if !strings.HasPrefix(got, "this machine's firewall or antivirus is refusing app-tail's network connections; allow app-tail in it. ") {
		t.Errorf("failure = %q, want it to name the firewall first", got)
	}
	for _, want := range []string{"Quad9 did not answer", "forbidden by its access permissions", "this network's own resolvers"} {
		if !strings.Contains(got, want) {
			t.Errorf("failure = %q, want it to keep %q", got, want)
		}
	}

	b.pool = deadPool(t)
	_, err = b.lookup(lookupContext(t), "dns.example.com")
	if err == nil {
		t.Fatal("a lookup neither path could answer came back without an error")
	}
	if got := resolverFailure(err); strings.Contains(got, "firewall") {
		t.Errorf("failure = %q, blames the firewall for a resolver that is merely unreachable", got)
	}
}

// refusedResolver is a resolver this machine's own policy will not let app-tail connect to,
// the way Windows reports a per-application firewall block.
type refusedResolver struct{}

func (refusedResolver) Exchange(context.Context, []byte, bool) ([]byte, error) {
	return nil, fmt.Errorf("dial tcp 9.9.9.9:443: connectex: An attempt was made to access a socket in a way forbidden by its access permissions. (%w)", fs.ErrPermission)
}

func (refusedResolver) Label() string { return "https://9.9.9.9/dns-query" }

func (refusedResolver) Close() error { return nil }

// Nothing left to ask is a failure, not an empty answer: a profile whose resolvers cannot be
// found is a profile that cannot be applied, and swallowing it would point the machine at a
// pool with no reachable server in it.
func TestALookupWithNothingLeftToAskIsAFailure(t *testing.T) {
	b := &bootstrap{
		name:  "Quad9",
		pool:  deadPool(t),
		local: plainPoolAt(t),
	}

	_, err := b.lookup(lookupContext(t), "dns.example.com")

	if err == nil {
		t.Fatal("a lookup nothing could answer came back without an error")
	}
	if !strings.Contains(err.Error(), "Quad9") || !strings.Contains(err.Error(), "dns.example.com") {
		t.Errorf("error = %v, want it to name the resolver and the hostname", err)
	}
}

// unreachableResolver is a resolver every query to which fails at once, which is what a
// resolver behind a captive portal or a black-holed route looks like from here. It is a
// fake rather than a closed loopback port because a port nobody listens on is refused at
// once on one platform and answered with silence on another: Windows drops the refusal a
// datagram socket would otherwise report, and the lookup runs out its own timeout instead.
type unreachableResolver struct{}

func (unreachableResolver) Exchange(context.Context, []byte, bool) ([]byte, error) {
	return nil, errors.New("no route to host")
}

func (unreachableResolver) Label() string { return "203.0.113.53" }

func (unreachableResolver) Close() error { return nil }

// deadPool is a pool of one resolver that cannot be reached.
func deadPool(t *testing.T) *dnsfwd.Pool {
	t.Helper()
	pool := dnsfwd.NewPool([]dnsfwd.Upstream{unreachableResolver{}}, nil)
	t.Cleanup(func() { pool.Close() })
	return pool
}

// A bootstrap resolver named by hostname would need the lookup it is there to perform, so it
// is left out. A profile of nothing but those cannot bootstrap at all, and the fallback that
// follows is only honest if it says which profile could not do it.
func TestOnlyTheResolversThatNeedNoLookupBootstrapAnything(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	if _, err := agent.store.Update(func(c *config.Config) error {
		c.DNSProfiles = []config.DNSProfile{
			{ID: "mixed", Name: "Mixed", Servers: []string{"tls://dns.example.com", "https://9.9.9.9/dns-query"}},
			{ID: "names", Name: "Names only", Servers: []string{"tls://dns.example.com"}},
		}
		return nil
	}); err != nil {
		t.Fatalf("store: %v", err)
	}

	t.Run("a profile with a literal address supplies only that one", func(t *testing.T) {
		c := agent.store.Get()
		c.Settings.SystemDNSBootstrapProfile = "mixed"
		profile, why := agent.bootstrapProfile(context.Background(), c)
		if why != "" {
			t.Fatalf("mixed was refused: %s", why)
		}
		dialable := dnsprofiles.Dialable(profile)
		if len(dialable) != 1 || dialable[0].Text != "https://9.9.9.9/dns-query" {
			t.Fatalf("dialable = %+v, want only the resolver that needs no lookup", dialable)
		}
	})

	t.Run("a profile of hostnames is refused with the reason", func(t *testing.T) {
		c := agent.store.Get()
		c.Settings.SystemDNSBootstrapProfile = "names"
		profile, why := agent.bootstrapProfile(context.Background(), c)
		if profile.ID != "" {
			t.Fatalf("profile = %q, want none: it would need the lookup it is there to do", profile.ID)
		}
		if !strings.Contains(why, "Names only") || !strings.Contains(why, "hostname") {
			t.Errorf("reason = %q, want it to name the profile and why it cannot", why)
		}
	})
}

// The default is not "this network", because that is the one answer that lets the network
// decide what a resolver hostname means. Quad9 answers at a literal address over HTTPS, so it
// needs no lookup itself and nothing on the path can answer for it.
func TestAFreshInstallLooksResolverHostnamesUpThroughQuad9(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })

	profile, why := agent.bootstrapProfile(context.Background(), agent.store.Get())

	if why != "" {
		t.Fatalf("a fresh install has no bootstrap resolver: %s", why)
	}
	if profile.ID != dnsprofiles.Quad9ID {
		t.Fatalf("bootstrap profile = %q, want %q", profile.ID, dnsprofiles.Quad9ID)
	}
	if len(dnsprofiles.Dialable(profile)) != len(profile.Servers) {
		t.Errorf("%s: only %d of %d resolvers can be dialled without a lookup",
			profile.Name, len(dnsprofiles.Dialable(profile)), len(profile.Servers))
	}
}

// System default means something different here from what it means for the machine's
// resolver: not "change nothing", but "let this network do the lookup". It is a real choice,
// so it carries no reason -- a reason would report the user's own decision as a fault.
func TestChoosingSystemDefaultSendsTheLookupToTheNetworkWithoutComplaint(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	c := agent.store.Get()
	c.Settings.SystemDNSBootstrapProfile = dnsprofiles.SystemID

	profile, why := agent.bootstrapProfile(context.Background(), c)

	if profile.ID != "" {
		t.Fatalf("profile = %q, want none so this network's resolvers do the lookup", profile.ID)
	}
	if why != "" {
		t.Errorf("reason = %q, want none: this is what was chosen", why)
	}
}

// The bootstrap decides which addresses the profile's hostnames resolved to. A fingerprint
// blind to it would keep the pools pinned to the addresses the previous choice found, and
// switching the bootstrap resolver would appear to do nothing at all.
func TestChangingTheBootstrapResolverRebuildsThePools(t *testing.T) {
	profile := config.DNSProfile{ID: "custom", Name: "Custom", Servers: []string{"tls://dns.example.com"}}
	base := tsnode.BaseResolvers{Nameservers: []netip.Addr{netip.MustParseAddr("192.168.6.1")}}
	quad9, _ := dnsprofiles.ByID(nil, dnsprofiles.Quad9ID)
	cloudflare, _ := dnsprofiles.ByID(nil, "cloudflare")

	before := resolverFingerprint(profile, quad9, base)
	after := resolverFingerprint(profile, cloudflare, base)

	if before == after {
		t.Fatal("the fingerprint is the same for two different bootstrap resolvers, so the pools would be reused")
	}
	if same := resolverFingerprint(profile, quad9, base); same != before {
		t.Error("the fingerprint moved without anything changing, so the pools would be rebuilt every reconcile")
	}
}

// Building a bootstrap for a profile whose resolvers are all literal addresses is a pool of
// connections nothing will ever ask a question, and for DNS over TLS a handshake per
// reconcile.
func TestNoBootstrapIsBuiltForAProfileWithNothingToLookUp(t *testing.T) {
	local := plainPoolAt(t)
	literal, _ := dnsprofiles.ByID(nil, "cloudflare")
	quad9, _ := dnsprofiles.ByID(nil, dnsprofiles.Quad9ID)

	b, err := newBootstrap(systemDNSTarget{profile: literal, bootstrap: quad9}, local)

	if err != nil {
		t.Fatalf("newBootstrap: %v", err)
	}
	if b.pool != nil {
		t.Error("a bootstrap resolver was built for a profile with no hostname in it")
	}
	if b.note != "" {
		t.Errorf("note = %q, want none: nothing was looked up", b.note)
	}
}

// The whole path, as the reconcile runs it: a profile named by hostname, resolved through the
// bootstrap, with what happened on the snapshot every surface reads.
func TestApplyingAProfileNamedByHostnameReportsWhatResolvedIt(t *testing.T) {
	bootAddr, bootCalls := serveNames(t, "203.0.113.10")
	rights := &fakeResolverRights{}
	runner := newResolverRunner(t, rights)
	target := resolverTarget(t)
	target.profile = config.DNSProfile{ID: "custom", Name: "Custom", Servers: []string{"tls://dns.example.com"}}
	target.bootstrap = config.DNSProfile{ID: "boot", Name: "Boot", Servers: []string{bootAddr.String()}}

	runner.apply(lookupContext(t), target)

	snap := runner.snapshot()
	if !snap.applied {
		t.Fatalf("the override is not installed; reason %q failure %q", snap.reason, snap.failure)
	}
	if bootCalls.Load() == 0 {
		t.Fatal("the bootstrap resolver was never asked where the profile's resolver lives")
	}
	if !strings.Contains(snap.bootstrap, "Boot") {
		t.Errorf("bootstrap = %q, want it to name the resolver that did the lookup", snap.bootstrap)
	}
}
