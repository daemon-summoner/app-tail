// SPDX-License-Identifier: MIT

package app

// Downloading one list: what is refused before a socket is opened. A feed decides which names
// are blocked and which connections are refused, so where it may be fetched from is checked
// here rather than trusted from the address somebody typed.

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsfwd"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/feeds"
	"github.com/sellitus/app-tail/internal/tsnode"
)

const testFetchCap = 1 << 20

// weAreTheResolver puts the agent in the state the fallback path exists for: app-tail holds
// this machine's name resolution, so the system resolver is this process and base is what the
// machine's own configuration said before app-tail replaced it.
func weAreTheResolver(a *Agent, base tsnode.BaseResolvers) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.systemDNS = &systemDNSRunner{logger: a.logger, base: base, applied: true}
}

// An address a list may not come from is refused after the name is resolved and before
// anything is dialled. Without this, "add a feed" is "read this machine's own services, or
// the cloud metadata address, and report the answer back through the byte count".
func TestAListIsNotFetchedFromAnAddressThisMachineCanReachPrivately(t *testing.T) {
	a := newUnstartedAgent(t)

	for _, tc := range []struct {
		name string
		url  string
	}{
		{"this machine itself", "https://127.0.0.1/list.txt"},
		{"a private network", "https://10.1.2.3/list.txt"},
		{"link-local", "https://169.254.169.254/list.txt"},
		{"the tailnet", "https://100.64.0.1/list.txt"},
		{"a private network on a port of its own", "https://10.1.2.3:8443/list.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.fetchFeed(context.Background(), tc.url, feeds.State{}, testFetchCap)

			if err == nil {
				t.Fatalf("fetchFeed(%s) succeeded, so a list was fetched from somewhere it may not be", tc.url)
			}
			if !strings.Contains(err.Error(), "not somewhere a list is fetched from") {
				t.Errorf("refusal = %q, which does not say why the address was refused", err)
			}
		})
	}
}

// An address nothing can read and a port nothing can dial are refused before a lookup is
// attempted, so the failure names what to fix rather than a resolver error.
func TestAnAddressThatIsNotOneIsRefusedBeforeAnythingIsLookedUp(t *testing.T) {
	a := newUnstartedAgent(t)

	for _, tc := range []struct {
		name string
		url  string
		says string
	}{
		{"not an address at all", "https://feeds.example\x7f/list.txt", "read the address"},
		{"a port that is not a number", "https://feeds.example:https/list.txt", "read the address"},
		{"a port outside what a port is", "https://feeds.example:99999/list.txt", "read the port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.fetchFeed(context.Background(), tc.url, feeds.State{}, testFetchCap)

			if err == nil {
				t.Fatalf("fetchFeed(%s) succeeded on an address nothing could read", tc.url)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("refusal = %q, want it to name what could not be read", err)
			}
		})
	}
}

// While app-tail is not the machine-wide resolver, the machine's own resolver is somebody
// else's and the lookup goes through it. What comes back is still checked: a name that resolves
// onto this machine is the way past a guard that only read the address somebody typed.
func TestAHostnameResolvedThroughTheMachineIsStillCheckedAgainstWhereListsMayCome(t *testing.T) {
	a := newUnstartedAgent(t)

	_, err := a.fetchFeed(context.Background(), "https://localhost/list.txt", feeds.State{}, testFetchCap)

	if err == nil {
		t.Fatal("a list was fetched from a name that resolves onto this machine")
	}
	if !strings.Contains(err.Error(), "not somewhere a list is fetched from") {
		t.Errorf("refusal = %q, which does not say why the address it resolved to was refused", err)
	}
}

// A name nothing can resolve is a failure that names the host: the download did not happen and
// the feed's view has to say what went wrong rather than reporting an empty list.
func TestAHostnameThatResolvesToNothingIsReportedAgainstTheHost(t *testing.T) {
	a := newUnstartedAgent(t)
	restore := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial:     func(context.Context, string, string) (net.Conn, error) { return nil, io.EOF },
	}
	t.Cleanup(func() { net.DefaultResolver = restore })

	_, err := a.fetchFeed(context.Background(), "https://feeds.example/list.txt", feeds.State{}, testFetchCap)

	if err == nil {
		t.Fatal("a list was fetched from a name that resolves nowhere")
	}
	if !strings.Contains(err.Error(), "look up feeds.example") {
		t.Errorf("error = %q, which does not name the host that could not be looked up", err)
	}
}

// An address a list may come from is dialled rather than refused. The download itself is
// stopped here by a context that is already over, which is what proves the guard passed it on
// instead of a network this test would otherwise depend on.
func TestAnAddressAListMayComeFromIsDialledRatherThanRefused(t *testing.T) {
	a := newUnstartedAgent(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// 192.0.2.0/24 is the range reserved for documentation: on the internet as far as the
	// guard is concerned, and answering nothing.
	_, err := a.fetchFeed(ctx, "https://192.0.2.1/list.txt", feeds.State{}, testFetchCap)

	if err == nil {
		t.Fatal("a download completed against an address nothing answers on")
	}
	if strings.Contains(err.Error(), "not somewhere a list is fetched from") {
		t.Errorf("refusal = %q, but a documentation address is where a list may come from", err)
	}
	if !strings.Contains(err.Error(), "download ") {
		t.Errorf("error = %q, want the failure to come from the download rather than before it", err)
	}
}

// While app-tail IS the machine-wide resolver, asking it would be asking for the answer this
// call is producing. With no bootstrap profile chosen and nothing published by this network,
// there is nowhere left to ask -- and the refusal has to say that rather than fall back to the
// resolver that would deadlock.
func TestALookupWithNowhereToAskThatIsNotAppTailIsRefusedRatherThanDeadlocked(t *testing.T) {
	a := newUnstartedAgent(t)
	if _, err := a.store.Update(func(c *config.Config) error {
		c.Settings.SystemDNSBootstrapProfile = dnsprofiles.SystemID
		return nil
	}); err != nil {
		t.Fatalf("choose this network's resolvers: %v", err)
	}
	weAreTheResolver(a, tsnode.BaseResolvers{})

	_, err := a.fetchFeed(context.Background(), "https://feeds.example/list.txt", feeds.State{}, testFetchCap)

	if err == nil {
		t.Fatal("a hostname was resolved with nowhere to ask but app-tail itself")
	}
	if !strings.Contains(err.Error(), "without asking app-tail's own resolver") {
		t.Errorf("error = %q, which does not say why the lookup had nowhere to go", err)
	}
	if !strings.Contains(err.Error(), "published no resolver") {
		t.Errorf("error = %q, which does not say that this network offered nothing either", err)
	}
}

// What this network published is the fallback while app-tail is the machine-wide resolver.
// One that answers nothing is a failure carrying what each resolver did, not a silent empty
// list of addresses to dial.
func TestAResolverThisNetworkPublishedThatAnswersNothingIsReported(t *testing.T) {
	a := newUnstartedAgent(t)
	if _, err := a.store.Update(func(c *config.Config) error {
		c.Settings.SystemDNSBootstrapProfile = dnsprofiles.SystemID
		return nil
	}); err != nil {
		t.Fatalf("choose this network's resolvers: %v", err)
	}
	// 192.0.2.0/24 is the range reserved for documentation, so nothing answers on it.
	weAreTheResolver(a, tsnode.BaseResolvers{Nameservers: []netip.Addr{netip.MustParseAddr("192.0.2.1")}})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := a.fetchFeed(ctx, "https://feeds.example/list.txt", feeds.State{}, testFetchCap)

	if err == nil {
		t.Fatal("a hostname resolved through a resolver that answers nothing")
	}
	if !strings.Contains(err.Error(), "without asking app-tail's own resolver") {
		t.Errorf("error = %q, which does not say the lookup avoided app-tail's own resolver", err)
	}
}

// The bootstrap profile is asked first: it is the one place that resolves a hostname without
// this network deciding what the resolver's own name means. A profile that answers nothing is
// named in the refusal, or the failure reads as if nothing was tried.
func TestTheBootstrapResolversAreAskedFirstAndNamedWhenTheyAnswerNothing(t *testing.T) {
	a := newUnstartedAgent(t)
	if _, err := a.store.Update(func(c *config.Config) error {
		// 192.0.2.0/24 is the range reserved for documentation: a literal address, so it needs
		// no lookup of its own, and nothing answers on it.
		c.DNSProfiles = append(c.DNSProfiles, config.DNSProfile{
			ID: "quiet", Name: "Quiet resolvers", Servers: []string{"192.0.2.1"},
		})
		c.Settings.SystemDNSBootstrapProfile = "quiet"
		return nil
	}); err != nil {
		t.Fatalf("store the bootstrap profile: %v", err)
	}
	weAreTheResolver(a, tsnode.BaseResolvers{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := a.fetchFeed(ctx, "https://feeds.example/list.txt", feeds.State{}, testFetchCap)

	if err == nil {
		t.Fatal("a hostname resolved through resolvers that answer nothing")
	}
	if !strings.Contains(err.Error(), "Quiet resolvers") {
		t.Errorf("error = %q, which does not name the profile that was asked", err)
	}
}

// A bootstrap profile of hostnames alone cannot bootstrap: resolving them is the lookup it is
// there to perform. The reason has to reach the refusal, or the feed reads as unreachable for
// no stated cause while the fix is one setting away.
func TestABootstrapProfileThatCannotBootstrapIsNamedInTheRefusal(t *testing.T) {
	a := newUnstartedAgent(t)
	if _, err := a.store.Update(func(c *config.Config) error {
		c.DNSProfiles = append(c.DNSProfiles, config.DNSProfile{
			ID: "names", Name: "Names only", Servers: []string{"tls://dns.example.com"},
		})
		c.Settings.SystemDNSBootstrapProfile = "names"
		return nil
	}); err != nil {
		t.Fatalf("store the bootstrap profile: %v", err)
	}
	weAreTheResolver(a, tsnode.BaseResolvers{})

	_, err := a.fetchFeed(context.Background(), "https://feeds.example/list.txt", feeds.State{}, testFetchCap)

	if err == nil {
		t.Fatal("a hostname resolved through a profile that cannot resolve one")
	}
	if !strings.Contains(err.Error(), "Names only") {
		t.Errorf("error = %q, which does not name the profile that could not be used", err)
	}
}

// The whole point of the bootstrap resolvers is that a download's hostname is resolved through
// them while app-tail holds this machine's name resolution. This is that path end to end, and
// the answer it produces is checked like any other: a resolver that points a feed's hostname at
// this machine is exactly the shape the guard exists for, and being the chosen resolver does not
// exempt it.
func TestADownloadsHostnameIsResolvedThroughTheBootstrapResolversAndStillChecked(t *testing.T) {
	a := newUnstartedAgent(t)
	resolver, asked := serveNames(t, "127.0.0.1")
	if _, err := a.store.Update(func(c *config.Config) error {
		c.DNSProfiles = append(c.DNSProfiles, config.DNSProfile{
			ID: "local", Name: "Local resolver", Servers: []string{resolver.String()},
		})
		c.Settings.SystemDNSBootstrapProfile = "local"
		return nil
	}); err != nil {
		t.Fatalf("store the bootstrap profile: %v", err)
	}
	weAreTheResolver(a, tsnode.BaseResolvers{})

	_, err := a.fetchFeed(context.Background(), "https://feeds.example/list.txt", feeds.State{}, testFetchCap)

	if asked.Load() == 0 {
		t.Fatal("the bootstrap resolver was never asked, so the lookup went somewhere else")
	}
	if err == nil {
		t.Fatal("a list was fetched from the address the chosen resolver pointed at")
	}
	if !strings.Contains(err.Error(), "not somewhere a list is fetched from") {
		t.Errorf("error = %q, which does not say the answer itself was refused", err)
	}
}

// What this network published is read from the machine, so it can be something no resolver can
// be built from. That is a reason the lookup failed and has to be carried like the others: a
// download that reports "nowhere left to ask" while hiding the one thing that was wrong sends
// the user looking at their network instead of at the address in it.
func TestAResolverThisNetworkPublishedThatCannotBeBuiltIsCarriedIntoTheFailure(t *testing.T) {
	a := newUnstartedAgent(t)
	if _, err := a.store.Update(func(c *config.Config) error {
		c.Settings.SystemDNSBootstrapProfile = dnsprofiles.SystemID
		return nil
	}); err != nil {
		t.Fatalf("choose this network's resolvers: %v", err)
	}
	// The zero address is what a nameserver the machine could not read comes back as.
	weAreTheResolver(a, tsnode.BaseResolvers{Nameservers: []netip.Addr{{}}})

	_, err := a.fetchFeed(context.Background(), "https://feeds.example/list.txt", feeds.State{}, testFetchCap)

	if err == nil {
		t.Fatal("a hostname resolved through a resolver that could not be built")
	}
	if !strings.Contains(err.Error(), "this machine's own resolver") {
		t.Errorf("error = %q, which does not say that the published resolver was the unusable part", err)
	}
	if !strings.Contains(err.Error(), "published no resolver") {
		t.Errorf("error = %q, which drops the rest of what was tried", err)
	}
}

// One resolver in a profile that cannot be built stops the lookup rather than quietly resolving
// through the rest. The addresses a feed is fetched from decide what gets blocked, so a lookup
// answered by a subset of the resolvers the user chose is a different answer, not a partial one.
func TestOneResolverThatCannotBeBuiltStopsTheLookupBeforeAnyIsAsked(t *testing.T) {
	a := newUnstartedAgent(t)
	resolver, asked := serveNames(t, "203.0.113.9")
	good, err := dnsprofiles.ParseUpstream(resolver.String())
	if err != nil {
		t.Fatalf("parse %s: %v", resolver, err)
	}
	unbuildable := dnsprofiles.Upstream{Protocol: "quic", Text: "quic://dns.example"}

	_, err = a.lookupThrough(lookupContext(t), []dnsprofiles.Upstream{good, unbuildable}, "feeds.example")

	if err == nil {
		t.Fatal("a lookup ran through a profile holding a resolver that could not be built")
	}
	if !strings.Contains(err.Error(), "quic://dns.example") {
		t.Errorf("error = %q, which does not name the resolver that could not be built", err)
	}
	if asked.Load() != 0 {
		t.Errorf("the resolvers were asked %d times, want the lookup stopped before any of them was",
			asked.Load())
	}
}

// stubbornUpstream answers every query and then refuses to shut down, which is a socket the
// process could not close rather than an answer that was wrong.
type stubbornUpstream struct {
	answer   string
	askErr   error
	closeErr error
	closes   int
}

func (u *stubbornUpstream) Exchange(_ context.Context, query []byte, _ bool) ([]byte, error) {
	if u.askErr != nil {
		return nil, u.askErr
	}
	return answerA(query, u.answer)
}

func (u *stubbornUpstream) Label() string { return "the resolver that will not close" }

func (u *stubbornUpstream) Close() error {
	u.closes++
	return u.closeErr
}

// A pool that would not close held its sockets; it did not get the addresses wrong. Throwing the
// answer away there would fail a download over something the caller can do nothing about, and
// would do it after the lookup already succeeded.
func TestAResolverThatWillNotCloseStillHandsBackTheAddressesItFound(t *testing.T) {
	a := newUnstartedAgent(t)
	up := &stubbornUpstream{answer: "203.0.113.9", closeErr: errors.New("the socket would not close")}

	addrs, err := a.lookupAndClose(lookupContext(t), dnsfwd.NewPool([]dnsfwd.Upstream{up}, nil), "feeds.example")

	if err != nil {
		t.Fatalf("a lookup that answered failed because the resolvers would not close: %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "203.0.113.9" {
		t.Fatalf("feeds.example resolved to %v, want the address the resolver answered with", addrs)
	}
	if up.closes != 1 {
		t.Errorf("the pool was closed %d times, want once -- these sockets are read by nothing else",
			up.closes)
	}
}

// When the lookup failed too, the close failure goes back with it: it may be why, and there is
// no answer left for it to be weighed against.
func TestALookupThatFailedCarriesTheCloseFailureWithIt(t *testing.T) {
	a := newUnstartedAgent(t)
	up := &stubbornUpstream{
		askErr:   errors.New("nothing answered"),
		closeErr: errors.New("the socket would not close"),
	}

	_, err := a.lookupAndClose(lookupContext(t), dnsfwd.NewPool([]dnsfwd.Upstream{up}, nil), "feeds.example")

	if err == nil {
		t.Fatal("a lookup nothing answered came back without an error")
	}
	if !strings.Contains(err.Error(), "nothing answered") {
		t.Errorf("error = %q, which does not say the lookup itself failed", err)
	}
	if !strings.Contains(err.Error(), "the socket would not close") {
		t.Errorf("error = %q, which drops the close failure that may be the reason", err)
	}
}
