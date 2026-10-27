// SPDX-License-Identifier: MIT

package grants

import (
	"fmt"
	"slices"
	"sync"
	"testing"
)

var (
	publicRoute = Need{Kind: KindRoute, Value: "203.0.113.0/24", Reason: "send 203.0.113.0/24 through app-tail"}
	fullTunnel  = Need{Kind: KindFullTunnel, Reason: "carry all of this machine's internet traffic"}
	systemDNS   = Need{Kind: KindSystemDNS, Reason: "decide how this machine resolves every name"}
)

func pendingKinds(needs []PendingNeed) []Kind {
	out := make([]Kind, 0, len(needs))
	for _, n := range needs {
		out = append(out, n.Kind)
	}
	return out
}

func TestARefusedChangeIsWaitingForApprovalUnderTheFeatureThatAskedForIt(t *testing.T) {
	p := NewPending()
	p.Refused(Source{Feature: FeatureInterface, Change: "set-routes"}, []Need{publicRoute})

	got := p.Needs()
	if len(got) != 1 || got[0].Kind != KindRoute || got[0].Value != "203.0.113.0/24" {
		t.Fatalf("Needs() = %+v, want the one refused route", got)
	}
	if !slices.Equal(got[0].Features, []Feature{FeatureInterface}) {
		t.Errorf("the route is recorded for %v, want [interface]", got[0].Features)
	}
}

func TestTheSameApprovalAskedForByTwoFeaturesIsListedOnceNamingBoth(t *testing.T) {
	p := NewPending()
	p.Refused(Source{Feature: FeatureInterface, Change: "set-routes"}, []Need{publicRoute})
	p.Refused(Source{Feature: OpenVPNFeature("work"), Change: "run-openvpn"}, []Need{publicRoute, fullTunnel})

	got := p.Needs()
	if want := []Kind{KindRoute, KindFullTunnel}; !slices.Equal(pendingKinds(got), want) {
		t.Fatalf("Needs() kinds = %v, want %v once each", pendingKinds(got), want)
	}
	if want := []Feature{FeatureInterface, OpenVPNFeature("work")}; !slices.Equal(got[0].Features, want) {
		t.Errorf("the shared route names %v, want %v", got[0].Features, want)
	}
}

func TestOneServerApprovedWithDifferentCertificatesIsTwoApprovals(t *testing.T) {
	p := NewPending()
	a := Need{Kind: KindOpenVPNRemote, Value: "vpn.example.com:1194", CASHA256: []string{"aa"}, Reason: "a"}
	b := Need{Kind: KindOpenVPNRemote, Value: "vpn.example.com:1194", CASHA256: []string{"bb"}, Reason: "b"}
	p.Refused(Source{Feature: OpenVPNFeature("one"), Change: "run-openvpn"}, []Need{a})
	p.Refused(Source{Feature: OpenVPNFeature("two"), Change: "run-openvpn"}, []Need{b})

	if got := p.Needs(); len(got) != 2 {
		t.Fatalf("Needs() = %+v, want both certificate authorities, since approving one does not approve the other", got)
	}
}

func TestASuccessClearsOnlyTheChangeThatSucceeded(t *testing.T) {
	p := NewPending()
	routes := Source{Feature: FeatureInterface, Change: "set-routes"}
	dns := Source{Feature: FeatureInterface, Change: "set-dns"}
	p.Refused(routes, []Need{publicRoute})
	p.Refused(dns, []Need{{Kind: KindDNSDomain, Value: "corp.example.", Reason: "answer corp.example"}})

	p.Accepted(dns)
	if got := pendingKinds(p.Needs()); !slices.Equal(got, []Kind{KindRoute}) {
		t.Fatalf("after the resolver change succeeded, waiting = %v, want only the still-refused route", got)
	}
	p.Accepted(routes)
	if got := p.Needs(); len(got) != 0 {
		t.Errorf("after both succeeded, waiting = %+v, want nothing", got)
	}
}

func TestARefusalReplacesWhatTheSameChangeWasWaitingForBefore(t *testing.T) {
	p := NewPending()
	src := Source{Feature: FeatureInterface, Change: "set-routes"}
	p.Refused(src, []Need{publicRoute, fullTunnel})
	p.Refused(src, []Need{fullTunnel})

	if got := pendingKinds(p.Needs()); !slices.Equal(got, []Kind{KindFullTunnel}) {
		t.Errorf("waiting = %v, want only what the latest refusal named", got)
	}
}

func TestAChangeRefusedAgainKeepsItsPlaceInTheList(t *testing.T) {
	p := NewPending()
	first := Source{Feature: FeatureTLSInterception, Change: "intercept"}
	p.Refused(first, []Need{{Kind: KindTLSInterception, Reason: "r"}})
	p.Refused(Source{Feature: FeatureSystemDNS, Change: "set-system-dns"}, []Need{systemDNS})
	p.Refused(first, []Need{{Kind: KindTLSInterception, Reason: "r"}})

	if got, want := pendingKinds(p.Needs()), []Kind{KindTLSInterception, KindSystemDNS}; !slices.Equal(got, want) {
		t.Errorf("waiting = %v, want %v: a repeated refusal moved to the end of the list", got, want)
	}
}

func TestSwitchingAFeatureOffDropsWhatItWasWaitingFor(t *testing.T) {
	p := NewPending()
	p.Refused(Source{Feature: FeatureSystemDNS, Change: "set-system-dns"}, []Need{systemDNS})
	p.Refused(Source{Feature: OpenVPNFeature("gone"), Change: "run-openvpn"}, []Need{fullTunnel})
	p.Refused(Source{Feature: FeatureInterface, Change: "set-routes"}, []Need{publicRoute})

	p.Retain(func(f Feature) bool { return f == FeatureInterface })
	got := p.Needs()
	if len(got) != 1 || got[0].Kind != KindRoute {
		t.Errorf("after keeping only the interface, waiting = %+v, want only its route", got)
	}
}

func TestARefusalNamingNothingClearsTheChange(t *testing.T) {
	p := NewPending()
	src := Source{Feature: FeatureFabric, Change: "set-host-routes"}
	p.Refused(src, []Need{publicRoute})
	p.Refused(src, nil)
	if got := p.Needs(); len(got) != 0 {
		t.Errorf("waiting = %+v, want nothing: a refusal that names no approval is not one an administrator can answer", got)
	}
}

func TestTheWaitingListStaysBoundedHoweverManyChangesAreRefused(t *testing.T) {
	p := NewPending()
	many := make([]Need, 0, maxPendingNeedsPerSource*2)
	for i := range maxPendingNeedsPerSource * 2 {
		many = append(many, Need{Kind: KindRoute, Value: fmt.Sprintf("198.51.%d.0/24", i), Reason: "r"})
	}
	for i := range maxPendingSources * 2 {
		p.Refused(Source{Feature: OpenVPNFeature(fmt.Sprintf("c%d", i)), Change: "run-openvpn"}, many)
	}
	if got := len(p.Needs()); got > maxPendingNeedsPerSource {
		t.Errorf("Needs() holds %d distinct approvals, want at most %d from one change", got, maxPendingNeedsPerSource)
	}
	if got := len(p.Features()); got != maxPendingSources {
		t.Errorf("Features() holds %d features, want the cap of %d", got, maxPendingSources)
	}
	// The newest refusal is the one a person is looking at, so it is the one kept.
	newest := OpenVPNFeature(fmt.Sprintf("c%d", maxPendingSources*2-1))
	if !slices.Contains(p.Features(), newest) {
		t.Errorf("the newest refused feature %q was dropped to make room", newest)
	}
}

func TestTheWaitingListIsACopyTheCallerCannotChange(t *testing.T) {
	p := NewPending()
	ca := []string{"aa"}
	p.Refused(Source{Feature: OpenVPNFeature("x"), Change: "run-openvpn"},
		[]Need{{Kind: KindOpenVPNRemote, Value: "vpn:1194", CASHA256: ca, Reason: "r"}})
	ca[0] = "changed by the caller after the call"
	got := p.Needs()
	got[0].CASHA256[0] = "changed by the reader"
	got[0].Features[0] = "changed"
	again := p.Needs()
	if again[0].CASHA256[0] != "aa" || again[0].Features[0] != OpenVPNFeature("x") {
		t.Errorf("the stored list changed under a caller's edit: %+v", again)
	}
}

func TestPendingIsSafeToReportFromManyGoroutines(t *testing.T) {
	p := NewPending()
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			src := Source{Feature: OpenVPNFeature(fmt.Sprint(i)), Change: "run-openvpn"}
			p.Refused(src, []Need{publicRoute})
			_ = p.Needs()
			p.Accepted(src)
		}()
	}
	wg.Wait()
	if got := p.Needs(); len(got) != 0 {
		t.Errorf("waiting = %+v after every change succeeded", got)
	}
}

func TestAnOpenVPNFeatureNamesItsConnection(t *testing.T) {
	id, ok := OpenVPNFeature("home-office").OpenVPNID()
	if !ok || id != "home-office" {
		t.Errorf("OpenVPNID() = %q, %v, want home-office, true", id, ok)
	}
	if _, ok := FeatureInterface.OpenVPNID(); ok {
		t.Error("the interface feature reported itself as an OpenVPN connection")
	}
}

func TestTheApprovalCommandQuotesEveryValueForTheShellItIsPastedInto(t *testing.T) {
	hostile := Need{Kind: KindOpenVPNRemote, Value: "a$(reboot):1194", CASHA256: []string{"aa"}, Reason: "r"}
	posix := CommandLine("darwin", []Need{fullTunnel, hostile})
	if want := "sudo app-tail tun grant --full-tunnel '--openvpn=a$(reboot):1194=aa'"; posix != want {
		t.Errorf("CommandLine(darwin) = %q, want %q", posix, want)
	}
	quote := Need{Kind: KindDNSDomain, Value: "it's.example.", Reason: "r"}
	if got, want := CommandLine("linux", []Need{quote}), `sudo app-tail tun grant '--dns-domain=it'\''s.example.'`; got != want {
		t.Errorf("CommandLine(linux) = %q, want %q", got, want)
	}
	windows := CommandLine("windows", []Need{{Kind: KindTLSInterception, Reason: "r"}})
	if want := "app-tail tun grant --tls-interception"; windows != want {
		t.Errorf("CommandLine(windows) = %q, want %q", windows, want)
	}
	if got, want := CommandLine("windows", []Need{hostile}), "app-tail tun grant '--openvpn=a$(reboot):1194=aa'"; got != want {
		t.Errorf("CommandLine(windows) = %q, want %q: PowerShell runs a $(...) inside double quotes", got, want)
	}
	if got := CommandLine("darwin", nil); got != "" {
		t.Errorf("CommandLine with nothing to approve = %q, want empty", got)
	}
}
