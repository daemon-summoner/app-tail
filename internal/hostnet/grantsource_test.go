// SPDX-License-Identifier: MIT

package hostnet

import (
	"net/netip"
	"testing"

	"tailscale.com/net/dns"
	"tailscale.com/wgengine/router"

	"github.com/sellitus/app-tail/internal/grants"
)

func TestEachChangeThatCanNeedAnApprovalIsCreditedToTheFeatureThatSendsIt(t *testing.T) {
	route := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	resolver := []netip.Addr{netip.MustParseAddr("100.100.100.100")}
	tests := []struct {
		name    string
		req     request
		want    grants.Feature
		changes bool
	}{
		{"the engine's routes are the interface's", request{Op: opSetRoutes, Router: &router.Config{Routes: route}}, grants.FeatureInterface, true},
		{"the engine's resolver is the interface's", request{Op: opSetDNS, DNS: &dns.OSConfig{Nameservers: resolver}}, grants.FeatureInterface, true},
		{"host routes are the fabric's", request{Op: opSetHostRoutes, Host: &Routes{Routes: route}}, grants.FeatureFabric, true},
		{"the machine's resolver is system DNS", request{Op: opSetSystemDNS, Resolvers: []string{"127.0.0.1"}}, grants.FeatureSystemDNS, true},
		{"starting a connection is that connection's", request{Op: opRunOpenVPN, OpenVPN: &OpenVPNRun{ID: "tn_one"}}, grants.OpenVPNFeature("tn_one"), true},
		{"scoping a connection is that connection's", request{Op: opScopeOpenVPN, Scope: &OpenVPNScope{ID: "tn_two"}}, grants.OpenVPNFeature("tn_two"), true},
		{"removing the engine's routes changes nothing approvable", request{Op: opSetRoutes}, grants.FeatureInterface, false},
		{"clearing the engine's resolver changes nothing approvable", request{Op: opSetDNS, DNS: &dns.OSConfig{}}, grants.FeatureInterface, false},
		{"removing host routes changes nothing approvable", request{Op: opSetHostRoutes, Host: &Routes{}}, grants.FeatureFabric, false},
		{"restoring the machine's resolver changes nothing approvable", request{Op: opSetSystemDNS}, grants.FeatureSystemDNS, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, changes, ok := grantSource(tt.req)
			if !ok {
				t.Fatalf("grantSource(%s) is not credited to any feature", tt.req.Op)
			}
			if src.Feature != tt.want || src.Change != tt.req.Op {
				t.Errorf("grantSource(%s) = %+v, want feature %q, change %q", tt.req.Op, src, tt.want, tt.req.Op)
			}
			if changes != tt.changes {
				t.Errorf("grantSource(%s) carries a change = %v, want %v", tt.req.Op, changes, tt.changes)
			}
		})
	}
}

func TestARequestThatNeverNeedsAnApprovalIsCreditedToNoFeature(t *testing.T) {
	for _, op := range []string{opCapabilities, opOpenTUN, opRouterUp, opBaseDNS, opOpenResolver, opStopOpenVPN, opUnscopeOpenVPN, opRepairTailnetRoutes} {
		if src, _, ok := grantSource(request{Op: op}); ok {
			t.Errorf("grantSource(%s) = %+v, want none", op, src)
		}
	}
}
