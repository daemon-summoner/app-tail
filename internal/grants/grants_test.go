// SPDX-License-Identifier: MIT

package grants

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// testCA is a PEM certificate made for one test, and the SHA-256 of its DER bytes.
func testCA(t *testing.T, name string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("make a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("make a certificate: %v", err)
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), hex.EncodeToString(sum[:])
}

func prefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func kinds(needs []Need) []Kind {
	out := make([]Kind, 0, len(needs))
	for _, n := range needs {
		out = append(out, n.Kind)
	}
	return out
}

func TestAFileWithAFieldThisBuildDoesNotKnowIsRefused(t *testing.T) {
	_, err := Parse([]byte(`{"version":1,"fullTunel":true}`))
	if err == nil {
		t.Fatal("a misspelled approval parsed, so the administrator's intent would be dropped without a word")
	}
}

func TestAFileThatIsNotJSONIsRefused(t *testing.T) {
	for _, data := range []string{``, `{"version":1`, `{"version":1}{"version":1}`, `{"version":2}`} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("%q parsed as approvals", data)
		}
	}
}

func TestAnOpenVPNApprovalWithoutACertificateAuthorityIsRefused(t *testing.T) {
	_, err := Parse([]byte(`{"version":1,"openvpn":[{"remote":"vpn.example.com:1194","caSha256":[]}]}`))
	if err == nil {
		t.Fatal("an approval naming no certificate authority parsed, so any server answering at that name would be trusted")
	}
}

// An approval names one server exactly, so a value that is not a host and a port never
// reaches the file the helper trusts.
func TestAnOpenVPNApprovalAcceptsOnlyAHostAndAPort(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	parse := func(remote string) error {
		doc, err := json.Marshal(map[string]any{
			"version": 1,
			"openvpn": []map[string]any{{"remote": remote, "caSha256": []string{pin}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = Parse(doc)
		return err
	}
	for _, remote := range []string{"vpn.example.com:1194", "192.0.2.10:443", "[2001:db8::1]:1194"} {
		if err := parse(remote); err != nil {
			t.Errorf("%q was refused: %v", remote, err)
		}
	}
	for _, remote := range []string{
		"vpn.example.com",       // no port
		"2001:db8::1:1194",      // IPv6 without brackets: the port cannot be told apart
		"[2001:db8::1]",         // brackets, no port
		"[]:1194",               // no host
		":1194",                 // no host
		"vpn.example.com:0",     // port out of range
		"vpn.example.com:65536", // port out of range
		"vpn.example.com:http",  // not a number
		"vpn example.com:1194",  // whitespace
		"../vpn:1194",           // a path
	} {
		if err := parse(remote); err == nil {
			t.Errorf("%q was accepted as a server", remote)
		}
	}
}

func TestADocumentSurvivesBeingStoredAndReadBack(t *testing.T) {
	_, pin := testCA(t, "ca")
	doc := Document{
		FullTunnel: true,
		Routes:     prefixes(t, "203.0.113.7/24", "203.0.113.0/24"),
		DNSDomains: []string{"Corp.Example.com", "corp.example.com."},
		OpenVPN:    []OpenVPNRemote{{Remote: "vpn.example.com:1194", CASHA256: []string{strings.ToUpper(pin)}}},
	}
	data, err := doc.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("parse what was just encoded: %v", err)
	}
	if !got.FullTunnel || !slices.Equal(got.Routes, prefixes(t, "203.0.113.0/24")) ||
		!slices.Equal(got.DNSDomains, []string{"corp.example.com."}) ||
		len(got.OpenVPN) != 1 || !slices.Equal(got.OpenVPN[0].CASHA256, []string{pin}) {
		t.Fatalf("read back %+v", got)
	}
}

func TestMergingApprovalsKeepsEveryCertificateApprovedForTheSameServer(t *testing.T) {
	_, first := testCA(t, "first")
	_, second := testCA(t, "second")
	a := Document{OpenVPN: []OpenVPNRemote{{Remote: "vpn.example.com:1194", CASHA256: []string{first}}}}
	b := Document{SystemDNS: true, OpenVPN: []OpenVPNRemote{{Remote: "VPN.example.com:1194", CASHA256: []string{second}}}}
	got, err := a.With(b)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !got.SystemDNS || len(got.OpenVPN) != 1 || len(got.OpenVPN[0].CASHA256) != 2 {
		t.Fatalf("merged %+v", got)
	}
}

func TestADefaultRouteNeedsTheFullTunnelApprovalWholeOrInHalves(t *testing.T) {
	for _, routes := range [][]netip.Prefix{
		prefixes(t, "0.0.0.0/0"),
		prefixes(t, "::/0"),
		prefixes(t, "0.0.0.0/1", "128.0.0.0/1"),
	} {
		needs := None().RouteNeeds(routes, nil)
		if !slices.Equal(kinds(needs), []Kind{KindFullTunnel}) {
			t.Errorf("%v needs %+v", routes, needs)
		}
		if got := (Document{FullTunnel: true}).RouteNeeds(routes, nil); len(got) != 0 {
			t.Errorf("%v still needs %+v with the full tunnel approved", routes, got)
		}
	}
}

func TestHalfOfTheInternetIsAPublicRouteRatherThanAFullTunnel(t *testing.T) {
	needs := None().RouteNeeds(prefixes(t, "0.0.0.0/1"), nil)
	if len(needs) != 1 || needs[0].Kind != KindRoute || needs[0].Value != "0.0.0.0/1" {
		t.Fatalf("half the internet needs %+v", needs)
	}
}

func TestPrivateRangesAwayFromTheLANNeedNothing(t *testing.T) {
	routes := prefixes(t, "100.64.0.0/10", "fd7a:115c:a1e0::/48", "10.20.0.0/16", "172.16.4.0/24", "198.18.0.0/15", "fd00:1::/64")
	if needs := None().RouteNeeds(routes, prefixes(t, "192.168.1.0/24")); len(needs) != 0 {
		t.Fatalf("private ranges away from the LAN need %+v", needs)
	}
}

func TestAPublicRangeNeedsARouteApprovalThatCoversIt(t *testing.T) {
	routes := prefixes(t, "203.0.113.0/25")
	needs := None().RouteNeeds(routes, nil)
	if len(needs) != 1 || needs[0].Kind != KindRoute || needs[0].Value != "203.0.113.0/25" {
		t.Fatalf("a public range needs %+v", needs)
	}
	if got := (Document{Routes: prefixes(t, "203.0.113.0/24")}).RouteNeeds(routes, nil); len(got) != 0 {
		t.Fatalf("a range inside an approved one still needs %+v", got)
	}
	if got := (Document{Routes: prefixes(t, "203.0.113.0/26")}).RouteNeeds(routes, nil); len(got) != 1 {
		t.Fatalf("a range wider than the approved one needs %+v", got)
	}
}

func TestAPrivateRangeCoveringTheLANNeedsAnApproval(t *testing.T) {
	needs := None().RouteNeeds(prefixes(t, "192.168.0.0/16"), prefixes(t, "192.168.1.0/24"))
	if len(needs) != 1 || needs[0].Kind != KindRoute || !strings.Contains(needs[0].Reason, "192.168.1.0/24") {
		t.Fatalf("a range over the LAN needs %+v", needs)
	}
}

func TestTailnetResolversForTailnetNamesNeedNothing(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("100.100.100.100"), netip.MustParseAddr("127.0.0.1")}
	domains := []string{"example-tailnet.ts.net", "64.100.in-addr.arpa", "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."}
	if needs := None().InterfaceDNSNeeds(servers, domains); len(needs) != 0 {
		t.Fatalf("the tailnet's own resolver for its own names needs %+v", needs)
	}
}

func TestAResolverForEveryLookupNeedsTheSystemDNSApproval(t *testing.T) {
	needs := None().InterfaceDNSNeeds([]netip.Addr{netip.MustParseAddr("100.100.100.100")}, nil)
	if !slices.Equal(kinds(needs), []Kind{KindSystemDNS}) {
		t.Fatalf("a primary resolver needs %+v", needs)
	}
	if got := (Document{SystemDNS: true}).InterfaceDNSNeeds([]netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil); len(got) != 0 {
		t.Fatalf("with system DNS approved it still needs %+v", got)
	}
}

func TestAResolverOutsideTheTailnetNeedsTheSystemDNSApproval(t *testing.T) {
	needs := None().InterfaceDNSNeeds([]netip.Addr{netip.MustParseAddr("10.0.0.53")}, []string{"tail.ts.net"})
	if !slices.Equal(kinds(needs), []Kind{KindSystemDNS}) {
		t.Fatalf("a resolver on the LAN needs %+v", needs)
	}
}

func TestADomainOutsideTheTailnetNeedsItsOwnApproval(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("100.100.100.100")}
	needs := None().InterfaceDNSNeeds(servers, []string{"corp.example.com", "1.168.192.in-addr.arpa", "evilts.net"})
	want := []string{"corp.example.com.", "1.168.192.in-addr.arpa.", "evilts.net."}
	var got []string
	for _, n := range needs {
		if n.Kind != KindDNSDomain {
			t.Fatalf("unexpected need %+v", n)
		}
		got = append(got, n.Value)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("domains needing approval: %v, want %v", got, want)
	}
	approved := Document{DNSDomains: []string{"example.com.", "168.192.in-addr.arpa.", "evilts.net."}}
	if left := approved.InterfaceDNSNeeds(servers, []string{"corp.example.com"}); len(left) != 0 {
		t.Fatalf("a domain under an approved one still needs %+v", left)
	}
}

func TestPointingTheMachineAtAppTailNeedsTheSystemDNSApprovalAndPuttingItBackDoesNot(t *testing.T) {
	if needs := None().SystemDNSNeeds([]netip.Addr{netip.MustParseAddr("127.0.0.53")}); !slices.Equal(kinds(needs), []Kind{KindSystemDNS}) {
		t.Fatalf("taking over the machine's resolver needs %+v", needs)
	}
	if needs := None().SystemDNSNeeds(nil); len(needs) != 0 {
		t.Fatalf("restoring the machine's resolver needs %+v", needs)
	}
}

func TestAnOpenVPNServerNobodyApprovedIsRefused(t *testing.T) {
	ca, pin := testCA(t, "ca")
	needs, err := None().OpenVPNNeeds("vpn.example.com:1194", ca)
	if err != nil {
		t.Fatal(err)
	}
	if len(needs) != 1 || needs[0].Kind != KindOpenVPNRemote || !slices.Equal(needs[0].CASHA256, []string{pin}) {
		t.Fatalf("an unapproved server needs %+v", needs)
	}
	approved := Document{OpenVPN: []OpenVPNRemote{{Remote: "VPN.example.com:1194", CASHA256: []string{pin}}}}
	if needs, err := approved.OpenVPNNeeds("vpn.example.com:1194", ca); err != nil || len(needs) != 0 {
		t.Fatalf("an approved server needs %+v (%v)", needs, err)
	}
}

func TestAnApprovedOpenVPNServerWithAnotherCertificateAuthorityIsRefused(t *testing.T) {
	ca, _ := testCA(t, "impostor")
	approvedCA, approvedPin := testCA(t, "real")
	approved := Document{OpenVPN: []OpenVPNRemote{{Remote: "vpn.example.com:1194", CASHA256: []string{approvedPin}}}}
	needs, err := approved.OpenVPNNeeds("vpn.example.com:1194", ca)
	if err != nil {
		t.Fatal(err)
	}
	if len(needs) != 1 || !strings.Contains(needs[0].Reason, "not approved with") {
		t.Fatalf("a swapped certificate authority needs %+v", needs)
	}
	// A bundle that adds a certificate to the approved one trusts a server nobody approved.
	needs, err = approved.OpenVPNNeeds("vpn.example.com:1194", approvedCA+ca)
	if err != nil || len(needs) != 1 {
		t.Fatalf("a bundle with an extra certificate needs %+v (%v)", needs, err)
	}
}

func TestACertificateAuthorityThatIsNotCertificatesCannotBeApproved(t *testing.T) {
	ca, _ := testCA(t, "ca")
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}))
	for _, bad := range []string{"", "not pem", ca + key, ca + "trailing"} {
		if _, err := CAPins(bad); err == nil {
			t.Errorf("%q gave pins", bad)
		}
	}
}

func TestARefusalMatchesErrNeedsGrantAndNamesTheCommandThatApprovesIt(t *testing.T) {
	err := error(&MissingGrants{Needs: []Need{
		{Kind: KindFullTunnel, Reason: "carry everything"},
		{Kind: KindRoute, Value: "203.0.113.0/24", Reason: "reach a public range"},
		{Kind: KindOpenVPNRemote, Value: "vpn.example.com:1194", CASHA256: []string{"ab", "cd"}, Reason: "start openvpn"},
	}})
	if !errors.Is(err, ErrNeedsGrant) {
		t.Fatal("a missing approval does not match ErrNeedsGrant")
	}
	want := "`app-tail tun grant --full-tunnel --route=203.0.113.0/24 --openvpn=vpn.example.com:1194=ab,cd`"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refusal %q does not name %s", err, want)
	}
	if errors.Is(errors.New("broken"), ErrNeedsGrant) {
		t.Fatal("an unrelated error matches ErrNeedsGrant")
	}
}
