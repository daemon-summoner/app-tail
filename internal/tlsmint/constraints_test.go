// SPDX-License-Identifier: MIT

package tlsmint

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// limitsFor builds constraints a test states, failing the test if the list is refused.
func limitsFor(t *testing.T, mode Mode, entries ...string) Constraints {
	t.Helper()
	limits, err := ConstraintsFor(mode, entries)
	if err != nil {
		t.Fatalf("building constraints for %v failed: %v", entries, err)
	}
	return limits
}

func authorityFor(t *testing.T, limits Constraints) *Authority {
	t.Helper()
	a, err := NewAuthority(theTimeIs, limits)
	if err != nil {
		t.Fatalf("generating a root failed: %v", err)
	}
	return a
}

// parsedRoot is the root as a verifier on another machine would read it: from the exported file,
// through crypto/x509, with nothing this package remembers about how it was made.
func parsedRoot(t *testing.T, a *Authority) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(a.CertPEM())
	if block == nil {
		t.Fatal("the exported root holds no certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("crypto/x509 cannot read the exported root: %v", err)
	}
	return cert
}

// forgeLeaf signs a server certificate with the root's own key for any name at all, going around
// the minting checks. It is what somebody holding a stolen key would make, which is exactly what
// the constraints in the root have to defeat.
func forgeLeaf(t *testing.T, a *Authority, name string) *x509.Certificate {
	t.Helper()
	serial, err := newSerial()
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    theTimeIs.Add(-time.Hour),
		NotAfter:     theTimeIs.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if addr, err := netip.ParseAddr(name); err == nil {
		template.IPAddresses = []net.IP{net.IP(addr.AsSlice())}
	} else {
		template.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &a.leafKey.PublicKey, a.key)
	if err != nil {
		t.Fatalf("forging a certificate for %s failed: %v", name, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// verifies reports whether a client trusting only this root accepts a certificate for name.
func verifies(t *testing.T, a *Authority, leaf *x509.Certificate) error {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(parsedRoot(t, a))
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: theTimeIs,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

// A stolen root key is worth whatever the root may sign. This pins the root down to signing
// server certificates for a year and nothing else: no code signing, no mail, no client identity,
// no further authority beneath it.
func TestANewRootSignsServerCertificatesForAYearAndNothingElse(t *testing.T) {
	t.Parallel()
	root := parsedRoot(t, newTestAuthority(t))

	if !slices.Equal(root.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) || len(root.UnknownExtKeyUsage) != 0 {
		t.Errorf("the root is good for %v %v, want server authentication only", root.ExtKeyUsage, root.UnknownExtKeyUsage)
	}
	if root.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("the root's key usage is %b, want certificate and CRL signing only", root.KeyUsage)
	}
	if !root.BasicConstraintsValid || !root.IsCA {
		t.Error("the root is not marked as an authority")
	}
	if root.MaxPathLen != 0 || !root.MaxPathLenZero {
		t.Errorf("the root allows %d authorities beneath it (zero set: %t)", root.MaxPathLen, root.MaxPathLenZero)
	}
	if got, want := root.NotAfter.Sub(root.NotBefore), 365*24*time.Hour+clockSkew; got != want {
		t.Errorf("the root is good for %v, want %v", got, want)
	}
	if !root.NotAfter.Equal(theTimeIs.Add(365 * 24 * time.Hour)) {
		t.Errorf("the root ends %s, a year after it was made", root.NotAfter)
	}
}

// In "only these" mode the root is limited to the names and networks listed, and a certificate
// for anything else -- even one signed with the root's real key -- is refused by a verifier.
func TestAnOnlyRootPermitsTheListedDestinationsAndRefusesEverythingElse(t *testing.T) {
	t.Parallel()
	a := authorityFor(t, limitsFor(t, ModeOnly, "api.internal.example", "10.8.0.0/16"))
	root := parsedRoot(t, a)

	if want := []string{"api.internal.example", probeDomain}; !slices.Equal(root.PermittedDNSDomains, want) {
		t.Errorf("permitted names are %v, want %v", root.PermittedDNSDomains, want)
	}
	if !root.PermittedDNSDomainsCritical {
		t.Error("the name constraints are not critical, so a verifier that cannot read them would ignore them")
	}
	if len(root.PermittedIPRanges) != 1 || root.PermittedIPRanges[0].String() != "10.8.0.0/16" {
		t.Errorf("permitted networks are %v, want [10.8.0.0/16]", root.PermittedIPRanges)
	}
	if len(root.ExcludedDNSDomains) != 0 {
		t.Errorf("an only root excludes %v", root.ExcludedDNSDomains)
	}

	for _, name := range []string{"api.internal.example", "v2.api.internal.example", "10.8.3.4"} {
		if err := verifies(t, a, forgeLeaf(t, a, name)); err != nil {
			t.Errorf("a certificate for %s, which is listed, was refused: %v", name, err)
		}
	}
	for _, name := range []string{"bank.example", "internal.example", "other-api.internal.example", "10.9.0.1"} {
		err := verifies(t, a, forgeLeaf(t, a, name))
		var invalid x509.CertificateInvalidError
		if !errors.As(err, &invalid) || invalid.Reason != x509.CANotAuthorizedForThisName {
			t.Errorf("a certificate for %s, which is not listed, verified (err %v)", name, err)
		}
	}
}

// X.509 reads an empty permitted list as no limit, so a list of names alone has to exclude every
// address outright or the root would sign for any IP.
func TestAnOnlyRootWithNoNetworkListedSignsForNoAddress(t *testing.T) {
	t.Parallel()
	a := authorityFor(t, limitsFor(t, ModeOnly, "api.internal.example"))
	root := parsedRoot(t, a)

	if len(root.PermittedIPRanges) != 0 || len(root.ExcludedIPRanges) != 2 {
		t.Fatalf("permitted %v, excluded %v; want every address excluded", root.PermittedIPRanges, root.ExcludedIPRanges)
	}
	for _, addr := range []string{"192.0.2.10", "2001:db8::1"} {
		if err := verifies(t, a, forgeLeaf(t, a, addr)); err == nil {
			t.Errorf("a certificate for the address %s verified under a root limited to names", addr)
		}
	}
}

// In "everything except" mode the root leaves out exactly the destinations interception leaves
// alone, so even a stolen key cannot sign for them.
func TestAnExceptRootExcludesTheDestinationsLeftAlone(t *testing.T) {
	t.Parallel()
	a := authorityFor(t, limitsFor(t, ModeExcept, "apple.com", "198.51.100.0/24"))
	root := parsedRoot(t, a)

	if !slices.Equal(root.ExcludedDNSDomains, []string{"apple.com"}) {
		t.Errorf("excluded names are %v, want [apple.com]", root.ExcludedDNSDomains)
	}
	if len(root.ExcludedIPRanges) != 1 || root.ExcludedIPRanges[0].String() != "198.51.100.0/24" {
		t.Errorf("excluded networks are %v", root.ExcludedIPRanges)
	}
	if len(root.PermittedDNSDomains) != 0 || len(root.PermittedIPRanges) != 0 {
		t.Errorf("an except root permits %v %v", root.PermittedDNSDomains, root.PermittedIPRanges)
	}
	if !root.PermittedDNSDomainsCritical {
		t.Error("the name constraints are not critical")
	}

	for _, name := range []string{"example.org", "192.0.2.1"} {
		if err := verifies(t, a, forgeLeaf(t, a, name)); err != nil {
			t.Errorf("a certificate for %s, which is not left alone, was refused: %v", name, err)
		}
	}
	for _, name := range []string{"apple.com", "push.apple.com", "198.51.100.7"} {
		if err := verifies(t, a, forgeLeaf(t, a, name)); err == nil {
			t.Errorf("a certificate for %s, which is left alone, verified", name)
		}
	}
}

// Permits is the answer the data path acts on before a certificate exists, so it has to agree with
// the verifier that will judge the certificate afterwards, name for name.
func TestPermitsAgreesWithTheVerifierInBothModes(t *testing.T) {
	t.Parallel()
	names := []string{
		"api.internal.example", "deep.api.internal.example", "internal.example", "xapi.internal.example",
		"apple.com", "www.apple.com", "notapple.com", "example.org",
		"10.8.0.1", "10.9.0.1", "198.51.100.200", "198.51.101.1", "2001:db8::5",
		installedProbe,
	}
	for _, limits := range []Constraints{
		limitsFor(t, ModeOnly, "api.internal.example", "10.8.0.0/16"),
		limitsFor(t, ModeOnly, "api.internal.example"),
		limitsFor(t, ModeExcept, "apple.com", "198.51.100.0/24", "2001:db8::/32"),
	} {
		a := authorityFor(t, limits)
		for _, name := range names {
			verified := verifies(t, a, forgeLeaf(t, a, name)) == nil
			if got := a.Covers(name); got != verified {
				t.Errorf("%v %v: Covers(%s) = %t, the verifier says %t", limits.Mode, limits.Domains, name, got, verified)
			}
		}
	}
}

// Minting is where the root's key is used, so it is where a name the root was not made for is
// stopped: a certificate for it would only ever be refused.
func TestMintingRefusesANameTheRootWasNotMadeFor(t *testing.T) {
	t.Parallel()
	a := authorityFor(t, limitsFor(t, ModeOnly, "api.internal.example"))

	if _, err := a.Leaf("bank.example", theTimeIs); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("minting outside the root's limits gave %v, want ErrOutsideRoot", err)
	}
	leaf, err := a.Leaf("api.internal.example", theTimeIs)
	if err != nil {
		t.Fatalf("minting a listed name failed: %v", err)
	}
	if err := verifies(t, a, leaf.Leaf); err != nil {
		t.Fatalf("the minted certificate does not verify: %v", err)
	}
}

// The installed check mints for a probe name, and a root limited to a short list must still
// answer it, or a correctly installed root reads as missing.
func TestAnOnlyRootStillAnswersWhetherItIsInstalled(t *testing.T) {
	t.Parallel()
	a := authorityFor(t, limitsFor(t, ModeOnly, "api.internal.example"))
	pool := x509.NewCertPool()
	pool.AddCert(a.cert)

	installed, err := a.installedIn(theTimeIs, pool)
	if err != nil {
		t.Fatal(err)
	}
	if !installed {
		t.Fatal("a root in the trust store reads as not installed")
	}
}

// A root with no limits is the very thing this package exists not to make.
func TestARootIsNeverMadeWithoutLimits(t *testing.T) {
	t.Parallel()
	if _, err := NewAuthority(theTimeIs, Constraints{}); err == nil {
		t.Fatal("a root was made that can sign for any site")
	}
}

// The list is read the way the scope reads it, and the result is canonical, so the same list
// written twice in different ways makes the same root and compares as covered.
func TestConstraintsAreReadFromTheListTheWayTheScopeReadsIt(t *testing.T) {
	t.Parallel()
	got := limitsFor(t, ModeOnly,
		"API.Internal.Example.", " api.internal.example ", "10.8.4.5/16", "192.0.2.7",
		"::ffff:192.0.2.8", "", "*.wild.example", "::ffff:10.9.0.0/112")

	if want := []string{"api.internal.example", "wild.example"}; !slices.Equal(got.Domains, want) {
		t.Errorf("domains = %v, want %v", got.Domains, want)
	}
	wantNets := []netip.Prefix{
		netip.MustParsePrefix("10.8.0.0/16"),
		netip.MustParsePrefix("10.9.0.0/16"),
		netip.MustParsePrefix("192.0.2.7/32"),
		netip.MustParsePrefix("192.0.2.8/32"),
	}
	if !slices.Equal(got.Networks, wantNets) {
		t.Errorf("networks = %v, want %v", got.Networks, wantNets)
	}

	if _, err := ConstraintsFor(ModeOnly, []string{"not a name", ""}); err == nil {
		t.Error("a list with nothing usable on it made constraints")
	}
	if _, err := ConstraintsFor(ModeExcept, nil); err == nil {
		t.Error("an empty except list made constraints, which would be a root for every site")
	}
	if _, err := ConstraintsFor(ModeOff, []string{"example.com"}); err == nil {
		t.Error("constraints were made for interception that is off")
	}
}

// In "everything except" mode, an exception the root does not carry is one it signs for
// anyway. A wildcard means the name it sits on and everything under it, which is what a name
// constraint already covers, and an IPv4 network written in IPv6's mapped form is that IPv4
// network, so both have to reach the excluded list.
func TestAnExceptionWrittenAsAWildcardOrAMappedNetworkIsStillLeftAlone(t *testing.T) {
	t.Parallel()
	a := authorityFor(t, limitsFor(t, ModeExcept, "*.mybank.example", "::ffff:10.0.0.0/104"))

	for _, name := range []string{"mybank.example", "login.mybank.example", "10.1.2.3"} {
		if err := verifies(t, a, forgeLeaf(t, a, name)); err == nil {
			t.Errorf("a certificate for %s, which is left alone, verified", name)
		}
		if a.Covers(name) {
			t.Errorf("Covers(%s) is true for a destination left alone", name)
		}
	}
	for _, name := range []string{"example.org", "192.0.2.1"} {
		if err := verifies(t, a, forgeLeaf(t, a, name)); err != nil {
			t.Errorf("a certificate for %s, which is not left alone, was refused: %v", name, err)
		}
	}
}

// An entry no name constraint can express is refused, naming the entry, rather than left out
// of the root: in "everything except" mode the root would sign for the very destination the
// person asked to have left alone.
func TestAnEntryNoRootCanBeLimitedByIsRefusedRatherThanSkipped(t *testing.T) {
	t.Parallel()
	for _, mode := range []Mode{ModeOnly, ModeExcept} {
		for _, entry := range []string{"localhost", "not a name", "*.", "bank*.example"} {
			_, err := ConstraintsFor(mode, []string{"apple.com", entry})
			if err == nil {
				t.Errorf("%v: a list holding %q made constraints", mode, entry)
				continue
			}
			if !strings.Contains(err.Error(), strconv.Quote(entry)) {
				t.Errorf("%v: error = %v, want the entry %q named", mode, err, entry)
			}
		}
	}
}

// The root is read back from disk on every start and while interception is off, and has to
// report the same limits it was made with.
func TestARootReadBackFromItsFileReportsTheLimitsItWasMadeWith(t *testing.T) {
	t.Parallel()
	for _, limits := range []Constraints{
		limitsFor(t, ModeOnly, "api.internal.example", "10.8.0.0/16"),
		limitsFor(t, ModeOnly, "api.internal.example"),
		limitsFor(t, ModeExcept, "apple.com", "google.com", "198.51.100.0/24"),
	} {
		a := authorityFor(t, limits)
		root, err := ParseRoot(a.CertPEM())
		if err != nil {
			t.Fatalf("reading the root back failed: %v", err)
		}
		back := root.Constraints()
		if back.Mode != limits.Mode || !slices.Equal(back.Domains, limits.Domains) || !slices.Equal(back.Networks, limits.Networks) {
			t.Errorf("made with %+v, read back as %+v", limits, back)
		}
		if root.Fingerprint() != a.Fingerprint() {
			t.Error("the fingerprint read back differs from the one the authority reports")
		}
	}
}

// A root made before roots were limited carries no constraint at all. It reads as covering
// everything -- because it does -- and says so, so the card can ask for it to be replaced.
func TestARootWithNoConstraintsReadsAsSigningForAnySite(t *testing.T) {
	t.Parallel()
	a := newTestAuthority(t)
	template := &x509.Certificate{
		SerialNumber:          a.cert.SerialNumber,
		Subject:               a.cert.Subject,
		NotBefore:             a.cert.NotBefore,
		NotAfter:              a.cert.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &a.key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ParseRoot(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	if root.Constraints().Mode != ModeOff {
		t.Fatalf("an unconstrained root reads as %v", root.Constraints().Mode)
	}
	if !root.Covers("bank.example") || !root.Constraints().Covers(limitsFor(t, ModeOnly, "anything.example")) {
		t.Error("an unconstrained root reads as not covering a name it can sign for")
	}
	if !strings.HasPrefix(root.Constraints().Describe(), "any site") {
		t.Errorf("an unconstrained root is described as %q", root.Constraints().Describe())
	}
}

// When the list changes, the root either still covers it or a new root is needed. This is the
// table of which changes are which.
func TestAScopeChangeOutsideTheRootNeedsANewRoot(t *testing.T) {
	t.Parallel()
	only := limitsFor(t, ModeOnly, "a.example", "10.0.0.0/8")
	except := limitsFor(t, ModeExcept, "apple.com", "198.51.100.0/24")
	onlyDeep := limitsFor(t, ModeOnly, "api.a.example")
	exceptDeep := limitsFor(t, ModeExcept, "push.apple.com")

	for _, c := range []struct {
		name   string
		root   Constraints
		want   Constraints
		covers bool
	}{
		{"only: a name under one listed", only, limitsFor(t, ModeOnly, "x.a.example"), true},
		{"only: the same list narrowed", only, limitsFor(t, ModeOnly, "a.example", "10.1.0.0/16"), true},
		{"only: a name not listed", only, limitsFor(t, ModeOnly, "a.example", "b.example"), false},
		{"only: the parent of a listed name", onlyDeep, limitsFor(t, ModeOnly, "a.example"), false},
		{"only: a wider network", only, limitsFor(t, ModeOnly, "10.0.0.0/7"), false},
		{"only: switched to except", only, limitsFor(t, ModeExcept, "a.example"), false},
		{"except: an only list clear of the exclusions", except, limitsFor(t, ModeOnly, "example.org", "192.0.2.0/24"), true},
		{"except: an only list naming an excluded name", except, limitsFor(t, ModeOnly, "push.apple.com"), false},
		{"except: an only list covering an excluded name", exceptDeep, limitsFor(t, ModeOnly, "apple.com"), false},
		{"except: an only list overlapping an excluded network", except, limitsFor(t, ModeOnly, "198.51.0.0/16"), false},
		{"except: the exclusions grown", except, limitsFor(t, ModeExcept, "apple.com", "google.com", "198.51.100.0/24"), true},
		{"except: an exclusion widened", except, limitsFor(t, ModeExcept, "apple.com", "198.51.0.0/16"), true},
		{"except: an exclusion dropped", except, limitsFor(t, ModeExcept, "google.com", "198.51.100.0/24"), false},
		{"except: a name exclusion narrowed", except, limitsFor(t, ModeExcept, "push.apple.com", "198.51.100.0/24"), false},
		{"interception switched off", only, Constraints{}, true},
	} {
		if got := c.root.Covers(c.want); got != c.covers {
			t.Errorf("%s: covers = %t, want %t", c.name, got, c.covers)
		}
	}
}

// Expiry is reported from thirty days out and from the moment it passes, and never acted on: the
// thresholds are what the card's warning hangs off.
func TestARootIsReportedAsExpiringThirtyDaysOutAndAsExpiredFromItsEnd(t *testing.T) {
	t.Parallel()
	a := newTestAuthority(t)
	end := a.NotAfter()

	for _, c := range []struct {
		at   time.Time
		want Expiry
	}{
		{theTimeIs, ExpiryAhead},
		{end.Add(-30*24*time.Hour - time.Nanosecond), ExpiryAhead},
		{end.Add(-30 * 24 * time.Hour), ExpirySoon},
		{end.Add(-time.Nanosecond), ExpirySoon},
		{end, ExpiryPassed},
		{end.Add(48 * time.Hour), ExpiryPassed},
	} {
		if got := a.Expiry(c.at); got != c.want {
			t.Errorf("at %s (root ends %s): expiry = %d, want %d", c.at, end, got, c.want)
		}
	}
}

// Removal takes the root out of the trust store the install command put it in, with each path
// one argument, in an order that works: on macOS the trust setting needs the certificate file,
// so it goes first.
func TestRemovalUndoesWhatTheInstallCommandDidOnEachSystem(t *testing.T) {
	t.Parallel()
	const certPath = `/Users/a b/state/tls/ca.crt`

	for _, c := range []struct {
		goos string
		want []Command
	}{
		{"darwin", []Command{
			{"sudo", "security", "remove-trusted-cert", "-d", certPath},
			{"sudo", "security", "delete-certificate", "-c", "app-tail traffic inspection", "/Library/Keychains/System.keychain"},
		}},
		{"linux", []Command{
			{"sudo", "rm", "/usr/local/share/ca-certificates/app-tail.crt"},
			{"sudo", "update-ca-certificates", "--fresh"},
		}},
		{"windows", []Command{{"certutil", "-delstore", "Root", "app-tail traffic inspection"}}},
		{"plan9", nil},
	} {
		got := RemovalCommands(c.goos, certPath)
		if !slices.EqualFunc(got, c.want, func(a, b Command) bool { return slices.Equal(a, b) }) {
			t.Errorf("%s: removal is %q, want %q", c.goos, got, c.want)
		}
		if remove := TrustInstructions(c.goos, certPath).Remove; remove != CommandLines(c.goos, c.want) {
			t.Errorf("%s: the command shown (%q) is not the one removal runs", c.goos, remove)
		}
	}

	// The install command names the same keychain and anchor file the removal clears.
	if install := TrustInstructions("darwin", certPath).Install; !strings.Contains(install, "/Library/Keychains/System.keychain") {
		t.Errorf("darwin install %q does not use the keychain removal clears", install)
	}
	if install := TrustInstructions("linux", certPath).Install; !strings.Contains(install, "/usr/local/share/ca-certificates/app-tail.crt") {
		t.Errorf("linux install %q does not write the file removal deletes", install)
	}
	if install := TrustInstructions("windows", certPath).Install; !strings.Contains(install, " Root ") {
		t.Errorf("windows install %q does not use the store removal clears", install)
	}
}

// The dashboard and `ips root` finish the sentence "This root can sign for" with Describe, so
// each mode has to read as English for any length of list.
func TestARootsLimitsAreDescribedInPlainWords(t *testing.T) {
	nets := func(ss ...string) []netip.Prefix {
		out := make([]netip.Prefix, len(ss))
		for i, s := range ss {
			out[i] = netip.MustParsePrefix(s)
		}
		return out
	}
	cases := []struct {
		c    Constraints
		want string
	}{
		{Constraints{Mode: ModeOnly, Domains: []string{"example.com"}}, "only example.com"},
		{Constraints{Mode: ModeOnly, Domains: []string{"a.example", "b.example"}}, "only a.example and b.example"},
		{Constraints{Mode: ModeOnly, Domains: []string{"a.example", "b.example"}, Networks: nets("10.0.0.0/8")},
			"only a.example, b.example and 10.0.0.0/8"},
		{Constraints{Mode: ModeOnly, Domains: []string{"a.example", "b.example", "c.example", "d.example", "e.example"}},
			"only the 5 destinations it was made for"},
		{Constraints{Mode: ModeExcept, Domains: []string{"bank.example"}},
			"any site except the 1 destination it was made to leave alone"},
		{Constraints{Mode: ModeExcept, Domains: []string{"bank.example"}, Networks: nets("192.0.2.0/24")},
			"any site except the 2 destinations it was made to leave alone"},
		{Constraints{Mode: ModeOff}, "any site, because it was made before app-tail limited its roots"},
	}
	for _, tc := range cases {
		if got := tc.c.Describe(); got != tc.want {
			t.Errorf("Describe(%+v) = %q, want %q", tc.c, got, tc.want)
		}
	}
}
