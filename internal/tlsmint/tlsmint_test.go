// SPDX-License-Identifier: MIT

package tlsmint

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// theTimeIs is a fixed clock, so a certificate's validity window is something the test states
// rather than something it reads off the machine it happens to run on.
var theTimeIs = time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)

func newTestAuthority(t *testing.T) *Authority {
	t.Helper()
	a, err := NewAuthority(theTimeIs, broadLimits(t))
	if err != nil {
		t.Fatalf("generating a root failed: %v", err)
	}
	return a
}

// broadLimits is the limit the tests that are not about limits mint under: an except root
// leaving out one name no test asks for, which is as wide as a root is allowed to be.
func broadLimits(t *testing.T) Constraints {
	t.Helper()
	limits, err := ConstraintsFor(ModeExcept, []string{"left-alone.invalid"})
	if err != nil {
		t.Fatalf("building the limits a test root is made with failed: %v", err)
	}
	return limits
}

// TestAClientTrustingTheRootCompletesAHandshakeWithAMintedCertificate is the test the whole
// package exists to pass: a real TLS client, verifying a real chain against nothing but this
// root, accepts the certificate minted for the name it asked for.
func TestAClientTrustingTheRootCompletesAHandshakeWithAMintedCertificate(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority.CertPEM()) {
		t.Fatal("the exported root is not something a trust store can read")
	}

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	serverSide := tls.Server(server, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return authority.Leaf(hello.ServerName, theTimeIs)
		},
	})
	handshakes := make(chan error, 1)
	go func() { handshakes <- serverSide.Handshake() }()

	clientSide := tls.Client(client, &tls.Config{
		ServerName: "inspected.example",
		RootCAs:    roots,
		Time:       func() time.Time { return theTimeIs },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := clientSide.HandshakeContext(ctx); err != nil {
		t.Fatalf("a client trusting the root refused the certificate minted for the name it asked for: %v", err)
	}
	if err := <-handshakes; err != nil {
		t.Fatalf("the server side of the handshake failed: %v", err)
	}

	state := clientSide.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("the handshake completed with no certificate")
	}
	if got := state.PeerCertificates[0].Subject.CommonName; got != "inspected.example" {
		t.Fatalf("the certificate was minted for %q, not for the name the client asked for", got)
	}
	if err := state.PeerCertificates[0].VerifyHostname("inspected.example"); err != nil {
		t.Fatalf("the minted certificate does not cover the name it was minted for: %v", err)
	}
}

// TestAClientThatDoesNotHoldTheRootRefusesTheMintedCertificate is the other half of the
// property: the certificate is accepted because the root was trusted, not because it is
// acceptable to anything that meets it.
func TestAClientThatDoesNotHoldTheRootRefusesTheMintedCertificate(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	serverSide := tls.Server(server, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return authority.Leaf(hello.ServerName, theTimeIs)
		},
	})
	go func() { _ = serverSide.Handshake() }()

	clientSide := tls.Client(client, &tls.Config{
		ServerName: "inspected.example",
		RootCAs:    x509.NewCertPool(),
		Time:       func() time.Time { return theTimeIs },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := clientSide.HandshakeContext(ctx)
	if err == nil {
		t.Fatal("a client holding no roots accepted the minted certificate")
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("the handshake failed for the wrong reason: %v", err)
	}
}

// TestARootReadBackFromItsFilesMintsCertificatesTheOriginalRootSigned covers the restart: the
// certificates minted after loading have to chain to the same root the trust store holds, or
// every intercepted site fails the first time app-tail is restarted.
func TestARootReadBackFromItsFilesMintsCertificatesTheOriginalRootSigned(t *testing.T) {
	t.Parallel()
	first := newTestAuthority(t)
	keyPEM, err := first.KeyPEM()
	if err != nil {
		t.Fatalf("writing the root's key failed: %v", err)
	}

	second, err := LoadAuthority(first.CertPEM(), keyPEM)
	if err != nil {
		t.Fatalf("reading the root back failed: %v", err)
	}
	if second.Fingerprint() != first.Fingerprint() {
		t.Fatal("the root read back is a different root")
	}

	leaf, err := second.Leaf("restarted.example", theTimeIs)
	if err != nil {
		t.Fatalf("minting after a restart failed: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(first.CertPEM()) {
		t.Fatal("the exported root is not something a trust store can read")
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: theTimeIs,
		DNSName:     "restarted.example",
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("a certificate minted after a restart does not chain to the trusted root: %v", err)
	}
}

// TestARootAndAKeyThatDoNotGoTogetherAreRefusedWhenTheyAreRead catches the state where one of
// the two files was replaced or half-written. Left undetected it produces certificates nothing
// can verify, and the first sign of it is every intercepted site failing at once.
func TestARootAndAKeyThatDoNotGoTogetherAreRefusedWhenTheyAreRead(t *testing.T) {
	t.Parallel()
	first := newTestAuthority(t)
	second := newTestAuthority(t)
	otherKey, err := second.KeyPEM()
	if err != nil {
		t.Fatalf("writing the root's key failed: %v", err)
	}

	_, err = LoadAuthority(first.CertPEM(), otherKey)
	if err == nil {
		t.Fatal("a root was accepted with another root's key")
	}
	if !strings.Contains(err.Error(), "do not go together") {
		t.Fatalf("the refusal does not say what is wrong: %v", err)
	}
}

func TestFilesThatHoldNoRootAreRefusedRatherThanUsed(t *testing.T) {
	t.Parallel()
	good := newTestAuthority(t)
	goodKey, err := good.KeyPEM()
	if err != nil {
		t.Fatalf("writing the root's key failed: %v", err)
	}

	// A certificate that is not a certificate authority, paired with the key it really was
	// signed for: readable, correctly paired, and still unable to sign anything.
	notACA, err := good.mint("plain.example", theTimeIs)
	if err != nil {
		t.Fatalf("minting failed: %v", err)
	}
	notACAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: notACA.Certificate[0]})
	leafKeyDER, err := x509.MarshalECPrivateKey(good.leafKey)
	if err != nil {
		t.Fatalf("writing a key failed: %v", err)
	}
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})

	for _, c := range []struct {
		name    string
		cert    []byte
		key     []byte
		message string
	}{
		{"an empty certificate file", nil, goodKey, "holds no certificate"},
		{"a certificate file holding a key", goodKey, goodKey, "holds no certificate"},
		{"an empty key file", good.CertPEM(), nil, "holds no key"},
		{"a key file holding a certificate", good.CertPEM(), good.CertPEM(), "holds no key"},
		{"a certificate that is not an authority", notACAPEM, leafKeyPEM, "not a certificate authority"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadAuthority(c.cert, c.key)
			if err == nil {
				t.Fatalf("%s was accepted as a root", c.name)
			}
			if !strings.Contains(err.Error(), c.message) {
				t.Fatalf("the refusal does not say what is wrong: %v", err)
			}
		})
	}
}

// TestTheRootCanSignServerCertificatesAndNothingElse pins the two constraints that keep the
// root from being more than it needs to be: it signs, and it cannot delegate that to another
// authority.
func TestTheRootCanSignServerCertificatesAndNothingElse(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)
	root := authority.cert

	if !root.IsCA {
		t.Fatal("the root cannot sign anything")
	}
	if root.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("the root is not allowed to sign certificates")
	}
	if !root.MaxPathLenZero || root.MaxPathLen != 0 {
		t.Fatal("the root can sign another authority, which hands this machine's trust onwards")
	}
	if root.NotAfter.Sub(root.NotBefore) > rootLifetime+2*clockSkew {
		t.Fatalf("the root is good for %v, which is longer than it was asked to be", root.NotAfter.Sub(root.NotBefore))
	}
	if !authority.NotAfter().Equal(root.NotAfter) {
		t.Fatal("the expiry the card reads is not the certificate's")
	}
}

// TestTwoRootsAreTellableApartByTheirFingerprints matters because the subject is identical on
// every machine: the fingerprint is the only thing a person comparing what their trust store
// holds against what this process is using has to compare.
func TestTwoRootsAreTellableApartByTheirFingerprints(t *testing.T) {
	t.Parallel()
	first := newTestAuthority(t)
	second := newTestAuthority(t)

	if first.Fingerprint() == second.Fingerprint() {
		t.Fatal("two separately generated roots have the same fingerprint")
	}
	if len(first.Fingerprint()) != 64 {
		t.Fatalf("the fingerprint is %d characters, not a SHA-256 in hex", len(first.Fingerprint()))
	}
	held := first.Fingerprint()
	if first.Fingerprint() != held {
		t.Fatal("the fingerprint changes between reads")
	}
}

func TestACertificateAlreadyMintedIsTheOneHandedBackAgain(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)

	first, err := authority.Leaf("repeat.example", theTimeIs)
	if err != nil {
		t.Fatalf("minting failed: %v", err)
	}
	second, err := authority.Leaf("repeat.example", theTimeIs.Add(time.Hour))
	if err != nil {
		t.Fatalf("minting failed: %v", err)
	}
	if first != second {
		t.Fatal("a second connection to the same name paid for a second signature")
	}

	// The same name in a different shape is the same name: a client sending a trailing dot or
	// mixed case must not cost another signature or another cache entry.
	shaped, err := authority.Leaf("Repeat.Example.", theTimeIs)
	if err != nil {
		t.Fatalf("minting failed: %v", err)
	}
	if shaped != first {
		t.Fatal("the same name written differently was minted twice")
	}
}

func TestACertificateThatHasExpiredIsMintedAgain(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)

	first, err := authority.Leaf("stale.example", theTimeIs)
	if err != nil {
		t.Fatalf("minting failed: %v", err)
	}
	later := theTimeIs.Add(leafLifetime + time.Hour)
	second, err := authority.Leaf("stale.example", later)
	if err != nil {
		t.Fatalf("minting failed: %v", err)
	}
	if first == second {
		t.Fatal("an expired certificate was handed out again")
	}
	if !later.Before(second.Leaf.NotAfter) {
		t.Fatal("the replacement is already expired")
	}
}

// TestTheCertificatesHeldAreBoundedByHowManyNotByWhatConnected is the memory property: the
// cache key comes off the wire, so a program opening connections for a million names has to
// cost a million signatures and never a million entries.
func TestTheCertificatesHeldAreBoundedByHowManyNotByWhatConnected(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)

	first, err := authority.Leaf("name0.example", theTimeIs)
	if err != nil {
		t.Fatalf("minting failed: %v", err)
	}
	for i := 1; i <= maxLeaves; i++ {
		if _, err := authority.Leaf("name"+strconv.Itoa(i)+".example", theTimeIs); err != nil {
			t.Fatalf("minting failed: %v", err)
		}
	}

	authority.mu.Lock()
	held := len(authority.leaves)
	ordered := len(authority.order)
	authority.mu.Unlock()
	if held > maxLeaves {
		t.Fatalf("%d certificates are held, more than the %d bound", held, maxLeaves)
	}
	if ordered != held {
		t.Fatalf("%d names are remembered for %d certificates, so the two have drifted apart", ordered, held)
	}

	again, err := authority.Leaf("name0.example", theTimeIs)
	if err != nil {
		t.Fatalf("minting failed: %v", err)
	}
	if again == first {
		t.Fatal("the oldest certificate was kept, so the cache grows with whatever connected")
	}
}

// TestTwoConnectionsForOneNameArrivingTogetherShareOneCertificate is the race the double check
// under the lock exists for. It is meaningful only under -race, which is how the suite runs.
func TestTwoConnectionsForOneNameArrivingTogetherShareOneCertificate(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)

	const callers = 16
	got := make([]*tls.Certificate, callers)
	var start, done sync.WaitGroup
	start.Add(1)
	done.Add(callers)
	for i := range callers {
		go func() {
			defer done.Done()
			start.Wait()
			leaf, err := authority.Leaf("together.example", theTimeIs)
			if err != nil {
				t.Errorf("minting failed: %v", err)
				return
			}
			got[i] = leaf
		}()
	}
	start.Done()
	done.Wait()

	for i, leaf := range got {
		if leaf == nil {
			t.Fatalf("caller %d got no certificate", i)
		}
		if leaf != got[0] {
			t.Fatal("callers arriving together were handed different certificates for one name")
		}
	}
	authority.mu.Lock()
	held := len(authority.leaves)
	authority.mu.Unlock()
	if held != 1 {
		t.Fatalf("%d certificates are held for one name", held)
	}
}

// TestANameACertificateCannotHoldIsRefusedRatherThanMintedFor is the boundary between the
// network and something a trust store evaluates. Every one of these is a value a client can
// send as its SNI.
func TestANameACertificateCannotHoldIsRefusedRatherThanMintedFor(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)

	for _, name := range []string{
		"",
		"   ",
		".",
		"localhost",
		"no-dot-anywhere",
		"..example",
		"host..example",
		"host .example",
		"host\x00.example",
		"host\r\n.example",
		"host\n.example",
		"under_score.example",
		"-leading.example",
		"trailing-.example",
		"exam*ple.example",
		"*x.example",
		strings.Repeat("a", 64) + ".example",
		strings.Repeat("a.", 200) + "example",
	} {
		if _, err := authority.Leaf(name, theTimeIs); !errors.Is(err, ErrNoLeaf) {
			t.Fatalf("a certificate was minted for %q: %v", name, err)
		}
	}

	authority.mu.Lock()
	held := len(authority.leaves)
	authority.mu.Unlock()
	if held != 0 {
		t.Fatalf("%d certificates were kept for names none could be made for", held)
	}
}

func TestTheNamesACertificateCanHoldAreMintedFor(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)

	// Each name has to land in the SAN a client checks it against: a domain in DNSNames, an
	// address in IPAddresses, never both and never the wrong one.
	for _, c := range []struct {
		name    string
		covers  string
		address bool
	}{
		{"example.com", "example.com", false},
		{"a.very.deep.subdomain.example.com", "a.very.deep.subdomain.example.com", false},
		{"xn--80ak6aa92e.com", "xn--80ak6aa92e.com", false},
		{"host-with-dashes.example", "host-with-dashes.example", false},
		{"*.wildcard.example", "anything.wildcard.example", false},
		{"9.9.9.9", "9.9.9.9", true},
		{"2606:4700:4700::1111", "2606:4700:4700::1111", true},
	} {
		leaf, err := authority.Leaf(c.name, theTimeIs)
		if err != nil {
			t.Fatalf("no certificate could be made for %q: %v", c.name, err)
		}
		if err := leaf.Leaf.VerifyHostname(c.covers); err != nil {
			t.Errorf("the certificate for %q does not cover %q: %v", c.name, c.covers, err)
		}
		if c.address {
			if len(leaf.Leaf.IPAddresses) != 1 || len(leaf.Leaf.DNSNames) != 0 {
				t.Errorf("%q was minted with addresses %v and names %v", c.name, leaf.Leaf.IPAddresses, leaf.Leaf.DNSNames)
			}
		} else if len(leaf.Leaf.DNSNames) != 1 || leaf.Leaf.DNSNames[0] != c.name || len(leaf.Leaf.IPAddresses) != 0 {
			t.Errorf("%q was minted with names %v and addresses %v", c.name, leaf.Leaf.DNSNames, leaf.Leaf.IPAddresses)
		}
	}
}

// A root that has passed its end signs nothing any client accepts, so minting against it is
// refused up front with the reason rather than producing certificates that fail on the wire.
func TestNothingIsMintedOnceTheRootHasExpired(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)
	expired := authority.NotAfter()

	if _, err := authority.Leaf("late.example", expired); !errors.Is(err, ErrRootExpired) {
		t.Fatalf("Leaf on the day the root ends = %v, want ErrRootExpired", err)
	}
	if _, err := authority.Leaf("late.example", theTimeIs.Add(rootLifetime+24*time.Hour)); !errors.Is(err, ErrRootExpired) {
		t.Fatalf("Leaf after the root ended = %v, want ErrRootExpired", err)
	}
	if _, err := authority.Installed(expired); !errors.Is(err, ErrRootExpired) {
		t.Fatalf("Installed after the root ended = %v, want ErrRootExpired rather than a false 'not installed'", err)
	}
	// One second short of the end is still the root's, and it still mints.
	if _, err := authority.Leaf("late.example", expired.Add(-time.Second)); err != nil {
		t.Fatalf("Leaf just before the root ends: %v", err)
	}
}

// A leaf that outlives its root is refused by every client from the day the root ends, so the
// last ones minted end with the root instead of promising the usual month.
func TestALeafNeverOutlivesTheRoot(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)
	nearTheEnd := authority.NotAfter().Add(-time.Hour)

	leaf, err := authority.Leaf("last.example", nearTheEnd)
	if err != nil {
		t.Fatalf("minting failed: %v", err)
	}
	if !leaf.Leaf.NotAfter.Equal(authority.NotAfter()) {
		t.Fatalf("the leaf ends %s, the root %s", leaf.Leaf.NotAfter, authority.NotAfter())
	}

	// Well before the end, the leaf gets its whole lifetime.
	early, err := authority.Leaf("early.example", theTimeIs)
	if err != nil {
		t.Fatalf("minting failed: %v", err)
	}
	if !early.Leaf.NotAfter.Equal(theTimeIs.Add(leafLifetime)) {
		t.Fatalf("a leaf minted early ends %s, want %s", early.Leaf.NotAfter, theTimeIs.Add(leafLifetime))
	}
}

// Installed is a question put to a trust store: yes when the root is in it, no when the store
// is empty or holds a different root, and never a guess from the files on disk.
func TestInstalledIsAnsweredByTheTrustStoreAndNothingElse(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)
	other := newTestAuthority(t)

	trusting := x509.NewCertPool()
	trusting.AddCert(authority.cert)
	trustingAnother := x509.NewCertPool()
	trustingAnother.AddCert(other.cert)

	for _, c := range []struct {
		store *x509.CertPool
		want  bool
		name  string
	}{
		{trusting, true, "a store holding the root"},
		{x509.NewCertPool(), false, "an empty store"},
		{trustingAnother, false, "a store holding a different root"},
	} {
		got, err := authority.installedIn(theTimeIs, c.store)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: installed = %t, want %t", c.name, got, c.want)
		}
	}
}

// The path to the root goes into a command a person pastes into a shell, and the state
// directory lives under a home directory that can hold spaces or quotes. The path has to
// survive as one argument on every platform, and the commands that do not carry a path stay
// exactly as documented.
func TestTrustInstructionsCarryThePathAsOneArgumentOnEveryPlatform(t *testing.T) {
	t.Parallel()
	const certPath = `/Users/a b/o'brien/state/root.pem`

	darwin := TrustInstructions("darwin", certPath)
	if want := `'/Users/a b/o'\''brien/state/root.pem'`; !strings.HasSuffix(darwin.Install, " "+want) {
		t.Errorf("darwin install = %q, want it to end with %s", darwin.Install, want)
	}
	if !strings.HasPrefix(darwin.Install, "sudo security add-trusted-cert ") {
		t.Errorf("darwin install = %q", darwin.Install)
	}
	if want := `sudo security remove-trusted-cert -d '/Users/a b/o'\''brien/state/root.pem' && ` +
		`sudo security delete-certificate -c 'app-tail traffic inspection' /Library/Keychains/System.keychain`; darwin.Remove != want {
		t.Errorf("darwin remove = %q, want %q", darwin.Remove, want)
	}

	linux := TrustInstructions("linux", certPath)
	if want := `sudo cp '/Users/a b/o'\''brien/state/root.pem' /usr/local/share/ca-certificates/app-tail.crt && sudo update-ca-certificates`; linux.Install != want {
		t.Errorf("linux install = %q, want %q", linux.Install, want)
	}
	if !strings.Contains(linux.Remove, "update-ca-certificates --fresh") {
		t.Errorf("linux remove = %q", linux.Remove)
	}

	windows := TrustInstructions("windows", `C:\Users\a b\AppData\Local\app-tail\root.pem`)
	if want := `certutil -addstore -f Root "C:\Users\a b\AppData\Local\app-tail\root.pem"`; windows.Install != want {
		t.Errorf("windows install = %q, want %q", windows.Install, want)
	}
	if windows.Remove != `certutil -delstore Root "`+Subject+`"` {
		t.Errorf("windows remove = %q", windows.Remove)
	}
	if !strings.Contains(windows.Note, "administrator") {
		t.Errorf("windows note = %q, want it to say the prompt has to be elevated", windows.Note)
	}

	// A system with no known answer gives no command to run, only the note saying so.
	unknown := TrustInstructions("plan9", certPath)
	if unknown.Install != "" || unknown.Remove != "" {
		t.Errorf("an unknown system was handed commands: %q / %q", unknown.Install, unknown.Remove)
	}
	if !strings.Contains(unknown.Note, "does not know") {
		t.Errorf("unknown note = %q", unknown.Note)
	}

	// Every platform's note names the browser this does not reach.
	for _, goos := range []string{"darwin", "windows", "linux"} {
		if !strings.Contains(TrustInstructions(goos, certPath).Note, "Firefox") {
			t.Errorf("%s note does not mention Firefox keeping its own roots", goos)
		}
	}
}

// TestACertificateForAnAddressCarriesItAsAnAddress matters because a client that dialled an
// address checks the address SAN, and a certificate naming it in the DNS SAN instead is
// rejected by every TLS stack.
func TestACertificateForAnAddressCarriesItAsAnAddress(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)

	leaf, err := authority.Leaf("9.9.9.9", theTimeIs)
	if err != nil {
		t.Fatalf("minting failed: %v", err)
	}
	if len(leaf.Leaf.IPAddresses) != 1 || leaf.Leaf.IPAddresses[0].String() != "9.9.9.9" {
		t.Fatalf("the certificate names the addresses %v", leaf.Leaf.IPAddresses)
	}
	if len(leaf.Leaf.DNSNames) != 0 {
		t.Fatalf("the certificate also names %v as a domain", leaf.Leaf.DNSNames)
	}
	if err := leaf.Leaf.VerifyHostname("9.9.9.9"); err != nil {
		t.Fatalf("the certificate does not cover the address it was minted for: %v", err)
	}
}

// TestAMintedCertificateIsAServerCertificateAndNothingMore keeps the leaves from carrying more
// authority than presenting one connection needs.
func TestAMintedCertificateIsAServerCertificateAndNothingMore(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)

	held, err := authority.Leaf("scoped.example", theTimeIs)
	if err != nil {
		t.Fatalf("minting failed: %v", err)
	}
	leaf := held.Leaf
	if leaf.IsCA {
		t.Fatal("a minted certificate can sign other certificates")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("a minted certificate is good for %v", leaf.ExtKeyUsage)
	}
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got > leafLifetime+2*clockSkew {
		t.Fatalf("a minted certificate is good for %v, which is longer than it was asked to be", got)
	}
	if len(held.Certificate) != 2 {
		t.Fatalf("the chain presented has %d certificates, so the root does not go with it", len(held.Certificate))
	}
}

// TestTwoRootsDoNotShareTheKeyTheirCertificatesAreMintedWith is the property that makes one
// shared leaf key acceptable: it is shared within one authority, never across installations.
func TestTwoRootsDoNotShareTheKeyTheirCertificatesAreMintedWith(t *testing.T) {
	t.Parallel()
	first := newTestAuthority(t)
	second := newTestAuthority(t)

	if first.leafKey.Equal(second.leafKey) {
		t.Fatal("two roots mint certificates with the same key")
	}
	if first.leafKey.Equal(first.key) {
		t.Fatal("certificates are minted with the root's own key")
	}
}
