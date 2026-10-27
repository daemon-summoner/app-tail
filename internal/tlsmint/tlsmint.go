// SPDX-License-Identifier: MIT

// Package tlsmint holds the certificate authority traffic interception presents with, and
// mints the server certificates it presents.
//
// Interception terminates a TLS connection and starts a second one, which means the client
// has to be handed a certificate for a name this machine does not own. That certificate is
// signed by a root generated here, on this machine, and trusted only because the person using
// the machine went and trusted it themselves.
//
// # What this package deliberately does not do
//
// It never installs anything. The root is written to the state directory and the person using
// the machine runs the trust command; app-tail's privileged helper has no operation for adding
// a root of trust and is not to grow one. The helper's vocabulary is the list of things any
// unprivileged caller that reaches its socket can ask for (internal/hostnet/protocol.go), and
// "add a root of trust to this machine" is the one request that would turn that socket into a
// way to own the machine permanently.
//
// It never holds a private key anywhere but in memory and in one file the caller writes with
// owner-only permissions. The key is generated here and has no way out of the process except
// KeyPEM, which exists so the caller can persist it across restarts.
//
// It never decides that an upstream certificate is good enough. That decision belongs to the
// code that dials upstream, and the only correct answer there is the standard one: verify the
// real chain, and stop the connection when it does not verify. An interceptor that carries on
// past an upstream it could not verify has quietly replaced every server's identity with its
// own opinion.
package tlsmint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	// rootLifetime is how long a generated root is good for.
	//
	// A year: short enough that a root left behind on a machine app-tail was removed from, or a
	// key copied off one, stops being usable on its own within the year, and long enough that
	// re-installing it is a yearly chore rather than a monthly one. The person who installed it
	// is the only one who can remove it, so expiry is the only bound this side can put on it.
	rootLifetime = 365 * 24 * time.Hour

	// expiryWarning is how long before a root's end it is reported as ending, so the person who
	// has to replace it hears about it while every intercepted site still works.
	expiryWarning = 30 * 24 * time.Hour

	// leafLifetime is how long one minted certificate is good for. Short because there is no
	// revocation here: nothing publishes a CRL or answers OCSP for these, so expiry is the
	// only way one stops being accepted.
	leafLifetime = 30 * 24 * time.Hour

	// clockSkew is how far before now a minted certificate starts being valid, so a client
	// whose clock is a little behind this machine's does not reject one the moment it is made.
	clockSkew = time.Hour

	// maxLeaves is how many minted certificates are kept. The key is a name that came off the
	// wire, so the cache is bounded and evicting rather than a map that grows with whatever a
	// connection asked for: a program opening connections for a million distinct names must
	// cost a million signatures, not a million entries held forever.
	maxLeaves = 256
)

// ErrNoLeaf reports that a name is not one a certificate can be made for. It is what a name
// that is empty, malformed, or too long comes back as, and the connection it came from is
// stopped rather than carried: a name this side cannot even write into a certificate is not
// one to hand to a TLS stack.
var ErrNoLeaf = errors.New("no certificate can be made for this name")

// ErrRootExpired reports that the root has passed the end of its validity, so nothing it signs
// from now on is accepted by a client that trusts it. A root this old is replaced by hand:
// removed from the trust store it was installed in, and its two files deleted so the next
// start generates a new one.
var ErrRootExpired = errors.New("the interception root has expired")

// ErrOutsideRoot reports that a name falls outside the destinations the root was limited to when
// it was made, so a certificate for it would be refused by every client that trusts the root. A
// new root, made for the list as it stands now, is what covers it.
var ErrOutsideRoot = errors.New("the interception root was not made for this destination")

// Root is the public half of an interception root: the certificate a trust store is given, and
// what can be read off it without the key. The card reads one from disk while interception is
// off, which is when somebody removing the root needs its fingerprint and the key has no
// business being in memory.
type Root struct {
	// der is the certificate itself, kept because the fingerprint and the exported file are
	// both made from it and re-encoding it each time would be work for nothing.
	der  []byte
	cert *x509.Certificate
	// limits are the name constraints read off cert once, since every mint consults them.
	limits Constraints
}

// ParseRoot reads a root certificate written by CertPEM.
func ParseRoot(certPEM []byte) (*Root, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("read the interception root: the file holds no certificate")
	}
	return parseRoot(block.Bytes)
}

func parseRoot(der []byte) (*Root, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("read the interception root: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("the interception root is not a certificate authority")
	}
	return &Root{der: der, cert: cert, limits: constraintsOf(cert)}, nil
}

// Authority is the root this machine signs with, and the certificates already minted under it.
//
// One exists per app-tail installation and lives as long as the process. It is safe for
// concurrent use: minting happens on connection goroutines, and the card reads the fingerprint
// from a request goroutine.
type Authority struct {
	Root
	key *ecdsa.PrivateKey

	// leafKey is one key shared by every minted certificate.
	//
	// A key per name would be one P-256 generation per connection to a name not yet seen,
	// which is the expensive half of minting, and it would buy nothing: every certificate here
	// is signed by the same root and presented by the same process, so a key that is private
	// to one of them is private to exactly the same set of things as a key shared by all.
	leafKey *ecdsa.PrivateKey

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
	// order is the names in leaves, oldest first, so the cache evicts rather than grows.
	order []string
}

// NewAuthority generates a root certificate and its key, limited to the destinations limits
// names. now is the clock, so a test pins the validity window rather than reading the
// machine's.
//
// A root with no limits is refused: it would sign for every site on the internet, and the
// only scope interception has that reaches that far is none at all.
//
// P-256 rather than Ed25519: the certificate has to be accepted by whatever the person using
// this machine browses with, and every trust store and TLS stack in use accepts P-256 while
// Ed25519 certificates are still refused by enough of them to make this the wrong place to be
// principled about curves.
func NewAuthority(now time.Time, limits Constraints) (*Authority, error) {
	if limits.Mode == ModeOff {
		return nil, errors.New("a root has to be limited to the destinations interception opens")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate the interception root's key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   Subject,
			Organization: []string{"app-tail"},
		},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(rootLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// One level: this root signs server certificates and nothing else. A root that can
		// sign another CA is a root that can delegate the whole machine's trust onwards.
		MaxPathLen:     0,
		MaxPathLenZero: true,
		// Server authentication only. Verifiers carry a CA's extended key usage down the chain,
		// so a stolen key cannot sign code, mail or a client identity this machine accepts.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	limits.apply(template)
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create the interception root: %w", err)
	}
	return newAuthority(der, key)
}

// LoadAuthority reads a root and its key back from what NewAuthority produced. A pair that
// does not go together is refused here rather than at the first connection that needed it.
func LoadAuthority(certPEM, keyPEM []byte) (*Authority, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("read the interception root: the file holds no certificate")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		return nil, errors.New("read the interception root's key: the file holds no key")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("read the interception root's key: %w", err)
	}
	return newAuthority(certBlock.Bytes, key)
}

// newAuthority is the shared tail of generating and loading: it parses the certificate, checks
// the key really is the one it was signed with, and makes the key the leaves are signed with.
func newAuthority(der []byte, key *ecdsa.PrivateKey) (*Authority, error) {
	root, err := parseRoot(der)
	if err != nil {
		return nil, err
	}
	pub, ok := root.cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		// A certificate and a key that do not go together would mint certificates nothing can
		// verify, and the first sign of it would be every intercepted site failing at once.
		return nil, errors.New("the interception root and its key do not go together")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate the key the minted certificates use: %w", err)
	}
	return &Authority{
		Root:    *root,
		key:     key,
		leafKey: leafKey,
		leaves:  make(map[string]*tls.Certificate, maxLeaves),
	}, nil
}

// newSerial is a random 128-bit serial, which is what a certificate needs and what nothing
// here would gain by making sequential.
func newSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("choose a certificate serial: %w", err)
	}
	// Zero is a valid *big.Int and not a valid serial, so it is moved rather than retried.
	return serial.Add(serial, big.NewInt(1)), nil
}

// CertPEM is the root certificate, in the form a trust store is given.
func (r *Root) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.der})
}

// KeyPEM is the root's private key, for the one file that holds it between restarts. It is
// the whole of the secret: anything holding this can issue a certificate for any name that
// every machine trusting this root will accept.
func (a *Authority) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(a.key)
	if err != nil {
		return nil, fmt.Errorf("write the interception root's key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// Fingerprint is the SHA-256 of the root certificate, lower-case hex.
//
// It is what the card shows and what tells one installed root from another: the name in the
// subject is the same on every machine, so a user checking whether the root their trust store
// holds is the one this process is using has nothing else to compare.
func (r *Root) Fingerprint() string {
	sum := sha256.Sum256(r.der)
	return hex.EncodeToString(sum[:])
}

// NotAfter is when the root stops being accepted, for the card to warn before it happens
// rather than after every site has started failing.
func (r *Root) NotAfter() time.Time { return r.cert.NotAfter }

// Constraints are the destinations the root was limited to when it was made.
func (r *Root) Constraints() Constraints { return r.limits }

// Covers reports whether the root can sign a certificate for one name or address that a client
// honouring its constraints would accept.
func (r *Root) Covers(name string) bool { return r.limits.Permits(name) }

// Expiry is how close a root is to the end of its validity.
type Expiry uint8

const (
	// ExpiryAhead is a root with more than expiryWarning left.
	ExpiryAhead Expiry = iota
	// ExpirySoon is a root inside its last expiryWarning, still signing and due to be replaced.
	ExpirySoon
	// ExpiryPassed is a root past its end, whose certificates no client accepts.
	ExpiryPassed
)

// Expiry reports how close the root is to its end at now. It only reports: a root installed in
// a trust store is replaced by the person who installed it, never swapped underneath them.
func (r *Root) Expiry(now time.Time) Expiry {
	switch {
	case !now.Before(r.cert.NotAfter):
		return ExpiryPassed
	case !now.Before(r.cert.NotAfter.Add(-expiryWarning)):
		return ExpirySoon
	}
	return ExpiryAhead
}

// Subject is the name every generated root carries. It is fixed rather than per-machine so
// that the command which removes one by name is the same command everywhere.
const Subject = "app-tail traffic inspection"

// Installed reports whether this machine's trust store currently accepts certificates from
// this root.
//
// It answers by asking the machine the question a browser would ask: mint a certificate and
// try to verify it the way anything verifying a server would, against nothing but the trust
// store. That is the only answer worth having. A file sitting in the state directory says
// nothing about whether it was ever installed, and the per-platform commands that list a trust
// store differ in every detail including whether they exist.
//
// It is also how removal is checked. app-tail does not install the root and so cannot remove
// it, which makes "did the removal work" a question only the machine can answer.
//
// One platform caveat, which is the reason this returns what it observed rather than a
// promise: Go reads the trust store on some systems once per process. On those, a root
// installed or removed while app-tail is running is not seen until it is restarted.
func (a *Authority) Installed(now time.Time) (bool, error) {
	// Nil roots is this machine's own trust store, which is the whole question.
	return a.installedIn(now, nil)
}

// installedIn is Installed against the trust store given, so a test can say what a machine
// trusts rather than depend on what the one it runs on does.
func (a *Authority) installedIn(now time.Time, roots *x509.CertPool) (bool, error) {
	const probe = installedProbe
	leaf, err := a.mint(probe, now)
	if err != nil {
		return false, err
	}
	_, err = leaf.Leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		DNSName:     probe,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	// A verification that fails is the answer rather than a fault: it is what this machine
	// says when it does not trust the root. The error itself carries nothing a caller could
	// act on, because "not installed" is the only reason it can have here.
	return err == nil, nil
}

// Instructions are the commands that put this root into a machine's trust store and take it
// out again, for the operating system asked about.
//
// Install is shown rather than run. Adding a root of trust is the one change on this machine
// that outlives app-tail and cannot be undone by removing it, so it is made by the person
// using the machine, in their own shell, with the command in front of them. Remove is the same
// RemovalCommands that `app-tail ips remove-root` runs in that person's terminal.
type Instructions struct {
	// Install and Remove are the commands. Empty on a system with no single answer, which is
	// what Note then explains.
	Install string
	Remove  string
	// Note is what the commands do not cover, always worth reading and sometimes the whole
	// answer.
	Note string
}

// Paths in the trust stores the commands write to. The Linux one is a file app-tail names, so
// removal deletes exactly what installing created and nothing a package put beside it.
const (
	darwinKeychain = "/Library/Keychains/System.keychain"
	linuxAnchor    = "/usr/local/share/ca-certificates/app-tail.crt"
)

// TrustInstructions are the commands for one operating system, named as GOOS names it.
func TrustInstructions(goos, certPath string) Instructions {
	remove := CommandLines(goos, RemovalCommands(goos, certPath))
	switch goos {
	case "darwin":
		return Instructions{
			Install: "sudo security add-trusted-cert -d -r trustRoot -k " + darwinKeychain + " " + shellQuote(certPath),
			Remove:  remove,
			Note: "Firefox keeps its own list of roots and ignores this one, so connections it " +
				"makes are carried untouched rather than opened.",
		}
	case "windows":
		return Instructions{
			Install: "certutil -addstore -f Root " + cmdQuote(certPath),
			Remove:  remove,
			Note: "Run both from a command prompt started as administrator. Firefox keeps its " +
				"own list of roots and ignores this one.",
		}
	case "linux":
		return Instructions{
			Install: "sudo cp " + shellQuote(certPath) + " " + linuxAnchor + " && sudo update-ca-certificates",
			Remove:  remove,
			Note: "These are the Debian and Ubuntu commands. On Fedora and its relatives the " +
				"directory is /etc/pki/ca-trust/source/anchors and the command is " +
				"update-ca-trust. Firefox and Chrome keep their own lists of roots on Linux and " +
				"ignore this one.",
		}
	default:
		return Instructions{
			Note: "app-tail does not know how roots are installed on this system. The " +
				"certificate is the file named above; add it to whatever this system trusts " +
				"server certificates from.",
		}
	}
}

// Command is one program and its arguments, run as they are rather than through a shell, so a
// path holding a space or a quote is one argument whatever it holds.
type Command []string

// RemovalCommands take the root out of the trust store the install command put it in, in the
// order they have to run. Nil on a system with no known answer.
//
// macOS takes two: the trust setting first, which needs the certificate file to name what it
// applies to, then the certificate itself, by the subject every generated root carries.
func RemovalCommands(goos, certPath string) []Command {
	switch goos {
	case "darwin":
		return []Command{
			{"sudo", "security", "remove-trusted-cert", "-d", certPath},
			{"sudo", "security", "delete-certificate", "-c", Subject, darwinKeychain},
		}
	case "windows":
		return []Command{{"certutil", "-delstore", "Root", Subject}}
	case "linux":
		return []Command{
			{"sudo", "rm", linuxAnchor},
			{"sudo", "update-ca-certificates", "--fresh"},
		}
	}
	return nil
}

// CommandLines writes commands as one line a person pastes into this system's shell, each
// argument quoted where it needs to be and the commands joined so a failure stops the rest.
func CommandLines(goos string, commands []Command) string {
	lines := make([]string, 0, len(commands))
	for _, c := range commands {
		lines = append(lines, CommandLine(goos, c))
	}
	return strings.Join(lines, " && ")
}

// CommandLine writes one command the way CommandLines does.
func CommandLine(goos string, c Command) string {
	words := make([]string, 0, len(c))
	for _, arg := range c {
		switch {
		case plainWord(arg):
			words = append(words, arg)
		case goos == "windows":
			words = append(words, cmdQuote(arg))
		default:
			words = append(words, shellQuote(arg))
		}
	}
	return strings.Join(words, " ")
}

// plainWord reports an argument every shell reads as itself, so it is written without quotes.
func plainWord(arg string) bool {
	if arg == "" {
		return false
	}
	for i := 0; i < len(arg); i++ {
		c := arg[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune("-_./:=@", rune(c)) {
			return false
		}
	}
	return true
}

// shellQuote makes a path one word to a POSIX shell, whatever it holds. The state directory is
// under the user's home, and a home with a space in it is ordinary on a Mac.
func shellQuote(path string) string {
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}

// cmdQuote makes a path one argument to cmd.exe, where double quotes are the only quoting and
// a path cannot hold one.
func cmdQuote(path string) string {
	return `"` + path + `"`
}

// Leaf returns the certificate to present for one name, minting it if this is the first
// connection asking for it.
//
// The name comes off the wire, so it is checked before it reaches a certificate: anything that
// is not a plausible host name or an address is refused, and the caller stops the connection.
func (a *Authority) Leaf(name string, now time.Time) (*tls.Certificate, error) {
	key := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if !mintable(key) {
		return nil, fmt.Errorf("%w: %q", ErrNoLeaf, name)
	}

	a.mu.Lock()
	held, ok := a.leaves[key]
	a.mu.Unlock()
	if ok && now.Before(held.Leaf.NotAfter) {
		return held, nil
	}

	made, err := a.mint(key, now)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	// Checked again under the lock: two connections for the same name can arrive together, and
	// the second one's certificate is as good as the first's, so the first one in stays and the
	// other is dropped rather than both being kept under one key.
	if held, ok := a.leaves[key]; ok && now.Before(held.Leaf.NotAfter) {
		return held, nil
	}
	if _, replacing := a.leaves[key]; !replacing {
		if len(a.order) >= maxLeaves {
			delete(a.leaves, a.order[0])
			a.order = a.order[1:]
		}
		a.order = append(a.order, key)
	}
	a.leaves[key] = made
	return made, nil
}

// mint signs one certificate for one name. It holds no lock: the signature is the expensive
// part, and holding the cache's lock across it would make every connection to an unseen name
// wait for every other one.
func (a *Authority) mint(name string, now time.Time) (*tls.Certificate, error) {
	if !now.Before(a.cert.NotAfter) {
		return nil, fmt.Errorf("%w: it stopped being accepted on %s", ErrRootExpired, a.cert.NotAfter.Format(time.DateOnly))
	}
	if !a.Covers(name) {
		return nil, fmt.Errorf("%w: %s", ErrOutsideRoot, name)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	// A leaf that outlives its root is refused by every client from the day the root ends, so
	// the last leaves end with it rather than promising a month the root cannot keep.
	notAfter := now.Add(leafLifetime)
	if notAfter.After(a.cert.NotAfter) {
		notAfter = a.cert.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{Subject}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if addr, err := netip.ParseAddr(name); err == nil {
		template.IPAddresses = []net.IP{net.IP(addr.AsSlice())}
	} else {
		template.DNSNames = []string{name}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &a.leafKey.PublicKey, a.key)
	if err != nil {
		return nil, fmt.Errorf("make a certificate for %s: %w", name, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("read back the certificate made for %s: %w", name, err)
	}
	return &tls.Certificate{
		// The root goes with it, so a client that has the root as a trust anchor but has not
		// been handed it in the chain still builds one.
		Certificate: [][]byte{der, a.der},
		PrivateKey:  a.leafKey,
		Leaf:        leaf,
	}, nil
}

// mintable reports whether a name can go into a certificate. It is deliberately narrow: this
// is the one place a value from the network becomes part of something a trust store evaluates,
// and every shape that is not obviously a host or an address is refused.
func mintable(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return true
	}
	if !strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			case c == '-' && i != 0 && i != len(label)-1:
			case c == '*' && i == 0 && len(label) == 1:
				// A wildcard label is what a server hands out for a subtree, and a client
				// that asked for one by name is asking for exactly this.
			default:
				return false
			}
		}
	}
	return true
}
