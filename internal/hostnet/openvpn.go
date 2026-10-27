// SPDX-License-Identifier: MIT

package hostnet

// Running an OpenVPN connection, which is the one thing this boundary does by starting
// another program.
//
// That is a bigger step than anything else here, so it is worth being exact about what does
// and does not cross. The caller does not name a program, does not supply arguments and does
// not supply a configuration file. It sends the typed value below -- a server, a transport,
// certificates, key material, a few algorithm names and a list of networks -- and this side
// renders the configuration from it against a fixed template, refusing anything that is not
// one of those shapes. Every directive that could name a program to run is one this side
// never writes, so there is no value the caller can send that becomes one.
//
// The alternative -- accepting a .ovpn file and handing it to openvpn -- would be a root
// code-execution primitive with extra steps: an OpenVPN configuration can name programs to
// run through up, down, route-up, plugin and several more, and openvpn runs them with the
// rights it holds.
//
// The connection is supervised rather than detached. openvpn is started listening on a
// management socket in a directory belonging to root, and told the one account allowed to
// connect to it -- the account this helper serves -- so the agent drives it and nobody else
// on the machine can. When that conversation drops, openvpn restarts and holds until it is
// driven again rather than carrying on unsupervised; this side kills it when the session
// ends, because a privileged process that outlives what was supervising it is the failure
// this whole boundary exists to avoid.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// ErrNoOpenVPN reports that the openvpn program is not installed where this side will run
// one from. It is a sentinel because the answer is to install it rather than to repair
// anything about app-tail.
var ErrNoOpenVPN = errors.New("the openvpn program is not installed on this machine")

// ErrOpenVPNUnsupported reports that this platform has no OpenVPN connections at all. It is
// separate from ErrUnsupported because the two are different answers: a machine can have an
// interface mode and still have no way to run OpenVPN.
var ErrOpenVPNUnsupported = errors.New("this platform cannot run an OpenVPN connection")

// openvpnStopGrace is how long a connection is given to close itself after being asked
// before it is killed. It is short because the ask is a signal openvpn handles by telling
// its server the client is leaving and taking its own interface down, and long enough that
// an ordinary shutdown is the clean one.
const openvpnStopGrace = 5 * time.Second

// maxOpenVPNRoutes bounds how many networks one connection may carry. It is a routing-table
// budget an unprivileged caller would otherwise choose the size of, and it is far above what
// any real configuration carries.
const maxOpenVPNRoutes = 256

// maxOpenVPNMaterialLen bounds one certificate or key. A PEM chain is a few kilobytes; this
// is the same kind of bound the message size is, applied to the fields big enough to matter.
const maxOpenVPNMaterialLen = 128 << 10

// The two transports, spelled out here rather than imported. This package is the privilege
// boundary and refuses on its own terms, so what it accepts is written down where it accepts
// it rather than agreed with the side being checked.
const (
	openvpnProtoUDP = "udp"
	openvpnProtoTCP = "tcp"
)

// OpenVPNRun is one connection to start, as typed values rather than as a configuration.
//
// Nothing here is a path, a command or a directive. Render below is the only thing that
// turns any of it into configuration, and it writes a fixed set of directives whatever this
// carries.
type OpenVPNRun struct {
	// ID is the connection this is. It names the connection in this side's log, it is what
	// a stop names, and it is used as a file name under a directory this side makes -- so
	// its shape is checked rather than its meaning.
	ID string `json:"id"`
	// Remote is the server, as host:port.
	Remote string `json:"remote"`
	// Proto is the transport: udp or tcp, and nothing else.
	Proto string `json:"proto"`

	// CA, Cert and Key are PEM. TLSCrypt and TLSAuth are OpenVPN static keys. All five were
	// decoded and re-encoded before they were sent, so what arrives is material rather than
	// whatever surrounded it in the file it came from.
	CA       string `json:"ca"`
	Cert     string `json:"cert,omitempty"`
	Key      string `json:"key,omitempty"`
	TLSCrypt string `json:"tlsCrypt,omitempty"`
	TLSAuth  string `json:"tlsAuth,omitempty"`
	// KeyDirection is "", "0" or "1", and applies to a tls-auth key.
	KeyDirection string `json:"keyDirection,omitempty"`

	// AuthUserPass says the server signs this connection in with an account. The account
	// itself never comes here: it is answered over the management interface, so it is never
	// written to a file at all.
	AuthUserPass bool `json:"authUserPass,omitempty"`

	// Cipher and Auth are algorithm names, checked against the shape of a name before they
	// are written.
	Cipher string `json:"cipher,omitempty"`
	Auth   string `json:"auth,omitempty"`
	// VerifyServerCert requires the server's certificate to be marked as a server's.
	VerifyServerCert bool `json:"verifyServerCert,omitempty"`
	// VerifyName and VerifyNameType are the check on the name in that certificate.
	VerifyName     string `json:"verifyName,omitempty"`
	VerifyNameType string `json:"verifyNameType,omitempty"`

	// Routes are the networks this connection carries. openvpn installs them against its own
	// interface and removes them when it exits.
	Routes []netip.Prefix `json:"routes,omitempty"`
	// RedirectGateway sends everything this machine has no better route for through this
	// connection. It is separate from a default route among Routes because the two are
	// different decisions: a connection may be able to carry everything without being the
	// one chosen to.
	RedirectGateway bool `json:"redirectGateway,omitempty"`
	// MTU is the largest packet, zero to leave it to openvpn.
	MTU int `json:"mtu,omitempty"`
}

// OpenVPNManagementDir is where the helper has openvpn create its management sockets.
//
// It sits inside the helper's own socket directory and belongs to root with mode 0711: any
// account can reach a socket in it by its exact name, and only root can list it or put
// anything there. The caller never names this path. openvpn listening on a socket a caller
// chose would be the caller deciding where a root process creates a file, and openvpn
// connecting out to one would be a root process reaching wherever the caller pointed it.
const OpenVPNManagementDir = "/var/run/app-tail/openvpn"

// maxUnixSocketPath bounds a management socket's path.
//
// A unix socket address is a fixed-size field in the kernel -- 104 bytes on macOS, 108 on
// Linux -- and a path longer than it is truncated rather than refused, which binds something
// to a different socket than the one that was named. The bound here is the smaller of the
// two, minus room for the terminator.
const maxUnixSocketPath = 100

// OpenVPNManagementSocket is the socket openvpn listens on for one connection, which the
// agent dials to drive it.
//
// Both sides compute it from the connection id rather than one telling the other, so nothing
// about where root creates a socket crosses the boundary. Only one session runs OpenVPN at a
// time and a connection id is never running twice, so the name cannot collide.
func OpenVPNManagementSocket(id string) string {
	return filepath.Join(OpenVPNManagementDir, id+".sock")
}

// OpenVPNRunner is the privileged side of running an OpenVPN connection.
//
// It is a capability rather than part of Host for the reason SystemResolver is one: it has
// its own lifetime and its own session, and a machine that cannot run one still has an
// interface mode.
type OpenVPNRunner interface {
	// StartOpenVPN starts the connection. It returns once the program is running and has
	// been given its configuration, which is before it has reached the server: a wrong
	// password or an unreachable server is a connection that started and did not connect,
	// and the management interface is where that is reported.
	StartOpenVPN(ctx context.Context, run OpenVPNRun) error
	// StopOpenVPN stops the connection with this id, and reports nothing amiss for one that
	// is not running: asking for it to be stopped and it already being stopped are the same
	// outcome.
	StopOpenVPN(ctx context.Context, id string) error
	// ScopeOpenVPN gives the interface this connection is running on a default route of its
	// own, so traffic bound to that interface reaches the network through the connection
	// rather than failing for want of a route. Asking again for a connection that already has
	// one replaces it, which is what a connection that reconnected onto a fresh interface
	// needs: the interface it had went away and took the route with it.
	ScopeOpenVPN(ctx context.Context, scope OpenVPNScope) error
	// UnscopeOpenVPN takes that route back while the connection goes on running, and reports
	// nothing amiss for a connection that has none. Ending the connection removes it too, by
	// this side rather than by the caller: the caller may be the thing that has gone away.
	UnscopeOpenVPN(ctx context.Context, id string) error
}

// OpenVPNSession is a privileged side that can run OpenVPN connections, plus the Close that
// ends every one it started.
type OpenVPNSession interface {
	OpenVPNRunner
	Close() error
}

// OpenOpenVPN claims the right to run OpenVPN connections, in this process when it already
// holds the rights and over the helper socket when it does not.
//
// It is its own connection rather than the node's, for the reason the system resolver's is:
// the lifetimes are separate, and sharing one would mean every rebuild of the node dropping
// every VPN connection with it.
func OpenOpenVPN(ctx context.Context, opts Options) (OpenVPNSession, error) {
	if !OpenVPNSupported() {
		return nil, ErrOpenVPNUnsupported
	}
	host, err := Open(ctx, opts)
	if err != nil {
		return nil, err
	}
	session, ok := host.(OpenVPNSession)
	if !ok {
		return nil, errors.Join(
			fmt.Errorf("this build's privileged side (%T) cannot run an OpenVPN connection", host),
			host.Close(),
		)
	}
	return session, nil
}

// OpenVPNBinary is the program this side will run, or a refusal naming where it looked.
//
// The candidates are a fixed list per platform, and the program at each has to be one no
// account but root can change: the file, every directory on the way to it, and every library
// it loads (trustedRootProgram). Searching a path would mean the program this runs as root is
// chosen by whatever an environment variable said, which is the shape of the problem this
// whole boundary is here to avoid.
//
// A refusal ends with how to install a copy that passes, because the usual cause is an
// ordinary package manager install rather than anything wrong with the machine.
func OpenVPNBinary() (string, error) {
	candidates := openvpnCandidates()
	if len(candidates) == 0 {
		return "", ErrOpenVPNUnsupported
	}
	var refused []error
	for _, path := range candidates {
		err := trustedRootProgram(path)
		switch {
		case err == nil:
			return path, nil
		case errors.Is(err, os.ErrNotExist):
			continue
		default:
			// A file that is there and not usable is worth saying out loud: it is the
			// difference between "install openvpn" and "the openvpn on this machine can be
			// rewritten by a normal account", and the second one is a finding.
			refused = append(refused, err)
		}
	}
	if len(refused) > 0 {
		return "", errors.Join(append(append([]error{ErrNoOpenVPN}, refused...), errors.New(openvpnInstallAdvice()))...)
	}
	return "", fmt.Errorf("%w: looked in %s. %s", ErrNoOpenVPN, strings.Join(candidates, ", "), openvpnInstallAdvice())
}

// Validate refuses a request this side will not act on.
//
// It runs on the privileged side. The caller checks too, but a check that only runs before
// the message is sent is a check on the well-behaved.
func (r OpenVPNRun) Validate() error {
	switch {
	case !validConnectionID(r.ID):
		return fmt.Errorf("%q is not a connection identifier", r.ID)
	case r.Proto != openvpnProtoUDP && r.Proto != openvpnProtoTCP:
		return fmt.Errorf("the transport must be %q or %q, not %q", openvpnProtoUDP, openvpnProtoTCP, r.Proto)
	}
	if _, _, err := openvpnRemote(r.Remote); err != nil {
		return err
	}
	if len(r.Routes) > maxOpenVPNRoutes {
		return fmt.Errorf("a connection may carry at most %d networks, and this one names %d",
			maxOpenVPNRoutes, len(r.Routes))
	}
	for _, prefix := range r.Routes {
		if !prefix.IsValid() {
			return errors.New("one of the networks this connection carries is not a network")
		}
	}
	for _, field := range []struct{ name, value string }{
		{"certificate authority", r.CA},
		{"device certificate", r.Cert},
		{"device private key", r.Key},
		{"tls-crypt key", r.TLSCrypt},
		{"tls-auth key", r.TLSAuth},
	} {
		if len(field.value) > maxOpenVPNMaterialLen {
			return fmt.Errorf("the %s is %d bytes, over the %d-byte limit",
				field.name, len(field.value), maxOpenVPNMaterialLen)
		}
	}
	if r.CA == "" {
		return errors.New("no certificate authority was given, so there is nothing to check the server against")
	}
	if (r.Cert == "") != (r.Key == "") {
		return errors.New("a device certificate and its private key are given together or not at all")
	}
	if r.Cert == "" && !r.AuthUserPass {
		return errors.New("this connection has neither a device certificate nor an account, so the server has no way to tell who is connecting")
	}
	if r.TLSCrypt != "" && r.TLSAuth != "" {
		return errors.New("a connection uses a tls-crypt key or a tls-auth key, not both")
	}
	switch r.KeyDirection {
	case "", "0", "1":
	default:
		return fmt.Errorf("the key direction must be 0 or 1, not %q", r.KeyDirection)
	}
	for _, token := range []struct{ name, value string }{{"cipher", r.Cipher}, {"digest", r.Auth}} {
		if token.value != "" && !openvpnTokenShape(token.value) {
			return fmt.Errorf("%q is not an algorithm name for the %s", token.value, token.name)
		}
	}
	if err := validOpenVPNVerifyName(r.VerifyName, r.VerifyNameType); err != nil {
		return err
	}
	if r.MTU != 0 && (r.MTU < 1280 || r.MTU > 9000) {
		return fmt.Errorf("the packet size must be 0 or between 1280 and 9000, not %d", r.MTU)
	}
	return nil
}

// validConnectionID reports whether s is one of this app's connection identifiers. The shape
// is what is checked, because the value becomes a file name under a directory this side
// makes: anything with a separator in it is refused before it can be a path.
func validConnectionID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// openvpnTokenShape reports whether s can be an algorithm name: the characters one is made
// of, and nothing that could begin a second word in a configuration file.
func openvpnTokenShape(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case (r == '.' || r == '-' || r == '_') && i > 0:
		default:
			return false
		}
	}
	return true
}

// openvpnRemote splits and checks the server address.
//
// The host may be a name, because a great many OpenVPN servers are named rather than
// numbered, but only one made of the characters a name is made of: it is written into a file
// a root process reads back.
func openvpnRemote(remote string) (host, port string, err error) {
	if remote == "" {
		return "", "", errors.New("no server address was given")
	}
	if strings.HasPrefix(remote, "[") {
		end := strings.Index(remote, "]")
		if end < 0 || end+2 > len(remote) || remote[end+1] != ':' {
			return "", "", fmt.Errorf("the server address %q is not a host and a port", remote)
		}
		host, port = remote[1:end], remote[end+2:]
	} else {
		var found bool
		host, port, found = strings.Cut(remote, ":")
		if !found || strings.Contains(port, ":") {
			return "", "", fmt.Errorf("the server address %q is not a host and a port", remote)
		}
	}
	if !openvpnHostShape(host) {
		return "", "", fmt.Errorf("the server %q is not an address or a host name", host)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("the server's port %q is not between 1 and 65535", port)
	}
	return host, port, nil
}

// openvpnHostShape reports whether a host is one this side will write into a configuration:
// a literal address without a zone, or a name made of letters, digits, hyphens, underscores
// and dots. A zone is refused because netip takes any bytes after the %, newlines included,
// and the host becomes a line of a configuration root's OpenVPN reads.
func openvpnHostShape(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, r := range host {
		if unicode.IsControl(r) {
			return false
		}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Zone() == ""
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			default:
				return false
			}
		}
	}
	return true
}

// validOpenVPNVerifyName checks the certificate-name requirement.
//
// The name is written as a quoted argument, so the two characters that would end the quoting
// are refused rather than escaped: this side does not rely on its own escaping being right.
func validOpenVPNVerifyName(name, kind string) error {
	if name == "" {
		return nil
	}
	if len(name) > 256 {
		return fmt.Errorf("the certificate name is %d characters, over the 256-character limit", len(name))
	}
	if strings.ContainsAny(name, "\"\\\n\r\x00") {
		return errors.New("the certificate name must not contain a quotation mark, a backslash or a line break")
	}
	switch kind {
	case "", "name", "name-prefix", "subject":
		return nil
	}
	return fmt.Errorf("the certificate name is matched as name, name-prefix or subject, not as %q", kind)
}

// Render writes the configuration this run becomes.
//
// It is a fixed template: every line comes from this function, and the request only decides
// which of them are present and what values they carry. There is no arm that copies a line
// from the caller, which is what makes the result something no request can turn into a
// directive naming a program.
//
// dev is the platform's interface argument, supplied by this package rather than by the
// request: which kind of interface to open is this side's decision.
func (r OpenVPNRun) Render(dev string) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	host, port, err := openvpnRemote(r.Remote)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	line := func(format string, args ...any) {
		fmt.Fprintf(&b, format+"\n", args...)
	}

	line("# Written by app-tail. Edits here are replaced every time the connection starts.")
	line("client")
	line("nobind")
	line("dev-type tun")
	line("dev %s", dev)
	line("persist-key")
	line("resolv-retry infinite")
	line("remote %s %s %s", host, port, r.Proto)
	// Everything the server pushes about this machine's routing and name resolution is
	// dropped. What this connection carries is what app-tail was told it carries, and a
	// server able to add routes here would be a guest deciding what its host does with its
	// own traffic. The interface's own addressing still comes from the server, which is the
	// one part of this only the server knows.
	line("route-nopull")
	// The account is answered over the management interface, so it is never written to a
	// file, and it is asked for again rather than kept when the connection renegotiates.
	line("auth-nocache")
	line("management-query-passwords")
	// openvpn waits here until the agent's management client releases it, so the connection
	// does not reach the server before there is anything listening to what it reports.
	line("management-hold")
	line("management-forget-disconnect")
	line("verb 3")

	if r.VerifyServerCert {
		line("remote-cert-tls server")
	}
	if r.VerifyName != "" {
		kind := r.VerifyNameType
		if kind == "" {
			// openvpn's own default for a bare verify-x509-name, which is the match the
			// configurations that leave it out are written against.
			kind = "subject"
		}
		line("verify-x509-name %q %s", r.VerifyName, kind)
	}
	if r.Cipher != "" {
		// Offered alongside the modern set rather than instead of it: this value usually
		// comes from a `cipher` line in a configuration file written years ago, and a
		// connection offering only that one cipher would fail against a server that has
		// since moved on.
		line("data-ciphers %s:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", r.Cipher)
		line("data-ciphers-fallback %s", r.Cipher)
	}
	if r.Auth != "" {
		line("auth %s", r.Auth)
	}
	if r.MTU != 0 {
		line("tun-mtu %d", r.MTU)
	}
	if r.AuthUserPass {
		line("auth-user-pass")
	}
	if r.TLSAuth != "" && r.KeyDirection != "" {
		line("key-direction %s", r.KeyDirection)
	}

	redirectsIPv6 := false
	for _, prefix := range r.Routes {
		if prefix.Bits() == 0 {
			// Carrying everything is RedirectGateway's job. Written as a plain route it
			// would replace this machine's own default rather than sit beside it, and
			// whether it is written at all is a decision made elsewhere.
			redirectsIPv6 = redirectsIPv6 || prefix.Addr().Is6()
			continue
		}
		if prefix.Addr().Is4() {
			line("route %s %s", prefix.Masked().Addr(), maskOf(prefix))
			continue
		}
		line("route-ipv6 %s", prefix.Masked())
	}
	if r.RedirectGateway {
		// def1 installs two half-sized routes rather than replacing the default, so this
		// machine's own default route survives -- which is what the connection's own
		// encrypted packets still leave by, and so what stops it routing itself in a circle.
		//
		// The ipv6 keyword is added only when the connection said it carries a v6 default.
		// Sending v6 traffic into a connection that does not carry it is a hole in the
		// floor; leaving it out means v6 traffic keeps going out the way it always did,
		// which the connection reports as a limit rather than hides.
		if redirectsIPv6 {
			line("redirect-gateway def1 ipv6")
		} else {
			line("redirect-gateway def1")
		}
	}

	for _, block := range []struct{ name, body string }{
		{"ca", r.CA},
		{"cert", r.Cert},
		{"key", r.Key},
		{"tls-crypt", r.TLSCrypt},
		{"tls-auth", r.TLSAuth},
	} {
		if block.body == "" {
			continue
		}
		if strings.Contains(block.body, "</"+block.name+">") {
			// Reached only by material carrying the line that would close its own section,
			// which is the one way a value here could become configuration. It is refused
			// rather than escaped, because no certificate and no key has such a line in it.
			return "", fmt.Errorf("the %s carries a </%s> line, which is not part of any certificate or key",
				block.name, block.name)
		}
		line("<%s>", block.name)
		b.WriteString(strings.TrimRight(block.body, "\n"))
		b.WriteString("\n")
		line("</%s>", block.name)
	}
	return b.String(), nil
}

// maskOf renders a prefix length as the dotted mask openvpn's route directive takes.
func maskOf(prefix netip.Prefix) netip.Addr {
	var mask [4]byte
	for bit := range prefix.Bits() {
		mask[bit/8] |= 1 << (7 - bit%8)
	}
	return netip.AddrFrom4(mask)
}

// openvpnProcess is one running connection and everything that has to be released with it.
type openvpnProcess struct {
	cmd *exec.Cmd
	// dir holds the rendered configuration. It is removed once the program has exited and
	// not before, because openvpn re-reads its configuration when it restarts itself.
	dir string
	// socket is the management socket openvpn listens on, removed once the program has exited.
	socket string
	// done is closed once the program has exited and its directory is gone.
	done chan struct{}

	// mu guards scoped alone. It is the connection's own lock rather than the session's
	// because installing a route is an operation on this machine that takes as long as the
	// operating system takes, and holding the session lock across it would stop every other
	// connection from being started or stopped meanwhile.
	mu sync.Mutex
	// scoped is the interface this side gave a default route of its own, empty for none. It
	// is what the teardown takes back: a policy rule outlives the interface it names on
	// Linux, so an interface going away is not the route going away.
	scoped string
}

func (p *openvpnProcess) scopedInterface() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.scoped
}

func (p *openvpnProcess) setScopedInterface(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.scoped = name
}

// StartOpenVPN starts one connection.
func (l *Local) StartOpenVPN(ctx context.Context, run OpenVPNRun) error {
	if !OpenVPNSupported() {
		return ErrOpenVPNUnsupported
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := run.Validate(); err != nil {
		return err
	}
	binary, err := l.openvpnBinary()
	if err != nil {
		return err
	}
	text, err := run.Render(openvpnDevice())
	if err != nil {
		return err
	}
	// Looked up before anything is created: an account openvpn cannot be told the name of is
	// a connection nobody would be allowed to drive.
	manager, err := openvpnManagementUser()
	if err != nil {
		return err
	}
	socket := l.ManagementSocket(run.ID)
	if len(socket) > maxUnixSocketPath {
		return fmt.Errorf("the management socket %s is %d characters, over the %d-character limit a socket address holds",
			socket, len(socket), maxUnixSocketPath)
	}

	l.mu.Lock()
	switch {
	case l.closed:
		l.mu.Unlock()
		return errors.New("this session has already been torn down")
	case l.openvpn[run.ID] != nil:
		l.mu.Unlock()
		return fmt.Errorf("connection %s is already running", run.ID)
	}
	l.mu.Unlock()

	dir, err := os.MkdirTemp("", "app-tail-openvpn-")
	if err != nil {
		return fmt.Errorf("make a directory for this connection's configuration: %w", err)
	}
	// MkdirTemp already makes the directory 0700 and this process owns it; the file is
	// written 0600 as well, so a private key stays unreadable even if something else widens
	// the directory.
	path := openvpnConfigPath(dir, run.ID)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return errors.Join(fmt.Errorf("write this connection's configuration: %w", err), os.RemoveAll(dir))
	}

	// Written down before the program is started, and refused rather than worked around: what
	// follows creates a root process and a directory holding a private key, and creating either
	// without a record of it is the thing this record exists to prevent. The process number is
	// not known yet, so this first write is the directory alone -- which is the part that would
	// otherwise be left on the disk by a crash between here and the start.
	state := l.machineState()
	if err := state.setProcess(run.ID, dir, 0); err != nil {
		return errors.Join(err, os.RemoveAll(dir))
	}

	if err := prepareManagementSocket(l.managementDir(), socket); err != nil {
		return errors.Join(err, l.discardOpenVPNStart(state, run.ID, dir))
	}

	// The arguments are a list rather than a command line, so nothing here reaches a shell.
	// The context is deliberately not attached: it belongs to the request that asked for the
	// connection, and a connection that ended when that request returned would never survive
	// its own first second. What ends this process is StopOpenVPN or the session teardown.
	cmd := exec.Command(binary, openvpnArgs(path, socket, manager)...) //nolint:noctx // outliving the request is the point; see above.
	cmd.Dir = dir
	// Nothing from this session's environment reaches it, so an environment variable cannot
	// be a second way to configure a program running as root. What it does get is fixed per
	// platform; see openvpnEnv.
	cmd.Env = openvpnEnv()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return errors.Join(fmt.Errorf("read what this connection reports: %w", err),
			l.discardOpenVPNStart(state, run.ID, dir))
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return errors.Join(fmt.Errorf("read what this connection reports: %w", err),
			l.discardOpenVPNStart(state, run.ID, dir))
	}

	if err := cmd.Start(); err != nil {
		return errors.Join(
			fmt.Errorf("start the openvpn program for connection %s: %w", run.ID, err),
			l.discardOpenVPNStart(state, run.ID, dir),
		)
	}

	// The number the program was given, so a run that ends without stopping it leaves the next
	// one something to aim at. A failure here is reported and not fatal: the program is already
	// running, and refusing the start now would leave it running with this side no longer
	// tracking it -- which is worse than a record that names its directory and not its number.
	if err := state.setProcess(run.ID, dir, cmd.Process.Pid); err != nil {
		l.logf("openvpn %s: could not record the process number of this connection: %v", run.ID, err)
	}

	proc := &openvpnProcess{cmd: cmd, dir: dir, socket: socket, done: make(chan struct{})}
	l.mu.Lock()
	if l.openvpn == nil {
		l.openvpn = make(map[string]*openvpnProcess)
	}
	l.openvpn[run.ID] = proc
	l.mu.Unlock()

	go l.readOpenVPNOutput(run.ID, stderr)
	go l.watchOpenVPNOutput(run.ID, stdout, func() {
		if err := l.stopOpenVPNProcess(run.ID, proc); err != nil {
			l.logf("openvpn %s: %v", run.ID, err)
		}
	})
	go l.reapOpenVPN(run.ID, proc)
	return nil
}

// openvpnArgs is the command line one connection's openvpn is started with.
//
// Everything about the management interface is here rather than in the rendered file, so no
// value the caller sent is anywhere near it. From openvpn(8):
//
//   - "--management socket-name unix" listens on a unix socket. "For unix sockets, the default
//     behaviour is to create a unix domain socket that may be connected to by any process."
//   - "--management-client-user u: When the management interface is listening on a unix domain
//     socket, only allow connections from user u." openvpn checks the connecting process's
//     account itself, so the socket being open to every account in the file system does not
//     matter: anyone else is disconnected before a command is read.
//   - "--management-signal: Send SIGUSR1 signal to OpenVPN if management session disconnects."
//     With management-hold in the file, the restart that follows waits for a management client
//     before it reaches the server again, so an agent that has gone away leaves a held
//     process rather than a connection carrying traffic with nothing watching it.
func openvpnArgs(config, socket, manager string) []string {
	return []string{
		"--config", config,
		"--management", socket, "unix",
		"--management-client-user", manager,
		"--management-signal",
	}
}

// ManagementSocket is the socket openvpn listens on for one connection this side starts.
//
// The agent learns it the same way, from OpenVPNManagementSocket, so the two agree without the
// path crossing the boundary. It is a method so a runner that keeps its sockets somewhere else
// can say so, which is what a suite with no root does.
func (l *Local) ManagementSocket(id string) string {
	return filepath.Join(l.managementDir(), id+".sock")
}

// managementDir is the directory this side's management sockets go in.
func (l *Local) managementDir() string {
	if l.openvpnManagementDir == "" {
		return OpenVPNManagementDir
	}
	return l.openvpnManagementDir
}

// openvpnConfigPath is where one connection's rendered configuration goes.
//
// It is a function because two things need the same answer: the program is started with this
// path, and a later run identifies that program as the one a previous run started by finding
// this path among its arguments.
func openvpnConfigPath(dir, id string) string { return filepath.Join(dir, id+".conf") }

// discardOpenVPNStart undoes what was set up for a connection whose program never started.
//
// The directory goes before the record does: a record naming a directory that is gone costs
// the next start one removal that finds nothing, where a directory with no record left is a
// private key on the disk that nothing will ever remove.
func (l *Local) discardOpenVPNStart(state *rootState, id, dir string) error {
	return errors.Join(os.RemoveAll(dir), state.dropProcess(id))
}

// readOpenVPNOutput copies what the program writes to its error stream into this side's log.
//
// It is the only record of the failures that happen before the management connection is up
// -- a configuration openvpn will not parse, a certificate it will not read -- which are
// exactly the ones the agent would otherwise see as a connection that started and vanished.
func (l *Local) readOpenVPNOutput(id string, r io.ReadCloser) {
	scanner := bufio.NewScanner(r)
	// A line longer than this is not a message, it is something that has gone wrong with the
	// stream, and reading it whole would be memory another program decides the size of.
	scanner.Buffer(make([]byte, 0, 4096), 64<<10)
	for scanner.Scan() {
		l.logf("openvpn %s: %s", id, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		l.logf("openvpn %s: could not read what the connection reported: %v", id, err)
	}
}

// reapOpenVPN waits for one connection to exit and releases what it held.
func (l *Local) reapOpenVPN(id string, proc *openvpnProcess) {
	defer close(proc.done)
	err := proc.cmd.Wait()
	l.mu.Lock()
	if held, ok := l.openvpn[id]; ok && held == proc {
		delete(l.openvpn, id)
	}
	l.mu.Unlock()
	l.unscopeOpenVPN(id, proc)
	// openvpn leaves its socket behind when it exits, and the next start of the same
	// connection would otherwise find it in the way.
	if err := os.Remove(proc.socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		l.logf("openvpn %s: could not remove this connection's management socket: %v", id, err)
	}
	if rmErr := os.RemoveAll(proc.dir); rmErr != nil {
		l.logf("openvpn %s: could not remove this connection's configuration directory: %v", id, rmErr)
	} else if stateErr := l.machineState().dropProcess(id); stateErr != nil {
		// Forgotten only once the directory is gone: a record kept for a directory that is
		// still there is the next start removing it, and dropping the record first would leave
		// nothing that ever would.
		l.logf("openvpn %s: could not forget this connection in the record of what app-tail installed: %v", id, stateErr)
	}
	if err != nil {
		l.logf("openvpn %s: the connection ended: %v", id, err)
		return
	}
	l.logf("openvpn %s: the connection ended", id)
}

// StopOpenVPN stops one connection.
func (l *Local) StopOpenVPN(_ context.Context, id string) error {
	l.mu.Lock()
	proc := l.openvpn[id]
	l.mu.Unlock()
	if proc == nil {
		return nil
	}
	return l.stopOpenVPNProcess(id, proc)
}

// stopOpenVPNProcess asks one connection to close and kills it if it will not.
//
// The ask comes first because openvpn handles it by telling the server the client is going
// and taking its own interface and routes down, where killing it outright leaves the server
// holding the session until it times out. The kill is what guarantees the process does not
// outlive this one, which is the property that matters more of the two.
//
// It must not be called while the session lock is held: the goroutine that closes done takes
// that lock on its way past.
func (l *Local) stopOpenVPNProcess(id string, proc *openvpnProcess) error {
	kill := func() error {
		if err := proc.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("stop the openvpn program for connection %s: %w", id, err)
		}
		<-proc.done
		return nil
	}
	if err := terminate(proc.cmd.Process); err != nil && !errors.Is(err, os.ErrProcessDone) {
		l.logf("openvpn %s: could not ask the connection to close, killing it: %v", id, err)
		return kill()
	}
	timer := time.NewTimer(openvpnStopGrace)
	defer timer.Stop()
	select {
	case <-proc.done:
		return nil
	case <-timer.C:
	}
	l.logf("openvpn %s: the connection did not close when asked, killing it", id)
	return kill()
}

// closeOpenVPN stops every connection this session started.
//
// It is part of the teardown rather than something the agent has to remember, because the
// connections hold a network interface and routes on this machine and the agent may be the
// thing that has just gone away.
func (l *Local) closeOpenVPN() []error {
	l.mu.Lock()
	running := make(map[string]*openvpnProcess, len(l.openvpn))
	for id, proc := range l.openvpn {
		running[id] = proc
	}
	l.mu.Unlock()

	// Concurrently, because each one waits out its own grace period: a machine holding
	// several would otherwise take that long once per connection, on the path that ends the
	// process.
	var mu sync.Mutex
	var errs []error
	var wg sync.WaitGroup
	for id, proc := range running {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.stopOpenVPNProcess(id, proc); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	// Sorted because they are gathered from goroutines: a teardown that reports the same
	// failures in a different order every time is one nobody can compare against the last.
	slices.SortFunc(errs, func(a, b error) int { return strings.Compare(a.Error(), b.Error()) })
	return errs
}
