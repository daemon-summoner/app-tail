// SPDX-License-Identifier: MIT

//go:build unix

package hostnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/grants"
)

// managementDir is a directory a Local may put its management sockets in, not yet made: the
// start is what makes it.
//
// os.MkdirTemp rather than t.TempDir: a unix socket address is a fixed-size field in the
// kernel, and the per-test directory name t.TempDir builds is long enough on macOS to push a
// socket path over the limit a start enforces -- which would make these tests fail for a
// reason that has nothing to do with what they are about.
func managementDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ovpn") //nolint:usetesting // t.TempDir's names are too long; see above.
	if err != nil {
		t.Fatalf("make a directory for the management sockets: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove the management socket directory: %v", err)
		}
	})
	return filepath.Join(dir, "openvpn")
}

// workingRun is a connection that passes every check, so a case can change one thing about
// it and be sure that thing is what was refused.
//
// It records this account as the one the helper serves, so the account openvpn is told may
// manage the connection is one that exists.
// workingRunCA is the certificate authority workingRun trusts.
const workingRunCA = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----"

func workingRun(t *testing.T) OpenVPNRun {
	t.Helper()
	t.Setenv(ownerEnv, strconv.Itoa(os.Geteuid()))
	return OpenVPNRun{
		ID:               "tn_a1b2c3",
		Remote:           "vpn.example.com:1194",
		Proto:            openvpnProtoUDP,
		CA:               workingRunCA,
		Cert:             "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----",
		Key:              "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----",
		VerifyServerCert: true,
		Routes:           []netip.Prefix{netip.MustParsePrefix("10.8.0.0/16")},
	}
}

// The privileged side checks everything again, because a check that only runs before the
// message is sent is a check on the well-behaved.
func TestARunIsCheckedOnTheSideThatHoldsTheRights(t *testing.T) {
	base := workingRun(t)
	if err := base.Validate(); err != nil {
		t.Fatalf("the run every case is built from was refused: %v", err)
	}

	for _, tc := range []struct {
		what   string
		change func(*OpenVPNRun)
	}{
		{"an identifier that is a path", func(r *OpenVPNRun) { r.ID = "../../etc/openvpn" }},
		{"a transport this side does not have", func(r *OpenVPNRun) { r.Proto = "sctp" }},
		{"a server address with a directive in it", func(r *OpenVPNRun) {
			r.Remote = "vpn.example.com\nup /tmp/x:1194"
		}},
		{"no certificate authority", func(r *OpenVPNRun) { r.CA = "" }},
		{"a certificate with no key", func(r *OpenVPNRun) { r.Key = "" }},
		{"a key with no certificate", func(r *OpenVPNRun) { r.Cert = "" }},
		{"neither a certificate nor an account", func(r *OpenVPNRun) { r.Cert, r.Key = "", "" }},
		{"both kinds of tls key", func(r *OpenVPNRun) { r.TLSCrypt, r.TLSAuth = "x", "y" }},
		{"a key direction that is not a direction", func(r *OpenVPNRun) { r.KeyDirection = "2" }},
		{"a cipher carrying a second directive", func(r *OpenVPNRun) { r.Cipher = "AES-256-GCM\nup /tmp/x" }},
		{"a digest carrying a second directive", func(r *OpenVPNRun) { r.Auth = "SHA256 x" }},
		{"a certificate name that ends its own quoting", func(r *OpenVPNRun) { r.VerifyName = `a" b` }},
		{"a packet size below any interface", func(r *OpenVPNRun) { r.MTU = 576 }},
		{"a packet size above any interface", func(r *OpenVPNRun) { r.MTU = 65535 }},
		{"more networks than a connection may carry", func(r *OpenVPNRun) {
			r.Routes = make([]netip.Prefix, maxOpenVPNRoutes+1)
			for i := range r.Routes {
				r.Routes[i] = netip.MustParsePrefix("10.8.0.0/16")
			}
		}},
		{"a network that is not a network", func(r *OpenVPNRun) { r.Routes = []netip.Prefix{{}} }},
		{"key material past the size limit", func(r *OpenVPNRun) {
			r.Key = strings.Repeat("x", maxOpenVPNMaterialLen+1)
		}},
	} {
		run := base
		tc.change(&run)
		if err := run.Validate(); err == nil {
			t.Errorf("%s was accepted, want a refusal", tc.what)
		}
	}
}

// The rendered configuration is a fixed template. What matters is that no value the caller
// sent reaches it as a directive, and that the directives which would run a program are
// never written at all.
func TestTheRenderedConfigurationNamesNoProgramToRun(t *testing.T) {
	run := workingRun(t)
	run.Proto = openvpnProtoTCP
	run.Cipher = "AES-256-CBC"
	run.Auth = "SHA512"
	run.MTU = 1400
	run.AuthUserPass = true
	run.VerifyName = "server.example.com"
	run.VerifyNameType = "subject"
	run.TLSAuth = "-----BEGIN OpenVPN Static key V1-----\ndeadbeef\n-----END OpenVPN Static key V1-----"
	run.KeyDirection = "1"
	run.Routes = append(run.Routes, netip.MustParsePrefix("192.168.4.0/24"), netip.MustParsePrefix("fd00::/64"))

	text, err := run.Render("utun")
	if err != nil {
		t.Fatalf("render the configuration: %v", err)
	}

	for _, want := range []string{
		"client\n",
		"dev utun\n",
		"remote vpn.example.com 1194 tcp\n",
		// The one line that decides whether the server or this app says what the machine
		// routes and how it resolves names.
		"route-nopull\n",
		"management-query-passwords\n",
		"management-hold\n",
		"remote-cert-tls server\n",
		`verify-x509-name "server.example.com" subject` + "\n",
		"data-ciphers AES-256-CBC:",
		"data-ciphers-fallback AES-256-CBC\n",
		"auth SHA512\n",
		"tun-mtu 1400\n",
		"auth-user-pass\n",
		"key-direction 1\n",
		"route 10.8.0.0 255.255.0.0\n",
		"route 192.168.4.0 255.255.255.0\n",
		"route-ipv6 fd00::/64\n",
		"<ca>\n",
		"</tls-auth>\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the configuration does not carry %q:\n%s", want, text)
		}
	}
	// The directives that name a program, plus the two that would let a caller reach the
	// file system through this. None of them has an arm that writes it, and this is the
	// check that says so rather than the reading of the code that says so.
	for _, forbidden := range []string{"\nup ", "\ndown ", "\nroute-up ", "\nplugin ", "\nscript-security ",
		"\niproute ", "\nchroot ", "\ndaemon", "\nsetcon ", "\nconfig ", "\nauth-user-pass /"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("the configuration carries %q:\n%s", forbidden, text)
		}
	}
	// Carrying everything is a separate decision, and nothing asked for it here.
	if strings.Contains(text, "redirect-gateway") {
		t.Errorf("the configuration redirects this machine's traffic without being asked to:\n%s", text)
	}
}

// Declaring a default route makes a connection eligible to carry everything. Actually
// carrying it is the other decision, and only that one writes the directive.
func TestCarryingEverythingIsWrittenOnlyWhenTheConnectionWasChosenToCarryIt(t *testing.T) {
	run := workingRun(t)
	run.Routes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}

	text, err := run.Render("utun")
	if err != nil {
		t.Fatalf("render the configuration: %v", err)
	}
	if strings.Contains(text, "redirect-gateway") {
		t.Errorf("a declared default route redirected this machine's traffic on its own:\n%s", text)
	}
	if strings.Contains(text, "\nroute 0.0.0.0") {
		t.Errorf("a default route was written as a plain route, which would replace this machine's own:\n%s", text)
	}

	run.RedirectGateway = true
	text, err = run.Render("utun")
	if err != nil {
		t.Fatalf("render the configuration: %v", err)
	}
	if !strings.Contains(text, "\nredirect-gateway def1\n") {
		t.Errorf("the connection chosen to carry everything does not redirect v4:\n%s", text)
	}
	// The v6 keyword is absent because this connection never said it carries v6. Adding it
	// would send v6 traffic into a connection with nowhere to put it.
	if strings.Contains(text, "ipv6") {
		t.Errorf("v6 traffic was redirected into a connection carrying no v6 route:\n%s", text)
	}

	run.Routes = append(run.Routes, netip.MustParsePrefix("::/0"))
	text, err = run.Render("utun")
	if err != nil {
		t.Fatalf("render the configuration: %v", err)
	}
	if !strings.Contains(text, "\nredirect-gateway def1 ipv6\n") {
		t.Errorf("a connection carrying a v6 default did not redirect v6:\n%s", text)
	}
}

// A name with no match written is checked against the whole subject, which is openvpn's own
// default for a bare verify-x509-name. Matching it as a common name would compare a subject
// line to a name no certificate carries: a connection that reaches its server every time and
// refuses its certificate every time.
func TestANameWithNoMatchIsCheckedAgainstTheWholeSubject(t *testing.T) {
	run := workingRun(t)
	run.VerifyName = "CN=vpn.example.com"
	run.VerifyNameType = ""

	text, err := run.Render("utun")
	if err != nil {
		t.Fatalf("render the configuration: %v", err)
	}
	if want := `verify-x509-name "CN=vpn.example.com" subject` + "\n"; !strings.Contains(text, want) {
		t.Errorf("the configuration does not carry %q:\n%s", want, text)
	}
}

// The one way a value could become configuration is material carrying the line that closes
// its own section. It is refused rather than escaped.
func TestMaterialCarryingItsOwnClosingTagIsRefused(t *testing.T) {
	run := workingRun(t)
	run.CA += "\n</ca>\nup /tmp/x\n<ca>\n"
	if _, err := run.Render("utun"); err == nil {
		t.Error("material carrying its own closing tag was rendered, want a refusal")
	}
}

// The program runs as root, so the file at the end of the path has to be one no other
// account can rewrite. A search would let whatever wrote PATH decide what runs.
func TestTheOpenVPNProgramMustBeOneNoOtherAccountCanRewrite(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "openvpn")
	if err := trustedRootProgram(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("trustedRootProgram on a path with nothing at it = %v, want os.ErrNotExist", err)
	}

	if err := os.Mkdir(filepath.Join(dir, "dir"), 0o700); err != nil {
		t.Fatalf("make a directory where a program should be: %v", err)
	}
	if err := trustedRootProgram(filepath.Join(dir, "dir")); err == nil {
		t.Error("a directory was accepted as a program, want a refusal")
	}

	if os.Geteuid() == 0 {
		// The remaining arm is about a file belonging to somebody other than root, and this
		// suite is running as root, so it cannot make one that is not its own.
		t.Skip("this check needs a file that does not belong to root, and the suite is running as root")
	}
	mine := filepath.Join(dir, "mine")
	if err := os.WriteFile(mine, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("make a program belonging to this account: %v", err)
	}
	if err := trustedRootProgram(mine); err == nil {
		t.Error("a program belonging to this account was accepted to run as root, want a refusal")
	}
}

// What follows is the life of a running connection rather than the shape of one: it is stopped,
// it will not stop, it ends on its own, the session ends under it. The program that stands in
// for openvpn is the machine's own shell, because what is under test is what this side does
// with a process it started -- ask, wait, kill, reap -- and none of that is about openvpn.

// runningProgram registers a connection running the given program, with the reaper watching it
// the way StartOpenVPN leaves one watching.
func runningProgram(t *testing.T, l *Local, id string, argv ...string) *openvpnProcess {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command(argv[0], argv[1:]...) //nolint:noctx // the connection outlives the request, as the real one does.
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the program standing in for the connection: %v", err)
	}
	proc := &openvpnProcess{cmd: cmd, dir: dir, done: make(chan struct{})}
	l.mu.Lock()
	if l.openvpn == nil {
		l.openvpn = make(map[string]*openvpnProcess)
	}
	l.openvpn[id] = proc
	l.mu.Unlock()
	go l.reapOpenVPN(id, proc)
	t.Cleanup(func() {
		select {
		case <-proc.done:
		default:
			_ = cmd.Process.Kill()
			<-proc.done
		}
	})
	return proc
}

// awaitFile waits for a program to report that it has reached the state a test needs it in.
func awaitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the program standing in for the connection never reached the state under test (%s was never written)", path)
}

// recordingLog collects what this side reports, which for a connection that ended is the only
// place it is reported at all.
type recordingLog struct {
	mu    sync.Mutex
	lines []string
}

func (r *recordingLog) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}

func (r *recordingLog) said(text string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, line := range r.lines {
		if strings.Contains(line, text) {
			return true
		}
	}
	return false
}

// A connection is asked to close before it is killed, because openvpn handles the ask by telling
// its server the client is leaving and taking its own interface and routes down. A stop that
// killed outright would leave every server holding the session until it timed out.
func TestAConnectionThatClosesWhenAskedIsNotKilled(t *testing.T) {
	log := &recordingLog{}
	local := NewLocal(log.logf)
	proc := runningProgram(t, local, "tn_stop001", "/bin/sh", "-c", "sleep 30")

	started := time.Now()
	if err := local.StopOpenVPN(context.Background(), "tn_stop001"); err != nil {
		t.Fatalf("stop the connection: %v", err)
	}
	if took := time.Since(started); took >= openvpnStopGrace {
		t.Errorf("stopping a connection that closes when asked took %v, so it waited out the grace period", took)
	}
	if log.said("killing it") {
		t.Error("a connection that closed when asked was killed as well")
	}

	<-proc.done
	local.mu.Lock()
	defer local.mu.Unlock()
	if local.openvpn["tn_stop001"] != nil {
		t.Error("the connection is still recorded as running after it ended")
	}
	if _, err := os.Stat(proc.dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the connection's configuration directory is still there (%v), so a private key was left on disk", err)
	}
}

// The kill is what guarantees the program does not outlive this process, which matters more
// than the clean shutdown: a connection left running holds an interface and routes on this
// machine that nothing is driving any more.
func TestAConnectionThatWillNotCloseIsKilled(t *testing.T) {
	log := &recordingLog{}
	local := NewLocal(log.logf)
	// Deaf to the ask, which is the state this whole arm exists for. The wait is a loop rather
	// than one sleep because a shell whose last command is the whole script replaces itself with
	// that command, and the replacement carries none of the shell's signal handling. The file is
	// how the test knows the program is deaf yet: asked before the trap is installed, it closes
	// like any other program and the arm under test is never reached.
	ready := filepath.Join(t.TempDir(), "deaf")
	proc := runningProgram(t, local, "tn_stop002", "/bin/sh", "-c",
		`trap "" TERM; : > "$0"; while true; do sleep 1; done`, ready)
	awaitFile(t, ready)

	if err := local.StopOpenVPN(context.Background(), "tn_stop002"); err != nil {
		t.Fatalf("stop a connection that will not close: %v", err)
	}
	select {
	case <-proc.done:
	default:
		t.Fatal("the stop returned while the connection was still running")
	}
	if !log.said("did not close when asked") {
		t.Error("a connection that had to be killed was not reported, so nothing records that it happened")
	}
}

// Asking for a connection to be stopped and it already being stopped are the same outcome. A
// failure here would have every caller that stops a connection twice -- the agent's own
// teardown after a connection ended on its own -- reporting something wrong.
func TestStoppingAConnectionThatIsNotRunningIsNothingAmiss(t *testing.T) {
	local := NewLocal(func(string, ...any) {})
	if err := local.StopOpenVPN(context.Background(), "tn_none001"); err != nil {
		t.Errorf("stop a connection that is not running: %v", err)
	}
}

// The session teardown stops every connection, because the connections hold interfaces and
// routes on this machine and the agent may be the thing that has just gone away.
func TestEveryConnectionIsStoppedWhenTheSessionEnds(t *testing.T) {
	local := NewLocal(func(string, ...any) {})
	first := runningProgram(t, local, "tn_close01", "/bin/sh", "-c", "sleep 30")
	second := runningProgram(t, local, "tn_close02", "/bin/sh", "-c", "sleep 30")

	if err := local.Close(); err != nil {
		t.Fatalf("end the session: %v", err)
	}
	for name, proc := range map[string]*openvpnProcess{"the first": first, "the second": second} {
		select {
		case <-proc.done:
		default:
			t.Errorf("%s connection was still running after the session ended", name)
		}
	}
}

// What a connection writes before its management connection is up -- a configuration openvpn
// will not parse, a certificate it will not read -- reaches nothing else. Without this it is a
// connection that started and vanished with no reason anywhere.
func TestWhatAConnectionReportsReachesThisSidesLog(t *testing.T) {
	log := &recordingLog{}
	local := NewLocal(log.logf)

	r, w := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		local.readOpenVPNOutput("tn_says001", r)
	}()
	if _, err := io.WriteString(w, "Cannot load certificate file\nExiting due to fatal error\n"); err != nil {
		t.Fatalf("write what the connection reports: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close the connection's error stream: %v", err)
	}
	<-done

	for _, want := range []string{"Cannot load certificate file", "Exiting due to fatal error"} {
		if !log.said(want) {
			t.Errorf("%q never reached this side's log, so the connection failed with no reason anywhere", want)
		}
	}
	if !log.said("tn_says001") {
		t.Error("the report does not name the connection it came from")
	}
}

// Once openvpn says it has finished configuring the connection, this side reads the addresses
// on the interface openvpn named and holds them to the approvals. One that is not approved
// stops the connection and says why; one that is leaves it running. Everything the program
// writes is read either way, so a full pipe never stalls it.
func TestTheAddressesAConnectionEndsUpWithAreCheckedOnceItIsUp(t *testing.T) {
	output := "TUN/TAP device tun7 opened\nPUSH: Received control message\nInitialization Sequence Completed\n" +
		strings.Repeat("traffic\n", 10000)
	for _, tc := range []struct {
		name     string
		verdict  error
		wantStop bool
	}{
		{"approved", nil, false},
		{"not approved", &grants.MissingGrants{Needs: []grants.Need{{Kind: grants.KindRoute, Value: "203.0.0.0/8", Reason: "send 203.0.0.0/8"}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &recordingLog{}
			local := NewLocal(log.logf)
			var askedID, askedName string
			var asked []netip.Prefix
			local.interfaceAddrs = func(name string) ([]netip.Prefix, error) {
				askedName = name
				return []netip.Prefix{netip.MustParsePrefix("203.0.113.7/8")}, nil
			}
			local.openvpnAddrs = func(id string, addrs []netip.Prefix) error {
				askedID, asked = id, addrs
				return tc.verdict
			}
			stopped := false
			local.watchOpenVPNOutput("tn_pushed01", strings.NewReader(output), func() { stopped = true })

			if askedID != "tn_pushed01" || askedName != "tun7" || len(asked) != 1 {
				t.Fatalf("checked %q on %q with %v, want the connection's own interface tun7", askedID, askedName, asked)
			}
			if stopped != tc.wantStop {
				t.Errorf("stopped = %v, want %v", stopped, tc.wantStop)
			}
			if tc.wantStop && !log.said("203.0.0.0/8") {
				t.Error("the connection was stopped without saying which range was not approved")
			}
		})
	}
}

// A connection that says it is configured without having named its interface cannot be
// checked, and is stopped rather than trusted.
func TestAConnectionWhoseInterfaceIsUnknownIsStoppedWhenItComesUp(t *testing.T) {
	log := &recordingLog{}
	local := NewLocal(log.logf)
	local.openvpnAddrs = func(string, []netip.Prefix) error { return nil }
	stopped := false
	local.watchOpenVPNOutput("tn_nodev001", strings.NewReader("Initialization Sequence Completed\n"), func() { stopped = true })
	if !stopped {
		t.Error("a connection on an interface nobody named was left running unchecked")
	}
}

// The record is written before the program is started, so a record that cannot be written is a
// program that is not started. Started anyway, it would be a root openvpn holding a network
// interface with its configuration -- and the private key in it -- in a directory nothing left
// on this machine names.
func TestNoOpenVPNIsStartedWhenTheRecordOfItCannotBeWritten(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections")
	}
	local := NewLocal(func(string, ...any) {})
	local.state = closedRootState(t)
	local.openvpnManagementDir = managementDir(t)
	program, args, _ := standInOpenVPN(t)
	local.openvpnBinary = func() (string, error) { return program, nil }
	pattern := filepath.Join(os.TempDir(), "app-tail-openvpn-*")
	before, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("look for connection directories: %v", err)
	}

	err = local.StartOpenVPN(t.Context(), workingRun(t))

	if err == nil {
		t.Fatal("a root openvpn was started with nothing recording it")
	}
	if !strings.Contains(err.Error(), "record") {
		t.Errorf("the reason given is %q, want it to say the record could not be written", err)
	}
	local.mu.Lock()
	running := len(local.openvpn)
	local.mu.Unlock()
	if running != 0 {
		t.Errorf("%d connections are running after a start that was refused", running)
	}
	if _, err := os.Stat(args); err == nil {
		t.Error("the program was started although the record of it could not be written")
	}
	after, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("look for connection directories: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("a start that was refused left %d connection directories behind, each holding a private key",
			len(after)-len(before))
	}
}

// The directory goes before the record does. A record naming a directory that is gone costs the
// next start one removal that finds nothing; a directory with no record left is a private key
// on the disk that nothing will ever remove.
func TestDiscardingAStartRemovesTheConfigurationAndItsRecord(t *testing.T) {
	local := NewLocal(func(string, ...any) {})
	state := testRootState(t)
	dir := filepath.Join(t.TempDir(), "app-tail-openvpn-discarded")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("make a directory standing in for a connection's own: %v", err)
	}
	if err := os.WriteFile(openvpnConfigPath(dir, "tn_disc01"), []byte("<key>secret</key>\n"), 0o600); err != nil {
		t.Fatalf("write a configuration standing in for a connection's own: %v", err)
	}
	if err := state.setProcess("tn_disc01", dir, 0); err != nil {
		t.Fatalf("record a connection: %v", err)
	}

	if err := local.discardOpenVPNStart(state, "tn_disc01", dir); err != nil {
		t.Fatalf("discard a connection whose program never started: %v", err)
	}

	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the directory holding a private key is still on the disk (%v)", err)
	}
	rec, err := state.read()
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if len(rec.OpenVPN) != 0 {
		t.Errorf("the record still holds %+v for a connection that never started", rec.OpenVPN)
	}
}

// gonePID is a process number nothing on this machine holds: a child that has been started,
// has exited, and has been waited for.
func gonePID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", "exit 0") //nolint:noctx // it exits before the call returns.
	if err := cmd.Run(); err != nil {
		t.Fatalf("run a program that exits immediately: %v", err)
	}
	return cmd.Process.Pid
}

// A number that names nothing reads as already gone rather than as a failure to signal. Read as
// a failure, every reclaim of a machine that has since rebooted -- which is every process in the
// record -- would report a stop that did not happen.
func TestASignalAimedAtANumberNothingHoldsReadsAsAlreadyGone(t *testing.T) {
	pid := gonePID(t)

	if err := askToClose(pid); !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("asking process %d to close gave %v, want it read as already gone", pid, err)
	}
	if err := killProcess(pid); !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("killing process %d gave %v, want it read as already gone", pid, err)
	}
}

// Process number zero is every process in this one's own group, so asking the kernel about it
// is asking about this test and everything running alongside it. The answer has to come from
// the guard rather than from the kernel.
func TestProcessNumberZeroIsNotAskedAbout(t *testing.T) {
	if processAlive(0) {
		t.Error("process number zero was reported as a running process")
	}
	if processAlive(-1) {
		t.Error("a negative process number, which is a whole process group, was reported as a running process")
	}
}

// Reading a process's arguments is what tells the one a previous run recorded from whatever
// holds its number now, so a read that failed is reported rather than taken as "not it". Taken
// as "not it", a machine whose process table cannot be read is one where every recorded openvpn
// is left running and dropped from the record.
func TestArgumentsThatCannotBeReadAreReported(t *testing.T) {
	if _, err := processArgs(t.Context(), gonePID(t)); err == nil {
		t.Error("the arguments of a process that is not there were read without complaint")
	}
}

// The configuration is on the disk before the program is started, so a program that never
// starts leaves a private key behind unless the failure path removes it. Nothing else on this
// machine ever will: the directory has a random name and the only record of it is the one this
// path drops.
func TestAProgramThatWillNotStartLeavesNoConfigurationBehind(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections")
	}
	local := NewLocal(func(string, ...any) {})
	local.state = testRootState(t)
	local.openvpnManagementDir = managementDir(t)
	missing := filepath.Join(t.TempDir(), "openvpn-that-is-not-there")
	local.openvpnBinary = func() (string, error) { return missing, nil }
	pattern := filepath.Join(os.TempDir(), "app-tail-openvpn-*")
	before, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("look for connection directories: %v", err)
	}

	err = local.StartOpenVPN(t.Context(), workingRun(t))

	if err == nil {
		t.Fatal("a connection whose program does not exist was reported as started")
	}
	if !strings.Contains(err.Error(), "start the openvpn program") {
		t.Errorf("the reason given is %q, want it to say the program could not be started", err)
	}
	after, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("look for connection directories: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("a start that failed left %d connection directories behind, each holding a private key",
			len(after)-len(before))
	}
	rec, err := local.state.read()
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if len(rec.OpenVPN) != 0 {
		t.Errorf("the record still holds %+v for a connection that never started", rec.OpenVPN)
	}
}

// standInOpenVPN is a program that records the arguments it was started with, one per line,
// and makes the file at its management path the way openvpn makes the socket there, then
// exits. It is enough to see what this side tells openvpn and what it cleans up after it,
// without a root openvpn or a server.
//
// It also notes whether something was already at the management path when it started, which
// is how a test sees that a leftover from a previous run was cleared first.
func standInOpenVPN(t *testing.T) (program, args, stale string) {
	t.Helper()
	dir := t.TempDir()
	program = filepath.Join(dir, "openvpn")
	args = filepath.Join(dir, "args")
	stale = filepath.Join(dir, "stale")
	script := fmt.Sprintf(`#!/bin/sh
if [ -e "$4" ]; then : > %q; fi
for a in "$@"; do printf '%%s\n' "$a"; done > %q.tmp
: > "$4"
/bin/mv %q.tmp %q
`, stale, args, args, args)
	if err := os.WriteFile(program, []byte(script), 0o755); err != nil {
		t.Fatalf("write the program standing in for openvpn: %v", err)
	}
	return program, args, stale
}

// startStandIn starts one connection on a stand-in openvpn and waits until it has recorded its
// arguments, returning them.
func startStandIn(t *testing.T, local *Local, run OpenVPNRun, program, args string) []string {
	t.Helper()
	local.openvpnBinary = func() (string, error) { return program, nil }
	if err := local.StartOpenVPN(t.Context(), run); err != nil {
		t.Fatalf("start a connection on the stand-in openvpn: %v", err)
	}
	awaitFile(t, args)
	raw, err := os.ReadFile(args)
	if err != nil {
		t.Fatalf("read the arguments the stand-in was started with: %v", err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

// awaitGone waits for a file this side is meant to remove once a connection has ended.
func awaitGone(t *testing.T, path, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("%s (%s) is still there after the connection ended", what, path)
}

// The management socket is the one way to drive a root openvpn, so where it lives is the
// helper's decision rather than the caller's: a directory belonging to root that nobody else
// can list or add to, with the socket named after the connection it belongs to. The agent
// dials the same path because both sides compute it from the connection id.
func TestTheManagementSocketLivesInARootOwnedDirectory(t *testing.T) {
	if got, want := OpenVPNManagementSocket("tn_a1b2c3"), "/var/run/app-tail/openvpn/tn_a1b2c3.sock"; got != want {
		t.Errorf("the management socket for tn_a1b2c3 is %s, want %s", got, want)
	}
	if got := filepath.Dir(OpenVPNManagementDir); got != socketDir {
		t.Errorf("the management sockets live under %s, want the helper's own %s", got, socketDir)
	}
	if longest := OpenVPNManagementSocket(strings.Repeat("a", 64)); len(longest) > maxUnixSocketPath {
		t.Errorf("the socket for the longest connection id is %d characters, past the %d a socket address holds",
			len(longest), maxUnixSocketPath)
	}

	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections")
	}
	local := NewLocal(func(string, ...any) {})
	local.state = testRootState(t)
	local.openvpnManagementDir = managementDir(t)
	program, args, stale := standInOpenVPN(t)
	run := workingRun(t)
	socket := filepath.Join(local.openvpnManagementDir, run.ID+".sock")
	if got := local.ManagementSocket(run.ID); got != socket {
		t.Errorf("this side reports the management socket for %s as %s, want %s", run.ID, got, socket)
	}

	// A leftover from a run that crashed: openvpn would refuse to bind over it.
	if err := os.MkdirAll(local.openvpnManagementDir, 0o755); err != nil {
		t.Fatalf("make the management directory: %v", err)
	}
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatalf("leave a file where the socket goes: %v", err)
	}

	startStandIn(t, local, run, program, args)

	info, err := os.Lstat(local.openvpnManagementDir)
	if err != nil {
		t.Fatalf("read the management directory: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o711 {
		t.Errorf("the management directory is mode %#o, want 0711 so only its owner can list or add to it", mode)
	}
	if owner, _, err := ownerOf(info, local.openvpnManagementDir); err != nil || int(owner) != os.Geteuid() {
		t.Errorf("the management directory belongs to %d (%v), want this side's own account %d", owner, err, os.Geteuid())
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("openvpn was started with the previous run's socket still in its place")
	}
	// The socket is the helper's to remove once openvpn has gone: openvpn leaves it behind
	// when it exits on its own.
	awaitGone(t, socket, "the management socket")

	// A directory somebody swapped for a link is not one this side creates sockets in.
	elsewhere := t.TempDir()
	linked := filepath.Join(filepath.Dir(managementDir(t)), "linked")
	if err := os.Symlink(elsewhere, linked); err != nil {
		t.Fatalf("make the link: %v", err)
	}
	refused := NewLocal(func(string, ...any) {})
	refused.state = testRootState(t)
	refused.openvpnManagementDir = linked
	refusedProgram, refusedArgs, _ := standInOpenVPN(t)
	refused.openvpnBinary = func() (string, error) { return refusedProgram, nil }
	if err := refused.StartOpenVPN(t.Context(), run); err == nil {
		t.Error("a management directory that is a symbolic link was accepted")
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(refusedArgs); err == nil {
		t.Error("openvpn was started with its management socket in a directory reached through a link")
	}
	rec, err := refused.state.read()
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if len(rec.OpenVPN) != 0 {
		t.Errorf("the record still holds %+v for a connection that never started", rec.OpenVPN)
	}
}

// openvpn creates the socket and listens; the agent connects. What keeps another account on
// this machine from connecting first and driving a root process is openvpn itself, told which
// account may: per openvpn(8), "--management-client-user u: When the management interface is
// listening on a unix domain socket, only allow connections from user u." Without it the man
// page is explicit that the socket "may be connected to by any process".
func TestOpenVPNIsToldWhichAccountMayManageIt(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections")
	}
	me, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatalf("look up the account running the suite: %v", err)
	}
	local := NewLocal(func(string, ...any) {})
	local.state = testRootState(t)
	local.openvpnManagementDir = managementDir(t)
	program, args, _ := standInOpenVPN(t)
	run := workingRun(t)

	got := startStandIn(t, local, run, program, args)

	want := []string{
		"--config", "",
		"--management", filepath.Join(local.openvpnManagementDir, run.ID+".sock"), "unix",
		"--management-client-user", me.Username,
		"--management-signal",
	}
	if len(got) != len(want) {
		t.Fatalf("openvpn was started with %q, want %q", got, want)
	}
	for i := range want {
		if i == 1 {
			if !strings.HasSuffix(got[i], "/"+run.ID+".conf") {
				t.Errorf("the configuration openvpn was given is %s, want this connection's own", got[i])
			}
			continue
		}
		if got[i] != want[i] {
			t.Errorf("argument %d is %q, want %q (all of them: %q)", i, got[i], want[i], got)
		}
	}
	if slices.Contains(got, "--management-client") {
		t.Errorf("openvpn was told to connect out to a socket the caller names: %q", got)
	}

	// An account with no name is one openvpn cannot be told about, so nothing is started.
	unnamed := NewLocal(func(string, ...any) {})
	unnamed.state = testRootState(t)
	unnamed.openvpnManagementDir = managementDir(t)
	unnamedProgram, unnamedArgs, _ := standInOpenVPN(t)
	unnamed.openvpnBinary = func() (string, error) { return unnamedProgram, nil }
	t.Setenv(ownerEnv, "4242")
	if _, err := user.LookupId("4242"); err == nil {
		t.Skip("this machine has an account numbered 4242, so the case needs another number")
	}
	if err := unnamed.StartOpenVPN(t.Context(), run); err == nil {
		t.Error("a connection was started for an account openvpn cannot be told the name of")
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(unnamedArgs); err == nil {
		t.Error("openvpn was started with nobody named as the account that may manage it")
	}
}
