// SPDX-License-Identifier: MIT

package app

// Opening encrypted connections, from the settings that ask for it down to the file the root is
// written to. Most of what is under test here is what does not happen: the agreement gate, the
// root that is generated once and never a second time, and the file that is refused rather than
// replaced.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fileown/fileowntest"
	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/telemetry"
	"github.com/sellitus/app-tail/internal/tlsmint"
)

// intercepting is the settings of a machine that has asked for connections to be opened and
// recorded that it understands what that means.
func intercepting(s *config.Settings) {
	inspecting(s)
	s.IPSIntercept = config.IPSInterceptOnly
	s.IPSInterceptAgreed = true
	s.IPSInterceptOnly = []string{"inside.example", "10.20.0.0/24"}
}

// The default. Nothing is opened, nothing is generated, and no file appears in the state
// directory: a machine that never asked for this must not be holding a key that can sign a
// certificate for any name it trusts.
func TestInterceptionIsOffAndGeneratesNothingUntilItIsAskedFor(t *testing.T) {
	api := newIPSAPI(t, inspecting)

	runner := api.a.currentIPS()
	if runner.authority.Load() != nil {
		t.Error("a root was generated for a machine that never asked for one")
	}
	if runner.scope.Load().On() {
		t.Error("connections are being opened on a machine that never asked for it")
	}

	certPath, keyPath := interceptPaths(api.a.stateDir())
	for _, path := range []string{certPath, keyPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("stat %s = %v, want the file never to have been written", path, err)
		}
	}

	view := api.View()
	if view.Intercept.Mode != config.IPSInterceptOff || view.Intercept.Running {
		t.Errorf("intercept view = %+v, want it off and running nothing", view.Intercept)
	}
}

// The agreement gate. A mode on its own opens nothing: the setting recording that the person
// using this machine read what interception does is separate precisely so that a restored
// settings file or an upgrade cannot arrive with it already on.
func TestAModeWithoutTheAgreementOpensNothing(t *testing.T) {
	api := newIPSAPI(t, func(s *config.Settings) {
		intercepting(s)
		s.IPSInterceptAgreed = false
	})

	runner := api.a.currentIPS()
	if runner.authority.Load() != nil {
		t.Error("a root was generated for a mode nobody agreed to")
	}
	if runner.scope.Load().On() {
		t.Error("connections are being opened without the agreement")
	}
	if certPath, _ := interceptPaths(api.a.stateDir()); fileExists(certPath) {
		t.Error("a certificate was written for a mode nobody agreed to")
	}

	view := api.View()
	if view.Intercept.Agreed || view.Intercept.Running {
		t.Errorf("intercept view = %+v, want it to say the agreement is missing", view.Intercept)
	}
}

// Asked for, and the root is generated and written down: the certificate readable, the key
// readable by nobody else. The key's permissions are most of the security of this feature on a
// shared machine.
func TestAskingForItGeneratesARootAndWritesItWhereItCanBeInstalled(t *testing.T) {
	api := newIPSAPI(t, intercepting)

	runner := api.a.currentIPS()
	authority := runner.authority.Load()
	if authority == nil {
		t.Fatal("no root was generated for a machine that asked for one")
	}
	if !runner.scope.Load().On() {
		t.Fatal("the root was generated and nothing is being opened with it")
	}

	certPath, keyPath := interceptPaths(api.a.stateDir())
	// The key can sign a certificate for any name this machine trusts.
	fileowntest.AssertOwnerOnly(t, keyPath, config.FileMode)
	cert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read the certificate: %v", err)
	}
	if !strings.Contains(string(cert), "BEGIN CERTIFICATE") {
		t.Errorf("the certificate file holds %q, want a certificate to install", cert)
	}

	view := api.View()
	if !view.Intercept.Running {
		t.Errorf("intercept view = %+v, want it running", view.Intercept)
	}
	if view.Intercept.Fingerprint != authority.Fingerprint() {
		t.Errorf("view fingerprint = %q, want the root's own %q",
			view.Intercept.Fingerprint, authority.Fingerprint())
	}
	if view.Intercept.Destinations != 2 {
		t.Errorf("view names %d destinations, want the two that were listed", view.Intercept.Destinations)
	}
	if view.Intercept.CertPath != certPath {
		t.Errorf("view cert path = %q, want %q", view.Intercept.CertPath, certPath)
	}
	// The card cannot ask somebody to install something and then not say how.
	if view.Intercept.Install == "" || view.Intercept.Remove == "" {
		t.Errorf("intercept view = %+v, want the commands to install it and to remove it", view.Intercept)
	}
}

// The root is generated once. A second one would be a certificate this machine's trust store has
// never heard of, and the first sign of it would be every opened connection failing at once,
// with the root that was installed still sitting in the trust store.
func TestTheRootIsGeneratedOnceAndReadBackAfterThat(t *testing.T) {
	api := newIPSAPI(t, intercepting)
	first := api.a.currentIPS().authority.Load()
	if first == nil {
		t.Fatal("no root was generated")
	}
	certPath, keyPath := interceptPaths(api.a.stateDir())
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read the key: %v", err)
	}

	api.a.reconcileIPS()
	if again := api.a.currentIPS().authority.Load(); again != first {
		t.Error("a reconcile replaced a root that was already in memory")
	}

	// Dropping the root and reconciling again is what a restart looks like from here: nothing in
	// memory, both files on disk.
	api.a.currentIPS().stopIntercepting()
	api.a.reconcileIPS()
	reloaded := api.a.currentIPS().authority.Load()
	if reloaded == nil {
		t.Fatal("the root was not read back from the files it was written to")
	}
	if reloaded.Fingerprint() != first.Fingerprint() {
		t.Errorf("the root read back is %s, want the one that was written, %s",
			reloaded.Fingerprint(), first.Fingerprint())
	}
	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read the key again: %v", err)
	}
	if string(after) != string(before) {
		t.Error("the key file was rewritten by a pass that should have read it")
	}
	if !fileExists(certPath) {
		t.Error("the certificate went away")
	}
}

// Switched off, the key leaves memory. Off has to mean this process is not holding something
// that can sign a certificate for any name the machine trusts, rather than only that nothing is
// currently asking it to.
func TestSwitchingItOffTakesTheKeyOutOfMemoryAndLeavesTheFiles(t *testing.T) {
	api := newIPSAPI(t, intercepting)
	if api.a.currentIPS().authority.Load() == nil {
		t.Fatal("no root was generated")
	}

	if _, err := api.a.store.Update(func(c *config.Config) error {
		c.Settings.IPSIntercept = config.IPSInterceptOff
		return nil
	}); err != nil {
		t.Fatalf("switch interception off: %v", err)
	}
	api.a.reconcileIPS()

	runner := api.a.currentIPS()
	if runner.authority.Load() != nil {
		t.Error("the key is still in memory after interception was switched off")
	}
	if runner.scope.Load().On() {
		t.Error("connections are still being opened after interception was switched off")
	}
	// The files stay. The certificate in them is the one that may be installed on this machine,
	// and deleting it would leave a root in the trust store with nothing left to identify it by.
	certPath, keyPath := interceptPaths(api.a.stateDir())
	if !fileExists(certPath) || !fileExists(keyPath) {
		t.Error("switching interception off deleted the root that may be installed")
	}
}

// The other mode, left empty. An empty list there cannot mean "open everything and leave nothing
// alone": that is a machine where the app store, the system updater and every pinned app stop
// working at once, so the list app-tail ships applies instead.
func TestOpeningEverythingWithNoListOfItsOwnUsesTheOneAppTailShips(t *testing.T) {
	api := newIPSAPI(t, func(s *config.Settings) {
		inspecting(s)
		s.IPSIntercept = config.IPSInterceptExcept
		s.IPSInterceptAgreed = true
	})

	scope := api.a.currentIPS().scope.Load()
	if !scope.On() {
		t.Fatal("nothing is being opened in the mode that opens everything")
	}
	shipped, err := tlsmint.CompileScope(tlsmint.ModeExcept, tlsmint.DefaultBypass)
	if err != nil {
		t.Fatalf("compile the shipped list: %v", err)
	}
	if scope.Count() != shipped.Count() {
		t.Errorf("the list in force holds %d destinations, want the %d app-tail ships",
			scope.Count(), shipped.Count())
	}
	// The point of the shipped list, checked at one entry of it rather than in the abstract.
	if scope.Intercepts("swscan.apple.com", netip.Addr{}) {
		t.Error("a destination under the shipped list is being opened")
	}
	if !scope.Intercepts("anything.example", netip.Addr{}) {
		t.Error("a destination nothing excuses is not being opened in the mode that opens everything")
	}

	view := api.View()
	if !view.Intercept.Shipped {
		t.Errorf("intercept view = %+v, want it to say the list is the one app-tail ships", view.Intercept)
	}
}

// A root that cannot be read is refused rather than replaced. Generating over it would leave the
// root that was installed sitting in the trust store, unaccounted for, while a new one nobody
// has seen starts signing.
func TestARootThatCannotBeReadIsRefusedRatherThanReplaced(t *testing.T) {
	api := newIPSAPI(t, intercepting)
	certPath, keyPath := interceptPaths(api.a.stateDir())
	if err := os.WriteFile(keyPath, []byte("this is not a key\n"), config.FileMode); err != nil {
		t.Fatalf("damage the key: %v", err)
	}
	api.a.currentIPS().stopIntercepting()

	api.a.reconcileIPS()

	runner := api.a.currentIPS()
	if runner.authority.Load() != nil {
		t.Error("a root was used despite its key being unreadable")
	}
	if runner.scope.Load().On() {
		t.Error("connections are being opened with no root to sign with")
	}
	held, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read the key: %v", err)
	}
	if string(held) != "this is not a key\n" {
		t.Error("the unreadable key was overwritten rather than reported")
	}
	if !fileExists(certPath) {
		t.Error("the certificate was deleted by a pass that could not read the key")
	}
}

// One of the two files missing is the same refusal for the same reason: something happened to
// these files that app-tail did not do, and writing over them is the one response that could
// make it worse.
func TestARootMissingHalfOfItselfIsRefusedRatherThanReplaced(t *testing.T) {
	api := newIPSAPI(t, intercepting)
	_, keyPath := interceptPaths(api.a.stateDir())
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("remove the key: %v", err)
	}
	api.a.currentIPS().stopIntercepting()

	api.a.reconcileIPS()

	if api.a.currentIPS().authority.Load() != nil {
		t.Error("a root was generated over a certificate that was still there")
	}
	if fileExists(keyPath) {
		t.Error("a new key was written beside a certificate it does not go with")
	}
}

// The seam every carried connection goes through. With nothing being opened it answers with the
// two connections it was handed and reads nothing at all, which is the state every machine that
// never turns interception on stays in for every byte app-tail carries.
func TestTheSeamCarriesEveryConnectionUntouchedWhileNothingIsOpened(t *testing.T) {
	api := newIPSAPI(t, inspecting)
	client, upstream := net.Pipe()
	t.Cleanup(func() { client.Close(); upstream.Close() })

	held, opened, err := api.a.currentIPS().Open(context.Background(),
		inspect.Flow{Where: "the network interface", Protocol: "tcp"}, client, upstream)

	if err != nil {
		t.Fatalf("Open with nothing being opened: %v", err)
	}
	if held != client || opened != upstream {
		t.Error("the seam wrapped a connection nothing was going to open")
	}
}

// A pause puts traffic back the way it was, and that has to include this. A pause is asked for
// because something is broken right now, and interception is the part of inspection most able to
// have broken it.
func TestAPauseStopsConnectionsBeingOpened(t *testing.T) {
	api := newIPSAPI(t, intercepting)
	api.a.currentIPS().pause(time.Minute)

	client, upstream := net.Pipe()
	t.Cleanup(func() { client.Close(); upstream.Close() })

	held, opened, err := api.a.currentIPS().Open(context.Background(),
		inspect.Flow{Name: "inside.example", Where: "the proxy", Protocol: "tcp"}, client, upstream)

	if err != nil {
		t.Fatalf("Open while paused: %v", err)
	}
	if held != client || opened != upstream {
		t.Error("a connection was opened while inspection was paused")
	}
}

// The card says this out loud. A machine reading its own encrypted traffic is a state somebody
// should see from the dashboard without going looking for it, and on a machine that has not
// installed the root it is also the state where every opened connection fails.
func TestOpeningConnectionsIsReportedAsDegradedWhileItIsOn(t *testing.T) {
	api := newIPSAPI(t, intercepting)

	view := api.View()

	if !view.Capability.Degraded {
		t.Error("a machine opening its own encrypted connections did not say so on the card")
	}
	if !strings.Contains(view.Capability.Reason, "certificate") {
		t.Errorf("capability reason = %q, want it to name the certificate being presented",
			view.Capability.Reason)
	}
}

// fileExists reports whether a path is there, for the cases that are about a file appearing or
// staying rather than about what is in it.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// openingTo is a runner that opens connections to one name, with the log in the test's
// hands: what a failure to open says is the whole of what the user gets to act on.
func openingTo(t *testing.T, name string) (*ipsRunner, *[]recordedIPSEvent) {
	t.Helper()
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, nil)
	scope, limits, err := compileIntercept(interceptTarget{on: true, mode: tlsmint.ModeOnly, list: []string{name}})
	if err != nil {
		t.Fatalf("compileIntercept: %v", err)
	}
	authority, err := tlsmint.NewAuthority(at, limits)
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	runner.authority.Store(authority)
	runner.scope.Store(scope)
	return runner, events
}

// A connection that could not be opened is stopped, counted, and written to the log against
// the name the program asked for, with the reason kept apart from the failure a user can act
// on: this one is this machine's problem, not a certificate to think about.
func TestAConnectionThatCouldNotBeOpenedIsStoppedAndSaysWhy(t *testing.T) {
	runner, events := openingTo(t, "inside.example")
	client, upstream := net.Pipe()
	t.Cleanup(func() { upstream.Close() })
	client.Close()

	held, opened, err := runner.Open(context.Background(),
		inspect.Flow{Name: "inside.example", Where: "the proxy", Protocol: "tcp"}, client, upstream)

	if err == nil {
		t.Fatal("a connection whose opening bytes could not be read was opened anyway")
	}
	if held != nil || opened != nil {
		t.Error("a pair came back alongside the failure, which is a pair somebody has to decide whether to trust")
	}
	if got := runner.interceptFailures.Load(); got != 1 {
		t.Errorf("interceptFailures = %d, want 1", got)
	}
	if len(*events) != 1 || (*events)[0].code != telemetry.CodeIPSInterceptFailed {
		t.Fatalf("events = %+v, want one %s", *events, telemetry.CodeIPSInterceptFailed)
	}
	event := (*events)[0]
	if !strings.Contains(event.message, "inside.example") {
		t.Errorf("message = %q, want it to name the destination", event.message)
	}
	if event.fields["where"] != "the proxy" || event.fields["reason"] != "the connection could not be opened" {
		t.Errorf("fields = %v, want where the connection came from and the general reason", event.fields)
	}
}

// The failure a user can act on is the one where the real server did not verify: a
// destination to add to the list left alone, or somebody really interfering. The log names
// that reason apart from every other failure, so the user is not sent looking at this
// machine for a problem that is on the wire.
func TestAServerThatDidNotVerifyIsReportedAsThatAndNothingElse(t *testing.T) {
	runner, events := openingTo(t, "inside.example")
	limits, err := tlsmint.ConstraintsFor(tlsmint.ModeOnly, []string{"inside.example"})
	if err != nil {
		t.Fatalf("ConstraintsFor: %v", err)
	}
	impostor, err := tlsmint.NewAuthority(time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC), limits)
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	served, err := impostor.Leaf("inside.example", time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}

	clientEnd, client := net.Pipe()
	upstream, serverEnd := net.Pipe()
	t.Cleanup(func() { clientEnd.Close(); client.Close(); upstream.Close(); serverEnd.Close() })
	// The two far ends drive their own handshakes. Both are expected to fail: the server is
	// refused by the interceptor, and the client gets the alert that refusal turns into.
	go tls.Server(serverEnd, &tls.Config{Certificates: []tls.Certificate{*served}, MinVersion: tls.VersionTLS12}).Handshake()
	go tls.Client(clientEnd, &tls.Config{ServerName: "inside.example", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}).Handshake()

	_, _, err = runner.Open(context.Background(),
		inspect.Flow{Addr: netip.MustParseAddr("10.20.0.7"), Where: "the network interface", Protocol: "tcp"}, client, upstream)

	if !errors.Is(err, tlsmint.ErrUpstreamRefused) {
		t.Fatalf("Open = %v, want %v", err, tlsmint.ErrUpstreamRefused)
	}
	if len(*events) != 1 || (*events)[0].code != telemetry.CodeIPSInterceptFailed {
		t.Fatalf("events = %+v, want one %s", *events, telemetry.CodeIPSInterceptFailed)
	}
	event := (*events)[0]
	if event.fields["reason"] != "the server's certificate did not verify" {
		t.Errorf("reason = %q, want the certificate named as what failed", event.fields["reason"])
	}
	if !strings.Contains(event.message, "10.20.0.7") {
		t.Errorf("message = %q, want the address named where no program asked for a name", event.message)
	}
}

// The name a failure is reported against is the one a person would recognise: what a program
// asked for first, the address it dialled second, and an honest "could not name" when the
// flow carried neither, since a made-up name sends people looking in the wrong place.
func TestAFailureIsReportedAgainstTheNameAPersonWouldRecognise(t *testing.T) {
	cases := []struct {
		flow inspect.Flow
		want string
	}{
		{inspect.Flow{Name: "inside.example", Addr: netip.MustParseAddr("10.20.0.7")}, "inside.example"},
		{inspect.Flow{Addr: netip.MustParseAddr("::ffff:10.20.0.7")}, "10.20.0.7"},
		{inspect.Flow{}, "a destination app-tail could not name"},
	}
	for _, c := range cases {
		if got := interceptedName(c.flow); got != c.want {
			t.Errorf("interceptedName(%+v) = %q, want %q", c.flow, got, c.want)
		}
	}
}

// A root past the end of its validity signs certificates no client accepts, so a root that
// old is refused rather than used, and refused rather than replaced: it is the one in the
// trust store, and a new one signing beside it would fail every connection with nothing on
// the card saying why. The refusal names what to do, because the doing is the user's.
func TestARootThatHasExpiredIsRefusedAndTheRemedyIsNamed(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	api := newIPSAPIAt(t, &now, func(s *config.Settings) {
		intercepting(s)
		s.TelemetryEnabled = true
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go api.a.telemetry.Run(ctx)
	certPath, keyPath := interceptPaths(api.a.stateDir())
	before, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read the root: %v", err)
	}
	api.a.currentIPS().stopIntercepting()

	now = now.Add(4 * 365 * 24 * time.Hour)
	api.a.reconcileIPS()

	runner := api.a.currentIPS()
	if runner.authority.Load() != nil {
		t.Error("an expired root is being used to sign with")
	}
	if runner.scope.Load().On() {
		t.Error("connections are being opened with a root no client accepts")
	}
	if after, err := os.ReadFile(certPath); err != nil || !bytes.Equal(before, after) {
		t.Error("the expired root was replaced rather than reported")
	}
	if view := api.View(); view.Intercept.Running {
		t.Error("the card says interception is running on a root no client accepts")
	}
	var refused string
	waitFor(t, 5*time.Second, "the refusal to reach the log", func() bool {
		page, err := api.a.TelemetryAPI().Events(context.Background(), telemetry.EventQuery{})
		if err != nil {
			t.Fatalf("read the event log: %v", err)
		}
		for _, e := range page.Events {
			if e.Code == telemetry.CodeIPSFailed {
				refused = e.Message
			}
		}
		return refused != ""
	})
	for _, want := range []string{"expired", "trust store", keyPath} {
		if !strings.Contains(refused, want) {
			t.Errorf("the event says %q, want it to mention %q", refused, want)
		}
	}
}

// "Only the ones I name" with nothing named would open nothing, and the setting that asks for it
// is refused rather than read as off: the card says why. No root is generated for it, because a
// root is limited to the list it was made for and this list names nothing to limit it to; the
// first destination named gets one, and that one is kept from then on.
func TestOpeningOnlyWhatIsNamedWithNothingNamedOpensNothingAndSaysWhy(t *testing.T) {
	api := newIPSAPI(t, func(s *config.Settings) {
		intercepting(s)
		s.IPSInterceptOnly = nil
		s.TelemetryEnabled = true
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go api.a.telemetry.Run(ctx)

	runner := api.a.currentIPS()
	if runner.authority.Load() != nil {
		t.Error("a root is held in memory while nothing can be opened with it")
	}
	if runner.scope.Load().On() {
		t.Error("connections are being opened for a list that names nothing")
	}
	if view := api.View(); view.Intercept.Running || view.Intercept.Destinations != 0 {
		t.Errorf("intercept view = %+v, want it running nothing", view.Intercept)
	}
	certPath, _ := interceptPaths(api.a.stateDir())
	if fileExists(certPath) {
		t.Error("a root was generated for a list that names nothing it could be limited to")
	}
	var refused string
	waitFor(t, 5*time.Second, "the refusal to reach the log", func() bool {
		page, err := api.a.TelemetryAPI().Events(context.Background(), telemetry.EventQuery{})
		if err != nil {
			t.Fatalf("read the event log: %v", err)
		}
		for _, e := range page.Events {
			if e.Code == telemetry.CodeIPSFailed {
				refused = e.Message
			}
		}
		return refused != ""
	})
	if !strings.Contains(refused, "nothing would be") {
		t.Errorf("the event says %q, want it to say nothing would be opened", refused)
	}

	// Named afterwards, a root is made for what was named, and reconciling again keeps it.
	if _, err := api.a.store.Update(func(c *config.Config) error {
		c.Settings.IPSInterceptOnly = []string{"inside.example"}
		return nil
	}); err != nil {
		t.Fatalf("name a destination: %v", err)
	}
	api.a.reconcileIPS()
	authority := api.a.currentIPS().authority.Load()
	if !api.a.currentIPS().scope.Load().On() || authority == nil {
		t.Fatal("naming a destination did not start opening connections")
	}
	if !authority.Covers("inside.example") || authority.Covers("elsewhere.example") {
		t.Errorf("the root made for inside.example signs for %s", authority.Constraints().Describe())
	}
	before, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read the root: %v", err)
	}
	api.a.reconcileIPS()
	if after, err := os.ReadFile(certPath); err != nil || !bytes.Equal(before, after) {
		t.Error("the root was generated again for the same machine")
	}
}

// The root's files are written through a temporary file beside them. When the last step fails,
// the temporary file is removed rather than left as a second copy of the key lying beside the
// path it was meant to become, and the failure names the file it could not put in place.
func TestAFileThatCannotBePutInPlaceLeavesNoCopyOfItselfBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.key")
	// A non-empty directory where the file was going: the rename over it fails on every platform.
	if err := os.MkdirAll(filepath.Join(path, "occupied"), 0o755); err != nil {
		t.Fatalf("occupy the path: %v", err)
	}

	err := writeInterceptFile(path, []byte("secret"), config.FileMode, true)

	if err == nil || !strings.Contains(err.Error(), "put "+path+" in place") {
		t.Fatalf("writeInterceptFile = %v, want the failure to name the file it could not put in place", err)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("read the directory: %v", readErr)
	}
	for _, entry := range entries {
		if entry.Name() != "ca.key" {
			t.Errorf("%s was left behind beside the file it was going to become", entry.Name())
		}
	}
	if _, statErr := os.Stat(filepath.Join(path, "occupied")); statErr != nil {
		t.Errorf("what was already at the path was disturbed: %v", statErr)
	}

	// The success path leaves exactly the file, with what was written in it.
	good := filepath.Join(dir, "ca.crt")
	if err := writeInterceptFile(good, []byte("public"), 0o644, false); err != nil {
		t.Fatalf("writeInterceptFile: %v", err)
	}
	entries, readErr = os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("read the directory: %v", readErr)
	}
	if len(entries) != 2 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Errorf("the directory holds %v, want only the two files", names)
	}
	if held, err := os.ReadFile(good); err != nil || string(held) != "public" {
		t.Errorf("the file holds %q (%v), want what was written", held, err)
	}
}

// outgrownEvents counts the events saying the list reached past the root. The hub writes events
// in the order they were recorded, so once a marker recorded after the reconciles is readable
// every event before it is too.
func outgrownEvents(t *testing.T, api ipsAPI) int {
	t.Helper()
	const marker = "every event before this one has been written"
	api.a.recordEvent(telemetry.CodeIPSCompiled, marker, nil)
	var count int
	waitFor(t, 5*time.Second, "the marker to reach the log", func() bool {
		page, err := api.a.TelemetryAPI().Events(context.Background(), telemetry.EventQuery{})
		if err != nil {
			t.Fatalf("read the event log: %v", err)
		}
		count = 0
		seen := false
		for _, e := range page.Events {
			if e.Message == rootOutgrownSentence {
				count++
			}
			seen = seen || e.Message == marker
		}
		return seen
	})
	return count
}

// setIntercept changes the interception settings and runs the reconcile that follows a save.
func setIntercept(t *testing.T, api ipsAPI, change func(*config.Settings)) {
	t.Helper()
	if _, err := api.a.store.Update(func(c *config.Config) error {
		change(&c.Settings)
		return nil
	}); err != nil {
		t.Fatalf("change the settings: %v", err)
	}
	api.a.reconcileIPS()
}

// A list grown past what the root was made for keeps the root, because it is the one in the
// trust store, and says plainly on the card that a new root has to be installed. The event says
// so once per change, not on every reconcile, and narrowing the list back clears it.
func TestAListGrownPastTheRootSaysANewRootIsNeededAndKeepsTheOldOne(t *testing.T) {
	api := newIPSAPI(t, func(s *config.Settings) {
		intercepting(s)
		s.TelemetryEnabled = true
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go api.a.telemetry.Run(ctx)
	before := api.a.currentIPS().authority.Load().Fingerprint()
	if view := api.View(); view.Intercept.NeedsNewRoot {
		t.Fatalf("intercept view = %+v, want the root made for this list to cover it", view.Intercept)
	}

	setIntercept(t, api, func(s *config.Settings) {
		s.IPSInterceptOnly = append(s.IPSInterceptOnly, "outside.example")
	})
	api.a.reconcileIPS()

	view := api.View().Intercept
	if !view.NeedsNewRoot || view.NewRootReason != rootOutgrownSentence {
		t.Errorf("intercept view = %+v, want it to say a new root is needed", view)
	}
	if !strings.Contains(view.NewRootReason, "app-tail ips remove-root") {
		t.Errorf("reason = %q, want it to name the command that removes the root", view.NewRootReason)
	}
	if view.Fingerprint != before || !view.Running {
		t.Errorf("intercept view = %+v, want the installed root %s kept and still in use", view, before)
	}
	if got := outgrownEvents(t, api); got != 1 {
		t.Errorf("the log says the list outgrew the root %d times over two reconciles, want once", got)
	}

	setIntercept(t, api, func(s *config.Settings) { s.IPSInterceptOnly = []string{"inside.example"} })
	if view := api.View().Intercept; view.NeedsNewRoot || view.NewRootReason != "" {
		t.Errorf("intercept view = %+v, want a list inside the root to need nothing new", view)
	}
}

// The card warns from thirty days before the root's end, and says differently once it has
// passed it. It never replaces the root on its own: the old one is in the trust store.
func TestTheCardWarnsThirtyDaysBeforeTheRootExpiresAndAgainOnceItHas(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	api := newIPSAPIAt(t, &now, intercepting)
	authority := api.a.currentIPS().authority.Load()
	end := authority.NotAfter()

	now = end.Add(-31 * 24 * time.Hour)
	if view := api.View().Intercept; view.ExpiresSoon || view.Expired || view.ExpiryWarning != "" {
		t.Errorf("31 days out: intercept view = %+v, want no warning yet", view)
	}

	now = end.Add(-30 * 24 * time.Hour)
	view := api.View().Intercept
	if !view.ExpiresSoon || view.Expired {
		t.Errorf("30 days out: intercept view = %+v, want it expiring soon", view)
	}
	for _, want := range []string{"expires on " + end.UTC().Format(time.DateOnly), "in 30 days", "app-tail ips remove-root"} {
		if !strings.Contains(view.ExpiryWarning, want) {
			t.Errorf("30 days out: warning = %q, want it to say %q", view.ExpiryWarning, want)
		}
	}

	now = end.Add(-time.Hour)
	if view := api.View().Intercept; !strings.Contains(view.ExpiryWarning, "in 1 day") {
		t.Errorf("an hour out: warning = %q, want the last day read as one day", view.ExpiryWarning)
	}

	now = end
	view = api.View().Intercept
	if view.ExpiresSoon || !view.Expired || !strings.Contains(view.ExpiryWarning, "expired on") {
		t.Errorf("at its end: intercept view = %+v, want it reported as expired", view)
	}
	if view.Fingerprint != authority.Fingerprint() {
		t.Errorf("fingerprint = %s, want the root left as it was, %s", view.Fingerprint, authority.Fingerprint())
	}
}

// Off, the key is out of memory but the root is still in the trust store, so the card goes on
// showing which root it is and what it can sign for, read from the certificate alone.
func TestTheCardShowsTheRootFromItsFileWhileInterceptionIsOff(t *testing.T) {
	api := newIPSAPI(t, intercepting)
	fingerprint := api.a.currentIPS().authority.Load().Fingerprint()

	setIntercept(t, api, func(s *config.Settings) { s.IPSIntercept = config.IPSInterceptOff })

	view := api.View().Intercept
	if view.On || view.Running || api.a.currentIPS().authority.Load() != nil {
		t.Fatalf("intercept view = %+v, want interception off with no key held", view)
	}
	if view.Fingerprint != fingerprint {
		t.Errorf("fingerprint = %q, want the root still on disk, %q", view.Fingerprint, fingerprint)
	}
	if view.RootScope != "only inside.example and 10.20.0.0/24" {
		t.Errorf("root scope = %q, want the two destinations it was made for", view.RootScope)
	}
}

// Removing the root while interception is on would be undone by the next reconcile, which would
// generate a new one, so it is refused and the files are left alone.
func TestRemovingTheRootIsRefusedWhileInterceptionIsOn(t *testing.T) {
	api := newIPSAPI(t, intercepting)

	err := api.RemoveInterceptRoot()

	var invalid *config.ValidationError
	if !errors.As(err, &invalid) || invalid.Field != "ips.intercept" {
		t.Fatalf("RemoveInterceptRoot = %v, want a refusal naming ips.intercept", err)
	}
	certPath, keyPath := interceptPaths(api.a.stateDir())
	if !fileExists(certPath) || !fileExists(keyPath) {
		t.Error("a refused removal deleted the root's files")
	}
}

// Off, removal deletes the key and the certificate, the card stops showing a root, and switching
// back on makes a new one rather than finding the old one. Removing again finds nothing to do.
func TestRemovingTheRootDeletesBothFilesAndTheNextOneIsNew(t *testing.T) {
	api := newIPSAPI(t, intercepting)
	old := api.a.currentIPS().authority.Load().Fingerprint()
	setIntercept(t, api, func(s *config.Settings) { s.IPSIntercept = config.IPSInterceptOff })

	if err := api.RemoveInterceptRoot(); err != nil {
		t.Fatalf("RemoveInterceptRoot: %v", err)
	}

	certPath, keyPath := interceptPaths(api.a.stateDir())
	for _, path := range []string{certPath, keyPath} {
		if fileExists(path) {
			t.Errorf("%s is still there after the root was removed", path)
		}
	}
	if view := api.View().Intercept; view.Fingerprint != "" || view.RootError != "" {
		t.Errorf("intercept view = %+v, want no root shown", view)
	}
	if err := api.RemoveInterceptRoot(); err != nil {
		t.Errorf("removing a root that is already gone = %v, want nothing to do", err)
	}

	setIntercept(t, api, func(s *config.Settings) { s.IPSIntercept = config.IPSInterceptOnly })
	fresh := api.a.currentIPS().authority.Load()
	if fresh == nil || fresh.Fingerprint() == old {
		t.Errorf("switching back on after removal holds %v, want a new root", fresh)
	}
}

// A root made before roots were limited still works, since it is the one installed, but the card
// says it can sign for any site and has to be replaced.
func TestARootMadeBeforeRootsWereLimitedIsFlaggedForReplacement(t *testing.T) {
	api := newUnreconciledIPSAPI(t, nil, intercepting)
	certPath, keyPath := interceptPaths(api.a.stateDir())
	writeUnlimitedRoot(t, certPath, keyPath)

	api.a.reconcileIPS()

	view := api.View().Intercept
	if !view.Running {
		t.Fatalf("intercept view = %+v, want the installed root still used", view)
	}
	if !view.NeedsNewRoot || view.NewRootReason != rootUnlimitedSentence {
		t.Errorf("intercept view = %+v, want it to say the root has to be replaced", view)
	}
	if !strings.Contains(view.RootScope, "any site") {
		t.Errorf("root scope = %q, want it to say the root can sign for any site", view.RootScope)
	}
}

// writeUnlimitedRoot writes the root an earlier version generated: a CA with no name constraints.
func writeUnlimitedRoot(t *testing.T, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: tlsmint.Subject},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create the root: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal the key: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		t.Fatalf("make the directory: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write the key: %v", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write the root: %v", err)
	}
}

// Opening encrypted connections is a change to the machine an administrator approves, like the
// routes and resolvers the helper holds to the approvals file. Until they do, nothing is opened
// and no root is made, the card says why, and the approval joins the list one prompt answers.
func TestInterceptionNobodyApprovedOpensNothingAndWaitsForAnAdministrator(t *testing.T) {
	api := newIPSAPIWith(t, func() (grants.Document, error) { return grants.None(), nil }, intercepting)

	runner := api.a.currentIPS()
	if runner.scope.Load().On() || runner.authority.Load() != nil {
		t.Fatal("interception ran on a machine where nobody approved it")
	}
	certPath, _ := interceptPaths(api.a.stateDir())
	if _, err := os.Stat(certPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a root was written for interception nobody approved: %v", err)
	}
	view := api.View().Intercept
	if view.Running || view.AwaitingApproval == "" {
		t.Errorf("intercept view = %+v, want it not running and saying it waits for an approval", view)
	}
	if !view.On {
		t.Error("the view stopped saying the settings ask for interception, which is what removing the root is refused on")
	}
	waiting := api.a.approvalsView()
	if waiting == nil || len(waiting.Needs) != 1 || waiting.Needs[0].Kind != grants.KindTLSInterception {
		t.Fatalf("waiting = %+v, want the interception approval", waiting)
	}
	if !slices.Equal(waiting.Needs[0].Features, []grants.Feature{grants.FeatureTLSInterception}) {
		t.Errorf("the approval is waiting for %v, want traffic interception", waiting.Needs[0].Features)
	}
	if !strings.Contains(waiting.Command, "--tls-interception") {
		t.Errorf("the command %q does not approve interception", waiting.Command)
	}
}

// An approvals file that is there and cannot be relied on is no approval: interception stays
// off, and the card carries the reason rather than a plain "waiting" nobody can answer.
func TestAnApprovalsFileThatCannotBeReadRefusesInterceptionAndSaysWhy(t *testing.T) {
	api := newIPSAPIWith(t, func() (grants.Document, error) {
		return grants.Document{}, errors.New("grants.json belongs to another account")
	}, intercepting)

	if api.a.currentIPS().scope.Load().On() {
		t.Fatal("interception ran although the approvals could not be read")
	}
	view := api.View().Intercept
	if !strings.Contains(view.ApprovalError, "another account") {
		t.Errorf("approval error = %q, want the reason the approvals could not be read", view.ApprovalError)
	}
	if view.Running {
		t.Error("the view reports interception running")
	}
}

// Approved after the fact, and the next pass opens connections and clears the waiting entry,
// without the person switching anything off and on.
func TestInterceptionStartsOnThePassAfterAnAdministratorApprovesIt(t *testing.T) {
	doc := grants.None()
	api := newIPSAPIWith(t, func() (grants.Document, error) { return doc, nil }, intercepting)
	if api.a.currentIPS().scope.Load().On() {
		t.Fatal("interception ran before it was approved")
	}

	doc.TLSInterception = true
	api.a.reconcileIPS()

	if !api.a.currentIPS().scope.Load().On() {
		t.Fatal("interception did not start once it was approved")
	}
	if waiting := api.a.approvalsView(); waiting != nil {
		t.Errorf("waiting = %+v after the approval, want nothing", waiting)
	}
	if view := api.View().Intercept; view.AwaitingApproval != "" || !view.Running {
		t.Errorf("intercept view = %+v, want it running and waiting for nothing", view)
	}
}

// Switching interception off means it no longer needs the approval, so the prompt stops asking
// an administrator for it.
func TestSwitchingInterceptionOffDropsTheApprovalItWasWaitingFor(t *testing.T) {
	api := newIPSAPIWith(t, func() (grants.Document, error) { return grants.None(), nil }, intercepting)
	if api.a.approvalsView() == nil {
		t.Fatal("nothing was waiting before the switch was turned off")
	}

	if _, err := api.a.store.Update(func(c *config.Config) error {
		c.Settings.IPSIntercept = config.IPSInterceptOff
		return nil
	}); err != nil {
		t.Fatalf("switch interception off: %v", err)
	}
	api.a.prunePendingApprovals()

	if waiting := api.a.approvalsView(); waiting != nil {
		t.Errorf("waiting = %+v after interception was switched off, want nothing", waiting)
	}
}
