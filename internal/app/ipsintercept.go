// SPDX-License-Identifier: MIT

package app

// Opening encrypted connections so that what they carry can be read.
//
// This is the last rung of inspection and the only one that changes what the far end sees. Up
// to here app-tail reads what a connection says in the clear and carries it; here it ends the
// connection, starts its own to the real server, and hands the program a certificate it signed
// itself. Nothing accepts that certificate until the person using the machine has installed the
// root app-tail generated, which is a change to the machine that outlives app-tail and that
// app-tail deliberately cannot make for them.
//
// Three things keep it from being a downgrade rather than an inspection, and all three are
// load-bearing: the real server is verified on every connection and a connection whose server
// does not verify is stopped rather than carried; the private key is generated here and written
// to one owner-only file; and nothing is opened at all until the setting saying it was
// understood is on, which no upgrade or restored settings file can set.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fileown"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/telemetry"
	"github.com/sellitus/app-tail/internal/tlsmint"
)

// Open decides whether one connection is opened, and returns the pair of connections to carry
// it between either way.
//
// It is the seam every byte-carrying path calls, and the answer for almost every connection is
// the two it was handed: interception off, paused, or a destination outside the list all reach
// that without reading a byte.
//
// An error means the connection was going to be opened and could not be. The caller closes
// both ends rather than carrying it, which is the whole point of the failure: its opening bytes
// have been read and, more importantly, a connection whose server could not be verified is one
// nothing should be told succeeded.
func (r *ipsRunner) Open(ctx context.Context, f inspect.Flow, client, upstream net.Conn) (net.Conn, net.Conn, error) {
	if r == nil {
		return client, upstream, nil
	}
	authority := r.authority.Load()
	scope := r.scope.Load()
	if authority == nil || !scope.On() {
		return client, upstream, nil
	}
	// Read before anything is: a pause has to put traffic back the way it was on the next
	// connection, and a connection already opened is one a pause cannot help with.
	if until := r.pausedUntil.Load(); until != 0 && r.now().UnixNano() < until {
		return client, upstream, nil
	}

	held, err := tlsmint.Open(ctx, tlsmint.Config{
		Scope:     scope,
		Authority: authority,
		Now:       r.now,
	}, client, upstream, f.Addr)
	if err != nil {
		r.interceptFailures.Add(1)
		r.record(telemetry.CodeIPSInterceptFailed,
			fmt.Sprintf("A connection to %s was stopped rather than opened: %v.", interceptedName(f), err),
			map[string]string{
				"where":  f.Where,
				"reason": interceptReason(err),
			})
		// Nothing comes back with the error. The caller still holds both ends and cuts those:
		// a pair returned alongside a failure is a pair somebody has to decide whether to
		// trust, and the ends it already has are the sockets either way.
		return nil, nil, err
	}
	if held.Intercepted {
		r.intercepted.Add(1)
	}
	return held.Client, held.Upstream, nil
}

// interceptedName is what the failure is reported against. The flow's own name is preferred
// because it is what a user typed or a program asked for; the address is what is left on the
// paths that never had one.
func interceptedName(f inspect.Flow) string {
	switch {
	case f.Name != "":
		return f.Name
	case f.Addr.IsValid():
		return f.Addr.Unmap().String()
	}
	return "a destination app-tail could not name"
}

// interceptReason separates the one failure a user can act on from the rest. A server that did
// not verify is either a destination to add to the list left alone or a connection somebody
// really is interfering with; everything else is this machine's problem.
func interceptReason(err error) string {
	if errors.Is(err, tlsmint.ErrUpstreamRefused) {
		return "the server's certificate did not verify"
	}
	return "the connection could not be opened"
}

// interceptTarget is what the settings ask interception to do.
type interceptTarget struct {
	// on is every condition for opening a connection being met: the module, the agreement,
	// and a mode that is not off. Any one of them missing is off.
	on   bool
	mode tlsmint.Mode
	// list is the destinations the mode is about, already filled in with the shipped list
	// where the user has left it empty.
	list []string
	// waiting is why the settings ask for interception and an administrator has not approved
	// it, and unapproved why the approvals could not be read to find out. Either one leaves
	// on false.
	waiting    string
	unapproved error
}

// ipsInterceptTarget is what interception should do: what the settings ask, held to what an
// administrator has approved.
//
// Opening encrypted connections is decided on this side of the helper, so it is the one
// approval this process checks for itself and reports into the pending list the helper's
// refusals go to. The approvals are read on every call, so one taken back stops interception at
// the next pass. A file that cannot be read refuses interception, which is what an unreadable
// approval has to mean.
func (a *Agent) ipsInterceptTarget() (interceptTarget, error) {
	target, err := a.ipsInterceptSettings()
	if err != nil || !target.on {
		a.pending.Accepted(tlsInterceptionSource)
		return target, err
	}
	doc, err := a.loadGrants()
	if err != nil {
		return interceptTarget{unapproved: fmt.Errorf(
			"traffic interception needs an administrator's approval, and the approvals could not be read: %w", err)}, nil
	}
	if needs := doc.TLSInterceptionNeeds(); len(needs) > 0 {
		a.pending.Refused(tlsInterceptionSource, needs)
		return interceptTarget{waiting: needs[0].Reason}, nil
	}
	a.pending.Accepted(tlsInterceptionSource)
	return target, nil
}

// ipsInterceptSettings reads the settings into what interception should do.
//
// The mode is parsed rather than compared, so a value that is not one of the three is off and
// says so in the log rather than being read as something else.
func (a *Agent) ipsInterceptSettings() (interceptTarget, error) {
	s := a.store.Get().Settings
	if !s.IPSEnabled || !s.IPSInterceptAgreed {
		return interceptTarget{}, nil
	}
	mode, err := tlsmint.ParseMode(s.IPSIntercept)
	if err != nil {
		return interceptTarget{}, err
	}
	if mode == tlsmint.ModeOff {
		return interceptTarget{}, nil
	}

	list := slices.Clone(s.IPSInterceptOnly)
	if mode == tlsmint.ModeExcept {
		list = slices.Clone(s.IPSInterceptExcept)
		if len(list) == 0 {
			// Left empty, the shipped list applies. It is the only sane reading: an empty list
			// in this mode means every connection this machine makes is opened, including the
			// ones that stop working when they are.
			list = slices.Clone(tlsmint.DefaultBypass)
		}
	}
	return interceptTarget{on: true, mode: mode, list: list}, nil
}

// reconcileIPSIntercept brings interception to what the settings ask for. It runs inside the
// same reconcile as the rest of inspection, so it is single-threaded with respect to itself, and
// it holds the root's lock so a removal cannot delete the files between this reading them and
// this generating new ones.
//
// Off takes the root out of memory as well as the scope. That is not tidiness: while
// interception is on this process holds a key that can issue certificates the machine will
// accept, and the switch being off has to mean the key is not in memory rather than that nothing
// is currently reading it.
func (a *Agent) reconcileIPSIntercept(runner *ipsRunner) {
	runner.rootMu.Lock()
	defer runner.rootMu.Unlock()

	target, err := a.ipsInterceptTarget()
	if err != nil {
		a.logger.Warn("the traffic-interception setting could not be read", "error", err)
		runner.stopIntercepting()
		return
	}
	if target.unapproved != nil {
		a.logger.Warn("traffic interception is switched on and cannot run", "error", target.unapproved)
	}
	if !target.on {
		runner.stopIntercepting()
		return
	}

	// The list before the root: a root is made for the list, so a list that cannot be read is
	// one no root should be generated for.
	scope, limits, err := compileIntercept(target)
	if err != nil {
		a.logger.Warn("the list of destinations to intercept could not be read", "error", err)
		a.recordEvent(telemetry.CodeIPSFailed,
			fmt.Sprintf("Traffic interception is switched on and cannot run: %v.", err), nil)
		runner.stopIntercepting()
		return
	}

	authority, err := a.interceptAuthority(runner, limits)
	if err != nil {
		a.logger.Error("the root certificate traffic interception presents with is not usable", "error", err)
		a.recordEvent(telemetry.CodeIPSFailed,
			fmt.Sprintf("Traffic interception is switched on and cannot run: %v.", err), nil)
		runner.stopIntercepting()
		return
	}
	a.noteRootCoverage(runner, authority, limits)

	// The root first: a connection arriving between these two stores must find either nothing
	// to open with or both halves, never a scope with nothing to sign.
	runner.authority.Store(authority)
	runner.scope.Store(scope)
}

// compileIntercept reads the list into the scope connections are decided by and the
// constraints a root made for it carries.
func compileIntercept(target interceptTarget) (*tlsmint.Scope, tlsmint.Constraints, error) {
	scope, err := tlsmint.CompileScope(target.mode, target.list)
	if err != nil {
		return nil, tlsmint.Constraints{}, err
	}
	limits, err := tlsmint.ConstraintsFor(target.mode, target.list)
	if err != nil {
		return nil, tlsmint.Constraints{}, err
	}
	return scope, limits, nil
}

// noteRootCoverage reports, once per change, the list having grown past what the root was made
// for. The root is kept rather than replaced: it is the one in the trust store, and the
// destinations it cannot sign for are carried untouched until the person who installed it
// replaces it.
func (a *Agent) noteRootCoverage(runner *ipsRunner, authority *tlsmint.Authority, limits tlsmint.Constraints) {
	outgrown := !authority.Constraints().Covers(limits)
	if runner.rootOutgrown.Swap(outgrown) == outgrown || !outgrown {
		return
	}
	a.logger.Warn("the destinations to intercept reach beyond what the interception root was made for",
		"fingerprint", authority.Fingerprint())
	a.recordEvent(telemetry.CodeIPSFailed, rootOutgrownSentence, map[string]string{
		"fingerprint": authority.Fingerprint(),
	})
}

// stopIntercepting puts every connection back to being carried untouched and drops the key.
func (r *ipsRunner) stopIntercepting() {
	r.scope.Store(nil)
	r.authority.Store(nil)
	r.rootOutgrown.Store(false)
}

// interceptAuthority returns the root to sign with, generating it the first time, limited to the
// destinations limits names.
//
// A root already in memory is the one used: generating a second would produce certificates the
// trust store does not accept, and the first sign of it would be every opened connection
// failing at once.
func (a *Agent) interceptAuthority(runner *ipsRunner, limits tlsmint.Constraints) (*tlsmint.Authority, error) {
	if held := runner.authority.Load(); held != nil {
		return held, nil
	}

	certPath, keyPath := interceptPaths(a.stateDir())
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		authority, err := tlsmint.LoadAuthority(certPEM, keyPEM)
		if err != nil {
			// Not regenerated. A root that cannot be read may still be installed in this
			// machine's trust store, and quietly replacing it would leave that one installed
			// and unaccounted for while a new one starts signing.
			return nil, fmt.Errorf("%s and %s hold a root that cannot be used: %w", certPath, keyPath, err)
		}
		if !a.now().Before(authority.NotAfter()) {
			// Not regenerated either, for the same reason: this root is the one in the trust
			// store, and a new one signing beside it would fail every connection with nothing
			// on the card saying why. The remedy is named because it is the user's to do.
			return nil, fmt.Errorf("%w on %s; remove it from this machine's trust store, delete %s and %s, and switch interception on again",
				tlsmint.ErrRootExpired, authority.NotAfter().Format(time.DateOnly), certPath, keyPath)
		}
		return authority, nil

	case errors.Is(certErr, fs.ErrNotExist) && errors.Is(keyErr, fs.ErrNotExist):
		return a.newInterceptAuthority(certPath, keyPath, limits)

	default:
		// One of the two present, or one unreadable. Both cases mean something happened to
		// these files that this code did not do, and generating over them is the one response
		// that could make it worse.
		return nil, fmt.Errorf("the root certificate files are not in a state app-tail can use: %w",
			errors.Join(certErr, keyErr))
	}
}

// newInterceptAuthority generates a root and writes it down.
//
// The key is written first and the certificate second, so a crash between them leaves the pair
// incomplete in the direction the read above refuses rather than leaving a certificate whose
// key is gone.
func (a *Agent) newInterceptAuthority(certPath, keyPath string, limits tlsmint.Constraints) (*tlsmint.Authority, error) {
	authority, err := tlsmint.NewAuthority(a.now(), limits)
	if err != nil {
		return nil, err
	}
	keyPEM, err := authority.KeyPEM()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(keyPath), config.DirMode); err != nil {
		return nil, fmt.Errorf("make the directory for the root certificate: %w", err)
	}
	// The key is the whole secret, so it is written where only this user can read it. The
	// certificate beside it is public by definition: it is the thing that gets installed.
	if err := writeInterceptFile(keyPath, keyPEM, config.FileMode, true); err != nil {
		return nil, err
	}
	if err := writeInterceptFile(certPath, authority.CertPEM(), 0o644, false); err != nil {
		return nil, err
	}

	a.recordEvent(telemetry.CodeIPSInterceptReady,
		"A root certificate for traffic interception was generated. Nothing is opened until you install it.",
		map[string]string{
			"fingerprint": authority.Fingerprint(),
			"file":        certPath,
		})
	return authority, nil
}

// writeInterceptFile writes one file so that a reader never sees half of it: the content goes
// to a temporary file beside the target, is given its permissions and flushed, and is then
// renamed over the target in one step.
//
// ownerOnly narrows the file to this account on the platform where the mode bits do not:
// Windows hands a new file whatever its directory carries, and the access list is written on
// the temporary file so it travels with the rename and the key is never briefly readable at
// its final path.
func writeInterceptFile(path string, content []byte, mode fs.FileMode, ownerOnly bool) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	name := tmp.Name()
	// The temporary file is going away on every path that did not rename it, so what went wrong
	// closing or removing it cannot matter more than the cause -- but a key left lying beside
	// the file it was going to become is worth naming rather than dropping.
	discard := func(cause error) error {
		return errors.Join(cause, tmp.Close(), os.Remove(name))
	}

	if err := tmp.Chmod(mode); err != nil {
		return discard(fmt.Errorf("set the permissions of %s: %w", path, err))
	}
	if ownerOnly {
		if err := fileown.RestrictToOwner(name); err != nil {
			return discard(fmt.Errorf("set the permissions of %s: %w", path, err))
		}
	}
	if _, err := tmp.Write(content); err != nil {
		return discard(fmt.Errorf("write %s: %w", path, err))
	}
	if err := tmp.Sync(); err != nil {
		return discard(fmt.Errorf("flush %s: %w", path, err))
	}
	if err := tmp.Close(); err != nil {
		return errors.Join(fmt.Errorf("close %s: %w", path, err), os.Remove(name))
	}
	if err := os.Rename(name, path); err != nil {
		return errors.Join(fmt.Errorf("put %s in place: %w", path, err), os.Remove(name))
	}
	return nil
}

// interceptPaths are where the root and its key live, under the state directory that already
// holds everything else app-tail keeps between runs.
func interceptPaths(stateDir string) (certPath, keyPath string) {
	dir := filepath.Join(stateDir, "tls")
	return filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
}

// replaceRootSteps is how a root is replaced, which only the person using the machine can do:
// the old root is in their trust store, and app-tail neither puts it there nor takes it out.
const replaceRootSteps = "switch interception off, run `app-tail ips remove-root`, then switch it back on and install the new root it generates"

// rootOutgrownSentence is what the card and the log say when the list being intercepted reaches
// past what the root was made for.
const rootOutgrownSentence = "The destinations to intercept now reach beyond what the installed root was made for, " +
	"so those connections are carried untouched. To open them, " + replaceRootSteps + "."

// rootUnlimitedSentence is said of a root made before roots were limited to a list.
const rootUnlimitedSentence = "This root was made before app-tail limited its roots, so it can sign for any site. " +
	"Replace it: " + replaceRootSteps + "."

// expirySentence says how close the root is to its end and what to do about it, or nothing
// while it is further out than the warning reaches.
func expirySentence(root *tlsmint.Root, now time.Time) string {
	end := root.NotAfter().UTC().Format(time.DateOnly)
	switch root.Expiry(now) {
	case tlsmint.ExpiryPassed:
		return fmt.Sprintf("The interception root expired on %s, so nothing is opened. To go on, %s.", end, replaceRootSteps)
	case tlsmint.ExpirySoon:
		return fmt.Sprintf("The interception root expires on %s, %s. app-tail will not replace it on its own; to replace it, %s.",
			end, daysLeft(root.NotAfter().Sub(now)), replaceRootSteps)
	}
	return ""
}

// daysLeft says how long is left in whole days, rounded up so the last day reads as one.
func daysLeft(left time.Duration) string {
	days := int((left + 24*time.Hour - 1) / (24 * time.Hour))
	if days == 1 {
		return "in 1 day"
	}
	return fmt.Sprintf("in %d days", days)
}

// interceptRoot is the root as it stands: the one in memory while interception runs, else the
// public half read from its file. The key is never read here: describing a root needs only its
// certificate, and a key read to answer a page view is a key in memory while interception is off.
func (a *Agent) interceptRoot(runner *ipsRunner, certPath string) (*tlsmint.Root, error) {
	if runner != nil {
		if authority := runner.authority.Load(); authority != nil {
			return &authority.Root, nil
		}
	}
	certPEM, err := os.ReadFile(certPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return tlsmint.ParseRoot(certPEM)
}

// ipsInterceptView describes interception as it stands.
func (a *Agent) ipsInterceptView() httpapi.IPSInterceptView {
	s := a.store.Get().Settings
	certPath, _ := interceptPaths(a.stateDir())
	instructions := tlsmint.TrustInstructions(runtime.GOOS, certPath)

	view := httpapi.IPSInterceptView{
		Mode:     s.IPSIntercept,
		Agreed:   s.IPSInterceptAgreed,
		CertPath: certPath,
		Install:  instructions.Install,
		Remove:   instructions.Remove,
		Note:     instructions.Note,
	}
	if view.Mode == "" {
		view.Mode = config.DefaultIPSIntercept
	}
	// On is what the settings ask, which is what removing the root is refused on; the approval
	// is reported beside it as the reason it is not running.
	asked, askedErr := a.ipsInterceptSettings()
	view.On = askedErr == nil && asked.on
	if gated, err := a.ipsInterceptTarget(); err == nil {
		view.AwaitingApproval = gated.waiting
		if gated.unapproved != nil {
			view.ApprovalError = gated.unapproved.Error()
		}
	}

	runner := a.currentIPS()
	if runner != nil {
		view.Opened = runner.intercepted.Load()
		view.Failed = runner.interceptFailures.Load()
		if scope := runner.scope.Load(); scope.On() {
			view.Running = runner.authority.Load() != nil
			view.Destinations = scope.Count()
			view.Shipped = scope.Mode() == tlsmint.ModeExcept && len(s.IPSInterceptExcept) == 0
		}
	}

	root, err := a.interceptRoot(runner, certPath)
	if err != nil {
		view.RootError = fmt.Sprintf("The root certificate at %s could not be read: %v.", certPath, err)
		return view
	}
	if root == nil {
		return view
	}
	now := a.now()
	view.Fingerprint = root.Fingerprint()
	view.Expires = root.NotAfter().UTC().Format(time.RFC3339)
	view.RootScope = root.Constraints().Describe()
	expiry := root.Expiry(now)
	view.Expired = expiry == tlsmint.ExpiryPassed
	view.ExpiresSoon = expiry == tlsmint.ExpirySoon
	view.ExpiryWarning = expirySentence(root, now)

	switch {
	case root.Constraints().Mode == tlsmint.ModeOff:
		view.NeedsNewRoot, view.NewRootReason = true, rootUnlimitedSentence
	case view.On:
		if _, limits, err := compileIntercept(asked); err == nil && !root.Constraints().Covers(limits) {
			view.NeedsNewRoot, view.NewRootReason = true, rootOutgrownSentence
		}
	}

	// Whether the machine trusts the root is asked by minting a certificate, which takes the
	// key, so it is only answered while interception holds one.
	if runner == nil {
		return view
	}
	authority := runner.authority.Load()
	if authority == nil {
		return view
	}
	installed, err := authority.Installed(now)
	if err != nil {
		// Not fatal to the card: what could not be answered is whether the machine trusts the
		// root, and everything else here is still true.
		a.logger.Debug("checking whether the interception root is installed failed", "error", err)
		return view
	}
	view.Installed = installed
	return view
}

// RemoveInterceptRoot deletes the interception root's files; see removeInterceptRoot.
func (i ipsAPI) RemoveInterceptRoot() error { return i.a.removeInterceptRoot() }

// removeInterceptRoot deletes the root's key and certificate and drops it from memory.
//
// It is refused while interception is switched on: the next reconcile would generate a new
// root straight away, and the person removing one wants none. It runs under the root's lock so
// a reconcile cannot read the files half-deleted, and one waiting on the lock sees them gone.
//
// The key goes first, so a failure part way leaves a certificate with no key, which the read in
// interceptAuthority refuses rather than signs with.
func (a *Agent) removeInterceptRoot() error {
	runner := a.currentIPS()
	if runner != nil {
		runner.rootMu.Lock()
		defer runner.rootMu.Unlock()
	}
	if target, err := a.ipsInterceptSettings(); err == nil && target.on {
		return &config.ValidationError{
			Field:   "ips.intercept",
			Message: "switch traffic interception off before removing its root; while it is on, a new root would be generated straight away",
		}
	}

	certPath, keyPath := interceptPaths(a.stateDir())
	var fingerprint string
	if certPEM, err := os.ReadFile(certPath); err == nil {
		if root, err := tlsmint.ParseRoot(certPEM); err == nil {
			fingerprint = root.Fingerprint()
		}
	}
	for _, path := range []string{keyPath, certPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("delete %s: %w", path, err)
		}
	}
	if runner != nil {
		runner.stopIntercepting()
	}
	a.logger.Info("the traffic-interception root's files were deleted", "file", certPath, "fingerprint", fingerprint)
	return nil
}
