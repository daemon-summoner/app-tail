// SPDX-License-Identifier: MIT

package hostnet

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

// signedPeer is a check whose kernel answers are given: the helper's hash, the caller's, its
// signing flags and whether a debugger is attached.
func signedPeer(self, peer byte, status uint32, traced bool) darwinPeer {
	return darwinPeer{
		selfHash:   func() ([cdHashSize]byte, error) { return [cdHashSize]byte{self}, nil },
		peerHash:   func(auditToken) ([cdHashSize]byte, error) { return [cdHashSize]byte{peer}, nil },
		peerStatus: func(auditToken) (uint32, error) { return status, nil },
		traced:     func(int) (bool, error) { return traced, nil },
	}
}

func TestACallerWithTheHelpersCodeHashIsAccepted(t *testing.T) {
	if err := signedPeer(1, 1, csValid, false).check(auditToken{}); err != nil {
		t.Fatalf("refused: %v", err)
	}
}

func TestACallerWithAnotherCodeHashIsRefused(t *testing.T) {
	err := signedPeer(1, 2, csValid, false).check(auditToken{})
	if err == nil || !strings.Contains(err.Error(), "different program") {
		t.Fatalf("got %v, want a refusal for a different program", err)
	}
}

func TestACallerUnderADebuggerIsRefusedEvenWithTheHelpersCodeHash(t *testing.T) {
	for name, d := range map[string]darwinPeer{
		"attached":          signedPeer(1, 1, csValid, true),
		"changed by one":    signedPeer(1, 1, csValid|csDebugged, false),
		"running bad pages": signedPeer(1, 1, 0, false),
	} {
		if err := d.check(auditToken{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A process that ran another program after connecting no longer matches its token, and the
// kernel says so rather than answering about the new program.
func TestACallerThatReplacedItsProgramAfterConnectingIsRefused(t *testing.T) {
	d := signedPeer(1, 1, csValid, false)
	d.peerHash = func(auditToken) ([cdHashSize]byte, error) { return [cdHashSize]byte{}, syscall.ESRCH }
	if err := d.check(auditToken{}); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("got %v, want the kernel's refusal", err)
	}
	d = signedPeer(1, 1, csValid, false)
	d.peerStatus = func(auditToken) (uint32, error) { return 0, syscall.ESRCH }
	if err := d.check(auditToken{}); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("got %v, want the kernel's refusal", err)
	}
}

func TestAnUnsignedHelperRefusesEveryCaller(t *testing.T) {
	d := signedPeer(1, 1, csValid, false)
	d.selfHash = func() ([cdHashSize]byte, error) { return [cdHashSize]byte{}, syscall.EINVAL }
	err := d.check(auditToken{})
	if err == nil || !strings.Contains(err.Error(), "no code signature") {
		t.Fatalf("got %v, want a refusal explaining the helper is unsigned", err)
	}
}

// The suite's binary is signed by the linker, so the kernel has a hash for it.
func TestThisPlatformChecksCallersByCodeHash(t *testing.T) {
	if got := HelperCallerCheck(); got != CallerCheckCodeHash {
		t.Fatalf("the caller check here is %q, want %q", got, CallerCheckCodeHash)
	}
}

// The helper accepts callers by matching code hashes, so the flags signed into the hash are
// the caller's too. Without the hardened runtime, DYLD_INSERT_LIBRARIES puts any library into
// app-tail without changing its hash; with get-task-allow, any process of the account may
// attach a debugger to it. A helper signed either way would be serving whoever does that.
func TestAHelperAnyProgramCouldInjectCodeIntoRefusesToServe(t *testing.T) {
	for name, tc := range map[string]struct {
		status uint32
		want   string
	}{
		"no hardened runtime": {csValid, "hardened runtime"},
		"debuggable":          {csValid | csRuntime | csGetTaskAllow, "debugger"},
	} {
		err := refuseUnhardenedProgram("app-tail", tc.status)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want a refusal mentioning %q", name, err, tc.want)
		}
	}
	if err := refuseUnhardenedProgram("app-tail", csValid|csRuntime); err != nil {
		t.Errorf("a hardened helper was refused: %v", err)
	}
}
