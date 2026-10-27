// SPDX-License-Identifier: MIT

package apiauth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is a settable time source shared by a test and the Keys under test.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestKeys(t *testing.T) (*Keys, *clock, string) {
	t.Helper()
	dir := t.TempDir()
	c := &clock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	k, err := LoadOrCreate(dir, WithClock(c.Now))
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	return k, c, dir
}

func TestTheServerProofDependsOnTheAuthority(t *testing.T) {
	k, _, dir := newTestKeys(t)
	token, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	nonce, err := NewNonce()
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}

	proof := k.Proof(nonce, "127.0.0.1:8377")
	if !VerifyProof(token, nonce, "127.0.0.1:8377", proof) {
		t.Fatal("the proof for the authority the client dialed did not verify")
	}
	// A squatter on another port relaying the challenge to the real agent gets an answer
	// for the agent's own address, which must not pass for the squatter's.
	if VerifyProof(token, nonce, "127.0.0.1:9999", proof) {
		t.Error("a proof made for one authority verified for another")
	}
	other, err := NewNonce()
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}
	if VerifyProof(token, other, "127.0.0.1:8377", proof) {
		t.Error("a proof made for one challenge verified for another")
	}
	if VerifyProof("atk1_"+strings.Repeat("A", 43), nonce, "127.0.0.1:8377", proof) {
		t.Error("a proof verified against a token that did not make it")
	}
}

func TestOnlyChallengesOfASaneLengthAreAccepted(t *testing.T) {
	for _, tc := range []struct {
		nonce string
		ok    bool
	}{
		{strings.Repeat("A", 22), true},  // 16 bytes
		{strings.Repeat("A", 86), true},  // 64 bytes
		{strings.Repeat("A", 20), false}, // 15 bytes
		{strings.Repeat("A", 88), false}, // 66 bytes
		{"not base64!", false},
		{"", false},
	} {
		if got := ValidNonce(tc.nonce); got != tc.ok {
			t.Errorf("ValidNonce(%q) = %v, want %v", tc.nonce, got, tc.ok)
		}
	}
}

func TestTheRawTokenAndASessionAreBothAccepted(t *testing.T) {
	k, _, dir := newTestKeys(t)
	token, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !k.CheckBearer(token) {
		t.Error("the API token itself was refused")
	}
	if k.CheckBearer(token[:len(token)-1] + "x") {
		t.Error("a token differing in its last character was accepted")
	}
	if k.CheckBearer("") || k.CheckBearer("Bearer "+token) || k.CheckBearer("garbage") {
		t.Error("a malformed bearer value was accepted")
	}
}

func TestALaunchTokenIsRedeemedOnceForASessionThatWorks(t *testing.T) {
	k, _, _ := newTestKeys(t)
	launch, err := k.MintLaunch(ThisAccount)
	if err != nil {
		t.Fatalf("MintLaunch: %v", err)
	}
	if k.CheckBearer(launch) {
		t.Error("a launch token was accepted as a bearer credential")
	}
	session, err := k.RedeemLaunch(launch)
	if err != nil {
		t.Fatalf("RedeemLaunch: %v", err)
	}
	if !strings.HasPrefix(session, "ats1.") || !k.CheckBearer(session) {
		t.Errorf("the session %q from a fresh launch token was refused", session)
	}
	if _, err := k.RedeemLaunch(launch); !errors.Is(err, ErrLaunchRefused) {
		t.Errorf("a second redemption = %v, want ErrLaunchRefused", err)
	}
	if _, err := k.RedeemLaunch("never-minted"); !errors.Is(err, ErrLaunchRefused) {
		t.Errorf("redeeming an unknown token = %v, want ErrLaunchRefused", err)
	}
}

func TestALaunchTokenExpiresAfterTwoMinutes(t *testing.T) {
	k, c, _ := newTestKeys(t)
	launch, err := k.MintLaunch(ThisAccount)
	if err != nil {
		t.Fatalf("MintLaunch: %v", err)
	}
	c.advance(LaunchLifetime)
	if _, err := k.RedeemLaunch(launch); !errors.Is(err, ErrLaunchRefused) {
		t.Errorf("redeeming a launch token at its expiry = %v, want ErrLaunchRefused", err)
	}
}

func TestTheOldestLaunchTokenIsEvictedPastTheCap(t *testing.T) {
	k, _, _ := newTestKeys(t)
	var minted []string
	for range maxLaunches + 1 {
		l, err := k.MintLaunch(ThisAccount)
		if err != nil {
			t.Fatalf("MintLaunch: %v", err)
		}
		minted = append(minted, l)
	}
	if _, err := k.RedeemLaunch(minted[0]); !errors.Is(err, ErrLaunchRefused) {
		t.Errorf("the oldest of %d launch tokens was still redeemable: %v", maxLaunches+1, err)
	}
	for _, l := range minted[1:] {
		if _, err := k.RedeemLaunch(l); err != nil {
			t.Errorf("a launch token within the cap was refused: %v", err)
		}
	}
}

func TestASessionExpiresAfterThirtyDays(t *testing.T) {
	k, c, _ := newTestKeys(t)
	launch, err := k.MintLaunch(ThisAccount)
	if err != nil {
		t.Fatalf("MintLaunch: %v", err)
	}
	session, err := k.RedeemLaunch(launch)
	if err != nil {
		t.Fatalf("RedeemLaunch: %v", err)
	}
	c.advance(SessionLifetime - time.Second)
	if !k.CheckBearer(session) {
		t.Fatal("a session was refused a second before its expiry")
	}
	c.advance(time.Second)
	if k.CheckBearer(session) {
		t.Error("a session was accepted at its expiry")
	}
}

func TestATamperedSessionIsRefused(t *testing.T) {
	k, _, _ := newTestKeys(t)
	launch, err := k.MintLaunch(ThisAccount)
	if err != nil {
		t.Fatalf("MintLaunch: %v", err)
	}
	session, err := k.RedeemLaunch(launch)
	if err != nil {
		t.Fatalf("RedeemLaunch: %v", err)
	}
	body, sig, _ := strings.Cut(strings.TrimPrefix(session, "ats1."), ".")
	// Flipping the first body character changes the expiry's high bytes: the edit a
	// holder would make to extend a session forever.
	flipped := "B"
	if body[0] == 'B' {
		flipped = "C"
	}
	for name, forged := range map[string]string{
		"edited body":   "ats1." + flipped + body[1:] + "." + sig,
		"no signature":  "ats1." + body,
		"empty":         "ats1.",
		"foreign key":   foreignSession(t),
		"bad signature": "ats1." + body + "." + strings.Repeat("A", len(sig)),
	} {
		if k.CheckBearer(forged) {
			t.Errorf("a session with %s was accepted", name)
		}
	}
}

// foreignSession is a well-formed session another agent's keys issued.
func foreignSession(t *testing.T) string {
	t.Helper()
	other, _, _ := newTestKeys(t)
	launch, err := other.MintLaunch(ThisAccount)
	if err != nil {
		t.Fatalf("MintLaunch: %v", err)
	}
	session, err := other.RedeemLaunch(launch)
	if err != nil {
		t.Fatalf("RedeemLaunch: %v", err)
	}
	return session
}

func TestRotatingEndsSessionsLaunchesAndTheOldToken(t *testing.T) {
	k, _, dir := newTestKeys(t)
	old, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	launch, err := k.MintLaunch(ThisAccount)
	if err != nil {
		t.Fatalf("MintLaunch: %v", err)
	}
	pending, err := k.MintLaunch(ThisAccount)
	if err != nil {
		t.Fatalf("MintLaunch: %v", err)
	}
	session, err := k.RedeemLaunch(launch)
	if err != nil {
		t.Fatalf("RedeemLaunch: %v", err)
	}

	if err := k.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if k.CheckBearer(old) || k.CheckBearer(session) {
		t.Error("a credential issued before the rotation still works")
	}
	if _, err := k.RedeemLaunch(pending); !errors.Is(err, ErrLaunchRefused) {
		t.Errorf("a launch token minted before the rotation = %v, want ErrLaunchRefused", err)
	}
	fresh, err := Read(dir)
	if err != nil {
		t.Fatalf("Read after rotation: %v", err)
	}
	if fresh == old || !k.CheckBearer(fresh) {
		t.Error("the rotation did not write a new token the keys accept")
	}
}

// The token survives a restart; sessions do not. A browser keeps its session under the
// origin http://127.0.0.1:<port>, and while the agent is stopped another account can bind
// that port, serve a page at that origin and read the session out of storage. One that dies
// with the run it was issued in is worthless by the time anyone can do that.
func TestTheTokenSurvivesARestartAndItsSessionsDoNot(t *testing.T) {
	k, c, dir := newTestKeys(t)
	launch, err := k.MintLaunch(ThisAccount)
	if err != nil {
		t.Fatalf("MintLaunch: %v", err)
	}
	session, err := k.RedeemLaunch(launch)
	if err != nil {
		t.Fatalf("RedeemLaunch: %v", err)
	}
	token, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}

	again, err := LoadOrCreate(dir, WithClock(c.Now))
	if err != nil {
		t.Fatalf("LoadOrCreate again: %v", err)
	}
	if again.Replaced() != "" {
		t.Errorf("a healthy token file was replaced: %s", again.Replaced())
	}
	if !again.CheckBearer(token) {
		t.Error("the stored token was refused after a restart")
	}
	if again.CheckBearer(session) {
		t.Error("a session from before the restart was accepted")
	}
}

// A link the tray or the CLI hands a browser travels on a command line every account on the
// machine can read, so its token says it may only be redeemed by this account. The CLI's
// --print link never touches a command line and may be opened anywhere.
func TestALaunchTokenRemembersWhoMayRedeemIt(t *testing.T) {
	k, _, _ := newTestKeys(t)
	bound, err := k.MintLaunch(ThisAccount)
	if err != nil {
		t.Fatal(err)
	}
	open, err := k.MintLaunch(AnyAccount)
	if err != nil {
		t.Fatal(err)
	}
	if scope, ok := k.LaunchScopeOf(bound); !ok || scope != ThisAccount {
		t.Errorf("LaunchScopeOf(bound) = %v, %v; want ThisAccount", scope, ok)
	}
	if scope, ok := k.LaunchScopeOf(open); !ok || scope != AnyAccount {
		t.Errorf("LaunchScopeOf(open) = %v, %v; want AnyAccount", scope, ok)
	}
	if _, ok := k.LaunchScopeOf("never-minted"); ok {
		t.Error("an unknown token reported a scope")
	}
	if _, err := k.RedeemLaunch(bound); err != nil {
		t.Fatal(err)
	}
	if _, ok := k.LaunchScopeOf(bound); ok {
		t.Error("a redeemed token still reported a scope")
	}
}

// Two rotations at once must leave the file and the agent agreeing on one token; otherwise
// every CLI call is refused until the agent restarts.
func TestConcurrentRotationsLeaveTheFileAndTheKeysAgreeing(t *testing.T) {
	k, _, dir := newTestKeys(t)
	for round := 0; round < 20; round++ {
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := k.Rotate(); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		stored, err := Read(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !k.CheckBearer(stored) {
			t.Fatalf("round %d: the token in the file is not the one the keys accept", round)
		}
	}
}

func TestAMalformedTokenFileIsReplaced(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, TokenFileName), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if k.Replaced() == "" {
		t.Error("a malformed token file was not reported as replaced")
	}
	token, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !k.CheckBearer(token) {
		t.Error("the replacement token is not the one the keys accept")
	}
}

func TestReadReportsAMissingTokenAsNotExist(t *testing.T) {
	if _, err := Read(t.TempDir()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Read on an empty directory = %v, want ErrNotExist", err)
	}
}

func TestAFailingRandomSourceIsReportedNotIgnored(t *testing.T) {
	if _, err := LoadOrCreate(t.TempDir(), withRand(strings.NewReader("short"))); err == nil {
		t.Fatal("LoadOrCreate made a token out of five random bytes")
	}
}

func TestRemoveDeletesTheTokenAndToleratesNone(t *testing.T) {
	_, _, dir := newTestKeys(t)
	if err := Remove(dir); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, TokenFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the token file is still there: %v", err)
	}
	if err := Remove(dir); err != nil {
		t.Errorf("Remove with nothing to remove: %v", err)
	}
}
