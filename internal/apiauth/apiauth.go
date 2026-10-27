// SPDX-License-Identifier: MIT

// Package apiauth holds the secret that every caller of the agent's loopback API must
// present, and the short-lived credentials derived from it.
//
// Loopback is not a boundary on a machine with more than one account, or with any local
// process the user did not start on purpose: anything that can open a socket to
// 127.0.0.1 could otherwise reconfigure the agent, and on Windows the agent runs with
// administrator rights. So the API answers only callers holding a token that lives in a
// file only this account can read. The CLI reads that file; a browser cannot, so the tray
// and the CLI mint one-time launch tokens the dashboard trades for a session.
package apiauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

const (
	// TokenFileName is the file beside the dashboard-address record that holds the API
	// token. The CLI finds both from the config path it was pointed at.
	TokenFileName = "api-token"

	// SessionLifetime is the longest a dashboard stays signed in. A session also ends when
	// the agent stops, and rotating the token ends every one of them early.
	SessionLifetime = 30 * 24 * time.Hour

	// LaunchLifetime bounds the gap between the tray or the CLI minting a launch URL and
	// the browser opening it. A URL handed to a browser lands in its history, so the token
	// in it has to be worthless soon after it is used or not used.
	LaunchLifetime = 120 * time.Second

	// maxLaunches caps the launch tokens waiting to be redeemed. Each one is a credential
	// in memory, and nothing legitimate opens more than a handful of tabs in two minutes.
	maxLaunches = 16

	tokenPrefix   = "atk1_"
	sessionPrefix = "ats1."
	tokenBytes    = 32
	launchBytes   = 32
	sessionNonce  = 16
	runSaltBytes  = 32

	sessionLabel = "app-tail session v1"
	proofLabel   = "app-tail server proof v1"

	// MinNonceBytes and MaxNonceBytes bound the challenge a client sends before trusting
	// a listener with its token. Below the minimum a recorded proof could be replayed by
	// guessing; above the maximum the agent would be hashing whatever a caller sends.
	MinNonceBytes = 16
	MaxNonceBytes = 64
)

// ErrLaunchRefused reports a launch token that was never minted, has expired, or was
// already used.
var ErrLaunchRefused = errors.New("this sign-in link has expired or was already used")

// LaunchScope says who may trade a launch token for a session.
type LaunchScope int

const (
	// ThisAccount is a link handed to a browser by starting a program with it: the tray and
	// `app-tail dashboard` open it with `open` or `xdg-open`, and every account on the
	// machine can read another's command lines. Only a process running as the agent's own
	// account may redeem it. It is the zero value, so a scope left unset is the strict one.
	ThisAccount LaunchScope = iota
	// AnyAccount is a link that never appears on a command line -- `app-tail dashboard
	// --print` writes it to the terminal of the person who asked -- so it may be opened from
	// another account or, under Docker, from the host.
	AnyAccount
)

// Option adjusts how Keys reads the clock and draws randomness, for tests.
type Option func(*Keys)

// WithClock substitutes the clock every expiry is measured against.
func WithClock(now func() time.Time) Option { return func(k *Keys) { k.now = now } }

// withRand substitutes the source every token and nonce is drawn from.
func withRand(r io.Reader) Option { return func(k *Keys) { k.rand = r } }

// Keys is the agent's API credential and everything derived from it. It is safe for
// concurrent use.
type Keys struct {
	dir  string
	now  func() time.Time
	rand io.Reader

	// replaced says why LoadOrCreate wrote a fresh token over one it found, empty when it
	// kept the stored one or there was none.
	replaced string
	// runSalt is drawn once per process and mixed into the session key, so a session ends
	// with the agent run that issued it. Between runs another account can bind the dashboard
	// port and read whatever a browser kept for that origin.
	runSalt []byte

	// rotating serializes Rotate, so the token written to the file is the one installed.
	rotating sync.Mutex

	mu         sync.RWMutex
	token      string
	sessionKey []byte
	proofKey   []byte
	launches   []launch
}

type launch struct {
	token   string
	expires time.Time
	scope   LaunchScope
}

func newKeys(dir string, opts []Option) *Keys {
	k := &Keys{dir: dir, now: time.Now, rand: rand.Reader}
	for _, opt := range opts {
		opt(k)
	}
	return k
}

// install swaps in a token and the keys derived from it, ending every outstanding launch
// and, because the session key changes with it, every session.
func (k *Keys) install(token string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.token = token
	k.sessionKey = mac([]byte(token), append([]byte(sessionLabel), k.runSalt...))
	k.proofKey = derive(token, proofLabel)
	k.launches = nil
}

// Replaced reports why the stored token was not trusted and a new one was written in its
// place, or "" when nothing was replaced. The agent logs it: a token file someone else
// could read is worth a line even though it has already been dealt with.
func (k *Keys) Replaced() string { return k.replaced }

// CheckBearer reports whether tok is the API token itself or a session minted from it
// that has not expired. Both comparisons are constant-time.
func (k *Keys) CheckBearer(tok string) bool {
	k.mu.RLock()
	token, sessionKey := k.token, k.sessionKey
	k.mu.RUnlock()

	switch {
	case strings.HasPrefix(tok, tokenPrefix):
		return subtle.ConstantTimeCompare([]byte(tok), []byte(token)) == 1
	case strings.HasPrefix(tok, sessionPrefix):
		return validSession(sessionKey, tok, k.now())
	default:
		return false
	}
}

// MintLaunch issues a one-time token a browser trades for a session, redeemable by whom
// scope says. When the cap is reached the oldest outstanding one is dropped, so a caller
// minting in a loop can only ever invalidate its own earlier links.
func (k *Keys) MintLaunch(scope LaunchScope) (string, error) {
	raw, err := k.random(launchBytes)
	if err != nil {
		return "", fmt.Errorf("mint a sign-in link: %w", err)
	}
	t := base64.RawURLEncoding.EncodeToString(raw)

	k.mu.Lock()
	defer k.mu.Unlock()
	k.launches = k.liveLaunches(k.now())
	if len(k.launches) >= maxLaunches {
		k.launches = k.launches[len(k.launches)-maxLaunches+1:]
	}
	k.launches = append(k.launches, launch{token: t, expires: k.now().Add(LaunchLifetime), scope: scope})
	return t, nil
}

// LaunchScopeOf reports who may redeem an outstanding launch token, and false for one that
// was never minted, has expired or was already used. It consumes nothing, so a caller that
// is refused leaves the token for the browser it was meant for.
func (k *Keys) LaunchScopeOf(t string) (LaunchScope, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	now := k.now()
	scope, found := ThisAccount, false
	for _, l := range k.launches {
		if now.Before(l.expires) && subtle.ConstantTimeCompare([]byte(l.token), []byte(t)) == 1 {
			scope, found = l.scope, true
		}
	}
	return scope, found
}

// RedeemLaunch trades a launch token for a session, consuming it whether or not the
// session could be minted: a token that has been presented once has been seen.
func (k *Keys) RedeemLaunch(t string) (string, error) {
	k.mu.Lock()
	now := k.now()
	k.launches = k.liveLaunches(now)
	found := -1
	for i, l := range k.launches {
		if subtle.ConstantTimeCompare([]byte(l.token), []byte(t)) == 1 {
			found = i
		}
	}
	if found >= 0 {
		k.launches = append(k.launches[:found], k.launches[found+1:]...)
	}
	sessionKey := k.sessionKey
	k.mu.Unlock()

	if found < 0 {
		return "", ErrLaunchRefused
	}
	return k.mintSession(sessionKey, now)
}

// liveLaunches drops every launch token past its expiry. The caller holds the lock.
func (k *Keys) liveLaunches(now time.Time) []launch {
	live := k.launches[:0]
	for _, l := range k.launches {
		if now.Before(l.expires) {
			live = append(live, l)
		}
	}
	return live
}

// mintSession builds ats1.<body>.<mac>, where body is the expiry in Unix seconds and 16
// random bytes, and mac is HMAC-SHA256 of body under the session key. Nothing about a
// session is stored; the key it is checked against is.
func (k *Keys) mintSession(sessionKey []byte, now time.Time) (string, error) {
	nonce, err := k.random(sessionNonce)
	if err != nil {
		return "", fmt.Errorf("mint a session: %w", err)
	}
	body := make([]byte, 8, 8+sessionNonce)
	binary.BigEndian.PutUint64(body, uint64(now.Add(SessionLifetime).Unix()))
	body = append(body, nonce...)
	return sessionPrefix + base64.RawURLEncoding.EncodeToString(body) + "." +
		base64.RawURLEncoding.EncodeToString(mac(sessionKey, body)), nil
}

func validSession(sessionKey []byte, tok string, now time.Time) bool {
	encodedBody, encodedMAC, ok := strings.Cut(strings.TrimPrefix(tok, sessionPrefix), ".")
	if !ok {
		return false
	}
	body, err := base64.RawURLEncoding.DecodeString(encodedBody)
	if err != nil || len(body) != 8+sessionNonce {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(encodedMAC)
	if err != nil || !hmac.Equal(got, mac(sessionKey, body)) {
		return false
	}
	expires := time.Unix(int64(binary.BigEndian.Uint64(body[:8])), 0)
	return now.Before(expires)
}

// Proof answers a client's challenge: HMAC-SHA256 under the proof key of the nonce, a
// newline, and the authority the client connected to. Binding the authority is what
// stops a squatter on one port from relaying the challenge to the real agent on another
// and passing its answer back as its own.
func (k *Keys) Proof(nonce, authority string) string {
	k.mu.RLock()
	proofKey := k.proofKey
	k.mu.RUnlock()
	return proofWith(proofKey, nonce, authority)
}

// VerifyProof reports whether proof is what the holder of token answers to nonce for
// authority. The CLI calls it before sending the token to whatever is listening.
func VerifyProof(token, nonce, authority, proof string) bool {
	want := proofWith(derive(token, proofLabel), nonce, authority)
	return hmac.Equal([]byte(proof), []byte(want))
}

// ValidNonce reports whether a challenge is base64url (unpadded) of MinNonceBytes to
// MaxNonceBytes bytes.
func ValidNonce(nonce string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	return err == nil && len(raw) >= MinNonceBytes && len(raw) <= MaxNonceBytes
}

// NewNonce draws a challenge of MinNonceBytes*2 random bytes.
func NewNonce() (string, error) {
	raw := make([]byte, MinNonceBytes*2)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("draw a challenge: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func proofWith(proofKey []byte, nonce, authority string) string {
	return base64.RawURLEncoding.EncodeToString(mac(proofKey, []byte(nonce+"\n"+authority)))
}

func derive(token, label string) []byte { return mac([]byte(token), []byte(label)) }

func mac(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func (k *Keys) random(n int) ([]byte, error) {
	raw := make([]byte, n)
	if _, err := io.ReadFull(k.rand, raw); err != nil {
		return nil, fmt.Errorf("draw random bytes: %w", err)
	}
	return raw, nil
}

func (k *Keys) newToken() (string, error) {
	raw, err := k.random(tokenBytes)
	if err != nil {
		return "", fmt.Errorf("generate the API token: %w", err)
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// wellFormedToken reports whether stored file contents are a token this build issues.
func wellFormedToken(tok string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(tok, tokenPrefix))
	return strings.HasPrefix(tok, tokenPrefix) && err == nil && len(raw) == tokenBytes
}
