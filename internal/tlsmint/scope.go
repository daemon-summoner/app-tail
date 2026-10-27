// SPDX-License-Identifier: MIT

package tlsmint

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/sellitus/app-tail/internal/inspect"
)

// Mode is which connections interception is offered for.
//
// There are two of them because the two answers are wanted by different people for different
// reasons, and neither is a weaker version of the other. Someone debugging one service wants
// exactly that service opened and everything else left alone. Someone inspecting a machine
// they own wants everything opened except the handful of things that break when it is. A
// product that shipped only the first would be useless to the second, and only the second
// would be reckless for the first.
type Mode uint8

const (
	// ModeOff intercepts nothing. It is the zero value on purpose: a Scope that failed to be
	// built, or was never built, opens no connection.
	ModeOff Mode = iota
	// ModeOnly intercepts the destinations named and nothing else.
	ModeOnly
	// ModeExcept intercepts everything except the destinations named.
	ModeExcept
)

// Mode names as they are written in settings and read back by the CLI.
const (
	ModeNameOff    = "off"
	ModeNameOnly   = "only"
	ModeNameExcept = "except"
)

// String is the settings value for a mode, and what the card and the CLI show.
func (m Mode) String() string {
	switch m {
	case ModeOnly:
		return ModeNameOnly
	case ModeExcept:
		return ModeNameExcept
	default:
		return ModeNameOff
	}
}

// ParseMode reads a mode back from settings. An unknown value is an error rather than a
// silent fall back to off: a typo in the mode would otherwise turn interception off without
// saying so, and someone who asked for it would be told it was on while nothing happened.
func ParseMode(text string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "", ModeNameOff:
		return ModeOff, nil
	case ModeNameOnly:
		return ModeOnly, nil
	case ModeNameExcept:
		return ModeExcept, nil
	default:
		return ModeOff, fmt.Errorf("%q is not a way to choose what is intercepted; use %s, %s or %s",
			text, ModeNameOff, ModeNameOnly, ModeNameExcept)
	}
}

// DefaultBypass is the list shipped with ModeExcept, and the reason that mode is usable at
// all.
//
// Every entry is something that verifies the certificate it is served itself rather than
// trusting whatever the machine's trust store holds. Intercepting one of these does not
// produce a warning the person using the machine can click through: it produces software
// that has stopped working, usually with an error naming neither TLS nor app-tail. Software
// updates that silently stop arriving are the worst of them, because nothing looks wrong
// until the machine is months behind.
//
// Entries are matched the way the resolver matches a blocklist entry -- the name and
// everything under it -- so one line covers a whole service.
//
// The list is a starting point rather than a guarantee. Pinning is a decision each vendor
// makes per release and nothing announces it, so this cannot be complete and users are
// expected to add to it. That is why it is one editable setting rather than a constant.
var DefaultBypass = []string{
	// Apple: push notifications, software update and iCloud all pin.
	"apple.com",
	"icloud.com",
	"mzstatic.com",
	"cdn-apple.com",

	// Microsoft: Windows Update and the connectivity checks that decide whether Windows
	// believes it is online.
	"microsoft.com",
	"windowsupdate.com",
	"msftconnecttest.com",
	"msftncsi.com",

	// Google and Chrome: component updates, certificate transparency and Safe Browsing are
	// verified against keys built into the browser.
	"google.com",
	"gstatic.com",
	"googleapis.com",

	// Mozilla. Firefox keeps its own trust store, so a root installed on the machine does
	// not apply to it at all unless enterprise roots are switched on -- which means every
	// intercepted connection Firefox makes fails rather than being inspected.
	"mozilla.org",
	"mozilla.com",
	"mozilla.net",

	// Messaging and sync clients that pin their own certificates.
	"signal.org",
	"whispersystems.org",
	"dropbox.com",
	"dropboxapi.com",

	// Container registries: the client verifies the registry itself and reports a pull
	// failure rather than a certificate problem.
	"docker.io",
	"docker.com",

	// Certificate infrastructure. Revocation and issuance run over HTTP and HTTPS to these,
	// and inspecting the machinery that decides whether certificates are valid is circular.
	"digicert.com",
	"letsencrypt.org",

	// The control plane app-tail itself talks to. Breaking this breaks the thing that would
	// have to be working to turn interception back off.
	"tailscale.com",
}

// Scope decides whether one connection is intercepted.
//
// It is immutable once compiled and replaced whole, exactly like inspect.Rules, so the data
// path reads it without a lock and a connection in flight keeps the answer it started with.
type Scope struct {
	mode Mode
	// list is the named destinations, compiled by the same matcher the rules use. It carries
	// them as deny entries because that is the arm inspect.Rules reports a match from; what
	// a match means here is decided by the mode, not by the word.
	list *inspect.Rules
}

// CompileScope builds the decision from a mode and the list that goes with it.
//
// An empty list is refused in both modes, because in each one it means the opposite of what
// the person switching it on asked for: ModeOnly with nothing named intercepts nothing at
// all, and ModeExcept with nothing named intercepts every connection this machine makes
// including the ones that will break. Neither is a state to arrive at by leaving a field
// blank.
func CompileScope(mode Mode, entries []string) (*Scope, error) {
	if mode == ModeOff {
		return &Scope{mode: ModeOff}, nil
	}
	var kept []string
	for _, entry := range entries {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			kept = append(kept, trimmed)
		}
	}
	if len(kept) == 0 {
		switch mode {
		case ModeOnly:
			return nil, errors.New("no destination is named to intercept, so nothing would be")
		default:
			return nil, errors.New("no destination is left out of interception, so every connection this machine makes would be intercepted")
		}
	}
	id, name := ModeNameOnly, "the destinations to intercept"
	if mode == ModeExcept {
		id, name = ModeNameExcept, "the destinations to leave alone"
	}
	list, err := inspect.Compile([]inspect.Source{{ID: id, Name: name, Deny: kept}})
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return &Scope{mode: mode, list: list}, nil
}

// On reports whether interception is switched on at all, for the card and for the one branch
// on the data path that decides whether any of this runs.
func (s *Scope) On() bool { return s != nil && s.mode != ModeOff }

// Mode is which of the two ways of choosing is in use.
func (s *Scope) Mode() Mode {
	if s == nil {
		return ModeOff
	}
	return s.mode
}

// Count is how many destinations the list holds, for the card.
func (s *Scope) Count() int {
	if s == nil || s.list == nil {
		return 0
	}
	return s.list.Count()
}

// Intercepts answers whether one connection is terminated and inspected, or carried
// untouched.
//
// The name is what the client asked for -- the SNI, or the host a proxy client named -- and
// the address is where the connection is bound. Either may be absent, and a connection with
// neither is never intercepted in ModeOnly (nothing names it) and always intercepted in
// ModeExcept (nothing excuses it), which is the conservative answer in both directions.
func (s *Scope) Intercepts(name string, addr netip.Addr) bool {
	if s == nil || s.mode == ModeOff {
		return false
	}
	_, listed := s.list.Check(name, addr)
	if s.mode == ModeOnly {
		return listed
	}
	return !listed
}
