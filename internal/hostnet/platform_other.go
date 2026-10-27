// SPDX-License-Identifier: MIT

//go:build !darwin && !windows && !linux

package hostnet

import "context"

// Supported reports whether this platform has an interface mode at all.
//
// It does not. The two the app ships for are covered by their own files, and Linux by
// its own; anything else reaches here, where the honest answer is that nobody has
// written or tested the privileged side for it. Reporting false is what turns that into
// a setting that is offered as unavailable with a reason, rather than one that is offered
// and fails at the point of use.
func Supported() bool { return false }

// Privileged reports whether this process can create the interface itself. On a platform
// with no interface mode the question has no answer, and false is the one that keeps
// every caller on the path that reports ErrUnsupported.
func Privileged() bool { return false }

// DefaultInterfaceName is the interface a new node would get.
func DefaultInterfaceName() string { return "" }

// resolvesPerDomain reports whether installing a resolver here means naming the domains it
// answers for. No interface is ever opened on this platform, so no resolver is installed
// and the answer only has to be the one that changes nothing.
func resolvesPerDomain() bool { return false }

// DetectConflict names another program managing a tailnet on this machine.
func DetectConflict(context.Context, string) string { return "" }

// DetectLeftovers lists what a previous run left on the machine.
func DetectLeftovers() []string { return nil }

// CleanUpLeftovers removes what a previous run left behind.
func CleanUpLeftovers(func(format string, args ...any)) {}

// UndoFor is what a user runs by hand to remove the given leftovers. There are none here,
// because nothing on this platform ever installs anything.
func UndoFor([]string) []string { return nil }

// DetectMissing names a component the interface mode needs that is not on this machine.
// There is no interface mode here, so nothing is missing that installing anything would fix.
func DetectMissing() string { return "" }
