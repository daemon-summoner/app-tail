// SPDX-License-Identifier: MIT

//go:build !windows

// Package fileown narrows a file to the account that owns it, on the one platform where
// creating it with restrictive mode bits does not.
package fileown

// RestrictToOwner narrows a file to the account that owns it. FileMode carries that on
// this platform and is applied when the file is created, so there is nothing left to do.
func RestrictToOwner(string) error { return nil }

// RestrictToAdministrators and RestrictTreeToAdministrators narrow a file to the accounts
// that may elevate. Everywhere but Windows the caller creates these under a root-owned
// directory with mode bits that say the same thing, applied as the file is created.
func RestrictToAdministrators(string) error { return nil }

func RestrictTreeToAdministrators(string) error { return nil }

// OwnedByAdministrators reports that a file was put there by a privileged process. The
// directories this guards are writable by root alone on this platform, so there is no
// second account that could have left a file in one for a privileged process to act on.
func OwnedByAdministrators(string) (bool, string, error) { return true, "", nil }

// ReplaceableByOtherAccounts reports whether a program that is about to be started with
// administrator rights could be swapped for another one first. Nothing here ever starts
// this binary with rights -- the privileged work is a separate helper, installed once by
// root -- so the question does not arise.
func ReplaceableByOtherAccounts(string) (bool, string, error) { return false, "", nil }

// transientRenameError is never true here: a rename this platform refuses stays refused.
func transientRenameError(error) bool { return false }
