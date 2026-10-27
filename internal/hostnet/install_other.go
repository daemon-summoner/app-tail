// SPDX-License-Identifier: MIT

//go:build !darwin

package hostnet

import (
	"context"
	"errors"
	"runtime"
)

// Only macOS installs the helper for the user. Windows elevates the whole process instead,
// because the wintun session handle it needs cannot be passed between processes the way a
// utun file descriptor can. Linux has the helper but no install step: there is no single
// service manager to write a unit for, so it is started by hand as root.

// errNoInstaller explains the absence rather than reporting a failure, because on the
// platforms that reach it there is nothing wrong -- the install is simply not how this
// machine gets its rights.
var errNoInstaller = errors.New(noInstallerReason(HasHelper()))

// SupportsHelperInstall reports whether this platform can install the helper for the user.
func SupportsHelperInstall() bool { return false }

// HelperInstalled reports whether a helper is installed, whatever its state.
func HelperInstalled() bool { return false }

// machineApproveSteps reads this machine for ApproveGrants. No platform but macOS has an
// installed helper to run an approval with, so the platform alone decides the answer.
func machineApproveSteps() approveSteps {
	return approveSteps{goos: runtime.GOOS, elevate: runCombined}
}

// InstallHelper reports that there is nothing to install here.
func InstallHelper(context.Context, func(string, ...any), string, int) error { return errNoInstaller }

// UninstallHelper reports that there is nothing to remove here.
func UninstallHelper(context.Context, func(string, ...any)) error { return errNoInstaller }
