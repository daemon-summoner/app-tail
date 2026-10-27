// SPDX-License-Identifier: MIT

//go:build !windows

package sysproxy

import (
	"errors"
	"runtime"
)

// errUnsupported is returned by the read and write paths, which nothing reaches: the
// caller checks supported() first. It exists so a future caller that forgets fails
// loudly rather than believing an empty string means "nothing is configured".
var errUnsupported = errors.New("this platform's proxy configuration cannot be changed without an administrator")

type unsupportedProxy struct{}

func newMachineProxy() machineProxy { return unsupportedProxy{} }

func (unsupportedProxy) supported() (bool, string) { return unsupportedReason(runtime.GOOS) }

// unsupportedReason says why this platform's proxy cannot be written, in the words the
// card renders. It takes the platform rather than reading it so both answers are
// reachable from a test running on either one.
func unsupportedReason(goos string) (bool, string) {
	switch goos {
	case "darwin":
		return false, "changing this Mac's proxy settings needs an administrator, and applies to one network service at a time -- so app-tail shows the command instead of running it"
	default:
		return false, "this system has no single proxy setting app-tail can write -- point individual programs at the proxy instead"
	}
}

func (unsupportedProxy) get() (string, error) { return "", errUnsupported }

func (unsupportedProxy) set(string) error { return errUnsupported }

func platformLimits() []string { return limitsFor(runtime.GOOS) }

// limitsFor is what this platform will still not do once the proxy is set, listed on the
// card beside the setting. It takes the platform for the same reason unsupportedReason
// does.
func limitsFor(goos string) []string {
	switch goos {
	case "darwin":
		return []string{
			"macOS applies a proxy per network service, so a setting made for Wi-Fi does not follow you onto Ethernet or a phone hotspot.",
			"Firefox and many command-line tools ignore the system setting entirely and need their own.",
		}
	default:
		return []string{
			"Desktop environments, browsers and command-line tools each read their own proxy setting on Linux; there is no single one to write.",
		}
	}
}
