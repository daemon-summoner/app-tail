// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// OpenVPNSupported reports whether this platform runs OpenVPN connections.
func OpenVPNSupported() bool { return true }

// processArgs reads the whole command line a process was started with.
//
// It is how a process recorded by a previous run is told apart from whatever holds that number
// now, which is what has to be settled before anything is signalled. The kernel answers it
// from a file, so no program is run to ask.
func processArgs(_ context.Context, pid int) (string, error) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return "", fmt.Errorf("read what process %d was started with: %w", pid, err)
	}
	// The arguments are separated by null bytes rather than by spaces, and the last one carries
	// a trailing separator.
	return strings.ReplaceAll(string(raw), "\x00", " "), nil
}

// openvpnDevice is the interface openvpn opens. Naming the type rather than an interface
// lets the kernel hand out the next free one, so several connections can run at once without
// this side having to keep track of which names it has used.
func openvpnDevice() string { return "tun" }

// openvpnCandidates is where a root-owned openvpn is looked for, in order.
//
// It is a fixed list rather than a path search because the program at the end of it runs as
// root: a search would let whatever wrote PATH choose what this side executes. The
// distribution locations come before /usr/local, which is where a hand-built one lands.
func openvpnCandidates() []string {
	return []string{
		"/usr/sbin/openvpn",
		"/usr/bin/openvpn",
		"/sbin/openvpn",
		"/bin/openvpn",
		"/usr/local/sbin/openvpn",
		"/usr/local/bin/openvpn",
	}
}

// openvpnInstallAdvice is how to put an openvpn where this side will run it, for a refusal
// to end with. The distribution's own package installs one under /usr/sbin, owned by root
// with its libraries in the system's own folders, which is everything the check asks.
func openvpnInstallAdvice() string {
	return "Install your distribution's openvpn package, or copy a build whose libraries all live in root-owned " +
		"folders with: sudo install -o root -g root -m 755 <path to openvpn> /usr/local/sbin/openvpn"
}

// openvpnEnv is the whole environment openvpn starts with: none. A distribution's OpenSSL
// reads its configuration from a root-owned folder, and that file is where system-wide crypto
// policy lives, so OpenSSL is left to find it.
func openvpnEnv() []string { return []string{} }
