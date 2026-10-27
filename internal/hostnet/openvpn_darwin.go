// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
)

// psBinary reads what a process was started with. It is an absolute path rather than a name
// for the reason every other program this side runs is: this runs as root, and a name would
// let whatever wrote PATH choose what gets run.
const psBinary = "/bin/ps"

// OpenVPNSupported reports whether this platform runs OpenVPN connections.
func OpenVPNSupported() bool { return true }

// processArgs reads the whole command line a process was started with.
//
// It is how a process recorded by a previous run is told apart from whatever holds that number
// now, which is what has to be settled before anything is signalled.
func processArgs(ctx context.Context, pid int) (string, error) {
	// -ww, because ps otherwise cuts each line at the terminal's width and the configuration
	// path this is read to find sits well past it.
	out, err := exec.CommandContext(ctx, psBinary, "-ww", "-o", "command=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return "", fmt.Errorf("read what process %d was started with: %w", pid, err)
	}
	return string(out), nil
}

// openvpnDevice is the interface openvpn opens. macOS has no persistent tun devices, so the
// kernel's utun driver hands out the next free one at open time and the name is discovered
// afterwards rather than chosen here.
func openvpnDevice() string { return "utun" }

// trustedOpenVPNPath is where an openvpn installed for app-tail goes: beside the helper, in a
// directory only root can change, all the way up.
const trustedOpenVPNPath = helperDir + "/openvpn"

// openvpnCandidates is where a root-owned openvpn is looked for, in order.
//
// It is a fixed list rather than a path search because the program at the end of it runs as
// root: a search would let whatever wrote PATH choose what this side executes. The copy
// installed for app-tail comes first. Homebrew's two prefixes follow because they are where a
// machine with a current openvpn has one -- Apple ships none -- but Homebrew's prefix belongs
// to the account that installed it, so a copy there is found and refused with the advice
// below rather than run.
func openvpnCandidates() []string {
	return []string{
		trustedOpenVPNPath,
		"/opt/homebrew/sbin/openvpn",
		"/opt/homebrew/bin/openvpn",
		"/usr/local/sbin/openvpn",
		"/usr/local/bin/openvpn",
		"/usr/sbin/openvpn",
		"/usr/bin/openvpn",
	}
}

// openvpnInstallAdvice is how to put an openvpn where this side will run it, for a refusal
// to end with.
//
// Copying the binary is not always enough: a Homebrew build loads its TLS and compression
// libraries from Homebrew's prefix, which the installing account can write, so even a copy in
// a root-owned directory is refused for what it loads. A statically linked build -- the one
// Tunnelblick ships, for example -- loads nothing but the system's own libraries and passes.
func openvpnInstallAdvice() string {
	return "To install one app-tail will run: sudo mkdir -p " + filepath.Dir(trustedOpenVPNPath) +
		" && sudo install -o root -g wheel -m 755 <path to openvpn> " + trustedOpenVPNPath +
		". A Homebrew openvpn loads libraries from Homebrew's folder, which a normal account can change, " +
		"so it is refused even when copied there; a statically linked openvpn, such as the one Tunnelblick ships, is not."
}

// openvpnEnv is the whole environment openvpn starts with. OpenSSL otherwise reads a
// configuration file and loads provider modules from folders compiled into it, and a Homebrew
// build compiles in folders the installing account can write, where a configuration file
// could name a module for a root process to load. /var/empty is root-owned and empty on
// every macOS.
func openvpnEnv() []string {
	return []string{"OPENSSL_CONF=/dev/null", "OPENSSL_MODULES=/var/empty", "OPENSSL_ENGINES=/var/empty"}
}
