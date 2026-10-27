// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Supported reports whether this platform has an interface mode at all.
func Supported() bool { return true }

// Privileged reports whether this process can create the interface itself.
func Privileged() bool { return os.Geteuid() == 0 }

// DefaultInterfaceName is the interface a new node gets.
//
// "utun" is macOS's request for the first free number, and the kernel appends it: the
// interface that appears is utun4 or whatever was next. Naming a number here instead
// would fail on any machine already holding that one, which on a laptop running a VPN is
// most of them.
func DefaultInterfaceName() string { return "utun" }

// resolverDir is where macOS reads per-domain resolver configuration, and where a
// tailnet DNS configuration leaves files behind.
const resolverDir = "/etc/resolver"

// resolverMarker is the comment tailscale's own configurator writes into every file it
// creates. It is matched rather than the file names because the names are tailnet
// domains, which differ per install.
const resolverMarker = "# Added by tailscaled"

// resolvesPerDomain reports whether installing a resolver here means naming the domains it
// answers for. macOS resolves through the files in resolverDir, each named for the one
// domain it serves, so a resolver configuration carrying no domains installs nothing.
func resolvesPerDomain() bool { return true }

// DetectConflict names another program managing a tailnet on this machine.
//
// This is a refusal rather than a warning because the two cannot coexist: the resolver
// configurator deletes every /etc/resolver file carrying the marker above that is not in
// its own keep-set, so app-tail and an official tailscaled delete each other's files in a
// loop, and both install routes for the same address range.
//
// What conflicts is an interface already holding the tailnet's addresses, not an installed
// client and not a running process. macOS keeps the packaged client's network extension
// running whether or not anyone has the app open -- it is activated system-wide and stays
// resident after the app is quit -- so treating the process as the conflict refuses this mode on
// a machine where nothing is using a tailnet at all, and names something the user cannot find to
// quit. The process is asked about only once an interface has been found, to say which client
// it belongs to.
//
// own is the interface app-tail opened itself, empty when it has none. See tailnetHolder.
func DetectConflict(ctx context.Context, own string) string {
	iface, addr, ok := tailnetHolder(machineAdapters(), own)
	if !ok {
		return ""
	}
	return conflictWith(runningTailnetClient(ctx), iface, addr.String())
}

// conflictWith is the sentence a user acts on, with the machine's answers passed in so every
// case it distinguishes is reachable from a test rather than only from a machine with the
// official client connected on it.
func conflictWith(client, iface, addr string) string {
	who := "another tailnet client is connected on this machine"
	if client != "" {
		who = "the official Tailscale client is connected on this machine (" + client + ")"
	}
	return who + ": " + iface + " holds the tailnet address " + addr + ". Two clients cannot " +
		"share the tailnet's addresses, its routes or the resolver files, so disconnect it " +
		"before switching app-tail to the network-interface mode. Quitting the Tailscale app " +
		"does not always do that -- its network extension stays connected, and its switch is in " +
		"System Settings > General > Login Items & Extensions > Network Extensions."
}

// runningTailnetClient names the program driving the tailnet that was found, empty when none of
// the shapes the official client ships as is running.
//
// The three do not look alike from here. The open-source daemon is a process called tailscaled
// with a socket beside it. The two packaged clients -- the direct download and the App Store
// build -- run their tailnet inside a network system extension whose process is named for its
// bundle, keep no socket anywhere this side can see, and answer on a TCP port recorded in
// /Library/Tailscale/ipnport instead. That file outlives the client that wrote it, so it is the
// process that is asked about rather than the file.
func runningTailnetClient(ctx context.Context) string {
	for _, path := range []string{
		"/var/run/tailscale/tailscaled.sock",
		"/Library/Tailscale/tailscaled.sock",
	} {
		if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return path
		}
	}
	for _, name := range conflictingProcesses {
		out, err := exec.CommandContext(ctx, "/usr/bin/pgrep", "-x", name).Output()
		if err == nil && len(strings.TrimSpace(string(out))) > 0 {
			return name
		}
	}
	return ""
}

// conflictingProcesses are the programs that drive a tailnet on macOS, by the name they run
// under.
var conflictingProcesses = []string{
	"tailscaled",
	"io.tailscale.ipn.macsys.network-extension",
	"io.tailscale.ipn.macos.network-extension",
}

// DetectLeftovers lists what a previous run left on the machine.
//
// Only the resolver files are listed. A utun interface does not outlive the process that
// opened it -- the kernel tears it down with the last reference, and its routes go with
// it -- but a file in /etc/resolver stays until something deletes it, and one naming an
// address that no longer answers breaks resolution for that domain machine-wide.
func DetectLeftovers() []string {
	entries, err := os.ReadDir(resolverDir)
	if err != nil {
		// Nothing is listed either way. The directory is absent on a machine that has never
		// had a resolver file, and one this process cannot read is one it could not have
		// cleaned up from either -- so naming a path it never confirmed would send somebody
		// deleting a file that may not be app-tail's.
		return []string{}
	}
	var out []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(resolverDir, entry.Name())
		body, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(body), resolverMarker) {
			continue
		}
		out = append(out, path)
	}
	return out
}

// CleanUpLeftovers removes what a previous run left behind, before a new one starts.
//
// A failure is logged and not returned: the caller is about to install its own
// configuration over the top, and refusing to start because one stale file could not be
// deleted would turn a cosmetic problem into an outage. What could not be removed still
// shows up in the doctor's report.
func CleanUpLeftovers(logf func(format string, args ...any)) {
	for _, path := range DetectLeftovers() {
		if err := os.Remove(path); err != nil {
			logf("could not remove the leftover resolver file %s: %v", path, err)
		}
	}
}

// UndoFor is what a user runs by hand to remove the given leftovers, when the app is gone
// and something is still installed. It takes the list rather than scanning for one,
// because the authoritative scan is the privileged side's: an unprivileged process cannot
// read every file this would name, and printing an undo for a shorter list than the one
// reported would be worse than printing none.
func UndoFor(leftovers []string) []string {
	if len(leftovers) == 0 {
		return nil
	}
	out := make([]string, 0, len(leftovers)+1)
	for _, path := range leftovers {
		out = append(out, fmt.Sprintf("sudo rm %s", path))
	}
	// The resolver cache holds the old answers until it is told otherwise, so removing
	// the files alone leaves the machine resolving through an address that is gone.
	return append(out, "sudo killall -HUP mDNSResponder")
}

// DetectMissing names a component the interface mode needs that is not on this machine.
// Everything it uses here is part of the kernel, so there is never anything to install.
func DetectMissing() string { return "" }
