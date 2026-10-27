// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows"
)

// app-tail's adapter is registered under its own type and its own identifier.
//
// Importing the engine's tun package brings the official client's defaults with it,
// which would have this app create an adapter carrying Tailscale's identity: Windows
// keys a network profile off that identifier, so the two installs would share one
// profile and each would look to the other like its own adapter left behind. The value
// itself is arbitrary and fixed -- what matters is only that it is not shared.
func init() {
	tun.WintunTunnelType = "AppTail"
	guid, err := windows.GUIDFromString("{6f0a4e2b-8c31-4d5a-9e77-1b3c8a52f014}")
	if err != nil {
		// A literal that does not parse is a typo in this file, caught the first time
		// this package is loaded rather than at the point an adapter is created.
		panic("hostnet: the app-tail adapter identifier does not parse: " + err.Error())
	}
	tun.WintunStaticRequestedGUID = &guid
}

// Supported reports whether this platform has an interface mode at all.
func Supported() bool { return true }

// DetectMissing names a component the interface mode needs that is not on this machine, or
// that is there and is not the copy this build may load.
//
// The loader searches the application directory and the system directory and nowhere
// else, so a copy anywhere on PATH does not count and must not be reported as present.
// Without this the failure arrives much later, as a message about a library, from a
// process that has already torn down the working userspace node to make room.
//
// The copy found is also checked against the pinned release and loaded here, so an empty
// answer means the module is already in this process. Every caller that opens an adapter
// asks this first (Capabilities.Usable), and the wintun binding's own load by name then
// resolves to the module already loaded rather than to whatever is at the path by then.
// A file that does not match is never loaded, and the answer says so by hash.
func DetectMissing() string {
	dirs, err := wintunSearchPath()
	if err != nil {
		// A search that never happened must not be reported as a search that found nothing:
		// that sends somebody to download a file they already have, and leaves the reason the
		// interface mode will not start unsaid.
		return fmt.Sprintf("whether %s is on this machine could not be checked: %v. The "+
			"network-interface mode needs that file, so it will not start until this is resolved.", wintunDLL, err)
	}
	path, found, err := firstWintun(dirs)
	if err != nil {
		return fmt.Sprintf("%v. The network-interface mode needs that file, so it will not start until this is resolved.", err)
	}
	if !found {
		return wintunDLL + " is not next to app-tail.exe. The network-interface mode needs it, and " +
			"it is not part of app-tail: release archives carry the exact copy this build checks for. " +
			"Unpack the archive into one folder and run `app-tail install` from it, which puts " +
			"app-tail.exe and wintun.dll together where only administrators can change them."
	}
	if err := loadPinnedWintun(path); err != nil {
		return fmt.Sprintf("%v. The network-interface mode will not start until this is resolved.", err)
	}
	return ""
}

// wintunSearchPath is where the loader looks, in its own order: the directory holding
// this executable, then the system directory.
//
// Both are asked of Windows rather than assumed, and a refusal from either ends this: the
// answer with a directory missing is not a shorter search but a wrong one, since the file
// this looks for is most often in exactly the directory that could not be named.
func wintunSearchPath() ([]string, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("find the folder app-tail.exe is running from: %w", err)
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, fmt.Errorf("find this machine's system directory: %w", err)
	}
	return []string{filepath.Dir(exe), system}, nil
}

// Privileged reports whether this process can create the interface itself.
//
// Creating a wintun adapter goes through SetupAPI, which needs Administrator. Windows
// has no helper: the adapter handle is not exposed by the Go binding in a form that can
// be duplicated into another process, so a helper would have to host the whole engine.
// The process elevates itself instead, which costs far less here than on macOS because
// elevation keeps the same user and the same %APPDATA%.
func Privileged() bool {
	token := windows.GetCurrentProcessToken()
	elevated, err := isElevated(token)
	if err != nil {
		return false
	}
	return elevated
}

// isElevated asks the process token whether it is running with a full administrator
// token, rather than inferring it from group membership -- an administrator's ordinary
// process is in the group and cannot open the adapter.
func isElevated(token windows.Token) (bool, error) {
	var elevation uint32
	var size uint32
	err := windows.GetTokenInformation(
		token,
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevation)),
		uint32(unsafe.Sizeof(elevation)),
		&size,
	)
	if err != nil {
		return false, err
	}
	return elevation != 0, nil
}

// resolvesPerDomain reports whether installing a resolver here means naming the domains it
// answers for. Windows takes a resolver carrying no domains as the adapter's own, which is
// what a tailnet without split DNS is asking for.
func resolvesPerDomain() bool { return false }

// DefaultInterfaceName is the adapter a new node gets. Windows names adapters rather
// than numbering them, and a fixed name is what makes one left behind by an unclean exit
// identifiable in `netsh interface show interface`.
func DefaultInterfaceName() string { return "app-tail" }

// officialAdapterName is the network adapter the official Tailscale client creates. The
// name is fixed rather than configured: tailscaled passes it to wintun as the adapter's
// friendly name on every Windows install, which is also the name Go reports for it.
const officialAdapterName = "Tailscale"

// DetectConflict names another program managing a tailnet on this machine.
//
// What conflicts is an adapter holding the tailnet's addresses, not an installed client.
// The official package leaves a Tailscale service running whether or not anybody has the
// app open, so treating the service itself as the conflict reports one that quitting the
// app cannot clear -- and refuses the interface mode on a machine where nothing is
// actually using the tailnet.
//
// own is the interface app-tail opened itself, empty when it has none. See tailnetHolder.
func DetectConflict(_ context.Context, own string) string {
	return conflictFrom(machineAdapters(), own)
}

// conflictFrom is DetectConflict's decision with the machine's adapters passed in, so
// every case it distinguishes is reachable from a test rather than only from a machine
// with the official client installed on it.
//
// What is looked for is an adapter holding the tailnet's addresses, not one with a particular
// name: a second install of the official client is named "Tailscale 2", an adapter a user
// renamed is named whatever they typed, and either one holds the addresses this mode needs.
// The name is used only to say whose it is once one has been found.
func conflictFrom(adapters []adapter, own string) string {
	iface, ip, ok := tailnetHolder(adapters, own)
	if !ok {
		return ""
	}
	who := "another tailnet client is connected on this machine"
	stop := ""
	if strings.EqualFold(iface, officialAdapterName) {
		who = "the official Tailscale client is connected on this machine"
		stop = " Quitting the Tailscale app does not always do that -- it leaves the " +
			"Tailscale service connected, which an administrator prompt stops with: " +
			"sc stop Tailscale"
	}
	return who + ": its " + iface + " adapter holds the tailnet address " + ip.String() +
		". Two clients cannot share the tailnet's addresses or its routes, so " +
		"disconnect it before switching app-tail to the network-interface mode." + stop
}

// DetectLeftovers lists what a previous run left on the machine.
//
// A wintun adapter does outlive its process on Windows, unlike a utun on macOS: it is a
// driver-created device that stays until something removes it. Opening the same name
// again adopts it, so this reports rather than blocks -- but an adapter nothing is
// driving still holds its routes, which is worth naming.
//
// An adapter this process is driving is not a leftover, and saying it is would be worse than
// saying nothing: the undo beside it takes an adapter out of use, and the one it would name
// is the tunnel the user is on.
func DetectLeftovers() []string {
	return leftoversFrom(machineAdapters(), HeldInterface())
}

// leftoversFrom is DetectLeftovers' decision with the machine's adapters and this process's
// own interface passed in, so both answers are reachable from a test rather than only from a
// machine an unclean run left an adapter on.
func leftoversFrom(adapters []adapter, held string) []string {
	name := DefaultInterfaceName()
	if strings.EqualFold(held, name) {
		return nil
	}
	for _, a := range adapters {
		if strings.EqualFold(a.name, name) {
			return []string{"the network adapter " + name + " is still present, holding " +
				"whatever routes the run that made it installed; app-tail adopts it again on " +
				"its next start in the network-interface mode"}
		}
	}
	return nil
}

// CleanUpLeftovers removes what a previous run left behind.
//
// Nothing to do: opening the adapter by the same name adopts the existing one and
// reconfigures it, and removing it first would mean creating it again a moment later,
// which is the slow path and the one that can fail.
func CleanUpLeftovers(func(format string, args ...any)) {}

// UndoFor is what a user runs by hand to take the given leftovers out of use, when the app is
// gone and something is still installed. It takes the list rather than scanning for one, so
// the undo always matches the findings that were reported.
//
// It disables the adapter rather than removing it, which is what a command can do here: a
// wintun adapter is a driver-created device, and removing one is Device Manager or the driver
// itself. A disabled adapter carries no traffic and no routes, which is what the leftover was
// about, and app-tail enables it again when it adopts it.
func UndoFor(leftovers []string) []string {
	if len(leftovers) == 0 {
		return nil
	}
	return []string{
		`netsh interface set interface name="` + DefaultInterfaceName() + `" admin=disable`,
	}
}
