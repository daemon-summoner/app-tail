// SPDX-License-Identifier: MIT

package hostnet

import (
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows"
)

// The loader that opens wintun.dll is given LOAD_LIBRARY_SEARCH_APPLICATION_DIR and
// LOAD_LIBRARY_SEARCH_SYSTEM32 and nothing else, so a copy on PATH is not a copy the
// interface mode can use. Looking somewhere the loader does not would turn a refusal
// anyone can act on into a start that tears down a working node and then fails.
func TestWintunIsLookedForOnlyWhereItsLoaderWillLookForIt(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve this executable: %v", err)
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatalf("resolve the system directory: %v", err)
	}

	path, err := wintunSearchPath()
	if err != nil {
		t.Fatalf("work out where wintun is looked for: %v", err)
	}

	if len(path) != 2 {
		t.Fatalf("wintun is looked for in %v, want the application directory and the system directory", path)
	}
	// The application directory comes first because that is the order the loader itself
	// uses: a copy shipped beside app-tail.exe is the one that gets opened.
	if path[0] != filepath.Dir(exe) {
		t.Errorf("first place searched is %q, want the directory holding this executable, %q", path[0], filepath.Dir(exe))
	}
	if path[1] != system {
		t.Errorf("second place searched is %q, want the system directory, %q", path[1], system)
	}
}

// A DLL beside the executable is the shape every release archive ships, so the refusal for
// an absent one has to name the file and the way to get the right copy, because it is not
// part of app-tail and nobody can be expected to know that. A file that is there but is not
// the pinned release is reported too, by its hash, since it is never going to be loaded.
func TestTheMissingDriverIsReportedUntilOneIsBesideTheExecutable(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve this executable: %v", err)
	}
	beside := filepath.Join(filepath.Dir(exe), wintunDLL)
	if _, err := os.Stat(beside); err == nil {
		t.Skipf("%s already exists, so this machine cannot show the absent case", beside)
	}

	missing := DetectMissing()
	if missing == "" {
		t.Fatal("a machine with no wintun.dll reported nothing missing")
	}
	if !strings.Contains(missing, wintunDLL) {
		t.Errorf("the refusal does not name the file: %q", missing)
	}
	if !strings.Contains(missing, "app-tail install") {
		t.Errorf("the refusal does not say how to put the right copy in place: %q", missing)
	}

	if err := os.WriteFile(beside, []byte("not a real library"), 0o644); err != nil {
		t.Fatalf("stage a wintun.dll beside the executable: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(beside); err != nil {
			t.Errorf("remove the staged %s: %v", beside, err)
		}
	})

	got := DetectMissing()
	if got == "" {
		t.Fatal("a wintun.dll that is not the pinned release was reported as ready to load")
	}
	if !strings.Contains(got, wintunSHA256[runtime.GOARCH]) {
		t.Errorf("the report on a replaced wintun.dll does not name the hash it expected: %q", got)
	}
}

// The conflict that matters is an adapter holding the tailnet, because that is what two
// clients cannot share. An installed Tailscale is not one: the official package leaves a
// service running whether or not anybody has the app open, so a machine where nobody is
// using the tailnet must not be refused the interface mode over it.
func TestOnlyAnAdapterHoldingTheTailnetIsAConflict(t *testing.T) {
	cases := []struct {
		name      string
		adapters  []adapter
		own       string
		conflicts bool
		official  bool
	}{{
		name:      "connected",
		adapters:  []adapter{{name: "Tailscale", up: true, addrs: addrs("100.101.102.103")}},
		conflicts: true,
		official:  true,
	}, {
		name:      "connected over IPv6 alone",
		adapters:  []adapter{{name: "Tailscale", up: true, addrs: addrs("fd7a:115c:a1e0::1")}},
		conflicts: true,
		official:  true,
	}, {
		// A second install of the official client, and any adapter somebody renamed, holds
		// the same addresses under a name nothing can predict. Deciding on the name alone
		// lets this machine run two clients on one tailnet, which is the outage the whole
		// check exists to refuse.
		name:      "a tailnet held under another name",
		adapters:  []adapter{{name: "Tailscale 2", up: true, addrs: addrs("100.101.102.103")}},
		conflicts: true,
	}, {
		// The service keeps the adapter after a disconnect, which is the state the app
		// being closed leaves behind and the one that must not refuse anything.
		name:     "present but holding no tailnet address",
		adapters: []adapter{{name: "Tailscale", up: true, addrs: addrs("fe80::1")}},
	}, {
		name:     "down",
		adapters: []adapter{{name: "Tailscale", up: false, addrs: addrs("100.101.102.103")}},
	}, {
		// app-tail's own adapter carries a tailnet address by design, so a decision made
		// on the address alone would report this app as its own conflict.
		name:     "app-tail's own adapter",
		adapters: []adapter{{name: "app-tail", up: true, addrs: addrs("100.64.0.1")}},
		own:      "app-tail",
	}, {
		name:     "no adapters at all",
		adapters: nil,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := conflictFrom(tc.adapters, tc.own)
			if tc.conflicts && got == "" {
				t.Fatal("an adapter holding the tailnet was not reported as a conflict")
			}
			if !tc.conflicts {
				if got != "" {
					t.Fatalf("reported a conflict where nothing holds the tailnet: %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.adapters[0].name) {
				t.Errorf("the conflict does not name the adapter holding it: %q", got)
			}
			// The remedy is the whole message for the official client: someone who has
			// already closed the app needs to be told the service is what is still holding
			// the tailnet, and how to stop it, or there is nothing left for them to try.
			// Nothing is claimed about an adapter that is not the official client's, because
			// stopping a service by that name would act on something else entirely.
			if got, want := strings.Contains(got, "sc stop Tailscale"), tc.official; got != want {
				t.Errorf("says how to stop the Tailscale service = %v, want %v", got, want)
			}
		})
	}
}

// app-tail's adapter must not carry the official client's identity. Windows keys a network
// profile off the tunnel type and the requested GUID, so sharing either would put both
// installs on one profile and make each look to the other like its own adapter left
// behind -- with the firewall rules of whichever wrote the profile last.
func TestTheAdapterCarriesAnIdentityOfItsOwn(t *testing.T) {
	if tun.WintunTunnelType != "AppTail" {
		t.Errorf("the adapter registers as %q, want %q", tun.WintunTunnelType, "AppTail")
	}
	if tun.WintunStaticRequestedGUID == nil {
		t.Fatal("no adapter identifier is requested, so Windows derives one from the engine's defaults")
	}
	// The zero value is what the field holds when nothing set it, and it is not an
	// identifier Windows keys a profile off -- it is the engine choosing its own.
	if *tun.WintunStaticRequestedGUID == (windows.GUID{}) {
		t.Error("the requested adapter identifier is empty, so Windows falls back to the engine's default")
	}
}

// A leftover adapter is reported, never blocked on: opening the same name again adopts it.
// The report exists because an adapter nothing is driving still holds its routes, and the
// undo has to name that same adapter or it repairs nothing.
func TestALeftoverAdapterIsReportedAndTheUndoNamesIt(t *testing.T) {
	if got := UndoFor(nil); got != nil {
		t.Errorf("UndoFor(nothing) = %v, want no commands; the app would offer a repair for a machine with nothing on it", got)
	}

	leftovers := DetectLeftovers()
	for _, found := range leftovers {
		if !strings.Contains(found, DefaultInterfaceName()) {
			t.Errorf("a leftover is reported as %q, which names no adapter anyone can act on", found)
		}
	}

	undo := UndoFor([]string{"the network adapter " + DefaultInterfaceName() + " is still present"})
	if len(undo) == 0 {
		t.Fatal("a reported leftover has no undo, so nothing tells the user how to remove it")
	}
	for _, command := range undo {
		if !strings.Contains(command, `name="`+DefaultInterfaceName()+`"`) {
			t.Errorf("the undo %q does not name app-tail's own adapter, so it acts on the wrong one", command)
		}
	}
}

// The adapter this process is driving is not a leftover. Reporting it as one puts a repair on
// the dashboard whose command disables the tunnel the user is connected through.
func TestTheAdapterThisProcessIsDrivingIsNotALeftover(t *testing.T) {
	present := []adapter{{name: DefaultInterfaceName(), up: true}}

	if got := leftoversFrom(present, DefaultInterfaceName()); got != nil {
		t.Errorf("leftovers while app-tail holds that adapter = %v, want none", got)
	}
	// The exclusion is that adapter alone: an interface this process opened under some other
	// name says nothing about whether an unclean run left this one behind.
	if got := leftoversFrom(present, "some other adapter"); len(got) != 1 {
		t.Fatalf("leftovers with the adapter present and unheld = %v, want the one adapter", got)
	}
	if got := leftoversFrom(present, ""); !strings.Contains(got[0], DefaultInterfaceName()) {
		t.Errorf("a leftover is reported as %q, which names no adapter anyone can act on", got[0])
	}
	if got := leftoversFrom(nil, ""); got != nil {
		t.Errorf("leftovers on a machine with no adapters = %v, want none", got)
	}
}

// addrs parses the addresses a case gives its adapter, so the table stays readable.
func addrs(t ...string) []netip.Addr {
	parsed := make([]netip.Addr, 0, len(t))
	for _, s := range t {
		parsed = append(parsed, netip.MustParseAddr(s))
	}
	return parsed
}
