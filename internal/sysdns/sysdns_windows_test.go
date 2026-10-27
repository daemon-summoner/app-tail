// SPDX-License-Identifier: MIT

package sysdns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

// recordingResolver is a windowsResolver whose system tools are watched rather than run.
// Every call here would otherwise repoint the name resolution of the machine the test is
// running on.
func recordingResolver(t *testing.T) (windowsResolver, *[][]string, *[]string) {
	t.Helper()
	var calls [][]string
	var logs []string
	w := windowsResolver{
		logf: func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) },
		run: func(_ context.Context, path string, args []string) (string, error) {
			calls = append(calls, append([]string{filepath.Base(path)}, args...))
			return "", nil
		},
		values: func(string, string) (string, error) { return "", nil },
		// An empty name leaves the recorded one in place, which is the machine where nothing
		// has been renamed; the rename itself has a test of its own.
		names: func(string) (string, error) { return "", nil },
		// Absent rather than zero: an adapter carrying neither registration value is on the
		// defaults, which is what almost every machine is on.
		flags: func(string, string) (uint64, bool, error) { return 0, false, nil },
	}
	return w, &calls, &logs
}

// The whole point of the module is that the machine ends up pointed somewhere. An
// IPv6-only list used to be accepted and then skipped address by address, so set returned
// success having run nothing at all -- the manager then recorded a machine it had
// repointed and offered to put it back.
func TestPointingAnAdapterAtIPv6OnlyResolversIsRefusedRatherThanDoingNothing(t *testing.T) {
	w, calls, _ := recordingResolver(t)

	err := w.set(t.Context(), Service{ID: "{guid}", Name: "Ethernet"}, addrs("2606:4700:4700::1111", "2001:4860:4860::8888"))
	if err == nil {
		t.Fatal("an IPv6-only resolver list was accepted, so the caller believes the adapter was repointed")
	}
	for _, want := range []string{"Ethernet", "2606:4700:4700::1111"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("the refusal still ran %v", *calls)
	}
}

// A mixed list is still worth acting on, but the addresses left out have to be said out
// loud: a user who chose an IPv4+IPv6 profile and gets IPv4 only has no other way to find
// out which half took effect.
func TestIPv6ResolversAreLeftOutAndSaidSo(t *testing.T) {
	w, calls, logs := recordingResolver(t)

	if err := w.set(t.Context(), Service{ID: "{guid}", Name: "Wi-Fi"}, addrs("9.9.9.9", "2620:fe::fe")); err != nil {
		t.Fatalf("point an adapter at a mixed resolver list: %v", err)
	}

	if len(*calls) != 1 {
		t.Fatalf("ran %d commands for one usable address: %v", len(*calls), *calls)
	}
	if !strings.Contains(strings.Join((*calls)[0], " "), "9.9.9.9") {
		t.Errorf("the IPv4 resolver was not the one set: %v", (*calls)[0])
	}
	joined := strings.Join(*logs, "\n")
	if !strings.Contains(joined, "2620:fe::fe") {
		t.Errorf("the address left unset was never mentioned:\n%s", joined)
	}
}

// netsh takes the first resolver as "primary" and every later one at an explicit index.
// Indexing off the caller's list rather than the addresses actually being set produced an
// index=2 with nothing ever placed at index 1 whenever an IPv6 address came first.
func TestTheFirstResolverSetIsPrimaryAndTheRestAreIndexedFromIt(t *testing.T) {
	w, calls, _ := recordingResolver(t)

	if err := w.set(t.Context(), Service{ID: "{guid}", Name: "Ethernet"}, addrs("2620:fe::fe", "9.9.9.9", "149.112.112.112")); err != nil {
		t.Fatalf("point an adapter at a list beginning with IPv6: %v", err)
	}

	if len(*calls) != 2 {
		t.Fatalf("ran %d commands for two usable addresses: %v", len(*calls), *calls)
	}
	first := strings.Join((*calls)[0], " ")
	if !strings.Contains(first, "9.9.9.9") || !strings.Contains(first, "primary") {
		t.Errorf("the first address set is not the primary one: %s", first)
	}
	second := strings.Join((*calls)[1], " ")
	if !strings.Contains(second, "149.112.112.112") || !strings.Contains(second, "index=2") {
		t.Errorf("the second address did not land at index 2: %s", second)
	}
}

// An empty list is how the module is switched off, and it has to hand the adapter back to
// whatever the network hands out rather than leaving an empty static override.
func TestAnEmptyListHandsTheAdapterBackToDhcp(t *testing.T) {
	w, calls, _ := recordingResolver(t)

	if err := w.set(t.Context(), Service{ID: "{guid}", Name: "Ethernet"}, nil); err != nil {
		t.Fatalf("hand an adapter back to DHCP: %v", err)
	}

	if len(*calls) != 1 {
		t.Fatalf("ran %d commands to hand one adapter back: %v", len(*calls), *calls)
	}
	got := strings.Join((*calls)[0], " ")
	if !strings.Contains(got, "source=dhcp") {
		t.Errorf("the adapter was not handed back to DHCP: %s", got)
	}
}

// A refusal partway through leaves the adapter holding whatever was set before it, so
// carrying on would build a resolver list nobody asked for on top of a failure nobody saw.
func TestASetThatFailsStopsRatherThanCarryingOn(t *testing.T) {
	var calls [][]string
	w := windowsResolver{
		logf: func(string, ...any) {},
		run: func(_ context.Context, _ string, args []string) (string, error) {
			calls = append(calls, args)
			return "", errors.New("The requested operation requires elevation")
		},
		values: func(string, string) (string, error) { return "", nil },
		names:  func(string) (string, error) { return "", nil },
		flags:  func(string, string) (uint64, bool, error) { return 0, false, nil },
	}

	err := w.set(t.Context(), Service{ID: "{guid}", Name: "Ethernet"}, addrs("9.9.9.9", "149.112.112.112"))
	if err == nil {
		t.Fatal("a netsh refusal was reported as a successful set")
	}
	if !strings.Contains(err.Error(), "elevation") {
		t.Errorf("netsh's own words were dropped from the error: %v", err)
	}
	if len(calls) != 1 {
		t.Errorf("kept going after a refusal: ran %d commands", len(calls))
	}
}

// A failure after the first address leaves the adapter neither where it was nor where it was
// asked to be. The record of what to put back is still right, so this is not a rollback -- it
// is a machine nobody asked for, and the error has to name what did land or the next person
// to look has no way to tell which half took effect.
func TestASetThatFailsPartWayThroughNamesWhatDidLand(t *testing.T) {
	var calls [][]string
	w, _, _ := recordingResolver(t)
	w.run = func(_ context.Context, _ string, args []string) (string, error) {
		calls = append(calls, args)
		if len(calls) == 1 {
			return "", nil
		}
		return "", errors.New("The parameter is incorrect")
	}

	err := w.set(t.Context(), Service{ID: "{guid}", Name: "Ethernet"}, addrs("9.9.9.9", "149.112.112.112"))

	if err == nil {
		t.Fatal("a half-applied resolver list was reported as a successful set")
	}
	if !strings.Contains(err.Error(), "pointed Ethernet at 9.9.9.9") {
		t.Errorf("the error does not name the adapter and the address that did land: %v", err)
	}
	if !strings.Contains(err.Error(), "could not add the rest") {
		t.Errorf("the error does not say the list is incomplete: %v", err)
	}
	if len(calls) != 2 {
		t.Errorf("kept going after the failure: ran %d commands", len(calls))
	}
}

// The registry keeps resolvers in one string, separated by a comma in one value and by a
// space in another. Reading only one of the two forms loses whatever the machine already
// had, which is the list the module restores.
func TestBothRegistrySeparatorsAreRead(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  []string
	}{
		{"comma separated", "9.9.9.9,149.112.112.112", []string{"9.9.9.9", "149.112.112.112"}},
		{"space separated", "9.9.9.9 149.112.112.112", []string{"9.9.9.9", "149.112.112.112"}},
		{"mixed and padded", " 9.9.9.9, 149.112.112.112 ", []string{"9.9.9.9", "149.112.112.112"}},
		{"IPv6 kept", "2620:fe::fe", []string{"2620:fe::fe"}},
		{"nothing set", "", nil},
		{"unparseable entries dropped", "9.9.9.9,not-an-address", []string{"9.9.9.9"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := splitRegistryAddrs(tc.value)
			if len(got) != len(tc.want) {
				t.Fatalf("read %v from %q, want %v", got, tc.value, tc.want)
			}
			for i := range got {
				if got[i].String() != tc.want[i] {
					t.Errorf("entry %d is %s, want %s", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// The adapter a tailnet client owns is the one adapter that must be left alone: pointing
// it at app-tail's forwarder puts the tailnet's own resolution behind the forwarder that
// is meant to sit beside it.
func TestTailnetOwnedAdaptersAreRecognisedWhateverTheirCase(t *testing.T) {
	for _, name := range []string{"Tailscale", "tailscale", "TAILSCALE", "app-tail", "App-Tail", "Tailscale Tunnel"} {
		if !isTailnetAdapter(name) {
			t.Errorf("%q was not recognised as a tailnet adapter, so it would be repointed", name)
		}
	}
	for _, name := range []string{"Ethernet", "Wi-Fi", "vEthernet (Default Switch)", "OpenVPN TAP-Windows6"} {
		if isTailnetAdapter(name) {
			t.Errorf("%q was treated as a tailnet adapter, so it would be skipped", name)
		}
	}
}

// The record names the addresses an elevated process will later put back, so it lives where
// a standard account cannot rewrite it -- and where Windows says that is, not where this
// session's environment says. An elevated app-tail inherits the environment of the session
// that started it, so a %ProgramData% set in HKCU\Environment would otherwise choose where an
// elevated process reads its instructions from.
func TestTheRecordLivesWhereWindowsKeepsProgramDataNotWhereTheEnvironmentSaysSo(t *testing.T) {
	got := DefaultRecordPath()
	if got == "" {
		t.Fatal("this machine did not say where its machine-wide application data lives")
	}
	if !filepath.IsAbs(got) {
		t.Errorf("the record path %q is not absolute, so the working directory decides where it lands", got)
	}
	if want := filepath.Join("app-tail", RecordFileName); !strings.HasSuffix(got, want) {
		t.Errorf("the record path %q does not end in %q", got, want)
	}

	t.Setenv("ProgramData", `Z:\nowhere`)
	if again := DefaultRecordPath(); again != got {
		t.Errorf("an environment variable moved the record from %q to %q", got, again)
	}
}

// netsh takes the name a user can change in the network settings, and the record is keyed by
// the identifier that survives the change. A rename between applying and restoring would
// otherwise leave netsh looking for an adapter that is not there, and that adapter pointed at
// a resolver that stopped running.
func TestAnAdapterRenamedSinceItWasRecordedIsStillFound(t *testing.T) {
	w, calls, logs := recordingResolver(t)
	w.names = func(guid string) (string, error) {
		if guid != "{guid}" {
			t.Errorf("the adapter name was looked up by %q rather than by the recorded identifier", guid)
		}
		return "Ethernet 2", nil
	}

	if err := w.set(t.Context(), Service{ID: "{guid}", Name: "Ethernet"}, addrs("9.9.9.9")); err != nil {
		t.Fatalf("point a renamed adapter at a resolver: %v", err)
	}

	if len(*calls) != 1 {
		t.Fatalf("ran %d commands for one address: %v", len(*calls), *calls)
	}
	if got := strings.Join((*calls)[0], " "); !strings.Contains(got, "name=Ethernet 2") {
		t.Errorf("netsh was given the recorded name rather than the current one: %s", got)
	}
	if joined := strings.Join(*logs, "\n"); !strings.Contains(joined, "Ethernet 2") {
		t.Errorf("the rename was never mentioned:\n%s", joined)
	}
}

// The register parameter has no "leave this alone" value and netsh applies its own default
// when it is left out, so pointing an adapter at a resolver would otherwise change which
// names a managed network can find this machine under -- with nothing recorded to put back.
func TestPointingAnAdapterAtAResolverLeavesItsDnsRegistrationAsItWas(t *testing.T) {
	for _, tc := range []struct {
		name     string
		settings map[string]uint64
		want     string
	}{
		{name: "neither value set", settings: nil, want: "register=primary"},
		{name: "registration turned off", settings: map[string]uint64{"RegistrationEnabled": 0}, want: "register=none"},
		{name: "the connection name registered too", settings: map[string]uint64{"RegistrationEnabled": 1, "RegisterAdapterName": 1}, want: "register=both"},
		{name: "the primary suffix only", settings: map[string]uint64{"RegistrationEnabled": 1, "RegisterAdapterName": 0}, want: "register=primary"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, calls, _ := recordingResolver(t)
			w.flags = func(_, name string) (uint64, bool, error) {
				value, ok := tc.settings[name]
				return value, ok, nil
			}

			if err := w.set(t.Context(), Service{ID: "{guid}", Name: "Ethernet"}, addrs("9.9.9.9")); err != nil {
				t.Fatalf("point an adapter at a resolver: %v", err)
			}

			if len(*calls) != 1 {
				t.Fatalf("ran %d commands for one address: %v", len(*calls), *calls)
			}
			if got := strings.Join((*calls)[0], " "); !strings.Contains(got, tc.want) {
				t.Errorf("netsh was given %s, want %s", got, tc.want)
			}
		})
	}
}

// A registration setting that cannot be read falls back to the default almost every machine
// is on, and says so: guessing silently changes how this machine is registered in DNS with
// nothing to point at afterwards.
func TestARegistrationSettingThatCannotBeReadIsSaidOutLoud(t *testing.T) {
	w, calls, logs := recordingResolver(t)
	w.flags = func(string, string) (uint64, bool, error) {
		return 0, false, errors.New("the registry key is not readable")
	}

	if err := w.set(t.Context(), Service{ID: "{guid}", Name: "Ethernet"}, addrs("9.9.9.9")); err != nil {
		t.Fatalf("point an adapter at a resolver: %v", err)
	}

	if got := strings.Join((*calls)[0], " "); !strings.Contains(got, "register=primary") {
		t.Errorf("netsh was given %s, want the default this machine is most likely on", got)
	}
	if joined := strings.Join(*logs, "\n"); !strings.Contains(joined, "registers itself in DNS") {
		t.Errorf("the unreadable setting was never mentioned:\n%s", joined)
	}
}

// A suffix that cannot be read is the difference between restoring a machine that resolves
// short names on its network and one that does not, so it is said out loud rather than
// dropped into an empty search list.
func TestASearchSuffixThatCannotBeReadIsSaidOutLoud(t *testing.T) {
	w, _, logs := recordingResolver(t)
	w.values = func(_, name string) (string, error) {
		if name == "Domain" {
			return "", errors.New("the registry value is not readable")
		}
		return "corp.example", nil
	}

	base, err := w.base(t.Context(), Service{ID: "{guid}", Name: "Ethernet"})
	if err != nil {
		t.Fatalf("read what DHCP handed the adapter: %v", err)
	}
	if len(base.SearchDomains) != 1 || base.SearchDomains[0] != "corp.example" {
		t.Errorf("search domains %v, want the one that could be read", base.SearchDomains)
	}
	if joined := strings.Join(*logs, "\n"); !strings.Contains(joined, "Domain") {
		t.Errorf("the unreadable suffix was never mentioned:\n%s", joined)
	}
}

// A bare command name is resolved through PATH and through the working directory, and
// these programs repoint the whole machine's name resolution. Asking Windows for its own
// system directory is what takes that choice away from the environment.
func TestSystemToolsAreNamedByAbsolutePathNotThroughPath(t *testing.T) {
	got, err := systemProgram("netsh.exe")
	if err != nil {
		t.Fatalf("resolve netsh.exe: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("netsh.exe resolved to %q, which PATH decides", got)
	}
	if filepath.Base(got) != "netsh.exe" {
		t.Errorf("resolved to %q, which is not netsh.exe", got)
	}
	t.Setenv("SystemRoot", `Z:\nowhere`)
	again, err := systemProgram("netsh.exe")
	if err != nil {
		t.Fatalf("resolve netsh.exe with SystemRoot repointed: %v", err)
	}
	if again != got {
		t.Errorf("an environment variable moved the resolved path from %q to %q", got, again)
	}
}

// Windows already answers on the whole of 127/8, so app-tail failing to bind a loopback
// address means something else holds it. Adding an address would change this machine for a
// reason nobody diagnosed, so both halves refuse and say why.
func TestLoopbackAddressesAreRefusedRatherThanAdded(t *testing.T) {
	w, calls, _ := recordingResolver(t)
	addr := netip.MustParseAddr("127.0.0.53")

	if err := w.holdLoopback(t.Context(), addr); err == nil {
		t.Error("holding a loopback address was accepted, so the caller believes one was added")
	} else if !strings.Contains(err.Error(), addr.String()) {
		t.Errorf("the refusal does not name the address: %v", err)
	}
	if err := w.releaseLoopback(t.Context(), addr); err == nil {
		t.Error("giving back a loopback address was accepted, so the caller believes one was removed")
	}
	if len(*calls) != 0 {
		t.Errorf("a refusal still ran %v", *calls)
	}
}

// The stored settings are read through one seam, and the two domain values are appended in
// the order Windows searches them: the suffix somebody configured on the adapter before
// the one the network handed it. A dropped value loses a suffix a machine on a managed
// network needs to resolve short names; the reverse order resolves a short name against
// the network before the machine's own configuration.
func TestWhatDhcpHandedTheAdapterIsReadBackWholeAndInOrder(t *testing.T) {
	w := windowsResolver{
		logf: func(string, ...any) {},
		run:  func(context.Context, string, []string) (string, error) { return "", nil },
		values: func(_, name string) (string, error) {
			switch name {
			case "DhcpNameServer":
				return "10.0.0.1 10.0.0.2", nil
			case "DhcpDomain":
				return "corp.example", nil
			case "Domain":
				return "lab.example", nil
			}
			return "", nil
		},
		names: func(string) (string, error) { return "", nil },
		flags: func(string, string) (uint64, bool, error) { return 0, false, nil },
	}

	base, err := w.base(t.Context(), Service{ID: "{guid}", Name: "Ethernet"})
	if err != nil {
		t.Fatalf("read what DHCP handed the adapter: %v", err)
	}
	if got := describe(base.Nameservers); got != "10.0.0.1, 10.0.0.2" {
		t.Errorf("resolvers read as %q, want both of them", got)
	}
	want := []string{"lab.example", "corp.example"}
	if len(base.SearchDomains) != len(want) {
		t.Fatalf("search domains %v, want %v", base.SearchDomains, want)
	}
	for i := range want {
		if base.SearchDomains[i] != want[i] {
			t.Errorf("search domain %d is %q, want %q", i, base.SearchDomains[i], want[i])
		}
	}
}

// An adapter that has never had a static resolver has no NameServer value, and that is an
// answer -- the module records it as "there was nothing here" and puts nothing back later.
// Reporting it as a failure stops the module from ever being switched on.
func TestAnAdapterWithNoStaticResolverReadsAsNoneRatherThanAFailure(t *testing.T) {
	w, _, _ := recordingResolver(t)

	got, err := w.get(t.Context(), Service{ID: "{guid}", Name: "Ethernet"})
	if err != nil {
		t.Fatalf("read an adapter with no static resolver: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("read %v from an adapter with no static resolver, want none", got)
	}
}

// Windows is a platform the module writes, and reporting otherwise would hide the whole
// feature behind a "not supported here" note on the one platform that needs no helper.
func TestWindowsReportsItselfWritable(t *testing.T) {
	ok, reason := windowsResolver{}.supported()
	if !ok {
		t.Errorf("Windows reports its resolver cannot be written: %q", reason)
	}
	if reason != "" {
		t.Errorf("a writable platform still gave the reason %q", reason)
	}
}
