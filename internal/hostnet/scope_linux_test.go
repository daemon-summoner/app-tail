// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The routing this side does on Linux is a conversation with the ip program, and what the
// program says is read back as text. Both halves are pinned here against a stand-in for the
// program, so what is asserted is what would be run and how its answers are read, without a
// root account or a routing table to disturb.

// ipCall is one command the stand-in was asked to run.
type ipCall struct {
	args []string
}

func (c ipCall) String() string { return strings.Join(c.args, " ") }

// standInIP answers each ip command from the function given and records what was asked.
func standInIP(t *testing.T, answer func(args []string) (string, error)) *[]ipCall {
	t.Helper()
	was := runIP
	t.Cleanup(func() { runIP = was })
	var asked []ipCall
	runIP = func(_ context.Context, args ...string) (string, error) {
		asked = append(asked, ipCall{args: append([]string(nil), args...)})
		return answer(args)
	}
	return &asked
}

var errIPFailed = errors.New("exit status 2")

// What ip prints for a default route is read for two words, and everything else on the line
// is passed over. A next hop that is not an address is not passed on, a line that is not a
// default route is not a default route, and an interface name that could be a second argument
// is refused before it is put into a command.
func TestTheDefaultRouteIsReadFromWhatIPPrints(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		iface   string
		gateway string
		ok      bool
		refused bool
	}{
		{
			name:    "a router on an ethernet network",
			out:     "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.20 metric 100",
			iface:   "eth0",
			gateway: "192.168.1.1",
			ok:      true,
		},
		{
			name:  "a point to point link with no next hop",
			out:   "default dev ppp0 scope link",
			iface: "ppp0",
			ok:    true,
		},
		{
			name:    "the lowest metric is listed first and taken",
			out:     "default via 10.0.0.1 dev wlan0 metric 600\ndefault via 192.168.1.1 dev eth0 metric 100",
			iface:   "wlan0",
			gateway: "10.0.0.1",
			ok:      true,
		},
		{
			name:    "an IPv6 next hop",
			out:     "default via fe80::1 dev eth0 proto ra metric 1024 pref medium",
			iface:   "eth0",
			gateway: "fe80::1",
			ok:      true,
		},
		{
			name:  "a next hop that is not an address is not passed on",
			out:   "default via somewhere dev eth0",
			iface: "eth0",
			ok:    true,
		},
		{
			name: "no default route at all",
			out:  "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5",
		},
		{
			name: "nothing printed",
			out:  "",
		},
		{
			name: "a default line naming no interface",
			out:  "default via 192.168.1.1",
		},
		{
			name:    "an interface name that could be a second argument",
			out:     "default via 192.168.1.1 dev eth0;reboot",
			refused: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			asked := standInIP(t, func([]string) (string, error) { return c.out, nil })

			iface, gateway, ok, err := hostDefaultRoute(context.Background(), false)

			if c.refused {
				if err == nil {
					t.Fatalf("hostDefaultRoute = %q, %q, %t, want the interface name refused", iface, gateway, ok)
				}
				return
			}
			if err != nil {
				t.Fatalf("hostDefaultRoute: %v", err)
			}
			if iface != c.iface || gateway != c.gateway || ok != c.ok {
				t.Errorf("hostDefaultRoute = %q, %q, %t, want %q, %q, %t", iface, gateway, ok, c.iface, c.gateway, c.ok)
			}
			if len(*asked) != 1 || (*asked)[0].String() != "-4 route show default table main" {
				t.Errorf("ip was asked %v, want the main table's default route", *asked)
			}
		})
	}
}

// The v6 question is put to the v6 table, and a program that fails is reported with what it
// said rather than as a machine with no default route.
func TestAFailureToListRoutesIsReportedWithWhatIPSaid(t *testing.T) {
	asked := standInIP(t, func([]string) (string, error) { return "Cannot open netlink socket", errIPFailed })

	_, _, ok, err := hostDefaultRoute(context.Background(), true)

	if ok || !errors.Is(err, errIPFailed) || !strings.Contains(err.Error(), "Cannot open netlink socket") {
		t.Fatalf("hostDefaultRoute = ok %t, %v; want the failure and what ip said", ok, err)
	}
	if len(*asked) != 1 || (*asked)[0].args[0] != "-6" {
		t.Errorf("ip was asked %v, want the v6 table", *asked)
	}
}

// Rules are removed until there are none: a start that failed between adding its rule and
// recording it leaves one behind per attempt, and "no such file" is the answer that says the
// last one is gone. Any other refusal is reported, and a machine with more rules than this
// side could have installed is reported rather than looped over.
func TestRulesAreRemovedUntilNoneAreLeft(t *testing.T) {
	t.Run("three rules then none", func(t *testing.T) {
		removed := 0
		asked := standInIP(t, func(args []string) (string, error) {
			if removed < 3 {
				removed++
				return "", nil
			}
			return "RTNETLINK answers: No such file or directory", errIPFailed
		})

		if err := unscopeByName(context.Background(), "tun0", false); err != nil {
			t.Fatalf("unscopeByName: %v", err)
		}
		if len(*asked) != 4 {
			t.Errorf("ip was asked %d times, want three removals and the one that found none", len(*asked))
		}
		for _, call := range *asked {
			if call.String() != "-4 rule del oif tun0" {
				t.Errorf("ip was asked %q", call)
			}
		}
	})

	t.Run("a refusal that is not absence is reported", func(t *testing.T) {
		standInIP(t, func([]string) (string, error) { return "RTNETLINK answers: Operation not permitted", errIPFailed })

		err := unscopeByName(context.Background(), "tun0", true)

		if !errors.Is(err, errIPFailed) || !strings.Contains(err.Error(), "Operation not permitted") || !strings.Contains(err.Error(), "tun0") {
			t.Fatalf("unscopeByName = %v, want the refusal named against the interface", err)
		}
	})

	t.Run("rules that never run out are not looped over forever", func(t *testing.T) {
		asked := standInIP(t, func([]string) (string, error) { return "", nil })

		err := unscopeByName(context.Background(), "tun0", false)

		if err == nil || !strings.Contains(err.Error(), "more than 16") {
			t.Fatalf("unscopeByName = %v, want the bound reported", err)
		}
		if len(*asked) != maxScopedRules {
			t.Errorf("ip was asked %d times, want exactly the bound", len(*asked))
		}
	})
}

// Giving an interface its own default route is three commands in a fixed order, the old state
// removed first so a reconnected interface reusing its index reuses a clean table. The next
// hop goes into the route only when there is one.
func TestAnInterfaceIsGivenItsOwnTableInOrder(t *testing.T) {
	// lo is on every Linux machine, and its index gives the table number.
	table, err := routeTableFor("lo")
	if err != nil {
		t.Fatalf("routeTableFor(lo): %v", err)
	}

	t.Run("with a next hop", func(t *testing.T) {
		asked := standInIP(t, func(args []string) (string, error) {
			if args[1] == "rule" && args[2] == "del" {
				return "RTNETLINK answers: No such file or directory", errIPFailed
			}
			return "", nil
		})

		if err := scopeDefault(context.Background(), "lo", "10.8.0.1", false); err != nil {
			t.Fatalf("scopeDefault: %v", err)
		}

		want := []string{
			"-4 rule del oif lo",
			"-4 route flush table " + table,
			"-4 route add default via 10.8.0.1 dev lo table " + table,
			"-4 rule add oif lo table " + table + " priority " + table,
		}
		if got := calls(*asked); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("ip was asked:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	})

	t.Run("without a next hop", func(t *testing.T) {
		asked := standInIP(t, func(args []string) (string, error) {
			if args[1] == "rule" && args[2] == "del" {
				return "RTNETLINK answers: No such file or directory", errIPFailed
			}
			return "", nil
		})

		if err := scopeDefault(context.Background(), "lo", "", true); err != nil {
			t.Fatalf("scopeDefault: %v", err)
		}

		if got := calls(*asked)[2]; got != "-6 route add default dev lo table "+table {
			t.Errorf("the route was added as %q, want no next hop", got)
		}
	})

	t.Run("a rule that cannot be added takes the route back with it", func(t *testing.T) {
		asked := standInIP(t, func(args []string) (string, error) {
			switch {
			case args[1] == "rule" && args[2] == "del":
				return "RTNETLINK answers: No such file or directory", errIPFailed
			case args[1] == "rule" && args[2] == "add":
				return "RTNETLINK answers: Invalid argument", errIPFailed
			}
			return "", nil
		})

		err := scopeDefault(context.Background(), "lo", "10.8.0.1", false)

		if !errors.Is(err, errIPFailed) || !strings.Contains(err.Error(), "Invalid argument") {
			t.Fatalf("scopeDefault = %v, want the rule's refusal", err)
		}
		got := calls(*asked)
		if len(got) != 6 || got[4] != "-4 rule del oif lo" || got[5] != "-4 route flush table "+table {
			t.Errorf("after the refusal ip was asked %v, want the table emptied again", got[4:])
		}
	})

	t.Run("an interface that is not there is refused before anything is run", func(t *testing.T) {
		asked := standInIP(t, func([]string) (string, error) { return "", nil })

		if err := scopeDefault(context.Background(), "nothing0", "", false); err == nil || !strings.Contains(err.Error(), "nothing0") {
			t.Fatalf("scopeDefault = %v, want the interface named as missing", err)
		}
		if len(*asked) != 0 {
			t.Errorf("ip was asked %v for an interface that is not there", *asked)
		}
	})
}

// An interface that has already gone still has its rule removed by name, since the table it
// was using cannot be worked out without it.
func TestAnInterfaceThatHasGoneStillHasItsRuleRemoved(t *testing.T) {
	asked := standInIP(t, func([]string) (string, error) {
		return "RTNETLINK answers: No such file or directory", errIPFailed
	})

	if err := unscopeDefault(context.Background(), "gone0", "10.8.0.1", false); err != nil {
		t.Fatalf("unscopeDefault: %v", err)
	}
	if got := calls(*asked); len(got) != 1 || got[0] != "-4 rule del oif gone0" {
		t.Errorf("ip was asked %v, want the rule removed by name and nothing else", got)
	}
}

// The ip program is run as root, so it has to be one root wrote: the places it is looked for
// are fixed, a machine with none of them says where it looked, and one holding a program
// another account could have written says why that one was refused.
func TestOnlyARootOwnedIPProgramIsRun(t *testing.T) {
	was := ipBinaries
	t.Cleanup(func() { ipBinaries = was })
	dir := t.TempDir()

	t.Run("none of them installed", func(t *testing.T) {
		ipBinaries = []string{filepath.Join(dir, "sbin", "ip"), filepath.Join(dir, "bin", "ip")}

		_, err := ipBinary()

		if !errors.Is(err, ErrScopedRoutesUnsupported) {
			t.Fatalf("ipBinary = %v, want ErrScopedRoutesUnsupported", err)
		}
		for _, path := range ipBinaries {
			if !strings.Contains(err.Error(), path) {
				t.Errorf("the refusal %q does not say it looked in %s", err, path)
			}
		}
		if ScopedRoutesSupported() == nil {
			t.Error("scoped routes were reported as supported with no ip program to run")
		}
	})

	t.Run("one that is not root's", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("a file this test writes belongs to root when root runs it")
		}
		mine := filepath.Join(dir, "ip")
		if err := os.WriteFile(mine, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("write a program: %v", err)
		}
		ipBinaries = []string{filepath.Join(dir, "missing", "ip"), mine}

		_, err := ipBinary()

		if !errors.Is(err, ErrScopedRoutesUnsupported) {
			t.Fatalf("ipBinary = %v, want ErrScopedRoutesUnsupported", err)
		}
		if !strings.Contains(err.Error(), "will not run it as root") || !strings.Contains(err.Error(), mine) ||
			!strings.Contains(err.Error(), "can write") {
			t.Errorf("the refusal %q does not say which program it found and why it is not root's to run", err)
		}
		if strings.Contains(err.Error(), "looked for") {
			t.Errorf("the refusal %q reads as no program found, when one was found and refused", err)
		}
	})
}

func calls(asked []ipCall) []string {
	out := make([]string, 0, len(asked))
	for _, call := range asked {
		out = append(out, call.String())
	}
	return out
}

// goneInterfaceRouting stands in for ip while a test takes routes back from an interface that
// is gone. Linux keeps the rules an interface's routes were reached through after the
// interface itself goes, so taking them back is a real removal that only root may run, and
// the routing table cannot be asked by a test that does not have that. The answer given is
// the one the kernel gives root for a rule that is not there, which is the shape a name no
// interface has takes. Any other command is one the gone path must not reach, and fails the
// test naming it.
func goneInterfaceRouting(t *testing.T, iface string) {
	t.Helper()
	standInIP(t, func(args []string) (string, error) {
		if slices.Equal(args[1:], []string{"rule", "del", "oif", iface}) {
			return "RTNETLINK answers: " + ruleMissing, errIPFailed
		}
		t.Errorf("ip %s was run for an interface that is gone, which has nothing to route", strings.Join(args, " "))
		return "", errIPFailed
	})
}
