// SPDX-License-Identifier: MIT

package sysdns

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// toolCall is one invocation of one of the machine's own tools.
type toolCall struct {
	path  string
	args  []string
	stdin []string
}

// fakeTools stands in for the tools this package drives. Every test below is about what
// app-tail does to a machine -- which service it writes, with which arguments, and what it
// makes of the answer -- and the arguments are the part a machine cannot be asked to check
// after the fact: a wrong one is a resolver written onto the wrong service.
type fakeTools struct {
	calls  []toolCall
	answer func(call toolCall) (string, error)
}

func (f *fakeTools) run(_ context.Context, path string, args []string, stdinLines ...string) (string, error) {
	call := toolCall{path: path, args: args, stdin: stdinLines}
	f.calls = append(f.calls, call)
	if f.answer == nil {
		return "", nil
	}
	return f.answer(call)
}

// resolverWith builds the darwin resolver over canned answers.
func resolverWith(answer func(call toolCall) (string, error)) (darwinResolver, *fakeTools) {
	tools := &fakeTools{answer: answer}
	return darwinResolver{logf: func(string, ...any) {}, run: tools.run}, tools
}

// argvFor is the arguments of the first call to path, and whether there was one.
func (f *fakeTools) argvFor(path string) ([]string, bool) {
	for _, call := range f.calls {
		if call.path == path {
			return call.args, true
		}
	}
	return nil, false
}

const activeServicesOutput = `  subKey [0] = State:/Network/Service/AAAA-1/IPv4
  subKey [1] = State:/Network/Service/BBBB-2/IPv4
  subKey [2] = State:/Network/Service/AAAA-1/IPv6
  subKey [0] = State:/Network/Service/CCCC-3/IPv6
`

// A laptop carries a dozen services -- every adapter it has ever seen, every VPN -- and only
// the ones with an address can resolve anything. The names come from a second read, and the
// two have to line up: a service named from the wrong entry is app-tail handing networksetup
// one service's name for another service's setting.
func TestOnlyTheServicesCarryingAnAddressAreOfferedAResolver(t *testing.T) {
	resolver, tools := resolverWith(func(call toolCall) (string, error) {
		if len(call.stdin) > 0 && strings.HasPrefix(call.stdin[0], "list ") {
			return activeServicesOutput, nil
		}
		return `<dictionary> {
  UserDefinedName : Wi-Fi
}
<dictionary> {
  UserDefinedName : Tailscale
}
<dictionary> {
  ServerAddresses : <array> {
    0 : 192.168.1.1
  }
}
`, nil
	})

	services, err := resolver.services(context.Background())
	if err != nil {
		t.Fatalf("services: %v", err)
	}
	want := []Service{{ID: "AAAA-1", Name: "Wi-Fi"}}
	if !slices.Equal(services, want) {
		t.Errorf("services = %v, want %v: the tailnet's own service and one with no name are not offered", services, want)
	}

	// The names are read for exactly the services that were listed, in that order, or the
	// answers line up against the wrong ones.
	show := tools.calls[1]
	wantShow := []string{
		"show Setup:/Network/Service/AAAA-1",
		"show Setup:/Network/Service/BBBB-2",
		"show Setup:/Network/Service/CCCC-3",
	}
	if !slices.Equal(show.stdin, wantShow) {
		t.Errorf("scutil was asked %v, want %v", show.stdin, wantShow)
	}
}

// Every read is one process launch on a path a user is waiting on, so the whole batch goes in
// one invocation -- and scutil answers a batch positionally. An answer count that does not
// match the question count means every entry after the first gap belongs to another service,
// which is why it is refused rather than read.
func TestABatchAnsweredWithTheWrongNumberOfEntriesIsRefused(t *testing.T) {
	resolver, _ := resolverWith(func(toolCall) (string, error) {
		return "<dictionary> {\n  UserDefinedName : Wi-Fi\n}\n", nil
	})

	_, err := resolver.scutilShow(context.Background(), []string{"Setup:/one", "Setup:/two"})
	if err == nil {
		t.Fatal("two keys answered with one dictionary were read as an answer")
	}
	if !strings.Contains(err.Error(), "2") || !strings.Contains(err.Error(), "1") {
		t.Errorf("err = %v, want it to say how many keys were asked about and how many came back", err)
	}
}

// The override layer and the network's own answer live in different keys, and this package
// depends on the difference: reading the wrong one reports app-tail's own resolver as what
// the network published, which is what gets written back on restore.
func TestTheOverrideIsReadFromTheKeyThatHoldsIt(t *testing.T) {
	resolver, tools := resolverWith(func(toolCall) (string, error) {
		return `<dictionary> {
  ServerAddresses : <array> {
    0 : 127.0.0.53
  }
}
`, nil
	})

	got, err := resolver.get(context.Background(), Service{ID: "AAAA-1", Name: "Wi-Fi"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("127.0.0.53")}) {
		t.Errorf("get = %v, want the address in the override key", got)
	}
	if want := "show Setup:/Network/Service/AAAA-1/DNS"; tools.calls[0].stdin[0] != want {
		t.Errorf("read %q, want %q", tools.calls[0].stdin[0], want)
	}
}

// A machine following its network has no override key at all. Reading that as an empty list
// of resolvers rather than as "there is nothing here" is the difference between restoring a
// service to what it had and pinning it to nothing.
func TestAServiceWithNoOverrideReadsAsNothingRatherThanAsEmpty(t *testing.T) {
	resolver, _ := resolverWith(func(toolCall) (string, error) { return "No such key\n", nil })

	got, err := resolver.get(context.Background(), Service{ID: "AAAA-1", Name: "Wi-Fi"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != nil {
		t.Errorf("get = %v, want nothing at all", got)
	}
}

// networksetup takes the service's name and the addresses, and "Empty" is its documented word
// for "follow the network again". Sending the id, or an empty argument list, points a real
// machine's service somewhere nobody asked for or fails with the reason buried in a tool.
func TestWritingAResolverNamesTheServiceAndItsAddresses(t *testing.T) {
	resolver, tools := resolverWith(noSuchService)
	service := Service{ID: "AAAA-1", Name: "Wi-Fi"}

	if err := resolver.set(context.Background(), service, []netip.Addr{
		netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("::1"),
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	want := []string{"-setdnsservers", "Wi-Fi", "127.0.0.53", "::1"}
	if argv, ok := tools.argvFor(networksetupPath); !ok || !slices.Equal(argv, want) {
		t.Errorf("networksetup was run with %v, want %v", argv, want)
	}

	resolver, tools = resolverWith(noSuchService)
	if err := resolver.set(context.Background(), service, nil); err != nil {
		t.Fatalf("set with no addresses: %v", err)
	}
	want = []string{"-setdnsservers", "Wi-Fi", "Empty"}
	if argv, _ := tools.argvFor(networksetupPath); !slices.Equal(argv, want) {
		t.Errorf("clearing the resolver ran %v, want %v", argv, want)
	}
}

// A refused write is the whole reason Apply stops and puts back what it has already changed.
// Swallowing it would leave a machine half pointed at app-tail with a record saying it is
// pointed there entirely.
func TestAResolverWriteThatFailedIsReported(t *testing.T) {
	refused := errors.New("networksetup: cannot find the service")
	resolver, _ := resolverWith(func(call toolCall) (string, error) {
		if call.path == networksetupPath {
			return "", refused
		}
		return noSuchService(call)
	})

	err := resolver.set(context.Background(), Service{ID: "AAAA-1", Name: "Wi-Fi"}, nil)
	if !errors.Is(err, refused) {
		t.Fatalf("set = %v, want the write networksetup refused reported", err)
	}
}

// noSuchService answers every scutil read as a key that is not there, and every other tool
// with nothing.
func noSuchService(call toolCall) (string, error) {
	if call.path == scutilPath {
		return strings.Repeat("No such key\n", len(call.stdin)), nil
	}
	return "", nil
}

// The record keeps the name a service had when it was written. Renamed in System Settings
// while the override stood, the service would be one networksetup no longer knows by that
// name, so every restore would fail and the service would stay pointed at app-tail for good.
// The id is what survives a rename, so the name is read from it at the moment of writing.
func TestARenamedServiceIsWrittenUnderTheNameItHasNow(t *testing.T) {
	resolver, tools := resolverWith(func(call toolCall) (string, error) {
		if call.path == scutilPath {
			return "<dictionary> {\n  UserDefinedName : Home Wi-Fi\n}\n", nil
		}
		return "", nil
	})

	if err := resolver.set(context.Background(), Service{ID: "AAAA-1", Name: "Wi-Fi"}, nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	want := []string{"-setdnsservers", "Home Wi-Fi", "Empty"}
	if argv, ok := tools.argvFor(networksetupPath); !ok || !slices.Equal(argv, want) {
		t.Errorf("networksetup was run with %v, want %v", argv, want)
	}
}

// Some networks hand out their resolver in the DHCP lease without configd copying it into the
// DNS key. Reading only the copied key reports a service as having no resolver of its own,
// and restoring one to nothing is what leaves a machine unable to resolve anything.
func TestAResolverThatCameStraightFromTheLeaseIsStillFound(t *testing.T) {
	resolver, _ := resolverWith(func(toolCall) (string, error) {
		return `No such key
<dictionary> {
  Option_6 : <data> 0xc0a80601c0a80602
  Option_15 : <data> 0x6c616e00
}
`, nil
	})

	base, err := resolver.base(context.Background(), Service{ID: "AAAA-1", Name: "Wi-Fi"})
	if err != nil {
		t.Fatalf("base: %v", err)
	}
	want := []netip.Addr{netip.MustParseAddr("192.168.6.1"), netip.MustParseAddr("192.168.6.2")}
	if !slices.Equal(base.Nameservers, want) {
		t.Errorf("nameservers = %v, want the ones in the lease %v", base.Nameservers, want)
	}
	if !slices.Contains(base.SearchDomains, "lan") {
		t.Errorf("search domains = %v, want the lease's domain", base.SearchDomains)
	}
}

// The machine answers from its cache until it is told not to, and the responder holds a copy
// of the configuration as well as a cache. A switch that skipped either reads as a switch
// that did nothing, so both run and neither failure is swallowed.
func TestAResolverChangeIsMadeToTakeEffectNow(t *testing.T) {
	resolver, tools := resolverWith(nil)
	if err := resolver.flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if _, ok := tools.argvFor(dsCacheUtilPath); !ok {
		t.Error("the machine's own cache was left holding the old answers")
	}
	if argv, ok := tools.argvFor(killallPath); !ok || !slices.Equal(argv, []string{"-HUP", "mDNSResponder"}) {
		t.Errorf("the responder was signalled with %v, want -HUP mDNSResponder", argv)
	}

	for _, failing := range []string{dsCacheUtilPath, killallPath} {
		resolver, _ := resolverWith(func(call toolCall) (string, error) {
			if call.path == failing {
				return "", errors.New("refused")
			}
			return "", nil
		})
		if err := resolver.flush(context.Background()); err == nil {
			t.Errorf("%s failed and the flush reported success", failing)
		}
	}
}

// macOS assigns 127.0.0.1 to lo0 and refuses the rest of 127/8, so an address other than that
// one has to be added before anything can listen on it. The mask is a single address: an
// alias carrying the whole range would restate the loopback route.
func TestListeningOnAnotherLoopbackAddressAddsExactlyThatAddress(t *testing.T) {
	resolver, tools := resolverWith(nil)

	if err := resolver.holdLoopback(context.Background(), netip.MustParseAddr("127.0.0.53")); err != nil {
		t.Fatalf("holdLoopback: %v", err)
	}
	want := []string{loopbackInterface, "alias", "127.0.0.53", "netmask", "255.255.255.255", "up"}
	if argv, ok := tools.argvFor(ifconfigPath); !ok || !slices.Equal(argv, want) {
		t.Errorf("ifconfig ran with %v, want %v", argv, want)
	}
}

// The forwarder listens on IPv4, and an IPv6 alias would be a change to this machine made for
// an address nothing is going to listen on.
func TestAnAddressTheForwarderCannotListenOnIsRefusedBeforeTheMachineIsTouched(t *testing.T) {
	resolver, tools := resolverWith(nil)

	err := resolver.holdLoopback(context.Background(), netip.MustParseAddr("::1"))
	if err == nil {
		t.Fatal("an IPv6 loopback address was added to this machine")
	}
	if len(tools.calls) != 0 {
		t.Errorf("the machine was changed %d times before the refusal", len(tools.calls))
	}
}

// A reboot drops every alias, so "it is already gone" is the state releasing wants. Reporting
// that as a failure keeps the record on disk and repeats the same removal forever.
func TestGivingBackALoopbackAddressTheMachineNoLongerCarriesSucceeds(t *testing.T) {
	resolver, _ := resolverWith(func(call toolCall) (string, error) {
		if slices.Contains(call.args, "-alias") {
			return "", errors.New("ifconfig: SIOCDIFADDR: Can't assign requested address")
		}
		return "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n", nil
	})

	if err := resolver.releaseLoopback(context.Background(), netip.MustParseAddr("127.0.0.53")); err != nil {
		t.Errorf("releaseLoopback: %v, and the machine does not carry the address", err)
	}
}

// An address the machine still carries after a failed removal is a claim on machine state
// app-tail cannot drop: reporting success would forget an address that is still there, and
// nothing would ever take it back off.
func TestALoopbackAddressThatIsStillThereAfterAFailedRemovalIsReported(t *testing.T) {
	resolver, _ := resolverWith(func(call toolCall) (string, error) {
		if slices.Contains(call.args, "-alias") {
			return "", errors.New("ifconfig: permission denied")
		}
		return "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n" +
			"\tinet 127.0.0.1 netmask 0xff000000\n" +
			"\tinet 127.0.0.53 netmask 0xffffffff\n", nil
	})

	err := resolver.releaseLoopback(context.Background(), netip.MustParseAddr("127.0.0.53"))
	if err == nil {
		t.Fatal("an address the machine still carries was reported as given back")
	}
	if !strings.Contains(err.Error(), "127.0.0.53") {
		t.Errorf("err = %v, want it to name the address still on the interface", err)
	}
}

// ifconfig prints an IPv6 address with the zone attached, and a comparison that kept the zone
// would never match -- which reads as an address that was removed while it is still there.
func TestReadingWhatTheLoopbackCarriesIgnoresTheZone(t *testing.T) {
	const out = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n" +
		"\tinet 127.0.0.1 netmask 0xff000000\n" +
		"\tinet6 ::1%lo0 prefixlen 128\n"

	if !loopbackCarries(out, netip.MustParseAddr("::1")) {
		t.Error("an address printed with its zone read as absent")
	}
	if loopbackCarries(out, netip.MustParseAddr("127.0.0.53")) {
		t.Error("an address the interface does not carry read as present")
	}
}

// Listing the services is the first thing every operation does, so a machine that would not
// answer has to stop it there rather than report that there is nothing to change.
func TestAMachineThatWouldNotListItsServicesIsReported(t *testing.T) {
	resolver, _ := resolverWith(func(toolCall) (string, error) {
		return "", errors.New("scutil: not permitted")
	})

	if _, err := resolver.services(context.Background()); err == nil {
		t.Fatal("a machine that refused to list its services read as one with no services")
	}
}
