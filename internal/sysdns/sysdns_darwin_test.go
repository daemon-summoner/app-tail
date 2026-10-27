// SPDX-License-Identifier: MIT

package sysdns

import (
	"slices"
	"testing"
)

// The samples below are scutil's own output, captured from a machine on a home network. The
// parser reads a batch of commands back as one entry per command, and getting the count
// wrong -- which a missing key or a nested dictionary is what would do -- reads one service's
// settings as another's.
func TestParseScutilReadsABatchBackOneEntryPerCommand(t *testing.T) {
	const out = `<dictionary> {
  ServerAddresses : <array> {
    0 : 192.168.6.1
    1 : 1.1.1.1
  }
  SearchDomains : <array> {
    0 : lan
  }
}
  No such key
<dictionary> {
  LeaseExpirationTime : 08/23/2026 14:11:16
  Option_1 : <data> 0xffffff00
  Option_6 : <data> 0xc0a80601c0a80602
  Option_15 : <data> 0x6c616e00
}
<dictionary> {
  UserDefinedName : Wi-Fi
  Interface : <dictionary> {
    DeviceName : en0
  }
}
`
	dicts := parseScutil(out)
	if len(dicts) != 4 {
		t.Fatalf("parseScutil read %d entries from four commands", len(dicts))
	}

	if got := dicts[0].array("ServerAddresses"); !slices.Equal(got, []string{"192.168.6.1", "1.1.1.1"}) {
		t.Errorf("ServerAddresses = %v", got)
	}
	if got := dicts[0].array("SearchDomains"); !slices.Equal(got, []string{"lan"}) {
		t.Errorf("SearchDomains = %v", got)
	}
	if dicts[1] != nil {
		t.Error("a key that does not exist read back as a dictionary, which would make a missing override look like an empty one")
	}
	if got := parseDHCPAddresses(dicts[2].value("Option_6")); !slices.Equal(got, addrs("192.168.6.1", "192.168.6.2")) {
		t.Errorf("the DHCP resolvers read as %v", got)
	}
	if got := dhcpText(dicts[2].value("Option_15")); got != "lan" {
		t.Errorf("the DHCP domain read as %q, want lan without its trailing NUL", got)
	}
	// A nested dictionary is skipped rather than flattened, and its keys do not leak up.
	if got := dicts[3].value("UserDefinedName"); got != "Wi-Fi" {
		t.Errorf("UserDefinedName = %q", got)
	}
	if got := dicts[3].value("DeviceName"); got != "" {
		t.Errorf("a nested dictionary's key leaked into the top level as %q", got)
	}
}

// scutil prints a one-entry list as a plain value when the thing that wrote it wrote a
// string, so a caller asking for a list has to get one either way.
func TestASingleValuedKeyReadsBackAsAOneEntryList(t *testing.T) {
	dicts := parseScutil("<dictionary> {\n  ServerAddresses : 192.168.6.1\n}\n")
	if len(dicts) != 1 {
		t.Fatalf("parseScutil read %d entries", len(dicts))
	}
	if got := dicts[0].array("ServerAddresses"); !slices.Equal(got, []string{"192.168.6.1"}) {
		t.Errorf("ServerAddresses = %v, want one entry", got)
	}
	if got := dicts[0].array("SearchDomains"); got != nil {
		t.Errorf("a key that is not there read back as %v", got)
	}
}

func TestParseDHCPAddressesRefusesABlobThatIsNotWholeAddresses(t *testing.T) {
	for _, value := range []string{"<data> 0xc0a806", "<data> 0xzz", "192.168.6.1", ""} {
		if got := parseDHCPAddresses(value); got != nil {
			t.Errorf("parseDHCPAddresses(%q) = %v, want nothing", value, got)
		}
	}
}

func TestTailnetServicesAreNotPointedAtTheForwarder(t *testing.T) {
	// These are service names as the user sees them, not device names: a TUN interface
	// app-tail opens itself has no network service at all and never reaches this check.
	for _, name := range []string{"Tailscale", "tailscale0", "app-tail", "App-Tail tailnet"} {
		if !isTailnetService(name) {
			t.Errorf("isTailnetService(%q) = false; pointing it at the forwarder puts tailnet name resolution behind it", name)
		}
	}
	for _, name := range []string{"Wi-Fi", "Ethernet", "Thunderbolt Bridge", "USB 10/100/1000 LAN"} {
		if isTailnetService(name) {
			t.Errorf("isTailnetService(%q) = true; a real network service would be skipped", name)
		}
	}
}

func TestDefaultRecordPathIsRootOwnedTerritory(t *testing.T) {
	// A user-writable file that root reads back and acts on is a list of addresses an
	// elevated process will point this machine at later.
	if got := DefaultRecordPath(); got != "/var/db/app-tail/"+RecordFileName {
		t.Errorf("DefaultRecordPath = %q", got)
	}
}
