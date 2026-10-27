// SPDX-License-Identifier: MIT

package hostnet

import (
	"net/netip"
	"testing"
)

// holding is an interface that is up and carries the given addresses.
func holding(name string, addrs ...string) adapter {
	a := adapter{name: name, up: true}
	for _, addr := range addrs {
		a.addrs = append(a.addrs, netip.MustParseAddr(addr))
	}
	return a
}

// What cannot be shared is an interface holding the tailnet's addresses. Every case here is one
// a machine really produces, and getting any of them wrong either refuses the mode on a machine
// where nothing is using a tailnet or lets two clients claim the same addresses at once.
func TestWhatCountsAsATailnetAlreadyOnThisMachine(t *testing.T) {
	tests := []struct {
		name     string
		adapters []adapter
		own      string
		want     string
	}{
		{
			name:     "an interface holding a tailnet address",
			adapters: []adapter{holding("en0", "192.168.1.5"), holding("utun4", "100.72.90.28")},
			want:     "utun4",
		},
		{
			name:     "the same, on the tailnet's IPv6 range",
			adapters: []adapter{holding("utun4", "fd7a:115c:a1e0::1")},
			want:     "utun4",
		},
		{
			name: "an interface app-tail opened itself",
			// The one case that would have the app refuse the mode it is already running.
			adapters: []adapter{holding("utun4", "100.72.90.28")},
			own:      "utun4",
		},
		{
			name:     "a machine with no tailnet on it at all",
			adapters: []adapter{holding("en0", "192.168.1.5"), holding("utun6", "10.8.0.2")},
		},
		{
			name:     "an interface holding a tailnet address while down",
			adapters: []adapter{{name: "utun4", addrs: []netip.Addr{netip.MustParseAddr("100.72.90.28")}}},
		},
		{
			name: "a machine that could not be read",
		},
		{
			name:     "an address next to the tailnet's range but outside it",
			adapters: []adapter{holding("utun4", "100.128.0.1"), holding("utun5", "100.63.255.255")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface, addr, ok := tailnetHolder(tt.adapters, tt.own)
			if ok != (tt.want != "") {
				t.Fatalf("tailnetHolder = %q, %v, %v; want a holder: %v", iface, addr, ok, tt.want != "")
			}
			if !ok {
				return
			}
			if iface != tt.want {
				t.Errorf("the tailnet was found on %q, want %q", iface, tt.want)
			}
			if !tailnetAddr(addr) {
				t.Errorf("the address reported, %s, is not one a tailnet hands out", addr)
			}
		})
	}
}

// Read from this machine rather than from a table: what the decision sees has to be interfaces
// that exist, or the interface named in a conflict is one the user cannot go and look at.
func TestThisMachinesInterfacesAreReadWithTheirAddresses(t *testing.T) {
	adapters := machineAdapters()

	if len(adapters) == 0 {
		t.Fatal("no interfaces were read from this machine, so no tailnet could ever be found on it")
	}
	loopback := false
	for _, a := range adapters {
		if a.name == "" {
			t.Errorf("an interface was read with no name: %+v", a)
		}
		for _, ip := range a.addrs {
			if ip.Is4In6() {
				t.Errorf("%s holds %s as a v4-in-v6 address, which no range this compares against contains",
					a.name, ip)
			}
			if ip.IsLoopback() {
				loopback = true
			}
		}
	}
	if !loopback {
		t.Error("no loopback address was read from any interface, so addresses are not being read at all")
	}
}
