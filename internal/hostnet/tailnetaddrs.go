// SPDX-License-Identifier: MIT

package hostnet

// What a machine looks like when a tailnet is already up on it.
//
// The thing that cannot be shared is not an installed client or a running process: it is an
// interface holding the tailnet's addresses, because that interface also holds the routes for
// them and the resolver configuration that answers for the tailnet's names. Two of those on one
// machine is the failure, and one client sitting installed and disconnected is not.

import (
	"net"
	"net/netip"
)

// tailnetRanges are the address ranges a tailnet hands out. An interface carrying one is
// carrying a tailnet.
var tailnetRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

// tailnetAddr reports whether ip is one a tailnet handed out.
func tailnetAddr(ip netip.Addr) bool {
	for _, prefix := range tailnetRanges {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// adapter is the part of a network interface the conflict decision reads.
type adapter struct {
	name  string
	up    bool
	addrs []netip.Addr
}

// adapterFrom reads one interface. An interface whose addresses cannot be read is carried
// with none, so it can still be recognised by name and reported as idle rather than
// dropped from the scan entirely.
func adapterFrom(iface net.Interface) adapter {
	a := adapter{name: iface.Name, up: iface.Flags&net.FlagUp != 0}
	addrs, err := iface.Addrs()
	if err != nil {
		return a
	}
	for _, addr := range addrs {
		prefix, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(prefix.IP)
		if !ok {
			continue
		}
		a.addrs = append(a.addrs, ip.Unmap())
	}
	return a
}

// machineAdapters is every interface on this machine, in the form the conflict decision reads.
//
// A machine that could not be read produces none. Reporting a conflict from a failed read would
// block the mode on a failure that says nothing about whether one exists, and creating the
// interface reports its own failure either way.
func machineAdapters() []adapter {
	ifaces, err := net.Interfaces()
	if err != nil {
		return []adapter{}
	}
	adapters := make([]adapter, 0, len(ifaces))
	for _, iface := range ifaces {
		adapters = append(adapters, adapterFrom(iface))
	}
	return adapters
}

// tailnetHolder names the interface already carrying a tailnet and the address it holds, other
// than the one app-tail opened itself.
//
// own is excluded because app-tail's own interface holds exactly the same kind of address: without
// that exclusion the app would read its own tailnet as somebody else's the moment anything asked
// this machine what it can do, and refuse the mode it is already running.
func tailnetHolder(adapters []adapter, own string) (string, netip.Addr, bool) {
	for _, a := range adapters {
		if !a.up || (own != "" && a.name == own) {
			continue
		}
		for _, ip := range a.addrs {
			if tailnetAddr(ip) {
				return a.name, ip, true
			}
		}
	}
	return "", netip.Addr{}, false
}
