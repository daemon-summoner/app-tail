// SPDX-License-Identifier: MIT

package hostnet

// The addresses an OpenVPN server hands a connection.
//
// A server is approved by its address and certificate authority, and everything it pushes
// about routes is dropped (route-nopull in Render). Its interface address is the one thing it
// still decides, because only the server knows which address in its network is this client's.
// That address carries a netmask, and the operating system routes the whole range the netmask
// names to the interface -- so a server handing out 203.0.113.7/1 would take half the internet
// without anyone approving a route. openvpn configures the interface itself, so the addresses
// are read off the interface once it says it has finished and held to the approvals like any
// route; a connection with one that is not approved is stopped, and the next start of it is
// refused with the approval it needs.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
)

// openvpnAddressCheck holds the addresses on connection id's interface to what an
// administrator approved, returning an error matching grants.ErrNeedsGrant for any that are not.
type openvpnAddressCheck func(id string, addrs []netip.Prefix) error

// openvpnConfigured is what openvpn writes once it has given its interface its addresses.
const openvpnConfigured = "Initialization Sequence Completed"

// OpenVPNDeviceOpened picks the interface openvpn opened out of one line of its output.
//
// openvpn names it in one of three shapes: `utun device [utun5] opened` where the operating
// system hands out its own utun devices, `DCO device tun0 opened` where Linux carries the data
// channel in the kernel, and `TUN/TAP device tun0 opened` everywhere else.
func OpenVPNDeviceOpened(text string) (string, bool) {
	if open := strings.IndexByte(text, '['); open >= 0 && strings.Contains(text, "device") {
		if end := strings.IndexByte(text[open:], ']'); end > 1 {
			name := text[open+1 : open+end]
			return name, strings.Contains(text[open+end:], "opened")
		}
	}
	rest, found := strings.CutPrefix(text, "TUN/TAP device ")
	if !found {
		rest, found = strings.CutPrefix(text, "DCO device ")
	}
	if !found {
		return "", false
	}
	name, _, found := strings.Cut(rest, " opened")
	if !found || name == "" || strings.ContainsAny(name, " \t") {
		return "", false
	}
	return name, true
}

// watchOpenVPNOutput reads what one connection's openvpn writes to its output, following the
// interface it opened and checking that interface's addresses each time openvpn says it has
// configured it, which it does again after every reconnect. stop is called for a connection
// whose addresses are refused or cannot be read.
//
// The lines themselves are not logged: at this verbosity they include what the server pushed,
// which can carry a session token. Everything is read to the end either way, because openvpn
// stalls once a pipe nobody reads is full.
func (l *Local) watchOpenVPNOutput(id string, r io.Reader, stop func()) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), 64<<10)
	device := ""
	for scanner.Scan() {
		text := scanner.Text()
		if name, found := OpenVPNDeviceOpened(text); found {
			device = name
			continue
		}
		if !strings.Contains(text, openvpnConfigured) {
			continue
		}
		if err := l.checkOpenVPNAddresses(id, device); err != nil {
			l.logf("openvpn %s: stopping the connection: %v", id, err)
			stop()
		}
	}
	if err := scanner.Err(); err != nil {
		l.logf("openvpn %s: could not read what the connection reported, so the addresses its server "+
			"hands out can no longer be checked; stopping it: %v", id, err)
		stop()
		if _, err := io.Copy(io.Discard, r); err != nil {
			l.logf("openvpn %s: %v", id, err)
		}
	}
}

// checkOpenVPNAddresses holds the addresses on device to the approvals. A process that is not
// serving a helper session approves nothing on anyone's behalf and checks nothing.
func (l *Local) checkOpenVPNAddresses(id, device string) error {
	if l.openvpnAddrs == nil {
		return nil
	}
	if device == "" {
		return fmt.Errorf("openvpn did not say which interface it opened, so the addresses its server " +
			"handed out cannot be checked")
	}
	addrs, err := l.interfaceAddrs(device)
	if err != nil {
		return err
	}
	return l.openvpnAddrs(id, addrs)
}

// interfacePrefixes is every address on the named interface with its prefix length, leaving out
// link-local ones: macOS gives every utun one of its own.
func interfacePrefixes(name string) ([]netip.Prefix, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("find the interface %s openvpn opened: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("read the addresses of %s: %w", name, err)
	}
	return addrPrefixes(addrs), nil
}
