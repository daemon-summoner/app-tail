// SPDX-License-Identifier: MIT

// Package peeraccount tells whether a TCP connection to one of the agent's own listeners
// comes from a process running as the agent's account.
//
// A dashboard sign-in link is handed to the browser on a command line, and on macOS and
// Linux every account can read every other account's command lines. Whoever reads the link
// first could trade it for a session, so a link that crossed a command line is only
// redeemed for a connection this account's own processes hold.
package peeraccount

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ErrOtherAccount reports a connection from this machine that no process of this account
// holds.
var ErrOtherAccount = errors.New("the connection comes from a program running as another account on this machine")

// Check returns nil when the connection from peer to server is held by a process of this
// account, or comes from another machine. A connection from another machine has no command
// line here to have read the link from; the dashboard only listens on loopback, so one
// arrives only through a proxy the person set up.
func Check(peer, server netip.AddrPort) error {
	local, err := onThisMachine(peer.Addr())
	if err != nil {
		return err
	}
	if !local {
		return nil
	}
	return ownedByThisAccount(peer, server)
}

// onThisMachine reports whether addr is loopback or one of this machine's own addresses: a
// process here can connect from either.
func onThisMachine(addr netip.Addr) (bool, error) {
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return true, nil
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, fmt.Errorf("read this machine's addresses: %w", err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if own, ok := netip.AddrFromSlice(ipnet.IP); ok && own.Unmap() == addr {
			return true, nil
		}
	}
	return false, nil
}

// procTCPOwner finds the uid of the socket whose local end is peer and remote end is server
// in a /proc/net/tcp or /proc/net/tcp6 table. Addresses there are hexadecimal in the
// kernel's byte order, one 32-bit word at a time; ports are big-endian hexadecimal.
func procTCPOwner(table []byte, peer, server netip.AddrPort, order binary.ByteOrder) (uint32, bool, error) {
	sc := bufio.NewScanner(bytes.NewReader(table))
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 {
			continue
		}
		local, err := parseProcAddr(fields[1], order)
		if err != nil {
			return 0, false, err
		}
		remote, err := parseProcAddr(fields[2], order)
		if err != nil {
			return 0, false, err
		}
		if !sameEnd(local, peer) || !sameEnd(remote, server) {
			continue
		}
		uid, err := strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			return 0, false, fmt.Errorf("read the owner of %s: %w", fields[1], err)
		}
		return uint32(uid), true, nil
	}
	return 0, false, sc.Err()
}

func parseProcAddr(field string, order binary.ByteOrder) (netip.AddrPort, error) {
	host, port, ok := strings.Cut(field, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("%q is not an address and port", field)
	}
	raw, err := hex.DecodeString(host)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, fmt.Errorf("%q is not an address", host)
	}
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(raw[i:], order.Uint32(raw[i:]))
	}
	addr, _ := netip.AddrFromSlice(raw)
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%q is not a port", port)
	}
	return netip.AddrPortFrom(addr, uint16(p)), nil
}

// lsofHasConnection reports whether lsof's -F output lists a socket whose local end is peer
// and remote end is server.
func lsofHasConnection(out []byte, peer, server netip.AddrPort) bool {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		name, ok := strings.CutPrefix(sc.Text(), "n")
		if !ok {
			continue
		}
		from, to, ok := strings.Cut(name, "->")
		if !ok {
			continue
		}
		local, err := netip.ParseAddrPort(from)
		if err != nil {
			continue
		}
		remote, err := netip.ParseAddrPort(to)
		if err != nil {
			continue
		}
		if sameEnd(local, peer) && sameEnd(remote, server) {
			return true
		}
	}
	return false
}

// sameEnd compares two socket ends, an IPv4 address and its IPv6-mapped form being one.
func sameEnd(a, b netip.AddrPort) bool {
	return a.Port() == b.Port() && a.Addr().Unmap() == b.Addr().Unmap()
}
