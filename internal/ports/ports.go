// SPDX-License-Identifier: MIT

// Package ports finds local ports that are actually free, by binding them.
package ports

import (
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/sellitus/app-tail/internal/config"
)

// scanLimit bounds how far past the preferred port a search will walk before
// falling back to letting the OS choose.
const scanLimit = 200

// bothStackAttempts bounds the search for an OS-assigned port that is free on TCP
// and UDP at once. Each attempt holds its rejected port, so the attempts are over
// distinct numbers rather than one number retried.
const bothStackAttempts = 20

// Free reports whether a port can be bound right now on the given address.
// It answers by binding, because a port can be occupied by any process on the
// machine, not just by this app's own forwards. A "both" forward needs the port
// free on each stack, so both binds must succeed.
func Free(protocol config.Protocol, bindAddr string, port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	addr := net.JoinHostPort(hostOrDefault(bindAddr), strconv.Itoa(port))
	for _, p := range protocol.Protocols() {
		if p == config.UDP {
			pc, err := net.ListenPacket("udp", addr)
			if err != nil {
				return false
			}
			pc.Close()
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return false
		}
		ln.Close()
	}
	return true
}

// Suggest returns a free local port for a new forward, preferring the target's own
// port number so `remote:8100` maps to `127.0.0.1:8100` when that is available.
// Ports that reserved reports as taken are skipped even if nothing is bound to
// them, so a suggestion never collides with a configured-but-stopped forward.
func Suggest(protocol config.Protocol, bindAddr string, preferred int, reserved func(int) bool) (int, error) {
	if reserved == nil {
		reserved = func(int) bool { return false }
	}
	if preferred >= 1 && preferred <= 65535 {
		for port := preferred; port < preferred+scanLimit && port <= 65535; port++ {
			if !reserved(port) && Free(protocol, bindAddr, port) {
				return port, nil
			}
		}
	}
	// Nothing near the preferred port was usable; ask the OS for any free one.
	for attempt := 0; attempt < 10; attempt++ {
		port, err := ephemeral(protocol, bindAddr)
		if err != nil {
			return 0, err
		}
		if !reserved(port) {
			return port, nil
		}
	}
	return 0, fmt.Errorf("could not find a free local port near %d", preferred)
}

// ephemeral asks the OS for a free port by binding port 0. For a "both" forward it
// keeps asking until a number one stack assigned is also free on the other, so the
// returned port is bindable on every stack the forward will use.
func ephemeral(protocol config.Protocol, bindAddr string) (int, error) {
	addr := net.JoinHostPort(hostOrDefault(bindAddr), "0")
	switch protocol {
	case config.UDP:
		pc, port, err := listenUDP(addr)
		if err != nil {
			return 0, err
		}
		pc.Close()
		return port, nil
	case config.TCP:
		ln, port, err := listenTCP(addr)
		if err != nil {
			return 0, err
		}
		ln.Close()
		return port, nil
	}
	// A port one stack assigns is often already bound on the other -- mDNS, DNS clients
	// and the tailnet itself hold plenty of UDP sockets in the same ephemeral range --
	// so a both forward asks again instead of failing on the first collision. Rejected
	// sockets stay open for the duration: closing one would let the OS hand the same
	// number straight back and the retries would all land on it.
	//
	// The attempts alternate which stack is asked. Windows assigns ephemeral ports in
	// sequence and carves reserved blocks of hundreds of consecutive ports out of one
	// stack at a time (Hyper-V and WSL take theirs from UDP), so a run of TCP-assigned
	// numbers can all sit inside a block UDP refuses. The UDP-assigned numbers come from
	// a cursor of their own, which such a block never captures.
	var rejected []io.Closer
	defer func() {
		for _, c := range rejected {
			c.Close()
		}
	}()
	for attempt := 0; attempt < bothStackAttempts; attempt++ {
		if attempt%2 == 0 {
			ln, port, err := listenTCP(addr)
			if err != nil {
				return 0, err
			}
			if Free(config.UDP, bindAddr, port) {
				ln.Close()
				return port, nil
			}
			rejected = append(rejected, ln)
			continue
		}
		pc, port, err := listenUDP(addr)
		if err != nil {
			return 0, err
		}
		if Free(config.TCP, bindAddr, port) {
			pc.Close()
			return port, nil
		}
		rejected = append(rejected, pc)
	}
	return 0, fmt.Errorf("no os-assigned port was free on both tcp and udp after %d attempts", bothStackAttempts)
}

// listenTCP binds an OS-assigned TCP port and returns the listener with its number. A
// variable so a test can stand in for the OS's port allocation, which no test controls.
var listenTCP = func(addr string) (net.Listener, int, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, 0, fmt.Errorf("find a free tcp port: %w", err)
	}
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		ln.Close()
		return nil, 0, fmt.Errorf("tcp listener on %s reported a %T, not a *net.TCPAddr", addr, ln.Addr())
	}
	return ln, tcp.Port, nil
}

// listenUDP binds an OS-assigned UDP port and returns the socket with its number.
var listenUDP = func(addr string) (net.PacketConn, int, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, 0, fmt.Errorf("find a free udp port: %w", err)
	}
	udp, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		pc.Close()
		return nil, 0, fmt.Errorf("udp listener on %s reported a %T, not a *net.UDPAddr", addr, pc.LocalAddr())
	}
	return pc, udp.Port, nil
}

func hostOrDefault(bindAddr string) string {
	if bindAddr == "" {
		return config.DefaultBindAddr
	}
	return bindAddr
}

// TargetPort extracts the port from a host:port target, for use as the preferred
// local port. It returns 0 when the target cannot be parsed.
func TargetPort(target string) int {
	_, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}
