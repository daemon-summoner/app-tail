// SPDX-License-Identifier: MIT

// Package testport hands out loopback ports that tests can bind a moment later.
//
// Tests cannot use a ":0" bind for this: the port has to be known before the code
// under test binds it, so the probe socket must be closed first, and ":0" draws
// from the OS ephemeral range -- the same pool every other ":0" listener and
// outbound connection in the suite draws from. Under parallel test processes the
// kernel hands the same number to two of them and one loses the race.
//
// Reserving from a fixed range below every platform's ephemeral floor takes the
// kernel out of the contest; claiming a band of that range with a held listener
// keeps concurrent `go test` processes off each other's numbers.
package testport

import (
	"fmt"
	"net"
	"sync"
)

// The reservable range sits below the lowest ephemeral floor of any platform the
// suite runs on (Linux 32768, macOS/Windows 49152), so the kernel never allocates
// into it on its own. Each band's first port is the sentinel that claims it, so a
// band yields bandSize-1 reservations -- ample for `-count` reruns of every package.
const (
	rangeLo   = 20000
	rangeHi   = 32000
	bandSize  = 250
	bandCount = (rangeHi - rangeLo) / bandSize
)

var (
	mu sync.Mutex

	// claim holds this process's band open for the whole run and is deliberately
	// never closed: the kernel arbitrates the sentinel bind, so two concurrent test
	// processes can never work out of one band, and a crashed process releases its
	// band the moment it dies. Nothing here needs a lock file or a liveness check.
	claim          net.Listener
	bandLo, bandHi int
	next           int

	handed = map[int]bool{}
)

// claimBandLocked binds the sentinel port of the first band no other process holds.
// The caller must hold mu.
func claimBandLocked() error {
	if claim != nil {
		return nil
	}
	for band := 0; band < bandCount; band++ {
		sentinel := rangeLo + band*bandSize
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", sentinel))
		if err != nil {
			continue
		}
		claim = ln
		bandLo, bandHi = sentinel+1, sentinel+bandSize
		next = bandLo
		return nil
	}
	return fmt.Errorf("every port band in %d-%d is held by another process; "+
		"at most %d test processes can run concurrently", rangeLo, rangeHi, bandCount)
}

// Reserve returns a loopback port that is bindable for both TCP and UDP, and that
// this process will not return again.
//
// Both protocols are probed even for a TCP-only caller so that a forward carrying
// both protocols on one port cannot half-collide, and so a TCP reservation and a
// UDP reservation can never name the same port.
func Reserve() (int, error) {
	mu.Lock()
	defer mu.Unlock()

	if err := claimBandLocked(); err != nil {
		return 0, err
	}

	for scanned := 0; scanned < bandHi-bandLo; scanned++ {
		port := next
		next++
		if next >= bandHi {
			next = bandLo
		}
		if handed[port] {
			continue
		}
		if !bindable(port) {
			// Something outside this process holds it; never offer it again.
			handed[port] = true
			continue
		}
		handed[port] = true
		return port, nil
	}
	return 0, fmt.Errorf("no free port left in band %d-%d after %d reservations",
		bandLo, bandHi, len(handed))
}

// bindable reports whether port is currently free for both TCP and UDP on loopback.
func bindable(port int) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	if err := ln.Close(); err != nil {
		return false
	}

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return false
	}
	return pc.Close() == nil
}
