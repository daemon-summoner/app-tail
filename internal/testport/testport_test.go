// SPDX-License-Identifier: MIT

package testport

import (
	"fmt"
	"net"
	"testing"
)

// Every reservation has to be usable and unique: a repeat or an occupied number is
// exactly the flake this package exists to remove from the suite.
func TestReserveHandsOutDistinctBindablePorts(t *testing.T) {
	const want = 50

	seen := make(map[int]bool, want)
	for i := 0; i < want; i++ {
		port, err := Reserve()
		if err != nil {
			t.Fatalf("Reserve #%d: %v", i, err)
		}
		if seen[port] {
			t.Fatalf("Reserve returned port %d twice", port)
		}
		seen[port] = true

		if port < rangeLo || port >= rangeHi {
			t.Errorf("port %d is outside the reservable range %d-%d", port, rangeLo, rangeHi)
		}
		if port < bandLo || port >= bandHi {
			t.Errorf("port %d is outside this process's band %d-%d", port, bandLo, bandHi)
		}

		addr := fmt.Sprintf("127.0.0.1:%d", port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("reserved port %d is not bindable on tcp: %v", port, err)
		}
		ln.Close()
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			t.Fatalf("reserved port %d is not bindable on udp: %v", port, err)
		}
		pc.Close()
	}
}

// A number this process has not handed out may still be taken by something else on
// the machine. Reserve must probe rather than assume its band is untouched.
func TestReserveSkipsAPortSomethingElseHolds(t *testing.T) {
	if _, err := Reserve(); err != nil {
		t.Fatalf("claim a band: %v", err)
	}

	mu.Lock()
	occupied := next
	mu.Unlock()

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", occupied))
	if err != nil {
		t.Skipf("could not occupy port %d to set the test up: %v", occupied, err)
	}
	defer ln.Close()

	port, err := Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if port == occupied {
		t.Fatalf("Reserve returned port %d while a listener was holding it", occupied)
	}
}

// A band that runs dry must say so. Wrapping around and re-offering a number a
// caller already holds would put the collision back while looking like success.
func TestReserveFailsWhenTheBandRunsDry(t *testing.T) {
	if _, err := Reserve(); err != nil {
		t.Fatalf("claim a band: %v", err)
	}

	const tiny = 3
	mu.Lock()
	savedLo, savedHi, savedNext := bandLo, bandHi, next
	bandLo, bandHi = next, next+tiny
	mu.Unlock()
	defer func() {
		mu.Lock()
		bandLo, bandHi, next = savedLo, savedHi, savedNext
		mu.Unlock()
	}()

	seen := make(map[int]bool, tiny)
	for i := 0; i < tiny*2; i++ {
		port, err := Reserve()
		if err != nil {
			if len(seen) != tiny {
				t.Fatalf("a band of %d yielded %d ports before reporting exhaustion", tiny, len(seen))
			}
			return
		}
		if seen[port] {
			t.Fatalf("Reserve returned port %d a second time", port)
		}
		seen[port] = true
	}
	t.Fatalf("Reserve never reported the band exhausted; it handed out %d ports from a band of %d",
		len(seen), tiny)
}

// The band claim is what keeps concurrent test processes off each other's numbers.
// If the sentinel is ever released, two `go test` processes can work out of one band
// and the port collisions this package removes come straight back.
func TestBandSentinelStaysHeld(t *testing.T) {
	if _, err := Reserve(); err != nil {
		t.Fatalf("claim a band: %v", err)
	}

	sentinel := bandLo - 1
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", sentinel))
	if err == nil {
		ln.Close()
		t.Fatalf("sentinel port %d is not held; another process could claim this band", sentinel)
	}
}
