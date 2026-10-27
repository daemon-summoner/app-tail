// SPDX-License-Identifier: MIT

package forward

import (
	"net"
	"strconv"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
)

func bothToLocal(id string, port int, target string) config.Forward {
	return config.Forward{
		ID:         id,
		Name:       id,
		Direction:  config.ToLocal,
		Protocol:   config.Both,
		BindAddr:   "127.0.0.1",
		ListenPort: port,
		Target:     target,
		Enabled:    true,
	}
}

// startEchoBoth runs a TCP and a UDP echo server on the same loopback port, so a
// both-protocol forward pointed at one target name reaches both transports.
//
// The port comes from a reservation rather than a ":0" bind: holding the TCP
// listener says nothing about the same number on the UDP stack, which another
// process may already own.
func startEchoBoth(t *testing.T) string {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(freeBothPort(t)))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("start tcp echo on %s: %v", addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						conn.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("start udp echo on %s: %v", addr, err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], from); err != nil {
				return
			}
		}
	}()
	return addr
}

// freeBothPort returns a port free on both the TCP and UDP stacks right now, which a
// both forward needs so neither half fails to bind. Reservations already cover both
// stacks, so this is freePort under the name that says why it is called here.
func freeBothPort(t *testing.T) int {
	t.Helper()
	return freePort(t)
}

func TestBothForwardCarriesTCPAndUDPOnOnePort(t *testing.T) {
	echo := startEchoBoth(t)
	tn := newFakeTailnet()
	tn.route("dns-box:53", echo)

	m := newTestManager(t, tn)
	port := freeBothPort(t)
	m.Apply([]config.Forward{bothToLocal("f_both", port, "dns-box:53")})
	waitForStatus(t, m, "f_both", "the both forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	local := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	// The TCP half must carry traffic on the shared port.
	if got := roundTripTCP(t, local, "tcp payload"); got != "tcp payload" {
		t.Fatalf("tcp round trip returned %q, want %q", got, "tcp payload")
	}

	// The UDP half must carry traffic on the very same port.
	conn := dialUDP(t, local)
	if got := udpExchange(t, conn, "udp payload"); got != "udp payload" {
		t.Fatalf("udp round trip returned %q, want %q", got, "udp payload")
	}

	// Two exchanges of equal-length payloads, one per transport.
	wantBytes := int64(len("tcp payload") + len("udp payload"))

	// Both stacks report on the one forward: the udp session stays live, the tcp
	// connection is released, and bytes from both transports accumulate.
	//
	// The byte totals are part of the wait rather than only of the assertions below: a udp
	// session is registered before the datagram that opened it is counted (udp.go:189 then
	// :155), so the reply can reach this test in the window between the two.
	st := waitForStatus(t, m, "f_both", "both stacks to be accounted for", func(s Status) bool {
		return s.ActiveUDP == 1 && s.ActiveTCP == 0 &&
			s.BytesUp == wantBytes && s.BytesDown == wantBytes
	})
	if st.BytesUp != wantBytes {
		t.Errorf("BytesUp = %d, want %d (tcp + udp)", st.BytesUp, wantBytes)
	}
	if st.BytesDown != wantBytes {
		t.Errorf("BytesDown = %d, want %d (tcp + udp)", st.BytesDown, wantBytes)
	}
}

func TestStoppingABothForwardReleasesBothStacks(t *testing.T) {
	echo := startEchoBoth(t)
	tn := newFakeTailnet()
	tn.route("box:53", echo)

	m := newTestManager(t, tn)
	port := freeBothPort(t)
	fwd := bothToLocal("f_stopboth", port, "box:53")
	m.Apply([]config.Forward{fwd})
	waitForStatus(t, m, "f_stopboth", "the both forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	local := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if got := roundTripTCP(t, local, "before"); got != "before" {
		t.Fatalf("tcp round trip returned %q, want %q", got, "before")
	}
	conn := dialUDP(t, local)
	udpExchange(t, conn, "before")
	waitForStatus(t, m, "f_stopboth", "a live udp session", func(s Status) bool {
		return s.ActiveUDP == 1
	})

	fwd.Enabled = false
	m.Apply([]config.Forward{fwd})
	st := waitForStatus(t, m, "f_stopboth", "the forward to stop", func(s Status) bool {
		return s.State == StateStopped
	})
	if st.ActiveUDP != 0 {
		t.Errorf("ActiveUDP = %d after stop, want the table cleared", st.ActiveUDP)
	}

	// Both stacks must be released, or a restarted both forward would fail to bind.
	probeTCP, err := net.Listen("tcp", local)
	if err != nil {
		t.Fatalf("stopped both forward did not release its tcp port: %v", err)
	}
	probeTCP.Close()
	probeUDP, err := net.ListenPacket("udp", local)
	if err != nil {
		t.Fatalf("stopped both forward did not release its udp port: %v", err)
	}
	probeUDP.Close()
}
