// SPDX-License-Identifier: MIT

package udpsock

import (
	"net"
	"testing"
	"time"
)

// handleless is a PacketConn with no operating-system handle behind it. Embedding the
// interface gives it the methods a PacketConn needs and none of syscall.Conn's.
type handleless struct{ net.PacketConn }

// The ioctl is the whole function. A socket it cannot reach has to be refused with a
// sentence rather than accepted, because accepting it leaves a listener that dies the first
// time a client stops listening -- and nothing later would say why.
func TestASocketWithNoHandleIsRefusedRatherThanQuietlySkipped(t *testing.T) {
	err := SilenceUnreachable(handleless{})

	if err == nil {
		t.Fatal("a PacketConn carrying no operating-system handle was accepted")
	}
}

// Windows answers an ICMP Port Unreachable by queueing WSAECONNRESET on the socket that sent
// the datagram, including an unconnected listener, so one client that went away ends the read
// loop for everybody. This is the entire reason the package exists, so it is asserted against
// a real socket rather than a stand-in.
func TestOneClientRefusingADatagramDoesNotEndTheListener(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("open the listener: %v", err)
	}
	defer listener.Close()
	if err := SilenceUnreachable(listener); err != nil {
		t.Fatalf("silence the listener's unreachable reports: %v", err)
	}

	if _, err := listener.WriteTo([]byte("nobody is there"), closedPort(t)); err != nil {
		t.Fatalf("send to a port nothing is listening on: %v", err)
	}

	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("open the peer: %v", err)
	}
	defer peer.Close()
	// The refusal travels back before the datagram that has to survive it, so that a read
	// finding the queued error ahead of the datagram is the failure this reports.
	time.Sleep(250 * time.Millisecond)
	if _, err := peer.WriteTo([]byte("still here"), listener.LocalAddr()); err != nil {
		t.Fatalf("send to the listener: %v", err)
	}

	if err := listener.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set the read deadline: %v", err)
	}
	buf := make([]byte, 64)
	n, _, err := listener.ReadFrom(buf)
	if err != nil {
		t.Fatalf("the listener failed after one client refused a datagram: %v", err)
	}
	if got := string(buf[:n]); got != "still here" {
		t.Fatalf("the listener read %q, want %q", got, "still here")
	}
}

// closedPort is an address on this machine that nothing is listening on.
func closedPort(t *testing.T) net.Addr {
	t.Helper()
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("open a socket to take a port from: %v", err)
	}
	addr := probe.LocalAddr()
	if err := probe.Close(); err != nil {
		t.Fatalf("close the socket the port was taken from: %v", err)
	}
	return addr
}
