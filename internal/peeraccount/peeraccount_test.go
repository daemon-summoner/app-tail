// SPDX-License-Identifier: MIT

package peeraccount

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

// Two rows from a little-endian machine's /proc/net/tcp: 127.0.0.1:41000 -> 127.0.0.1:8377
// held by uid 1000, and the agent's side of the same connection held by uid 10001.
const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:A028 0100007F:20B9 01 00000000:00000000 00:00000000 00000000  1000        0 41231 1 0000000000000000 20 4 30 10 -1
   1: 0100007F:20B9 0100007F:A028 01 00000000:00000000 00:00000000 00000000 10001        0 41232 1 0000000000000000 20 4 30 10 -1
`

// An IPv4 connection to a dual-stack listener, as /proc/net/tcp6 lists it: ::ffff:127.0.0.1.
const procTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000100007F:A029 0000000000000000FFFF00000100007F:20B9 01 00000000:00000000 00:00000000 00000000   501        0 51 1 0000000000000000 20 4 30 10 -1
`

func TestTheSocketTableNamesTheAccountHoldingTheBrowsersEnd(t *testing.T) {
	server := netip.MustParseAddrPort("127.0.0.1:8377")
	uid, found, err := procTCPOwner([]byte(procTCP), netip.MustParseAddrPort("127.0.0.1:41000"), server, binary.LittleEndian)
	if err != nil || !found || uid != 1000 {
		t.Errorf("owner of 127.0.0.1:41000 = %d, %v, %v; want uid 1000", uid, found, err)
	}
	// The agent's own end of the connection has the ports the other way round and must not
	// be mistaken for the browser's.
	if _, found, _ := procTCPOwner([]byte(procTCP), netip.MustParseAddrPort("127.0.0.1:41001"), server, binary.LittleEndian); found {
		t.Error("a port nothing holds was found")
	}
	uid, found, err = procTCPOwner([]byte(procTCP6), netip.MustParseAddrPort("127.0.0.1:41001"), server, binary.LittleEndian)
	if err != nil || !found || uid != 501 {
		t.Errorf("owner of the mapped connection = %d, %v, %v; want uid 501", uid, found, err)
	}
}

func TestAGarbledSocketTableIsAnErrorNotAMatch(t *testing.T) {
	garbled := "header\n   0: XYZ:A028 0100007F:20B9 01 0 0 0 1000 0 1\n"
	if _, _, err := procTCPOwner([]byte(garbled), netip.MustParseAddrPort("127.0.0.1:41000"),
		netip.MustParseAddrPort("127.0.0.1:8377"), binary.LittleEndian); err == nil {
		t.Error("an unreadable address was skipped silently")
	}
}

func TestLsofOutputIsMatchedOnBothEndsOfTheConnection(t *testing.T) {
	out := []byte("p36723\ncPython\nf4\nn127.0.0.1:8377->127.0.0.1:53264\np36750\nf8\nn127.0.0.1:53264->127.0.0.1:8377\n")
	peer := netip.MustParseAddrPort("127.0.0.1:53264")
	if !lsofHasConnection(out, peer, netip.MustParseAddrPort("127.0.0.1:8377")) {
		t.Error("the browser's end of the connection was not found")
	}
	// Only the agent's own end, which names the peer as its remote side, does not count.
	agentOnly := []byte("p36723\nf4\nn127.0.0.1:8377->127.0.0.1:53264\n")
	if lsofHasConnection(agentOnly, peer, netip.MustParseAddrPort("127.0.0.1:8377")) {
		t.Error("the agent's own end was taken for the browser's")
	}
	if lsofHasConnection(out, peer, netip.MustParseAddrPort("127.0.0.1:9999")) {
		t.Error("a connection to another listener was accepted")
	}
	v6 := []byte("p1\nf3\nn[::1]:53264->[::1]:8377\n")
	if !lsofHasConnection(v6, netip.MustParseAddrPort("[::1]:53264"), netip.MustParseAddrPort("[::1]:8377")) {
		t.Error("an IPv6 loopback connection was not found")
	}
}

// A connection this test process makes to itself is this account's, on every platform.
func TestAConnectionFromThisAccountIsAccepted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
		close(accepted)
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, ok := <-accepted
	if !ok {
		t.Fatal("the listener accepted nothing")
	}
	defer server.Close()

	peer := netip.MustParseAddrPort(server.RemoteAddr().String())
	local := netip.MustParseAddrPort(server.LocalAddr().String())
	if err := Check(peer, local); err != nil {
		t.Errorf("Check(%v -> %v) = %v, want this account's own connection accepted", peer, local, err)
	}
	// Nothing holds a connection from this port to that listener.
	if err := Check(netip.AddrPortFrom(peer.Addr(), peer.Port()^1), local); err == nil && !skipsCheck {
		t.Error("a connection nobody holds was accepted")
	}
}

func TestAConnectionFromAnotherMachineIsNotLookedUp(t *testing.T) {
	if err := Check(netip.MustParseAddrPort("192.0.2.7:41000"), netip.MustParseAddrPort("127.0.0.1:8377")); err != nil {
		t.Errorf("a documentation-range peer was looked up: %v", err)
	}
}
