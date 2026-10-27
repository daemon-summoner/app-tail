// SPDX-License-Identifier: MIT

package ovpntunnel

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/hostnet"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// The interface openvpn opened is read out of what openvpn says, because nothing else on the
// machine knows which one it is. Reading the wrong line -- or reading a name out of a line
// that carries none -- would point every dial through this connection at somebody else's
// interface.
func TestTheInterfaceIsReadOutOfWhatOpenVPNSaidItOpened(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"utun device [utun6] opened", "utun6"},
		{"Opened utun device utun6", ""},
		{"TUN/TAP device tun0 opened", "tun0"},
		{"DCO device tun1 opened", "tun1"},
		{"DCO device  opened", ""},
		{"TUN/TAP device tun0 opened for the second time", "tun0"},
		{"Closing utun interface", ""},
		{"TUN/TAP device  opened", ""},
		{"do_ifconfig, ipv4=1, ipv6=0", ""},
		{"NOTE: Tried to delete pre-existing tun/tap instance", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got, found := hostnet.OpenVPNDeviceOpened(tt.line)
		if !found {
			got = ""
		}
		if got != tt.want {
			t.Errorf("%q named the interface %q, want %q", tt.line, got, tt.want)
		}
	}
}

// The connection reports the interface openvpn named, and stops reporting it when the program
// holding it is replaced. An interface name that outlived its program would send a reader --
// and every dial through this connection -- at whatever took the name next.
func TestTheConnectionReportsTheInterfaceOpenVPNOpened(t *testing.T) {
	runner := &fakeOpenVPN{}
	runner.speak = answering(runner, func(hostnet.OpenVPNRun) string {
		return ">LOG:1699999999,I,utun device [utun9] opened\n" + connectedLine
	})

	live := newTunnel(t, heldFixture(), CarryNone, runner)
	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	t.Cleanup(func() {
		if err := live.Close(); err != nil {
			t.Errorf("close the connection: %v", err)
		}
	})
	waitForState(t, live, tunnel.StateConnected)

	if got := live.Interface(); got != "utun9" {
		t.Errorf("the connection reports interface %q, want the one openvpn opened", got)
	}
}

// A dial through a connection with no interface is refused. Dialling anyway would bind this
// connection's address to a socket that leaves by whatever route covers the destination --
// which, once something else is carrying this machine's internet traffic, is that something
// else, reported to the caller as this connection.
func TestADialThroughAConnectionWithNoInterfaceIsRefused(t *testing.T) {
	live := newTunnel(t, heldFixture(), CarryNone, &fakeOpenVPN{})

	_, err := live.sendOut()

	if err == nil {
		t.Fatal("a connection with no interface handed out a way to send through it")
	}
	if !strings.Contains(err.Error(), "no network interface") {
		t.Errorf("error = %v, want it to say the connection has no interface yet", err)
	}
}

// loopbackName is what this machine calls its loopback interface.
func loopbackName(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("read this machine's interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return iface.Name
		}
	}
	t.Skip("this machine has no loopback interface")
	return ""
}
