// SPDX-License-Identifier: MIT

//go:build darwin || linux

package ovpntunnel

import (
	"context"
	"net"
	"testing"
)

// The socket really is put on the interface, and an interface that is not there is refused.
// It is the one part of this the operating system decides, so it is exercised against a real
// socket rather than against the call being made.
func TestASocketIsPutOnTheInterfaceItIsToldToAndRefusedOneThatIsNotThere(t *testing.T) {
	name := loopbackName(t)
	bind, err := through(name)
	if err != nil {
		t.Fatalf("send a connection out %s: %v", name, err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the dial to arrive: %v", err)
	}
	defer ln.Close()
	dialer := net.Dialer{Control: bind}
	conn, err := dialer.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial out %s: %v", name, err)
	}
	if err := conn.Close(); err != nil {
		t.Errorf("close the dialled connection: %v", err)
	}

	// A name no interface answers to must not become an ordinary dial: that is the failure
	// mode this exists to prevent, arriving as a success.
	absent, err := through("nosuchif0")
	if err == nil {
		_, err = (&net.Dialer{Control: absent}).DialContext(
			context.Background(), "tcp", ln.Addr().String())
	}
	if err == nil {
		t.Error("a dial out an interface that is not there was allowed to leave some other way")
	}
}
