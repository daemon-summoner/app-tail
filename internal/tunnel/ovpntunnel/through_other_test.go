// SPDX-License-Identifier: MIT

//go:build !darwin && !linux

package ovpntunnel

import (
	"strings"
	"testing"
)

// A platform with no way to put a socket on an interface says so rather than handing back
// a way that leaves by whatever route covers the destination: a dial that pretended to go
// out this connection would go out whichever one carries this machine's internet traffic.
func TestAPlatformThatCannotChooseAnInterfaceSaysSo(t *testing.T) {
	bind, err := through(loopbackName(t))

	if err == nil {
		t.Fatal("a platform with no way to choose an interface handed one out")
	}
	if !strings.Contains(err.Error(), "cannot send a connection out a chosen network interface") {
		t.Errorf("error = %v, want it to say this system cannot choose the interface", err)
	}
	if bind != nil {
		t.Error("a refusal came with a way to bind, which a caller could use as though it worked")
	}
}
