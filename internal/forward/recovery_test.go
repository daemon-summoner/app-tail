// SPDX-License-Identifier: MIT

package forward

import (
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

// A forward that recorded a dial failure must clear that message once the target
// comes back, so a transient outage does not leave a stale error stuck in the UI.
func TestForwardClearsAStaleErrorAfterTheTargetRecovers(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.failDials(errors.New("connection refused by ACL"))

	m := newTestManager(t, tn)
	port := freePort(t)
	m.Apply([]config.Forward{tcpToLocal(t, "f_recover", port, "box:22")})
	waitForStatus(t, m, "f_recover", "the forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	local := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	// First connection cannot reach the target, so its reason surfaces on the forward.
	if conn, err := net.DialTimeout("tcp", local, 3*time.Second); err == nil {
		conn.Close()
	}
	waitForStatus(t, m, "f_recover", "the dial failure to be recorded", func(s Status) bool {
		return s.Error != "" && s.State == StateRunning
	})

	// The target recovers: dials now succeed and resolve to the echo server.
	tn.route("box:22", echo)
	tn.failDials(nil)

	// A connection that gets through must wipe the stale error.
	if got := roundTripTCP(t, local, "back online"); got != "back online" {
		t.Fatalf("round trip after recovery returned %q, want %q", got, "back online")
	}
	st := waitForStatus(t, m, "f_recover", "the stale error to clear", func(s Status) bool {
		return s.Error == "" && s.State == StateRunning
	})
	if st.Error != "" {
		t.Errorf("Error = %q after a successful connection, want it cleared", st.Error)
	}
}
