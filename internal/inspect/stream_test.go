// SPDX-License-Identifier: MIT

package inspect

// The window's own contract, which is the half of this package that is not a parser: one
// verdict per connection, the window let go the moment it is reached, and a chunk after that
// costing one comparison.

import (
	"strings"
	"testing"
)

// counting is a report that records what it was told and how often.
type counting struct {
	seen  []Handshake
	stops bool
}

func (c *counting) report(h Handshake) bool {
	c.seen = append(c.seen, h)
	return c.stops
}

// A connection is reported once. A second report on the same connection would be a second
// detection of the same thing, and every count downstream would be wrong.
func TestAConnectionIsReportedOnceHoweverManyChunksFollow(t *testing.T) {
	var counted counting
	stream := NewStream(StreamOptions{}, counted.report)

	win := capture(t, "clienthello-curl.hex")
	stream.Up(win)
	for i := 0; i < 100; i++ {
		if stream.Up([]byte(strings.Repeat("x", 4096))) {
			t.Fatal("a chunk after the verdict asked for the connection to be stopped")
		}
	}
	stream.Close()

	if len(counted.seen) != 1 {
		t.Fatalf("the connection was reported %d times, want once", len(counted.seen))
	}
	if counted.seen[0].Name != "example.test" {
		t.Errorf("the one report named %q, want %q", counted.seen[0].Name, "example.test")
	}
}

// The window goes back at the verdict rather than at the close. That ordering is the defence
// against a client opening thousands of connections and sending one byte down each, so it is
// asserted rather than assumed.
func TestTheWindowIsLetGoAtTheVerdictNotAtTheClose(t *testing.T) {
	var counted counting
	stream := NewStream(StreamOptions{}, counted.report)

	stream.Up([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
	if len(counted.seen) != 1 {
		t.Fatalf("a banner was reported %d times, want once", len(counted.seen))
	}
	if stream.win != nil {
		t.Error("the window is still held after the verdict")
	}
	if !stream.done {
		t.Error("the stream is still reading after the verdict")
	}

	// And closing twice is safe, because a stream that reached its verdict has already let go.
	stream.Close()
	stream.Close()
}

// A client that sends one byte at a time must not make the parser walk the window once per
// byte, and must still get a verdict rather than an open window held forever.
func TestAClientDrippingBytesGetsAVerdictWithoutAWalkPerByte(t *testing.T) {
	var counted counting
	stream := NewStream(StreamOptions{}, counted.report)

	win := capture(t, "clienthello-go.hex")
	for at := 0; at < len(win); at++ {
		stream.Up(win[at : at+1])
	}
	if len(counted.seen) != 1 {
		t.Fatalf("a dripped hello was reported %d times, want once", len(counted.seen))
	}
	// The reads are used up long before the hello finishes, so the answer is the honest one
	// for what was read: a TLS connection whose name never arrived in time.
	if got := counted.seen[0].Protocol; got != ProtocolTLS {
		t.Errorf("a dripped hello read as %q, want %q", got, ProtocolTLS)
	}
	if stream.win != nil {
		t.Error("the window is still held after the verdict")
	}
}

// A window that filled with something nothing recognises is a verdict, not a wait: the
// connection is carried and the window goes back.
func TestAFullWindowOfSomethingUnknownEndsInAVerdict(t *testing.T) {
	var counted counting
	stream := NewStream(StreamOptions{}, counted.report)

	stream.Up([]byte(strings.Repeat("\xa5", windowSize)))
	if len(counted.seen) != 1 {
		t.Fatalf("a full window was reported %d times, want once", len(counted.seen))
	}
	if got := counted.seen[0].Protocol; got != "" {
		t.Errorf("bytes nothing recognises read as %q, want no name", got)
	}
	if stream.win != nil {
		t.Error("the window is still held after the verdict")
	}
}

// Nothing is read from the far side, so nothing the far side sends can stop a connection.
func TestNothingComingBackIsEverRead(t *testing.T) {
	var counted counting
	stream := NewStream(StreamOptions{}, counted.report)
	if stream.Down(capture(t, "clienthello-curl.hex")) {
		t.Error("bytes from the far side asked for the connection to be stopped")
	}
	if len(counted.seen) != 0 {
		t.Errorf("the far side was reported %d times, want never", len(counted.seen))
	}
}

// A caller that has not decided must not end up holding a window it never reads.
func TestAStreamWithNothingToReportReadsNothing(t *testing.T) {
	var stream *Stream
	if NewStream(StreamOptions{}, nil) != nil {
		t.Fatal("a stream with no report was handed back rather than nothing")
	}
	// And the nil stream is safe on every method, because that is what a caller gets back.
	if stream.Up([]byte("GET / HTTP/1.1\r\n\r\n")) || stream.Down(nil) {
		t.Error("a stream that reads nothing asked for the connection to be stopped")
	}
	stream.Close()
}

// The report decides, and the stream carries that decision back to the copy loop that will
// act on it.
func TestWhatTheReportSaysIsWhatTheStreamAnswers(t *testing.T) {
	counted := counting{stops: true}
	stream := NewStream(StreamOptions{}, counted.report)
	if !stream.Up([]byte("GET / HTTP/1.1\r\nHost: stopped.example\r\n\r\n")) {
		t.Fatal("a report asking for a stop was not carried back")
	}
	// And once the verdict is in, nothing further is asked or answered.
	if stream.Up([]byte("GET / HTTP/1.1\r\nHost: stopped.example\r\n\r\n")) {
		t.Error("a chunk after the verdict asked for the connection to be stopped")
	}
}

// The fingerprint is a switch of its own, because it is the one field here that describes the
// program rather than the destination.
func TestTheFingerprintIsOnlyComputedWhenItIsAskedFor(t *testing.T) {
	win := capture(t, "clienthello-openssl.hex")

	var off counting
	NewStream(StreamOptions{}, off.report).Up(win)
	if len(off.seen) != 1 || off.seen[0].Fingerprint != "" {
		t.Errorf("with fingerprinting off the report carried %q", off.seen[0].Fingerprint)
	}

	var on counting
	NewStream(StreamOptions{Fingerprint: true}, on.report).Up(win)
	if len(on.seen) != 1 || on.seen[0].Fingerprint == "" {
		t.Error("with fingerprinting on the report carried no fingerprint")
	}
}
