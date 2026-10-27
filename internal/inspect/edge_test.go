// SPDX-License-Identifier: MIT

package inspect

// The answers this package gives when it is handed something it cannot read, and the one
// place it is allowed to swallow a failure: the recover that keeps a bug in a parser from
// taking the data path down with it.

import (
	"strings"
	"testing"
)

// A reader that reported the connection was for a name, without saying the name came off the
// wire, would send the user looking through the list of names they typed for one they never
// did.
func TestAMatchSaysWhereTheNameItMatchedCameFrom(t *testing.T) {
	cases := []struct {
		signal Signal
		want   string
	}{
		{SignalHandshake, "the connection is for bad.example, which is named by your own entries"},
		{SignalDestination, "the address is in bad.example, which is named by your own entries"},
		{SignalName, "bad.example is named by your own entries"},
	}
	for _, held := range cases {
		found := Finding{Signal: held.signal, Value: "bad.example", Source: "your own entries"}
		if got := found.Reason(); got != held.want {
			t.Errorf("a %s match reads %q, want %q", held.signal, got, held.want)
		}
	}
}

// A window with nothing in it is not a protocol, and naming one would put a name nobody sent
// on every connection that has yet to say anything.
func TestNothingIsNotAProtocol(t *testing.T) {
	if got := bannerOf(nil); got != "" {
		t.Errorf("an empty window is named %q, want nothing", got)
	}
}

// A head that was never parsed has no method, and answering with the first bytes of an empty
// array would be answering with a name nothing sent.
func TestAHeadThatWasNeverReadHasNoMethod(t *testing.T) {
	var head HTTPHead
	if got := head.Method(); got != "" {
		t.Errorf("an unread head reports method %q, want none", got)
	}
}

// A name longer than a name may be is refused rather than truncated: a truncated name is a
// different name, and matching a list against it would match the wrong entry.
func TestANameLongerThanANameMayBeIsRefused(t *testing.T) {
	label := strings.Repeat("a", 63)
	var msg []byte
	msg = append(msg, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// Five full labels plus separators run past the 255 bytes a name may hold.
	for range 5 {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00, 0x00, 0x01, 0x00, 0x01)

	if name, ok := DNSQuestion(msg); ok {
		t.Errorf("a name of %d bytes was read as %q, want a refusal", len(name), name)
	}
}

// A protocol offered in a form the parser does not keep must be stepped over, and one cut off
// by the end of the window is unfinished rather than a protocol.
func TestAProtocolCutOffByTheWindowIsUnfinished(t *testing.T) {
	var list helloWriter
	list.u8(maxALPNValue + 8) // longer than the parser keeps, and longer than what follows it
	list.raw([]byte("h2")...)
	var body helloWriter
	body.u16(len(list.b))
	body.raw(list.b...)

	if _, state := ParseClientHello(buildHello(extension(extALPN, body.b), 0)); state != Incomplete {
		t.Errorf("a protocol cut off by the end of the window read as %v, want Incomplete", state)
	}
}

// A name whose last label runs past what a name may hold is refused at the label rather than
// at the separator, which is a second length check and a second chance to walk off the end.
func TestANameWhoseLastLabelRunsPastTheEndIsRefused(t *testing.T) {
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// Three full labels, a short one, then a full one: the separator before the last still
	// fits, and the label behind it does not.
	for _, size := range []int{63, 63, 63, 10, 63} {
		msg = append(msg, byte(size))
		msg = append(msg, strings.Repeat("a", size)...)
	}
	msg = append(msg, 0x00, 0x00, 0x01, 0x00, 0x01)

	if name, ok := DNSQuestion(msg); ok {
		t.Errorf("a name of %d bytes was read as %q, want a refusal", len(name), name)
	}
}

// A line with a method and a target and nothing after them is not a request line. Reading one
// as a request would report a method for every line of a protocol that happens to start with
// a word this knows.
func TestARequestLineWithNoVersionIsNotARequest(t *testing.T) {
	cases := []string{
		"GET /path\r\n\r\n",          // no version at all
		"GET /path HTTP/9.9\r\n\r\n", // a version this does not know
	}
	for _, line := range cases {
		head, state := ParseHTTPHead([]byte(line))
		if state == Parsed {
			t.Errorf("%q read as a request for method %q, want it refused", line, head.Method())
		}
	}
}

// panicking is a report that fails the way a bug in the code that acts on a finding would.
func panicking(Handshake) bool { panic("a report that went wrong") }

// The one place this package swallows a failure, and the reason it is allowed to: these are
// bytes an attacker chooses, and the cost of being wrong about them has to be one connection
// carried uninspected rather than an interface that stops carrying traffic.
func TestAReportThatPanicsCarriesTheConnectionRatherThanEndingIt(t *testing.T) {
	stream := NewStream(StreamOptions{}, panicking)
	if stream.Up(helloForTest(t, "bad.example")) {
		t.Error("a connection was stopped by a report that never finished")
	}
	// The window is let go on the way out, so a report that panics on every connection cannot
	// pin one window per connection for as long as the process runs.
	if stream.win != nil {
		t.Error("the window was held after a report that panicked")
	}
	// And nothing is read again afterwards: the flow carries on uninspected rather than
	// panicking once per chunk.
	if stream.Up([]byte("more bytes")) {
		t.Error("a connection was stopped after inspection of it had already given up")
	}
	stream.Close()
}

func TestAReportThatPanicsCarriesTheDatagramFlowRatherThanEndingIt(t *testing.T) {
	flow := NewDatagrams(DatagramOptions{Report: panicking})
	if flow.Up(dnsQueryForTest("bad.example")) {
		t.Error("a datagram flow was stopped by a report that never finished")
	}
	if flow.Up(dnsQueryForTest("other.example")) {
		t.Error("a datagram flow was stopped after inspection of it had already given up")
	}
	// Closing is what the copy loop does with every flow, including this one.
	flow.Close()
}

// A banner that is only its prefix names nothing. A greeting is a prefix and then the text
// of the greeting, and the prefix on its own is bytes any protocol could open with: naming a
// connection from the prefix alone is naming it from noise, and a wrong name is the one
// thing the naming refuses to guess at.
func TestABannerThatIsOnlyItsPrefixNamesNothing(t *testing.T) {
	for _, win := range []string{"220 ", "220-", "SSH-2.0-", "SSH-1."} {
		if got := bannerOf([]byte(win)); got != "" {
			t.Errorf("%q read as %q, want no name at all", win, got)
		}
	}
}

// helloForTest is a client hello asking for one name.
func helloForTest(t *testing.T, name string) []byte {
	t.Helper()
	return buildHello(extension(extServerName, serverName(name)), 0)
}

// dnsQueryForTest is a query for one name, as a program with its own resolver sends it.
func dnsQueryForTest(name string) []byte {
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	start := 0
	for at := 0; at <= len(name); at++ {
		if at == len(name) || name[at] == '.' {
			msg = append(msg, byte(at-start))
			msg = append(msg, name[start:at]...)
			start = at + 1
		}
	}
	return append(msg, 0x00, 0x00, 0x01, 0x00, 0x01)
}
