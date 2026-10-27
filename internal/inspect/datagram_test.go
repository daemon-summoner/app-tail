// SPDX-License-Identifier: MIT

package inspect

// The datagram side, where every message stands alone. The difference from the stream is the
// whole of what is tested here: a resolver goes on asking different names and each one counts,
// while a QUIC flow says what it is once and says nothing else in the clear.

import "testing"

// A program that brought its own resolver and pointed it past app-tail's is the hole this
// closes, so every name it asks for has to be reported.
func TestEveryNameADatagramFlowAsksForIsReported(t *testing.T) {
	var counted counting
	flow := NewDatagrams(DatagramOptions{Report: counted.report})

	for _, name := range []string{"one.example", "two.example", "three.example"} {
		if flow.Up(dnsQuery(name)) {
			t.Fatalf("the query for %q asked for the flow to be stopped", name)
		}
	}
	if len(counted.seen) != 3 {
		t.Fatalf("three queries were reported %d times, want three", len(counted.seen))
	}
	for i, want := range []string{"one.example", "two.example", "three.example"} {
		if counted.seen[i].Name != want {
			t.Errorf("report %d named %q, want %q", i, counted.seen[i].Name, want)
		}
		if counted.seen[i].Protocol != ProtocolDNS {
			t.Errorf("report %d read as %q, want %q", i, counted.seen[i].Protocol, ProtocolDNS)
		}
	}
}

// A QUIC flow is named once. Everything after the first packet is encrypted, so examining it
// would be work spent on bytes that say nothing.
func TestAQUICFlowIsNamedOnceAndThenLeftAlone(t *testing.T) {
	var counted counting
	flow := NewDatagrams(DatagramOptions{Report: counted.report})

	initial := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x11, 0x22}
	for i := 0; i < 10; i++ {
		flow.Up(initial)
	}
	if len(counted.seen) != 1 {
		t.Fatalf("a QUIC flow was reported %d times, want once", len(counted.seen))
	}
	if got := counted.seen[0].Protocol; got != ProtocolQUIC {
		t.Errorf("the flow read as %q, want %q", got, ProtocolQUIC)
	}
	if counted.seen[0].Name != "" {
		t.Errorf("a QUIC flow was reported with the name %q, which is not readable here",
			counted.seen[0].Name)
	}
}

// A datagram that says nothing is dropped where it lands: it is not the start of anything the
// next one finishes, so keeping it would be keeping bytes nothing will ever read.
func TestADatagramThatSaysNothingIsNotReported(t *testing.T) {
	var counted counting
	flow := NewDatagrams(DatagramOptions{Report: counted.report})

	for _, datagram := range [][]byte{
		{0x01, 0x02, 0x03},
		[]byte("not a message at all"),
		nil,
		dnsQuery("real.example")[:6],
	} {
		if flow.Up(datagram) {
			t.Fatal("a datagram that says nothing asked for the flow to be stopped")
		}
	}
	if len(counted.seen) != 0 {
		t.Fatalf("datagrams that say nothing were reported %d times, want never", len(counted.seen))
	}

	// And the flow is still reading, because none of that was a verdict about what it is.
	flow.Up(dnsQuery("later.example"))
	if len(counted.seen) != 1 {
		t.Fatalf("a later query was reported %d times, want once", len(counted.seen))
	}
}

// Nothing coming back is read: a DNS answer repeats the question that was already reported on
// the way out.
func TestNothingComingBackToADatagramFlowIsRead(t *testing.T) {
	var counted counting
	flow := NewDatagrams(DatagramOptions{Report: counted.report})

	answer := dnsQuery("answered.example")
	answer[2] |= dnsFlagResponse
	if flow.Down(answer) {
		t.Error("an answer asked for the flow to be stopped")
	}
	if len(counted.seen) != 0 {
		t.Errorf("the far side was reported %d times, want never", len(counted.seen))
	}
}

// The decision belongs to the report, and a flow with no report reads nothing at all.
func TestADatagramFlowCarriesTheReportsDecision(t *testing.T) {
	counted := counting{stops: true}
	flow := NewDatagrams(DatagramOptions{Report: counted.report})
	if !flow.Up(dnsQuery("stopped.example")) {
		t.Error("a report asking for a stop was not carried back")
	}

	if NewDatagrams(DatagramOptions{}) != nil {
		t.Fatal("a flow with no report was handed back rather than nothing")
	}
	var none *Datagrams
	if none.Up(dnsQuery("nobody.example")) || none.Down(nil) {
		t.Error("a flow that reads nothing asked for the flow to be stopped")
	}
	none.Close()
}
