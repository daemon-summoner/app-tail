// SPDX-License-Identifier: MIT

package dnsfwd

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

// A device that answers for an address it is not is the whole failure this detects: the
// user picks Cloudflare, the router answers instead, and nothing about the machine looks
// wrong. Without this the switch reports success while resolving through the thing it was
// switched away from.
func TestSomethingAnsweringForAnAddressNothingLivesAtIsInterception(t *testing.T) {
	probe, udp, _ := servePlain(t, "203.0.113.7")

	intercepted, err := plainDNSIntercepted(context.Background(), probe)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !intercepted {
		t.Fatal("an answer came back from an address nothing lives at and the probe called the network clean")
	}
	if udp.Load() == 0 {
		t.Fatal("the probe reported interception without asking anything")
	}
}

func TestAnAddressThatAnswersNothingIsNotInterception(t *testing.T) {
	// A bound-then-closed port is an address on this machine that nothing answers for,
	// which is what an unreachable resolver looks like from here.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	probe := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))

	intercepted, err := plainDNSIntercepted(context.Background(), probe)
	if intercepted {
		t.Fatal("nothing answered and the probe reported interception")
	}
	if err == nil {
		t.Fatal("the probe found nothing and reported no reason why")
	}
}

// The probe must not answer "intercepted" to a packet that is not an answer to what it
// asked, or every network with a device that sends anything at all on port 53 reads as
// hostile.
func TestAPacketThatIsNotTheAnswerIsNotInterception(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	port := pc.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, maxUDPAnswer)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo([]byte("not a DNS message at all"), from)
		}
	}()

	probe := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
	intercepted, err := plainDNSIntercepted(context.Background(), probe)
	if intercepted {
		t.Fatal("a packet that answers nothing was read as interception")
	}
	if err == nil {
		t.Fatal("the probe gave up without saying why")
	}
}
