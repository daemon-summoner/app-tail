// SPDX-License-Identifier: MIT

package fabric

// The stack under the conditions the interface itself imposes: an interface that cannot be
// built, one that hands over packets one at a time, one carrying addresses of the other
// family, and one that stops accepting what the stack writes to it.

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// scriptedDevice is an interface entirely under the test's control: it hands over exactly
// the frames it was given and remembers how it was read.
type scriptedDevice struct {
	batch  int
	frames chan []byte
	events chan tun.Event

	done      chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	readWith []int
}

var _ tun.Device = (*scriptedDevice)(nil)

func newScriptedDevice(batch int) *scriptedDevice {
	return &scriptedDevice{
		batch:  batch,
		frames: make(chan []byte, 8),
		events: make(chan tun.Event, 1),
		done:   make(chan struct{}),
	}
}

func (d *scriptedDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	d.mu.Lock()
	d.readWith = append(d.readWith, len(bufs))
	d.mu.Unlock()
	select {
	case <-d.done:
		return 0, os.ErrClosed
	case frame := <-d.frames:
		sizes[0] = copy(bufs[0][offset:], frame)
		return 1, nil
	}
}

func (d *scriptedDevice) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }

func (d *scriptedDevice) MTU() (int, error)        { return testMTU, nil }
func (d *scriptedDevice) Name() (string, error)    { return "scripted", nil }
func (d *scriptedDevice) File() *os.File           { return nil }
func (d *scriptedDevice) Events() <-chan tun.Event { return d.events }
func (d *scriptedDevice) BatchSize() int           { return d.batch }
func (d *scriptedDevice) Close() error {
	d.closeOnce.Do(func() { close(d.done) })
	return nil
}

// buffers is how many packets at a time the stack asked this interface for.
func (d *scriptedDevice) buffers() []int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]int(nil), d.readWith...)
}

// quietStack builds a stack over the given interface whose handlers do nothing, for the
// tests that are about the interface rather than about the flows.
func quietStack(t *testing.T, dev tun.Device, mtu int) *netStack {
	t.Helper()
	s, err := newStack(dev, mtu, slog.New(slog.DiscardHandler),
		func(*tcp.ForwarderRequest) {}, func(*udp.ForwarderRequest) bool { return true })
	if err != nil {
		t.Fatalf("build the stack: %v", err)
	}
	t.Cleanup(func() {
		s.stop()
		dev.Close()
		s.wait()
		s.release()
	})
	return s
}

// An interface that cannot carry traffic has to be refused where it is offered. Building the
// stack anyway leaves the machine's routes pointing at something that will never answer, and
// the reason -- which is known here and nowhere later -- would be gone.
func TestAnInterfaceThatCannotCarryPacketsIsRefusedWithItsReason(t *testing.T) {
	dev := newScriptedDevice(1)
	t.Cleanup(func() { dev.Close() })

	cases := []struct {
		name string
		dev  tun.Device
		mtu  int
		says string
	}{
		{"no interface at all", nil, testMTU, "no network interface"},
		{"an interface carrying nothing", dev, 0, "0 bytes"},
		{"an interface of negative size", dev, -1, "-1 bytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := newStack(c.dev, c.mtu, slog.New(slog.DiscardHandler),
				func(*tcp.ForwarderRequest) {}, func(*udp.ForwarderRequest) bool { return true })
			if err == nil {
				s.stop()
				t.Fatalf("an interface %s was accepted", c.name)
			}
			if s != nil {
				t.Errorf("a refused interface still produced a stack")
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Errorf("refused with %q, want it to name %q", err, c.says)
			}
		})
	}
}

// An interface that will not say how many packets it hands over at once still has to be read
// one at a time: reading it with no buffers at all would spin on a read that can never return
// a packet, which is a stack that is up and carrying nothing.
func TestAnInterfaceThatClaimsNoBatchSizeIsStillReadOnePacketAtATime(t *testing.T) {
	dev := newScriptedDevice(0)
	quietStack(t, dev, testMTU)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if buffers := dev.buffers(); len(buffers) > 0 {
			if buffers[0] != 1 {
				t.Fatalf("read with room for %d packets, want 1", buffers[0])
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the interface was never read")
}

// Anything that is not an IP packet is dropped rather than guessed at, and dropping it does
// not stop the interface: a single malformed frame from the machine's own stack would
// otherwise take every private network down with it. That good packets do arrive through the
// same path is what the end-to-end tests above assert.
func TestAFrameThatIsNotAnIPPacketIsDroppedRatherThanStoppingTheInterface(t *testing.T) {
	dev := newScriptedDevice(1)
	s := quietStack(t, dev, testMTU)

	for _, frame := range [][]byte{
		{},                       // nothing at all
		{0x00},                   // a version this stack has never heard of
		{0xf0, 0x01, 0x02, 0x03}, // and one that is not a version number at all
	} {
		select {
		case dev.frames <- frame:
		case <-time.After(5 * time.Second):
			t.Fatal("the interface never took the frame")
		}
	}

	// Long enough for the reader to have taken all three and stopped if it were going to.
	select {
	case <-s.Done():
		t.Fatalf("a malformed frame stopped the interface: %v", s.Err())
	case <-time.After(200 * time.Millisecond):
	}
	if err := s.Err(); err != nil {
		t.Errorf("the interface reported %v, want nothing wrong", err)
	}
}

// A network addressed the other way is a network like any other. Carrying only one family
// would leave every IPv6-only private network unreachable in the one mode that is supposed
// to need no per-program setup.
func TestANetworkAddressedTheOtherWayIsCarriedToo(t *testing.T) {
	lab := &recordingCarrier{to: echoServer(t, "lab")}
	table := tableOf(t, at("tn_lab", "fd00:1ab::/64"))
	_, m := fabricUnder(t, table, carrierSet{"tn_lab": lab}, nil)

	conn, err := m.dialTCP(dialCtx(t), netip.MustParseAddrPort("[fd00:1ab::5]:5432"))
	if err != nil {
		t.Fatalf("dial [fd00:1ab::5]:5432: %v", err)
	}
	defer conn.Close()

	greeted(t, conn, "lab")
	if asks := lab.asks(); len(asks) != 1 || asks[0] != "tcp [fd00:1ab::5]:5432" {
		t.Errorf("the connection was asked for %v, want one dial to tcp [fd00:1ab::5]:5432", asks)
	}
}

// brittleDevice is an interface that stops accepting what is written to it, which is what a
// removed interface does to the packets already on their way out.
type brittleDevice struct {
	*wireEnd
	broken error
	// closeErr is what this interface reports when it is asked to go away, which is the one
	// failure the fabric has to pass back to its caller.
	closeErr error

	mu      sync.Mutex
	refused int
}

func (d *brittleDevice) Close() error {
	d.wireEnd.Close()
	return d.closeErr
}

func (d *brittleDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.mu.Lock()
	broken := d.broken
	if broken != nil {
		d.refused++
	}
	d.mu.Unlock()
	if broken != nil {
		return 0, broken
	}
	return d.wireEnd.Write(bufs, offset)
}

func (d *brittleDevice) breaks(err error) {
	d.mu.Lock()
	d.broken = err
	d.mu.Unlock()
}

// refusals is how many packets this interface has turned away.
func (d *brittleDevice) refusals() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.refused
}

// An interface that will not take what the stack writes to it is a failure the dashboard has
// to be told about: the machine's routes still point here, so every program reaching a
// private network fails from now on, and there is nothing else that would say why.
func TestAnInterfaceThatStopsTakingPacketsIsReportedRatherThanRetriedAround(t *testing.T) {
	hostEnd, machineEnd := wirePair()
	brittle := &brittleDevice{wireEnd: hostEnd}
	brittle.breaks(errors.New("the interface went away"))

	office := &recordingCarrier{to: echoServer(t, "office")}
	f, err := New(Options{
		Device:   brittle,
		Carriers: carrierSet{"tn_office": office},
		MTU:      testMTU,
		Table:    tableOf(t, at("tn_office", "10.1.0.0/16")),
		Logger:   slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("build the fabric: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	m := newMachine(t, machineEnd)

	// The dial provokes the stack's first answer, which is the write this interface refuses.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if conn, err := m.dialTCP(ctx, netip.MustParseAddrPort("10.1.2.3:5432")); err == nil {
		conn.Close()
		t.Fatal("a dial succeeded over an interface that takes no packets")
	}

	select {
	case <-f.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the interface never reported that it had stopped")
	}
	status := f.Status("wire")
	if status.Running {
		t.Error("an interface that stopped taking packets is still reported as running")
	}
	if !strings.Contains(status.Error, "the interface went away") {
		t.Errorf("reported %q, want it to carry the interface's own reason", status.Error)
	}

	// And it stopped rather than kept offering: an interface that has gone away is not
	// something to retry around, and a loop writing into it burns a core for as long as the
	// mode stays switched on.
	settled := brittle.refusals()
	time.Sleep(200 * time.Millisecond)
	if again := brittle.refusals(); again != settled {
		t.Errorf("the interface was written to %d more times after it had stopped", again-settled)
	}
}
