// SPDX-License-Identifier: MIT

package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// fakeTunnel is a registered thing with an id. The registry never touches the network
// methods, so they are here only to satisfy the interface.
type fakeTunnel struct {
	id       string
	closeErr error
	closed   int
}

func (f *fakeTunnel) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not dialled in these tests")
}
func (f *fakeTunnel) Listen(string, uint16) (net.Listener, error) {
	return nil, errors.New("not listened on in these tests")
}
func (f *fakeTunnel) ListenPacket(string, uint16) (net.PacketConn, error) {
	return nil, errors.New("not listened on in these tests")
}
func (f *fakeTunnel) ID() string                  { return f.id }
func (f *fakeTunnel) Kind() Kind                  { return KindTailscale }
func (f *fakeTunnel) Start(context.Context) error { return nil }
func (f *fakeTunnel) Close() error                { f.closed++; return f.closeErr }
func (f *fakeTunnel) Status() Status              { return Status{State: StateConnected} }
func (f *fakeTunnel) Events() <-chan struct{}     { return nil }
func (f *fakeTunnel) Routes(context.Context) ([]netip.Prefix, error) {
	return nil, nil
}
func (f *fakeTunnel) Addrs() []netip.Addr { return nil }

// Two tunnels under one id means whichever was registered last silently receives the
// traffic meant for the other, and nothing anywhere reports it. Refusing is the only
// outcome that surfaces the mistake.
func TestASecondTunnelCannotTakeAnIDAlreadyInUse(t *testing.T) {
	r := NewRegistry()
	first := &fakeTunnel{id: "tn_a"}
	if err := r.Add(first); err != nil {
		t.Fatalf("adding the first: %v", err)
	}

	err := r.Add(&fakeTunnel{id: "tn_a"})

	if err == nil || !strings.Contains(err.Error(), "tn_a") {
		t.Fatalf("error = %v, want a refusal naming the id", err)
	}
	held, ok := r.Get("tn_a")
	if !ok || held != Tunnel(first) {
		t.Error("the second registration displaced the first")
	}
}

func TestATunnelWithNoIDIsRefused(t *testing.T) {
	r := NewRegistry()

	if err := r.Add(&fakeTunnel{}); err == nil {
		t.Fatal("a tunnel with no id was registered, so nothing could ever address it")
	}
	if r.Len() != 0 {
		t.Errorf("Len = %d, want the refused tunnel not counted", r.Len())
	}
}

// Every surface lists connections in the order they were declared. Reading them out of a
// map alone would reorder the list on every poll, which reads as the list changing.
func TestConnectionsComeBackInTheOrderTheyWereAdded(t *testing.T) {
	r := NewRegistry()
	for _, id := range []string{"tn_c", "tn_a", "tn_b"} {
		if err := r.Add(&fakeTunnel{id: id}); err != nil {
			t.Fatalf("adding %s: %v", id, err)
		}
	}

	var got []string
	for _, held := range r.All() {
		got = append(got, held.ID())
	}

	want := []string{"tn_c", "tn_a", "tn_b"}
	if len(got) != len(want) {
		t.Fatalf("All() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("All() = %v, want %v", got, want)
		}
	}
}

// Removing hands the tunnel back rather than closing it, because a caller replacing one
// wants the old closed only after the new is in place.
func TestRemovingHandsTheTunnelBackStillOpen(t *testing.T) {
	r := NewRegistry()
	held := &fakeTunnel{id: "tn_a"}
	if err := r.Add(held); err != nil {
		t.Fatalf("adding: %v", err)
	}

	got, ok := r.Remove("tn_a")

	if !ok || got != Tunnel(held) {
		t.Fatalf("Remove returned (%v, %v), want the registered tunnel", got, ok)
	}
	if held.closed != 0 {
		t.Error("Remove closed the tunnel, so a caller replacing one would cut traffic early")
	}
	if _, still := r.Get("tn_a"); still {
		t.Error("the removed tunnel is still registered")
	}
}

// Removing must take the id out of the order list too, or the next All() would read a
// missing key out of the map and hand back a nil tunnel that every caller dereferences.
func TestARemovedConnectionIsGoneFromTheListedOrder(t *testing.T) {
	r := NewRegistry()
	for _, id := range []string{"tn_a", "tn_b", "tn_c"} {
		if err := r.Add(&fakeTunnel{id: id}); err != nil {
			t.Fatalf("adding %s: %v", id, err)
		}
	}

	r.Remove("tn_b")

	for _, held := range r.All() {
		if held == nil {
			t.Fatal("All() returned a nil tunnel: the order list still names a removed id")
		}
		if held.ID() == "tn_b" {
			t.Fatal("the removed connection is still listed")
		}
	}
	if r.Len() != 2 {
		t.Errorf("Len = %d, want 2", r.Len())
	}
}

func TestRemovingSomethingNeverRegisteredSaysSo(t *testing.T) {
	r := NewRegistry()

	got, ok := r.Remove("tn_missing")

	if ok || got != nil {
		t.Errorf("Remove returned (%v, %v), want (nil, false)", got, ok)
	}
}

// A failing close must not abandon the tunnels after it: they hold interfaces and
// listeners, and nothing would be left holding a reference to close them later.
func TestOneFailingCloseDoesNotStopTheRest(t *testing.T) {
	r := NewRegistry()
	broken := &fakeTunnel{id: "tn_broken", closeErr: errors.New("the interface is wedged")}
	after := &fakeTunnel{id: "tn_after"}
	for _, held := range []*fakeTunnel{{id: "tn_before"}, broken, after} {
		if err := r.Add(held); err != nil {
			t.Fatalf("adding %s: %v", held.id, err)
		}
	}

	err := r.Close()

	if after.closed != 1 {
		t.Errorf("the tunnel after the failing one was closed %d times, want 1", after.closed)
	}
	if err == nil || !strings.Contains(err.Error(), "tn_broken") {
		t.Errorf("error = %v, want the failure reported and attributed", err)
	}
	if r.Len() != 0 {
		t.Errorf("Len = %d, want the registry emptied", r.Len())
	}
}

// Degraded means traffic still crosses. Treating it as not-live would turn one unhappy
// exit node into a total outage.
func TestDegradedStillCarriesTraffic(t *testing.T) {
	live := map[State]bool{
		StateOff: false, StateStarting: false, StateNeedsLogin: false,
		StateConnecting: false, StateConnected: true, StateDegraded: true,
		StateFailed: false, StateStopping: false,
	}
	for state, want := range live {
		if got := state.Live(); got != want {
			t.Errorf("%s.Live() = %v, want %v", state, got, want)
		}
	}
}

// Every state needs a word, because every surface shows the word beside the colour --
// a colour alone is unreadable in a log and to anyone who cannot distinguish the hues.
func TestEveryStateReadsAsSomethingOtherThanItsWireValue(t *testing.T) {
	for _, state := range []State{
		StateOff, StateStarting, StateNeedsLogin, StateConnecting,
		StateConnected, StateDegraded, StateFailed, StateStopping,
	} {
		if label := state.Label(); label == "" || label == string(state) {
			t.Errorf("%s.Label() = %q, want a written label", state, label)
		}
	}
}
