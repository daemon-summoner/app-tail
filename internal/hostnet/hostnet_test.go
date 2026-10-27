// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/dns"
)

// A helper from another build holds root and reads this build's messages by its own rules.
// The version check is the only thing standing between "an old helper is installed" and
// "an old helper is acting on fields it understands differently", so it refuses on every
// answer that is not an exact match -- including the two ways of saying nothing.
func TestAHelperFromAnotherBuildIsRefused(t *testing.T) {
	tests := []struct {
		name         string
		want, got    string
		wantErr      bool
		wantPhrase   string
		wantSentinel error
	}{
		{name: "the same build is accepted", want: "1.2.3", got: "1.2.3"},
		{
			name: "an older helper is refused", want: "1.2.3", got: "1.2.2",
			wantErr: true, wantPhrase: "1.2.2", wantSentinel: ErrHelperFromAnotherBuild,
		},
		{
			name: "a newer helper is refused just the same", want: "1.2.3", got: "1.3.0",
			wantErr: true, wantPhrase: "1.3.0", wantSentinel: ErrHelperFromAnotherBuild,
		},
		{
			name: "a helper that said nothing is refused", want: "1.2.3", got: "",
			wantErr: true, wantPhrase: "did not say",
		},
		{
			name: "and so is a build that does not know its own version", want: "", got: "1.2.3",
			wantErr: true, wantPhrase: "did not say",
		},
		{
			name: "two unknowns are not a match", want: "", got: "",
			wantErr: true, wantPhrase: "did not say",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkVersion(tt.want, tt.got)
			if tt.wantErr && err == nil {
				t.Fatalf("checkVersion(%q, %q) accepted the helper, want a refusal", tt.want, tt.got)
			}
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("checkVersion(%q, %q) = %v, want it accepted", tt.want, tt.got, err)
				}
				return
			}
			if !strings.Contains(err.Error(), tt.wantPhrase) {
				t.Errorf("checkVersion(%q, %q) said %q, which does not mention %q",
					tt.want, tt.got, err, tt.wantPhrase)
			}
			// The refusal has to identify itself, because the sentence saying what to
			// run is added where the platform is known and is chosen by this sentinel.
			if tt.wantSentinel != nil && !errors.Is(err, tt.wantSentinel) {
				t.Errorf("checkVersion(%q, %q) = %v, which no caller can recognise as %v",
					tt.want, tt.got, err, tt.wantSentinel)
			}
		})
	}
}

// Usable is what the preflight refuses on. Two conditions stop a start -- another tailnet
// client, because the two delete each other's resolver files, and a component that is not
// installed -- and each has to come back with the sentence that says what to do about it.
// Leftovers must not stop one, because the start is what clears them.
func TestOnlyAConflictOrAMissingComponentMakesTheMachineUnusable(t *testing.T) {
	tests := []struct {
		name    string
		caps    Capabilities
		want    bool
		wantWhy string
	}{
		{name: "a clean machine is usable", caps: Capabilities{Version: "1"}, want: true},
		{
			name: "leftovers do not stop a start, because starting is what clears them",
			caps: Capabilities{Version: "1", Leftovers: []string{"/etc/resolver/example.com"}},
			want: true,
		},
		{
			name:    "another tailnet client does",
			caps:    Capabilities{Version: "1", Conflict: "tailscaled is running"},
			want:    false,
			wantWhy: "tailscaled is running",
		},
		{
			name:    "so does a component that is not installed",
			caps:    Capabilities{Version: "1", Missing: "wintun.dll is not next to app-tail.exe"},
			want:    false,
			wantWhy: "wintun.dll is not next to app-tail.exe",
		},
		{
			// Whichever client this machine ends up running needs the missing piece, so
			// naming the conflict first would send someone to quit an app they will have
			// to start again before anything works.
			name: "a machine with both is told to install first",
			caps: Capabilities{
				Version:  "1",
				Conflict: "tailscaled is running",
				Missing:  "wintun.dll is not next to app-tail.exe",
			},
			want:    false,
			wantWhy: "wintun.dll is not next to app-tail.exe",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, why := tt.caps.Usable()
			if ok != tt.want {
				t.Fatalf("Usable() = %v, want %v", ok, tt.want)
			}
			if ok && why != "" {
				t.Errorf("Usable() said yes but gave the reason %q", why)
			}
			if why != tt.wantWhy {
				t.Errorf("Usable() said no because %q, want %q", why, tt.wantWhy)
			}
		})
	}
}

// Open decides which side of the privilege boundary a caller ends up on. The one case
// worth pinning without a machine in a particular state is the refusal to run with no way
// to report what the privileged side did: a route change that half-failed has to be
// visible somewhere, and Local logs rather than returns most of it.
func TestOpenRefusesToRunWithNowhereToReport(t *testing.T) {
	_, err := Open(context.Background(), Options{})
	if err == nil {
		t.Fatal("Open with no log function was accepted, so the privileged side would have nowhere to report a partial failure")
	}
	if !strings.Contains(err.Error(), "log function") {
		t.Errorf("Open said %q, which does not say what was missing", err)
	}
}

// Every operation on a Local that was never opened is a mistake in the caller, and each
// one has to say so rather than fail somewhere deeper with a nil dereference. This is the
// path a helper takes when an agent sends set-routes before open-tun.
func TestALocalWithNoInterfaceRefusesEveryOperation(t *testing.T) {
	ctx := context.Background()
	l := NewLocal(func(string, ...any) {})

	if err := l.RouterUp(ctx); err == nil {
		t.Error("RouterUp on an unopened Local was accepted")
	}
	if err := l.SetRoutes(ctx, nil); err == nil {
		t.Error("SetRoutes on an unopened Local was accepted")
	}
	if err := l.SetDNS(ctx, dns.OSConfig{}); err == nil {
		t.Error("SetDNS on an unopened Local was accepted")
	}
	if _, err := l.BaseDNS(ctx); err == nil {
		t.Error("BaseDNS on an unopened Local was accepted")
	}
	if _, err := l.SplitDNS(ctx); err == nil {
		t.Error("SplitDNS on an unopened Local was accepted")
	}
}

// Open is the privilege boundary's front door: it decides, from this process's own
// privilege rather than from configuration, whether the rights are already here or have to
// be asked of a helper. Each refusal is a different thing for the user to do, and a wrong
// one sends them to install a helper on a machine that needs none.
func TestOpenChoosesTheSideThatHoldsTheRights(t *testing.T) {
	// Bounded, because on a machine with a helper installed this reaches it, and a helper
	// is a separately installed binary that a suite has no way to put into a known state.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	host, err := Open(ctx, Options{Logf: func(string, ...any) {}})
	// Checked and closed exactly the way a caller would, because a refusal that comes back
	// with a non-nil interface holding a nil pointer passes this check and panics on the
	// next line.
	if host != nil {
		if err := host.Close(); err != nil {
			t.Errorf("close the privileged side: %v", err)
		}
	}
	if err != nil && host != nil {
		t.Errorf("Open refused with %v and still handed back a %T to close", err, host)
	}

	switch {
	case !Supported():
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("Open on %s = %v, want ErrUnsupported", runtime.GOOS, err)
		}
	case Privileged():
		// Already root, so the work happens here and asking for a helper would be a step
		// that changes nothing.
		if err != nil {
			t.Errorf("Open in a privileged process = %v, want the in-process side", err)
		}
	case !HasHelper():
		if !errors.Is(err, ErrNeedsElevation) {
			t.Errorf("Open on a platform with no helper = %v, want ErrNeedsElevation", err)
		}
	case !HelperInstalled():
		// The helper is the design here and it is not installed, which is every machine
		// before somebody runs the install. That is a refusal, not a fallback to doing
		// the privileged work in this process.
		if err == nil {
			t.Error("Open reached a privileged side on a machine where none is installed")
		}
	}
}

// Capabilities is read before anything is torn down, so it must not need an interface --
// the whole point is to answer while the existing node is still up.
func TestCapabilitiesAnswersWithoutOpeningAnything(t *testing.T) {
	l := NewLocal(func(string, ...any) {})
	caps, err := l.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities on an unopened Local: %v", err)
	}
	if caps.Version != Version {
		t.Errorf("Capabilities reported version %q, want this build's %q", caps.Version, Version)
	}
}

// A cancelled context must stop a privileged operation before it reaches the OS. The
// caller that cancels is the one that gave up waiting, and a route installed after that is
// one nothing will remove.
func TestACancelledContextStopsAnOperationBeforeTheOS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l := NewLocal(func(string, ...any) {})

	if _, err := l.Capabilities(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Capabilities with a cancelled context = %v, want context.Canceled", err)
	}
	if _, _, err := l.OpenTUN(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Errorf("OpenTUN with a cancelled context = %v, want context.Canceled", err)
	}
}

// countingDevice stands in for the kernel's interface. The real one is a file descriptor
// on an AF_SYSTEM socket; substituting it here is substituting the operating system, not
// this app's code, and it is the only way to observe how many times the descriptor is
// closed -- which on a real one is the difference between a clean teardown and a close of
// a descriptor the process has since reused for something else.
type countingDevice struct {
	file   *os.File
	closes int
}

var _ tun.Device = (*countingDevice)(nil)

func (d *countingDevice) File() *os.File                         { return d.file }
func (d *countingDevice) Read([][]byte, []int, int) (int, error) { return 0, io.EOF }
func (d *countingDevice) Write([][]byte, int) (int, error)       { return 0, io.EOF }
func (d *countingDevice) MTU() (int, error)                      { return 1280, nil }
func (d *countingDevice) Name() (string, error)                  { return "test0", nil }
func (d *countingDevice) Events() <-chan tun.Event               { return nil }
func (d *countingDevice) BatchSize() int                         { return 1 }
func (d *countingDevice) Close() error                           { d.closes++; return nil }

// Close is the teardown that runs when the agent dies, and it runs from more than one
// place: the deferred call in the helper's session loop, and an explicit one on the way
// out of a failed start. Closing the interface twice would be a close of a descriptor this
// process has since reused, which corrupts whatever took its number.
func TestClosingALocalTwiceClosesTheInterfaceOnce(t *testing.T) {
	dev := &countingDevice{}
	l := NewLocal(func(string, ...any) {})
	// Retain is what the helper does: it holds a reference of its own because the same
	// descriptor is open in the agent too.
	l.Retain(dev)

	if err := l.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if dev.closes != 1 {
		t.Fatalf("the first Close closed the interface %d times, want 1", dev.closes)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if dev.closes != 1 {
		t.Errorf("the interface was closed %d times across two teardowns, want 1", dev.closes)
	}
}

// A Local that has been torn down must not create another interface. It would be one
// nothing tears down: the teardown that would have removed it has already run.
//
// The refusal is checked by its reason rather than by the presence of an error, because
// creating an interface fails anyway in a test that is not root -- and a test satisfied by
// that failure would pass with the guard deleted.
func TestAClosedLocalRefusesToCreateAnotherInterface(t *testing.T) {
	l := NewLocal(func(string, ...any) {})
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, _, err := l.OpenTUN(context.Background(), "")
	if err == nil {
		t.Fatal("OpenTUN after Close was accepted, so a closed Local would create an interface nothing tears down")
	}
	if !strings.Contains(err.Error(), "already been torn down") {
		t.Errorf("OpenTUN after Close failed with %q, want the refusal rather than an attempt that failed", err)
	}
}

// The handover window is how long a caller waits for a session that is being torn down. A
// caller whose own context ended is no longer waiting for anything, and holding it for the
// rest of that window would stall a shutdown behind a helper it has already given up on.
func TestACallerThatHasGivenUpIsNotHeldForTheHandover(t *testing.T) {
	// Long enough that returning inside it can only be the cancellation being read, never
	// the window running out.
	gate := newSessionGate(time.Minute)
	if !gate.take(context.Background(), gateInterface) {
		t.Fatal("the first caller did not get a free session")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	got := gate.take(ctx, gateInterface)

	if got {
		t.Fatal("a caller that had given up was handed the session, which is held by another connection")
	}
	if waited := time.Since(start); waited > 10*time.Second {
		t.Errorf("the caller was held for %v, so it waits out the handover it is no longer waiting for", waited)
	}
}
