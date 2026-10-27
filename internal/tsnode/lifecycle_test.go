// SPDX-License-Identifier: MIT

package tsnode

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"tailscale.com/client/local"
)

// newBareNode builds a node without contacting anything, so lifecycle behaviour can
// be exercised without a tailnet.
func newBareNode(t *testing.T) *Node {
	t.Helper()
	return New(Options{
		Params: ServerParams{Hostname: "lifecycle-test", Mode: AuthInteractive},
		Logger: quietLogger(),
	})
}

// The backend client is written when the node starts and read by every API handler
// on its own goroutine. Under -race an unsynchronized field would be reported here.
func TestBackendClientAccessIsSynchronized(t *testing.T) {
	n := newBareNode(t)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = n.client()
				}
			}
		}()
	}

	for range 200 {
		n.publish(&local.Client{}, func() {})
	}
	close(stop)
	wg.Wait()
}

// Every tailnet operation must refuse cleanly before the node has started, rather
// than dereferencing a client that does not exist yet.
func TestTailnetOperationsRefuseBeforeStart(t *testing.T) {
	n := newBareNode(t)
	ctx := context.Background()

	if err := n.StartLogin(ctx); !errors.Is(err, ErrNotRunning) {
		t.Errorf("StartLogin before start = %v, want ErrNotRunning", err)
	}
	if err := n.Logout(ctx); !errors.Is(err, ErrNotRunning) {
		t.Errorf("Logout before start = %v, want ErrNotRunning", err)
	}
	if _, err := n.Peers(ctx); !errors.Is(err, ErrNotRunning) {
		t.Errorf("Peers before start = %v, want ErrNotRunning", err)
	}
	if _, err := n.SuggestExitNode(ctx); !errors.Is(err, ErrNotRunning) {
		t.Errorf("SuggestExitNode before start = %v, want ErrNotRunning", err)
	}
	if _, err := n.PingPeer(ctx, netip.MustParseAddr("100.64.0.1")); !errors.Is(err, ErrNotRunning) {
		t.Errorf("PingPeer before start = %v, want ErrNotRunning", err)
	}
}

// A node is published before it is started, so a start that fails leaves a node the
// agent will still close at shutdown. tsnet's own Close panics before Start, so this
// has to be a no-op rather than a crash on the way down.
func TestClosingANodeThatNeverStartedIsSafe(t *testing.T) {
	n := newBareNode(t)
	if err := n.Close(); err != nil {
		t.Fatalf("Close on an unstarted node: %v", err)
	}
	// Closing twice must stay safe: shutdown paths can overlap a restart.
	if err := n.Close(); err != nil {
		t.Fatalf("second Close on an unstarted node: %v", err)
	}
}

// A restart closes the old node while handlers may still hold it. Those calls have
// to report that the node is gone; an operation against a closed backend would
// otherwise surface as an opaque failure the dashboard cannot explain.
func TestTailnetOperationsRefuseAfterClose(t *testing.T) {
	n := newBareNode(t)
	n.publish(&local.Client{}, nil)

	if n.client() == nil {
		t.Fatal("publish did not make the backend client visible")
	}
	if err := n.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n.client() != nil {
		t.Fatal("the backend client is still reachable after Close")
	}

	ctx := context.Background()
	if err := n.StartLogin(ctx); !errors.Is(err, ErrNotRunning) {
		t.Errorf("StartLogin after close = %v, want ErrNotRunning", err)
	}
	if err := n.Logout(ctx); !errors.Is(err, ErrNotRunning) {
		t.Errorf("Logout after close = %v, want ErrNotRunning", err)
	}
	if _, err := n.Peers(ctx); !errors.Is(err, ErrNotRunning) {
		t.Errorf("Peers after close = %v, want ErrNotRunning", err)
	}
	if _, err := n.SuggestExitNode(ctx); !errors.Is(err, ErrNotRunning) {
		t.Errorf("SuggestExitNode after close = %v, want ErrNotRunning", err)
	}
	if _, err := n.PingPeer(ctx, netip.MustParseAddr("100.64.0.1")); !errors.Is(err, ErrNotRunning) {
		t.Errorf("PingPeer after close = %v, want ErrNotRunning", err)
	}
}

// The tailscale stack writes several lines per second at rest. Carrying them into the
// agent's log unasked buries every line this app writes itself, and dropping them when they
// were asked for leaves the one person debugging a connection with nothing to read.
func TestTheBackendsOwnLoggingIsCarriedOnlyWhenItWasAskedFor(t *testing.T) {
	tests := []struct {
		name    string
		verbose bool
		want    bool
	}{
		{name: "an ordinary run discards it", verbose: false},
		{name: "a verbose run keeps it", verbose: true, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var log bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))

			backendLogf(Options{Verbose: tc.verbose}, logger, &loginURLRedactor{})("magicsock: home DERP is now %d", 12)

			got := strings.Contains(log.String(), "home DERP is now 12")
			if got != tc.want {
				t.Errorf("the backend's line reaching the log = %v, want %v (log was %q)", got, tc.want, log.String())
			}
		})
	}
}
