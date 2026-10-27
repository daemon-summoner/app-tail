// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"tailscale.com/client/local"
	"tailscale.com/net/tsdial"
	"tailscale.com/tsd"
)

// reachNode builds a node that is Running and classifies with plan, so Reach can be
// exercised without a tailnet.
func reachNode(plan dialPlanner) *Node {
	return &Node{
		status:    Status{BackendState: StateRunning},
		plan:      plan,
		events:    make(chan struct{}, 1),
		watchDone: make(chan struct{}),
	}
}

// Reach exists so a caller can refuse an address before dialing it. Both halves of
// the answer have to arrive intact: the verdict decides whether to dial at all, and
// the resolved address is what gets dialed -- resolving the name a second time is the
// race the backend documents, and it resolves in the permissive direction.
func TestReachReportsTheVerdictAndTheAddressItResolved(t *testing.T) {
	cases := []struct {
		name       string
		address    string
		want       netip.AddrPort
		viaTailnet bool
	}{
		{
			name:       "a peer by MagicDNS name",
			address:    "laptop.tail1a2b3c.ts.net:22",
			want:       netip.MustParseAddrPort("100.64.0.7:22"),
			viaTailnet: true,
		},
		{
			name:       "a peer by tailnet IP",
			address:    "100.64.0.7:22",
			want:       netip.MustParseAddrPort("100.64.0.7:22"),
			viaTailnet: true,
		},
		{
			name:       "a public address",
			address:    "example.com:443",
			want:       netip.MustParseAddrPort("93.184.216.34:443"),
			viaTailnet: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := reachNode(func(context.Context, string, string) (netip.AddrPort, bool, error) {
				return tc.want, tc.viaTailnet, nil
			})

			got, err := n.Reach(context.Background(), "tcp", tc.address)
			if err != nil {
				t.Fatalf("Reach: %v", err)
			}
			if got.Addr != tc.want {
				t.Errorf("Addr = %v, want %v", got.Addr, tc.want)
			}
			if got.ViaTailnet != tc.viaTailnet {
				t.Errorf("ViaTailnet = %v, want %v", got.ViaTailnet, tc.viaTailnet)
			}
		})
	}
}

// The classifier is what a caller enforcing a tailnet-only scope decides on. A node
// that cannot classify must say so: an answer of "not via the tailnet" would read as
// a deliberate refusal, and one of "via the tailnet" would open the scope.
func TestReachRefusesRatherThanGuessingWhenItCannotClassify(t *testing.T) {
	t.Run("before the node is running", func(t *testing.T) {
		n := reachNode(func(context.Context, string, string) (netip.AddrPort, bool, error) {
			t.Error("a node that is not running classified an address anyway")
			return netip.AddrPort{}, true, nil
		})
		n.status = Status{BackendState: StateNeedsLogin}

		if _, err := n.Reach(context.Background(), "tcp", "peer:22"); !errors.Is(err, ErrNotRunning) {
			t.Errorf("error = %v, want ErrNotRunning", err)
		}
	})

	t.Run("with no classifier registered", func(t *testing.T) {
		n := reachNode(nil)

		if _, err := n.Reach(context.Background(), "tcp", "peer:22"); !errors.Is(err, ErrNoDialPlan) {
			t.Errorf("error = %v, want ErrNoDialPlan", err)
		}
	})

	t.Run("when the name does not resolve", func(t *testing.T) {
		refusal := errors.New("no such host")
		n := reachNode(func(context.Context, string, string) (netip.AddrPort, bool, error) {
			return netip.AddrPort{}, false, refusal
		})

		got, err := n.Reach(context.Background(), "tcp", "nope.invalid:22")
		if !errors.Is(err, refusal) {
			t.Errorf("error = %v, want it to wrap the resolver's own", err)
		}
		if got.ViaTailnet {
			t.Error("a failed resolution was reported as reachable over the tailnet")
		}
	})
}

// publish reads the classifier off the engine's subsystem table, which does not exist
// until the tsnet server has started. A node published without one -- a start that
// failed before the engine was built -- must come out of publish unable to classify,
// not crash the process on the way.
func TestPublishingANodeWithNoEngineLeavesItUnableToClassify(t *testing.T) {
	n := New(Options{
		Params: ServerParams{Hostname: "reach-test", Mode: AuthInteractive},
		Logger: quietLogger(),
	})

	n.publish(&local.Client{}, func() {})
	// Past the running check, so the refusal below is the missing classifier rather
	// than the node simply not being up.
	n.status = Status{BackendState: StateRunning}

	if _, err := n.Reach(context.Background(), "tcp", "peer:22"); !errors.Is(err, ErrNoDialPlan) {
		t.Errorf("error = %v, want ErrNoDialPlan", err)
	}
}

// Once the engine has registered its dialer, that dialer is what classifies. Reading a
// subsystem the engine has not filled in must answer nothing rather than panic: the
// registry's plain Get panics on an unset subsystem, and a node whose start failed part
// way through is published all the same.
func TestTheClassifierIsTheEnginesOwnDialerOnceItHasOne(t *testing.T) {
	if got := dialPlanFrom(nil); got != nil {
		t.Error("a node with no engine produced a classifier, which would answer from nothing")
	}
	if got := dialPlanFrom(new(tsd.System)); got != nil {
		t.Error("an engine that has not registered a dialer produced a classifier")
	}

	sys := new(tsd.System)
	dialer := &tsdial.Dialer{Logf: func(string, ...any) {}}
	sys.Set(dialer)

	plan := dialPlanFrom(sys)
	if plan == nil {
		t.Fatal("an engine with a registered dialer produced no classifier, so Reach refuses every address")
	}
	// The classifier has to be the dialer's own: anything else classifies against a
	// routing table the connections are not dialed through.
	if _, _, err := plan(context.Background(), "tcp", "100.64.0.9:22"); err != nil {
		t.Errorf("classifying a tailnet address through the engine's dialer: %v", err)
	}
}

// The classifier belongs to the engine Close just shut down. Answering from it
// afterwards would describe a routing table that no longer exists.
func TestReachStopsClassifyingOnceTheNodeIsClosed(t *testing.T) {
	n := reachNode(func(context.Context, string, string) (netip.AddrPort, bool, error) {
		return netip.MustParseAddrPort("100.64.0.7:22"), true, nil
	})
	if err := n.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Close leaves the cached status alone, so this is the classifier being cleared
	// rather than the running check standing in for it.
	if _, err := n.Reach(context.Background(), "tcp", "peer:22"); !errors.Is(err, ErrNoDialPlan) {
		t.Errorf("error = %v, want ErrNoDialPlan", err)
	}
}
