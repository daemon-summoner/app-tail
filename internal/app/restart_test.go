// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// recordingNodes builds a fresh fakeNode per call, recording each one and the params
// it was constructed with, so a restart test can inspect the whole sequence.
type recordingNodes struct {
	mu    sync.Mutex
	built []*fakeNode
}

func (r *recordingNodes) factory() func(tsnode.Options) NodeController {
	return func(o tsnode.Options) NodeController {
		r.mu.Lock()
		defer r.mu.Unlock()
		n := newFakeNode()
		n.params = o.Params
		r.built = append(r.built, n)
		return n
	}
}

func (r *recordingNodes) snapshot() []*fakeNode {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*fakeNode(nil), r.built...)
}

// runAgent starts an agent over a throwaway state dir with the given node factory and
// tears it down at the end of the test.
func runAgent(t *testing.T, newNode func(tsnode.Options) NodeController) *Agent {
	t.Helper()
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	rt, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	agent, err := New(Options{
		Store: store, Runtime: rt, Getenv: emptyEnv, Logger: quietLogger(),
		Version: "test", NewNode: newNode,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- agent.Run(ctx) }()
	waitFor(t, 5*time.Second, "agent to bind", func() bool { return agent.UIAddr() != nil })

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-runErr:
			if err != nil {
				t.Errorf("agent exited with %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("agent did not exit within 15s of cancellation")
		}
	})
	return agent
}

// A restart must build a replacement node carrying the new settings, close the old
// one, and leave the management API's node facade serving the replacement.
func TestRestartRebuildsTheNodeWithNewSettings(t *testing.T) {
	rec := &recordingNodes{}
	agent := runAgent(t, rec.factory())

	waitFor(t, 5*time.Second, "the first node to be built", func() bool {
		return len(rec.snapshot()) == 1
	})

	// ControlURL flows straight into the node's params, so it is an unambiguous probe
	// that the rebuild used the updated settings. It sits behind a module, so the
	// switch travels in the same save -- which is also how the dashboard sends it.
	const newControl = "https://controlplane.tailscale.com"
	patch := settingsPatch(t, map[string]any{"advancedNetworking": true, "controlURL": newControl})
	if _, impact, err := agent.Settings().Update(context.Background(), patch); err != nil {
		t.Fatalf("update settings: %v", err)
	} else if !impact.NodeRestart {
		t.Fatal("a control-URL change should require a node restart")
	}

	if err := agent.RestartNode(context.Background()); err != nil {
		t.Fatalf("RestartNode: %v", err)
	}

	built := rec.snapshot()
	if len(built) != 2 {
		t.Fatalf("built %d nodes, want one per start plus the restart", len(built))
	}
	if !built[0].wasClosed() {
		t.Error("the previous node was not closed on restart")
	}
	if built[1].wasClosed() {
		t.Error("the replacement node was closed")
	}
	if got := built[1].params.ControlURL; got != newControl {
		t.Errorf("replacement node ControlURL = %q, want the updated %q", got, newControl)
	}

	built[1].setState(tsnode.StateRunning)
	if got := agent.NodeAPI().Status().BackendState; got != tsnode.StateRunning {
		t.Errorf("node facade backend state = %q, want it to follow the replacement node", got)
	}
}

// A replacement node that fails to start leaves the agent with no watcher and an
// empty forward set, so nothing will ever fire another event on its own. The reason
// has to reach the health surface, and a later successful restart has to clear it --
// otherwise the agent looks merely idle while it is actually stuck.
func TestAFailedRestartIsReportedAndClearsOnRecovery(t *testing.T) {
	const reason = "state directory is locked by another process"

	rec := &recordingNodes{}
	var failNext atomic.Bool
	agent := runAgent(t, func(o tsnode.Options) NodeController {
		node := rec.factory()(o)
		if failNext.Load() {
			node.(*fakeNode).startErr = errors.New(reason)
		}
		return node
	})
	waitFor(t, 5*time.Second, "the first node to be built", func() bool {
		return len(rec.snapshot()) == 1
	})

	failNext.Store(true)
	if err := agent.RestartNode(context.Background()); err == nil {
		t.Fatal("RestartNode reported success although the replacement node could not start")
	}

	if got := agent.NodeAPI().Status().Problem; !strings.Contains(got, reason) {
		t.Fatalf("node status Problem = %q, want it to carry why the restart failed", got)
	}

	failNext.Store(false)
	if err := agent.RestartNode(context.Background()); err != nil {
		t.Fatalf("RestartNode after the failure: %v", err)
	}
	if got := agent.NodeAPI().Status().Problem; got != "" {
		t.Fatalf("node status Problem = %q after a successful restart, want it cleared", got)
	}
}

// When the new configuration cannot even be resolved into node params, the restart
// must fail without tearing down the running node.
func TestRestartFailsClosedWhenTheNewParamsAreInvalid(t *testing.T) {
	rec := &recordingNodes{}
	agent := runAgent(t, rec.factory())

	waitFor(t, 5*time.Second, "the first node to be built", func() bool {
		return len(rec.snapshot()) == 1
	})

	// Point at a secret file that does not exist. Validation passes (a tag is set), but
	// building params reads the file and fails.
	missing := filepath.Join(t.TempDir(), "nonexistent-secret")
	if _, _, err := agent.Settings().Update(context.Background(), settingsPatch(t, map[string]any{"oauthClientSecretFile": missing})); err != nil {
		t.Fatalf("update settings: %v", err)
	}

	if err := agent.RestartNode(context.Background()); err == nil {
		t.Fatal("RestartNode reported success with an unreadable secret file")
	}

	built := rec.snapshot()
	if len(built) != 1 {
		t.Fatalf("built %d nodes; an invalid restart must not construct a replacement", len(built))
	}
	if built[0].wasClosed() {
		t.Error("the running node was torn down by a restart that could not build its replacement")
	}
}
