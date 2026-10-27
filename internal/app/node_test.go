// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// The node facade is what makes an in-process restart invisible to the management
// API: every call must reach whatever node the agent currently holds, not a node
// captured once at startup.
func TestNodeAPIDelegatesToTheLiveNode(t *testing.T) {
	h := newHarness(t, nil)
	h.node.setPeers(tsnode.Peer{HostName: "gpu-box"})
	node := h.agent.NodeAPI()

	if err := node.StartLogin(context.Background()); err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	if got := node.Status().AuthURL; got == "" {
		t.Error("StartLogin did not reach the live node; no auth URL appeared")
	}

	peers, err := node.Peers(context.Background())
	if err != nil {
		t.Fatalf("Peers: %v", err)
	}
	if len(peers) != 1 || peers[0].HostName != "gpu-box" {
		t.Errorf("Peers = %v, want the live node's single peer", peers)
	}

	if err := node.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if got := node.Status().BackendState; got != tsnode.StateNeedsLogin {
		t.Errorf("after Logout backend state = %q, want %q", got, tsnode.StateNeedsLogin)
	}
}

// Before the agent has built a node, the facade must report "not running" rather
// than panic on a nil node — the management API can be hit during that window.
func TestNodeAPIReportsNoNodeBeforeStartup(t *testing.T) {
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
		Version: "test", NewNode: func(tsnode.Options) NodeController { return newFakeNode() },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	node := agent.NodeAPI()
	if got := node.Status().BackendState; got != tsnode.StateNoState {
		t.Errorf("Status before startup = %q, want %q", got, tsnode.StateNoState)
	}
	if err := node.StartLogin(context.Background()); !errors.Is(err, tsnode.ErrNotRunning) {
		t.Errorf("StartLogin before startup = %v, want ErrNotRunning", err)
	}
	if err := node.Logout(context.Background()); !errors.Is(err, tsnode.ErrNotRunning) {
		t.Errorf("Logout before startup = %v, want ErrNotRunning", err)
	}
	if _, err := node.Peers(context.Background()); !errors.Is(err, tsnode.ErrNotRunning) {
		t.Errorf("Peers before startup = %v, want ErrNotRunning", err)
	}
}
