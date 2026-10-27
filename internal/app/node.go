// SPDX-License-Identifier: MIT

package app

import (
	"context"

	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// nodeAPI presents the agent's current tailnet node to the management API. Each
// method resolves the node on use, so an in-process restart that swaps the node is
// invisible to the long-lived API server that holds this facade.
type nodeAPI struct{ a *Agent }

var (
	_ httpapi.Node      = nodeAPI{}
	_ httpapi.Restarter = (*Agent)(nil)
)

// NodeAPI exposes the agent's current node as the management API's node dependency.
func (a *Agent) NodeAPI() httpapi.Node { return nodeAPI{a: a} }

func (n nodeAPI) Status() tsnode.Status {
	status := tsnode.Status{BackendState: tsnode.StateNoState}
	if node := n.a.currentNode(); node != nil {
		status = node.Status()
	}
	// A node that failed to start has no problem of its own to report -- it never got
	// far enough to have one. The agent knows why, and both /healthz and the
	// dashboard already read Problem, so putting it here lights up every surface.
	if status.Problem == "" && !status.Running() {
		status.Problem = n.a.nodeProblem()
	}
	// Reported whatever the node's state, because this is the case where the node is
	// working and is not doing what was asked: nothing else on the status would hint
	// that the machine is not carrying tailnet addresses.
	status.NetworkFallback = n.a.networkModeFallback()
	return status
}

func (n nodeAPI) StartLogin(ctx context.Context) error {
	node := n.a.currentNode()
	if node == nil {
		return tsnode.ErrNotRunning
	}
	return node.StartLogin(ctx)
}

func (n nodeAPI) Logout(ctx context.Context) error {
	node := n.a.currentNode()
	if node == nil {
		return tsnode.ErrNotRunning
	}
	return node.Logout(ctx)
}

func (n nodeAPI) Peers(ctx context.Context) ([]tsnode.Peer, error) {
	node := n.a.currentNode()
	if node == nil {
		return nil, tsnode.ErrNotRunning
	}
	return node.Peers(ctx)
}
