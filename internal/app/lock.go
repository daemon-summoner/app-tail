// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// lockAPI presents tailnet lock to the management API.
type lockAPI struct{ a *Agent }

var _ httpapi.Lock = lockAPI{}

// LockAPI exposes tailnet lock.
func (a *Agent) LockAPI() httpapi.Lock { return lockAPI{a: a} }

// View reports what tailnet lock means for this device.
//
// Everything here is read-only and the module has no switch, because the state it
// explains reaches a user who turned nothing on: a device whose key is unsigned connects,
// reports Running, and can reach nothing at all.
func (l lockAPI) View(ctx context.Context) httpapi.LockView {
	a := l.a

	node := a.currentNode()
	if node == nil || !node.Status().Running() {
		return httpapi.LockView{Capability: lockCapability(httpapi.LockView{}, false, a.nodeProblem())}
	}

	status, err := node.NetworkLock(ctx)
	if err != nil {
		a.logger.Debug("reading tailnet lock status failed", "error", err)
		view := httpapi.LockView{Error: err.Error()}
		view.Capability = lockCapability(view, true, a.nodeProblem())
		return view
	}

	view := httpapi.LockView{
		Enabled: status.Enabled,
		Signed:  status.Signed,
		NodeKey: status.NodeKey,
		LockKey: status.LockKey,
		CanSign: status.CanSign,
		Visible: status.Visible,
		Head:    status.Head,
	}
	// The command is built here rather than in a client because it is the entire remedy
	// for a locked-out device, and a dashboard that assembled it from the two keys would
	// be the second place its shape is written down. Both keys are required by
	// `tailscale lock sign`, so it is offered only when both are known.
	if status.NodeKey != "" && status.LockKey != "" {
		view.SignCommand = fmt.Sprintf("tailscale lock sign %s %s", status.NodeKey, status.LockKey)
	}
	for _, k := range status.Trusted {
		view.Trusted = append(view.Trusted, httpapi.LockKeyView{
			ID:    k.ID,
			Kind:  k.Kind,
			Votes: k.Votes,
			Self:  k.Self,
			Label: lockKeyLabel(k),
		})
	}
	for _, p := range status.Filtered {
		view.Filtered = append(view.Filtered, httpapi.LockPeerView{
			ID:      p.ID,
			Name:    p.Name,
			NodeKey: p.NodeKey,
			IPs:     append([]string(nil), p.IPs...),
		})
	}

	view.Capability = lockCapability(view, true, a.nodeProblem())
	return view
}

// Log reads the tailnet's key authority history.
func (l lockAPI) Log(ctx context.Context) ([]httpapi.LockUpdate, error) {
	node := l.a.currentNode()
	if node == nil || !node.Status().Running() {
		return nil, httpapi.Unavailable("the tailnet lock log", "the tailnet node is not running")
	}
	entries, err := node.LockLog(ctx, 0)
	if err != nil {
		return nil, err
	}
	out := make([]httpapi.LockUpdate, 0, len(entries))
	for _, e := range entries {
		out = append(out, httpapi.LockUpdate{Hash: e.Hash, Change: e.Change})
	}
	return out, nil
}

// Sign authorizes another device for a locked tailnet.
func (l lockAPI) Sign(ctx context.Context, nodeKey, rotationKey string) error {
	node := l.a.currentNode()
	if node == nil || !node.Status().Running() {
		return httpapi.Unavailable("signing a device for tailnet lock",
			"the tailnet node is not running")
	}
	return node.SignNode(ctx, nodeKey, rotationKey)
}

// DisableLocal forgets this device's copy of the tailnet lock state.
func (l lockAPI) DisableLocal(ctx context.Context) error {
	node := l.a.currentNode()
	if node == nil || !node.Status().Running() {
		return httpapi.Unavailable("forgetting this device's tailnet lock state",
			"the tailnet node is not running")
	}
	return node.DisableLockLocally(ctx)
}

// lockKeyLabel renders what the tailnet recorded against a key as a phrase.
//
// The metadata is open-ended, so anything that is not the well-known `purpose` is shown
// whole rather than dropped -- and sorted, because map order is random and an unsorted
// label would reshuffle on every poll.
func lockKeyLabel(k tsnode.LockKey) string {
	if purpose := k.Meta["purpose"]; purpose != "" {
		return purpose
	}
	if len(k.Meta) == 0 {
		return k.ID
	}
	pairs := make([]string, 0, len(k.Meta))
	for name, value := range k.Meta {
		pairs = append(pairs, name+": "+value)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ", ")
}

// lockCapability answers "is tailnet lock affecting this device, and how" in one place.
//
// The order matters. A node that is down is reported first because nothing below it has
// been read at all, and "lock is off" is the one reading of an empty view that a user
// would act on. An unsigned key comes next because it is the state that leaves a user
// with a Running node and no peers, and every other reading of that screen sends them
// looking for a network problem that is not there.
func lockCapability(view httpapi.LockView, nodeUp bool, nodeProblem string) httpapi.Capability {
	switch {
	case !nodeUp:
		reason := "The tailnet node is not running, so this device's tailnet lock state " +
			"cannot be read."
		if nodeProblem != "" {
			reason = "The tailnet node is not running (" + nodeProblem +
				"), so this device's tailnet lock state cannot be read."
		}
		return httpapi.Capability{Reason: reason}
	case view.Error != "":
		return httpapi.Capability{Available: true, Degraded: true, Reason: view.Error}
	case !view.Enabled:
		return httpapi.Capability{
			Available: true,
			Reason: "Tailnet lock is off for your tailnet, so every device your network " +
				"admits can be reached without a signature.",
		}
	case !view.Signed:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "This device is not signed for tailnet lock yet, so it can reach no device " +
				"on your tailnet however your access rules read. Ask someone holding a trusted " +
				"key to run the command above.",
		}
	case len(view.Filtered) > 0:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "Tailnet lock is holding back some devices this one can otherwise see. " +
				"They are unreachable until someone signs them, however your access rules read.",
		}
	}
	return httpapi.Capability{
		Available: true,
		Reason:    "This device is signed for tailnet lock and can reach every device it is allowed to.",
	}
}
