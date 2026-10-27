// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sellitus/app-tail/internal/automap"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/ports"
)

// peerListTimeout bounds the peer read the reconcile loop makes. It is short because
// the loop is also what starts and stops every forward: a slow answer here delays all
// of them, and the previous mapping stands in until the next pass.
const peerListTimeout = 5 * time.Second

// autoMapState is the last plan the reconcile loop produced, kept so the forwards API
// can report the derived entries without recomputing them -- and so the API and the
// running forwards can never disagree about which ones exist.
type autoMapState struct {
	mu        sync.RWMutex
	forwards  []config.Forward
	truncated int
	reason    string
}

func (a *autoMapState) snapshot() ([]config.Forward, int, string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.forwards, a.truncated, a.reason
}

func (a *autoMapState) publish(forwards []config.Forward, truncated int, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.forwards, a.truncated, a.reason = forwards, truncated, reason
}

// autoMapForwards derives the forwards for the current peer list and merges them with
// the stored ones, newly allocated ports written back before they are used.
//
// A failure here yields no derived forwards and a reason the dashboard shows, rather
// than a partial set: half a mapping is a listener on a port whose peer nobody can
// name, and the user cannot tell it from a peer that is simply down.
func (a *Agent) autoMapForwards(ctx context.Context, stored []config.Forward, nodeUp bool) []config.Forward {
	settings := a.settings()
	if !settings.AutoMapEnabled {
		a.autoMap.publish(nil, 0, "")
		return stored
	}
	if !nodeUp {
		// The peer list is empty until the node is running, and mapping against an
		// empty list would tear every derived forward down and put it back moments
		// later. Holding the previous plan keeps the ports bound and refusing, which
		// is the same thing every other forward does while the node is down.
		previous, truncated, _ := a.autoMap.snapshot()
		a.autoMap.publish(previous, truncated, "the tailnet node is not running, so the device list is the last one seen")
		return append(stored, previous...)
	}

	remotePorts, err := settings.AutoMapPortList()
	if err != nil {
		a.autoMap.publish(nil, 0, err.Error())
		return stored
	}

	// Bounded because this runs on the one goroutine that starts and stops every
	// forward: a peer read that hung would stop the whole engine reconciling.
	peerCtx, cancel := context.WithTimeout(ctx, peerListTimeout)
	peers, err := a.node.Peers(peerCtx)
	cancel()
	if err != nil {
		previous, truncated, _ := a.autoMap.snapshot()
		a.autoMap.publish(previous, truncated,
			fmt.Sprintf("the device list could not be read, so the mappings are the last ones seen: %v", err))
		return append(stored, previous...)
	}

	plan, err := automap.Build(automap.Params{
		// The primary connection, because these are its peers: a.node is the tailnet this
		// installation was built around, and the module maps the devices on it. A second
		// connection's devices are mapped when that connection is asked to, not here.
		TunnelID: config.PrimaryTunnelID,
		Peers:    peers,
		Ports:    remotePorts,
		Max:      settings.AutoMapLimit(),
		PortBase: settings.AutoMapBase(),
		Existing: a.store.Get().AutoMap,
		Allocate: a.autoMapAllocator(stored),
		Disabled: autoMapOffSet(a.store.Get().AutoMapOff),
		BindAddr: config.DefaultBindAddr,
	})
	if err != nil {
		a.logger.Warn("automatic port mapping could not be planned", "error", err)
		a.autoMap.publish(nil, 0, err.Error())
		return stored
	}

	// Persisted before the forwards are used: a mapping that started listening on a
	// port no run after this one would reproduce is the one failure this module has to
	// rule out, so the assignment is durable before anything depends on it.
	if plan.Allocations != nil {
		if _, err := a.store.Update(func(c *config.Config) error {
			c.AutoMap = plan.Allocations
			return nil
		}); err != nil {
			a.logger.Warn("recording the automatic port assignments failed", "error", err)
			a.autoMap.publish(nil, 0, fmt.Sprintf("the port assignments could not be saved, so nothing was mapped: %v", err))
			return stored
		}
	}

	a.autoMap.publish(plan.Forwards, plan.Truncated, truncationReason(plan.Truncated, settings.AutoMapLimit()))
	return append(stored, plan.Forwards...)
}

// truncationReason explains a limit that left devices out. Silence here would read as
// "your newest device does not work", which is the wrong conclusion to leave someone.
func truncationReason(truncated, limit int) string {
	if truncated == 0 {
		return ""
	}
	return fmt.Sprintf("%d more device-and-port pairs than the limit of %d; raise the limit "+
		"or map fewer ports to reach them", truncated, limit)
}

// autoMapAllocator hands out local ports that nothing else already holds: no stored
// forward, no assignment made on an earlier run, not the dashboard's own port -- and
// that are free to bind right now.
//
// Assignments from earlier runs are claimed even for devices not currently mapped. They
// are still owed to those devices, and handing one to a new device would move a port
// that something out there already names.
func (a *Agent) autoMapAllocator(stored []config.Forward) automap.Allocator {
	claimed := make(map[int]bool, len(stored))
	for _, f := range stored {
		if f.Direction == config.ToLocal && f.Protocol.CarriesTCP() {
			claimed[f.ListenPort] = true
		}
	}
	for _, port := range a.store.Get().AutoMap {
		claimed[port] = true
	}
	if addr := a.UIAddr(); addr != nil {
		if port := portOf(addr.String()); port != 0 {
			claimed[port] = true
		}
	}
	return func(preferred int) (int, error) {
		port, err := ports.Suggest(config.TCP, config.DefaultBindAddr, preferred, func(p int) bool {
			return claimed[p]
		})
		if err != nil {
			return 0, err
		}
		claimed[port] = true
		return port, nil
	}
}

// autoMapAPI presents the derived mappings to the management API.
type autoMapAPI struct{ a *Agent }

var _ httpapi.AutoMap = autoMapAPI{}

// AutoMap exposes the automatic port mapping module.
func (a *Agent) AutoMap() httpapi.AutoMap { return autoMapAPI{a: a} }

func (m autoMapAPI) View() httpapi.AutoMapView {
	settings := m.a.settings()
	forwards, truncated, reason := m.a.autoMap.snapshot()

	view := httpapi.AutoMapView{
		Enabled:   settings.AutoMapEnabled,
		Limit:     settings.AutoMapLimit(),
		Truncated: truncated,
		Mapped:    len(forwards),
		Reason:    reason,
		Stored:    len(m.a.store.Get().AutoMap),
	}
	if ports, err := settings.AutoMapPortList(); err == nil {
		view.Ports = ports
	}
	return view
}

// Forget drops the stored assignments for devices the tailnet no longer reports, and
// reports how many went.
//
// It is a deliberate action rather than part of the reconcile loop: an empty peer list
// is also what a node that has not finished starting looks like, and pruning on that
// would hand every device a new port -- breaking exactly the promise this module makes.
func (m autoMapAPI) Forget(ctx context.Context) (int, error) {
	node := m.a.currentNode()
	if node == nil || !node.Status().Running() {
		return 0, httpapi.Unavailable("automatic ports",
			"the tailnet node is not running, so the device list cannot be trusted to prune against")
	}

	peers, err := node.Peers(ctx)
	if err != nil {
		return 0, fmt.Errorf("read the device list to prune against: %w", err)
	}

	var removed int
	if _, err := m.a.store.Update(func(c *config.Config) error {
		kept, gone := automap.Prune(config.PrimaryTunnelID, c.AutoMap, peers)
		c.AutoMap, removed = kept, gone
		return nil
	}); err != nil {
		return 0, fmt.Errorf("drop the assignments for devices that are gone: %w", err)
	}
	m.a.pokeReconcile()
	return removed, nil
}

// findAutoForward looks up one derived forward by id.
func (a *Agent) findAutoForward(id string) (config.Forward, bool) {
	derived, _, _ := a.autoMap.snapshot()
	for _, f := range derived {
		if f.ID == id {
			return f, true
		}
	}
	return config.Forward{}, false
}

// isAutoForward reports that an id names a derived forward. They are rebuilt from the
// peer list on every reconcile, so a write to one would be undone without explanation.
func isAutoForward(id string) bool { return strings.HasPrefix(id, automap.IDPrefix) }

// autoMapOffSet is the stored off-list in the shape the planner reads it in.
func autoMapOffSet(ids []string) map[string]bool {
	if len(ids) == 0 {
		return nil
	}
	off := make(map[string]bool, len(ids))
	for _, id := range ids {
		off[id] = true
	}
	return off
}

// autoMapOffWith is the off-list with one mapping added or removed. It is sorted and
// free of duplicates so that flipping the same switch twice leaves the document exactly
// as it was, rather than growing a line per click.
func autoMapOffWith(ids []string, id string, off bool) []string {
	out := make([]string, 0, len(ids)+1)
	for _, have := range ids {
		if have != id {
			out = append(out, have)
		}
	}
	if off {
		out = append(out, id)
		sort.Strings(out)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// autoForwardRefusal is what a write to a derived forward is refused with. It names the
// module rather than only reporting a failure, so the reader knows which switch to turn
// off to take the port over.
func autoForwardRefusal(id string) error {
	return httpapi.Unavailable(fmt.Sprintf("editing %q", id),
		fmt.Sprintf("it is created by the %s module and is rebuilt from the device list; "+
			"turn that module off to manage this port yourself", config.ModuleLabel(config.ModuleAutoMap)))
}
