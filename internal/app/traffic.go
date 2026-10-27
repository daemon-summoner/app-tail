// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/sellitus/app-tail/internal/bytecount"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fabric"
	"github.com/sellitus/app-tail/internal/forward"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/traffic"
	"github.com/sellitus/app-tail/internal/tsnode"
	"github.com/sellitus/app-tail/internal/tsproxy"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// trafficInterval is how often the agent reads its own counters, and trafficWindow how
// much of that history it keeps. Five minutes at a second apiece is three hundred small
// structs -- cheap enough not to think about, long enough that a graph shows a transfer
// starting and finishing rather than only the moment it is looked at.
const (
	trafficInterval = time.Second
	trafficWindow   = 5 * time.Minute
)

// tunnelSampleTimeout bounds the one backend call a sample makes. A backend that has
// stopped answering must cost this tick and no more: the sampler is on a fixed ticker, so
// a read left to run would push out the next sample and draw a gap across a window where
// the other counters were perfectly readable.
const tunnelSampleTimeout = 2 * time.Second

// trafficSource reads every counter the agent keeps, at one instant.
//
// The proxy, forward and subnet-router reads are atomics or one uncontended mutex. The
// tunnel totals cost a backend round trip that walks the netmap, which is why they go
// through the node's own short-lived status cache: one dashboard poll and one sample
// landing in the same second share a single call rather than making two.
//
// The tunnel lane is read even though it costs that, because without it interface mode
// reports nothing at all -- packets go straight out through the network interface without
// passing the proxy, a forward or the subnet router, so every other lane in this sample
// correctly reads zero while the machine saturates its uplink.
type trafficSource struct{ a *Agent }

func (t trafficSource) Sample(ctx context.Context) traffic.Sample {
	a := t.a
	s := traffic.Sample{At: time.Now()}

	var destinations map[string]traffic.Row
	if set := a.currentProxies(); set != nil {
		c := set.Counters()
		s.ProxyUp, s.ProxyDown = c.BytesUp, c.BytesDown
		s.ProxyActive, s.ProxyOpened = c.Active, c.Opened
		s.ProxyRefused, s.ProxyFailed = c.Refused, c.Failed
		destinations = destinationRows(c.Destinations)
	}

	var forwards []forward.Status
	if manager := a.currentManager(); manager != nil {
		forwards = manager.Statuses()
		for _, st := range forwards {
			s.ForwardUp += st.BytesUp
			s.ForwardDown += st.BytesDown
			s.ForwardActive += int64(st.ActiveTCP) + int64(st.ActiveUDP)
		}
	}

	if router := a.currentSubnets(); router != nil {
		st := router.Status()
		s.RouteIn, s.RouteOut = int64(st.BytesIn), int64(st.BytesOut)
	}

	// One deadline for every connection read rather than one apiece: the sampler is on a
	// fixed ticker, and a per-connection timeout would let a machine with four connections
	// spend four times the tick before the first backend gave up.
	readCtx, cancel := context.WithTimeout(ctx, tunnelSampleTimeout)
	defer cancel()
	readings := a.tunnelReadings(readCtx)

	s.TunnelUp, s.TunnelDown = tunnelBytes(readings)
	connections := connectionRows(readings)
	mergeFabricCounters(connections, a.fabricCounters())
	s.Keyed = map[traffic.Lane]map[string]traffic.Row{
		traffic.LaneDevices:      deviceRows(readings),
		traffic.LaneConnections:  connections,
		traffic.LaneDestinations: destinations,
		traffic.LanePorts:        a.portRows(readings, forwards),
	}
	return s
}

// tunnelReading is what one connection reported at a sample.
//
// A connection answers for its own totals in one of two ways and never both: a kind that
// sees its own packets counts them, and a kind made of named devices is counted per device
// by the network itself. Holding the device list alongside the totals is what lets one read
// serve both the connection lane and the device lane -- two reads a second of the same
// netmap would be the most expensive thing on this path.
type tunnelReading struct {
	id    string
	label string
	kind  config.TunnelType
	// carried is the connection's own account of itself, and peers the device list for a
	// kind that has one. Exactly one of the two is populated.
	carried traffic.Pair
	peers   []tsnode.Peer
}

// tunnelBytes is what the tailnet has carried in each direction, summed over its peers.
//
// These are WireGuard's own totals, so they cover every byte the node moved however it was
// asked to move it. Per peer, Tx is what this machine sent and Rx what it received, which is
// what makes the sum this machine's own up and down.
//
// Only the primary connection counts here, because this is the lane the flat sample has
// always held and widening it would restate history: a window that spans the moment a second
// connection was added would show a step nothing carried. The connection lane below is where
// every connection is accounted for.
func tunnelBytes(readings []tunnelReading) (up, down int64) {
	for _, r := range readings {
		if r.id != config.PrimaryTunnelID {
			continue
		}
		for _, p := range r.peers {
			up += p.TxBytes
			down += p.RxBytes
		}
	}
	return up, down
}

// tunnelReadings reads every stored connection's counters at one instant.
//
// It walks what is stored rather than what is registered so a connection keeps its name: the
// registry holds ids, and a chart labelled by id names nothing a reader recognises. A
// connection nothing is running contributes no reading at all, which is what marks it absent
// for the tick rather than idle.
//
// A connection that cannot be read is left out for the same reason: the rate derivation
// treats an absence as a gap, which is the truthful reading of a backend that stopped
// answering, and every other connection in the sample is still worth recording.
func (a *Agent) tunnelReadings(ctx context.Context) []tunnelReading {
	held := a.store.Get().Tunnels
	out := make([]tunnelReading, 0, len(held))
	for _, t := range held {
		reading := tunnelReading{id: t.ID, label: t.Name, kind: t.Type}

		switch live, running := a.tunnels.Get(t.ID); {
		case running:
			// Asked of the connection itself rather than derived from its status, the way the
			// connection list asks: only a kind that sees its own packets counts anything, and a
			// kind that counts nothing must report nothing here rather than a confident zero.
			if metered, ok := live.(tunnel.Metered); ok {
				carried := metered.Carried()
				reading.carried = traffic.Pair{Up: carried.Up, Down: carried.Down}
				out = append(out, reading)
				continue
			}
		default:
			// The primary connection's node outlives its registration, so it is read below even
			// when the registry has nothing under this id.
			if t.ID != config.PrimaryTunnelID {
				continue
			}
		}

		node := a.nodeOf(t.ID)
		if node == nil {
			continue
		}
		peers, err := node.Peers(ctx)
		if err != nil {
			a.logger.Debug("traffic sample could not read a connection's totals",
				"tunnel", t.ID, "error", err)
			continue
		}
		reading.peers = peers
		out = append(out, reading)
	}
	return out
}

// deviceRows is what each device on each tailnet carried, keyed so two tailnets holding a
// device of the same name stay two devices.
//
// A device that has never exchanged a byte is left out. It would draw as a flat zero, and
// the keyed table is capped: a tailnet of two hundred idle devices would spend the whole
// budget on lines with nothing in them and fold away the ones that are moving.
func deviceRows(readings []tunnelReading) map[string]traffic.Row {
	rows := map[string]traffic.Row{}
	for _, r := range readings {
		for _, p := range r.peers {
			if p.RxBytes == 0 && p.TxBytes == 0 {
				continue
			}
			rows[r.id+"/"+p.ID] = traffic.Row{
				Label:  p.Label(),
				Detail: pathDetail(p),
				Via:    r.id,
				Peer:   p.ID,
				// Tx is what this machine sent to the device, which is this machine's up.
				Pair: traffic.Pair{Up: p.TxBytes, Down: p.RxBytes},
			}
		}
	}
	return rows
}

// pathDetail is how packets are reaching a device right now: through a named relay, or
// straight to it. It is the usual explanation for a device that works and feels slow.
func pathDetail(p tsnode.Peer) string {
	if p.CurAddr != "" {
		return "direct"
	}
	if p.Relay != "" {
		return "relay " + p.Relay
	}
	return ""
}

// connectionRows is what each connection carried, whichever way it is counted.
func connectionRows(readings []tunnelReading) map[string]traffic.Row {
	rows := make(map[string]traffic.Row, len(readings))
	for _, r := range readings {
		pair := r.carried
		for _, p := range r.peers {
			pair.Up += p.TxBytes
			pair.Down += p.RxBytes
		}
		rows[r.id] = traffic.Row{
			Label:  r.label,
			Detail: r.kind.Label(),
			Via:    r.id,
			Pair:   pair,
		}
	}
	return rows
}

// fabricCounters is what the network interface carried per connection, and nil when the
// interface is not up.
func (a *Agent) fabricCounters() map[string]fabric.Counters {
	runner := a.currentFabric()
	if runner == nil {
		return nil
	}
	snap := runner.snapshot()
	if !snap.running {
		return nil
	}
	return snap.status.Counters
}

// mergeFabricCounters raises a connection's totals to what the interface counted for it,
// where that is more.
//
// The two count the same bytes from either end -- what the interface handed to a connection
// is what that connection then carried -- so they overlap rather than add, and summing them
// would double every byte that crossed in interface mode. The larger is taken because a kind
// that counts nothing of its own reports zero here, and the interface's own tally is then
// the only account of what it carried.
func mergeFabricCounters(rows map[string]traffic.Row, counters map[string]fabric.Counters) {
	for id, c := range counters {
		// The empty key is what the interface refused because no connection carried the
		// address at all. It belongs to no connection, so it names no row.
		row, ok := rows[id]
		if id == "" || !ok {
			continue
		}
		row.Up = max(row.Up, clampToInt64(c.Sent))
		row.Down = max(row.Down, clampToInt64(c.Received))
		rows[id] = row
	}
}

// destinationRows is what each destination a program asked the proxy for has carried.
//
// The proxy's own folded bucket is deliberately not a row: it is a sum over whichever
// destinations happened to be evicted, so it names nothing a reader could filter or
// recognise, and the breakdown reports what was folded as a count instead.
func destinationRows(dests []tsproxy.DestCounters) map[string]traffic.Row {
	rows := make(map[string]traffic.Row, len(dests))
	for _, d := range dests {
		rows[d.Address] = traffic.Row{
			Label:  d.Address,
			Detail: d.Protocol,
			Via:    d.Via,
			Pair:   traffic.Pair{Up: d.BytesUp, Down: d.BytesDown},
		}
	}
	return rows
}

// portRows is what each port carried, gathered from the three places app-tail sees a whole
// flow: the network interface, the subnet router and the forwards.
//
// The three are kept as separate rows rather than summed per port number because they are
// three different things that happen to share a number -- what this machine sent out through
// a connection, what a tailnet device sent in to a routed network, and what a listener on
// this machine accepted. Summing them would produce a figure no counter anywhere holds.
//
// Nothing here is populated in TUN mode: the operating system carries those packets and this
// process never sees a flow, only per-device totals. The breakdown says so in words rather
// than drawing an empty chart, which reads as "nothing is moving".
func (a *Agent) portRows(readings []tunnelReading, forwards []forward.Status) map[string]traffic.Row {
	rows := map[string]traffic.Row{}

	if runner := a.currentFabric(); runner != nil {
		named, _, _ := runner.ports()
		addInterfacePorts(rows, named)
	}

	if router := a.currentSubnets(); router != nil {
		named, _, _ := router.Ports()
		addRoutedPorts(rows, named, peersByAddr(readings))
	}

	addForwardPorts(rows, forwards, a.store.Get().Forwards)
	return rows
}

// addInterfacePorts adds what this machine sent out through the network interface. There is
// no device to name: these are its own outbound flows, not another device's.
func addInterfacePorts(into map[string]traffic.Row, named []bytecount.Row) {
	for _, p := range named {
		into["interface/"+p.Key] = traffic.Row{
			Label:  p.Detail + "/" + p.Label,
			Detail: "interface",
			Via:    p.Via,
			Pair:   traffic.Pair{Up: p.Up, Down: p.Down},
		}
	}
}

// addRoutedPorts adds what tailnet devices sent in to the networks this machine routes.
//
// The router knows a device only as the address it came from, which names nothing on a chart.
// byAddr is the peer list the same sample already read, and is what turns it into a device.
func addRoutedPorts(into map[string]traffic.Row, named []bytecount.Row, byAddr map[string]tsnode.Peer) {
	for _, p := range named {
		row := traffic.Row{
			Label:  p.Detail + "/" + p.Label,
			Detail: "routed",
			Via:    config.PrimaryTunnelID,
			// Bytes the device sent to the routed network are bytes this machine received,
			// which is what makes the router's own down the row's down.
			Pair: traffic.Pair{Up: p.Up, Down: p.Down},
		}
		if peer, ok := byAddr[p.Peer]; ok {
			row.Peer = peer.ID
			row.Detail = peer.Label()
		}
		into["routed/"+p.Key] = row
	}
}

// addForwardPorts adds each forward as the port it listens on. A status whose forward the
// document no longer holds can name no port, so it is left out rather than drawn under its id.
func addForwardPorts(into map[string]traffic.Row, forwards []forward.Status, stored []config.Forward) {
	byID := map[string]config.Forward{}
	for _, f := range stored {
		byID[f.ID] = f
	}
	for _, st := range forwards {
		f, ok := byID[st.ID]
		if !ok {
			continue
		}
		into["forward/"+st.ID] = traffic.Row{
			Label:  string(f.Protocol) + "/" + strconv.Itoa(f.ListenPort),
			Detail: "forward",
			Via:    f.Connection(),
			Pair:   traffic.Pair{Up: st.BytesUp, Down: st.BytesDown},
		}
	}
}

// peersByAddr indexes every device on every tailnet by each address it answers to, which is
// the only handle the subnet router has on the device that reached it.
func peersByAddr(readings []tunnelReading) map[string]tsnode.Peer {
	out := map[string]tsnode.Peer{}
	for _, r := range readings {
		for _, p := range r.peers {
			for _, ip := range p.IPs {
				out[ip] = p
			}
		}
	}
	return out
}

// clampToInt64 holds an unsigned counter inside the signed one the samples are kept in. A
// machine would have to move eight exabytes to reach it; clamping rather than wrapping is
// what keeps that from being drawn as a counter reset.
func clampToInt64(n uint64) int64 {
	if n > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(n)
}

// trafficAPI answers the dashboard's traffic view.
type trafficAPI struct{ a *Agent }

// maxSeries is how many keys one breakdown names individually.
//
// Eight is what a line chart can be read at: past it the colours stop telling lines apart,
// and it is also exactly how many chart colours the dashboard's palette defines. Everything
// quieter is summed into one trailing line rather than dropped, so the chart still adds up
// to what the machine-wide lane says.
const maxSeries = 8

// Breakdown is one lane of the rolling window, split by what that lane names.
func (t trafficAPI) Breakdown(_ context.Context, name string) (httpapi.TrafficBreakdown, error) {
	lane := traffic.Lane(name)
	if !slices.Contains(traffic.Lanes, lane) {
		return httpapi.TrafficBreakdown{}, fmt.Errorf("traffic breakdown %q: %w", name, config.ErrNotFound)
	}

	out := httpapi.TrafficBreakdown{
		Lane:        name,
		IntervalSec: int(trafficInterval.Seconds()),
		WindowSec:   int(trafficWindow.Seconds()),
		Unmeasured:  t.a.unmeasured(lane),
		// Empty rather than nil: a lane naming nothing yet is the ordinary state on a quiet
		// network, and a nil slice would reach the dashboard as null where it declares a list.
		Series: []httpapi.TrafficSeries{},
	}

	sampler := t.a.currentSampler()
	if sampler == nil {
		// Before the agent has started, or after it has stopped: an empty window is the honest
		// answer, and the dashboard draws nothing rather than inventing a floor.
		return out, nil
	}
	out.IntervalSec = int(sampler.Interval().Seconds())

	// The lane was checked against the set the sampler builds its tables from, so it has one.
	table := sampler.Lane(lane)

	// Both are read before anything is derived from them, and the sampler keeps writing
	// meanwhile: taking the times after the snapshot would pair one tick's readings with the
	// next tick's clock and shift every rate on the chart by an interval.
	when := table.Times()
	series, dropped := table.Snapshot()
	out.Folded = dropped

	named, rest := series, []traffic.Series(nil)
	if len(series) > maxSeries {
		named, rest = series[:maxSeries], series[maxSeries:]
	}
	for _, s := range named {
		rates := s.Rates(when, sampler.Interval())
		out.Series = append(out.Series, httpapi.TrafficSeries{
			Key:    s.Key,
			Label:  s.Label,
			Detail: s.Detail,
			Via:    s.Via,
			Peer:   s.Peer,
			Up:     upOf(rates),
			Down:   downOf(rates),
		})
	}
	if len(rest) > 0 {
		rates := make([][]traffic.Movement, 0, len(rest))
		for _, s := range rest {
			rates = append(rates, s.Rates(when, sampler.Interval()))
		}
		folded := traffic.Fold(rates)
		out.Series = append(out.Series, httpapi.TrafficSeries{
			Key:    otherKey,
			Label:  "Everything else",
			Detail: fmt.Sprintf("%d more", len(rest)),
			Up:     upOf(folded),
			Down:   downOf(folded),
		})
		out.Folded += len(rest)
	}
	return out, nil
}

// unmeasured says why a lane cannot be complete right now, in words the dashboard shows
// instead of a chart, and empty when the lane is measured in full.
//
// Only ports has an answer, and only in TUN mode: the operating system carries the packets
// through a real network interface, so this process sees per-device totals and never a flow.
// Drawing an empty chart there would say the machine is quiet when it may be saturating its
// uplink.
func (a *Agent) unmeasured(lane traffic.Lane) string {
	if lane != traffic.LanePorts {
		return ""
	}
	node := a.currentNode()
	if node == nil || node.Status().Network != config.NetworkTUN {
		return ""
	}
	return "Ports are not broken out in TUN mode: the operating system carries these packets, " +
		"so app-tail sees per-device totals rather than individual flows."
}

// otherKey names the series standing for everything the chart is not drawing by name. It is
// not a key any lane produces -- devices are node ids, connections are connection ids -- so
// it cannot collide with a real one.
const otherKey = "__other__"

// upOf and downOf pull one direction out of a window of movement, turning an interval that
// could not be measured into the null the chart breaks its line at rather than into a zero
// it would draw as quiet.
func upOf(rates []traffic.Movement) []*float64 {
	out := make([]*float64, len(rates))
	for i, m := range rates {
		if m.Gap {
			continue
		}
		out[i] = &rates[i].Up
	}
	return out
}

func downOf(rates []traffic.Movement) []*float64 {
	out := make([]*float64, len(rates))
	for i, m := range rates {
		if m.Gap {
			continue
		}
		out[i] = &rates[i].Down
	}
	return out
}

// View is the rolling window, the current rates derived from it, and where the traffic
// went -- per tailnet peer and, for the proxy, per destination.
func (t trafficAPI) View(ctx context.Context) httpapi.TrafficView {
	a := t.a

	sampler := a.currentSampler()
	if sampler == nil {
		// Before the agent has started, or after it has stopped: an empty window is the
		// honest answer, and the dashboard draws nothing rather than inventing a floor.
		return httpapi.TrafficView{IntervalSec: int(trafficInterval.Seconds())}
	}

	samples := sampler.Ring().Samples()
	points := traffic.Rates(samples, sampler.Interval())
	latest := traffic.Latest(points)

	view := httpapi.TrafficView{
		IntervalSec: int(sampler.Interval().Seconds()),
		WindowSec:   int(trafficWindow.Seconds()),
		Points:      points,
		Current:     latest,
	}

	if set := a.currentProxies(); set != nil {
		c := set.Counters()
		view.Destinations = c.Destinations
		view.Other = c.Other
		view.Folded = c.Folded
		view.Totals = httpapi.TrafficTotals{
			ProxyUp:   c.BytesUp,
			ProxyDown: c.BytesDown,
			Refused:   c.Refused,
			Failed:    c.Failed,
		}
	}

	view.Peers = a.trafficPeers(ctx)
	return view
}

// trafficPeers is what the tailnet has carried to and from each device.
//
// These are WireGuard's own totals, so they cover every byte the node moved -- forwards,
// the proxy, routed subnets and exit-node traffic alike -- which is why the peer table
// can disagree with the proxy's own figures without either being wrong.
//
// A tailnet that cannot be reached yields no peers rather than an error: the rest of the
// view is still worth drawing, and the dashboard already says elsewhere that the node is
// down. Reporting it again here would be a second alarm for one fault.
func (a *Agent) trafficPeers(ctx context.Context) []httpapi.TrafficPeer {
	node := a.currentNode()
	if node == nil {
		return nil
	}
	peers, err := node.Peers(ctx)
	if err != nil {
		a.logger.Debug("traffic view could not read the peer list", "error", err)
		return nil
	}

	latency := a.peerLatency()
	out := make([]httpapi.TrafficPeer, 0, len(peers))
	for _, p := range peers {
		// A peer that has never exchanged a byte and is not online is noise on a page
		// about what is moving; the device picker is where the full list belongs.
		if p.RxBytes == 0 && p.TxBytes == 0 && !p.Online {
			continue
		}
		peer := httpapi.TrafficPeer{
			ID:       p.ID,
			Label:    p.Label(),
			Online:   p.Online,
			Active:   p.Active,
			RxBytes:  p.RxBytes,
			TxBytes:  p.TxBytes,
			Relay:    p.Relay,
			Direct:   p.CurAddr != "",
			ExitNode: p.ExitNodeCurrent,
		}
		if !p.LastHandshake.IsZero() {
			peer.LastHandshake = p.LastHandshake
		}
		if rtt, ok := latency[p.ID]; ok {
			peer.LatencyMs = float64(rtt.Microseconds()) / 1000
		}
		out = append(out, peer)
	}
	return out
}

// latencyInterval is how often peers are measured while the setting is on. Slower than
// the traffic sampler by design: each round sends a real packet to every device, and a
// round trip does not change second to second the way a byte counter does.
const latencyInterval = 10 * time.Second

// runLatencyProbes measures the round trip to each peer while the setting asks for it.
//
// Off by default and off unless asked, because it is the one thing on this page that
// makes the machine send traffic rather than only report it: a laptop on battery should
// not be waking its radio every ten seconds to draw a column nobody switched on.
func (a *Agent) runLatencyProbes(ctx context.Context) {
	tick := time.NewTicker(latencyInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			a.probePeerLatency(ctx)
		}
	}
}

// probePeerLatency runs one measurement round, or clears the results when the setting is
// off. Clearing rather than leaving them is what keeps a stale figure from being read as
// live after someone switches the probing back off.
func (a *Agent) probePeerLatency(ctx context.Context) {
	if !a.settings().TrafficLatency {
		if a.peerLatency() != nil {
			a.setPeerLatency(nil)
		}
		return
	}

	node := a.currentNode()
	if node == nil {
		return
	}
	peers, err := node.Peers(ctx)
	if err != nil {
		a.logger.Debug("latency round could not read the peer list", "error", err)
		return
	}

	targets := make([]probeTarget, 0, len(peers))
	for _, p := range peers {
		// Offline devices are skipped rather than measured and left out: probing one
		// costs the full timeout, and a round spent waiting on devices that are away
		// delays the answer for every device that is not.
		if !p.Online || len(p.IPs) == 0 {
			continue
		}
		addr, err := netip.ParseAddr(p.IPs[0])
		if err != nil {
			continue
		}
		targets = append(targets, probeTarget{ID: p.ID, Label: p.Label(), Addr: addr})
	}
	if len(targets) == 0 {
		a.setPeerLatency(nil)
		return
	}

	a.setPeerLatency(measureLatency(ctx, node, targets, a.logger))
}
