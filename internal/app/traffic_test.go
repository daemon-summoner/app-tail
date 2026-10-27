// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/bytecount"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fabric"
	"github.com/sellitus/app-tail/internal/forward"
	"github.com/sellitus/app-tail/internal/traffic"
	"github.com/sellitus/app-tail/internal/tsnode"
	"github.com/sellitus/app-tail/internal/tsproxy"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// In interface mode packets leave through the network interface without passing the
// proxy, a forward or the subnet router, so every counter the sampler used to read stays
// at zero however hard the machine is working. Without the tunnel lane the traffic graph
// reports a saturated uplink as idle, which is the bug this pins.
func TestASampleCarriesWhatTheTunnelMovedEvenWithNothingElseRunning(t *testing.T) {
	node := newFakeNode()
	node.setPeers(
		tsnode.Peer{ID: "n1", TxBytes: 4_000, RxBytes: 11_000},
		tsnode.Peer{ID: "n2", TxBytes: 500, RxBytes: 40},
	)
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return node })
	agent.node = node

	s := trafficSource{a: agent}.Sample(context.Background())

	// Per peer, Tx is what this machine sent and Rx what it received, so the sums are this
	// machine's own up and down. Swapping them reports every upload as a download.
	if s.TunnelUp != 4_500 {
		t.Errorf("tunnelUp = %d, want 4500 (the peers' Tx totals)", s.TunnelUp)
	}
	if s.TunnelDown != 11_040 {
		t.Errorf("tunnelDown = %d, want 11040 (the peers' Rx totals)", s.TunnelDown)
	}
	// The point of the lane: nothing else in this sample saw any of it.
	if s.ProxyUp != 0 || s.ForwardUp != 0 || s.RouteOut != 0 {
		t.Errorf("proxy/forward/route lanes = %d/%d/%d, want zero -- the fixture runs none of them",
			s.ProxyUp, s.ForwardUp, s.RouteOut)
	}
}

// A backend that cannot answer must cost this lane and nothing else. Failing the whole
// sample would throw away the proxy, forward and subnet-router counters, which were read
// without touching the backend and are still true.
func TestAnUnreadableTunnelLeavesTheRestOfTheSampleIntact(t *testing.T) {
	node := newFakeNode()
	node.failPeers(errors.New("the backend is not answering"))
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return node })
	agent.node = node

	s := trafficSource{a: agent}.Sample(context.Background())

	if s.TunnelUp != 0 || s.TunnelDown != 0 {
		t.Errorf("tunnel up/down = %d/%d with the backend down, want zero rather than a guess",
			s.TunnelUp, s.TunnelDown)
	}
	if s.At.IsZero() {
		t.Error("the sample was abandoned, so the lanes that did read correctly were lost too")
	}
}

// Before the node exists there is nothing to ask, and asking anyway is a nil dereference
// on the agent's own sampling goroutine -- which takes the process down rather than one
// graph.
func TestSamplingBeforeTheNodeExistsIsHarmless(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })

	s := trafficSource{a: agent}.Sample(context.Background())

	if s.TunnelUp != 0 || s.TunnelDown != 0 {
		t.Errorf("tunnel up/down = %d/%d with no node, want zero", s.TunnelUp, s.TunnelDown)
	}
}

// The flat lane answers "how much", and could always answer it by summing the peer list.
// Keeping the breakdown is what lets the dashboard answer "whose", which is the whole point
// of the device graph: a saturated uplink with no idea which machine is doing it.
func TestASampleKeepsWhatEachDeviceCarried(t *testing.T) {
	node := newFakeNode()
	node.setPeers(
		tsnode.Peer{ID: "n1", HostName: "nas", TxBytes: 4_000, RxBytes: 11_000, CurAddr: "100.64.0.2:41641"},
		tsnode.Peer{ID: "n2", HostName: "phone", TxBytes: 500, RxBytes: 40, Relay: "nyc"},
	)
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return node })
	agent.node = node

	rows := trafficSource{a: agent}.Sample(context.Background()).Keyed[traffic.LaneDevices]

	if len(rows) != 2 {
		t.Fatalf("the device lane held %d rows, want one per peer", len(rows))
	}
	nas, ok := rows[config.PrimaryTunnelID+"/n1"]
	if !ok {
		t.Fatalf("no row for n1; the lane held %v", keysOfRows(rows))
	}
	// Tx is what this machine sent to the device, so it is this machine's up. Swapping them
	// reports every upload as a download, which no total on the page would contradict.
	if nas.Up != 4_000 || nas.Down != 11_000 {
		t.Errorf("n1 carried up/down = %d/%d, want 4000/11000", nas.Up, nas.Down)
	}
	if nas.Label != "nas" || nas.Detail != "direct" || nas.Peer != "n1" {
		t.Errorf("n1 labelled %q/%q/%q, want the device's own name, path and id",
			nas.Label, nas.Detail, nas.Peer)
	}
	// The connection is on every row so the port lane can be filtered by it later, and so two
	// tailnets holding a device of the same name stay two devices.
	if nas.Via != config.PrimaryTunnelID {
		t.Errorf("n1 carried via %q, want the connection it was read from", nas.Via)
	}
	if phone := rows[config.PrimaryTunnelID+"/n2"]; phone.Detail != "relay nyc" {
		t.Errorf("n2 detailed %q, want the relay carrying it", phone.Detail)
	}
}

// The keyed table is capped, and a tailnet of a few hundred devices is ordinary. A device
// that has never exchanged a byte would draw as a flat zero while displacing one that is
// actually moving, so it is not a row at all.
func TestASampleLeavesOutADeviceThatHasCarriedNothing(t *testing.T) {
	node := newFakeNode()
	node.setPeers(
		tsnode.Peer{ID: "busy", TxBytes: 1, RxBytes: 0},
		tsnode.Peer{ID: "idle", Online: true},
	)
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return node })
	agent.node = node

	rows := trafficSource{a: agent}.Sample(context.Background()).Keyed[traffic.LaneDevices]

	if _, ok := rows[config.PrimaryTunnelID+"/idle"]; ok {
		t.Errorf("the lane held a row for a device that has carried nothing: %v", keysOfRows(rows))
	}
	if _, ok := rows[config.PrimaryTunnelID+"/busy"]; !ok {
		t.Errorf("the lane dropped the device that has carried something: %v", keysOfRows(rows))
	}
}

// Two kinds of connection are counted two ways and never both: one that sees its own packets
// counts them, and a tailnet is counted per device by the network itself. A lane that read
// only one of them would draw half the machine's connections as permanently idle.
func TestASampleCountsEachConnectionHoweverItIsCounted(t *testing.T) {
	node := newFakeNode()
	node.setPeers(tsnode.Peer{ID: "n1", TxBytes: 4_000, RxBytes: 11_000})
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return node })
	agent.node = node

	wg := newFakeWireGuard("wg1", config.WireGuardTunnel{})
	wg.carries(tunnel.Carried{Up: 700, Down: 900})
	addStoredTunnel(t, agent, "wg1", "work", config.TunnelWireGuard)
	if err := agent.tunnels.Add(wg); err != nil {
		t.Fatalf("register the connection: %v", err)
	}

	rows := trafficSource{a: agent}.Sample(context.Background()).Keyed[traffic.LaneConnections]

	tailnet, ok := rows[config.PrimaryTunnelID]
	if !ok {
		t.Fatalf("no row for the tailnet; the lane held %v", keysOfRows(rows))
	}
	if tailnet.Up != 4_000 || tailnet.Down != 11_000 {
		t.Errorf("the tailnet carried up/down = %d/%d, want its peers' totals 4000/11000",
			tailnet.Up, tailnet.Down)
	}
	work, ok := rows["wg1"]
	if !ok {
		t.Fatalf("no row for the WireGuard connection; the lane held %v", keysOfRows(rows))
	}
	if work.Up != 700 || work.Down != 900 {
		t.Errorf("the WireGuard connection carried up/down = %d/%d, want its own counters 700/900",
			work.Up, work.Down)
	}
	// Labelled by what the user named it, not by the id the registry holds: a chart of ids
	// names nothing anybody recognises.
	if work.Label != "work" || work.Detail != "WireGuard" {
		t.Errorf("the WireGuard connection labelled %q/%q, want its stored name and kind",
			work.Label, work.Detail)
	}
}

// A connection that is stored but not running has no counters to report. Reporting a zero
// would draw a flat line where the truthful answer is that nothing was measured.
func TestASampleLeavesOutAConnectionNothingIsRunning(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	addStoredTunnel(t, agent, "wg1", "work", config.TunnelWireGuard)

	rows := trafficSource{a: agent}.Sample(context.Background()).Keyed[traffic.LaneConnections]

	if _, ok := rows["wg1"]; ok {
		t.Errorf("the lane held a row for a connection nothing is running: %v", keysOfRows(rows))
	}
}

// In interface mode the same bytes are counted twice -- once by the interface handing them
// to a connection, once by that connection carrying them. Adding the two would draw double
// the traffic that crossed, on the one mode where this graph is the only thing measuring.
func TestTheInterfaceTallyDoesNotAddToWhatAConnectionAlreadyCounted(t *testing.T) {
	rows := map[string]traffic.Row{
		"wg1": {Label: "work", Pair: traffic.Pair{Up: 1_000, Down: 5_000}},
		"wg2": {Label: "home", Pair: traffic.Pair{Up: 0, Down: 0}},
	}

	mergeFabricCounters(rows, map[string]fabric.Counters{
		// Less than the connection's own count, which is the ordinary case: the connection
		// counts its own overheads too.
		"wg1": {Sent: 900, Received: 4_800},
		// A kind that counts nothing of its own. The interface's tally is then the only
		// account there is of what it carried.
		"wg2": {Sent: 20, Received: 30},
		// Refused because no connection carried the address at all, so it belongs to none.
		"": {Sent: 77},
	})

	if got := rows["wg1"]; got.Up != 1_000 || got.Down != 5_000 {
		t.Errorf("wg1 carried up/down = %d/%d, want its own larger counters 1000/5000 rather than a sum",
			got.Up, got.Down)
	}
	if got := rows["wg2"]; got.Up != 20 || got.Down != 30 {
		t.Errorf("wg2 carried up/down = %d/%d, want the interface's tally 20/30", got.Up, got.Down)
	}
	if _, ok := rows[""]; ok {
		t.Error("the unattributed tally became a connection row; it belongs to no connection")
	}
}

// The destination lane is what makes "9 MB/s up" answerable as "9 of it to the NAS": both
// halves of that sentence -- which destination and through which connection -- have to
// survive the sample, or the chart can be drawn but not filtered.
func TestASampleKeepsWhereEachDestinationWentAndHow(t *testing.T) {
	rows := destinationRows([]tsproxy.DestCounters{
		{Address: "nas.home:445", BytesUp: 900, BytesDown: 12_000, Via: "wg1", Protocol: "tcp"},
		{Address: "dns.home:53", BytesUp: 40, BytesDown: 80, Via: "tn_primary", Protocol: "udp"},
	})

	nas, ok := rows["nas.home:445"]
	if !ok {
		t.Fatalf("the lane held %v, want a row per destination", keysOfRows(rows))
	}
	if nas.Up != 900 || nas.Down != 12_000 {
		t.Errorf("the NAS carried up/down = %d/%d, want 900/12000", nas.Up, nas.Down)
	}
	if nas.Via != "wg1" || nas.Detail != "tcp" {
		t.Errorf("the NAS row went via %q over %q, want wg1 over tcp -- the filter reads both",
			nas.Via, nas.Detail)
	}
	if got := rows["dns.home:53"]; got.Via != "tn_primary" || got.Detail != "udp" {
		t.Errorf("the resolver row went via %q over %q, want tn_primary over udp", got.Via, got.Detail)
	}
}

// A forward has one fixed listen port, so it is a port row without any new counting. It has
// to name the connection it crosses, or the ports chart cannot be filtered by connection the
// way the interface's own rows can.
func TestASampleCountsAForwardAsThePortItListensOn(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	addStoredTunnel(t, agent, "wg1", "work", config.TunnelWireGuard)
	if _, err := agent.store.Update(func(c *config.Config) error {
		c.Forwards = append(c.Forwards, config.Forward{
			ID: "fw1", Name: "smb", TunnelID: "wg1", Direction: config.ToLocal,
			Protocol: config.TCP, BindAddr: "127.0.0.1", ListenPort: 445, Target: "nas:445", Enabled: true,
		})
		return nil
	}); err != nil {
		t.Fatalf("store a forward: %v", err)
	}

	rows := agent.portRows(nil, []forward.Status{
		{ID: "fw1", BytesUp: 700, BytesDown: 2_100},
		// A forward the document no longer holds: it can name no port, so it is left out
		// rather than drawn under its own id.
		{ID: "gone", BytesUp: 5},
	})

	row, ok := rows["forward/fw1"]
	if !ok {
		t.Fatalf("the lane held %v, want the forward's port", keysOfRows(rows))
	}
	if row.Label != "tcp/445" {
		t.Errorf("the forward drew as %q, want tcp/445", row.Label)
	}
	if row.Via != "wg1" {
		t.Errorf("the forward crossed %q, want wg1", row.Via)
	}
	if row.Up != 700 || row.Down != 2_100 {
		t.Errorf("the forward carried up/down = %d/%d, want 700/2100", row.Up, row.Down)
	}
	if _, ok := rows["forward/gone"]; ok {
		t.Errorf("a forward the document no longer holds became a row: %v", keysOfRows(rows))
	}
}

// In interface mode nothing else on this machine sees a flow, so what the interface counts is
// the only account there is. It has to reach the sample by both handles the graphs use: the
// per-connection totals the flat lanes raise themselves to, and the per-port rows.
func TestARunningInterfaceReachesTheSampleByBothItsCounters(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	live := newFakeFabric(fabric.LiveOptions{Name: "apptest0", MTU: fabricFloorMTU})
	live.counters = map[string]fabric.Counters{"wg1": {Sent: 900, Received: 4_800}}
	live.ports = []bytecount.Row{
		{Key: "tcp/443", Meta: bytecount.Meta{Label: "443", Detail: "tcp", Via: "wg1"},
			Up: 900, Down: 4_800},
	}
	runner := newFabricRunner(quietLogger(), nil, nil, func(context.Context, fabric.LiveOptions) (fabricLive, error) {
		return live, nil
	}, nil)
	runner.apply(context.Background(), fabricTarget{
		on: true, table: &fabric.Table{}, routes: []netip.Prefix{labRange}, mtu: fabricFloorMTU,
	})
	agent.fabric = runner

	if got := agent.fabricCounters()["wg1"]; got.Sent != 900 || got.Received != 4_800 {
		t.Errorf("the interface's connection counters read %+v, want 900 sent and 4800 received", got)
	}
	row, ok := agent.portRows(nil, nil)["interface/tcp/443"]
	if !ok {
		t.Fatalf("the ports lane held %v, want the port the interface carried",
			keysOfRows(agent.portRows(nil, nil)))
	}
	if row.Via != "wg1" || row.Up != 900 || row.Down != 4_800 {
		t.Errorf("the port crossed %q carrying %d/%d, want wg1 carrying 900/4800",
			row.Via, row.Up, row.Down)
	}
}

// Counters are unsigned and the samples are signed. A machine would have to move eight
// exabytes to reach the edge; clamping rather than wrapping is what keeps that from being
// drawn as a counter reset, which blanks the chart.
func TestACounterPastTheSignedEdgeClampsRatherThanWraps(t *testing.T) {
	if got := clampToInt64(math.MaxUint64); got != math.MaxInt64 {
		t.Errorf("clamped to %d, want the signed maximum rather than a wrap", got)
	}
	if got := clampToInt64(900); got != 900 {
		t.Errorf("clamped an ordinary counter to %d, want it untouched", got)
	}
}

// The three seams share a port number and nothing else: what this machine sent out through a
// connection, what a device sent in to a routed network, and what a listener here accepted.
// Summed per port they would report a figure no counter anywhere holds, so each keeps its own
// row and says which of the three it is.
func TestThePortsLaneKeepsTheThreeSeamsApart(t *testing.T) {
	rows := map[string]traffic.Row{}
	addInterfacePorts(rows, []bytecount.Row{
		{Key: "tcp/443", Meta: bytecount.Meta{Label: "443", Detail: "tcp", Via: "wg1"}, Up: 900, Down: 12_000},
	})
	addRoutedPorts(rows, []bytecount.Row{
		{Key: "tcp/443/100.64.0.7", Meta: bytecount.Meta{Label: "443", Detail: "tcp", Peer: "100.64.0.7"},
			Up: 30, Down: 70},
	}, nil)

	if len(rows) != 2 {
		t.Fatalf("the lane held %v, want a row per seam rather than one summed port", keysOfRows(rows))
	}
	out, ok := rows["interface/tcp/443"]
	if !ok {
		t.Fatalf("the lane held %v, want the interface's own port", keysOfRows(rows))
	}
	if out.Label != "tcp/443" || out.Detail != "interface" {
		t.Errorf("the interface port drew as %q (%q), want tcp/443 marked interface", out.Label, out.Detail)
	}
	// Which connection carried it is what the ports chart filters by, and the interface is the
	// one seam that knows it per flow.
	if out.Via != "wg1" || out.Up != 900 || out.Down != 12_000 {
		t.Errorf("the interface port crossed %q carrying %d/%d, want wg1 carrying 900/12000",
			out.Via, out.Up, out.Down)
	}

	in := rows["routed/tcp/443/100.64.0.7"]
	if in.Detail != "routed" || in.Via != config.PrimaryTunnelID {
		t.Errorf("the routed port drew as %q via %q, want routed via the tailnet", in.Detail, in.Via)
	}
	// A device the peer list does not name is still drawn: leaving it out would lose bytes
	// the router really carried.
	if in.Peer != "" || in.Up != 30 || in.Down != 70 {
		t.Errorf("the routed port named device %q carrying %d/%d, want no device and 30/70",
			in.Peer, in.Up, in.Down)
	}
}

// The subnet router knows a device only as the address it came from, which names nothing on
// a chart. The peer list the sample already read is what turns it into a device, and the
// device id is what the ports chart filters by.
func TestARoutedPortCarriesTheDeviceThatReachedIt(t *testing.T) {
	rows := map[string]traffic.Row{}
	addRoutedPorts(rows, []bytecount.Row{
		{Key: "tcp/445/100.64.0.7", Meta: bytecount.Meta{Label: "445", Detail: "tcp", Peer: "100.64.0.7"}},
	}, peersByAddr([]tunnelReading{{
		peers: []tsnode.Peer{{ID: "n1", HostName: "laptop", IPs: []string{"100.64.0.7"}}},
	}}))

	row := rows["routed/tcp/445/100.64.0.7"]
	if row.Peer != "n1" {
		t.Errorf("the routed port belongs to device %q, want n1 -- the filter matches on the id", row.Peer)
	}
	// The address is replaced by the name, because "100.64.0.7" beside a port tells a reader
	// nothing they could act on.
	if row.Detail != "laptop" {
		t.Errorf("the routed port reads as %q, want the device's name", row.Detail)
	}
}

func TestTheDeviceBehindARoutedPortIsNamedFromThePeerList(t *testing.T) {
	byAddr := peersByAddr([]tunnelReading{{
		id: config.PrimaryTunnelID,
		peers: []tsnode.Peer{
			{ID: "n1", HostName: "laptop", IPs: []string{"100.64.0.7", "fd7a::7"}},
			{ID: "n2", HostName: "phone", IPs: []string{"100.64.0.8"}},
		},
	}})

	peer, ok := byAddr["100.64.0.7"]
	if !ok || peer.ID != "n1" {
		t.Fatalf("100.64.0.7 resolved to %+v, want the laptop", peer)
	}
	// Every address a device answers to, not only the first: a device reached over IPv6 is
	// the same device and must not draw as an unnamed row beside itself.
	if peer, ok := byAddr["fd7a::7"]; !ok || peer.ID != "n1" {
		t.Errorf("fd7a::7 resolved to %+v, want the same laptop", peer)
	}
	if _, ok := byAddr["100.64.0.9"]; ok {
		t.Error("an address no device holds resolved to a device")
	}
}

// TUN mode is the one mode where app-tail never sees a flow: the operating system carries
// the packets. An empty ports chart there reads as a quiet network, so the lane has to say
// in words why it is empty.
func TestThePortsLaneSaysWhyItIsEmptyInTunMode(t *testing.T) {
	node := newFakeNode()
	node.status.Network = config.NetworkTUN
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return node })
	agent.node = node

	out, err := trafficAPI{a: agent}.Breakdown(context.Background(), string(traffic.LanePorts))
	if err != nil {
		t.Fatalf("breakdown: %v", err)
	}
	if out.Unmeasured == "" {
		t.Error("the ports lane drew an empty chart in TUN mode without saying why")
	}

	// Only ports, and only in this mode: a caveat on a lane that is measured in full would
	// teach a reader to ignore the one that matters.
	devices, err := trafficAPI{a: agent}.Breakdown(context.Background(), string(traffic.LaneDevices))
	if err != nil {
		t.Fatalf("breakdown: %v", err)
	}
	if devices.Unmeasured != "" {
		t.Errorf("the devices lane said %q, want nothing -- it is measured in full", devices.Unmeasured)
	}

	node.status.Network = config.NetworkUserspace
	measured, err := trafficAPI{a: agent}.Breakdown(context.Background(), string(traffic.LanePorts))
	if err != nil {
		t.Fatalf("breakdown: %v", err)
	}
	if measured.Unmeasured != "" {
		t.Errorf("the ports lane said %q in userspace mode, where it sees every flow", measured.Unmeasured)
	}
}

// A quiet network is the ordinary state, and the dashboard declares the field a list. A nil
// slice marshals to null, which is not a list: the chart reaches for it and the card dies.
func TestALaneNamingNothingIsAnEmptyListRatherThanNull(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })

	for _, lane := range traffic.Lanes {
		out, err := trafficAPI{a: agent}.Breakdown(context.Background(), string(lane))
		if err != nil {
			t.Fatalf("breakdown %q: %v", lane, err)
		}
		if out.Series == nil {
			t.Errorf("the %q lane named no keys and reported a nil series", lane)
			continue
		}
		body, err := json.Marshal(out)
		if err != nil {
			t.Fatalf("marshal %q: %v", lane, err)
		}
		if !bytes.Contains(body, []byte(`"series":[]`)) {
			t.Errorf("the %q lane went on the wire as %s, want an empty list", lane, body)
		}
	}
}

func TestBreakdownRefusesALaneItDoesNotKnow(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })

	_, err := trafficAPI{a: agent}.Breakdown(context.Background(), "sockets")

	// Not an empty breakdown: a mistyped route drawing a blank chart reads as a quiet
	// network, and nobody would go looking for the typo.
	if !errors.Is(err, config.ErrNotFound) {
		t.Errorf("an unknown lane reported %v, want a not-found error", err)
	}
}

// Eight lines is what the chart can be told apart at, and the ninth key onwards still
// carried bytes. Dropping them would make the breakdown disagree with the machine-wide
// lane above it, with nothing on screen explaining the difference.
func TestBreakdownFoldsEverythingPastTheEighthKeyIntoOneLine(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.sampler = traffic.NewSampler(nil, trafficInterval, trafficWindow)

	// Ten keys, each moving a hundred bytes a second more than the last, so the busiest eight
	// are named and the two quietest are the ones folded away. The ticks are spaced from one
	// instant rather than from the clock, or the interval the rates divide by would carry
	// however long the loop itself took.
	at := time.Now()
	for tick := range 2 {
		rows := map[string]traffic.Row{}
		for key := range 10 {
			rows[fmt.Sprintf("d%d", key)] = traffic.Row{
				Label: fmt.Sprintf("device %d", key),
				Pair:  traffic.Pair{Up: int64(tick * (key + 1) * 100)},
			}
		}
		agent.sampler.Record(traffic.Sample{
			At:    at.Add(time.Duration(tick) * trafficInterval),
			Keyed: map[traffic.Lane]map[string]traffic.Row{traffic.LaneDevices: rows},
		})
	}

	out, err := trafficAPI{a: agent}.Breakdown(context.Background(), string(traffic.LaneDevices))
	if err != nil {
		t.Fatalf("breakdown: %v", err)
	}

	if len(out.Series) != maxSeries+1 {
		t.Fatalf("the breakdown drew %d lines, want %d named plus the folded one",
			len(out.Series), maxSeries)
	}
	folded := out.Series[len(out.Series)-1]
	if folded.Key != otherKey {
		t.Fatalf("the last line was %q, want the folded one", folded.Key)
	}
	if out.Folded != 2 {
		t.Errorf("the breakdown said %d keys were folded, want 2 -- a list cut short has to say so",
			out.Folded)
	}
	// d0 and d1 moved 100 and 200 bytes in the second between the two ticks.
	if len(folded.Up) != 1 || folded.Up[0] == nil || *folded.Up[0] != 300 {
		t.Errorf("the folded line carried %v, want the 300 B/s its two keys moved", pointsOf(folded.Up))
	}
	// The busiest first, or the eight named lines would be an arbitrary eight.
	if out.Series[0].Key != "d9" {
		t.Errorf("the first line was %q, want the busiest key", out.Series[0].Key)
	}
}

// An interval a key was not measured across is a null rather than a zero: a device that went
// offline carried an unknown amount, and drawing that as a floor invents a quiet stretch.
func TestBreakdownDrawsAnUnmeasuredIntervalAsAGap(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.sampler = traffic.NewSampler(nil, trafficInterval, trafficWindow)

	at := time.Now()
	rows := map[string]traffic.Row{"d1": {Label: "nas", Pair: traffic.Pair{Up: 100}}}
	agent.sampler.Record(traffic.Sample{At: at, Keyed: map[traffic.Lane]map[string]traffic.Row{
		traffic.LaneDevices: rows,
	}})
	// The device is gone for this tick, then back with a higher counter.
	agent.sampler.Record(traffic.Sample{At: at.Add(trafficInterval)})
	agent.sampler.Record(traffic.Sample{
		At: at.Add(2 * trafficInterval),
		Keyed: map[traffic.Lane]map[string]traffic.Row{
			traffic.LaneDevices: {"d1": {Label: "nas", Pair: traffic.Pair{Up: 900}}},
		},
	})

	out, err := trafficAPI{a: agent}.Breakdown(context.Background(), string(traffic.LaneDevices))
	if err != nil {
		t.Fatalf("breakdown: %v", err)
	}

	if len(out.Series) != 1 {
		t.Fatalf("the breakdown drew %d lines, want the one device", len(out.Series))
	}
	up := out.Series[0].Up
	if len(up) != 2 {
		t.Fatalf("the line held %d intervals, want the two between three ticks", len(up))
	}
	if up[0] != nil || up[1] != nil {
		t.Errorf("the line carried %v, want both intervals null -- each touches the tick the "+
			"device was absent for", pointsOf(up))
	}
}

// addStoredTunnel writes one connection into the agent's document, which is where the
// connection lane reads its names from.
func addStoredTunnel(t *testing.T, a *Agent, id, name string, kind config.TunnelType) {
	t.Helper()
	if _, err := a.store.Update(func(c *config.Config) error {
		c.Tunnels = append(c.Tunnels, config.NewTunnel(id, name, name, kind))
		return nil
	}); err != nil {
		t.Fatalf("store a %s connection: %v", kind, err)
	}
}

func keysOfRows(rows map[string]traffic.Row) []string {
	out := make([]string, 0, len(rows))
	for key := range rows {
		out = append(out, key)
	}
	return out
}

// pointsOf renders a line for a failure message, since a slice of pointers prints as
// addresses and says nothing about where the gaps are.
func pointsOf(values []*float64) []string {
	out := make([]string, len(values))
	for i, v := range values {
		if v == nil {
			out[i] = "gap"
			continue
		}
		out[i] = fmt.Sprintf("%g", *v)
	}
	return out
}

// latencyProbing is a quiet agent over one fake node, with the setting the probe reads in
// the test's hands.
func latencyProbing(t *testing.T, on bool, peers ...tsnode.Peer) (*Agent, *fakeNode) {
	t.Helper()
	node := newFakeNode()
	node.setPeers(peers...)
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return node })
	agent.node = node
	agent.runtime.Settings.TrafficLatency = on
	return agent, node
}

// Switching the probing off clears what the last round measured, on the next round, and
// sends nothing. A figure left standing would be read as live on the page for as long as
// the setting stayed off, which is a number nobody measured.
func TestSwitchingLatencyProbingOffClearsTheLastRoundAndSendsNothing(t *testing.T) {
	agent, node := latencyProbing(t, true, exitNodePeer("n1", "nas", "100.64.0.1"))
	node.setLatency(map[string]time.Duration{"100.64.0.1": 12 * time.Millisecond})
	agent.probePeerLatency(context.Background())
	if got := agent.peerLatency(); got["n1"] != 12*time.Millisecond {
		t.Fatalf("measured %v after a round with the setting on, want n1 at 12ms", got)
	}
	sent := node.pingCalls()

	agent.runtime.Settings.TrafficLatency = false
	agent.probePeerLatency(context.Background())

	if got := agent.peerLatency(); got != nil {
		t.Errorf("the last round is still published as %v with the setting off", got)
	}
	if node.pingCalls() != sent {
		t.Error("a round was sent with the setting off")
	}
	for _, p := range agent.trafficPeers(context.Background()) {
		if p.LatencyMs != 0 {
			t.Errorf("%s still shows %vms on the page with the setting off", p.ID, p.LatencyMs)
		}
	}
}

// A device that is away is skipped rather than measured: probing it costs the full timeout,
// and a round spent waiting on devices that are away delays the answer for every device
// that is not. A device with no address yet cannot be asked at all.
func TestARoundMeasuresOnlyTheDevicesThatAreThere(t *testing.T) {
	agent, node := latencyProbing(t, true,
		exitNodePeer("n1", "here", "100.64.0.1"),
		tsnode.Peer{ID: "n2", HostName: "away", IPs: []string{"100.64.0.2"}},
		tsnode.Peer{ID: "n3", HostName: "brand-new", Online: true},
	)
	node.setLatency(map[string]time.Duration{
		"100.64.0.1": 8 * time.Millisecond,
		"100.64.0.2": 9 * time.Millisecond,
	})

	agent.probePeerLatency(context.Background())

	got := agent.peerLatency()
	if got["n1"] != 8*time.Millisecond {
		t.Errorf("the device that is here measured %v, want 8ms", got["n1"])
	}
	if _, measured := got["n2"]; measured {
		t.Error("a device that is away was measured, which spent the timeout waiting on it")
	}
	if node.pingCalls() != 1 {
		t.Errorf("%d measurements were sent, want one for the one device that can be asked", node.pingCalls())
	}
}

// A round in which nothing can be asked publishes nothing rather than leaving the previous
// round's figures standing against devices that have since gone away.
func TestARoundWithNothingToAskClearsThePreviousOne(t *testing.T) {
	agent, node := latencyProbing(t, true, exitNodePeer("n1", "nas", "100.64.0.1"))
	node.setLatency(map[string]time.Duration{"100.64.0.1": 12 * time.Millisecond})
	agent.probePeerLatency(context.Background())
	if agent.peerLatency()["n1"] != 12*time.Millisecond {
		t.Fatal("the first round measured nothing, so this proves nothing about the second")
	}

	node.setPeers(tsnode.Peer{ID: "n1", HostName: "nas", IPs: []string{"100.64.0.1"}})
	agent.probePeerLatency(context.Background())

	if got := agent.peerLatency(); got != nil {
		t.Errorf("a device that went away is still measured at %v", got)
	}
}
