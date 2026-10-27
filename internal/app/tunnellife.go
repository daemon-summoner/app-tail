// SPDX-License-Identifier: MIT

package app

// Starting and stopping the connections beside the primary one.
//
// The primary connection is the tailnet this app was built around: it is started by
// start(), rebuilt by restartNode() and torn down by shutdown, because the forward
// manager, the subnet router and the proxy are all built on it. Every other connection is
// only itself, so it is reconciled here from the stored document like any other module --
// started when it is meant to be up, stopped when it is not, and rebuilt in place when the
// identity it enrolls with changes, with no process or node restart involved.

import (
	"context"
	"fmt"
	"slices"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsfwd"
	"github.com/sellitus/app-tail/internal/spread"
	"github.com/sellitus/app-tail/internal/telemetry"
	"github.com/sellitus/app-tail/internal/tsnode"
	"github.com/sellitus/app-tail/internal/tunnel"
	"github.com/sellitus/app-tail/internal/tunnel/ovpntunnel"
	"github.com/sellitus/app-tail/internal/tunnel/tstunnel"
	"github.com/sellitus/app-tail/internal/tunnel/wgtunnel"
)

// startableTypes are the kinds of network this process can actually bring up, given
// whether its privileged side runs OpenVPN.
//
// It is the one table both the add path and the reconcile read, so a kind that cannot be
// started cannot be added either. The alternative -- accepting one and reporting it off
// forever -- would put a connection on screen that nothing can explain and nothing can
// fix, which is worse than saying so at the point somebody asks for it.
func startableTypes(openvpn bool) map[config.TunnelType]bool {
	return map[config.TunnelType]bool{
		config.TunnelTailscale: true,
		config.TunnelWireGuard: true,
		// Only where the privileged side can check who owns the program it would run as
		// root. Elsewhere the kind is not startable, which is what puts the refusal at the
		// point somebody adds one instead of leaving a connection on screen that never
		// comes up.
		config.TunnelOpenVPN: openvpn,
	}
}

// tunnelPlan is one connection rendered into what it would be built from, and the test for
// whether what is running was built from the same thing.
//
// It is an interface because the answer differs by kind and nothing outside this file needs
// to know how: a tailnet connection is the identity it enrolls with, a WireGuard connection
// is its keys, addresses and server. What both have in common is that a connection whose
// plan still matches is left alone and one whose plan changed is rebuilt.
type tunnelPlan interface {
	sameAs(other tunnelPlan) bool
}

// tailscalePlan is what one tailnet connection's node is built from.
type tailscalePlan struct{ params tsnode.ServerParams }

func (p tailscalePlan) sameAs(other tunnelPlan) bool {
	// A plan of another kind is never the same connection, so the kind change itself is a
	// rebuild -- which is what changing a connection's type is.
	o, ok := other.(tailscalePlan)
	return ok && p.params.SameAs(o.params)
}

// wireguardPlan is what one WireGuard connection's device is built from.
//
// The connection carrying this one's own packets is part of it. A chain is built into the
// device -- the way out of the machine and the packet size that leaves room for it are both
// settled when it starts -- so a connection that changed places in a chain, or left one, is a
// rebuild rather than something applied to what is running.
type wireguardPlan struct {
	held config.WireGuardTunnel
	// through is the id of the connection carrying this one, and "" for one whose packets
	// leave over this machine's own network.
	through string
}

func (p wireguardPlan) sameAs(other tunnelPlan) bool {
	o, ok := other.(wireguardPlan)
	return ok && p.through == o.through && p.held.SameAs(o.held)
}

// openvpnPlan is what one OpenVPN connection's program is started with.
//
// The egress choice is part of it, unlike the other two kinds, but only where it reaches the
// program. Taking this machine's own default route is a line in the configuration openvpn is
// started with, so moving to or from that arrangement is a rebuild. Carrying the traffic on a
// route belonging to this connection's own interface is not: the program is started with the
// same configuration either way, and what changes is a route this app installs beside it. That
// one is applied to the running connection instead, because restarting openvpn to install a
// route would drop a working connection and take this machine off the internet for as long as
// the handshake takes -- which is the switch itself failing.
type openvpnPlan struct {
	held  config.OpenVPNTunnel
	carry ovpntunnel.Carry
	// through is the connection this one's packets travel inside, empty for a connection
	// dialled over this machine's own network. It names the connection rather than holding it,
	// because the plan is compared against the stored settings and a running object is not
	// something the settings say.
	through string
}

func (p openvpnPlan) sameAs(other tunnelPlan) bool {
	o, ok := other.(openvpnPlan)
	return ok && p.startsTheSameProgramAs(o) && p.held.SameAs(o.held) && p.through == o.through
}

// startsTheSameProgramAs reports whether two plans render to the same openvpn configuration.
// Only one connection at a time owns this machine's default route, and that ownership is the
// one part of the egress choice openvpn itself is told about.
func (p openvpnPlan) startsTheSameProgramAs(o openvpnPlan) bool {
	return (p.carry == ovpntunnel.CarryDefault) == (o.carry == ovpntunnel.CarryDefault)
}

// runningTunnel is one connection this agent started beside the primary one.
type runningTunnel struct {
	// node is the tailnet node behind this connection, and nil for a connection of any
	// other kind. It is what the tailnet-only surfaces -- preferences, enrollment -- reach
	// through, and its absence is what tells them this connection has none.
	node NodeController
	// plan is what this connection was built from. A connection whose stored settings no
	// longer render to it is a different network, which is a rebuild rather than an edit.
	plan tunnelPlan
	// stopWatch ends the goroutine that turns this connection's own events into reconciles.
	stopWatch context.CancelFunc
	// close takes down what was built. It is only reached when the registry is not holding
	// this connection, which nothing is expected to produce.
	close func() error
	// limits are what this connection does not do, settled when it was built and true for as
	// long as it runs. They are not failures: a connection nothing could attach a link watcher
	// to still carries traffic, it just will not notice this machine moving networks, and that
	// belongs on the connection rather than in a log nobody reads.
	limits []string
}

// reconcileTunnels brings the connections beside the primary one into line with the stored
// document. It runs only from applyDesiredState, so it is the one place any of them is
// started or stopped.
func (a *Agent) reconcileTunnels(ctx context.Context) {
	app := a.settings()
	stateDir := a.stateDir()
	stored := a.runtimeTunnels()

	// Every stored connection is named, including the ones that are off. A name has to
	// keep naming its connection while that connection is down: the alternative is a name
	// that quietly resolves somewhere else, and the networks this convention exists for
	// are precisely the ones carrying each other's addresses.
	a.tunnels.SetNaming(namingOf(stored, app))

	// The per-destination exceptions, from the stored document for the same reason: a rule
	// naming a connection that is down stays the rule, and the registry refuses the
	// destination rather than quietly sending it out the way everything else goes.
	a.tunnels.SetRoutes(a.routes())

	// Set from the stored setting rather than from what is running, for the same reason:
	// a connection chosen to carry this machine's internet traffic keeps being the choice
	// while it is down. The registry answers "nothing is carrying it" either way, and the
	// difference between not chosen and chosen-but-down stays visible in the settings and
	// on the mode screen.
	switch members, spreadOn := app.EgressSpread(); {
	case spreadOn:
		// An empty list means every connection there is, resolved here rather than in the
		// registry so the registry never has to know what is configured -- only which
		// connections were chosen. The registry drops the ones that are not running.
		if len(members) == 0 {
			members = enabledTunnelIDs(stored)
		}
		a.tunnels.SetEgressMembers(members, spread.SeedFrom(app.MachineID))
	case app.EgressExit() != "":
		// A chain leaves through its last connection and only through that one: everything
		// before it is carrying the hop after it, not this machine's traffic. It is set as a
		// set of one rather than as the single choice, because the two differ in what happens
		// when it is down -- a chain holds the traffic here, and choosing one connection
		// leaves the machine on the network it was already on.
		a.tunnels.SetEgressMembers([]string{app.EgressExit()}, spread.SeedFrom(app.MachineID))
	case app.EgressHeld():
		// The kill switch, over one chosen connection: the same set of one, held for the same
		// reason. A connection that is down then refuses the destinations it was carrying rather
		// than handing them back to this machine's own network, which is the whole promise.
		var chosen []string
		if one := app.EgressTunnel(); one != "" {
			chosen = []string{one}
		}
		a.tunnels.SetEgressMembers(chosen, spread.SeedFrom(app.MachineID))
	default:
		a.tunnels.SetEgress(app.EgressTunnel())
	}

	// Declaration order, because a start writes to the log and the log should read in the
	// order the connections are listed rather than in map order.
	var wanted []config.Tunnel
	for _, held := range stored {
		if held.ID == config.PrimaryTunnelID || !held.Enabled {
			continue
		}
		// A kind this build cannot bring up is refused at the point it is added, so this is
		// reached only by a document that was hand-edited or written by a later version.
		// It is skipped rather than attempted, and the connections screen says why.
		if !a.startable[held.Type] {
			continue
		}
		wanted = append(wanted, held)
	}
	wanted = chainLast(wanted, app)

	desired := make(map[string]tunnelPlan, len(wanted))
	for _, held := range wanted {
		plan, err := tunnelPlanFor(held, app, stateDir)
		if err != nil {
			// The connection is configured in a way nothing can be built from -- an OAuth
			// secret file that cannot be read, an identity that renders to no hostname. It
			// is recorded against the connection, which is where the user is looking, and
			// anything running under it is stopped: a node still up on the previous
			// credentials would make a broken configuration look like a working one.
			a.recordTunnelProblem(held.ID, err.Error())
			continue
		}
		desired[held.ID] = plan
	}

	// Taken once for the whole pass: a connection asked to be tried again is rebuilt rather
	// than kept, whether or not anything about what it was built from changed.
	retrying := a.takeRetries()
	if len(retrying) > 0 {
		// Asking for a retry puts the automatic ladder back on its bottom rung: somebody who
		// pressed the button is watching, and the follow-up they get should come in seconds
		// rather than wherever the backoff had climbed to while they were not. If this pass
		// does not bring the connection up, settled() ends it by counting the failure again.
		a.supervise.failures = 0
	}

	for id, running := range a.runningTunnels() {
		want, keep := desired[id]
		if _, again := retrying[id]; keep && !again && want.sameAs(running.plan) && a.chainStillUp(ctx, want) {
			a.applyTunnelPlan(id, running, want)
			continue
		}
		a.stopTunnel(id)
	}

	for _, held := range wanted {
		plan, ok := desired[held.ID]
		if !ok {
			continue
		}
		if _, running := a.runningTunnel(held.ID); running {
			continue
		}
		a.startTunnel(ctx, held, plan)
	}
}

// carrier is a connection that can be moved between carrying this machine's internet traffic
// and not without being rebuilt.
//
// It is discovered by type assertion rather than asked for, which is the same way every other
// capability here is found: the kinds that reach the network through app-tail's own interface
// need nothing installed on this machine to carry the traffic, so for them there is nothing to
// move and the absence of this method is that answer.
type carrier interface {
	SetCarry(ovpntunnel.Carry)
}

// applyTunnelPlan settles the part of a plan a running connection can take without a rebuild.
//
// It runs for a connection the reconcile decided to keep, so what it applies is by definition
// something the plan comparison treats as the same connection. Today that is which connection
// carries this machine's internet traffic, on the kind where carrying it is a route beside the
// connection rather than a line in what started it.
func (a *Agent) applyTunnelPlan(id string, running *runningTunnel, want tunnelPlan) {
	plan, ok := want.(openvpnPlan)
	if !ok {
		return
	}
	held, was := running.plan.(openvpnPlan)
	if was && held.carry == plan.carry {
		return
	}
	// Kept so the next pass compares against what was applied rather than against what this
	// connection was started with, which is what stops this firing on every reconcile.
	running.plan = plan

	live, up := a.tunnels.Get(id)
	if !up {
		// The connection is in the running set and not in the registry, which the start path
		// does not produce: it registers first and publishes after. Said out loud rather than
		// passed over, because the setting the user changed has not been acted on.
		a.logger.Warn("a connection could not be told whether it carries this machine's internet "+
			"traffic, because nothing is registered under it", "connection", id)
		return
	}
	moved, ok := live.(carrier)
	if !ok {
		// Only reachable by an OpenVPN connection built as something that cannot be moved, which
		// is a mistake in this package rather than in anyone's configuration.
		a.logger.Warn("a connection could not be told whether it carries this machine's internet "+
			"traffic", "connection", id)
		return
	}
	moved.SetCarry(plan.carry)
}

// namingOf is the suffix each connection's own hosts answer under, keyed by connection id.
// It is derived from the stored document on every reconcile rather than kept beside it, so
// renaming a connection or changing the zone renames its names at the same moment.
func namingOf(held []config.Tunnel, app config.Settings) tunnel.Naming {
	suffixes := make(map[string]string, len(held))
	for _, t := range held {
		suffixes[t.ID] = t.DNSSuffix(&app)
	}
	return tunnel.NewNaming(suffixes)
}

// tunnelSuffixesOf is what the machine-wide resolver routes by: every stored connection's
// name suffix, with the connection named as the user named it so the refusal says whose
// name it was.
//
// It is built from the same two inputs as namingOf and by the same rule, because the two
// answers have to agree: a name the resolver claims for a connection is a name the route
// lookup then has to be able to act on.
func tunnelSuffixesOf(held []config.Tunnel, app config.Settings) []dnsfwd.TunnelSuffix {
	out := make([]dnsfwd.TunnelSuffix, 0, len(held))
	for _, t := range held {
		suffix := t.DNSSuffix(&app)
		if suffix == "" {
			continue
		}
		name := t.Name
		if name == "" {
			name = t.Handle()
		}
		out = append(out, dnsfwd.TunnelSuffix{Suffix: suffix, Name: name, ID: t.ID})
	}
	return out
}

// tunnelPlanFor renders one stored connection into what it would be built from.
func tunnelPlanFor(held config.Tunnel, app config.Settings, stateDir string) (tunnelPlan, error) {
	switch held.Type {
	case config.TunnelTailscale:
		params, err := secondaryParams(held, app, stateDir)
		if err != nil {
			return nil, err
		}
		return tailscalePlan{params: params}, nil
	case config.TunnelWireGuard:
		return wireguardPlan{held: held.WG(), through: app.EgressCarrierOf(held.ID)}, nil
	case config.TunnelOpenVPN:
		return openvpnPlan{
			held:    held.OVPN(),
			carry:   carryFor(held.ID, app),
			through: app.EgressCarrierOf(held.ID),
		}, nil
	default:
		// Only reachable by adding a kind to startableTypes without giving it a plan, which
		// is a mistake in this file rather than in anyone's configuration. It is reported
		// against the connection rather than skipped, because a connection listed as
		// startable and silently never started is the state nothing on screen can explain.
		return nil, fmt.Errorf("this build knows how to add a %s connection but not how to "+
			"bring one up", held.Type.Label())
	}
}

// enabledTunnelIDs is every connection meant to be up, in declaration order. It is what
// "every connection" resolves to when internet traffic is shared and no list was given: the
// ones that are off were not chosen, and the ones that are down are dropped by whoever holds
// what is actually running.
func enabledTunnelIDs(stored []config.Tunnel) []string {
	out := make([]string, 0, len(stored))
	for _, held := range stored {
		if held.Enabled {
			out = append(out, held.ID)
		}
	}
	return out
}

// chainHop is what a connection carrying another one has to offer: a way to reach the next
// connection's server, and the size of the packets it moves so the next one can be built to
// fit inside them.
type chainHop interface {
	wgtunnel.Carrier
	MTU() int
}

// chainCarrier is the running connection a chained one is built through, or the sentence
// saying what it is waiting for.
//
// Waiting is a state and not a failure. Hop two cannot be built until hop one has connected,
// so every start of a chain passes through this; the reconcile is poked by each connection's
// own events, so the wait ends when the connection before it comes up rather than on a timer.
func (a *Agent) chainCarrier(ctx context.Context, id string) (hop chainHop, ready bool, waiting string) {
	name := a.connectionName(id)
	live, running := a.tunnels.Get(id)
	if !running {
		return nil, false, fmt.Sprintf("This connection goes through %s, which is not running yet. "+
			"It starts as soon as that one is up.", name)
	}
	if !live.Status().State.Live() {
		return nil, false, fmt.Sprintf("This connection goes through %s, which is not connected "+
			"yet. It starts as soon as that one is carrying traffic.", name)
	}
	carrier, offers := live.(chainHop)
	if !offers {
		// Refused at the point the chain is written, so this is a kind that gained a place in
		// one without gaining a way to carry it. Reported against the connection rather than
		// passed over: nothing else would say why this connection never starts.
		return nil, false, fmt.Sprintf("%s cannot carry another connection's own packets, so "+
			"nothing can go through it.", name)
	}
	// The next hop's server is an address on the open internet, so a carrier that reaches only
	// its own network cannot get there. For a WireGuard hop the allowed addresses settle it
	// where the chain is written; a tailnet hop is settled by whether an exit node is chosen,
	// which is a running state and can only be asked here. Built through one that cannot, the
	// hop looks up and never completes a handshake -- silence that reads as a broken network.
	if carrying, why := canCarryExit(ctx, live); !carrying {
		return nil, false, fmt.Sprintf("This connection goes through %s, which cannot carry it "+
			"out to the internet: %s", name, why)
	}
	return carrier, true, ""
}

// chainStillUp reports whether what a running connection is carried by is still carrying it.
//
// A chained connection holds one conversation through the connection before it, opened when it
// was built. That conversation does not survive the connection before it going down, and
// nothing inside the device notices for as long as a session key stays valid -- three minutes
// of a connection that looks up and moves nothing. Taking it down here instead means it is
// rebuilt, through a new conversation, as soon as the one before it is back.
func (a *Agent) chainStillUp(ctx context.Context, plan tunnelPlan) bool {
	var through string
	switch held := plan.(type) {
	case wireguardPlan:
		through = held.through
	case openvpnPlan:
		through = held.through
	}
	if through == "" {
		return true
	}
	_, ready, _ := a.chainCarrier(ctx, through)
	return ready
}

// chainLast puts the connections of a chain at the end, in the chain's own order.
//
// A connection carried by another cannot be built before that one is up, so starting them in
// declaration order would mean a hop's first attempt failing whenever the list happens to name
// it before its carrier. The rest keep declaration order, which is what the log reads in.
//
// It is an ordering rather than a dependency graph because a chain is the only thing here that
// makes one connection wait for another, and it is already an order.
func chainLast(wanted []config.Tunnel, app config.Settings) []config.Tunnel {
	hops, chained := app.EgressChain()
	if !chained || len(hops) < 2 {
		return wanted
	}
	held := make(map[string]config.Tunnel, len(wanted))
	out := make([]config.Tunnel, 0, len(wanted))
	for _, t := range wanted {
		if slices.Contains(hops, t.ID) {
			held[t.ID] = t
			continue
		}
		out = append(out, t)
	}
	for _, id := range hops {
		if t, ok := held[id]; ok {
			out = append(out, t)
		}
	}
	return out
}

// carryFor reports whether an OpenVPN connection is to carry this machine's internet traffic,
// and which of the two ways it carries it.
//
// With nothing else carrying it, the connection takes this machine's own default route: in
// the kernel, at full speed, by the connection itself.
//
// The interface mode is the other case. It reaches every connection over one interface of its
// own and sends everything with no better route there, so the machine's default is already
// taken -- and a second claim on it would be settled by whichever connection asked first.
// Worse, an OpenVPN connection routes through the address its server handed out, and two
// connections to the same provider are handed the same one, so that default can end up
// resolving through the other connection's interface or through one that has just gone away.
// What this connection gets instead is a default route belonging to its own interface, which
// answers for the traffic app-tail dials into it and for nothing else on this machine.
//
// A connection sharing the traffic with others is always the scoped kind, whatever the
// interface mode is. There is one default route on this machine and several connections
// carrying the traffic, so a connection taking it would take the whole of it rather than the
// share it was given -- which is spreading nothing, decided by whichever connection started
// first. In a chain it is the same answer for a different reason: a connection there carries
// the hop after it, and one that took this machine's default route would carry everything
// else as well, out of the first hop instead of out of the last.
func carryFor(id string, app config.Settings) ovpntunnel.Carry {
	if members, shared := app.EgressShared(); shared {
		if len(members) > 0 && !slices.Contains(members, id) {
			return ovpntunnel.CarryNone
		}
		return ovpntunnel.CarryScoped
	}
	switch {
	case app.EgressTunnel() != id:
		return ovpntunnel.CarryNone
	case app.FabricSelected():
		return ovpntunnel.CarryScoped
	default:
		return ovpntunnel.CarryDefault
	}
}

// secondaryParams renders one connection's stored identity into the parameters its node is
// built from.
//
// The network mode is forced to userspace whatever the installation asked for. A machine
// has one network interface for this app and the primary connection is what owns it, so a
// second node built in interface mode would either fail to create one or take the
// interface the first is already carrying traffic on.
func secondaryParams(held config.Tunnel, app config.Settings, stateDir string) (tsnode.ServerParams, error) {
	ts := held.TS()
	secret, err := config.LoadOAuthSecret(ts)
	if err != nil {
		return tsnode.ServerParams{}, err
	}
	params, err := tsnode.BuildServerParams(ts, app, config.TunnelStateDir(stateDir, held.ID), secret)
	if err != nil {
		return tsnode.ServerParams{}, err
	}
	params.Network = config.NetworkUserspace
	params.InterfaceName = ""
	return params, nil
}

// startTunnel brings one connection up and registers it, so everything that reaches a
// network through the registry can reach this one.
func (a *Agent) startTunnel(ctx context.Context, held config.Tunnel, plan tunnelPlan) {
	switch plan := plan.(type) {
	case tailscalePlan:
		a.startTailscaleTunnel(ctx, held, plan.params)
	case wireguardPlan:
		a.startWireGuardTunnel(ctx, held, plan)
	case openvpnPlan:
		a.startOpenVPNTunnel(ctx, held, plan)
	default:
		// A plan with nothing to start it is a kind added above without a branch here. It is
		// recorded rather than dropped, for the same reason the missing plan is.
		a.recordTunnelProblem(held.ID, fmt.Sprintf("this build cannot bring up a %s connection",
			held.Type.Label()))
	}
}

// startWireGuardTunnel brings up one WireGuard connection.
//
// There is no node and no enrollment: the device is the connection, so it is built, started
// and registered in one step. What can go wrong is a configuration nothing could be built
// from -- a missing key, a server address that does not resolve -- and it is recorded against
// the connection the same way a tailnet node that will not enroll is.
func (a *Agent) startWireGuardTunnel(ctx context.Context, held config.Tunnel, plan wireguardPlan) {
	wg := plan.held

	// A carried connection cannot be built before the one carrying it is up: its way out of
	// this machine is a conversation through that connection. It is left for a later pass
	// rather than attempted and failed, and the connection says what it is waiting for --
	// every start of a chain passes through this state, so reporting it as a failure would
	// show a red card on every normal start.
	var through wgtunnel.Carrier
	var throughMTU int
	if plan.through != "" {
		carrier, ready, waiting := a.chainCarrier(ctx, plan.through)
		if !ready {
			a.recordTunnelProblem(held.ID, waiting)
			return
		}
		through, throughMTU = carrier, carrier.MTU()
	}

	// One context for everything that runs alongside this connection: the machine's link
	// watcher and the status watcher both end when the connection does.
	watchCtx, stopWatch := context.WithCancel(context.WithoutCancel(ctx))

	var limits []string
	links, err := a.watchLinks(watchCtx)
	if err != nil {
		// Carried on: without it the connection still works, it just will not notice this
		// machine changing networks -- a laptop that connects at the desk and is quiet at the
		// coffee shop until something restarts it. Stated on the connection because that is
		// where somebody wondering why it went quiet is looking.
		a.logger.Warn("this connection will not be told when the machine's networking changes",
			"connection", held.Handle(), "error", err)
		limits = append(limits, "This connection cannot be told when this machine changes "+
			"networks, so after moving to another network it stays down until it is switched "+
			"off and on again.")
	}

	live := a.newWireGuard(wgtunnel.Options{
		ID:          held.ID,
		Held:        wg,
		Logger:      a.logger,
		Verbose:     a.runtimeVerbose(),
		LinkChanges: links,
		Through:     through,
		ThroughMTU:  throughMTU,
	})
	if err := live.Start(ctx); err != nil {
		stopWatch()
		if closeErr := live.Close(); closeErr != nil {
			a.logger.Warn("closing a connection that could not start failed",
				"connection", held.Handle(), "error", closeErr)
		}
		a.logger.Warn("a connection could not start", "connection", held.Handle(), "error", err)
		a.recordTunnelProblem(held.ID, err.Error())
		return
	}

	if err := a.tunnels.Add(live); err != nil {
		// Unreachable: the reconcile only starts connections the registry does not hold. It
		// is handled rather than ignored because the device is up by now, and leaving it with
		// nothing holding a reference to it would be a socket this process can no longer close.
		stopWatch()
		if closeErr := live.Close(); closeErr != nil {
			a.logger.Warn("closing an unregisterable connection failed",
				"connection", held.Handle(), "error", closeErr)
		}
		a.recordTunnelProblem(held.ID, err.Error())
		return
	}

	go a.watchTunnel(watchCtx, live.Events())

	a.publishRunningTunnel(held.ID, &runningTunnel{
		plan:      plan,
		stopWatch: stopWatch,
		close:     live.Close,
		limits:    limits,
	})
	a.clearTunnelProblem(held.ID)

	a.logger.Info("connection started", "connection", held.Handle(), "server", wg.Peer.Endpoint)
	a.recordEvent(telemetry.CodeConnectionUp, "A connection was started.",
		map[string]string{"connection": held.ID, "type": string(held.Type)})
}

// startOpenVPNTunnel brings up one OpenVPN connection.
//
// It is the one kind that needs administrator rights to start, because the program carrying
// the traffic is a separate process on a real network interface. The claim on those rights is
// taken here, on the first connection that needs it, rather than held for the life of the
// process: a machine with no OpenVPN connection configured never asks for them at all.
func (a *Agent) startOpenVPNTunnel(ctx context.Context, held config.Tunnel, plan openvpnPlan) {
	// The same wait every carried connection passes through: openvpn is pointed at a listener
	// this app owns, and that listener has nothing to carry a stream through until the
	// connection before it is up.
	var through ovpntunnel.Carrier
	if plan.through != "" {
		carrier, ready, waiting := a.chainCarrier(ctx, plan.through)
		if !ready {
			a.recordTunnelProblem(held.ID, waiting)
			return
		}
		through = carrier
	}

	session, err := a.holdOpenVPN(ctx)
	if err != nil {
		a.logger.Warn("a connection could not start", "connection", held.Handle(), "error", err)
		a.recordTunnelProblem(held.ID, err.Error())
		return
	}

	// One context for everything that runs alongside this connection, the same as the other
	// kinds: the machine's link watcher and the status watcher both end when the connection does.
	watchCtx, stopWatch := context.WithCancel(context.WithoutCancel(ctx))

	var limits []string
	links, err := a.watchLinks(watchCtx)
	if err != nil {
		// Carried on: without it the connection still works, it just waits for openvpn's own
		// ping timeout after this machine changes networks instead of making the connection
		// again as soon as it happens. That wait is the server's to choose and is usually a
		// minute or more, so it is stated on the connection rather than left to a log.
		a.logger.Warn("this connection will not be told when the machine's networking changes",
			"connection", held.Handle(), "error", err)
		limits = append(limits, "This connection cannot be told when this machine changes "+
			"networks, so after moving to another network it waits for the server's own timeout "+
			"before connecting again.")
	}

	live := a.newOpenVPN(ovpntunnel.Options{
		ID:          held.ID,
		Held:        plan.held,
		Carry:       plan.carry,
		Logger:      a.logger,
		Runner:      session,
		Reached:     a.openvpnReached,
		LinkChanges: links,
		Through:     through,
	})
	if err := live.Start(ctx); err != nil {
		stopWatch()
		if closeErr := live.Close(); closeErr != nil {
			a.logger.Warn("closing a connection that could not start failed",
				"connection", held.Handle(), "error", closeErr)
		}
		a.releaseOpenVPNIfIdle()
		a.logger.Warn("a connection could not start", "connection", held.Handle(), "error", err)
		a.recordTunnelProblem(held.ID, err.Error())
		return
	}

	if err := a.tunnels.Add(live); err != nil {
		// Unreachable: the reconcile only starts connections the registry does not hold. It is
		// handled rather than ignored because a program holding administrator rights is
		// running by now, and leaving it with nothing holding a reference to it would be a
		// network interface this process can no longer take down.
		stopWatch()
		if closeErr := live.Close(); closeErr != nil {
			a.logger.Warn("closing an unregisterable connection failed",
				"connection", held.Handle(), "error", closeErr)
		}
		a.releaseOpenVPNIfIdle()
		a.recordTunnelProblem(held.ID, err.Error())
		return
	}

	go a.watchTunnel(watchCtx, live.Events())

	a.publishRunningTunnel(held.ID, &runningTunnel{
		plan:      plan,
		stopWatch: stopWatch,
		close:     live.Close,
		limits:    limits,
	})
	a.clearTunnelProblem(held.ID)

	a.logger.Info("connection started", "connection", held.Handle(), "server", plan.held.Remote)
	a.recordEvent(telemetry.CodeConnectionUp, "A connection was started.",
		map[string]string{"connection": held.ID, "type": string(held.Type)})
}

// holdOpenVPN returns the claim on the privileged side, taking it if this is the first
// connection that needs it.
func (a *Agent) holdOpenVPN(ctx context.Context) (ovpntunnel.Session, error) {
	a.tunnelMu.Lock()
	held := a.openvpn
	a.tunnelMu.Unlock()
	if held != nil {
		return held, nil
	}

	// Opened outside the lock: it talks to the helper, and on the path where this process
	// already holds the rights it starts a listener. Neither belongs under a mutex every
	// status read takes.
	session, err := a.openOpenVPN(ctx, func(format string, args ...any) {
		a.logger.Info("openvpn: " + fmt.Sprintf(format, args...))
	})
	if err != nil {
		return nil, err
	}

	a.tunnelMu.Lock()
	if a.openvpn != nil {
		// Another start won the race. Unreachable while the reconcile is the one goroutine
		// starting connections, and closed rather than kept because a second claim on the
		// helper is a second session that would have to be torn down by something.
		other := a.openvpn
		a.tunnelMu.Unlock()
		if closeErr := session.Close(); closeErr != nil {
			a.logger.Warn("closing a duplicate claim on OpenVPN failed", "error", closeErr)
		}
		return other, nil
	}
	a.openvpn = session
	a.tunnelMu.Unlock()
	return session, nil
}

// releaseOpenVPNIfIdle drops the claim once no OpenVPN connection is running.
//
// It has to be exactly that, because dropping the claim stops every connection started
// through it: released while one is still up, this would take that one down with it.
func (a *Agent) releaseOpenVPNIfIdle() {
	a.tunnelMu.Lock()
	if a.openvpn == nil {
		a.tunnelMu.Unlock()
		return
	}
	for _, running := range a.running {
		if _, ok := running.plan.(openvpnPlan); ok {
			a.tunnelMu.Unlock()
			return
		}
	}
	session := a.openvpn
	a.openvpn = nil
	a.tunnelMu.Unlock()

	if err := session.Close(); err != nil {
		a.logger.Warn("releasing this machine's OpenVPN rights failed", "error", err)
	}
}

// startTailscaleTunnel brings up one tailnet connection beside the primary one.
func (a *Agent) startTailscaleTunnel(ctx context.Context, held config.Tunnel, params tsnode.ServerParams) {
	node := a.newNode(tsnode.Options{
		Params:  params,
		Logger:  a.logger,
		Verbose: a.runtimeVerbose(),
		Grants:  a.pending,
	})
	if err := node.Start(ctx); err != nil {
		// Closed rather than kept: a node that failed to start still holds whatever it
		// opened before it failed, including files under its own state directory, and the
		// next pass builds a fresh one.
		if closeErr := node.Close(); closeErr != nil {
			a.logger.Warn("closing a connection that could not start failed",
				"connection", held.Handle(), "error", closeErr)
		}
		a.logger.Warn("a connection could not start", "connection", held.Handle(), "error", err)
		a.recordTunnelProblem(held.ID, err.Error())
		return
	}

	if err := a.tunnels.Add(tstunnel.New(held.ID, node)); err != nil {
		// The id is not registered -- the loop above only starts connections that are not
		// -- so this is unreachable. It is handled rather than ignored because the node is
		// running by now, and leaving it running with nothing holding a reference to it
		// would be a device on a tailnet this process can no longer stop.
		if closeErr := node.Close(); closeErr != nil {
			a.logger.Warn("closing an unregisterable connection failed",
				"connection", held.Handle(), "error", closeErr)
		}
		a.recordTunnelProblem(held.ID, err.Error())
		return
	}

	// Started after the tunnel is registered, so the first event it delivers describes a
	// connection the reconcile it wakes can already find.
	watchCtx, stopWatch := context.WithCancel(context.WithoutCancel(ctx))
	go a.watchTunnel(watchCtx, node.Events())

	a.publishRunningTunnel(held.ID, &runningTunnel{
		node:      node,
		plan:      tailscalePlan{params: params},
		stopWatch: stopWatch,
		close:     node.Close,
	})
	a.clearTunnelProblem(held.ID)

	a.logger.Info("connection started",
		"connection", held.Handle(), "hostname", params.Hostname, "authMode", params.Mode)
	a.recordEvent(telemetry.CodeConnectionUp, "A connection was started.",
		map[string]string{"connection": held.ID, "type": string(held.Type)})
}

// stopTunnel takes one connection out of the registry and closes it. It is a no-op for a
// connection that is not running, which is what lets a caller ask for a stop without first
// asking whether there is anything to stop.
func (a *Agent) stopTunnel(id string) {
	running, ok := a.takeRunningTunnel(id)
	if !ok {
		return
	}
	// Out of the registry before it is closed, so nothing dials through a connection that
	// is being torn down.
	held, registered := a.tunnels.Remove(id)
	running.stopWatch()

	var err error
	if registered {
		err = held.Close()
	} else {
		err = running.close()
	}
	if err != nil {
		a.logger.Warn("closing a connection failed", "connection", id, "error", err)
	}
	// After the connection is closed, so the claim is still held while the program it started
	// is being asked to stop.
	a.releaseOpenVPNIfIdle()
	// The problem a previous attempt recorded describes a connection that is no longer
	// there. Leaving it would report a stopped connection as a failed one.
	a.clearTunnelProblem(id)
	a.recordEvent(telemetry.CodeConnectionDown, "A connection was stopped.",
		map[string]string{"connection": id})
}

// stopAllTunnels closes every connection beside the primary one, which is the shutdown
// path: the registry's own Close would take the primary with them, and that one is torn
// down in its own order alongside the manager and the proxy built on it.
func (a *Agent) stopAllTunnels() {
	for id := range a.runningTunnels() {
		a.stopTunnel(id)
	}
}

// watchTunnel turns one connection's own events into reconciles, which is what keeps the
// connections screen current: the status a client reads comes from the tunnel, and without
// this nothing would notice it changed until something else asked for a pass.
func (a *Agent) watchTunnel(ctx context.Context, events <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-events:
			a.pokeReconcile()
		}
	}
}

// runningTunnels is a snapshot of what is up beside the primary connection. The map is
// copied because the caller iterates it while starting and stopping entries.
func (a *Agent) runningTunnels() map[string]*runningTunnel {
	a.tunnelMu.Lock()
	defer a.tunnelMu.Unlock()
	out := make(map[string]*runningTunnel, len(a.running))
	for id, held := range a.running {
		out[id] = held
	}
	return out
}

// nodeFor is the node one connection is running on, nil when that connection is not up.
//
// The primary connection is not in the running set: it is the node this process has always
// had, started and stopped by the reconcile itself. Every path that has a connection id and
// needs the node behind it comes through here rather than repeating that distinction.
func (a *Agent) nodeFor(id string) NodeController {
	if id == config.PrimaryTunnelID {
		return a.currentNode()
	}
	if held, up := a.runningTunnel(id); up {
		return held.node
	}
	return nil
}

// connectionProblem is why one connection's node is not running, empty when there is no
// stated reason.
func (a *Agent) connectionProblem(id string) string {
	if id == config.PrimaryTunnelID {
		return a.nodeProblem()
	}
	return a.tunnelProblem(id)
}

func (a *Agent) runningTunnel(id string) (*runningTunnel, bool) {
	a.tunnelMu.Lock()
	defer a.tunnelMu.Unlock()
	held, ok := a.running[id]
	return held, ok
}

func (a *Agent) publishRunningTunnel(id string, held *runningTunnel) {
	a.tunnelMu.Lock()
	defer a.tunnelMu.Unlock()
	if a.running == nil {
		a.running = make(map[string]*runningTunnel)
	}
	a.running[id] = held
}

// takeRunningTunnel removes a connection from the running set and hands it back, so a stop
// cannot be run twice against one node by two callers.
func (a *Agent) takeRunningTunnel(id string) (*runningTunnel, bool) {
	a.tunnelMu.Lock()
	defer a.tunnelMu.Unlock()
	held, ok := a.running[id]
	if ok {
		delete(a.running, id)
	}
	return held, ok
}

// tunnelProblem is why a connection that is meant to be up is not, empty when there is no
// such reason. It is what the connections screen reports for a connection with nothing
// registered under it, and it is the only thing distinguishing one that failed to start
// from one that is switched off.
func (a *Agent) tunnelProblem(id string) string {
	a.tunnelMu.Lock()
	defer a.tunnelMu.Unlock()
	return a.tunnelErrs[id]
}

func (a *Agent) recordTunnelProblem(id, problem string) {
	a.tunnelMu.Lock()
	changed := a.tunnelErrs[id] != problem
	if a.tunnelErrs == nil {
		a.tunnelErrs = make(map[string]string)
	}
	a.tunnelErrs[id] = problem
	a.tunnelMu.Unlock()

	// Only on a change: a connection that cannot start is retried on every pass, and one
	// entry per attempt would bury every other event under the same sentence.
	if changed {
		a.recordEvent(telemetry.CodeConnectionError, "A connection could not start.",
			map[string]string{"connection": id, "problem": problem})
	}
}

// askRetry records that somebody asked this connection to be tried again now.
//
// It is what makes a retry different from the pass that would have happened anyway: a
// connection that is up but not carrying anything -- a WireGuard peer that stopped answering,
// an OpenVPN program that is running and signed out -- is left alone by an ordinary reconcile,
// because nothing about what it was built from has changed. A retry says to build it again.
func (a *Agent) askRetry(id string) {
	a.tunnelMu.Lock()
	defer a.tunnelMu.Unlock()
	if a.tunnelRetry == nil {
		a.tunnelRetry = make(map[string]struct{})
	}
	a.tunnelRetry[id] = struct{}{}
}

// takeRetries is every connection asked to be tried again, and forgets them.
//
// Taken whole at the top of a pass rather than asked per connection, so a retry for one that
// is not running is consumed by the pass that starts it instead of waiting for a pass where
// that connection happens to be up.
func (a *Agent) takeRetries() map[string]struct{} {
	a.tunnelMu.Lock()
	defer a.tunnelMu.Unlock()
	asked := a.tunnelRetry
	a.tunnelRetry = nil
	return asked
}

func (a *Agent) clearTunnelProblem(id string) {
	a.tunnelMu.Lock()
	defer a.tunnelMu.Unlock()
	delete(a.tunnelErrs, id)
}
