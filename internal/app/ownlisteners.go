// SPDX-License-Identifier: MIT

package app

// A forward hands whatever it points at to everyone it serves. Pointed at one of app-tail's
// own loopback listeners -- the dashboard and its API, a proxy, the machine's resolver --
// it would publish that listener to every tailnet peer, or every machine on the network,
// none of whom it was ever meant for. This file is the list of those listeners and the
// rule that keeps a forward off them.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/forward"
	"github.com/sellitus/app-tail/internal/httpapi"
)

// targetLookupTimeout bounds the name lookup a forward's target gets when it is written.
// The write is waiting on it, and a name that does not answer in this long is not one a
// forward could use either.
const targetLookupTimeout = 2 * time.Second

// ownListener is one socket app-tail itself is listening on.
type ownListener struct {
	// what names it the way the refusal does: dashboard, proxy or resolver.
	what string
	addr netip.AddrPort
	tcp  bool
	udp  bool
}

// ownListeners gathers the addresses app-tail is listening on right now. They are read
// live rather than from the settings, because each of them can land somewhere other than
// where it was configured when that port is taken.
func (a *Agent) ownListeners() []ownListener {
	var out []ownListener
	if addr := a.UIAddr(); addr != nil {
		if at, err := netip.ParseAddrPort(addr.String()); err == nil {
			out = append(out, ownListener{what: "dashboard", addr: at, tcp: true})
		}
	}
	if set := a.currentProxies(); set != nil {
		for _, st := range set.Statuses() {
			if at, err := netip.ParseAddrPort(st.Listening); err == nil {
				out = append(out, ownListener{what: "proxy", addr: at, tcp: true})
			}
		}
	}
	if runner := a.currentSystemDNS(); runner != nil {
		runner.mu.Lock()
		sockets := []resolverSocket{runner.listen, runner.spare}
		runner.mu.Unlock()
		for _, s := range sockets {
			if s.open() {
				out = append(out, ownListener{what: "resolver", addr: s.addr, tcp: true, udp: true})
			}
		}
	}
	return out
}

// thisMachineAddrs is every address this machine answers on besides loopback: what its
// interfaces hold, and each connection's own address inside its network.
func (a *Agent) thisMachineAddrs() ([]netip.Addr, error) {
	addrs, err := a.hostAddrs()
	if err != nil {
		return nil, fmt.Errorf("read this machine's addresses: %w", err)
	}
	for _, t := range a.tunnels.All() {
		addrs = append(addrs, t.Addrs()...)
	}
	return addrs, nil
}

// interfaceAddrs reads the addresses this machine's interfaces hold. It is the production
// half of Options.HostAddrs.
func interfaceAddrs() ([]netip.Addr, error) {
	held, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(held))
	for _, a := range held {
		if ipnet, ok := a.(*net.IPNet); ok {
			if addr, ok := netip.AddrFromSlice(ipnet.IP); ok {
				out = append(out, addr.Unmap())
			}
		}
	}
	return out, nil
}

// lookupHost resolves a target's host name. It is the production half of the lookup
// selfTargetRefusal is handed.
func lookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, targetLookupTimeout)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// checkForwardTarget refuses a forward that would reach one of app-tail's own listeners.
// A target named by host name is looked up, since "localhost" is not the only name for
// this machine.
func (a *Agent) checkForwardTarget(ctx context.Context, f config.Forward) error {
	return selfTargetRefusal(f, a.ownListeners(), func(host string) ([]netip.Addr, error) {
		return lookupHost(ctx, host)
	}, a.thisMachineAddrs)
}

// admitForwards is the forward set as it may be started now: a forward that would reach
// one of app-tail's own listeners is handed on switched off, so the manager stops it
// rather than serving it.
//
// It is checked again here, on every pass, because the listeners move: a proxy that
// lost its port lands on another, and a forward that was harmless when it was written can
// point at it by the next pass. Only targets that need no lookup are judged here -- this
// runs on the goroutine that starts every forward, where a name lookup that hung would
// stop all of them. A named target is judged by ownListenerDial instead, on every
// connection, against the address its name resolves to then.
func (a *Agent) admitForwards(forwards []config.Forward) []config.Forward {
	listeners := a.ownListeners()
	out := make([]config.Forward, len(forwards))
	for i, f := range forwards {
		out[i] = f
		if !f.Enabled {
			continue
		}
		if err := selfTargetRefusal(f, listeners, nil, a.thisMachineAddrs); err != nil {
			a.logger.Warn("not starting a forward app-tail cannot serve safely",
				"id", f.ID, "name", f.Name, "reason", err.Error())
			out[i].Enabled = false
		}
	}
	return out
}

// ownListenerDial is the forward manager's dial guard: the address a connection is
// actually being made to, after its target's name was looked up, may not be one of
// app-tail's own listeners. The check when a forward is written cannot cover this alone,
// because a name can resolve somewhere else by the time a peer connects, and a lookup that
// failed then judged nothing.
func (a *Agent) ownListenerDial(network string, addr netip.AddrPort) error {
	tcp, udp := strings.HasPrefix(network, "tcp"), strings.HasPrefix(network, "udp")
	onPort := listenersOn(a.ownListeners(), int(addr.Port()), tcp, udp)
	if len(onPort) == 0 {
		return nil
	}
	hit, err := listenerReachedAt(addr.Addr(), onPort, a.thisMachineAddrs)
	if err != nil {
		return err
	}
	if hit != nil {
		return ownListenerRefusal(*hit)
	}
	return nil
}

// withSelfTargetRefusal marks a view whose forward is held off because it points at one
// of app-tail's own listeners, so the reason is on the forward rather than only in a log.
func (a *Agent) withSelfTargetRefusal(f config.Forward, view httpapi.ForwardView) httpapi.ForwardView {
	if !f.Enabled {
		return view
	}
	if err := selfTargetRefusal(f, a.ownListeners(), nil, a.thisMachineAddrs); err != nil {
		view.State = forward.StateError
		view.Error = err.Error()
		view.Listening = ""
	}
	return view
}

// selfTargetRefusal reports why f may not run while these listeners are open, or nil. A
// target it cannot read is refused too, since it cannot be shown to be harmless.
//
// Only listeners on the target's port, on a transport the forward carries, are in
// question. A loopback or unspecified target, or "localhost", is refused against any of
// them: the address itself is not compared, because 127.0.0.2 reaches a socket bound to
// 127.0.0.1 on some systems and every loopback address on others, and a forward to
// app-tail's own port on loopback has no legitimate use either way. Any other address
// machine reports as this machine's -- its LAN address, its tailnet address -- is refused
// against a listener bound to every address or to that one, which are the listeners
// reachable there. When lookup is given, a name is judged by each address it resolves to.
//
// A lookup that fails leaves a named target unjudged rather than refused: the name may
// simply not be up yet, and a forward to a name that does not resolve reaches nothing.
// What a name resolves to later is judged again on every connection, by ownListenerDial.
func selfTargetRefusal(f config.Forward, listeners []ownListener, lookup func(string) ([]netip.Addr, error), machine func() ([]netip.Addr, error)) error {
	host, portText, err := net.SplitHostPort(f.Target)
	if err != nil {
		return &config.ValidationError{Field: "target", Message: fmt.Sprintf("%q is not host:port: %v", f.Target, err)}
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return &config.ValidationError{Field: "target", Message: fmt.Sprintf("the port in %q is not a number", f.Target)}
	}
	onPort := listenersOn(listeners, port, f.Protocol.CarriesTCP(), f.Protocol.CarriesUDP())
	if len(onPort) == 0 {
		return nil
	}
	for _, addr := range hostAddrs(host, lookup) {
		hit, err := listenerReachedAt(addr, onPort, machine)
		if err != nil {
			return err
		}
		if hit != nil {
			return ownListenerRefusal(*hit)
		}
	}
	return nil
}

// ownListenerRefusal is the refusal for a forward that would reach l.
func ownListenerRefusal(l ownListener) error {
	return &config.ValidationError{
		Field: "target",
		Message: fmt.Sprintf("a forward cannot point at app-tail's own %s on %s; that would hand it to everyone the forward serves",
			l.what, l.addr),
	}
}

// listenersOn is the listeners on port that take one of the transports asked about.
func listenersOn(listeners []ownListener, port int, tcp, udp bool) []ownListener {
	var out []ownListener
	for _, l := range listeners {
		if int(l.addr.Port()) == port && ((l.tcp && tcp) || (l.udp && udp)) {
			out = append(out, l)
		}
	}
	return out
}

// hostAddrs is the addresses host stands for: the address itself when it is one, loopback
// for the names that always mean this machine, and otherwise what lookup answers. A name
// with no lookup, or one whose lookup failed, stands for nothing that can be judged here;
// the forward's dial guard judges the address it actually connects to.
func hostAddrs(host string, lookup func(string) ([]netip.Addr, error)) []netip.Addr {
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return []netip.Addr{netip.IPv6Loopback()}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}
	}
	if lookup == nil {
		return nil
	}
	addrs, err := lookup(host)
	if err != nil {
		return nil
	}
	return addrs
}

// listenerReachedAt is the listener among onPort that a connection to addr would reach,
// or nil. An IPv4 address written in its IPv6 form counts as itself: ::ffff:127.0.0.1
// reaches the same socket 127.0.0.1 does. machine is only read when addr is neither
// loopback nor unspecified, and a failure to read it is returned, since the target then
// cannot be shown to be somewhere else.
func listenerReachedAt(addr netip.Addr, onPort []ownListener, machine func() ([]netip.Addr, error)) (*ownListener, error) {
	addr = addr.Unmap().WithZone("")
	if len(onPort) == 0 {
		return nil, nil
	}
	if addr.IsLoopback() || addr.IsUnspecified() {
		return &onPort[0], nil
	}
	if machine == nil {
		return nil, nil
	}
	mine, err := machine()
	if err != nil {
		return nil, fmt.Errorf("cannot tell whether %s is this machine, so a forward to it is not started: %w", addr, err)
	}
	if !slices.ContainsFunc(mine, func(m netip.Addr) bool { return m.Unmap().WithZone("") == addr }) {
		return nil, nil
	}
	for i := range onPort {
		bound := onPort[i].addr.Addr().Unmap()
		if bound.IsUnspecified() || bound == addr {
			return &onPort[i], nil
		}
	}
	return nil, nil
}
