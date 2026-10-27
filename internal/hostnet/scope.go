// SPDX-License-Identifier: MIT

package hostnet

// A default route that belongs to one interface rather than to this machine.
//
// An OpenVPN connection runs on a real interface, and app-tail reaches it in one of two ways.
// With nothing else carrying this machine's traffic, openvpn takes the machine's own default
// route and every program here goes through it. With the one-interface mode on, app-tail owns
// that default and reaches each connection instead by dialling out of its interface -- and a
// socket bound to an interface holding no route for the destination fails outright rather
// than falling back, so an OpenVPN connection reached that way can carry nothing beyond its
// own network.
//
// This is what closes that gap: a default route scoped to the connection's own interface. It
// is consulted only for traffic already bound there, so it says where this connection's
// traffic goes without saying anything about where this machine's does.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// ErrScopedRoutesUnsupported is a platform with no way to give one interface a default route
// of its own. It is a sentence rather than a failure of the request: nothing is wrong with
// what was asked for, this machine just has no way to do it.
var ErrScopedRoutesUnsupported = errors.New("this platform cannot give one network interface a default route of its own")

// maxInterfaceName bounds an interface name. The kernel's own limit is 16 bytes including the
// terminator on both platforms this runs on; the name also becomes an argument to a program
// running as root, so its length is checked rather than assumed.
const maxInterfaceName = 15

// OpenVPNScope is the interface one connection's traffic leaves through.
//
// Both fields are required and both are checked again on the privileged side. The connection
// id is the part that keeps this narrow: the helper installs the route only for an interface
// named against a connection it started itself and is still running, so this is not "put a
// route on any interface" -- it is "the connection you already agreed to run reaches the
// network through its own interface".
type OpenVPNScope struct {
	// ID is the connection this interface belongs to.
	ID string `json:"id"`
	// Interface is the interface openvpn opened for it. The kernel chooses the name, so it is
	// discovered from what openvpn reported rather than decided in advance.
	Interface string `json:"interface"`
}

// Validate refuses a request this side will not act on.
//
// It runs on the privileged side. The caller checks too, for the reason every check on this
// boundary is doubled: a check that only runs before the message is sent is a check on the
// well-behaved.
func (s OpenVPNScope) Validate() error {
	if !validConnectionID(s.ID) {
		return fmt.Errorf("%q is not a connection identifier", s.ID)
	}
	return validInterfaceName(s.Interface)
}

// validInterfaceName refuses a name that is not one an interface can have.
//
// The name reaches a program run as root as an argument, so what it is made of is checked
// rather than escaped: letters, digits and the two separators a kernel allows, and nothing
// that could begin a second argument or a second line.
func validInterfaceName(name string) error {
	if name == "" {
		return errors.New("no network interface was given")
	}
	if len(name) > maxInterfaceName {
		return fmt.Errorf("%q is %d characters, over the %d-character limit an interface name has",
			name, len(name), maxInterfaceName)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
		default:
			return fmt.Errorf("%q is not a network interface name", name)
		}
	}
	return nil
}

// scopableInterface refuses an interface a connection's default route may not be put on.
//
// The caller names the interface because the kernel, not this side, chose it: openvpn is
// started with the family name and told what it got afterwards. So the name cannot be
// compared against one this side recorded, and the shape has to carry the guarantee instead
// -- a tunnel device of the kind openvpn opens, which is the set the caller could have been
// given honestly, and never a physical interface. Without this a caller holding one running
// connection could put a root default route on the interface the whole machine reaches the
// network through.
//
// app-tail's own interface is refused for the reason wantedHostDefaults refuses it: a default
// route pointing an interface at itself is a loop rather than a way out.
func scopableInterface(name, driving string) error {
	if driving != "" && name == driving {
		return fmt.Errorf("%s is the interface app-tail opened, which is not one a connection routes through", name)
	}
	prefix := openvpnDevice()
	digits, ok := strings.CutPrefix(name, prefix)
	if !ok || digits == "" {
		return fmt.Errorf("%q is not a tunnel interface openvpn opens, so no connection reaches the network through it", name)
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return fmt.Errorf("%q is not a tunnel interface openvpn opens, so no connection reaches the network through it", name)
		}
	}
	return nil
}

// ScopeOpenVPN gives one connection's interface a default route of its own.
//
// The connection has to be one this session started and is still running, and the interface
// has to be one openvpn could have opened for it -- scopableInterface. Together those are what
// make this acceptable for an unprivileged caller to ask for: the route lands on a tunnel
// belonging to a program this side chose to run rather than on whichever interface the caller
// named.
//
// A connection that reconnects opens its interface again, and an interface that went away
// took its routes with it -- so this is asked for again every time the connection comes back
// up, and installing the route is a replacement rather than a first attempt. The route this
// side last installed under a different name is removed before the new one goes in. Removing
// it when the connection stops is the teardown's, not the caller's: the caller may be the
// thing that has gone away.
func (l *Local) ScopeOpenVPN(ctx context.Context, scope OpenVPNScope) error {
	if !OpenVPNSupported() {
		return ErrOpenVPNUnsupported
	}
	if err := scope.Validate(); err != nil {
		return err
	}

	l.mu.Lock()
	proc, driving := l.openvpn[scope.ID], l.tunName
	l.mu.Unlock()
	if proc == nil {
		return fmt.Errorf("connection %s is not running here, so this side has no interface of its own to route", scope.ID)
	}
	if err := scopableInterface(scope.Interface, driving); err != nil {
		return err
	}

	v6, err := l.carriesV6(scope.Interface)
	if err != nil {
		return err
	}

	state := l.machineState()

	// The previous one first: an interface that has gone away takes its routes with it, but one
	// this side is about to stop using has not. The record still names it while it is being
	// removed, so a run that ends in the middle leaves the next one the interface to finish on.
	if previous := proc.scopedInterface(); previous != "" && previous != scope.Interface {
		if err := unscopeBoth(ctx, l.unscopeRoute, previous); err != nil {
			return err
		}
		proc.setScopedInterface("")
		if err := state.setScope(scope.ID, ""); err != nil {
			return err
		}
	}

	// Written down before the route is installed, for the reason sysdns writes before it
	// changes anything: a crash between the two would otherwise leave a root route on this
	// machine with nothing remembering to take it back. A record naming a route that was never
	// installed costs the next start one removal that finds nothing.
	if err := state.setScope(scope.ID, scope.Interface); err != nil {
		return err
	}
	if err := l.scopeRoute(ctx, scope.Interface, "", false); err != nil {
		return err
	}
	if v6 {
		if err := l.scopeRoute(ctx, scope.Interface, "", true); err != nil {
			return errors.Join(err, l.unscopeRoute(ctx, scope.Interface, "", false))
		}
	}
	proc.setScopedInterface(scope.Interface)
	return nil
}

// UnscopeOpenVPN takes back the route one connection's interface was given, while that
// connection goes on running.
//
// It is the other half of choosing which connection carries this machine's internet traffic:
// the one that stops carrying it keeps running, and a default route left on its interface
// would go on saying that traffic bound there reaches the whole internet.
//
// A connection with no such route is not a failure. The caller asks for the route to be gone,
// and it being gone already is that.
func (l *Local) UnscopeOpenVPN(ctx context.Context, id string) error {
	if !OpenVPNSupported() {
		return ErrOpenVPNUnsupported
	}
	if !validConnectionID(id) {
		return fmt.Errorf("%q is not a connection identifier", id)
	}

	l.mu.Lock()
	proc := l.openvpn[id]
	l.mu.Unlock()
	if proc == nil {
		return fmt.Errorf("connection %s is not running here, so this side holds no route of its own for it", id)
	}

	iface := proc.scopedInterface()
	if iface == "" {
		return nil
	}
	if err := unscopeBoth(ctx, l.unscopeRoute, iface); err != nil {
		return err
	}
	proc.setScopedInterface("")
	return l.machineState().setScope(id, "")
}

// scopedRouteTimeout bounds one route change on the path that ends a connection. The work is
// a program run once per address family; it is bounded at all because the goroutine reaping a
// connection is what closes that connection's done channel, and everything waiting on a stop
// is waiting on this.
const scopedRouteTimeout = 10 * time.Second

// unscopeOpenVPN takes back the route one connection's interface was given, on the path where
// that connection has ended.
//
// It reports rather than returns: the connection is already gone, there is nobody left to
// hand a failure to, and this side's log is where a route left behind on this machine has to
// be visible. The state is kept as it is on failure, so the teardown that ends the session
// tries again.
func (l *Local) unscopeOpenVPN(id string, proc *openvpnProcess) {
	iface := proc.scopedInterface()
	if iface == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), scopedRouteTimeout)
	defer cancel()
	if err := unscopeBoth(ctx, l.unscopeRoute, iface); err != nil {
		l.logf("openvpn %s: could not take back the default route on %s: %v", id, iface, err)
		return
	}
	proc.setScopedInterface("")
	if err := l.machineState().setScope(id, ""); err != nil {
		l.logf("openvpn %s: could not forget the default route on %s in the record of what app-tail installed: %v",
			id, iface, err)
	}
}

// routeChanger installs or takes back one scoped default route. Every caller of a route
// change here holds one of these rather than calling the platform function directly, so a
// test can stand in for the one thing in this package that needs root to run at all.
type routeChanger func(ctx context.Context, iface, gateway string, v6 bool) error

// unscopeBoth takes back both families' routes for one interface, through the given remover.
func unscopeBoth(ctx context.Context, remove routeChanger, iface string) error {
	return errors.Join(
		remove(ctx, iface, "", false),
		remove(ctx, iface, "", true),
	)
}

// interfaceCarriesV6 reports whether an interface holds an IPv6 address it could send from.
//
// A default route for a family the interface has no address in is a route nothing can use,
// and installing one fails on both platforms -- so this is what decides whether the second
// route is asked for at all. Reading which interfaces exist needs no privileges.
func interfaceCarriesV6(name string) (bool, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false, fmt.Errorf("read the network interface %s: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false, fmt.Errorf("read the addresses on %s: %w", name, err)
	}
	for _, addr := range addrs {
		prefix, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ip := prefix.IP; ip.To4() == nil && ip.IsGlobalUnicast() {
			return true, nil
		}
	}
	return false, nil
}
