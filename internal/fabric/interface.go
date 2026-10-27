// SPDX-License-Identifier: MIT

package fabric

// The one privileged step this mode needs, and the boundary it goes through.
//
// Everything else here is ordinary unprivileged work: a network stack in this process, a
// table, a dial. Creating an interface on the machine and pointing its routing table at that
// interface are not, and they are the only two things that are -- so they are the whole of
// what this file does, and it is the only file in the package that knows the privileged side
// exists.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/tailscale/wireguard-go/tun"

	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/hostnet"
)

// privileged is the part of the machine's privileged side this mode uses.
//
// It is named here rather than taken whole because the rest of hostnet.Host is the tailnet
// engine's own interfaces, expressed in the engine's own types -- which this package neither
// calls nor is allowed to name. Stating only what is used also leaves the machine's side
// substitutable, so the order these steps run in and what each of them undoes on the way out
// are decided by tests rather than only by a machine that already holds the rights.
type privileged interface {
	Capabilities(ctx context.Context) (hostnet.Capabilities, error)
	OpenTUN(ctx context.Context, name string) (tun.Device, string, error)
	RouterUp(ctx context.Context) error
	SetHostRoutes(ctx context.Context, r hostnet.Routes) error
	ScopeHostDefault(ctx context.Context) error
	UnscopeHostDefault(ctx context.Context) error
	Close() error
}

// Interface is the interface on this machine, and the privileged side that made it.
type Interface struct {
	host privileged
	dev  tun.Device
	name string
	// addrs are the addresses the interface itself holds, which every routing change has
	// to carry: the privileged side installs a whole configuration rather than a delta, so
	// leaving them out of one call takes them off the interface.
	addrs []netip.Prefix
	logf  func(format string, args ...any)
	// scopeReported keeps a platform that cannot keep this machine's own way out reachable to
	// one line. Carrying is asked for again on every change to what is carried, so the same
	// sentence would otherwise be written every time anything about the tailnet moved.
	scopeReported bool
}

// InterfaceAddrs are the addresses the interface itself holds.
//
// An interface with no address of its own is refused by macOS and unusable on Windows, so
// there has to be one, and it has to be somewhere no connected network will be presented
// from -- otherwise the machine would answer for one address inside a network it is
// supposed to be reaching. The first address of the pool is taken for it, and the caller
// passes the same range back to Allocate as one of this machine's own so nothing is ever
// presented there.
func InterfaceAddrs(pool []netip.Prefix) []netip.Prefix {
	if len(pool) == 0 {
		pool = DefaultPool
	}
	var out []netip.Prefix
	var haveV4, haveV6 bool
	for _, prefix := range pool {
		if !prefix.IsValid() {
			continue
		}
		addr := prefix.Masked().Addr()
		if addr.Is4() && !haveV4 {
			out, haveV4 = append(out, netip.PrefixFrom(addr, 32)), true
		}
		if !addr.Is4() && !haveV6 {
			out, haveV6 = append(out, netip.PrefixFrom(addr, 128)), true
		}
	}
	return out
}

// InterfaceOptions are what creating the interface needs.
//
// The privileged side's own options are deliberately not among them: this package is one of
// the two allowed to reach it, and passing its option type through would make every caller of
// this one a third. What crosses is a name, the addresses, and somewhere to put the
// privileged side's log lines.
type InterfaceOptions struct {
	// Name is what to call the interface, empty for the platform's default.
	Name string
	// Addrs are the addresses the interface itself holds. See InterfaceAddrs.
	Addrs []netip.Prefix
	// Logf is where the privileged side's own logging goes.
	Logf func(format string, args ...any)
	// Grants hears whether each routing change was refused for a missing approval.
	Grants grants.Observer

	// open is the privileged side, this machine's own when it is nil. It is unexported
	// because nothing outside this package has another one to supply.
	open func(ctx context.Context, opts hostnet.Options) (privileged, error)
}

// openHost is this machine's own privileged side, narrowed to what this package uses.
func openHost(ctx context.Context, opts hostnet.Options) (privileged, error) {
	return hostnet.Open(ctx, opts)
}

// OpenInterface creates the interface this mode runs on.
//
// The privileged side refuses a second interface, which is what makes this mode and the
// tailnet's own interface mode mutually exclusive without either of them having to know the
// other exists. That refusal is load-bearing: two processes driving one machine's routing
// table would each be removing the other's routes.
func OpenInterface(ctx context.Context, opts InterfaceOptions) (*Interface, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	open := opts.open
	if open == nil {
		open = openHost
	}
	host, err := open(ctx, hostnet.Options{Logf: logf, Grants: opts.Grants})
	if err != nil {
		return nil, err
	}
	caps, err := host.Capabilities(ctx)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("ask what this machine can do: %w", err), host.Close())
	}
	if usable, why := caps.Usable(); !usable {
		return nil, errors.Join(errors.New(why), host.Close())
	}

	dev, realName, err := host.OpenTUN(ctx, opts.Name)
	if err != nil {
		return nil, errors.Join(err, host.Close())
	}
	i := &Interface{host: host, dev: dev, name: realName, addrs: slices.Clone(opts.Addrs), logf: logf}
	if err := host.RouterUp(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("bring %s up: %w", realName, err), i.Close())
	}
	return i, nil
}

// Device is the interface itself, which the fabric drives and closes.
func (i *Interface) Device() tun.Device { return i.dev }

// Name is what the operating system called it.
func (i *Interface) Name() string { return i.name }

// Carry points this machine's routing table at the interface.
//
// exclude are the ranges that must keep leaving through the machine's own network. Every
// connection's own server address belongs there: a connection whose server falls inside a
// range this interface carries would have its encrypted packets routed back into the
// interface that produced them, and the machine would lose every network it has at once --
// including the dashboard that would switch this off.
//
// The machine's own way out is kept reachable first, before the ranges that make it necessary
// are installed. A program that binds a socket to the interface this machine's default route
// sits on -- the tailnet node this app runs is one, and so is anything else on the machine that
// pins its traffic to a network -- is answered from that interface's own routing, which
// carrying these ranges otherwise empties of any answer for the internet. Doing it first means
// there is no window in which those programs are cut off.
func (i *Interface) Carry(ctx context.Context, routes, exclude []netip.Prefix, mtu int) error {
	if err := i.scopeHostDefault(ctx); err != nil {
		return err
	}
	return i.host.SetHostRoutes(ctx, hostnet.Routes{
		LocalAddrs:  slices.Clone(i.addrs),
		Routes:      slices.Clone(routes),
		LocalRoutes: slices.Clone(exclude),
		MTU:         mtu,
	})
}

// scopeHostDefault keeps the machine's own way out reachable, reporting a platform that cannot
// do it once rather than refusing to carry traffic there.
//
// The refusal is a sentence about the machine, not about the request: on a platform where a
// bound socket is already answered from the whole table there is nothing to do, and treating
// that as a failure would make the one-interface mode unavailable on it. Every other failure is
// returned, because a machine carrying these ranges with its own way out unreachable is one
// where the tailnet node cannot reach its control server.
func (i *Interface) scopeHostDefault(ctx context.Context) error {
	err := i.host.ScopeHostDefault(ctx)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, hostnet.ErrScopedRoutesUnsupported):
		if !i.scopeReported {
			i.logf("this machine cannot give one interface a route of its own, so a program that "+
				"binds a socket to the interface this machine's default route sits on reaches the "+
				"network only while this machine's own routing answers for it: %v", err)
			i.scopeReported = true
		}
		return nil
	default:
		return fmt.Errorf("keep this machine's own way out reachable: %w", err)
	}
}

// Withdraw takes every range off the interface, leaving it up and carrying nothing.
//
// It is what happens when the stack behind the interface stops: the machine is still sending
// those ranges here, and an interface that accepts them and answers nothing is a black hole
// that looks exactly like a network being slow. Withdrawing them makes every one of those
// destinations fail at once, in the same way it fails when app-tail is not running at all.
//
// The copy of this machine's own default route goes with them, and after them: it exists
// because these ranges are installed, and taking it back first would be a window in which a
// program bound to the machine's own interface has neither answer.
func (i *Interface) Withdraw(ctx context.Context) error {
	if err := i.host.SetHostRoutes(ctx, hostnet.Routes{LocalAddrs: slices.Clone(i.addrs)}); err != nil {
		return err
	}
	if err := i.host.UnscopeHostDefault(ctx); err != nil && !errors.Is(err, hostnet.ErrScopedRoutesUnsupported) {
		return fmt.Errorf("take back this machine's own scoped default route: %w", err)
	}
	return nil
}

// Close undoes every change this made to the machine. The interface itself is closed by the
// fabric that was given it, so a Close here after the fabric's own is the routing and
// resolver state alone.
func (i *Interface) Close() error {
	if i.host == nil {
		return nil
	}
	return i.host.Close()
}
