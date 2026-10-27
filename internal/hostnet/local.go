// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/health"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tstun"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/wgengine/router"

	// The OS routers are registered by importing them. Without this line router.New
	// compiles cleanly and returns "unsupported OS" at run time, which is the worst of
	// both: a build that looks complete and an interface mode that never works.
	_ "tailscale.com/wgengine/router/osrouter"
)

// Local does the privileged work in this process. It is what runs when the process
// already holds the rights: Windows after elevating, or a unix agent started as root.
//
// The interface it opens is handed to the caller and closed by whatever the caller gives
// it to -- the engine closes the device it was built with. So Close here releases the
// routing and resolver state, and the device only in the failure paths where it was
// never handed over. Closing it in both places would be a double close on a live fd.
type Local struct {
	logf logger.Logf

	mu     sync.Mutex
	bus    *eventbus.Bus
	mon    *netmon.Monitor
	router router.Router
	dns    dns.OSConfigurator
	// dev is set only through Retain, by a caller that still holds a reference of its
	// own to the same interface. It is nil in the agent, where the engine owns it.
	dev    tun.Device
	opened bool
	closed bool
	// tunName is what the OS called the interface this side opened, empty until it has. It
	// is kept so the scoped copy of this machine's own default route can refuse to land on
	// app-tail's own interface.
	tunName string
	// hostScoped are the copies of this machine's own default route this side installed. See
	// hostdefault.go.
	hostScoped []scopedHostRoute

	// The machine-wide resolver half, which has nothing to do with the interface: it works
	// with no tailnet at all, and it outlives every rebuild of the node. It is held as an
	// interface for the reason the route changes below are fields: what this session does
	// on the way out when the machine refuses to be put back is not reachable with the
	// real one on the machine a suite runs on.
	sysdns           systemResolver
	systemDNSApplied bool
	// bootRepair arms what puts this machine's resolver back at the next boot if this process
	// dies with the override in place, nil where a helper already does that at boot. It is
	// fixed at construction.
	bootRepair func() error
	// holdServing takes the lock that tells a repair this machine is being served, nil where
	// nothing repairs it behind this session's back. releaseServing gives it up, and is set
	// for exactly as long as it is held.
	holdServing    func(ctx context.Context) (func() error, error)
	releaseServing func() error
	// The two halves of the newest resolver socket, held between being bound and being
	// handed over. Each is nil once its caller has taken it.
	resolverPacket net.PacketConn
	resolverStream net.Listener

	// The OpenVPN connections this session started, by connection id. They are the one thing
	// here that is a separate process, so they are the one thing that could outlive this one
	// -- which is why the teardown stops every one of them rather than leaving it to whoever
	// asked for them.
	openvpn map[string]*openvpnProcess

	// state is the on-disk record of what the two maps above describe, so a run that never
	// gets to undo any of it leaves the next one something to work from. See reclaim.go.
	state *rootState

	// The route changes this session makes to the machine, held as fields so a test can stand
	// in for them. They run the platform's routing tool as root, which a suite cannot do --
	// and what decides whether this machine is left with a route nothing is tracking is
	// exactly the branches where that tool refuses.
	scopeRoute   routeChanger
	unscopeRoute routeChanger
	// carriesV6 reports whether an interface holds an address of the second family, held here
	// for the same reason: which families a route goes on would otherwise be decided by the
	// machine a test runs on.
	carriesV6 func(name string) (bool, error)
	// openvpnBinary is the program a connection is started from. It is a field for the reason
	// the route changes are: what happens to the private key already written when the program
	// will not start is not reachable with the real one, which either starts or is not there.
	openvpnBinary func() (string, error)
	// openvpnManagementDir is where openvpn is told to create its management sockets, empty
	// for OpenVPNManagementDir. It is a field because that directory belongs to root, and a
	// suite has to be able to watch what is created there without being root.
	openvpnManagementDir string
	// tailnetRoutes reads and changes where this machine sends traffic aimed at a tailnet
	// another client on this machine is carrying. See tailnetroutes.go.
	tailnetRoutes tailnetRouteOps
	// openvpnAddrs holds the addresses a connection's server gave its interface to what an
	// administrator approved; nil in a process that is not serving a helper session, where
	// nothing is approved on anyone's behalf. See openvpnaddrs.go.
	openvpnAddrs openvpnAddressCheck
	// interfaceAddrs reads the addresses on a named interface, a field so a suite can say what
	// a server handed out without one.
	interfaceAddrs func(name string) ([]netip.Prefix, error)
}

// machineState is the record of what this side installed on the machine, made on first use.
//
// It is built lazily rather than in NewLocal so a session that changes nothing on this machine
// never touches the directory it lives in, and so a test can put the record somewhere it is
// allowed to write.
//
// It must not be called with the session lock held.
func (l *Local) machineState() *rootState {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state == nil {
		l.state = newRootState(DefaultRootStatePath(), l.logf)
	}
	return l.state
}

// systemDNSRestoreTimeout bounds putting this machine's resolver back during a teardown.
//
// It is generous because the work is one shell-out per network service on a machine that may
// have a dozen, and it is bounded at all because this runs on the path that ends the process:
// a restore that never returns is a machine left pointing at a resolver that is going away,
// which is the exact outcome the restore exists to prevent.
const systemDNSRestoreTimeout = 30 * time.Second

// NewLocal builds the in-process privileged side. Nothing is created until OpenTUN.
func NewLocal(logf func(format string, args ...any)) *Local {
	return &Local{
		logf:           logf,
		scopeRoute:     scopeDefault,
		unscopeRoute:   unscopeDefault,
		carriesV6:      interfaceCarriesV6,
		openvpnBinary:  OpenVPNBinary,
		tailnetRoutes:  defaultTailnetRouteOps(),
		interfaceAddrs: interfacePrefixes,
		bootRepair:     armBootRepair,
		holdServing:    holdSystemDNSServing,
	}
}

var (
	_ Host           = (*Local)(nil)
	_ SystemResolver = (*Local)(nil)
	_ OpenVPNRunner  = (*Local)(nil)
)

// Capabilities reports what this machine can do without changing anything.
func (l *Local) Capabilities(ctx context.Context) (Capabilities, error) {
	if err := ctx.Err(); err != nil {
		return Capabilities{}, err
	}
	l.mu.Lock()
	own := l.tunName
	l.mu.Unlock()
	return capabilities(ctx, BuildID, own)
}

// capabilities gathers what this machine can do, taking this side's own identity as a
// parameter so the refusal for a binary that cannot be read is reachable without a suite
// running from one.
//
// A privileged side that cannot say which binary it is running is refused by the other side
// rather than trusted, so failing to read it is reported here instead of answered around.
// The same read is what an install performs, so a machine this fails on could not have
// produced a helper either.
func capabilities(ctx context.Context, identify func() (string, error), own string) (Capabilities, error) {
	build, err := identify()
	if err != nil {
		return Capabilities{}, err
	}
	return Capabilities{
		Version:       Version,
		Build:         build,
		Interface:     DefaultInterfaceName(),
		Conflict:      DetectConflict(ctx, own),
		Missing:       DetectMissing(),
		ResolverBusy:  DetectResolverBusy(ctx),
		Leftovers:     DetectLeftovers(),
		StaleOverride: DetectStaleOverride(ctx),
	}, nil
}

// validTUNName refuses a name OpenTUN must not be asked to create.
//
// An empty name is the platform's default and always allowed. Anything else has to be a
// name an interface can have -- validInterfaceName's letters, digits, dots, hyphens and
// underscores within the kernel's 15 bytes, which on Linux keeps out a '/' and whitespace --
// and may not start with a hyphen, which a system tool handed the name would read as an
// option. macOS goes further: its kernel names every tunnel itself, as utun followed by a
// number, so a request there may only ask for utun (the next free one) or one particular
// utunN.
//
// goos is passed in rather than read so the macOS rule is checked on every platform the
// suite runs on.
func validTUNName(name, goos string) error {
	if name == "" {
		return nil
	}
	if err := validInterfaceName(name); err != nil {
		return err
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("%q starts with a hyphen, which a program handed it would read as an option", name)
	}
	if goos == "darwin" {
		number, ok := strings.CutPrefix(name, "utun")
		if !ok || strings.Trim(number, "0123456789") != "" {
			return fmt.Errorf("%q is not a name macOS gives a tunnel interface: it has to be utun, optionally followed by a number", name)
		}
	}
	return nil
}

// OpenTUN creates the interface and returns it along with the name the OS gave it.
func (l *Local) OpenTUN(ctx context.Context, name string) (tun.Device, string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, "", errors.New("this interface has already been torn down")
	}
	if l.opened {
		return nil, "", errors.New("an interface is already open")
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if name == "" {
		name = DefaultInterfaceName()
	}

	// Anything a previous run left behind is removed before a new interface is made.
	// Resolver files in particular outlive the process that wrote them, and a stale one
	// pointing at an address nothing answers on breaks name resolution machine-wide
	// until it is deleted.
	CleanUpLeftovers(l.logf)

	// Asked here as well as by the callers that check first: on Windows this is what loads
	// the pinned wintun.dll, and an adapter created before it would load whatever file
	// sits at that path.
	if missing := DetectMissing(); missing != "" {
		return nil, "", errors.New(missing)
	}

	dev, realName, err := tstun.New(l.logf, name)
	if err != nil {
		tstun.Diagnose(l.logf, name, err)
		return nil, "", fmt.Errorf("create the network interface %q: %w", name, err)
	}

	bus := eventbus.New()
	mon, err := netmon.New(bus, l.logf)
	if err != nil {
		l.unwind("the network interface", dev.Close)
		bus.Close()
		return nil, "", fmt.Errorf("watch this machine's network interfaces: %w", err)
	}
	tracker := healthTracker(bus)

	rtr, err := router.New(l.logf, dev, mon, tracker, bus)
	if err != nil {
		l.unwind("the network monitor", mon.Close)
		l.unwind("the network interface", dev.Close)
		bus.Close()
		return nil, "", fmt.Errorf("take over routing for %q: %w", realName, err)
	}
	osCfg, err := dns.NewOSConfigurator(l.logf, tracker, bus, policyclient.NoPolicyClient{}, nil, realName)
	if err != nil {
		l.unwind("the router", rtr.Close)
		l.unwind("the network monitor", mon.Close)
		l.unwind("the network interface", dev.Close)
		bus.Close()
		return nil, "", fmt.Errorf("take over name resolution for %q: %w", realName, err)
	}

	l.bus, l.mon = bus, mon
	l.router, l.dns = rtr, osCfg
	l.tunName = realName
	l.opened = true
	setHeldInterface(realName)
	return dev, realName, nil
}

// healthTracker builds the tracker the router and the resolver report their own health
// through.
//
// It is a function rather than a literal because the hazard it avoids is invisible at the
// call site: the tracker reports by publishing on the bus, and one that was never given a
// client to publish through dereferences nothing and brings the process down. Nothing
// reports here, so a tracker built wrong survives this call, the open and the start --
// on Windows the first report comes from a goroutine the router starts when configuring
// the interface takes longer than it expects, and the panic lands a second later with
// nothing on the stack naming this line.
func healthTracker(bus *eventbus.Bus) *health.Tracker { return health.NewTracker(bus) }

// unwind releases one piece of a half-opened interface. The failure being returned is the
// one worth acting on; a close that fails on top of it goes to the log, where it is the
// record that this machine may still be carrying something.
func (l *Local) unwind(what string, close func() error) {
	if err := close(); err != nil {
		l.logf("could not close %s after a failed open: %v", what, err)
	}
}

// Retain makes this Local close the interface as part of its own teardown.
//
// It is for the helper, and only for the helper. There, the descriptor is open in two
// processes -- the helper that created it and the agent it was handed to -- and the
// interface goes away only when both references are dropped, so the helper has to hold
// one to be able to take it back. In the agent, the engine the device was given to closes
// it, and retaining it here as well would be a double close on a live descriptor.
func (l *Local) Retain(dev tun.Device) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dev = dev
}

// RouterUp brings the interface up. On the platforms where creating an interface already
// leaves it up this does nothing, and the engine calls it exactly once either way.
func (l *Local) RouterUp(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.router == nil {
		return errors.New("no interface is open, so there is nothing to bring up")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := l.router.Up(); err != nil {
		return fmt.Errorf("bring the network interface up: %w", err)
	}
	return nil
}

// SetRoutes installs the addresses and routes the interface carries.
func (l *Local) SetRoutes(ctx context.Context, cfg *router.Config) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.router == nil {
		return errors.New("no interface is open, so there is nothing to route")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := l.router.Set(cfg); err != nil {
		return fmt.Errorf("install this device's routes: %w", err)
	}
	return nil
}

// SetHostRoutes installs the addressing for an interface this app drives itself.
//
// It goes through the same OS router the engine's own configuration does, because there is
// only one interface and only one routing table: two ways of changing them would be two
// places for the machine's routes to be wrong. What crosses the boundary is the narrow shape
// -- ranges and a packet size -- and it is turned into the engine's configuration here, on
// the privileged side, where the fields this caller may not set are simply not set.
func (l *Local) SetHostRoutes(ctx context.Context, r Routes) error {
	if err := r.Validate(); err != nil {
		return err
	}
	routes, err := r.Installed()
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.router == nil {
		return errors.New("no interface is open, so there is nothing to route")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	cfg := &router.Config{
		LocalAddrs:  slices.Clone(r.LocalAddrs),
		Routes:      routes,
		LocalRoutes: slices.Clone(r.LocalRoutes),
		NewMTU:      r.MTU,
	}
	if err := l.router.Set(cfg); err != nil {
		return fmt.Errorf("install this interface's routes: %w", err)
	}
	return nil
}

// SetDNS installs the resolver configuration.
func (l *Local) SetDNS(ctx context.Context, cfg dns.OSConfig) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dns == nil {
		return errors.New("no interface is open, so there is no resolver to configure")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := l.dns.SetDNS(matchTailnetDomains(cfg, resolvesPerDomain())); err != nil {
		return fmt.Errorf("install this device's resolver configuration: %w", err)
	}
	return nil
}

// BaseDNS reports what this machine would resolve names with if app-tail were not here.
//
// The tailnet resolver forwards everything that is not a tailnet name to it, so a wrong
// answer here is a machine that resolves tailnet names and nothing else. A platform that
// declines to say returns dns.ErrGetBaseConfigNotSupported, which the resolver handles by
// making itself the only resolver rather than by failing.
func (l *Local) BaseDNS(ctx context.Context) (dns.OSConfig, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dns == nil {
		return dns.OSConfig{}, errors.New("no interface is open, so there is no resolver to read")
	}
	if err := ctx.Err(); err != nil {
		return dns.OSConfig{}, err
	}
	return l.dns.GetBaseConfig()
}

// SplitDNS reports whether this machine can point one domain at the tailnet's resolver
// and leave the rest alone.
func (l *Local) SplitDNS(ctx context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dns == nil {
		return false, errors.New("no interface is open, so there is no resolver to ask")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return l.dns.SupportsSplitDNS(), nil
}

// Close reverses every change this made to the machine.
//
// Every step runs even when an earlier one failed, and the failures are joined rather
// than returned one at a time. A teardown that stopped at the first error would be the
// one that leaves resolver files pointing at an interface that is going away, which
// breaks name resolution for everything on the machine and not just for app-tail.
func (l *Local) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	// Marked closed before anything is released, and before the lock is dropped: from here
	// on a start that arrives is refused rather than left running behind the teardown.
	l.closed = true
	l.mu.Unlock()

	// First, and not merely early: a machine that loses this process gets its routes,
	// its interfaces and its child processes back on its own, and does not get its resolver
	// back. Everything below is bounded by somebody else's deadline -- a shutdown, a launchd
	// bootout, an instance takeover -- so the one step whose omission stops the machine
	// resolving any name is the one step that runs before the budget can be spent.
	l.mu.Lock()
	errs := l.closeSystemDNS()
	l.mu.Unlock()

	// Before the lock is taken again, because stopping an OpenVPN connection waits for the
	// goroutine that reaps it, and that goroutine takes this lock. Those are separate
	// processes carrying interfaces and routes of their own, and they are the only thing here
	// that could still be running once this returns.
	errs = append(errs, l.closeOpenVPN()...)

	// Also before the lock, and before the interface goes: while the routes that made it
	// necessary are still installed, so the removal is the exact reverse of what put it there.
	errs = append(errs, l.closeHostDefault()...)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.dns != nil {
		if err := l.dns.Close(); err != nil {
			errs = append(errs, fmt.Errorf("restore this machine's resolver configuration: %w", err))
		}
		l.dns = nil
	}
	if l.router != nil {
		if err := l.router.Close(); err != nil {
			errs = append(errs, fmt.Errorf("remove this device's routes: %w", err))
		}
		l.router = nil
	}
	// After the routes, never before: closing the interface first would take the
	// addresses the router is about to remove out from under it.
	if l.dev != nil {
		if err := l.dev.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close the network interface: %w", err))
		}
		l.dev = nil
	}
	if l.mon != nil {
		if err := l.mon.Close(); err != nil {
			errs = append(errs, fmt.Errorf("stop watching this machine's network interfaces: %w", err))
		}
		l.mon = nil
	}
	if l.bus != nil {
		l.bus.Close()
		l.bus = nil
	}
	// Last, so nothing above can still be reading the interface as this process's own: from
	// here an adapter still on the machine is a leftover, which is what it is.
	setHeldInterface("")
	return errors.Join(errs...)
}
