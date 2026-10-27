// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/ipn/store"
	"tailscale.com/logpolicy"
	"tailscale.com/logtail"
	"tailscale.com/net/memnet"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tsd"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"

	// The OS routers register themselves by being imported. Without this line
	// router.New compiles cleanly and returns "unsupported OS" the first time a node
	// starts on an interface -- a build that looks complete and a mode that never works.
	_ "tailscale.com/wgengine/router/osrouter"

	"github.com/sellitus/app-tail/internal/fileown"
	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/hostnet"
)

// tunBackend runs the node on a real network interface: the machine gets the tailnet's
// addresses, routes and resolver configuration, and every program on it reaches peers by
// address and name with no proxy.
//
// It exists because tsnet cannot do this. tsnet builds its own wgengine.Config with no
// Router and no DNS (tsnet/tsnet.go:848-859 in tailscale v1.100.0), and wgengine
// substitutes fakes for both (wgengine/userspace.go:337-347), so a tsnet server handed a
// real interface moves packets and installs no address, no route and no resolver -- it
// reports Running and not one byte of the machine's traffic crosses it. There is no
// exported way to override those two fields.
//
// So this mirrors the same start sequence with the two real implementations wired in,
// following cmd/tailscaled/tailscaled.go:749-842 and tsnet/tsnet.go:834-994 of tailscale
// v1.100.0. Every call it makes is exported, which is the point: when upstream changes
// this shape the build breaks here rather than drifting quietly into a node that is up
// and carrying nothing.
type tunBackend struct {
	params ServerParams
	logf   logger.Logf
	// userLogf carries the few lines a person should see, at the level the rest of the
	// app logs at, while logf carries the stack's own firehose.
	userLogf func(format string, args ...any)
	// grants hears how the helper answered each route and resolver change. See Options.Grants.
	grants grants.Observer

	// shutdownCtx bounds work that outlives a single call -- the credential exchange
	// during start, and the login the backend begins on its own. Close cancels it.
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	// startOnce makes Start idempotent, matching tsnet, whose Listen and Dial call it
	// on every use.
	startOnce sync.Once
	startErr  error

	// mu guards the fields below. It is never held across netstack or backend shutdown:
	// gVisor calls back into this type from its own goroutines, so waiting for those
	// while holding the lock they need is a deadlock.
	mu        sync.Mutex
	closed    bool
	host      hostnet.Host
	sys       *tsd.System
	lb        *ipnlocal.LocalBackend
	ns        *netstack.Impl
	dialer    *tsdial.Dialer
	netMon    *netmon.Monitor
	apiServer *http.Server
	apiLn     *memnet.Listener
	lc        *local.Client

	// fbMu guards the fallback handlers alone, because they are read on the packet path
	// from gVisor's goroutines and mu is held while tearing that path down.
	fbMu      sync.Mutex
	fallbacks map[*tsnet.FallbackTCPHandler]bool
}

var _ backend = (*tunBackend)(nil)

// newTUNBackend builds the interface-mode backend. Nothing is created and no privilege is
// asked for until Start, so a node that is never started leaves the machine untouched.
func newTUNBackend(opts Options, logf, userLogf func(format string, args ...any)) *tunBackend {
	ctx, cancel := context.WithCancel(context.Background())
	return &tunBackend{
		params:         opts.Params,
		logf:           logf,
		userLogf:       userLogf,
		grants:         opts.Grants,
		shutdownCtx:    ctx,
		shutdownCancel: cancel,
		fallbacks:      make(map[*tsnet.FallbackTCPHandler]bool),
	}
}

// Start brings the node up on a real interface.
func (b *tunBackend) Start() error {
	b.startOnce.Do(func() { b.startErr = b.start() })
	return b.startErr
}

// start is the whole wiring, in the order the pieces depend on each other. Any failure
// unwinds what was built, because a half-built engine holds an interface and the
// machine's resolver configuration.
// unwind releases one piece of a half-built stack after a failed start.
//
// The failure being returned is the one worth acting on, so a close that fails on top of
// it goes to the log rather than replacing it -- and it belongs in the log, because a
// piece that will not close is how an interface gets left on the machine.
func (b *tunBackend) unwind(what string, close func() error) {
	if err := close(); err != nil {
		b.logf("could not close %s after a failed start: %v", what, err)
	}
}

func (b *tunBackend) start() (reterr error) {
	if b.params.Dir == "" {
		return errors.New("the interface mode needs a state directory")
	}

	host, err := hostnet.Open(b.shutdownCtx, hostnet.Options{Logf: b.logf, Grants: b.grants})
	if err != nil {
		return err
	}
	// Everything from here on is torn down by Close on the way out of a failure, so the
	// machine is not left with an interface nothing is driving.
	defer func() {
		if reterr != nil {
			if err := host.Close(); err != nil {
				b.logf("could not undo the interface after a failed start: %v", err)
			}
		}
	}()

	caps, err := host.Capabilities(b.shutdownCtx)
	if err != nil {
		return fmt.Errorf("ask this machine what it can do: %w", err)
	}
	if ok, why := caps.Usable(); !ok {
		return errors.New(why)
	}

	dev, ifName, err := host.OpenTUN(b.shutdownCtx, b.params.InterfaceName)
	if err != nil {
		return err
	}
	b.userLogf("app-tail is running on the network interface %s", ifName)

	rtr, osDNS, err := hostnet.Engine(b.shutdownCtx, host)
	if err != nil {
		b.unwind("the network interface", dev.Close)
		return err
	}

	sys := tsd.NewSystem()
	bus := sys.Bus.Get()

	netMon, err := netmon.New(bus, b.logf)
	if err != nil {
		b.unwind("the network interface", dev.Close)
		return fmt.Errorf("watch this machine's network interfaces: %w", err)
	}

	dialer := &tsdial.Dialer{Logf: b.logf}
	dialer.SetBus(bus)

	eng, err := wgengine.NewUserspaceEngine(b.logf, wgengine.Config{
		Tun:           dev,
		Router:        rtr,
		DNS:           osDNS,
		EventBus:      bus,
		NetMon:        netMon,
		Dialer:        dialer,
		SetSubsystem:  sys.Set,
		ControlKnobs:  sys.ControlKnobs(),
		HealthTracker: sys.HealthTracker.Get(),
		ExtraRootCAs:  sys.ExtraRootCAs,
		Metrics:       sys.UserMetricsRegistry(),
	})
	if err != nil {
		b.unwind("the network monitor", netMon.Close)
		b.unwind("the tailnet dialer", dialer.Close)
		// The engine owns the device only once it has been built; before that this is
		// the last reference to it.
		b.unwind("the network interface", dev.Close)
		return fmt.Errorf("build the tailnet engine: %w", err)
	}
	// Past this point the engine closes the device, the router and the resolver
	// configurator when it shuts down, so nothing here may close them again.
	sys.Set(eng)
	sys.HealthTracker.Get().SetMetricsRegistry(sys.UserMetricsRegistry())

	ns, err := netstack.Create(b.logf, sys.Tun.Get(), eng, sys.MagicSock.Get(), dialer, sys.DNSManager.Get(), sys.ProxyMapper())
	if err != nil {
		eng.Close()
		b.unwind("the network monitor", netMon.Close)
		b.unwind("the tailnet dialer", dialer.Close)
		return fmt.Errorf("build the tailnet packet handler: %w", err)
	}
	sys.Tun.Get().Start()
	sys.Set(ns)

	// The machine's own stack owns this node's addresses now, so netstack must not
	// answer for them -- a packet for a local address is written to the interface and
	// whatever is listening on the machine receives it, which is the entire point of
	// this mode.
	ns.ProcessLocalIPs = false
	// Traffic for the networks this node advertises is a different matter: on the
	// platforms where the OS will not route it for us, netstack carries it, which is
	// what makes a subnet route and an advertised exit node work here for every
	// protocol rather than for TCP alone.
	ns.ProcessSubnets = processSubnetsInNetstack()
	// Required, not tuning. With local addresses left to the machine, this is the only
	// thing that lets a listener this app opens receive anything: it tells netstack to
	// absorb a packet for a local address when -- and only when -- it has an endpoint
	// registered for it. Without it every to_tailnet forward is created successfully
	// and never accepts a connection.
	ns.CheckLocalTransportEndpoints = true
	ns.GetTCPHandlerForFlow = b.tcpHandlerForFlow

	stateFile := filepath.Join(b.params.Dir, "tailscaled.state")
	stateStore, err := store.New(b.logf, stateFile)
	if err != nil {
		b.unwind("the packet handler", ns.Close)
		eng.Close()
		b.unwind("the network monitor", netMon.Close)
		b.unwind("the tailnet dialer", dialer.Close)
		return fmt.Errorf("open the node's state file %s: %w", stateFile, err)
	}
	// This file holds the node's private key, and the store creates it with mode bits that
	// carry nothing on Windows: without an access list of its own it keeps whatever the
	// state directory hands down, which under %ProgramData% includes every account on the
	// machine.
	if err := fileown.RestrictToOwner(stateFile); err != nil {
		b.unwind("the packet handler", ns.Close)
		eng.Close()
		b.unwind("the network monitor", netMon.Close)
		b.unwind("the tailnet dialer", dialer.Close)
		return fmt.Errorf("narrow the node's state file %s to this account: %w", stateFile, err)
	}
	sys.Set(stateStore)

	loginFlags := controlclient.LoginDefault
	if b.params.Ephemeral {
		loginFlags = controlclient.LoginEphemeral
	}
	// The OS-neutral start key is what makes this node the same node as the one the
	// userspace mode enrolled. tsnet sets it (tsnet.go:930), so a state directory
	// written there is only readable here with the same flag -- without it, switching
	// modes silently enrolls a second device.
	lb, err := ipnlocal.NewLocalBackend(b.logf, b.logID(), sys, loginFlags|controlclient.LocalBackendStartKeyOSNeutral)
	if err != nil {
		b.unwind("the packet handler", ns.Close)
		eng.Close()
		b.unwind("the network monitor", netMon.Close)
		b.unwind("the tailnet dialer", dialer.Close)
		return fmt.Errorf("build the tailnet backend: %w", err)
	}
	lb.SetVarRoot(b.params.Dir)

	if err := ns.Start(lb); err != nil {
		lb.Shutdown()
		b.unwind("the packet handler", ns.Close)
		b.unwind("the network monitor", netMon.Close)
		b.unwind("the tailnet dialer", dialer.Close)
		return fmt.Errorf("start the tailnet packet handler: %w", err)
	}
	// From here the backend owns the engine: its Shutdown closes it, and closing the
	// engine separately would be a second teardown of the same interface.

	prefs := ipn.NewPrefs()
	prefs.Hostname = b.params.Hostname
	prefs.WantRunning = true
	prefs.ControlURL = b.controlURL()
	prefs.AdvertiseTags = b.params.AdvertiseTags
	if err := lb.Start(ipn.Options{UpdatePrefs: prefs, AuthKey: b.params.AuthKey}); err != nil {
		lb.Shutdown()
		b.unwind("the packet handler", ns.Close)
		b.unwind("the network monitor", netMon.Close)
		b.unwind("the tailnet dialer", dialer.Close)
		return fmt.Errorf("start the tailnet backend: %w", err)
	}
	if lb.State() == ipn.NeedsLogin {
		if err := lb.StartLoginInteractive(b.shutdownCtx); err != nil {
			lb.Shutdown()
			b.unwind("the packet handler", ns.Close)
			b.unwind("the network monitor", netMon.Close)
			b.unwind("the tailnet dialer", dialer.Close)
			return fmt.Errorf("begin login: %w", err)
		}
	}

	apiLn, apiServer, lc := b.serveLocalAPI(sys, lb)

	b.mu.Lock()
	b.host, b.sys, b.lb, b.ns = host, sys, lb, ns
	b.dialer, b.netMon = dialer, netMon
	b.apiLn, b.apiServer, b.lc = apiLn, apiServer, lc
	b.mu.Unlock()
	return nil
}

// serveLocalAPI publishes the backend's local API over an in-memory pipe.
//
// The same shape tsnet uses, and for the same reason: it gives a real *local.Client with
// no socket anywhere on the machine, so nothing outside this process can reach an API
// that edits preferences, reads the pending login URL and mints certificates.
func (b *tunBackend) serveLocalAPI(sys *tsd.System, lb *ipnlocal.LocalBackend) (*memnet.Listener, *http.Server, *local.Client) {
	h := localapi.NewHandler(localapi.HandlerConfig{
		Actor:    ipnauth.Self,
		Backend:  lb,
		Logf:     b.logf,
		LogID:    b.logID(),
		EventBus: sys.Bus.Get(),
	})
	h.PermitRead = true
	h.PermitWrite = true

	ln := memnet.Listen("local-tailscaled.sock:80")
	srv := &http.Server{Handler: h}
	lc := &local.Client{Dial: ln.Dial}
	lb.ConfigureWebClient(lc)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			b.logf("local API stopped serving: %v", err)
		}
	}()
	return ln, srv, lc
}

// logID is the identifier the backend stamps its own logs with.
//
// It is read from -- and on first run written to -- the same file tsnet uses, so a node
// keeps one identity across a mode switch. No log uploader is started: this app writes
// the stack's logging to its own logger and nothing leaves the machine, so the identifier
// is only ever a local correlation key. A file that cannot be read or written costs a
// stable identifier and nothing else, which is not worth refusing to start over.
func (b *tunBackend) logID() logid.PublicID {
	path := filepath.Join(b.params.Dir, "tailscaled.log.conf")
	cfg, err := logpolicy.ConfigFromFile(path)
	if err == nil && cfg.Validate(logtail.CollectionNode) == nil {
		return cfg.PublicID
	}
	cfg = logpolicy.NewConfig(logtail.CollectionNode)
	if err := cfg.Save(path); err != nil {
		b.logf("could not save the log identifier to %s: %v", path, err)
	}
	return cfg.PublicID
}

// controlURL is the coordination server this node enrols with, defaulting to the public
// one the same way tsnet does.
func (b *tunBackend) controlURL() string {
	if b.params.ControlURL != "" {
		return b.params.ControlURL
	}
	return ipn.DefaultControlURL
}

// processSubnetsInNetstack reports whether this app carries traffic for the networks the
// node advertises, rather than leaving it to the OS.
//
// It mirrors the same decision in cmd/tailscaled (handleSubnetsInNetstack, tailscaled.go
// :729-745 of tailscale v1.100.0): on the platforms with no kernel forwarding path
// tailscale can configure, the packet handler in this process does the forwarding. Linux
// is the exception, where the kernel does it and doing it here as well would put every
// forwarded packet through userspace for nothing.
func processSubnetsInNetstack() bool {
	switch runtime.GOOS {
	case "linux", "android":
		return false
	default:
		return true
	}
}

// tcpHandlerForFlow is netstack's question about one inbound TCP flow that no listener in
// this process claimed.
//
// Returning intercept=false is the answer that matters: it means "not mine", and netstack
// then forwards the flow the way a subnet router does, from this machine's own stack.
// That is why this mode carries a subnet route for every protocol while the userspace mode
// carries only TCP -- there, tsnet answers an unclaimed flow with a reset.
func (b *tunBackend) tcpHandlerForFlow(src, dst netip.AddrPort) (func(net.Conn), bool) {
	b.fbMu.Lock()
	handlers := make([]*tsnet.FallbackTCPHandler, 0, len(b.fallbacks))
	for h := range b.fallbacks {
		handlers = append(handlers, h)
	}
	b.fbMu.Unlock()

	for _, h := range handlers {
		if conn, ok := (*h)(src, dst); ok {
			return conn, true
		}
	}
	return nil, false
}

// RegisterFallbackTCPHandler adds a handler for flows no listener claimed, and returns the
// function that removes it.
func (b *tunBackend) RegisterFallbackTCPHandler(cb tsnet.FallbackTCPHandler) func() {
	b.fbMu.Lock()
	defer b.fbMu.Unlock()
	b.fallbacks[&cb] = true
	return func() {
		b.fbMu.Lock()
		defer b.fbMu.Unlock()
		delete(b.fallbacks, &cb)
	}
}

// LocalClient returns the client for the node's own backend API.
func (b *tunBackend) LocalClient() (*local.Client, error) {
	if err := b.Start(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lc == nil {
		return nil, errors.New("the node is not running")
	}
	return b.lc, nil
}

// Sys returns the engine's subsystem registry, or nil before Start.
func (b *tunBackend) Sys() *tsd.System {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sys
}

// Dial opens a connection over the tailnet, resolving MagicDNS names.
//
// The machine's own stack carries it: this node's routes are installed on the machine, so
// an ordinary dial to a tailnet address already goes through the interface. The dialer is
// still the tailnet's own because it is what resolves MagicDNS names, which the machine's
// resolver only knows about through the configuration this mode installed.
func (b *tunBackend) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if err := b.Start(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	dialer := b.dialer
	b.mu.Unlock()
	if dialer == nil {
		return nil, ErrNotRunning
	}
	return dialer.UserDial(ctx, network, address)
}

// Listen accepts TCP connections addressed to this node over the tailnet.
//
// The listener lives in this process's own packet handler rather than on the machine, so
// a forward this app opens on port 22 does not collide with the machine's own service on
// port 22 and does not become reachable on any other network the machine is attached to.
// That is the same guarantee the userspace mode gives, which is what makes the setting a
// toggle rather than a different product.
func (b *tunBackend) Listen(network, addr string) (net.Listener, error) {
	if err := b.Start(); err != nil {
		return nil, err
	}
	ap, err := parseListenAddr(addr)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	ns := b.ns
	b.mu.Unlock()
	if ns == nil {
		return nil, ErrNotRunning
	}

	switch network {
	case "", "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("the interface mode cannot listen on %q; it accepts tcp", network)
	}
	// An unspecified address is bound as IPv6, which in this stack accepts both families
	// on the node's own addresses -- the same wildcard tsnet uses for a TUN listener.
	proto, bind := "tcp6", netip.AddrPortFrom(netip.IPv6Unspecified(), ap.Port())
	if ap.Addr().IsValid() && !ap.Addr().IsUnspecified() {
		bind = ap
		if ap.Addr().Is4() {
			proto = "tcp4"
		}
	}
	if network == "tcp4" {
		proto = "tcp4"
		if !bind.Addr().IsValid() || bind.Addr().IsUnspecified() {
			bind = netip.AddrPortFrom(netip.IPv4Unspecified(), ap.Port())
		}
	}
	ln, err := ns.ListenTCP(proto, bind.String())
	if err != nil {
		return nil, fmt.Errorf("listen on the tailnet at %s: %w", bind, err)
	}
	return ln, nil
}

// ListenPacket receives UDP addressed to this node over the tailnet.
func (b *tunBackend) ListenPacket(network, addr string) (net.PacketConn, error) {
	if err := b.Start(); err != nil {
		return nil, err
	}
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("the interface mode needs a concrete address to receive on, not %q: %w", addr, err)
	}
	b.mu.Lock()
	ns := b.ns
	b.mu.Unlock()
	if ns == nil {
		return nil, ErrNotRunning
	}

	proto := network
	switch network {
	case "", "udp":
		proto = "udp4"
		if ap.Addr().Is6() {
			proto = "udp6"
		}
	case "udp4", "udp6":
	default:
		return nil, fmt.Errorf("the interface mode cannot receive on %q; it accepts udp", network)
	}
	pc, err := ns.ListenPacket(proto, ap.String())
	if err != nil {
		return nil, fmt.Errorf("receive on the tailnet at %s: %w", ap, err)
	}
	return pc, nil
}

// parseListenAddr accepts the ":port" and "ip:port" forms the app uses.
func parseListenAddr(addr string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap, nil
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("read the listen address %q: %w", addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("read the port in %q: %w", addr, err)
	}
	if host == "" {
		return netip.AddrPortFrom(netip.Addr{}, uint16(port)), nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("the listen address %q must be an IP or empty", host)
	}
	return netip.AddrPortFrom(ip, uint16(port)), nil
}

// apiShutdown bounds the wait for the in-memory API server to finish its requests. It is
// short because the only client is in this process and is already going away.
const apiShutdown = 5 * time.Second

// Close shuts the node down and hands the machine back.
//
// The order is the reverse of start, and the last step is the one that matters: the
// privileged side removes the routes and the resolver configuration and drops the
// interface. It runs last so nothing is still trying to use them, and it runs on every
// path out of here -- including one where an earlier step failed, because a machine left
// with app-tail's routes and none of app-tail is the failure worth avoiding.
func (b *tunBackend) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	host, lb, ns := b.host, b.lb, b.ns
	dialer, netMon := b.dialer, b.netMon
	apiLn, apiServer, sys := b.apiLn, b.apiServer, b.sys
	b.lc = nil
	b.mu.Unlock()

	// Released before anything is torn down: gVisor calls back into this type while it
	// shuts down, and a handler waiting on a lock the teardown holds never returns.
	b.fbMu.Lock()
	b.fallbacks = make(map[*tsnet.FallbackTCPHandler]bool)
	b.fbMu.Unlock()

	var errs []error
	if apiServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), apiShutdown)
		if err := apiServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("stop the node's local API: %w", err))
		}
		cancel()
	}
	b.shutdownCancel()
	if ns != nil {
		if err := ns.Close(); err != nil {
			errs = append(errs, fmt.Errorf("stop the tailnet packet handler: %w", err))
		}
	}
	// Closes the engine, which closes the interface, the routing proxy and the resolver
	// proxy -- and sends the resolver configuration removal across the boundary while
	// the connection to the privileged side is still up.
	if lb != nil {
		lb.Shutdown()
	}
	if netMon != nil {
		if err := netMon.Close(); err != nil {
			errs = append(errs, fmt.Errorf("stop watching this machine's network interfaces: %w", err))
		}
	}
	if dialer != nil {
		if err := dialer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close this node's dialer: %w", err))
		}
	}
	if apiLn != nil {
		if err := apiLn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close the node's local API listener: %w", err))
		}
	}
	if host != nil {
		if err := host.Close(); err != nil {
			errs = append(errs, fmt.Errorf("hand this machine's network configuration back: %w", err))
		}
	}
	if sys != nil {
		sys.Bus.Get().Close()
	}
	return errors.Join(errs...)
}
