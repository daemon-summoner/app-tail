// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"fmt"
	"time"

	"tailscale.com/net/dns"
	"tailscale.com/wgengine/router"
)

// The engine drives the machine through exactly two interfaces: a router.Router for
// addresses and routes, and a dns.OSConfigurator for name resolution. Those two are also
// exactly the privilege boundary, so implementing them as proxies onto a Host is what lets
// the whole engine run unprivileged with no other change -- and is what makes the
// privileged side substitutable in a test.

// callTimeout bounds one privileged operation.
//
// The engine calls these from its reconfiguration path, which holds a lock the whole node
// depends on, and the peer is a separate process that could be stopped or wedged. Without
// a bound, a helper that never answers is a node that never reports anything again --
// indistinguishable from a hang in this process, and far harder to find.
const callTimeout = 30 * time.Second

// Engine returns the two interfaces the wireguard engine drives the machine through,
// both backed by host.
//
// They are returned together because they are only ever used together, and because the
// resolver has to be asked one question before it can answer any -- doing that here means
// a caller cannot forget to.
func Engine(ctx context.Context, host Host) (router.Router, dns.OSConfigurator, error) {
	osCfg, err := newDNSProxy(ctx, host)
	if err != nil {
		return nil, nil, err
	}
	return newRouterProxy(host), osCfg, nil
}

// routerProxy is the engine's router. Every method is one call across the boundary.
type routerProxy struct {
	host Host
}

var _ router.Router = (*routerProxy)(nil)

// newRouterProxy wraps a Host as the router the engine reconfigures.
func newRouterProxy(host Host) *routerProxy { return &routerProxy{host: host} }

// Up brings the interface up. The engine calls it once, before the first Set.
func (r *routerProxy) Up() error {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	return r.host.RouterUp(ctx)
}

// Set installs this node's addresses and routes. A nil config removes everything.
func (r *routerProxy) Set(cfg *router.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	return r.host.SetRoutes(ctx, cfg)
}

// Close does nothing here, and that is deliberate: the privileged side owns the teardown
// and runs it from Host.Close, which also runs when this process dies without reaching
// any of its own code. Removing the routes from here as well would be a second teardown
// racing the first, and only one of the two is reachable in the case that matters.
func (r *routerProxy) Close() error { return nil }

// dnsProxy is the engine's resolver configurator.
type dnsProxy struct {
	host Host
	// splitDNS is read once at construction rather than per call. It is a fixed property
	// of the configurator on the other side, and the engine asks it while holding the
	// lock every reconfiguration goes through.
	splitDNS bool
}

var _ dns.OSConfigurator = (*dnsProxy)(nil)

// newDNSProxy wraps a Host as the resolver configurator the engine drives, reading the
// one property of it that never changes.
func newDNSProxy(ctx context.Context, host Host) (*dnsProxy, error) {
	split, err := host.SplitDNS(ctx)
	if err != nil {
		return nil, fmt.Errorf("ask what this machine can do with resolver configuration: %w", err)
	}
	return &dnsProxy{host: host, splitDNS: split}, nil
}

// SetDNS installs the resolver configuration. A zero config removes it.
func (d *dnsProxy) SetDNS(cfg dns.OSConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	return d.host.SetDNS(ctx, cfg)
}

// SupportsSplitDNS reports whether one domain can be pointed at the tailnet's resolver
// while the rest of the machine is left alone.
func (d *dnsProxy) SupportsSplitDNS() bool { return d.splitDNS }

// GetBaseConfig reports what this machine resolved names with before app-tail.
func (d *dnsProxy) GetBaseConfig() (dns.OSConfig, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	return d.host.BaseDNS(ctx)
}

// Close does nothing, for the same reason routerProxy.Close does not: the privileged side
// restores the machine's resolver configuration from its own teardown, which is the only
// one that runs when this process is killed.
func (d *dnsProxy) Close() error { return nil }
