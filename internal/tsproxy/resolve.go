// SPDX-License-Identifier: MIT

package tsproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// How long an answer from a network's own resolver is reused. The floor keeps a busy
// destination from costing a query per connection; the ceiling bounds how long a record the
// network republished -- a failover, a moved service -- takes to be noticed, since nothing
// here is told when a private DNS zone changes.
const (
	minResolveTTL = 30 * time.Second
	maxResolveTTL = 5 * time.Minute
)

// resolve turns a destination into the address the dial will actually be made to, and the
// connection that carries it.
//
// Under ResolveViaTailnet the networks' own resolvers are asked first. They are the only
// ones that know a domain a private nameserver answers for: this machine's resolver answers
// such a name with a public address or with nothing, and either way the connection does not
// reach what the user meant. A name no network serves falls back to the ordinary route
// lookup, which is what keeps every other destination working while the mode is on.
//
// Whatever the mode, the address that comes back is what the rules are matched against, so
// permission is decided on the address actually dialled rather than on the name asked for.
//
// It hangs off the set rather than an instance because everything it uses is shared -- the
// connections and the answers they have already given -- and because a stored instance that
// is not currently listening still has to be answerable for what it would reach.
func (s *Set) resolve(ctx context.Context, network, address string, cfg Config) (tunnel.Route, error) {
	if cfg.ResolveVia != config.ResolveViaTailnet {
		return s.net.Resolve(ctx, network, address)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// Not a destination this can take apart. Resolve reports it in the terms the caller
		// already handles rather than this producing a second wording for it.
		return s.net.Resolve(ctx, network, address)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		// Already an address; there is no name to resolve.
		return s.net.Resolve(ctx, network, address)
	}
	if _, _, named := s.net.Naming().Match(host); named {
		// The name already says which connection it is on, and the route lookup asks that
		// one and no other. Asking every network's resolver first would put a name that
		// names one network to all of them, and the first to answer would win.
		return s.net.Resolve(ctx, network, address)
	}

	addr, served, err := s.privateAddr(ctx, host)
	if err != nil {
		return tunnel.Route{}, err
	}
	if !served {
		return s.net.Resolve(ctx, network, address)
	}
	return s.net.Resolve(ctx, network, net.JoinHostPort(addr.String(), port))
}

// privateAddr resolves one name through the networks' own resolvers, answering from the
// cache while an earlier answer is still live. served is false when no network serves the
// name at all, which is a fact about the name rather than a failure to resolve it.
//
// The connections are asked in declaration order and the first that answers wins, which is
// the same tie-break the route lookup uses: the list is the user's own, so the network they
// put first is the one they meant.
func (s *Set) privateAddr(ctx context.Context, host string) (netip.Addr, bool, error) {
	if addr, ok := s.resolved.get(host, s.now()); ok {
		return addr, true, nil
	}

	var refusals []error
	for _, t := range s.net.All() {
		asker, ok := t.(tunnel.Resolving)
		if !ok {
			continue
		}
		lookup, err := asker.LookupHost(ctx, host)
		if err != nil {
			// One network's resolver being unreachable is not an answer about the name.
			// The others are still asked, and the reasons are kept in case none of them
			// answers either.
			refusals = append(refusals, fmt.Errorf("%s: %w", t.ID(), err))
			continue
		}
		if !lookup.Served() {
			continue
		}
		addr := lookup.Addrs[0]
		s.resolved.put(host, addr, s.now().Add(cacheFor(lookup.TTL)))
		return addr, true, nil
	}

	if len(refusals) > 0 {
		return netip.Addr{}, false, fmt.Errorf("asking the private resolvers about %s: %w",
			host, errors.Join(refusals...))
	}
	return netip.Addr{}, false, nil
}

// cacheFor clamps a record's own lifetime into the window an answer is reused for.
func cacheFor(ttl time.Duration) time.Duration {
	switch {
	case ttl < minResolveTTL:
		return minResolveTTL
	case ttl > maxResolveTTL:
		return maxResolveTTL
	default:
		return ttl
	}
}

// resolveCache holds what the tailnet's resolver last said about each name, so a burst of
// connections to one destination costs one query rather than one per connection.
type resolveCache struct {
	mu    sync.Mutex
	names map[string]resolvedName
}

type resolvedName struct {
	addr    netip.Addr
	expires time.Time
}

func (c *resolveCache) get(host string, now time.Time) (netip.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.names[host]
	if !ok || !now.Before(entry.expires) {
		return netip.Addr{}, false
	}
	return entry.addr, true
}

func (c *resolveCache) put(host string, addr netip.Addr, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.names == nil {
		c.names = make(map[string]resolvedName)
	}
	c.names[host] = resolvedName{addr: addr, expires: expires}
}

// clear drops every remembered answer. Anything that changes which resolver is asked, or
// which tailnet is answering, invalidates all of them at once -- and a stale entry here
// would send a connection to the address the other resolver gave.
func (c *resolveCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.names)
}
