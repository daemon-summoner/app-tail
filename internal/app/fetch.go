// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/sellitus/app-tail/internal/dnsfwd"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/feeds"
	"github.com/sellitus/app-tail/internal/tsnode"
)

const (
	// feedFetchTimeout bounds one download.
	feedFetchTimeout = 3 * time.Minute
	// feedLookupTimeout bounds turning one download's hostname into addresses.
	feedLookupTimeout = 15 * time.Second
)

// fetchFeed is the real downloader behind every list app-tail keeps current: resolve the
// host without asking app-tail, refuse an address a file may not come from, then dial the
// address that came back.
//
// It takes the size cap rather than holding one, because the two consumers disagree about
// it on purpose: a domain blocklist is tens of megabytes of names and an address feed is
// hundreds of kilobytes, and a cap is a parse budget as much as a download limit.
func (a *Agent) fetchFeed(ctx context.Context, rawURL string, prev feeds.State, maxBytes int) (feeds.Fetched, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return feeds.Fetched{}, fmt.Errorf("read the address %q: %w", rawURL, err)
	}
	host := u.Hostname()
	port := uint16(443)
	if named := u.Port(); named != "" {
		n, err := strconv.ParseUint(named, 10, 16)
		if err != nil {
			return feeds.Fetched{}, fmt.Errorf("read the port in %q: %w", rawURL, err)
		}
		port = uint16(n)
	}

	addrs, err := a.resolveWithoutOurselves(ctx, host)
	if err != nil {
		return feeds.Fetched{}, err
	}
	for _, addr := range addrs {
		if err := feeds.Fetchable(addr); err != nil {
			return feeds.Fetched{}, fmt.Errorf("%s resolved to %s, which is not somewhere a list is fetched from: %w", host, addr, err)
		}
	}
	client := feeds.PinnedClient(addrs, port, feedFetchTimeout)
	defer client.CloseIdleConnections()
	return feeds.Fetch(ctx, client, rawURL, prev, maxBytes)
}

// resolveWithoutOurselves turns a hostname into addresses without the answer coming from
// app-tail's own resolver.
//
// While the machine-wide resolver is on, this process is what the system resolver answers
// with, so asking it here would be asking for the answer this call is producing. The way
// out is the one the resolver profiles already use: ask the bootstrap profile's encrypted
// resolvers at their literal addresses, and fall back to what this network published. With
// the override off, the machine's own resolver is somebody else's and answering through it
// is correct.
func (a *Agent) resolveWithoutOurselves(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}

	lookupCtx, cancel := context.WithTimeout(ctx, feedLookupTimeout)
	defer cancel()

	runner := a.currentSystemDNS()
	var (
		base    tsnode.BaseResolvers
		ourself bool
	)
	if runner != nil {
		base, ourself = runner.underlying()
	}
	if !ourself {
		addrs, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("look up %s: %w", host, err)
		}
		return addrs, nil
	}

	var failures []error
	profile, why := a.bootstrapProfile(lookupCtx, a.store.Get())
	if len(dnsprofiles.Dialable(profile)) > 0 {
		addrs, err := a.lookupThrough(lookupCtx, dnsprofiles.Dialable(profile), host)
		if err == nil {
			return addrs, nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", profile.Name, err))
	} else if why != "" {
		failures = append(failures, errors.New(why))
	}

	if len(base.Nameservers) > 0 {
		pool, err := plainPool(base.Nameservers)
		if err != nil {
			failures = append(failures, err)
		} else {
			addrs, err := a.lookupAndClose(lookupCtx, pool, host)
			if err == nil {
				return addrs, nil
			}
			failures = append(failures, err)
		}
	}

	// No fallback to this machine's own resolver: that is app-tail, and the answer it would
	// give is the one being asked for.
	failures = append(failures, errors.New("this network published no resolver to ask instead"))
	return nil, fmt.Errorf("look up %s without asking app-tail's own resolver: %w", host, errors.Join(failures...))
}

// lookupThrough resolves one hostname through upstreams built for this call, and closes
// them afterwards: they hold live sockets and nothing else reads them.
func (a *Agent) lookupThrough(ctx context.Context, upstreams []dnsprofiles.Upstream, host string) ([]netip.Addr, error) {
	var built []dnsfwd.Upstream
	closeAll := func() error {
		var errs []error
		for _, u := range built {
			errs = append(errs, u.Close())
		}
		return errors.Join(errs...)
	}
	for _, u := range upstreams {
		one, err := dnsfwd.NewUpstream(u, nil)
		if err != nil {
			return nil, errors.Join(err, closeAll())
		}
		built = append(built, one)
	}
	return a.lookupAndClose(ctx, dnsfwd.NewPool(built, nil), host)
}

// lookupAndClose resolves one hostname through a pool built for this one call, and closes it
// afterwards: it holds live sockets and nothing else reads it.
//
// A close that fails after the answer arrived is logged rather than returned. The addresses
// are correct and there is nothing the caller could do differently. A close that fails
// alongside a failed lookup goes back with it, because there it may be the reason.
func (a *Agent) lookupAndClose(ctx context.Context, pool *dnsfwd.Pool, host string) ([]netip.Addr, error) {
	addrs, err := dnsfwd.LookupAddrs(ctx, pool, host)
	closeErr := pool.Close()
	if err != nil {
		return nil, errors.Join(err, closeErr)
	}
	if closeErr != nil {
		a.logger.Debug("closing the resolvers used to look up a list failed", "error", closeErr)
	}
	return addrs, nil
}
