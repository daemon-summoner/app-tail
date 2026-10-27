// SPDX-License-Identifier: MIT

package dnsfwd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sellitus/app-tail/internal/dnsprofiles"
)

// Upstream is one resolver the forwarder can ask.
//
// The interface is the seam every test uses: the routing, failover and answer handling
// above it never learns which protocol carried a query, and a test never has to speak one.
type Upstream interface {
	// Exchange sends a query and returns the answer. stream asks for a transport with no
	// size limit, which is what a truncated UDP answer is retried over.
	Exchange(ctx context.Context, query []byte, stream bool) ([]byte, error)
	// Label is the address the user wrote, for logs and for the dashboard.
	Label() string
	// Close releases whatever connections the upstream is holding.
	Close() error
}

// NewUpstream builds the dialer for one parsed address.
//
// A hostname must already be resolved -- see dnsprofiles.Upstream.WithAddr. Resolving it
// here would mean asking a resolver where our resolver is, and on this machine the
// resolver being asked is this process.
func NewUpstream(u dnsprofiles.Upstream, tlsConfig *tls.Config) (Upstream, error) {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	switch u.Protocol {
	case dnsprofiles.Plain:
		return newPlainUpstream(u)
	case dnsprofiles.DoT:
		return newDoTUpstream(u, tlsConfig)
	case dnsprofiles.DoH:
		return newDoHUpstream(u, tlsConfig)
	}
	return nil, fmt.Errorf("%s: unknown resolver protocol %q", u.Text, u.Protocol)
}

// ErrNoUpstream reports that a query had nowhere to go. It is the reason a decision turns
// into SERVFAIL rather than into a wrong answer.
var ErrNoUpstream = errors.New("no resolver is configured")

// recheckPrimary is how long the pool stays on a backup before giving the first entry
// another chance. Short enough that a resolver coming back is noticed within a browse,
// long enough that a resolver flapping does not move every other query.
const recheckPrimary = time.Minute

// Pool is an ordered set of resolvers tried one after another.
//
// The order is the user's list, and the traversal is sequential and sticky rather than
// raced. Racing two providers would mean the fastest one answers, and when the two
// disagree -- which is the entire point of choosing a filtering resolver -- whether a
// domain is blocked would come down to which packet arrived first. Sticky, because moving
// back to a resolver that just failed on every query is a stall per query.
type Pool struct {
	now func() time.Time

	mu      sync.Mutex
	ups     []Upstream
	current int
	movedAt time.Time
}

// NewPool builds a pool over an ordered list. now is injected so failover timing is
// pinned by tests rather than waited out.
func NewPool(ups []Upstream, now func() time.Time) *Pool {
	if now == nil {
		now = time.Now
	}
	return &Pool{ups: ups, now: now}
}

// Len reports how many resolvers the pool holds.
func (p *Pool) Len() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ups)
}

// Labels lists the addresses in order, for the dashboard.
func (p *Pool) Labels() []string {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.ups))
	for _, u := range p.ups {
		out = append(out, u.Label())
	}
	return out
}

// Exchange asks the resolvers in order, starting from the one that last worked, and
// returns the first answer. Every resolver failing is an error naming each failure,
// because "DNS is broken" with no detail is the report this feature would otherwise
// generate.
func (p *Pool) Exchange(ctx context.Context, query []byte, stream bool) ([]byte, error) {
	if p == nil {
		return nil, ErrNoUpstream
	}
	start, ups := p.order()
	if len(ups) == 0 {
		return nil, ErrNoUpstream
	}
	var failures inlineErrors
	for n := range ups {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		i := (start + n) % len(ups)
		resp, err := ups[i].Exchange(ctx, query, stream)
		if err == nil {
			p.settle(i)
			return resp, nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", ups[i].Label(), err))
	}
	return nil, fmt.Errorf("no resolver answered -- %w", failures)
}

// order returns where to start and the list to walk: the resolver that last worked, then
// the rest in the user's order, wrapping.
//
// The list is handed back as it stands rather than copied because nothing ever writes into
// it -- Close replaces the field, it does not edit the entries -- so a caller holding this
// header walks the set that was current when it asked, which is what a copy gave it too.
func (p *Pool) order() (int, []Upstream) {
	p.mu.Lock()
	defer p.mu.Unlock()
	start := p.current
	if start != 0 && p.now().Sub(p.movedAt) >= recheckPrimary {
		// Long enough on a backup. The first entry is the one the user picked first, so
		// it gets the query back as soon as it might work again.
		start = 0
	}
	if start >= len(p.ups) {
		start = 0
	}
	return start, p.ups
}

// settle records which resolver answered, so the next query starts there.
func (p *Pool) settle(i int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current != i {
		p.current = i
		p.movedAt = p.now()
	}
}

// Close releases every resolver in the pool, reporting the first failure and closing the
// rest regardless.
func (p *Pool) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	ups := p.ups
	p.ups = nil
	p.mu.Unlock()
	var firstErr error
	for _, u := range ups {
		if err := u.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
