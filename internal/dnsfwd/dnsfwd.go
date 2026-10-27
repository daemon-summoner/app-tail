// SPDX-License-Identifier: MIT

// Package dnsfwd is the resolver app-tail points this machine at when the system-wide DNS
// switch is on.
//
// It answers on a loopback socket, decides per query whether the name belongs to the
// resolvers the user chose or to the ones this network handed out, and forwards it over
// plain DNS, DNS over TLS or DNS over HTTPS. The decision itself is a pure function --
// Route in route.go -- so every rule is reachable in a test without a socket.
//
// The package opens no sockets of its own. Both listeners are handed in, because on every
// platform port 53 belongs to root and the process that binds it is not this one.
//
// There is no cache here, deliberately. Every platform this runs on already caches in
// front of us -- mDNSResponder, the DNS Client service, systemd-resolved -- so a second
// cache would buy a few milliseconds and cost the one property a filtering resolver has to
// have: that a name stops resolving when the user's blocklist says it should.
package dnsfwd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// dialTimeout bounds reaching a resolver, handshake included.
	dialTimeout = 4 * time.Second
	// queryTimeout bounds one exchange with one resolver. A stub resolver gives up
	// around five seconds, so a longer wait here is a wait nobody is left to receive.
	queryTimeout = 5 * time.Second
	// writeTimeout bounds a write to a resolver that has stopped reading.
	writeTimeout = 5 * time.Second
	// idleTimeout is how long a connection with nothing outstanding stays open.
	idleTimeout = 30 * time.Second
	// maxUDPAnswer is the largest answer we will read off a UDP socket.
	maxUDPAnswer = 4096
	// maxStreamAnswer is the largest a DNS message can be on a stream.
	maxStreamAnswer = 65535
	// maxInFlight bounds concurrent exchanges. Past it a query is answered SERVFAIL
	// immediately rather than queued: a stub resolver that has already given up is not
	// helped by an answer arriving later, and the queue is what turns a slow resolver
	// into an unresponsive machine.
	maxInFlight = 256
	// maxStreamConns bounds concurrent TCP connections from local clients.
	maxStreamConns = 64
	// failuresBeforeUnhealthy is how many consecutive all-resolvers-failed exchanges it
	// takes to call the chosen profile unreachable. One failure is a packet; three in a
	// row is a network.
	failuresBeforeUnhealthy = 3
)

// Config is everything the forwarder answers with. It is replaced whole rather than
// edited, so a reconfigure is one atomic swap and a query in flight keeps the resolvers it
// started with.
type Config struct {
	// Rules decide where a query goes.
	Rules Rules
	// Profile holds the resolvers the user chose. Empty means every query that would
	// have gone there is answered SERVFAIL, which is the honest report of a switch that
	// is on with nothing behind it.
	Profile *Pool
	// Local holds the resolvers this network published.
	Local *Pool
	// Tunnels resolves a name inside one of app-tail's own connections. It is only ever
	// asked about a connection the rules say this machine reaches by address, so nil here
	// is a machine that reaches none of them: every name on a connection is then answered
	// with "no such name" by routing alone, and this is never called.
	Tunnels TunnelResolver
	// RetryOnNXDOMAIN sends a name the profile says does not exist to the network's
	// resolvers as well. It is off by default because a filtering resolver blocks a
	// domain by answering that it does not exist, so retrying elsewhere unblocks it.
	RetryOnNXDOMAIN bool
	// Logf receives one line per query that could not be answered. Nil discards.
	Logf func(format string, args ...any)
	// OnProfileHealth is called when the chosen profile stops answering entirely, and
	// again when it starts answering. It is the seam a captive-portal prompt hangs off:
	// unreachable-then-reachable is exactly the shape of walking into a hotel network.
	OnProfileHealth func(healthy bool, err error)
	// OnQuestion is called with every name asked about, once the query has parsed and
	// before anything is decided about it. It is a seam for traffic inspection, which
	// reads a run of questions rather than any one of them, so it is called for every
	// query including the ones answered from here.
	//
	// It is called on the goroutine answering the query. Nil discards, and an
	// implementation that blocks blocks that one answer.
	OnQuestion func(name string)
}

// TunnelResolver answers a name inside one of app-tail's own connections with the addresses
// this machine reaches the result at.
//
// The translation is the whole reason this is not just a resolver: a network moved out of
// another's way answers with its own addresses, and handing those to a program on this
// machine would send it to whichever network really holds them.
type TunnelResolver interface {
	// LookupTunnel resolves host inside the connection, and returns the addresses this
	// machine reaches it at. An answer with no addresses and no error is a name that
	// connection does not serve.
	LookupTunnel(ctx context.Context, tunnelID, host string) ([]netip.Addr, error)
}

// Stats are the counters the dashboard shows. They are cumulative since the forwarder
// started and are never reset, so a rate is a difference between two reads.
type Stats struct {
	Queries      uint64 `json:"queries"`
	ToProfile    uint64 `json:"toProfile"`
	ToLocal      uint64 `json:"toLocal"`
	AnsweredHere uint64 `json:"answeredHere"`
	// Blocked is how many of those answers were a name refused because it is on a list.
	// It is a subset of AnsweredHere rather than a category beside it: a blocked name is
	// answered here, and counting it twice would make the four stop summing to Queries.
	Blocked  uint64 `json:"blocked"`
	Failures uint64 `json:"failures"`
}

// Forwarder answers DNS on the sockets it is given.
type Forwarder struct {
	state atomic.Pointer[Config]

	queries      atomic.Uint64
	toProfile    atomic.Uint64
	toLocal      atomic.Uint64
	answeredHere atomic.Uint64
	blocked      atomic.Uint64
	failures     atomic.Uint64

	// consecutive counts all-resolvers-failed exchanges against the profile in a row,
	// and healthy is the state OnProfileHealth was last told about.
	healthMu    sync.Mutex
	consecutive int
	unhealthy   bool
}

// New builds a forwarder. It starts nothing: serving begins when a socket is handed to
// ServePacket or ServeStream.
func New(cfg Config) *Forwarder {
	f := &Forwarder{}
	f.state.Store(&cfg)
	return f
}

// Configure replaces the running configuration.
//
// Pools that are no longer referenced are closed after a grace period, so a query already
// on its way to the old resolver still gets its answer rather than a closed connection.
func (f *Forwarder) Configure(cfg Config) {
	old := f.state.Swap(&cfg)
	if old == nil {
		return
	}
	var retired []*Pool
	if old.Profile != nil && old.Profile != cfg.Profile {
		retired = append(retired, old.Profile)
	}
	if old.Local != nil && old.Local != cfg.Local {
		retired = append(retired, old.Local)
	}
	if len(retired) == 0 {
		return
	}
	// The retirement happens on a timer, so there is no caller left to return to and the
	// log is the only place a resolver that would not release its socket can be said out
	// loud. A silent one here is a descriptor leaked once per reconfigure.
	logf := cfg.Logf
	time.AfterFunc(queryTimeout, func() {
		for _, p := range retired {
			if err := p.Close(); err != nil && logf != nil {
				logf("releasing a replaced resolver failed: %v", err)
			}
		}
	})
}

// Config reports the running configuration.
func (f *Forwarder) Config() Config { return *f.state.Load() }

// Stats reports the counters.
func (f *Forwarder) Stats() Stats {
	return Stats{
		Queries:      f.queries.Load(),
		ToProfile:    f.toProfile.Load(),
		ToLocal:      f.toLocal.Load(),
		AnsweredHere: f.answeredHere.Load(),
		Blocked:      f.blocked.Load(),
		Failures:     f.failures.Load(),
	}
}

// Close releases the resolvers the forwarder holds. The sockets belong to whoever handed
// them in and are not closed here.
func (f *Forwarder) Close() error {
	cfg := f.state.Load()
	var firstErr error
	if err := cfg.Profile.Close(); err != nil {
		firstErr = err
	}
	if err := cfg.Local.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Answer resolves one query and returns the reply to send back.
//
// It always returns a reply, except for bytes too short to carry a transaction id -- there
// is no way to address a reply to those. Every other failure is a response code, because
// silence from a resolver reads to the machine asking as a resolver that is gone, and a
// machine with no resolver stops doing anything at all.
//
// stream says the query arrived over TCP, which means the answer has no size limit and a
// truncated upstream answer can be passed straight through.
func (f *Forwarder) Answer(ctx context.Context, query []byte, stream bool) []byte {
	f.queries.Add(1)
	cfg := f.state.Load()

	q, err := parseQuestion(query)
	if err != nil {
		id, ok := queryID(query)
		if !ok {
			f.failures.Add(1)
			return nil
		}
		f.answeredHere.Add(1)
		return headerOnly(dnsmessage.Header{ID: id, Response: true, RCode: dnsmessage.RCodeFormatError})
	}

	if cfg.OnQuestion != nil {
		cfg.OnQuestion(q.Name)
	}

	resp := f.resolve(ctx, cfg, q, query, stream)
	if !stream {
		if limit := udpPayloadSize(query); len(resp) > limit {
			// Too big for the client's buffer. The truncated reply is the protocol's way
			// of saying "ask again over TCP", which every stub resolver then does.
			return truncatedResponse(q)
		}
	}
	return resp
}

func (f *Forwarder) resolve(ctx context.Context, cfg *Config, q Question, query []byte, stream bool) []byte {
	decision := Route(q, cfg.Rules)
	switch decision.Target {
	case Here:
		f.answeredHere.Add(1)
		if decision.RCode == dnsmessage.RCodeNameError {
			// Routing decided the name does not exist. The other codes routing answers
			// here with are protocol errors about the query, which nothing caches.
			return localNegative(q, decision.RCode)
		}
		return response(q, decision.RCode)
	case Localhost:
		f.answeredHere.Add(1)
		return localhostAnswer(q)
	case ToTunnel:
		f.answeredHere.Add(1)
		return f.answerFromTunnel(ctx, cfg, q, decision)
	case Blocked:
		f.answeredHere.Add(1)
		f.blocked.Add(1)
		return blockedAnswer(q, cfg.Rules.BlockAnswer)
	}

	// The client's own EDNS options travel on -- the DNS-over-TLS flag, the payload size,
	// everything but the one that says which network the user is on.
	outbound := stripClientSubnet(query)

	pool, toProfile := cfg.Local, false
	if decision.Target == ToProfile {
		pool, toProfile = cfg.Profile, true
		f.toProfile.Add(1)
	} else {
		f.toLocal.Add(1)
	}

	resp, err := f.exchange(ctx, pool, outbound, stream)
	if toProfile {
		f.noteProfileHealth(cfg, err)
	}
	if err != nil {
		f.failures.Add(1)
		f.logf(cfg, "dns: %s (%s) went unanswered: %v", q, decision.Reason, err)
		// SERVFAIL and not NXDOMAIN: NXDOMAIN is an answer, and the machine would cache
		// it. This says the resolver failed, which is what happened.
		return response(q, dnsmessage.RCodeServerFailure)
	}

	if toProfile && cfg.RetryOnNXDOMAIN && isNXDomain(resp) {
		if second, err := f.exchange(ctx, cfg.Local, outbound, stream); err == nil && !isNXDomain(second) {
			f.toLocal.Add(1)
			return second
		}
	}
	return resp
}

// answerFromTunnel resolves a name inside one of app-tail's own connections and answers
// with the addresses this machine reaches the result at.
//
// The answer is built here rather than passed through, because the addresses in it are not
// the ones the connection's own resolver gave: a network moved out of another's way is
// reached somewhere else on this machine, and everything else in the upstream's reply --
// the records for other names it helpfully included, the ones of types this cannot
// translate -- would still carry the untranslated addresses.
func (f *Forwarder) answerFromTunnel(ctx context.Context, cfg *Config, q Question, decision Decision) []byte {
	if cfg.Tunnels == nil {
		// Routing said this machine reaches the connection by address and nothing here can
		// ask it. That is two halves of one feature disagreeing, not a fact about the name,
		// so it is a failure and not "no such name".
		f.failures.Add(1)
		f.logf(cfg, "dns: %s (%s) cannot be answered: nothing here resolves names inside a connection", q, decision.Reason)
		return response(q, dnsmessage.RCodeServerFailure)
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	addrs, err := cfg.Tunnels.LookupTunnel(ctx, decision.Tunnel, decision.Host)
	if err != nil {
		f.failures.Add(1)
		f.logf(cfg, "dns: %s (%s) went unanswered: %v", q, decision.Reason, err)
		return response(q, dnsmessage.RCodeServerFailure)
	}
	if len(addrs) == 0 {
		// The connection's own resolver does not serve the name. It is the only resolver
		// that could, so this is the whole answer.
		return localNegative(q, dnsmessage.RCodeNameError)
	}

	// Any other type is NOERROR with no records: the name exists on that network and this
	// answers for addresses only, which is the true answer and is not NXDOMAIN. A name whose
	// only records are of another type is indistinguishable from one that does not exist,
	// since what was asked inside the connection was for its addresses.
	var records []dnsmessage.Resource
	for _, addr := range addrs {
		switch {
		case q.Type == dnsmessage.TypeA && addr.Is4():
		case q.Type == dnsmessage.TypeAAAA && addr.Is6() && !addr.Is4In6():
		default:
			continue
		}
		records = append(records, addressRecord(q, addr))
	}
	if len(records) == 0 {
		return localNegative(q, dnsmessage.RCodeSuccess)
	}
	return buildResponse(q, dnsmessage.RCodeSuccess, false, records, nil)
}

// exchange asks a pool, retrying over TCP when the answer came back truncated.
func (f *Forwarder) exchange(ctx context.Context, pool *Pool, query []byte, stream bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	resp, err := pool.Exchange(ctx, query, stream)
	if err != nil || stream || !truncated(resp) {
		return resp, err
	}
	// The resolver had more to say than fits in a datagram. Asking again over a stream
	// costs one round trip and is the difference between an answer and a retry loop.
	if full, retryErr := pool.Exchange(ctx, query, true); retryErr == nil {
		return full, nil
	}
	return resp, nil
}

// noteProfileHealth tracks whether the chosen resolvers are answering at all, and reports
// each change of that answer exactly once.
func (f *Forwarder) noteProfileHealth(cfg *Config, err error) {
	f.healthMu.Lock()
	changed, healthy := false, true
	if err != nil {
		f.consecutive++
		if !f.unhealthy && f.consecutive >= failuresBeforeUnhealthy {
			f.unhealthy = true
			changed, healthy = true, false
		}
	} else {
		f.consecutive = 0
		if f.unhealthy {
			f.unhealthy = false
			changed = true
		}
	}
	f.healthMu.Unlock()

	if changed && cfg.OnProfileHealth != nil {
		cfg.OnProfileHealth(healthy, err)
	}
}

func isNXDomain(msg []byte) bool {
	code, ok := rcode(msg)
	return ok && code == dnsmessage.RCodeNameError
}

func (f *Forwarder) logf(cfg *Config, format string, args ...any) {
	if cfg.Logf != nil {
		cfg.Logf(format, args...)
	}
}

// answerSafely is the panic barrier.
//
// A forwarder that panics takes the machine's name resolution with it, and the helper
// holding the override cannot tell the difference between a crashed forwarder and a busy
// one. A panic here becomes SERVFAIL and a log line, and the next query is unaffected.
func (f *Forwarder) answerSafely(ctx context.Context, query []byte, stream bool) (resp []byte) {
	cfg := f.state.Load()
	defer func() {
		if r := recover(); r != nil {
			f.failures.Add(1)
			f.logf(cfg, "dns: panic while answering a query: %v", r)
			if q, err := parseQuestion(query); err == nil {
				resp = response(q, dnsmessage.RCodeServerFailure)
				return
			}
			if id, ok := queryID(query); ok {
				resp = headerOnly(dnsmessage.Header{ID: id, Response: true, RCode: dnsmessage.RCodeServerFailure})
			}
		}
	}()
	return f.Answer(ctx, query, stream)
}

// ServePacket answers queries on a datagram socket until the context ends or the socket
// fails. The socket is closed on return, because a listener nobody is reading is a
// machine whose queries vanish.
func (f *Forwarder) ServePacket(ctx context.Context, pc net.PacketConn) error {
	defer pc.Close()
	stop := context.AfterFunc(ctx, func() { pc.Close() })
	defer stop()

	sem := make(chan struct{}, maxInFlight)
	buf := make([]byte, maxUDPAnswer)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read a DNS query: %w", err)
		}
		if n < 12 || !fromLoopback(from) {
			// Only this machine may ask. The socket is bound to loopback, so a packet
			// from anywhere else is either a spoof or a routing mistake.
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])

		select {
		case sem <- struct{}{}:
		default:
			// Saturated. Answering now beats queueing behind resolvers that are already
			// too slow to be useful.
			f.failures.Add(1)
			q, perr := parseQuestion(query)
			if perr != nil {
				continue
			}
			f.logf(f.state.Load(), "dns: %d queries already in flight, answering %s with SERVFAIL", maxInFlight, q)
			if _, err := pc.WriteTo(response(q, dnsmessage.RCodeServerFailure), from); err != nil && ctx.Err() == nil {
				f.logf(f.state.Load(), "dns: could not answer %s: %v", from, err)
			}
			continue
		}
		go func() {
			defer func() { <-sem }()
			resp := f.answerSafely(ctx, query, false)
			if len(resp) == 0 {
				return
			}
			if _, err := pc.WriteTo(resp, from); err != nil && ctx.Err() == nil {
				f.logf(f.state.Load(), "dns: could not answer %s: %v", from, err)
			}
		}()
	}
}

// ServeStream answers queries on a stream listener until the context ends or the listener
// fails.
func (f *Forwarder) ServeStream(ctx context.Context, ln net.Listener) error {
	defer ln.Close()
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()

	conns := make(chan struct{}, maxStreamConns)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept a DNS connection: %w", err)
		}
		if !fromLoopback(conn.RemoteAddr()) {
			conn.Close()
			continue
		}
		select {
		case conns <- struct{}{}:
		default:
			// At the connection limit. Closing is the signal a stub resolver
			// understands, and it will come back over UDP.
			conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-conns }()
			f.serveConn(ctx, conn)
		}()
	}
}

// serveConn answers every query on one connection. A stub resolver sends several down the
// same connection, so this reads until the peer stops or goes quiet.
func (f *Forwarder) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	for {
		if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return
		}
		query, err := readFramed(conn)
		if err != nil {
			return
		}
		resp := f.answerSafely(ctx, query, true)
		if len(resp) == 0 {
			continue
		}
		if err := writeFramed(conn, resp); err != nil {
			return
		}
	}
}

// fromLoopback reports whether an address is this machine talking to itself.
func fromLoopback(addr net.Addr) bool {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.IsLoopback()
	case *net.TCPAddr:
		return a.IP.IsLoopback()
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return false
	}
	return ap.Addr().IsLoopback()
}
