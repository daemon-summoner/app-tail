// SPDX-License-Identifier: MIT

package forward

import (
	"bytes"
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/netpipe"
	"github.com/sellitus/app-tail/internal/udpsock"
)

// defaultJanitorInterval is how often idle UDP sessions are swept. Without this
// sweep the session table leaks one upstream socket per unique client forever.
const defaultJanitorInterval = 15 * time.Second

// maxUDPSessions bounds how many clients one forward tracks at once.
//
// The sweep above bounds the table in time and nothing bounds it in size, which is
// not the same guarantee: a session is created the first time a source address is
// seen, and UDP has no handshake, so a source address costs nothing to invent and
// need not be reachable. One datagram per made-up source is one dialed socket, one
// goroutine and one buffer, arriving as fast as the sender cares to send -- and the
// sweep cannot help, because it evicts on idleness measured from now while the flood
// is still arriving. What runs out is file descriptors, and it runs out for the whole
// process rather than for this forward.
//
// The cap is a descriptor budget rather than a tuned figure: several forwards may run
// at once and each needs room for the clients it really has, which for a forward on
// loopback is one per port a local program is using.
const maxUDPSessions = 2048

// udpDialTimeout bounds how long a new client's first datagram waits for the upstream
// socket. It is shorter than the TCP dial it used to share, because there is no
// handshake here to be slow -- what is being waited on is a socket and, on the tailnet
// side, a path to the peer. The wait is the new client's alone: its datagrams are held
// while it lasts, and every other client's keep moving.
const udpDialTimeout = 5 * time.Second

// maxUDPDials bounds how many new clients one forward is setting up at once.
//
// Each is a dial in flight on its own goroutine, started by a single datagram from a source
// address nobody has verified. maxUDPSessions bounds the clients that got through; this
// bounds the ones that have not yet, which a target that is slow to reach or not there at
// all would otherwise let pile up for a whole udpDialTimeout each.
const maxUDPDials = 64

// maxHeldBytes bounds what is kept for one client while its session is being set up. It is
// one datagram of the largest size there is: room for the handful a client sends before it
// hears back, and no more than that for a client that never will.
const maxHeldBytes = 64 << 10

// session is one client's UDP conversation: the socket carrying its datagrams
// upstream and the last time traffic was seen in either direction.
type session struct {
	key      string
	upstream net.Conn
	client   net.Addr
	lastSeen atomic.Int64 // unix nanos
	// seen is the session's place in the order traffic was seen across every session:
	// the clock's reading is what an idle timeout is measured against, and the order is
	// what decides which session goes when the table is full. Two readings of a coarse
	// clock tie; two places in the order never do.
	seen atomic.Uint64

	// place is the session's seat in the forward's eviction order and placed is the reading
	// of seen it was seated by. Both belong to udpForward.mu.
	place  *list.Element
	placed uint64

	// watch reads what the client sends, and is nil when nothing is reading. A datagram is
	// offered from whichever goroutine is carrying it while the janitor may be closing the
	// session, so the two are kept apart.
	watchMu sync.Mutex
	watch   netpipe.Stream
	shut    bool

	closeOnce sync.Once
}

// held is what one client has sent while its session is being set up.
type held struct {
	queue [][]byte
	bytes int
}

// activity numbers every moment traffic is seen on any session, in order.
var activity atomic.Uint64

func (s *session) touch() {
	s.lastSeen.Store(time.Now().UnixNano())
	s.seen.Store(activity.Add(1))
}

func (s *session) idleFor(now time.Time) time.Duration {
	return now.Sub(time.Unix(0, s.lastSeen.Load()))
}

// stops offers one datagram from the client to whatever is reading the flow, and reports
// whether it must not be carried.
func (s *session) stops(datagram []byte) bool {
	s.watchMu.Lock()
	defer s.watchMu.Unlock()
	if s.watch == nil || s.shut {
		return false
	}
	return s.watch.Up(datagram)
}

// close is safe to call from both the janitor and shutdown.
func (s *session) close() {
	s.closeOnce.Do(func() {
		s.upstream.Close()
		s.watchMu.Lock()
		defer s.watchMu.Unlock()
		s.shut = true
		if s.watch != nil {
			s.watch.Close()
		}
	})
}

// udpForward holds the live state of one UDP forward.
type udpForward struct {
	mgr   *Manager
	entry *entry
	// fwd is a copy taken at start: the manager may rewrite the registry entry
	// while this forward runs, and a live socket must keep serving what it was
	// started with.
	fwd     config.Forward
	local   net.PacketConn
	timeout time.Duration
	bufSize int
	// maxSessions is maxUDPSessions, held here so a test can reach the ceiling without
	// opening two thousand sockets to do it.
	maxSessions int

	mu       sync.Mutex
	sessions map[string]*session
	// order seats every session by the traffic it had carried when it was seated, least
	// recent at the front. It is brought up to date only when the table is full, so a
	// datagram costs a session nothing here.
	order list.List
	// opening holds, per client, what has arrived while that client's session is dialed.
	opening map[string]*held
	// openers counts the dials in flight, which the read loop waits out before it drains
	// the table: a session one of them added afterwards would never be closed.
	openers sync.WaitGroup
}

// listenLocalUDP binds this machine's own socket for a forward, in the one state a read loop
// on it is safe: a listening socket serves every client, so one client that goes away must
// not be able to end it.
//
// The tailnet side has no such call because it is served inside this process rather than by
// the operating system, and carries no host's refusal back to this one.
func listenLocalUDP(f config.Forward) (net.PacketConn, error) {
	addr := net.JoinHostPort(bindHost(f), strconv.Itoa(f.ListenPort))
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	if err := udpsock.SilenceUnreachable(pc); err != nil {
		return nil, errors.Join(err, pc.Close())
	}
	return pc, nil
}

// startUDP binds the listening socket for a UDP forward and starts its read loop
// and idle janitor. The returned Closer unblocks the read loop on stop.
func (m *Manager) startUDP(ctx context.Context, e *entry, wg *sync.WaitGroup) (io.Closer, error) {
	f := e.fwd
	var (
		pc  net.PacketConn
		err error
	)
	switch f.Direction {
	case config.ToLocal:
		pc, err = listenLocalUDP(f)
	case config.ToTailnet:
		pc, err = e.net.ListenPacket("udp", uint16(f.ListenPort))
	default:
		err = fmt.Errorf("unsupported direction %q", f.Direction)
	}
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", config.Endpoint(f), err)
	}

	uf := &udpForward{
		mgr:         m,
		entry:       e,
		fwd:         f,
		local:       pc,
		timeout:     m.udpTimeout(f),
		bufSize:     m.bufferSize(),
		maxSessions: maxUDPSessions,
		sessions:    make(map[string]*session),
	}

	e.counters.setRunning(pc.LocalAddr().String())
	m.logger.Info("forward started",
		"id", f.ID, "name", f.Name, "protocol", "udp",
		"direction", f.Direction, "listening", pc.LocalAddr().String(), "target", f.Target)

	wg.Add(2)
	go func() {
		defer wg.Done()
		uf.readLoop(ctx)
	}()
	go func() {
		defer wg.Done()
		uf.janitor(ctx)
	}()
	// Closing the socket unblocks ReadFrom; sessions are drained after the loop exits.
	return closerFunc(func() error { return pc.Close() }), nil
}

// readLoop reads datagrams from the listening socket and routes each to its
// client's session, starting one on first sight.
func (u *udpForward) readLoop(ctx context.Context) {
	opening, stopOpening := context.WithCancel(ctx)
	// Sessions outlive individual datagrams but not the forward.
	defer u.closeAllSessions()
	defer u.openers.Wait()
	defer stopOpening()

	buf := make([]byte, u.bufSize)
	for {
		n, client, err := u.local.ReadFrom(buf)
		if datagramTooLarge(err) {
			u.mgr.logger.Warn("udp forward dropped a datagram larger than its buffer",
				"id", u.fwd.ID, "name", u.fwd.Name, "bufferBytes", u.bufSize)
			u.entry.counters.noteError(fmt.Errorf(
				"a datagram larger than the %d-byte buffer was dropped", u.bufSize))
			continue
		}
		if err != nil {
			if ctx.Err() == nil {
				u.mgr.logger.Error("udp forward stopped reading",
					"id", u.fwd.ID, "name", u.fwd.Name, "error", err)
				u.entry.counters.setError(fmt.Errorf("read: %w", err))
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		u.route(opening, client, buf[:n])
	}
}

// route hands one datagram to its client's session. A client seen for the first time has
// its session dialed on a goroutine of its own, and what it sends meanwhile is held for it:
// this is the one loop every client's traffic passes through, and a target that is slow to
// reach must not stop it.
func (u *udpForward) route(ctx context.Context, client net.Addr, datagram []byte) {
	key := client.String()

	u.mu.Lock()
	if waiting, ok := u.opening[key]; ok {
		fits := waiting.bytes+len(datagram) <= maxHeldBytes
		if fits {
			waiting.queue = append(waiting.queue, bytes.Clone(datagram))
			waiting.bytes += len(datagram)
		}
		u.mu.Unlock()
		if !fits {
			u.mgr.logger.Warn("udp forward dropped a datagram from a client still being set up",
				"id", u.fwd.ID, "client", key, "heldBytes", maxHeldBytes)
			u.entry.counters.noteError(fmt.Errorf(
				"a datagram from %s was dropped: %d bytes were already waiting for its session to open",
				key, maxHeldBytes))
		}
		return
	}
	if s, ok := u.sessions[key]; ok {
		u.mu.Unlock()
		u.send(s, datagram)
		return
	}
	if len(u.opening) >= maxUDPDials {
		u.mu.Unlock()
		u.mgr.logger.Warn("udp forward turned a new client away",
			"id", u.fwd.ID, "client", key, "beingSetUp", maxUDPDials)
		u.entry.counters.noteError(fmt.Errorf(
			"%d clients are already being set up, so a new one (%s) was turned away",
			maxUDPDials, key))
		return
	}
	waiting := &held{queue: [][]byte{bytes.Clone(datagram)}, bytes: len(datagram)}
	if u.opening == nil {
		u.opening = make(map[string]*held)
	}
	u.opening[key] = waiting
	u.openers.Add(1)
	u.mu.Unlock()

	go u.open(ctx, client, waiting)
}

// open dials one new client's session and then sends what the client sent while it waited,
// in the order it arrived.
//
// The client stays in u.opening until nothing is left waiting, and is taken out under the
// same lock route queues under. Its datagrams are therefore sent from here or from the read
// loop and never from both, which is what keeps them in order.
func (u *udpForward) open(ctx context.Context, client net.Addr, waiting *held) {
	defer u.openers.Done()
	key := client.String()
	settle := func() {
		u.mu.Lock()
		delete(u.opening, key)
		u.mu.Unlock()
	}

	s, isNew, err := u.sessionFor(ctx, client)
	if err != nil {
		settle()
		if ctx.Err() != nil {
			return
		}
		// A dial failure (usually an ACL denial) must not create a broken
		// session; drop what was held and surface why.
		u.mgr.logger.Warn("udp forward could not reach its target",
			"id", u.fwd.ID, "target", u.fwd.Target, "error", err)
		u.entry.counters.noteError(dialFailure(u.fwd.Target, err))
		return
	}
	if isNew {
		// A fresh session means the dial got through, clearing any prior error.
		u.entry.counters.noteSuccess()
	}

	for {
		u.mu.Lock()
		queue := waiting.queue
		waiting.queue, waiting.bytes = nil, 0
		if len(queue) == 0 {
			delete(u.opening, key)
			u.mu.Unlock()
			return
		}
		u.mu.Unlock()

		for _, datagram := range queue {
			if !u.send(s, datagram) {
				settle()
				return
			}
		}
	}
}

// send carries one datagram from a client to the target, and reports whether the session
// is still there to carry the next.
func (u *udpForward) send(s *session, datagram []byte) bool {
	if s.stops(datagram) {
		// Whatever read the datagram has already reported what it found.
		u.mgr.logger.Debug("udp forward stopped a client on what it sent",
			"id", u.fwd.ID, "client", s.key)
		u.removeSession(s.key, s)
		return false
	}
	written, err := s.upstream.Write(datagram)
	if err != nil {
		u.mgr.logger.Debug("udp upstream write failed", "id", u.fwd.ID, "error", err)
		u.entry.counters.noteError(fmt.Errorf("write to %s: %w", u.fwd.Target, err))
		u.removeSession(s.key, s)
		return false
	}
	u.entry.counters.bytesUp.Add(int64(written))
	s.touch()
	return true
}

// sessionFor returns the session for a client address, dialing a dedicated
// upstream socket the first time that client is seen so replies come back to it.
// The bool reports whether this call created the session, which is the moment a
// successful dial is known.
func (u *udpForward) sessionFor(ctx context.Context, client net.Addr) (*session, bool, error) {
	key := client.String()

	u.mu.Lock()
	if s, ok := u.sessions[key]; ok {
		u.mu.Unlock()
		return s, false, nil
	}
	u.mu.Unlock()

	upstream, err := u.dialUpstream(ctx)
	if err != nil {
		return nil, false, err
	}

	s := &session{key: key, upstream: upstream, client: client, watch: u.mgr.watchesDatagrams(u.fwd)}

	u.mu.Lock()
	// Another datagram from the same client may have won the race.
	if existing, ok := u.sessions[key]; ok {
		u.mu.Unlock()
		s.close()
		return existing, false, nil
	}
	// Enforced here rather than before the dial, because here is where the table
	// actually grows and the lock is already held: checking earlier would let several
	// dials in flight at once push it past the cap between the check and the insert.
	evicted := u.makeRoomLocked()
	s.touch()
	u.sessions[key] = s
	s.placed = s.seen.Load()
	s.place = u.order.PushBack(s)
	u.entry.counters.activeUDP.Store(int32(len(u.sessions)))
	u.mu.Unlock()

	if evicted != nil {
		evicted.close()
		u.entry.counters.noteError(fmt.Errorf(
			"tracking %d clients at once, so the one idle longest (%s) was dropped to make room",
			u.maxSessions, evicted.client))
	}

	go u.pumpDownstream(ctx, s)
	return s, true, nil
}

// makeRoomLocked drops the session idle longest when the table is full, returning it so
// the caller can close its socket outside the lock. Nothing is dropped while there is
// room. The caller must hold u.mu.
//
// Idle-longest rather than oldest or random, because that is the choice a flood cannot
// use against a real client: a client still sending is touched by every datagram, so it
// is never the one idle longest, while a made-up source that sent once and will never
// send again is exactly that. The made-up sources therefore evict each other. Idleness is
// ranked by the order traffic was seen rather than by the clock: a flood fills the table
// within one tick of a coarse clock, and on the clock's reading the real client would tie
// with the made-up ones and go by chance.
//
// The order is kept as a list that is corrected only here. The session at the front was the
// least recent when it was seated; if it has carried traffic since, it is seated again by
// what it has carried now and the next one is looked at. A session that sent once and never
// again is found at the front untouched, so a flood pays for one session per eviction where
// ranking the whole table would pay for all of them.
func (u *udpForward) makeRoomLocked() *session {
	if u.maxSessions <= 0 || len(u.sessions) < u.maxSessions {
		return nil
	}
	for front := u.order.Front(); front != nil; front = u.order.Front() {
		s := front.Value.(*session)
		if u.sessions[s.key] != s {
			u.unseatLocked(s)
			continue
		}
		if seen := s.seen.Load(); seen != s.placed {
			s.placed = seen
			u.reseatLocked(s)
			continue
		}
		u.forgetLocked(s)
		return s
	}
	return nil
}

// reseatLocked moves a session back to where its placed reading belongs. The caller must
// hold u.mu.
func (u *udpForward) reseatLocked(s *session) {
	for at := u.order.Back(); at != nil && at != s.place; at = at.Prev() {
		if at.Value.(*session).placed <= s.placed {
			u.order.MoveAfter(s.place, at)
			return
		}
	}
}

// unseatLocked takes a session out of the eviction order. The caller must hold u.mu.
func (u *udpForward) unseatLocked(s *session) {
	if s.place != nil {
		u.order.Remove(s.place)
		s.place = nil
	}
}

// forgetLocked takes a session out of the table and the eviction order, leaving its socket
// for the caller to close outside the lock. The caller must hold u.mu.
func (u *udpForward) forgetLocked(s *session) {
	delete(u.sessions, s.key)
	u.unseatLocked(s)
}

// dialUpstream opens the socket carrying one client's datagrams to the target.
func (u *udpForward) dialUpstream(ctx context.Context) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, udpDialTimeout)
	defer cancel()
	if u.fwd.Direction == config.ToLocal {
		return u.entry.net.Dial(dialCtx, "udp", u.fwd.Target)
	}
	return u.mgr.localDialer().DialContext(dialCtx, "udp", u.fwd.Target)
}

// pumpDownstream carries replies from the target back to the client that owns
// this session. It exits when the session's socket closes.
func (u *udpForward) pumpDownstream(ctx context.Context, s *session) {
	buf := make([]byte, u.bufSize)
	for {
		n, err := s.upstream.Read(buf)
		if datagramTooLarge(err) {
			u.mgr.logger.Warn("udp forward dropped a reply larger than its buffer",
				"id", u.fwd.ID, "client", s.client.String(), "bufferBytes", u.bufSize)
			u.entry.counters.noteError(fmt.Errorf(
				"a reply larger than the %d-byte buffer was dropped", u.bufSize))
			continue
		}
		if err != nil {
			// Expected whenever the janitor evicts the session or the forward stops.
			u.removeSession(s.client.String(), s)
			return
		}
		if ctx.Err() != nil {
			return
		}
		written, err := u.local.WriteTo(buf[:n], s.client)
		if err != nil {
			u.mgr.logger.Debug("udp reply could not be delivered",
				"id", u.fwd.ID, "client", s.client.String(), "error", err)
			u.entry.counters.noteError(fmt.Errorf("reply to %s: %w", s.client, err))
			u.removeSession(s.client.String(), s)
			return
		}
		u.entry.counters.bytesDown.Add(int64(written))
		s.touch()
	}
}

// janitor evicts sessions that have been idle past the timeout. UDP has no close,
// so this sweep is the only thing that bounds the table.
func (u *udpForward) janitor(ctx context.Context) {
	interval := u.mgr.janitorInterval
	if interval <= 0 {
		interval = defaultJanitorInterval
	}
	// Sweeping faster than the timeout keeps eviction responsive without busy work.
	if interval > u.timeout {
		interval = u.timeout
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			u.evictIdle(now)
		}
	}
}

// evictIdle closes and removes every session idle past the timeout.
func (u *udpForward) evictIdle(now time.Time) {
	var stale []*session

	u.mu.Lock()
	for _, s := range u.sessions {
		if s.idleFor(now) >= u.timeout {
			u.forgetLocked(s)
			stale = append(stale, s)
		}
	}
	u.entry.counters.activeUDP.Store(int32(len(u.sessions)))
	u.mu.Unlock()

	for _, s := range stale {
		s.close()
	}
}

// removeSession drops one session from the table and closes its socket.
//
// The session is named as well as its key, and only that session is removed. A client
// evicted while it is still sending gets a second session under the same key, and the
// first one's downstream pump wakes on the socket the eviction closed and comes here to
// clean up -- by which time the key belongs to the replacement. Keyed removal alone
// would close the live session on the client's behalf, and the client would see its
// traffic stop for no reason it could act on.
func (u *udpForward) removeSession(key string, s *session) {
	u.mu.Lock()
	if u.sessions[key] == s {
		delete(u.sessions, key)
		u.entry.counters.activeUDP.Store(int32(len(u.sessions)))
	}
	u.unseatLocked(s)
	u.mu.Unlock()

	// Closed either way: this session is finished with its socket whether or not the
	// table still points at it, and the one case where it does not is the one where
	// something else already took the key.
	s.close()
}

// closeAllSessions drains the table when the forward stops.
func (u *udpForward) closeAllSessions() {
	u.mu.Lock()
	stale := make([]*session, 0, len(u.sessions))
	for _, s := range u.sessions {
		u.forgetLocked(s)
		stale = append(stale, s)
	}
	u.entry.counters.activeUDP.Store(0)
	u.mu.Unlock()

	for _, s := range stale {
		s.close()
	}
}

// closerFunc adapts a function to io.Closer.
type closerFunc func() error

func (f closerFunc) Close() error { return f() }
