// SPDX-License-Identifier: MIT

package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/netpipe"
)

const (
	// acceptRetryDelay throttles the accept loop after a transient accept error so
	// a persistently failing listener cannot spin the CPU.
	acceptRetryDelay = 50 * time.Millisecond

	// dialTimeout bounds how long one connection waits for its target. An
	// ACL-blocked target would otherwise hang until the client gives up.
	dialTimeout = 30 * time.Second

	// maxTCPConns bounds how many connections one forward proxies at once.
	//
	// The accept loop hands every connection to a goroutine holding two descriptors --
	// the accepted one and the dialed one -- for as long as the connection lives, and
	// a connection that says nothing lives until its peer gives up. Accepting is
	// cheap for whoever is connecting and not cheap here, so without a ceiling the
	// number of descriptors this forward holds is set by whoever is connecting to it.
	// Running out takes the whole process with it, not just this forward.
	//
	// Refusing at the cap rather than waiting for a slot: a connection held open in
	// the backlog looks accepted to the client and is indistinguishable to it from a
	// slow service, whereas a closed connection is an answer it can act on.
	maxTCPConns = 512
)

// startTCP binds the listener for a TCP forward and runs its accept loop.
// The returned Closer unblocks the loop when the forward is stopped.
func (m *Manager) startTCP(ctx context.Context, e *entry, wg *sync.WaitGroup) (io.Closer, error) {
	f := e.fwd
	var (
		ln  net.Listener
		err error
	)
	switch f.Direction {
	case config.ToLocal:
		// Listen on this machine, dial out over the tailnet.
		addr := net.JoinHostPort(bindHost(f), strconv.Itoa(f.ListenPort))
		ln, err = net.Listen("tcp", addr)
	case config.ToTailnet:
		// Listen on this node's tailnet identity, dial the local service.
		ln, err = e.net.Listen("tcp", uint16(f.ListenPort))
	default:
		err = fmt.Errorf("unsupported direction %q", f.Direction)
	}
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", config.Endpoint(f), err)
	}

	e.counters.setRunning(ln.Addr().String())
	m.logger.Info("forward started",
		"id", f.ID, "name", f.Name, "protocol", "tcp",
		"direction", f.Direction, "listening", ln.Addr().String(), "target", f.Target)

	// One slot per connection this forward may proxy at once. It belongs to the
	// listener rather than to the manager, so one busy forward cannot spend the
	// budget of another.
	slots := make(chan struct{}, maxTCPConns)

	wg.Add(1)
	go func() {
		defer wg.Done()
		m.acceptTCP(ctx, e, f, ln, wg, slots)
	}()
	return ln, nil
}

// acceptTCP accepts connections until the forward is stopped or the listener fails.
// It takes the forward by value: the manager may rewrite the registry entry while
// this loop runs, and a running listener must keep serving what it was started with.
func (m *Manager) acceptTCP(ctx context.Context, e *entry, f config.Forward, ln net.Listener, wg *sync.WaitGroup, slots chan struct{}) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return // deliberate stop
			}
			if isTemporary(err) {
				m.logger.Debug("transient accept error", "id", f.ID, "error", err)
				if !sleepCtx(ctx, acceptRetryDelay) {
					return
				}
				continue
			}
			m.logger.Error("forward listener failed", "id", f.ID, "name", f.Name, "error", err)
			e.counters.setError(fmt.Errorf("listener failed: %w", err))
			return
		}

		// Taken before the goroutine starts, so the ceiling is on connections held
		// rather than on goroutines that have got as far as running.
		select {
		case slots <- struct{}{}:
		default:
			// Recorded before the close, so a client that has already seen its
			// connection go away cannot ask why and be told nothing happened.
			m.logger.Warn("forward refused a connection at its limit",
				"id", f.ID, "name", f.Name, "limit", cap(slots))
			e.counters.noteError(fmt.Errorf(
				"already proxying %d connections, which is this forward's limit; the newest was refused", cap(slots)))
			conn.Close()
			continue
		}

		wg.Add(1)
		go func() {
			defer func() {
				<-slots
				wg.Done()
			}()
			m.handleTCP(ctx, e, f, conn)
		}()
	}
}

// handleTCP dials the other side for one accepted connection and proxies it.
func (m *Manager) handleTCP(ctx context.Context, e *entry, f config.Forward, client net.Conn) {
	upstream, err := m.dialTCPTarget(ctx, e.net, f)
	if err != nil {
		client.Close()
		if ctx.Err() != nil {
			return
		}
		// Most "won't connect" failures are ACLs on the target, not bugs here,
		// so the reason has to reach the UI.
		m.logger.Warn("forward could not reach its target",
			"id", f.ID, "name", f.Name, "target", f.Target, "error", err)
		e.counters.noteError(dialFailure(f.Target, err))
		return
	}
	// A connection got through, so a prior transient error no longer describes this
	// forward.
	e.counters.noteSuccess()
	m.proxyTCP(ctx, e, f, client, upstream)
}

// dialTCPTarget dials a forward's target on whichever stack its direction implies: the
// connection this forward crosses, or this machine's own.
func (m *Manager) dialTCPTarget(ctx context.Context, tn Tailnet, f config.Forward) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	if f.Direction == config.ToLocal {
		return tn.Dial(dialCtx, "tcp", f.Target)
	}
	return m.localDialer().DialContext(dialCtx, "tcp", f.Target)
}

// proxyTCP copies bytes in both directions until either side finishes or the
// forward is stopped, recording the transfer against this forward's counters.
func (m *Manager) proxyTCP(ctx context.Context, e *entry, f config.Forward, client, upstream net.Conn) {
	e.counters.activeTCP.Add(1)
	defer e.counters.activeTCP.Add(-1)

	opened, openedUpstream, err := m.opens(ctx, f, client, upstream)
	if err != nil {
		// Both ends are cut rather than closed. A connection that was going to be read and
		// could not be is being stopped on purpose, and a reset says that where a graceful
		// close would read to the program as the target hanging up.
		netpipe.Reset(client)
		netpipe.Reset(upstream)
		m.logger.Warn("a forwarded connection was stopped rather than carried unread",
			"id", f.ID, "name", f.Name, "target", f.Target, "error", err)
		return
	}
	client, upstream = opened, openedUpstream

	err = netpipe.CopyWith(ctx, client, upstream,
		func(n int64) { e.counters.bytesUp.Add(n) },
		func(n int64) { e.counters.bytesDown.Add(n) },
		m.watches(f))

	// Stopping the forward closes both sides underneath the copies, so their failure
	// there is the shutdown itself. A failure while the forward is still live is a
	// real transport fault, but it killed one connection rather than the forward, so
	// it is reported without marking the forward unhealthy.
	if err != nil && ctx.Err() == nil {
		m.logger.Debug("proxied connection ended early",
			"id", f.ID, "name", f.Name, "target", f.Target, "error", err)
	}
}

// bindHost returns the local address a to_local forward listens on, defaulting to
// loopback so a forward is never accidentally exposed to the LAN.
func bindHost(f config.Forward) string {
	if f.BindAddr == "" {
		return config.DefaultBindAddr
	}
	return f.BindAddr
}

// isTemporary reports whether an accept error is worth retrying.
func isTemporary(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}

// sleepCtx waits for d, reporting false if the context was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
