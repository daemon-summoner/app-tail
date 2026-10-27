// SPDX-License-Identifier: MIT

// Carrying one OpenVPN connection's own packets inside another connection.
//
// This is the one kind of connection whose packets never enter this process: openvpn is a
// separate program holding administrator rights, and it reaches its server through a socket
// on this machine that nothing here can substitute. So a chained OpenVPN connection is not
// given a different socket -- it is pointed at one on this machine's loopback that this
// package owns, and everything it sends there is carried to its real server through the
// connection before it.
//
// That makes the loopback address the only thing about the connection that changes. openvpn
// still verifies the server's certificate against the name it was configured with, because
// the certificate is checked against what the connection says rather than against where the
// stream went; and nothing on the privileged side has to be told this connection is a hop,
// because a loopback address is strictly less than an address on the open internet.
//
// The listener carries exactly one address: this connection's own server, which is a public
// endpoint anything on this machine could already have dialled directly. What it does not
// carry is anywhere else, so it is not a proxy and cannot be used as one.

package ovpntunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/sellitus/app-tail/internal/netpipe"
)

// Carrier is a connection this one's own packets are sent through.
//
// It is the one method a chain needs, declared here rather than taken from the tunnel seam
// so this package keeps depending on nothing that depends on it.
type Carrier interface {
	// Dial opens a connection to an address reachable through the carrier. A chain uses it
	// for one stream to this connection's server per attempt openvpn makes.
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// hopDialTimeout bounds reaching this connection's server through the carrier. openvpn
// retries on its own schedule, so a carrier that is up but not moving anything must give the
// stream back rather than hold openvpn on a connect that will never finish.
const hopDialTimeout = 30 * time.Second

// hopForward is a listener on this machine's loopback that carries every stream it accepts
// to one fixed address through a carrier.
type hopForward struct {
	ln      net.Listener
	server  string
	through Carrier
	logger  *slog.Logger
	id      string

	// ctx ends every stream in flight when this forwarder is closed, which is what stops a
	// transfer that is otherwise idle in a read.
	ctx    context.Context
	cancel context.CancelFunc
	// wg is the streams still running, waited on by Close so a stopped connection leaves
	// nothing reading from a carrier that is being taken down behind it.
	wg sync.WaitGroup
}

// startHopForward opens the loopback listener and begins accepting.
//
// The context bounds the streams rather than the listener: it is the connection's own
// lifetime, and detaching from the caller's would leave a forwarder running after the call
// that built it returned.
func startHopForward(id, server string, through Carrier, logger *slog.Logger) (*hopForward, error) {
	if through == nil {
		return nil, errors.New("this connection is a hop of a chain with nothing carrying it")
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		return nil, fmt.Errorf("this connection's server %q is not a host and a port", server)
	}
	// Loopback only. A listener on any other address would be this machine offering a way
	// into the chain to whatever else is on the network.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("open the loopback listener this connection reaches its server through: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &hopForward{ln: ln, server: server, through: through, logger: logger, id: id, ctx: ctx, cancel: cancel}
	f.wg.Add(1)
	go f.accept()
	return f, nil
}

// addr is where openvpn is pointed, as a host and a port.
func (f *hopForward) addr() string { return f.ln.Addr().String() }

// accept takes each stream openvpn opens and carries it.
func (f *hopForward) accept() {
	defer f.wg.Done()
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			// A closed listener is this forwarder being taken down, which is not a failure.
			if !errors.Is(err, net.ErrClosed) {
				f.logger.Warn("this connection stopped accepting the streams it reaches its server through",
					"connection", f.id, "error", err)
			}
			return
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			f.carry(conn)
		}()
	}
}

// carry moves one stream to this connection's server through the carrier.
//
// A stream that cannot be carried is closed rather than answered: openvpn treats that as the
// server refusing it and tries again, which is the same thing it would do if the server were
// unreachable over this machine's own network -- and while this connection is a hop, it is.
func (f *hopForward) carry(client net.Conn) {
	dialCtx, cancel := context.WithTimeout(f.ctx, hopDialTimeout)
	upstream, err := f.through.Dial(dialCtx, "tcp", f.server)
	cancel()
	if err != nil {
		client.Close()
		f.logger.Debug("this connection could not reach its server through the connection carrying it",
			"connection", f.id, "server", f.server, "error", err)
		return
	}
	// Copy closes both ends, including on a cancelled context, so the stream is accounted
	// for whichever side finishes first.
	if err := netpipe.Copy(f.ctx, client, upstream, nil, nil); err != nil && f.ctx.Err() == nil {
		f.logger.Debug("the stream this connection reaches its server over ended",
			"connection", f.id, "server", f.server, "error", err)
	}
}

// Close stops accepting, ends every stream in flight, and waits for them.
func (f *hopForward) Close() error {
	err := f.ln.Close()
	f.cancel()
	f.wg.Wait()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("close the loopback listener this connection reached its server through: %w", err)
	}
	return nil
}
