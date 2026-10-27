// SPDX-License-Identifier: MIT

package hostnet

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/dns"
	"tailscale.com/wgengine/router"

	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/sysdns"
)

// Client is the unprivileged side of the boundary: it asks a helper that holds root to
// do the four things this app needs, and does nothing itself.
//
// One connection carries the whole session, and that is the design rather than an
// implementation detail. The helper watches this connection: when it drops, for any
// reason including this process being killed, the helper removes the routes and the
// resolver configuration and closes the interface. A per-call connection would leave
// nothing for it to watch.
type Client struct {
	mu   sync.Mutex
	conn net.Conn
	// r holds bytes already taken off the socket, so it must be the same reader on
	// every call: a fresh one would drop whatever it had buffered past a newline.
	r      *bufio.Reader
	closed bool
	// grants hears how each change that can need an approval was answered; nil hears nothing.
	grants grants.Observer
}

var (
	_ Host           = (*Client)(nil)
	_ SystemResolver = (*Client)(nil)
	_ OpenVPNRunner  = (*Client)(nil)
)

// handshakeTimeout bounds connecting to the helper and finding out which build it is.
//
// The helper is a separately installed binary, so this is a call into a process whose
// behaviour this build does not decide: one left behind by an earlier release can accept a
// connection and never answer it. That has to become a failure the caller can report,
// because this runs on the agent's start path, where waiting for it wedges the process with
// nothing to show. Only the handshake is bounded -- the session that follows carries the
// deadlines its own callers set.
const handshakeTimeout = 10 * time.Second

// Dial connects to the helper and checks it is the one this build expects.
func Dial(ctx context.Context, opts Options) (*Client, error) {
	path := opts.SocketPath
	if path == "" {
		path = SocketPath()
	}
	if path == "" {
		return nil, ErrUnsupported
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			// A socket that is there and closed to this account is the one failure whose
			// answer is not "install a helper": there is one, and reporting it as missing
			// sends the user to a step they have already done.
			return nil, fmt.Errorf("%w: %s (%w)", ErrHelperNotOpenToThisAccount, path, err)
		}
		// Every remaining reason reads the same to a user -- no helper -- and the
		// answer to all of them is to install one, so the underlying error is carried
		// for a log rather than made the headline.
		return nil, fmt.Errorf("%w: %s (%w)", ErrNoHelper, path, err)
	}

	c := &Client{conn: conn, r: bufio.NewReader(conn), grants: opts.Grants}
	caps, err := c.Capabilities(ctx)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ask the helper what it can do: %w", err)
	}
	// Checked against this build's own identity, which the helper computes the same way.
	// A version a caller could state is a version a caller can state wrongly, and the two
	// sides then disagree about a machine that is correct.
	if err := expectedBuild(caps); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// Capabilities reports what the helper's machine can do, without changing anything.
func (c *Client) Capabilities(ctx context.Context) (Capabilities, error) {
	resp, _, err := c.call(ctx, request{Op: opCapabilities}, false)
	if err != nil {
		return Capabilities{}, err
	}
	if resp.Capabilities == nil {
		return Capabilities{}, errors.New("the helper answered without saying what it can do")
	}
	return *resp.Capabilities, nil
}

// OpenTUN asks the helper to create the interface and hand back the open file.
//
// The file arrives as out-of-band data on the same message, so this process ends up
// holding a descriptor for an interface it had no right to create. That is the whole
// point of the helper: everything after this call is ordinary unprivileged I/O.
func (c *Client) OpenTUN(ctx context.Context, name string) (tun.Device, string, error) {
	if name == "" {
		// Resolved on this side, because the helper is a separately installed binary and
		// an empty name asks it to supply its own default -- which is the one its build
		// carried, not this one's. The name the interface gets is this app's choice, so
		// it crosses the boundary as a name rather than as an absence of one.
		name = DefaultInterfaceName()
	}
	resp, file, err := c.call(ctx, request{Op: opOpenTUN, Name: name}, true)
	if err != nil {
		return nil, "", err
	}
	if file == nil {
		return nil, "", errors.New("the helper reported an interface but sent no descriptor for it")
	}
	dev, err := deviceFromFile(file)
	if err != nil {
		return nil, "", fmt.Errorf("take over the interface the helper opened: %w", err)
	}
	return dev, resp.Interface, nil
}

// RouterUp asks the helper to bring the interface up.
func (c *Client) RouterUp(ctx context.Context) error {
	_, _, err := c.call(ctx, request{Op: opRouterUp}, false)
	return err
}

// SetRoutes asks the helper to install the addresses and routes the interface carries.
func (c *Client) SetRoutes(ctx context.Context, cfg *router.Config) error {
	_, _, err := c.call(ctx, request{Op: opSetRoutes, Router: cfg}, false)
	return err
}

// SetHostRoutes asks the helper to install the addressing for an interface this app drives
// itself.
//
// It is checked on this side as well as on the helper's. The helper's check is the one that
// matters -- it is the side holding the rights, and it cannot trust a caller -- and this one
// exists so an impossible request is a sentence from the code that built it rather than a
// round trip that comes back refused.
func (c *Client) SetHostRoutes(ctx context.Context, r Routes) error {
	if err := r.Validate(); err != nil {
		return err
	}
	_, _, err := c.call(ctx, request{Op: opSetHostRoutes, Host: &r}, false)
	return err
}

// ScopeHostDefault asks the helper to keep this machine's own way out reachable for a socket
// bound to the interface holding it.
//
// The helper is told nothing about which interface or which next hop: it reads the machine's
// own default route and copies that. A platform with no scoped routing answers with the
// sentinel, which is reported as the sentinel rather than as a failure so the caller can tell a
// machine that will not do this from one where doing it went wrong.
func (c *Client) ScopeHostDefault(ctx context.Context) error {
	_, _, err := c.call(ctx, request{Op: opScopeHostDefault}, false)
	return scopedRoutesErr(err)
}

// UnscopeHostDefault asks the helper to take those copies back.
func (c *Client) UnscopeHostDefault(ctx context.Context) error {
	_, _, err := c.call(ctx, request{Op: opUnscopeHostDefault}, false)
	return scopedRoutesErr(err)
}

// scopedRoutesErr rebuilds the "this platform cannot do it" answer as its sentinel. It crossed
// the socket as a sentence, and the caller acts on it differently from a failure: it carries on
// and says so, rather than refusing to carry traffic at all.
func scopedRoutesErr(err error) error {
	if err != nil && strings.Contains(err.Error(), ErrScopedRoutesUnsupported.Error()) {
		return unsupportedScopedRoutes{err}
	}
	return err
}

// unsupportedScopedRoutes is the helper's own sentence about a machine that cannot give one
// interface a route of its own, matching the sentinel without replacing what the helper said.
// The helper is the only side that knows why, so its wording is what is reported.
type unsupportedScopedRoutes struct{ err error }

func (u unsupportedScopedRoutes) Error() string { return u.err.Error() }

func (u unsupportedScopedRoutes) Unwrap() []error {
	return []error{ErrScopedRoutesUnsupported, u.err}
}

// BaseDNS asks the helper what this machine resolves names with without app-tail.
//
// A helper that answers with the platform's "will not say" sentinel is reported as that
// sentinel rather than as a failure: the resolver treats the two differently, and turning
// a documented answer into an error would make it give up where it should take over.
func (c *Client) BaseDNS(ctx context.Context) (dns.OSConfig, error) {
	resp, _, err := c.call(ctx, request{Op: opBaseDNS}, false)
	if err != nil {
		if err.Error() == dns.ErrGetBaseConfigNotSupported.Error() {
			return dns.OSConfig{}, dns.ErrGetBaseConfigNotSupported
		}
		return dns.OSConfig{}, err
	}
	if resp.DNS == nil {
		return dns.OSConfig{}, nil
	}
	return *resp.DNS, nil
}

// SplitDNS asks the helper whether this machine can resolve one domain through the
// tailnet and leave the rest alone.
func (c *Client) SplitDNS(ctx context.Context) (bool, error) {
	resp, _, err := c.call(ctx, request{Op: opSplitDNS}, false)
	if err != nil {
		return false, err
	}
	return resp.SplitDNS, nil
}

// SetDNS asks the helper to install the resolver configuration.
func (c *Client) SetDNS(ctx context.Context, cfg dns.OSConfig) error {
	_, _, err := c.call(ctx, request{Op: opSetDNS, DNS: &cfg}, false)
	return err
}

// OpenResolverPacket asks the helper for the UDP half of a resolver socket.
//
// What comes back is a socket bound to a port this process could not have bound itself, and
// everything done with it afterwards is ordinary unprivileged I/O -- the same trade the
// interface makes.
func (c *Client) OpenResolverPacket(ctx context.Context, want netip.AddrPort) (net.PacketConn, error) {
	file, err := c.openResolver(ctx, protoUDP, want)
	if err != nil {
		return nil, err
	}
	// The descriptor is duplicated into the connection this builds, so this process's own
	// copy is closed either way: on failure it is the only reference to a socket bound on
	// port 53, and on success it is a second one nothing will ever close.
	defer closeQuietly(file)
	pc, err := net.FilePacketConn(file)
	if err != nil {
		return nil, fmt.Errorf("take over the resolver socket the helper opened: %w", err)
	}
	return pc, nil
}

// OpenResolverStream asks the helper for the TCP half, which lands on the same address.
func (c *Client) OpenResolverStream(ctx context.Context, want netip.AddrPort) (net.Listener, error) {
	file, err := c.openResolver(ctx, protoTCP, want)
	if err != nil {
		return nil, err
	}
	defer closeQuietly(file)
	ln, err := net.FileListener(file)
	if err != nil {
		return nil, fmt.Errorf("take over the resolver socket the helper opened: %w", err)
	}
	return ln, nil
}

// openResolver performs one open-resolver call and returns the descriptor that came with the
// answer.
func (c *Client) openResolver(ctx context.Context, proto string, want netip.AddrPort) (*os.File, error) {
	req := request{Op: opOpenResolver, Proto: proto}
	if want.IsValid() {
		req.Listen = want.String()
	}
	_, file, err := c.call(ctx, req, true)
	if err != nil {
		return nil, err
	}
	if file == nil {
		return nil, errors.New("the helper reported a resolver socket but sent no descriptor for it")
	}
	return file, nil
}

// SetSystemDNS asks the helper to point this machine's name resolution at the resolvers, or
// to restore what it had when the list is empty.
func (c *Client) SetSystemDNS(ctx context.Context, resolvers []netip.Addr) error {
	_, _, err := c.call(ctx, request{Op: opSetSystemDNS, Resolvers: formatResolvers(resolvers)}, false)
	return partialRestoreErr(err)
}

// partialRestoreErr rebuilds the helper's partial restore as its sentinel. It crossed the
// socket as a sentence, and the caller acts on it differently from a failure: the record
// naming the services still to put back survived, so the run carries on and says so rather
// than reporting a teardown that went wrong.
func partialRestoreErr(err error) error {
	if err != nil && strings.Contains(err.Error(), sysdns.ErrPartialRestore.Error()) {
		return partialRestore{err}
	}
	return err
}

// partialRestore is the helper's own sentence about the services it could not reach, matching
// the sentinel without replacing what the helper said. The helper is the only side that knows
// which services those were, so its wording is what is reported.
type partialRestore struct{ err error }

func (p partialRestore) Error() string { return p.err.Error() }

func (p partialRestore) Unwrap() []error {
	return []error{sysdns.ErrPartialRestore, p.err}
}

// BaseSystemDNS asks the helper what this machine resolves names with underneath app-tail.
func (c *Client) BaseSystemDNS(ctx context.Context) (sysdns.Base, error) {
	resp, _, err := c.call(ctx, request{Op: opBaseSystemDNS}, false)
	if err != nil {
		return sysdns.Base{}, err
	}
	if resp.SystemDNS == nil {
		return sysdns.Base{}, errors.New("the helper answered without saying what this machine resolves names with")
	}
	return *resp.SystemDNS, nil
}

// StartOpenVPN asks the helper to run one OpenVPN connection.
//
// The request is checked here as well as on the helper's side. The helper's check is the one
// that matters -- it is the side holding the rights, and it cannot trust a caller -- and this
// one exists so an impossible request is a sentence from the code that built it rather than a
// round trip that comes back refused.
func (c *Client) StartOpenVPN(ctx context.Context, run OpenVPNRun) error {
	if err := run.Validate(); err != nil {
		return err
	}
	_, _, err := c.call(ctx, request{Op: opRunOpenVPN, OpenVPN: &run}, false)
	return err
}

// ScopeOpenVPN asks the helper to give one connection's interface a default route of its own.
//
// It is asked for once the connection is up and the interface exists, because until then
// there is no interface to route -- and again every time the connection comes back up, since
// an interface that went away took the route with it.
func (c *Client) ScopeOpenVPN(ctx context.Context, scope OpenVPNScope) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	_, _, err := c.call(ctx, request{Op: opScopeOpenVPN, Scope: &scope}, false)
	return err
}

// UnscopeOpenVPN asks the helper to take that route back from a connection that goes on
// running, which is what choosing a different connection to carry this machine's internet
// traffic asks for. The helper removes it when the connection ends whether this is called or
// not: that is the one moment this side may not be there for.
func (c *Client) UnscopeOpenVPN(ctx context.Context, id string) error {
	if !validConnectionID(id) {
		return fmt.Errorf("%q is not a connection identifier", id)
	}
	_, _, err := c.call(ctx, request{Op: opUnscopeOpenVPN, ID: id}, false)
	return err
}

// RepairTailnetRoutes asks the helper to send the tailnet's own address ranges to the interface
// already carrying them.
//
// The name is checked here and again on the privileged side. This side's check is the cheap one
// -- a name no interface could have never reaches a root process -- and the one that matters is
// the helper's, which compares the name against what is actually on the machine.
func (c *Client) RepairTailnetRoutes(ctx context.Context, iface string) ([]netip.Prefix, error) {
	if err := validInterfaceName(iface); err != nil {
		return nil, err
	}
	resp, _, err := c.call(ctx, request{Op: opRepairTailnetRoutes, Interface: iface}, false)
	if err != nil {
		return nil, err
	}
	return resp.Repaired, nil
}

// StopOpenVPN asks the helper to stop one OpenVPN connection.
//
// Closing the whole connection would stop them all, which is what happens when this process
// goes away. This is the one that stops a single connection while the rest keep running.
func (c *Client) StopOpenVPN(ctx context.Context, id string) error {
	if !validConnectionID(id) {
		return fmt.Errorf("%q is not a connection identifier", id)
	}
	_, _, err := c.call(ctx, request{Op: opStopOpenVPN, ID: id}, false)
	return err
}

// Close drops the connection, which is what tells the helper to undo everything.
//
// There is no goodbye message. A message could be lost, and the case that matters most
// -- this process dying without running any of its own code -- would never send one. The
// connection closing is the one signal that is delivered in every case, so it is the only
// one the helper is made to depend on.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

// refusalReadTimeout bounds the wait for a reason after a send has already failed. It is
// short because the case it serves -- a helper that answered and closed -- has the answer
// in this process's own receive buffer before the send was even attempted.
const refusalReadTimeout = 2 * time.Second

// answerWaiting reads an answer that is already on the connection, reporting whether there
// was one. It runs only after a send has already failed: the connection is unusable either
// way, and the one thing left to find out is whether the helper said why before it went.
// Anything that goes wrong here means there was no answer to find, and the send failure
// stands as the caller's error.
func (c *Client) answerWaiting(ctx context.Context) (response, bool) {
	deadline := time.Now().Add(refusalReadTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := c.conn.SetReadDeadline(deadline); err != nil {
		return response{}, false
	}
	var resp response
	if err := readMessage(c.r, &resp); err != nil {
		return response{}, false
	}
	return resp, true
}

// call sends one request and reads its answer, with the connection held for the whole
// exchange so two callers cannot interleave a request with another's reply.
func (c *Client) call(ctx context.Context, req request, wantFile bool) (response, *os.File, error) {
	resp, file, err := c.exchange(ctx, req, wantFile)
	c.report(req, err)
	return resp, file, err
}

// report tells the observer how a change that can need an approval was answered. It sits here
// because every caller's answer passes through here, including the engine's, which swallows a
// failed route or resolver change and leaves nothing above this to see the refusal.
func (c *Client) report(req request, err error) {
	if c.grants == nil {
		return
	}
	src, changes, ok := grantSource(req)
	if !ok {
		return
	}
	var missing *grants.MissingGrants
	switch {
	case errors.As(err, &missing):
		c.grants.Refused(src, missing.Needs)
	case err == nil && changes:
		c.grants.Accepted(src)
	}
}

// grantSource is the feature a request is sent for and whether it carries a change that could
// have needed an approval, or false for a request the helper never holds to one. A request
// that only takes something away -- no routes, no resolvers -- needs no approval, so its
// success says nothing about one and must not clear a refusal.
func grantSource(req request) (src grants.Source, changes bool, ok bool) {
	src.Change = req.Op
	switch req.Op {
	case opSetRoutes:
		src.Feature = grants.FeatureInterface
		changes = req.Router != nil && len(req.Router.Routes)+len(req.Router.LocalAddrs) > 0
	case opSetDNS:
		src.Feature = grants.FeatureInterface
		changes = req.DNS != nil && len(req.DNS.Nameservers)+len(req.DNS.MatchDomains) > 0
	case opSetHostRoutes:
		src.Feature = grants.FeatureFabric
		changes = req.Host != nil && len(req.Host.Routes)+len(req.Host.LocalAddrs) > 0
	case opSetSystemDNS:
		src.Feature = grants.FeatureSystemDNS
		changes = len(req.Resolvers) > 0
	case opRunOpenVPN:
		if req.OpenVPN == nil {
			return grants.Source{}, false, false
		}
		src.Feature, changes = grants.OpenVPNFeature(req.OpenVPN.ID), true
	case opScopeOpenVPN:
		if req.Scope == nil {
			return grants.Source{}, false, false
		}
		src.Feature, changes = grants.OpenVPNFeature(req.Scope.ID), true
	default:
		return grants.Source{}, false, false
	}
	return src, changes, true
}

// exchange is one request and its answer on the wire.
func (c *Client) exchange(ctx context.Context, req request, wantFile bool) (response, *os.File, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return response{}, nil, errors.New("the connection to the helper is closed")
	}
	// Set on every call, from the caller's context or to the zero time that means none,
	// so a deadline never outlives the call that asked for one.
	deadline, _ := ctx.Deadline()
	if err := c.conn.SetDeadline(deadline); err != nil {
		return response{}, nil, fmt.Errorf("set the deadline on the helper connection: %w", err)
	}

	if err := writeMessage(c.conn, req); err != nil {
		// A helper that will not serve this connection writes its reason and drops the
		// connection in one motion, so this send can reach a socket whose answer is
		// already sitting in this process's receive buffer. Reporting the send failure
		// instead would say "broken pipe", which sends someone looking at the socket
		// rather than at the account the helper was installed to serve.
		if answer, ok := c.answerWaiting(ctx); ok {
			if refusal := answer.err(); refusal != nil {
				return response{}, nil, refusal
			}
		}
		return response{}, nil, fmt.Errorf("ask the helper to %s: %w", req.Op, err)
	}

	var resp response
	var file *os.File
	var err error
	if wantFile {
		resp, file, err = readWithFile(c.conn, c.r)
	} else {
		err = readMessage(c.r, &resp)
	}
	if err != nil {
		return response{}, nil, fmt.Errorf("read the helper's answer to %s: %w", req.Op, err)
	}
	if err := resp.err(); err != nil {
		if file != nil {
			// A helper that reported a failure and sent a descriptor anyway leaves this
			// side holding the only reference to whatever it opened.
			err = errors.Join(err, file.Close())
		}
		return response{}, nil, err
	}
	return resp, file, nil
}
