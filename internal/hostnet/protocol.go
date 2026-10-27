// SPDX-License-Identifier: MIT

package hostnet

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"tailscale.com/net/dns"
	"tailscale.com/wgengine/router"

	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/sysdns"
)

// The operations the helper answers. The set is closed and small on purpose: this is the
// entire vocabulary a process holding root will act on, and every addition to it is
// another thing an unprivileged caller can ask for.
const (
	opCapabilities = "capabilities"
	opOpenTUN      = "open-tun"
	opRouterUp     = "router-up"
	opSetRoutes    = "set-routes"
	opSetDNS       = "set-dns"
	opBaseDNS      = "base-dns"
	opSplitDNS     = "split-dns"

	// opSetHostRoutes is set-routes for a caller that is not the tailnet engine: it takes
	// address ranges and a packet size and nothing else. The engine's own configuration
	// carries Linux firewall settings and a subnet-routing flag beside the routes, and the
	// caller this exists for has no business setting any of them -- so rather than widening
	// who may send a router.Config, this is the narrow shape that says only where traffic
	// goes.
	opSetHostRoutes = "set-host-routes"

	// opScopeHostDefault copies this machine's own default route onto the interface that route
	// already sits on, scoped so it is consulted only for traffic already bound there.
	// opUnscopeHostDefault removes the copies again. Neither takes a value from the caller: the
	// helper reads the machine's own default route and copies exactly that, so the whole of what
	// an unprivileged caller can ask for is "state where this machine already sends its traffic,
	// on the interface it already sends it from". Where that traffic goes is unchanged, which is
	// the one thing an unprivileged caller must not be able to move.
	opScopeHostDefault   = "scope-host-default"
	opUnscopeHostDefault = "unscope-host-default"

	// The machine-wide resolver, which is a separate feature from the interface and works
	// with no tailnet at all. Each carries the reason it is acceptable for an unprivileged
	// caller to ask for it:
	//
	// opOpenResolver binds a DNS socket and hands the descriptor back. The caller may state
	// a preferred address, and the helper refuses one that is not loopback or whose port is
	// privileged and not 53 -- so this cannot become "bind any port a root process can".
	//
	// opSetSystemDNS points this machine's network services at loopback addresses, and at
	// nothing else. The worst it grants is redirecting this machine's name resolution to
	// another port on its own loopback, which the caller could already arrange by binding
	// one.
	//
	// opBaseSystemDNS reads what the machine resolves names with underneath app-tail. It
	// cannot reuse opBaseDNS, which on macOS reads /etc/resolv.conf -- the merged file this
	// feature's own override rewrites, so the answer would be app-tail's own address.
	opOpenResolver  = "open-resolver"
	opSetSystemDNS  = "set-system-dns"
	opBaseSystemDNS = "base-system-dns"

	// The one pair that starts another program, and the reason it is still a typed operation
	// rather than root-exec: what crosses is a server, a transport, key material, algorithm
	// names and a list of networks. The helper renders the configuration from those against a
	// fixed template and runs a root-owned openvpn from a fixed list of paths, so no value
	// the caller sends ever becomes a directive and no value it sends names a program.
	//
	// The connection is supervised, not launched: openvpn is pointed back at a socket the
	// caller already holds, and stops itself when that connection drops. The helper stops
	// every one it started when the session ends.
	opRunOpenVPN  = "run-openvpn"
	opStopOpenVPN = "stop-openvpn"

	// opScopeOpenVPN gives one running connection's interface a default route of its own, so
	// traffic already bound to that interface reaches the network instead of failing for want
	// of a route. It names a connection rather than an interface on its own, and the helper
	// refuses one it did not start and is not still running -- so what this grants is a route
	// on the interface of a program the helper already agreed to run, and the route is
	// consulted only for traffic bound there. It says nothing about where this machine's own
	// traffic goes, which is the one thing an unprivileged caller must not be able to move.
	opScopeOpenVPN = "scope-openvpn"

	// opRepairTailnetRoutes puts back the route for the tailnet's own address range on the
	// interface already carrying that range's addresses. Neither end of it is a value the
	// caller sends: the range is fixed at compile time, and the interface is checked here
	// against what is on the machine, so the caller cannot name one that is not already the
	// tailnet. What it grants is sending the tailnet's traffic to the tailnet, which is where
	// that traffic goes on a machine with nothing wrong with it.
	opRepairTailnetRoutes = "repair-tailnet-routes"

	// opUnscopeOpenVPN takes that route back while the connection goes on running, which is
	// what choosing a different connection to carry this machine's internet traffic asks for.
	// It grants nothing at all on its own: the most it can do is remove a route this side put
	// there for a connection it started, leaving that interface as it was before.
	opUnscopeOpenVPN = "unscope-openvpn"
)

// maxMessage bounds one frame. The helper reads from an unprivileged peer, so a frame
// size is a memory budget an attacker controls unless it is capped. Every real message
// is well under a kilobyte; a netmap-sized route list is a few tens of kilobytes.
const maxMessage = 1 << 20

// request is one call. Only the field the operation needs is set, and the helper reads
// only the field its own operation names -- a value in another field is ignored rather
// than reinterpreted.
type request struct {
	Op string `json:"op"`
	// Name is the interface to create, for open-tun.
	Name string `json:"name,omitempty"`
	// Router is the addresses and routes to install, for set-routes. A null value
	// removes everything, which is what the engine sends on the way down.
	Router *router.Config `json:"router,omitempty"`
	// DNS is the resolver configuration to install, for set-dns.
	DNS *dns.OSConfig `json:"dns,omitempty"`
	// Host is the addressing to install, for set-host-routes. A null value removes
	// everything, the same way a null Router does.
	Host *Routes `json:"host,omitempty"`
	// Proto is which half of the resolver socket to hand over, for open-resolver: "udp"
	// or "tcp". There is no third and no default -- an unknown value is refused.
	Proto string `json:"proto,omitempty"`
	// Listen is the address the caller would prefer the resolver socket on, for
	// open-resolver. Empty means the helper picks from its own list, which is also what
	// happens when the preferred address is taken.
	Listen string `json:"listen,omitempty"`
	// Resolvers is what to point this machine's name resolution at, for set-system-dns.
	// An empty list restores what the machine had before app-tail changed it: pointing a
	// machine at no resolver at all is not something this offers, so the empty list is
	// free to mean the other thing.
	Resolvers []string `json:"resolvers,omitempty"`
	// OpenVPN is the connection to start, for run-openvpn. Every field of it is checked
	// again on the privileged side before any of it is written anywhere.
	OpenVPN *OpenVPNRun `json:"openvpn,omitempty"`
	// Scope is the connection and the interface it is running on, for scope-openvpn.
	Scope *OpenVPNScope `json:"scope,omitempty"`
	// ID is the connection to stop, for stop-openvpn.
	ID string `json:"id,omitempty"`
	// Interface is the interface carrying a tailnet whose route is to be put back, for
	// repair-tailnet-routes. The helper checks it against the machine rather than acting on
	// the name, so this narrows which interface is repaired rather than choosing one.
	Interface string `json:"interface,omitempty"`
}

// response is one answer. Error carries the helper's own sentence, which the caller
// reports verbatim rather than replacing: the helper is the only side that knows why an
// OS call failed.
type response struct {
	Error string `json:"error,omitempty"`
	// NeedsGrant is, beside Error, every approval a refused request is missing. A caller that
	// can ask an administrator offers to; `app-tail tun grant` with the flags these name is
	// what approves them.
	NeedsGrant []grants.Need `json:"needsGrant,omitempty"`
	// Capabilities answers opCapabilities.
	Capabilities *Capabilities `json:"capabilities,omitempty"`
	// Interface answers opOpenTUN; the file itself travels beside this message
	// as out-of-band data rather than in it.
	Interface string `json:"interface,omitempty"`
	// DNS answers opBaseDNS with the resolver settings this machine would use without
	// app-tail. It is a pointer so "the platform will not say" is distinguishable from
	// "it said there are none", which are different answers the resolver acts on
	// differently: the first makes it install itself as the only resolver.
	DNS *dns.OSConfig `json:"baseDns,omitempty"`
	// SplitDNS answers opSplitDNS.
	SplitDNS bool `json:"splitDns,omitempty"`
	// Listen answers opOpenResolver with the address the helper actually bound, which is
	// not always the one the caller asked for: the socket itself travels beside this
	// message. The caller needs it because it is what the machine will be pointed at.
	Listen string `json:"listen,omitempty"`
	// SystemDNS answers opBaseSystemDNS. It is a pointer so a helper that did not answer
	// is distinguishable from a machine that reported nothing, which are different facts:
	// the first is a protocol disagreement and the second is a machine with no resolver of
	// its own to fall back to.
	SystemDNS *sysdns.Base `json:"systemDns,omitempty"`
	// Repaired answers opRepairTailnetRoutes with the ranges whose route was put back. It is
	// empty when the machine was already routing all of them, which is a success the caller
	// reports differently: nothing was wrong by the time this side looked.
	Repaired []netip.Prefix `json:"repaired,omitempty"`
}

// err rebuilds the helper's failure as an error, or nil when there was none.
//
// The busy refusal comes back as its sentinel. It crossed the socket as a sentence, so it
// is matched as one, and it is the only refusal a caller acts on differently from a
// failure: nothing about the machine is wrong. A refusal for a missing approval comes back as
// a *grants.MissingGrants, which matches grants.ErrNeedsGrant and carries what is missing.
func (r response) err() error {
	switch {
	case r.Error == "":
		return nil
	case r.Error == ErrHelperBusy.Error():
		return ErrHelperBusy
	case len(r.NeedsGrant) > 0:
		return &grants.MissingGrants{Needs: r.NeedsGrant}
	}
	return errors.New(r.Error)
}

// writeMessage frames one value as a JSON line.
//
// Newline framing is safe here because the encoder never emits a bare newline inside a
// value: every string is escaped. A length prefix would be equally correct and harder to
// read in a packet capture, which is the only way anyone will ever debug this.
func writeMessage(w io.Writer, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode the message: %w", err)
	}
	if len(raw) > maxMessage {
		return fmt.Errorf("the message is %d bytes, over the %d-byte limit", len(raw), maxMessage)
	}
	if _, err := w.Write(append(raw, '\n')); err != nil {
		return fmt.Errorf("send the message: %w", err)
	}
	return nil
}

// readMessage reads one JSON line into v.
//
// The reader must be the same *bufio.Reader across calls: it holds bytes already taken
// off the socket, and a fresh one per call would drop whatever it had buffered past the
// newline.
func readMessage(r *bufio.Reader, v any) error {
	line, err := readLine(r)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(line, v); err != nil {
		return fmt.Errorf("read the message: %w", err)
	}
	return nil
}

// readLine takes one framed message off the wire, refusing one that would not fit.
func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, more, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		line = append(line, chunk...)
		if len(line) > maxMessage {
			return nil, fmt.Errorf("the message is over the %d-byte limit", maxMessage)
		}
		if !more {
			return line, nil
		}
	}
}
