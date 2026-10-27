// SPDX-License-Identifier: MIT

package hostnet

// Holding a request to what an administrator has approved.
//
// The owner check on the socket says who may ask. It says nothing about what they may ask
// for, and the agent runs as an ordinary account: anything that account runs could connect
// and ask this side to carry all of the machine's traffic somewhere, or to answer all of its
// name lookups. So each request that moves the machine is held to the approvals file, which
// only root writes. What stays inside the tailnet and the private ranges beside it needs no
// approval; the rest is refused with the list of what is missing, and the caller turns that
// list into the one command an administrator runs to approve it.

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"

	"tailscale.com/net/dns"
	"tailscale.com/wgengine/router"

	"github.com/sellitus/app-tail/internal/grants"
)

// grantPolicy is where the approvals and the machine's own networks come from.
type grantPolicy struct {
	// load reads the approvals. It is called for every request that needs one, never cached:
	// an approval an administrator takes back stops counting at the next request.
	load func() (grants.Document, error)
	// attached are the networks on this machine's own interfaces, which a route may not take
	// over without an approval.
	attached func() ([]netip.Prefix, error)
}

// machineGrantPolicy reads this machine's approvals file and its real interfaces.
func machineGrantPolicy() grantPolicy {
	return grantPolicy{
		load: func() (grants.Document, error) {
			path, err := grants.Path()
			if err != nil {
				return grants.Document{}, err
			}
			return grants.Load(path)
		},
		attached: AttachedNetworks,
	}
}

// AttachedNetworks are the networks on this machine's physical interfaces: up, carrying a
// hardware address, and neither loopback nor a point-to-point link. Tunnels -- this app's own
// among them -- are left out, because a route over a tunnel's range is not taking anything
// away from the machine's own network.
func AttachedNetworks() ([]netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("read this machine's network interfaces: %w", err)
	}
	var out []netip.Prefix
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("read the addresses of %s: %w", iface.Name, err)
		}
		for _, p := range addrPrefixes(addrs) {
			out = append(out, p.Masked())
		}
	}
	return out, nil
}

// addrPrefixes is each address with its prefix length, leaving out link-local ones, which route
// nothing beyond their own link.
func addrPrefixes(addrs []net.Addr) []netip.Prefix {
	var out []netip.Prefix
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		ip = ip.Unmap()
		if ip.IsLinkLocalUnicast() {
			continue
		}
		if ip.Is4() && ones > 32 {
			ones -= 96
		}
		out = append(out, netip.PrefixFrom(ip, ones))
	}
	return out
}

// approvals is one connection's view of the policy: the policy itself, and the OpenVPN
// connections this session started, which a later scope-openvpn is checked against.
type approvals struct {
	policy grantPolicy
	mu     sync.Mutex
	// openvpn is each connection this session started, by id, with the server and certificate
	// authority it was approved for.
	openvpn map[string]approvedOpenVPN
	// openvpnAddrs is the addresses each connection's server last handed it, by id, kept after
	// the connection stops so starting it again is held to them before it reaches the server.
	openvpnAddrs map[string][]netip.Prefix
}

type approvedOpenVPN struct {
	remote string
	ca     string
}

func newApprovals(policy grantPolicy) *approvals {
	return &approvals{
		policy:       policy,
		openvpn:      make(map[string]approvedOpenVPN),
		openvpnAddrs: make(map[string][]netip.Prefix),
	}
}

// check asks needs of nothing approved first, and reads the approvals file only when that
// leaves something: most requests stay inside the tailnet, and those never depend on a file
// being readable. A file that is there and cannot be read refuses the request.
func (a *approvals) check(needs func(grants.Document) ([]grants.Need, error)) error {
	missing, err := needs(grants.None())
	if err != nil || len(missing) == 0 {
		return err
	}
	doc, err := a.policy.load()
	if err != nil {
		return fmt.Errorf("this change needs an administrator's approval, and the approvals could not be read: %w", err)
	}
	missing, err = needs(doc)
	if err != nil || len(missing) == 0 {
		return err
	}
	return &grants.MissingGrants{Needs: missing}
}

// routes checks a set of ranges about to be sent to an interface. The interface's own
// addresses count when they are wider than one address, because those install a route for
// the whole network they name.
func (a *approvals) routes(localAddrs, routes []netip.Prefix) error {
	all := append(slices.Clone(routes), networksOf(localAddrs)...)
	if len(all) == 0 {
		return nil
	}
	return a.check(func(doc grants.Document) ([]grants.Need, error) {
		attached, err := a.policy.attached()
		if err != nil {
			return nil, err
		}
		return doc.RouteNeeds(all, attached), nil
	})
}

// networksOf is the addresses that install a route for a network: those wider than one address.
func networksOf(addrs []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range addrs {
		if p.IsValid() && p.Bits() < p.Addr().BitLen() {
			out = append(out, p)
		}
	}
	return out
}

func (a *approvals) routerConfig(cfg *router.Config) error {
	if cfg == nil {
		return nil
	}
	return a.routes(cfg.LocalAddrs, cfg.Routes)
}

func (a *approvals) hostRoutes(r *Routes) error {
	if r == nil {
		return nil
	}
	return a.routes(r.LocalAddrs, r.Routes)
}

func (a *approvals) interfaceDNS(cfg dns.OSConfig) error {
	return a.check(func(doc grants.Document) ([]grants.Need, error) {
		domains := make([]string, 0, len(cfg.MatchDomains))
		for _, d := range cfg.MatchDomains {
			domains = append(domains, d.WithTrailingDot())
		}
		return doc.InterfaceDNSNeeds(cfg.Nameservers, domains), nil
	})
}

func (a *approvals) systemDNS(resolvers []netip.Addr) error {
	return a.check(func(doc grants.Document) ([]grants.Need, error) {
		return doc.SystemDNSNeeds(resolvers), nil
	})
}

// openVPN checks a connection about to be started: its server and certificate authority,
// and the networks it will carry, the ones its server handed it last time included.
func (a *approvals) openVPN(run OpenVPNRun) error {
	routes := slices.Clone(run.Routes)
	if run.RedirectGateway {
		routes = append(routes, netip.MustParsePrefix("0.0.0.0/0"))
	}
	a.mu.Lock()
	routes = append(routes, networksOf(a.openvpnAddrs[run.ID])...)
	a.mu.Unlock()
	return a.check(func(doc grants.Document) ([]grants.Need, error) {
		needs, err := doc.OpenVPNNeeds(run.Remote, run.CA)
		if err != nil {
			return nil, err
		}
		attached, err := a.policy.attached()
		if err != nil {
			return nil, err
		}
		return append(needs, doc.RouteNeeds(routes, attached)...), nil
	})
}

// startedOpenVPN remembers a connection the privileged side agreed to start, for the scope
// requests that name it later.
func (a *approvals) startedOpenVPN(run OpenVPNRun) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.openvpn[run.ID] = approvedOpenVPN{remote: run.Remote, ca: run.CA}
}

// openVPNAddresses holds the addresses connection id's server handed its interface to the
// approvals, and remembers them for the connection's next start. See openvpnaddrs.go.
func (a *approvals) openVPNAddresses(id string, addrs []netip.Prefix) error {
	a.mu.Lock()
	a.openvpnAddrs[id] = slices.Clone(addrs)
	a.mu.Unlock()
	return a.routes(addrs, nil)
}

// stoppedOpenVPN forgets a connection this session no longer runs.
func (a *approvals) stoppedOpenVPN(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.openvpn, id)
}

// scopeOpenVPN checks that the connection about to carry traffic bound to its interface is
// still one an administrator approves: an approval taken back after the connection started
// stops the next scope rather than waiting for a restart. A connection this session did not
// start is left to the privileged side, which refuses it.
func (a *approvals) scopeOpenVPN(id string) error {
	a.mu.Lock()
	started, ok := a.openvpn[id]
	a.mu.Unlock()
	if !ok {
		return nil
	}
	return a.check(func(doc grants.Document) ([]grants.Need, error) {
		return doc.OpenVPNNeeds(started.remote, started.ca)
	})
}

// grantRefusal is the reply for a refused request: the sentence a person reads, and the
// approvals that are missing for a caller that offers to ask for them.
func grantRefusal(err error) response {
	var missing *grants.MissingGrants
	if errors.As(err, &missing) {
		return response{Error: err.Error(), NeedsGrant: missing.Needs}
	}
	return response{Error: err.Error()}
}
