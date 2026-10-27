// SPDX-License-Identifier: MIT

package tsnode

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"slices"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/grants"
)

// installNeeds is what the config file at configPath asks the helper for, worked out by this
// unprivileged process before the password dialog so the dialog can list it and root is handed
// exactly that. An empty configPath approves nothing.
func installNeeds(configPath string, attached func() ([]netip.Prefix, error)) ([]grants.Need, error) {
	if configPath == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read the config to list what the install approves (%s): %w", configPath, err)
	}
	var cfg config.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("read the config to list what the install approves (%s): %w", configPath, err)
	}
	nets, err := attached()
	if err != nil {
		return nil, err
	}
	return NeedsOf(&cfg, nets)
}

// NeedsOf is what a config asks for that nothing is approved for yet. A connection's own DNS
// servers are not here: app-tail answers those lookups itself and never hands the servers to
// the helper. What the tailnet's coordination server pushes is not either, because it is not
// in the file; the helper refuses it at run time with the command that approves it.
func NeedsOf(cfg *config.Config, attached []netip.Prefix) ([]grants.Need, error) {
	none := grants.None()
	var needs []grants.Need
	s := cfg.Settings
	// An exit node, or the internet leaving through a connection, is this machine's default
	// route moving to app-tail.
	if s.ExitNodeEnabled || (s.EgressMode != "" && s.EgressMode != config.EgressDirect) {
		needs = append(needs, none.RouteNeeds([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, nil)...)
	}
	for _, t := range cfg.Tunnels {
		if !t.Enabled {
			continue
		}
		switch {
		case t.WireGuard != nil:
			// The interface's own addresses count as the helper counts them: only one wider
			// than a single address installs a route.
			routes := slices.Clone(t.WireGuard.Peer.AllowedIPs)
			for _, p := range t.WireGuard.Addresses {
				if p.IsValid() && p.Bits() < p.Addr().BitLen() {
					routes = append(routes, p)
				}
			}
			needs = append(needs, none.RouteNeeds(routes, attached)...)
		case t.OpenVPN != nil:
			ovpn := t.OpenVPN
			vpn, err := none.OpenVPNNeeds(ovpn.Remote, ovpn.CA)
			if err != nil {
				return nil, fmt.Errorf("the connection %q: %w", t.Name, err)
			}
			needs = append(needs, vpn...)
			needs = append(needs, none.RouteNeeds(ovpn.Routes, attached)...)
		}
	}
	if dnsprofiles.OverrideWanted(s) {
		needs = append(needs, none.SystemDNSNeeds([]netip.Addr{netip.MustParseAddr("127.0.0.1")})...)
	}
	if s.IPSIntercept != "" && s.IPSIntercept != config.IPSInterceptOff && s.IPSInterceptAgreed {
		needs = append(needs, none.TLSInterceptionNeeds()...)
	}
	return needs, nil
}
