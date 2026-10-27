// SPDX-License-Identifier: MIT

package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/sellitus/app-tail/internal/routing"
	"github.com/sellitus/app-tail/internal/sigscan"
)

// ErrNotFound is returned when an id does not match any stored record.
var ErrNotFound = errors.New("not found")

// ValidationError describes a rejected field. The API maps it to HTTP 400.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Message) }

func invalid(field, format string, args ...any) error {
	return &ValidationError{Field: field, Message: fmt.Sprintf(format, args...)}
}

// ConflictError reports that a forward would bind an endpoint another enabled
// forward already owns. The API maps it to HTTP 409 and names the other forward.
type ConflictError struct {
	Endpoint  string
	OtherID   string
	OtherName string
}

func (e *ConflictError) Error() string {
	name := e.OtherName
	if name == "" {
		name = e.OtherID
	}
	return fmt.Sprintf("%s is already used by forward %q", e.Endpoint, name)
}

// listenKeys identifies every endpoint a forward occupies, one per transport it
// carries. A "both" forward returns two keys, so it is seen to conflict with a
// tcp-only or udp-only forward on the same port, not just another "both".
// to_tailnet forwards all share one logical host namespace because they bind this
// node's tailnet IP, which is unknown until the node reaches Running.
func listenKeys(f Forward) []string {
	host := f.BindAddr
	if f.Direction == ToTailnet {
		host = "tailnet"
	} else if host == "" {
		host = DefaultBindAddr
	}
	protos := f.Protocol.Protocols()
	keys := make([]string, 0, len(protos))
	for _, p := range protos {
		keys = append(keys, fmt.Sprintf("%s/%s/%d", p, host, f.ListenPort))
	}
	return keys
}

// conflicts reports whether two forwards would bind an overlapping endpoint.
func conflicts(a, b Forward) bool {
	set := make(map[string]struct{}, 2)
	for _, k := range listenKeys(a) {
		set[k] = struct{}{}
	}
	for _, k := range listenKeys(b) {
		if _, dup := set[k]; dup {
			return true
		}
	}
	return false
}

// Endpoint renders the human-readable address a forward listens on.
func Endpoint(f Forward) string {
	host := f.BindAddr
	if f.Direction == ToTailnet {
		host = "<tailnet-ip>"
	} else if host == "" {
		host = DefaultBindAddr
	}
	return fmt.Sprintf("%s %s", protocolLabel(f.Protocol), net.JoinHostPort(host, strconv.Itoa(f.ListenPort)))
}

// protocolLabel renders a protocol for display: "both" reads as the two transports
// it actually carries rather than the opaque word.
func protocolLabel(p Protocol) string {
	if p == Both {
		return "TCP+UDP"
	}
	return strings.ToUpper(string(p))
}

// ValidateForward checks one forward in isolation. It does not check for conflicts
// with other forwards; use ValidateForwardIn for that.
func ValidateForward(f Forward) error {
	switch f.Direction {
	case ToLocal, ToTailnet:
	default:
		return invalid("direction", "must be %q or %q, got %q", ToLocal, ToTailnet, f.Direction)
	}
	switch f.Protocol {
	case TCP, UDP, Both:
	default:
		return invalid("protocol", "must be %q, %q or %q, got %q", TCP, UDP, Both, f.Protocol)
	}
	if f.ListenPort < 1 || f.ListenPort > 65535 {
		return invalid("listenPort", "must be 1-65535, got %d", f.ListenPort)
	}
	// bindAddr only applies to to_local; to_tailnet always binds the node's tailnet IP.
	if f.Direction == ToLocal && f.BindAddr != "" {
		addr, err := netip.ParseAddr(f.BindAddr)
		if err != nil {
			return invalid("bindAddr", "must be an IP address, got %q", f.BindAddr)
		}
		if !addr.IsLoopback() && !f.ExposeToNetwork {
			return invalid("bindAddr", "%s is reachable from other machines, and the forward would answer them "+
				"with no authentication; turn on exposeToNetwork (\"Let other machines on your network use this "+
				"forward\") to allow it, or listen on %s", f.BindAddr, DefaultBindAddr)
		}
	}
	if err := validateTarget(f.Target); err != nil {
		return err
	}
	if f.UDPTimeoutSec < 0 {
		return invalid("udpTimeoutSec", "must be >= 0, got %d", f.UDPTimeoutSec)
	}
	return nil
}

func validateTarget(target string) error {
	if strings.TrimSpace(target) == "" {
		return invalid("target", "is required (host:port)")
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return invalid("target", "must be host:port, got %q", target)
	}
	if strings.TrimSpace(host) == "" {
		return invalid("target", "host is required in %q", target)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return invalid("target", "port must be 1-65535 in %q", target)
	}
	return nil
}

// ValidateForwardIn validates f and checks it against the existing set. A forward
// with the same ID as an existing one is treated as an update of that entry.
// Only enabled forwards can conflict: two disabled entries may describe the same port.
func ValidateForwardIn(f Forward, existing []Forward) error {
	if err := ValidateForward(f); err != nil {
		return err
	}
	if !f.Enabled {
		return nil
	}
	for _, other := range existing {
		if other.ID == f.ID || !other.Enabled {
			continue
		}
		if conflicts(f, other) {
			return &ConflictError{Endpoint: Endpoint(f), OtherID: other.ID, OtherName: other.Name}
		}
	}
	return nil
}

// Validate checks the whole document: every forward individually, no duplicate ids,
// no conflicting endpoints, and sane settings.
func (c *Config) Validate() error {
	if err := c.Settings.Validate(); err != nil {
		return err
	}
	if err := validateTunnels(&c.Settings, c.Tunnels); err != nil {
		return err
	}
	if err := validateProxies(c); err != nil {
		return err
	}
	if err := validateEgress(c); err != nil {
		return err
	}
	if err := validateRoutes(c); err != nil {
		return err
	}
	seenID := make(map[string]struct{}, len(c.Forwards))
	seenKey := make(map[string]Forward, len(c.Forwards))
	for _, f := range c.Forwards {
		if f.ID == "" {
			return invalid("forwards.id", "is required")
		}
		if _, dup := seenID[f.ID]; dup {
			return invalid("forwards.id", "duplicate id %q", f.ID)
		}
		seenID[f.ID] = struct{}{}
		if err := ValidateForward(f); err != nil {
			return err
		}
		// Checked against the whole document rather than in isolation: a forward whose
		// connection is not there has no network to cross, and would fail at dial time
		// with an error about an address rather than about the connection that is gone.
		if _, exists := c.Tunnel(f.TunnelID); f.TunnelID != "" && !exists {
			return invalid("forwards.tunnelId", "forward %q names connection %q, which does not exist", f.ID, f.TunnelID)
		}
		if !f.Enabled {
			continue
		}
		for _, key := range listenKeys(f) {
			if other, dup := seenKey[key]; dup {
				return &ConflictError{Endpoint: Endpoint(f), OtherID: other.ID, OtherName: other.Name}
			}
			seenKey[key] = f
		}
	}
	return nil
}

// validateRoutes checks the per-destination exceptions, and that each one sending traffic
// through a connection names one the document holds.
//
// The connection check is against the whole document for the same reason the egress one
// is: a rule left pointing at a removed connection would send everything it names at a
// connection that is not there. Where egress falls back to this machine's own network, a
// route rule fails closed -- so the failure would be every destination the rule names
// going nowhere, reported as a dial failure rather than as the rule that caused it.
func validateRoutes(c *Config) error {
	if err := routing.ValidateRules(c.Routes); err != nil {
		return invalid("routes", "%s", err)
	}
	for i, r := range c.Routes {
		if r.Action != routing.Via {
			continue
		}
		if _, exists := c.Tunnel(r.Tunnel); !exists {
			return invalid("routes.tunnel",
				"rule %d sends traffic through connection %q, which does not exist", i+1, r.Tunnel)
		}
	}
	return nil
}

// validateEgress checks that a machine sending its internet traffic through a connection
// names one that exists.
//
// It is checked against the whole document because no single field can see the connection
// list. The failure it prevents is the quiet one: a connection id left behind by a removed
// connection would send every request that no other connection carries at a connection
// that is not there, which fails as a dial timeout to whatever was being reached rather
// than as anything naming the setting that caused it.
//
// An id stored while the traffic leaves directly is deliberately not checked. It carries
// nothing, and refusing it would make removing a connection able to stop the app loading.
func validateEgress(c *Config) error {
	if members, spread := c.Settings.EgressSpread(); spread {
		for _, id := range members {
			if _, exists := c.Tunnel(id); !exists {
				return invalid("egress.multi.tunnelIds",
					"internet traffic is set to be shared across connection %q, which does not exist", id)
			}
		}
		return nil
	}
	if hops, chained := c.Settings.EgressChain(); chained {
		return validateEgressChain(c, hops)
	}
	chosen := c.Settings.EgressTunnel()
	if chosen == "" {
		return nil
	}
	if _, exists := c.Tunnel(chosen); !exists {
		return invalid("egress.tunnelId",
			"internet traffic is set to go through connection %q, which does not exist", chosen)
	}
	return nil
}

// validateEgressChain checks a chain names connections that exist, in an order that can
// actually be built.
//
// The rules are what the packets require rather than policy. A hop after the first has its
// own packets carried inside the hop before it, and there are two ways that is possible
// here. WireGuard's transport is this app's own, so a carried one is simply given a
// different way to send. OpenVPN is a separate process on a real interface of the machine's
// and cannot be told to send its packets anywhere, but it can be pointed at an address --
// so a carried one is pointed at a listener on this machine that carries its stream on, and
// that is a stream, which is the TCP transport and not the UDP one. A tailnet is neither:
// it moves its own packets between relays and peers it chooses, and nothing here picks the
// path. Every hop also has to be able to carry traffic to anywhere: an intermediate hop
// carries the next hop's server, and the last carries the internet.
//
// Refused here rather than degraded at run time. A chain built with a hop that cannot carry
// the next one does not fail as an error -- it fails as a handshake that never completes,
// which reads as a broken server on the far side.
func validateEgressChain(c *Config, hops []string) error {
	if len(hops) == 0 {
		return invalid("egress.multi.tunnelIds",
			"internet traffic is set to be chained through several connections, so name the "+
				"connections it goes through: a chain is an order, and an empty list has none")
	}
	// One connection twice is a loop -- a connection cannot carry its own packets -- and it is
	// refused by the field's own list check before this runs, which is why there is no repeat
	// of it here.
	for i, id := range hops {
		held, exists := c.Tunnel(id)
		if !exists {
			return invalid("egress.multi.tunnelIds",
				"internet traffic is set to be chained through connection %q, which does not exist", id)
		}
		if i > 0 {
			switch {
			case held.Type == TunnelWireGuard:
			case held.Type == TunnelOpenVPN && held.OVPN().EffectiveProto() == OpenVPNProtoTCP:
			case held.Type == TunnelOpenVPN:
				return invalid("egress.multi.tunnelIds",
					"%s reaches its server over %s, and a connection carried inside another one "+
						"reaches it over a stream instead. Set its transport to %s, or make it "+
						"the first connection in the chain.",
					held.Name, held.OVPN().EffectiveProto(), OpenVPNProtoTCP)
			default:
				return invalid("egress.multi.tunnelIds",
					"%s is a %s connection, which sends its own packets over this machine's own "+
						"network and cannot be told to send them through another connection. It can "+
						"only be the first connection in the chain.", held.Name, held.Type.Label())
			}
		}
		if held.Type == TunnelWireGuard && !held.WG().CarriesDefault() {
			return invalid("egress.multi.tunnelIds",
				"%s carries only the addresses its server allows, so it cannot carry %s. Add a "+
					"default route to its allowed addresses, or leave it out of the chain.",
				held.Name, chainCarries(hops, i))
		}
	}
	return nil
}

// chainCarries names what a hop failing the default-route check would have had to carry, so
// the refusal says what is actually being asked of that connection.
func chainCarries(hops []string, i int) string {
	if i == len(hops)-1 {
		return "this machine's internet traffic"
	}
	return "the connection after it in the chain"
}

// validateTunnels checks the connection list's own invariants.
//
// Both uniqueness rules are load-bearing rather than tidiness. A duplicate id means
// whichever entry is found first receives every forward, rule and mapping naming it, and
// the other silently receives none. A duplicate slug means two networks claim one DNS
// label, so a name under that label has two answers and the resolver picks one.
func validateTunnels(app *Settings, tunnels []Tunnel) error {
	seenID := make(map[string]struct{}, len(tunnels))
	seenSlug := make(map[string]string, len(tunnels))
	for _, t := range tunnels {
		if t.ID == "" {
			return invalid("tunnels.id", "is required")
		}
		if _, dup := seenID[t.ID]; dup {
			return invalid("tunnels.id", "duplicate id %q", t.ID)
		}
		seenID[t.ID] = struct{}{}

		if ok, reason := ValidSlug(t.Slug); !ok {
			return invalid("tunnels.slug", "%q %s", t.Slug, reason)
		}
		if other, dup := seenSlug[t.Slug]; dup {
			return invalid("tunnels.slug", "%q is already used by connection %q", t.Slug, other)
		}
		seenSlug[t.Slug] = t.ID

		if !t.Type.Valid() {
			return invalid("tunnels.type", "%q is not a kind of connection this build knows", t.Type)
		}

		// The rest of the rules are the ones each field declares, applied through the same
		// registry a write goes through, so a hand-edited document is refused for the same
		// reason and with the same words a live edit would have been.
		if err := tunnelRegistry.Validate(&t); err != nil {
			return fmt.Errorf("connection %q: %w", t.Handle(), err)
		}

		// An OAuth client mints keys for a tagged, ownerless identity, so a tag is
		// mandatory. It spans two fields, which is why it is here rather than on either.
		ts := t.TS()
		if (ts.OAuthClientSecret != "" || ts.OAuthClientSecretFile != "") && len(ts.Tags) == 0 {
			return invalid("tags",
				"at least one tag is required when an OAuth client secret is configured")
		}

		// Offering this device as an exit node and sending its traffic through another one
		// are mutually exclusive. The first sentence is the backend's own, word for word, so
		// the two never state the rule differently. It is checked here as well as there
		// because the backend's check tests only a named peer: letting the tailnet choose
		// would pair with advertising and be accepted, then take effect as neither.
		//
		// The modules are folded in first, so the pair is judged on what this connection
		// would actually ask its node for rather than on values a switched-off module has
		// already taken out of play.
		if prefs := app.TailnetPrefsOf(t); prefs.ExitNodeSelected() && prefs.RoutesAdvertiseExitNode {
			return invalid("exitNode.enabled",
				"Cannot advertise an exit node and use an exit node at the same time. "+
					"Turn off %q to use one.", AdvertiseExitNodeLabel)
		}

		// A connection carries the settings of its own type and no others. A block of
		// another type is settings someone wrote that nothing will ever read, and its
		// credentials are ones the move into secrets.json never looks for.
		if stray := blocksOfOtherTypes(&t); len(stray) > 0 {
			return invalid("tunnels."+string(stray[0]),
				"connection %q is a %s connection and cannot carry %s settings",
				t.Handle(), t.Type.Label(), stray[0].Label())
		}
	}
	return nil
}

// blocksOfOtherTypes lists the settings blocks t carries for a type other than its own. Each
// block is stored under its type's name.
func blocksOfOtherTypes(t *Tunnel) []TunnelType {
	var stray []TunnelType
	if t.Tailscale != nil && t.Type != TunnelTailscale {
		stray = append(stray, TunnelTailscale)
	}
	if t.WireGuard != nil && t.Type != TunnelWireGuard {
		stray = append(stray, TunnelWireGuard)
	}
	if t.OpenVPN != nil && t.Type != TunnelOpenVPN {
		stray = append(stray, TunnelOpenVPN)
	}
	return stray
}

// dropBlocksOfOtherTypes removes every settings block a connection in c carries for a type
// other than its own, credentials included.
func dropBlocksOfOtherTypes(c *Config) bool {
	dropped := false
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		for _, stray := range blocksOfOtherTypes(t) {
			dropped = true
			switch stray {
			case TunnelTailscale:
				t.Tailscale = nil
			case TunnelWireGuard:
				t.WireGuard = nil
			case TunnelOpenVPN:
				t.OpenVPN = nil
			}
		}
	}
	return dropped
}

// Validate checks settings-level invariants: every field against the rules it declares
// in the registry, then the cross-field rules no single field can see.
//
// Availability is deliberately not checked here. A module switched off returns its
// settings to their defaults at write time, so an off module never leaves a value
// behind; refusing to load a document because a stored value outlives its switch would
// turn a hand-edited config into an unstartable one.
func (s Settings) Validate() error {
	for _, f := range settingsFields {
		if f.get == nil {
			continue
		}
		if err := f.ValidateValue(f.get(&s)); err != nil {
			return err
		}
	}
	if err := checkInterfaceName(s.InterfaceName); err != nil {
		return err
	}
	return nil
}

// interfaceNameMax is the longest name an OS will take. Linux's IFNAMSIZ is 16 counting
// the terminator and is the shortest of the three, so it is the limit everywhere: a name
// that works on one platform and is silently truncated on another is worse than refused.
const interfaceNameMax = 15

// checkInterfaceName refuses a name the OS would reject or mangle. It is checked here
// rather than at creation because the failure would otherwise land during startup, after
// the userspace node has already been torn down to make way for it.
func checkInterfaceName(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > interfaceNameMax {
		return invalid("interface.name",
			"must be at most %d characters, got %d", interfaceNameMax, len(name))
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return invalid("interface.name",
				"must be letters, digits, underscores or hyphens, got %q", name)
		}
	}
	return nil
}

// checkKindSyntax applies the format a field kind declares. The kinds whose format is
// their Go type -- bool, int, a free-text string -- are already settled by the decoder,
// so they have nothing left to check.
func checkKindSyntax(k FieldKind, v any) error {
	switch k {
	case KindAddrPort:
		_, err := parseListenAddr(typed[string](v))
		return err
	case KindURL:
		return checkHTTPURL(typed[string](v))
	case KindCidrList:
		return prefixesAreMasked(typed[[]netip.Prefix](v))
	case KindInterfaceAddrList:
		return addrsAreUsable(typed[[]netip.Prefix](v))
	case KindIPList:
		return resolversAreUsable(typed[[]netip.Addr](v))
	case KindTunnelRefList:
		return connectionsAreDistinct(typed[[]string](v))
	default:
		return nil
	}
}

// connectionsAreDistinct refuses a connection named twice in one list. A repeat is never a
// thing anybody means: it reads as "use this one more", which nothing here does, and it would
// silently change what a list of connections means to whichever surface counted its length.
func connectionsAreDistinct(ids []string) error {
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id == "" {
			return fmt.Errorf("names a connection with no id")
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("names connection %q twice", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

// splitList breaks a comma- or space-separated command-line value into its entries,
// dropping the blanks a trailing separator leaves behind.
func splitList(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
}

// ParsePrefixList reads a list of networks in CIDR form. An entry that cannot be read is
// an error rather than a skipped line: a typo dropped here would advertise or accept
// less than the user asked for, with nothing on screen saying so.
func ParsePrefixList(values []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		p, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return nil, fmt.Errorf("must be networks in CIDR form such as 10.0.0.0/24, got %q", raw)
		}
		out = append(out, p)
	}
	return out, nil
}

// ParseInterfaceAddrList reads a list of addresses this device holds, each written with
// the size of the network it is in. A bare address is accepted and read as being alone in
// its network, which is what a /32 or /128 says and what a configuration that omits the
// size means.
func ParseInterfaceAddrList(values []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if p, err := netip.ParsePrefix(trimmed); err == nil {
			out = append(out, p)
			continue
		}
		addr, err := netip.ParseAddr(trimmed)
		if err != nil {
			return nil, fmt.Errorf("must be addresses with their network size such as 10.0.0.2/24, got %q", raw)
		}
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}

// ParseAddrList reads a list of bare addresses.
func ParseAddrList(values []string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		addr, err := netip.ParseAddr(trimmed)
		if err != nil {
			return nil, fmt.Errorf("must be addresses such as 10.0.0.1, got %q", raw)
		}
		out = append(out, addr)
	}
	return out, nil
}

// addrsAreUsable refuses an address this device cannot hold inside a network. Each one is
// something that parses and then does nothing: an unspecified address names no host, and a
// multicast address is a group rather than somewhere a packet can come back to.
func addrsAreUsable(prefixes []netip.Prefix) error {
	for _, p := range prefixes {
		addr := p.Addr()
		switch {
		case !addr.IsValid() || addr.IsUnspecified():
			return fmt.Errorf("%s names no address for this device to hold", p)
		case addr.IsMulticast():
			return fmt.Errorf("%s is a multicast group rather than an address this device can hold", p)
		}
	}
	return nil
}

// resolversAreUsable refuses a resolver address nothing could be asked at.
func resolversAreUsable(addrs []netip.Addr) error {
	for _, addr := range addrs {
		if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() {
			return fmt.Errorf("%s is not an address a resolver can be reached at", addr)
		}
	}
	return nil
}

// prefixesAreMasked refuses a prefix carrying host bits. The sentence is the backend's
// own, word for word, so a route this app accepts and the tailnet then rejects cannot be
// described two different ways.
func prefixesAreMasked(prefixes []netip.Prefix) error {
	for _, p := range prefixes {
		if p != p.Masked() {
			return fmt.Errorf("route %s has non-address bits set; expected %s", p, p.Masked())
		}
	}
	return nil
}

// tailnetRanges are the address ranges a tailnet allocates its own devices from. They
// are written out rather than read from the Tailscale library because this package
// deliberately imports nothing from it; TestConfigRefusesToAdvertiseTheRealTailnetRanges
// in internal/tsnode binds these rules to the library's own values, so a range that
// moved upstream fails there instead of quietly leaving a rule that guards nothing.
var tailnetRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

// advertisableRoutes refuses a route list this device must not offer to carry.
//
// Each rule is a route that would break something rather than a matter of taste: a
// default route is the exit-node setting wearing a disguise and would be applied as
// neither; a range covering the tailnet's own addresses would have this node claim the
// path to every peer, including the path back to itself; loopback and link-local mean
// something different on every machine, so carrying them for a peer sends its traffic to
// whatever happens to answer here; and two entries covering the same address make the
// list ambiguous about which one an approval applies to.
func advertisableRoutes(v any) error {
	prefixes := typed[[]netip.Prefix](v)
	for i, p := range prefixes {
		if p.Bits() == 0 {
			return fmt.Errorf("%s routes everything rather than a network; use %q to offer this "+
				"device as an exit node", p, AdvertiseExitNodeLabel)
		}
		if containsAny(tailnetRanges, p) {
			return fmt.Errorf("%s covers the tailnet's own addresses, which every device already reaches", p)
		}
		addr := p.Addr()
		switch {
		case addr.IsLoopback():
			return fmt.Errorf("%s is this machine's own loopback, which is not a network other devices can be sent to", p)
		// Multicast is tested before link-local because the two overlap -- 224.0.0.0/24 is
		// both -- and multicast is the reason such a route is refused.
		case addr.IsMulticast():
			return fmt.Errorf("%s is multicast, which is not a destination a route carries", p)
		case addr.IsLinkLocalUnicast():
			return fmt.Errorf("%s is link-local, which means a different network on every device", p)
		case addr.IsUnspecified():
			return fmt.Errorf("%s is not a network this device can carry", p)
		}
		for _, other := range prefixes[i+1:] {
			if p.Overlaps(other) {
				return fmt.Errorf("%s and %s cover the same addresses; advertise the wider one alone", p, other)
			}
		}
	}
	return nil
}

// containsAny reports whether any of ranges covers p entirely.
func containsAny(ranges []netip.Prefix, p netip.Prefix) bool {
	for _, r := range ranges {
		if r.Overlaps(p) && r.Bits() <= p.Bits() {
			return true
		}
	}
	return false
}

// parseListenAddr splits a host:port carrying a literal IP host and returns the host.
// An empty value is accepted: an unset address means the field's default applies.
func parseListenAddr(v string) (netip.Addr, error) {
	if v == "" {
		return netip.Addr{}, nil
	}
	host, portStr, err := net.SplitHostPort(v)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("must be host:port, got %q", v)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("host must be an IP address, got %q", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return netip.Addr{}, fmt.Errorf("port must be 0-65535 in %q", v)
	}
	return addr, nil
}

// loopbackOnly refuses a listen address reachable from off this machine. The dashboard
// can reconfigure forwards and reveal the login URL, so it must never be.
func loopbackOnly(v any) error {
	addr := typed[string](v)
	if addr == "" {
		return nil
	}
	host, err := parseListenAddr(addr)
	if err != nil {
		return err
	}
	if !host.IsLoopback() {
		return fmt.Errorf("must bind a loopback address, got %q", host)
	}
	return nil
}

// dnsZone refuses a zone that could never carry a connection's names. Empty is accepted
// and means the default: a zone is required, and the way to say "the usual one" is to
// clear the field rather than to remember what it was.
func dnsZone(v any) error {
	zone := strings.Trim(strings.TrimSpace(typed[string](v)), ".")
	if zone == "" {
		return nil
	}
	return dnsSuffixes([]string{zone})
}

// dnsSuffixes refuses a name suffix that could never match a query.
//
// It is checked here rather than shrugged off at lookup time because the failure is
// invisible otherwise: a suffix with a stray space or a slash in it matches nothing, so the
// names it was added for quietly keep going to the wrong resolver, and the setting looks
// like it is in force.
func dnsSuffixes(v any) error {
	for _, suffix := range typed[[]string](v) {
		trimmed := strings.Trim(strings.TrimSpace(suffix), ".")
		if trimmed == "" {
			return fmt.Errorf("%q is not a name suffix", suffix)
		}
		for _, label := range strings.Split(trimmed, ".") {
			if label == "" {
				return fmt.Errorf("%q has an empty label, so it matches no name", suffix)
			}
			if err := checkDNSLabel(label, suffix); err != nil {
				return err
			}
		}
	}
	return nil
}

// namesOrPrefixes refuses an inspection entry that is neither a name nor an address, for
// the reason dnsSuffixes exists: an entry that parses as neither matches nothing, so a
// user who typed one is watching a list that is not doing what they read it as.
//
// Which form an entry is written in is read from the text rather than declared, so an
// address, a CIDR network and a domain all belong in the same setting and nobody has to
// sort them first.
func namesOrPrefixes(v any) error {
	for _, entry := range typed[[]string](v) {
		text := strings.TrimSpace(entry)
		if text == "" {
			return fmt.Errorf("%q is neither a name nor an address", entry)
		}
		if _, err := netip.ParsePrefix(text); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(text); err == nil {
			continue
		}
		if strings.ContainsRune(text, '/') {
			return fmt.Errorf("%q looks like a network but is not one; write it as "+
				"10.0.0.0/8", entry)
		}
		if err := dnsSuffixes([]string{text}); err != nil {
			return err
		}
	}
	return nil
}

// signaturePatterns refuses an inspection signature the matcher could not build, so a
// mistyped line is reported where it was typed rather than as a set that quietly stopped
// applying.
//
// A blank entry is skipped rather than refused: a list edited in a text box round-trips
// through empty rows, and refusing one would make the field impossible to edit.
func signaturePatterns(v any) error {
	written := 0
	for _, entry := range typed[[]string](v) {
		if strings.TrimSpace(entry) == "" {
			continue
		}
		if _, err := sigscan.Parse(entry); err != nil {
			return err
		}
		written++
	}
	if written > sigscan.MaxPatterns {
		return fmt.Errorf("%d signatures is more than the %d that are matched at once",
			written, sigscan.MaxPatterns)
	}
	return nil
}

// blockRefreshHours refuses an interval short enough to be a machine hammering somebody
// else's server. Zero is accepted and means the default applies.
func blockRefreshHours(v any) error {
	hours := typed[int](v)
	if hours != 0 && hours < MinDNSBlockRefreshHours {
		return fmt.Errorf("must be %d or more, since a list rebuilt daily gains nothing from "+
			"being fetched more often, got %d", MinDNSBlockRefreshHours, hours)
	}
	return nil
}

// blocklistIDs refuses a list named twice or named by nothing. A repeat would be counted
// where lists are counted and would credit a blocked name to whichever copy sorted first,
// and an empty id names no list at all.
//
// Whether an id exists is deliberately not checked here: the catalog lives outside this
// package, and a list switched on before it is added would otherwise be unsavable rather
// than simply inactive.
func blocklistIDs(v any) error {
	seen := make(map[string]struct{})
	for _, id := range typed[[]string](v) {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			return fmt.Errorf("names a list with no id")
		}
		if _, dup := seen[trimmed]; dup {
			return fmt.Errorf("names %q twice", trimmed)
		}
		seen[trimmed] = struct{}{}
	}
	return nil
}

// checkDNSLabel holds one label of a suffix to what a name can carry: letters, digits and
// hyphens, up to the 63 bytes a label is allowed.
func checkDNSLabel(label, suffix string) error {
	if len(label) > 63 {
		return fmt.Errorf("%q has a part longer than the 63 characters a name allows", suffix)
	}
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return fmt.Errorf("%q contains %q, which cannot appear in a name", suffix, string(r))
		}
	}
	return nil
}

// checkHTTPURL requires an absolute http(s) URL. An empty value is accepted, meaning
// the field's default applies.
func checkHTTPURL(v string) error {
	if v == "" {
		return nil
	}
	if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
		return fmt.Errorf("must be an http(s) URL, got %q", v)
	}
	return nil
}

// unprivilegedPort refuses a port this process could not bind without elevation. Zero
// is accepted and means the field's default applies.
func unprivilegedPort(v any) error {
	port := typed[int](v)
	if port != 0 && port < 1024 {
		return fmt.Errorf("must be 1024 or above, since binding below that needs privilege, got %d", port)
	}
	return nil
}

// rotateIntervalSec refuses an interval short enough to be an outage. The floor cannot
// be a declared bound because zero has to stay acceptable: it means the default applies,
// and a document written before this setting existed carries one.
func rotateIntervalSec(v any) error {
	secs := typed[int](v)
	if secs != 0 && secs < MinExitNodeRotateIntervalSec {
		return fmt.Errorf("must be %d or above, since every change of exit node drops the "+
			"connections going through the old one, got %d", MinExitNodeRotateIntervalSec, secs)
	}
	return nil
}

// arePorts refuses a port list carrying anything that is not a port. Skipping the bad
// entry instead would leave a typo indistinguishable from the feature being off.
func arePorts(v any) error {
	_, err := ParsePortList(typed[[]string](v))
	return err
}

// ParsePortList reads a list of port numbers, dropping blanks and duplicates but
// rejecting anything that is not a port between 1 and 65535.
func ParsePortList(values []string) ([]int, error) {
	out := make([]int, 0, len(values))
	seen := make(map[int]bool, len(values))
	for _, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		port, err := strconv.Atoi(trimmed)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("must be port numbers between 1 and 65535, got %q", raw)
		}
		if seen[port] {
			continue
		}
		seen[port] = true
		out = append(out, port)
	}
	return out, nil
}

// tagsAreQualified refuses a bare tag name. The control plane only recognises the
// tag: form, and an unqualified tag fails enrollment rather than being normalised.
func tagsAreQualified(v any) error {
	for _, tag := range typed[[]string](v) {
		if !strings.HasPrefix(tag, "tag:") {
			return fmt.Errorf("each tag must start with \"tag:\", got %q", tag)
		}
	}
	return nil
}
