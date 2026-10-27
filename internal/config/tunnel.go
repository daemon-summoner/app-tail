// SPDX-License-Identifier: MIT

package config

// A tunnel is one connection to one private network. This file holds what is stored
// about one; internal/tunnel holds what a live one does.
//
// The two identifiers are deliberately separate. ID is opaque and never reused, so a
// forward, an access rule or an automatic mapping that names a connection keeps naming
// the same one across every rename. Slug is the human handle and the DNS label, so it can
// be changed -- and because it is a DNS label it has to be unique, or two connections
// would claim one name suffix and the resolver could not say which network answered.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// TunnelType is what protocol a connection speaks.
type TunnelType string

const (
	TunnelTailscale TunnelType = "tailscale"
	TunnelWireGuard TunnelType = "wireguard"
	TunnelOpenVPN   TunnelType = "openvpn"
)

// TunnelTypes are every type this app can connect, in the order a picker offers them.
var TunnelTypes = []TunnelType{TunnelTailscale, TunnelWireGuard, TunnelOpenVPN}

// Valid reports whether t is a type this build knows. A stored document naming an
// unknown one is refused at load rather than started as something else.
func (t TunnelType) Valid() bool {
	for _, known := range TunnelTypes {
		if t == known {
			return true
		}
	}
	return false
}

// Label is the type as a person names it.
func (t TunnelType) Label() string {
	switch t {
	case TunnelTailscale:
		return "Tailscale"
	case TunnelWireGuard:
		return "WireGuard"
	case TunnelOpenVPN:
		return "OpenVPN"
	default:
		return string(t)
	}
}

// PrimaryTunnelID is the connection every install has: the tailnet this app was built
// around, carried forward by the migration from the version that could hold only one.
// Nothing may delete it while it is the only thing the settings document describes.
const PrimaryTunnelID = "tn_primary"

// PrimaryTunnelSlug is that connection's default DNS label and human handle.
const PrimaryTunnelSlug = "tailnet"

// MaxSlugLen is a DNS label's limit. A slug longer than this could not be part of a name.
const MaxSlugLen = 63

// Tunnel is one stored connection.
type Tunnel struct {
	// ID is opaque, stable across renames, and never reused.
	ID string `json:"id"`
	// Slug is the DNS label this connection is known by, unique across connections.
	Slug string `json:"slug"`
	// Name is what a person calls it on screen. It is not unique and has no other
	// meaning: two connections may both be called "Work".
	Name string     `json:"name"`
	Type TunnelType `json:"type"`
	// Enabled is whether this connection should be up. A disabled connection is a
	// configured one that is off, which is a state rather than a fault.
	Enabled bool `json:"enabled"`

	// PrefsAdopted records that this install has already read this connection's node
	// preferences into the document. It is what makes adoption happen exactly once per
	// connection: afterwards the document wins, so a preference the user cleared here is
	// not taken back from the node on the next start. It is per-connection because each
	// one is its own node, and a second one must still be asked what it was already
	// doing before anything is pushed to it.
	PrefsAdopted bool `json:"prefsAdopted,omitempty"`

	// Tailscale carries what only a tailnet connection has. It is a pointer, and the
	// document holds exactly the one its type names: a WireGuard peer with an empty
	// tailnet block would be a set of settings nothing reads, which is how a value
	// someone typed goes nowhere with no error anywhere.
	Tailscale *TailscaleTunnel `json:"tailscale,omitempty"`
	// WireGuard carries what only a WireGuard connection has, on the same terms.
	WireGuard *WireGuardTunnel `json:"wireguard,omitempty"`
	// OpenVPN carries what only an OpenVPN connection has, on the same terms.
	OpenVPN *OpenVPNTunnel `json:"openvpn,omitempty"`

	// Shelved holds what this connection's fields held for a module whose switch went
	// off, so turning that module back on returns the configuration rather than a set of
	// defaults. It is per-connection because the values are: deleting a connection has to
	// take its shelf with it. See shelf.go.
	Shelved map[string]json.RawMessage `json:"shelvedFields,omitempty"`
}

// TailscaleTunnel is one tailnet connection's own identity and credentials.
//
// They are per-connection because they are what makes two tailnets two tailnets: the
// device name it enrolls under, the key it enrolls with, and the coordination server it
// enrolls at. A second connection sharing any of them would be the same device joining
// twice.
type TailscaleTunnel struct {
	// Hostname is the device name on the tailnet. Empty renders HostnameTemplate.
	Hostname         string `json:"hostname"`
	HostnameTemplate string `json:"hostnameTemplate"`
	// Tags are advertised at enrollment. Required with an OAuth secret, which is
	// ownerless and so must be tagged.
	Tags                 []string `json:"tags"`
	AdvertiseTagsOnLogin bool     `json:"advertiseTagsOnLogin"`

	// AuthKey and the OAuth pair are the non-interactive credentials, write-only across
	// the API. OAuthClientSecretFile is preferred over the inline secret so a secrets
	// manager can own it.
	AuthKey               string `json:"authKey"`
	OAuthClientSecret     string `json:"oauthClientSecret"`
	OAuthClientSecretFile string `json:"oauthClientSecretFile"`

	// ControlURL is the coordination server. Empty means Tailscale's own.
	ControlURL string `json:"controlURL"`
	// Ephemeral removes the device from the tailnet when the agent exits.
	Ephemeral bool `json:"ephemeral"`

	// The node's own preferences, embedded so the document carries them flat under the
	// keys they have always had.
	TailnetPrefs
}

// TailnetPrefs are the preferences one tailnet connection asks its node to hold.
//
// They are per-connection because a preference is a fact about a node, and each
// connection is its own node: accepting one tailnet's subnet routes says nothing about
// another's, and two networks whose exit nodes are the same choice would be a coincidence
// rather than a setting. Storing one copy for the app would make every connection agree
// about things they have no reason to agree about.
//
// Every one of them is pushed to the running node rather than acted on here, so what this
// struct holds is a request. What the node currently holds is read back separately, and
// the difference between the two is what a consumer renders.
type TailnetPrefs struct {
	// RoutesAccept takes the subnets other devices on this tailnet advertise.
	RoutesAccept bool `json:"routes.accept"`
	// RoutesAdvertiseExitNode offers this device to the tailnet as an exit node. It is
	// the advertisement only: what this node does with the traffic that then arrives is
	// a separate setting, because app-tail routes in userspace and cannot carry all of
	// it.
	RoutesAdvertiseExitNode bool `json:"routes.advertiseExitNode"`
	// RoutesAdvertise are the private networks this device offers to carry for the rest
	// of the tailnet, once an admin approves them. They are stored parsed: a prefix that
	// cannot be read is refused at the write and at load, so no later stage has to decide
	// what to do with one -- and dropping a bad entry there would silently advertise less
	// than the user asked for.
	RoutesAdvertise []netip.Prefix `json:"routes.advertise"`
	// RoutesServe carries the traffic that arrives for an approved advertised network.
	// It is separate from advertising because advertising alone does nothing: a node can
	// be advertised to exercise an approval flow while refusing every connection, and a
	// node that carries traffic can only carry TCP.
	RoutesServe bool `json:"routes.serve"`

	// ExitNodeID names the peer to use, by stable node ID. While rotation is on this is
	// the node to fall back to rather than the one in use: the rotator's current pick is
	// runtime state, and writing it here would rewrite the settings file on a timer.
	ExitNodeID string `json:"exitNode.nodeId"`
	// ExitNodeAuto lets the backend choose. It takes precedence over ExitNodeID at the
	// backend, so this app never sends both.
	ExitNodeAuto bool `json:"exitNode.auto"`
	// ExitNodeAllowLANAccess keeps this machine's own local network reachable while an
	// exit node carries everything else.
	ExitNodeAllowLANAccess bool `json:"exitNode.allowLanAccess"`
	// ExitNodeOnFailure decides what happens when the chosen exit node goes offline.
	ExitNodeOnFailure ExitNodeFailurePolicy `json:"exitNode.onFailure"`
	// ExitNodeRotate moves between exit nodes on a schedule, so no single one sees all
	// of this device's traffic.
	ExitNodeRotate bool `json:"exitNode.rotate.enabled"`
	// ExitNodeRotateStrategy is how the next node is picked.
	ExitNodeRotateStrategy RotateStrategy `json:"exitNode.rotate.strategy"`
	// ExitNodeRotateIntervalSec is how long a node is used before the next is picked.
	ExitNodeRotateIntervalSec int `json:"exitNode.rotate.intervalSec"`
	// ExitNodeRotatePauseOnActive holds a rotation back while connections are open
	// through the current node, since switching breaks every one of them.
	ExitNodeRotatePauseOnActive bool `json:"exitNode.rotate.pauseOnActive"`
	// ExitNodeRotateMaxDeferrals bounds that hold, so a machine that is never idle
	// still rotates rather than pinning one node forever.
	ExitNodeRotateMaxDeferrals int `json:"exitNode.rotate.maxDeferrals"`

	// DNSUseTailnet configures this app's resolver with this tailnet's own DNS. It changes
	// nothing about how the rest of the machine resolves names: app-tail installs no
	// resolver configuration anywhere outside its own process.
	DNSUseTailnet bool `json:"dns.useTailnet"`

	// ShieldsUp refuses every incoming connection from this tailnet regardless of what
	// its ACLs allow, which includes the ones this app's own inbound forwards depend on.
	ShieldsUp bool `json:"security.shieldsUp"`
	// PostureChecking reports device posture -- serial numbers, OS version, MDM
	// identifiers -- to this tailnet. That information leaves this machine, so it is off
	// unless the user turns it on and no preset ever sets it.
	PostureChecking bool `json:"security.postureChecking"`
}

// ExitNodeSelected reports whether this connection sends the rest of its traffic through
// a peer, either one it names or one the backend picks.
func (p TailnetPrefs) ExitNodeSelected() bool {
	return p.ExitNodeAuto || p.ExitNodeID != ""
}

// AdvertisedSubnets are the networks this connection offers to carry, in a canonical
// order. The order is what makes two route lists comparable: the set is what matters, and
// a stored list the user typed in a different order than the node reports them in is the
// same advertisement, not a change to push.
func (p TailnetPrefs) AdvertisedSubnets() []netip.Prefix { return SortPrefixes(p.RoutesAdvertise) }

// EffectiveExitNodeFailurePolicy resolves what happens when the exit node goes away. An
// unset policy holds, which is the choice that cannot surprise: a document written
// before the setting existed must not start sending traffic out directly.
func (p TailnetPrefs) EffectiveExitNodeFailurePolicy() ExitNodeFailurePolicy {
	switch p.ExitNodeOnFailure {
	case FailureNext, FailureOff:
		return p.ExitNodeOnFailure
	default:
		return FailureHold
	}
}

// EffectiveRotateStrategy resolves how the next exit node is chosen. An unset strategy
// walks them in turn, which is the one that spreads traffic evenly without measuring
// anything.
func (p TailnetPrefs) EffectiveRotateStrategy() RotateStrategy {
	switch p.ExitNodeRotateStrategy {
	case RotateRandom, RotateLatency:
		return p.ExitNodeRotateStrategy
	default:
		return RotateRoundRobin
	}
}

// EffectiveRotateInterval is how long one exit node is used. Zero means the default, and
// anything under the floor is raised to it rather than refused here: the registry rejects
// a value below the floor at write time, so a document carrying one was hand-edited and
// is better clamped than treated as a request to rotate every few seconds.
func (p TailnetPrefs) EffectiveRotateInterval() time.Duration {
	secs := p.ExitNodeRotateIntervalSec
	if secs <= 0 {
		secs = DefaultExitNodeRotateIntervalSec
	}
	if secs < MinExitNodeRotateIntervalSec {
		secs = MinExitNodeRotateIntervalSec
	}
	return time.Duration(secs) * time.Second
}

// clone returns a copy sharing no slice with p.
func (p TailnetPrefs) clone() TailnetPrefs {
	p.RoutesAdvertise = append([]netip.Prefix(nil), p.RoutesAdvertise...)
	return p
}

// TailnetPrefsOf is what one connection actually asks its node for: the preferences it
// stores, with every module governing them applied.
//
// The modules are settings of the installation rather than of any one connection -- they
// decide how much of the app is on screen at all -- so folding them in is what turns a
// stored preference into the value to push. It happens once, here, because a module that
// is off has to read as off everywhere: in what is pushed to the node, in what the
// dashboard reports, and in the comparison against what the node already holds. Applying
// it at each of those places instead is how one of them comes to disagree.
func (s Settings) TailnetPrefsOf(t Tunnel) TailnetPrefs {
	p := t.TS().TailnetPrefs.clone()
	if !s.RoutesEnabled {
		p.RoutesAccept, p.RoutesAdvertiseExitNode = false, false
		p.RoutesAdvertise, p.RoutesServe = nil, false
	}
	if !s.ExitNodeEnabled {
		p.ExitNodeID, p.ExitNodeAuto, p.ExitNodeAllowLANAccess = "", false, false
		p.ExitNodeOnFailure = ""
		p.ExitNodeRotate, p.ExitNodeRotateStrategy = false, ""
		p.ExitNodeRotateIntervalSec, p.ExitNodeRotatePauseOnActive = 0, false
		p.ExitNodeRotateMaxDeferrals = 0
	}
	if !s.DNSEnabled {
		p.DNSUseTailnet = false
	}
	if !s.SecurityEnabled {
		p.ShieldsUp, p.PostureChecking = false, false
	}
	return p
}

// TS returns this connection's tailnet settings, and a zero value for a connection that
// has none. Reading through it rather than the pointer is what keeps a caller from having
// to decide what a missing block means.
func (t Tunnel) TS() TailscaleTunnel {
	if t.Tailscale == nil {
		return TailscaleTunnel{}
	}
	return *t.Tailscale
}

// Handle is what an error calls this connection. The slug is the name the user typed and
// the one on screen; the id is opaque and appears nowhere they would recognize, so it is
// only the fallback for a document hand-edited to leave the slug empty.
func (t Tunnel) Handle() string {
	if t.Slug != "" {
		return t.Slug
	}
	return t.ID
}

// EffectiveDNSZone is the zone every connection's names hang under, with an empty setting
// reading as the default. Clearing the field is how a person says "the usual one", so the
// stored value is empty on exactly the installations that meant the default.
func (s Settings) EffectiveDNSZone() string {
	zone := strings.Trim(strings.TrimSpace(s.DNSZone), ".")
	if zone == "" {
		return DefaultDNSZone
	}
	return strings.ToLower(zone)
}

// DNSSuffix is the name suffix this connection's own hosts answer under: a host called db
// on the connection whose short name is office is db.office.internal.
//
// It is derived from the short name rather than stored beside it, so the two can never
// disagree -- a stored suffix left behind by a rename would be a name that still resolves
// and now names a different network, which is the failure this whole convention exists to
// prevent. Uniqueness comes with it for free: short names are already unique across
// connections, so two connections cannot claim one suffix.
func (t Tunnel) DNSSuffix(app *Settings) string {
	if app == nil {
		return ""
	}
	handle := strings.ToLower(t.Handle())
	if handle == "" {
		return ""
	}
	return handle + "." + app.EffectiveDNSZone()
}

// ts returns the tailnet block to write into, creating it if this is the first write.
func (t *Tunnel) ts() *TailscaleTunnel {
	if t.Tailscale == nil {
		t.Tailscale = &TailscaleTunnel{}
	}
	return t.Tailscale
}

// EffectiveAuthKey is the stored key with surrounding whitespace removed.
func (ts TailscaleTunnel) EffectiveAuthKey() string { return strings.TrimSpace(ts.AuthKey) }

// Clone returns a copy that shares nothing with t, so a snapshot handed to a caller
// cannot be edited into the stored document through a pointer or a slice.
func (t Tunnel) Clone() Tunnel {
	out := t
	if t.Tailscale != nil {
		ts := *t.Tailscale
		ts.Tags = append([]string(nil), t.Tailscale.Tags...)
		ts.TailnetPrefs = ts.TailnetPrefs.clone()
		out.Tailscale = &ts
	}
	if t.WireGuard != nil {
		wg := t.WireGuard.clone()
		out.WireGuard = &wg
	}
	if t.OpenVPN != nil {
		ovpn := t.OpenVPN.clone()
		out.OpenVPN = &ovpn
	}
	out.Shelved = maps.Clone(t.Shelved)
	return out
}

// primaryTunnel is the connection a first run creates and the migration synthesizes.
// Both go through here so a fresh install and an upgraded one describe the same tailnet.
// It is Enabled because the connection it stands for is one that is meant to be up: on a
// first run that is the point of the app, and on an upgrade reading it off a switch that
// never existed would turn the upgrade into a disconnection.
func primaryTunnel() Tunnel {
	return NewTunnel(PrimaryTunnelID, PrimaryTunnelSlug, "Tailnet", TunnelTailscale)
}

// TunnelStateDir is where one connection keeps the state its backend owns -- the
// identity it enrolled with, its keys, its cached view of the network.
//
// Every connection gets its own, and that separation is the only thing keeping two of
// them apart: a Tailscale node takes no lock on its directory and rewrites the whole
// state file on every write, so two nodes sharing one would overwrite each other's
// identity with neither reporting anything. Deriving the path from the id -- which the
// document already refuses to repeat -- makes two connections unable to collide rather
// than merely unlikely to.
//
// The primary connection keeps the root directory it has always used. Moving it would
// leave the enrolled identity behind and present every existing install with a fresh
// login for a tailnet it is already on.
func TunnelStateDir(stateDir, id string) string {
	if id == PrimaryTunnelID {
		return stateDir
	}
	return filepath.Join(stateDir, "tunnels", id)
}

// NewTunnelID returns a unique identifier for a new connection.
func NewTunnelID() (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate connection id: %w", err)
	}
	return "tn_" + hex.EncodeToString(b), nil
}

// SuggestSlug derives a DNS label from a display name and makes it one no other
// connection already answers for. taken reports the slugs that are spoken for.
//
// The two names have different rules and a person should only have to supply one:
// "Office VPN" is what they want to read in a list, "office-vpn" is what a name under this
// connection has to be spelled with. Deriving it here rather than in the dialog is what
// keeps a connection added from the CLI named the same way as one added from the
// dashboard.
func SuggestSlug(name string, taken map[string]bool) string {
	base := slugify(name)
	if base == "" {
		// Reached by a name made entirely of characters a label cannot carry. It is a
		// name, not an error: what it cannot be is the label, so the label is generic and
		// the name the user typed is still what they see.
		base = "network"
	}
	if !taken[base] {
		return base
	}
	// Numbered rather than random: two connections added from one template read as
	// "office" and "office-2", which is what a person would have typed themselves.
	for n := 2; ; n++ {
		suffix := "-" + strconv.Itoa(n)
		candidate := trimToLabel(base, MaxSlugLen-len(suffix)) + suffix
		if !taken[candidate] {
			return candidate
		}
	}
}

// slugify renders a display name as a DNS label: lowercase, one hyphen for any run of
// characters a label may not carry, and nothing at either end that a label may not begin
// or finish with.
func slugify(name string) string {
	var b strings.Builder
	pendingDash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			pendingDash = false
		case !pendingDash && b.Len() > 0:
			b.WriteByte('-')
			pendingDash = true
		}
	}
	return trimToLabel(b.String(), MaxSlugLen)
}

// trimToLabel cuts a slug to at most n characters and drops a hyphen left at either end,
// which is what the cut itself can produce.
func trimToLabel(s string, n int) string {
	if n < 1 {
		return ""
	}
	if len(s) > n {
		s = s[:n]
	}
	return strings.Trim(s, "-")
}

// ValidSlug reports whether s can be a DNS label, and the reason when it cannot. The
// reason is bare: the caller names the field.
//
// The rule is the DNS one rather than something friendlier, because the slug becomes a
// label in every name this connection answers for. A slug that is only valid here would
// produce names nothing can look up.
func ValidSlug(s string) (bool, string) {
	switch {
	case s == "":
		return false, "must not be empty"
	case len(s) > MaxSlugLen:
		return false, fmt.Sprintf("must be at most %d characters, got %d", MaxSlugLen, len(s))
	case strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-"):
		return false, "must not start or end with a hyphen"
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return false, "may contain only lowercase letters, digits and hyphens"
		}
	}
	return true, ""
}

// Tunnel returns the stored connection with this id.
func (c *Config) Tunnel(id string) (Tunnel, bool) {
	for _, t := range c.Tunnels {
		if t.ID == id {
			return t, true
		}
	}
	return Tunnel{}, false
}

// PrimaryTailscale returns the tailnet settings of the connection every install has, to
// write into.
//
// It is how the settings that named the tailnet before there could be more than one --
// the env vars, the flags, the fleet profile, the legacy setting keys -- still reach a
// connection. Its absence is refused rather than worked around: those inputs name one
// specific network, and a document with no primary connection has nowhere to put them.
func (c *Config) PrimaryTailscale() (*TailscaleTunnel, error) {
	for i := range c.Tunnels {
		if c.Tunnels[i].ID == PrimaryTunnelID {
			return c.Tunnels[i].ts(), nil
		}
	}
	return nil, fmt.Errorf("connection %q is missing, so there is nothing to apply the tailnet settings to", PrimaryTunnelID)
}

// TunnelBySlug returns the stored connection answering to this DNS label.
func (c *Config) TunnelBySlug(slug string) (Tunnel, bool) {
	for _, t := range c.Tunnels {
		if t.Slug == slug {
			return t, true
		}
	}
	return Tunnel{}, false
}
