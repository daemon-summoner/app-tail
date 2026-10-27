// SPDX-License-Identifier: MIT

// Package config defines app-tail's on-disk configuration and the rules that
// govern it: schema, validation, layered resolution, and atomic persistence.
package config

import (
	"encoding/json"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/sellitus/app-tail/internal/routing"
)

// Direction says which side of the bridge a forward listens on.
type Direction string

const (
	// ToLocal pulls a tailnet service onto this machine: listen locally, dial over the tailnet.
	ToLocal Direction = "to_local"
	// ToTailnet publishes a local service on this node's tailnet IP.
	ToTailnet Direction = "to_tailnet"
)

// ProxyScope is how far the tailnet proxy will dial. Neither value ever falls through
// to a direct connection: a destination outside the scope is refused, so a program
// pointed at the proxy cannot silently leave the tailnet.
type ProxyScope string

const (
	// ScopeTailnet accepts only destinations the tailnet routes -- peers, MagicDNS
	// names, and any subnet routes this node accepts. Everything else is refused.
	ScopeTailnet ProxyScope = "tailnet"
	// ScopeAll additionally accepts destinations that leave this machine normally,
	// which is what a browser pointed entirely at the proxy needs, and what sends
	// public traffic through an exit node once one is selected.
	ScopeAll ProxyScope = "all"
)

// ProxyResolveVia is which resolver turns a name into an address for the proxy. The two
// answers differ for a domain the tailnet points at a private nameserver: only the
// tailnet's own resolver knows about it, and this machine's would answer with a public
// address or with nothing at all.
type ProxyResolveVia string

const (
	// ResolveViaNetmap reads MagicDNS names out of the netmap the node already holds
	// and hands every other name to this machine's resolver.
	ResolveViaNetmap ProxyResolveVia = "netmap"
	// ResolveViaTailnet asks the tailnet's own resolver first, which is what makes a
	// split-DNS domain resolve to the address the tailnet publishes for it. A name the
	// tailnet does not serve falls back to the netmap answer.
	ResolveViaTailnet ProxyResolveVia = "tailnet"
)

// ExitNodeFailurePolicy is what happens when the exit node in use stops being usable.
// It has to be a choice because the two sane answers are opposites: a node picked for
// privacy must never quietly fall back to the local connection, and a node picked for
// reach is useless if it stays selected while offline.
type ExitNodeFailurePolicy string

const (
	// FailureHold keeps the node selected. The backend blackholes the default route
	// while its exit node is unusable, so traffic stops rather than leaving directly.
	FailureHold ExitNodeFailurePolicy = "hold"
	// FailureNext moves to another usable exit node.
	FailureNext ExitNodeFailurePolicy = "next"
	// FailureOff stops using an exit node at all, which restores connectivity and gives
	// up the property the exit node was there for.
	FailureOff ExitNodeFailurePolicy = "off"
)

// RotateStrategy is how the next exit node is chosen while rotation is on.
type RotateStrategy string

const (
	// RotateRoundRobin walks the usable nodes in a stable order, so every one of them
	// carries a turn.
	RotateRoundRobin RotateStrategy = "round_robin"
	// RotateRandom picks at random from the usable nodes other than the current one.
	RotateRandom RotateStrategy = "random"
	// RotateLatency prefers the node that answers fastest right now.
	RotateLatency RotateStrategy = "latency"
)

// NetworkMode is the stack the tailnet node runs on.
type NetworkMode string

const (
	// NetworkUserspace keeps the tailnet inside this process: no interface, no routes,
	// no resolver files. It is what the app installs as and what every other module is
	// written against.
	NetworkUserspace NetworkMode = "userspace"
	// NetworkTUN creates a real network interface, so tailnet addresses and MagicDNS
	// names work in every program on the machine without any of them being configured.
	// It is the one mode that needs a privileged helper and writes outside the state
	// directory.
	NetworkTUN NetworkMode = "tun"
	// NetworkFabric creates one network interface for every connection at once, ending
	// each flow that arrives on it and re-dialling it inside whichever network the address
	// belonged to. It is the only mode that can present a network somewhere other than its
	// own addresses, which is what makes two networks that both use 10.0.0.0/8 reachable
	// at the same time, and it costs what terminating every flow costs.
	NetworkFabric NetworkMode = "fabric"
)

// NetworkModes are every stack a connection can be reached over, in the order the picker
// offers them: least of the machine touched first.
var NetworkModes = []NetworkMode{NetworkUserspace, NetworkTUN, NetworkFabric}

// EgressMode is where traffic that no connection carries -- the open internet -- leaves
// through.
//
// It is a statement about this machine rather than about any one connection, which is why
// it lives in the settings and not on a connection: putting it on one connection's page
// would make the choice invisible from the other two, and the whole question is which of
// them it is.
type EgressMode string

const (
	// EgressDirect leaves through this machine's own network, which is what every other
	// program on the machine does. It is the default: sending traffic somewhere else is a
	// change to where this machine appears to be, and nothing should do that unasked.
	EgressDirect EgressMode = "direct"
	// EgressTunnel sends it out through a chosen connection. What that costs and whether
	// the connection can carry it at all differ by kind, so the connection is asked rather
	// than assumed -- a tailnet needs an exit node selected, and a WireGuard peer needs a
	// default route in its allowed addresses.
	EgressTunnel EgressMode = "tunnel"
	// EgressMulti sends it out through several connections at once, one connection per
	// destination. It is a stronger claim than one connection: no single provider sees the
	// whole of what this machine does.
	//
	// Nothing ever falls back to this machine's own network in this mode, including when
	// every chosen connection is down. That is the point of choosing several: a mode whose
	// failure is a quiet return to the ISP link would hide exactly the traffic it promises
	// to spread.
	EgressMulti EgressMode = "multi"
)

// EgressShape is how several connections carry this machine's internet traffic together.
//
// The two are different promises, not two settings of one. Spread is about breadth: every
// chosen connection carries traffic at the same time, each provider sees a share of where
// this machine goes, and none sees all of it. A chain is about depth: the traffic goes
// through all of them in order, so the first provider knows who this machine is and not
// where it went, and the last knows where it went and not who asked.
type EgressShape string

const (
	// EgressSpreadShape gives each site one of the chosen connections and keeps it there.
	// It is the default: it costs nothing per packet and every connection runs at its own
	// speed, where a chain pays every hop's latency and encryption on every byte.
	EgressSpreadShape EgressShape = "spread"
	// EgressCascade sends the traffic through the chosen connections in order, each one
	// carrying the next one's own packets, and out of the last.
	EgressCascade EgressShape = "cascade"
)

// Protocol is the transport a forward carries.
type Protocol string

const (
	TCP Protocol = "tcp"
	UDP Protocol = "udp"
	// Both carries TCP and UDP on the same endpoint in one rule, for services like
	// DNS that speak both on the same port.
	Both Protocol = "both"
)

// Protocols expands a forward's protocol into the concrete transports it occupies:
// one for TCP or UDP, and both for Both. Conflict detection and the port scanner
// key off this so a "both" rule is seen to own the port on each stack.
func (p Protocol) Protocols() []Protocol {
	if p == Both {
		return []Protocol{TCP, UDP}
	}
	return []Protocol{p}
}

// CarriesUDP reports whether a forward on this protocol has a UDP side, which is
// what decides whether the UDP session timeout applies.
func (p Protocol) CarriesUDP() bool { return p == UDP || p == Both }

// CarriesTCP reports whether a forward on this protocol has a TCP side.
func (p Protocol) CarriesTCP() bool { return p == TCP || p == Both }

// ProtocolsOverlap reports whether two forwards' transports intersect, so a "both"
// forward is seen to share an endpoint with a tcp-only or udp-only one.
func ProtocolsOverlap(a, b Protocol) bool {
	return (a.CarriesTCP() && b.CarriesTCP()) || (a.CarriesUDP() && b.CarriesUDP())
}

// Defaults applied on first run and whenever a field is left empty.
const (
	DefaultHostnameTemplate = "app-tail-{hostname}"
	DefaultTag              = "tag:app-tail"
	DefaultUIListenAddr     = "127.0.0.1:0"
	DefaultBindAddr         = "127.0.0.1"
	// TailscaleControlURL is Tailscale's own coordination server, which the node uses
	// when no other is configured. It is shown as the control-URL field's example
	// rather than being stored, so an empty setting keeps meaning "whatever the
	// tailscale library defaults to" instead of pinning a URL we would have to track.
	TailscaleControlURL   = "https://controlplane.tailscale.com"
	DefaultUDPTimeoutSec  = 90
	DefaultUDPBufferBytes = 65535
	// DefaultProxyListenAddr is fixed rather than ephemeral so every snippet, PAC
	// file and shell export that names it stays correct across restarts. 1080 is the
	// registered SOCKS port. A conflict falls back to an ephemeral port, which is
	// then persisted here.
	DefaultProxyListenAddr = "127.0.0.1:1080"
	// DefaultProxyDialTimeoutSec covers a first connection to a cold peer, which
	// negotiates a path and may settle for DERP before any byte moves.
	DefaultProxyDialTimeoutSec = 30
	// DefaultAutoMapPortBase starts the automatic mappings well above anything a
	// developer runs by habit and below the ephemeral range every OS allocates from,
	// so a mapping neither collides with a local service nor gets taken by one.
	DefaultAutoMapPortBase = 14000
	// DefaultAutoMapMax bounds how many mappings exist at once. A large tailnet times
	// several ports is hundreds of listeners, which is a resource cost nobody asked
	// for; over the limit the surplus is reported rather than silently dropped.
	DefaultAutoMapMax = 32
	// DefaultExitNodeRotateIntervalSec is fifteen minutes: long enough that an ordinary
	// download or SSH session is not routinely cut in half, short enough that no single
	// exit node sees a whole afternoon of traffic.
	DefaultExitNodeRotateIntervalSec = 900
	// MinExitNodeRotateIntervalSec is a floor rather than advice. Every switch drops
	// every connection through the old node, so a rotation measured in seconds is a
	// denial of service this device would be running against itself.
	MinExitNodeRotateIntervalSec = 60
	// DefaultExitNodeRotateMaxDeferrals bounds how many turns a busy machine may skip
	// before rotating anyway. Three at the default interval is roughly an hour, after
	// which "wait for idle" has plainly stopped being a wait.
	DefaultExitNodeRotateMaxDeferrals = 3
	// DefaultAutoMapPort is what a device is mapped on when nothing else is asked for.
	// SSH is the one port worth reaching on an arbitrary device, and the one whose
	// client reads a fixed local port out of a config file.
	DefaultAutoMapPort = 22
	// DefaultSystemDNSListenAddr is where app-tail's own resolver listens when nothing
	// else is asked for, and what this machine's network services are pointed at.
	//
	// Not 127.0.0.1: a machine already running something there -- dnsmasq, a container
	// runtime, another DNS client -- would have that thing displaced by whichever of the
	// two started second. Every address in 127/8 is loopback with no interface alias to
	// add, so a less contended one costs nothing.
	DefaultSystemDNSListenAddr = "127.0.0.153:53"
	// DefaultSystemDNSProfile is the profile a fresh install carries: the one that leaves
	// this machine resolving names exactly as it does now.
	DefaultSystemDNSProfile = "system"
	// DefaultSystemDNSBootstrapProfile is what a resolver named by hostname is looked up
	// through. Quad9 because that lookup is the one query the chosen resolver cannot answer
	// for itself, and leaving it to the network's own resolver leaves the network deciding
	// which address answers for the name -- which makes the chosen resolver unreachable,
	// the certificate being checked against the hostname regardless. Quad9 answers at a
	// literal address over HTTPS, so it needs no lookup of its own and nothing on the path
	// can answer for it.
	DefaultSystemDNSBootstrapProfile = "quad9"
	// DefaultDNSZone is the parent every connection's name suffix hangs under.
	//
	// "internal" is the top-level domain ICANN reserved for private use and will never
	// delegate, so a name under it cannot collide with a real one. Deliberately not
	// ".local", which multicast DNS owns, and not an unreserved label that a future
	// delegation would turn into somebody else's namespace.
	DefaultDNSZone = "internal"
	// DefaultDNSBlockList is the list a fresh install carries. It is named here rather
	// than only in the catalog because a default is part of the settings registry, which
	// the catalog imports; the catalog is where it is described.
	DefaultDNSBlockList = "hagezi-pro"
	// DefaultDNSBlockAnswer is what a blocked name is answered with when nothing else is
	// asked for. "No such name" is what every filtering resolver answers, so a program
	// that meets it takes the path it already has for a name that does not exist, rather
	// than spending a connection attempt and a timeout on an address that answers nothing.
	DefaultDNSBlockAnswer = "nxdomain"
	// DefaultDNSBlockRefreshHours is how old a downloaded list may get before it is
	// fetched again. Hourly is affordable because the fetch is conditional: a list that
	// has not been rebuilt answers 304 and costs one round trip rather than a download.
	// The list that matters most here is a threat feed, and a day-old threat feed is a
	// day of names nobody is blocking yet.
	DefaultDNSBlockRefreshHours = 1
	// MinDNSBlockRefreshHours is a floor rather than advice: a list re-fetched every few
	// minutes is a machine hammering somebody else's server for a file that has not
	// changed.
	MinDNSBlockRefreshHours = 1
	// MaxDNSBlockRefreshHours is a month, past which "refreshed on a schedule" has stopped
	// being true and a list is better described as pinned.
	MaxDNSBlockRefreshHours = 720
	// DefaultIPSMode is what traffic inspection does with a match before the user has said
	// otherwise: record it and carry it. An inspector that starts refusing connections on
	// the day it is switched on is one whose first false positive is a machine that has
	// stopped working, found by a user who has no reason yet to suspect this feature.
	DefaultIPSMode = "detect"
	// IPSModeDetect records a match and carries the connection.
	IPSModeDetect = "detect"
	// IPSModePrevent refuses a matched connection before anything is dialled.
	IPSModePrevent = "prevent"
	// DefaultIPSRefreshHours is how old a downloaded address feed may get before it is
	// fetched again. A day rather than the blocklists' hour: these feeds are rebuilt daily
	// at best, and an address that was hosting malware an hour ago still is.
	DefaultIPSRefreshHours = 24
	// MaxIPSRefreshHours is a month, past which "refreshed on a schedule" has stopped being
	// true and a feed is better described as pinned.
	MaxIPSRefreshHours = 720
	// DefaultIPSIntercept is what encrypted connections are opened before the user has said
	// otherwise: none of them. It is the only default this may have. Opening a connection
	// means presenting a certificate this machine made in place of the real server's, which
	// is a thing to do on purpose and never a thing to arrive at by upgrading.
	DefaultIPSIntercept = "off"
	// IPSInterceptOff opens nothing.
	IPSInterceptOff = "off"
	// IPSInterceptOnly opens the destinations named and nothing else.
	IPSInterceptOnly = "only"
	// IPSInterceptExcept opens everything except the destinations named.
	IPSInterceptExcept = "except"
	// DefaultEventRetentionDays is how long a log entry survives with nothing configured.
	// A month covers "it did this again last week" without the log ever becoming a
	// record of the machine's whole year.
	DefaultEventRetentionDays = 30
	// AppDirName is the subdirectory of the OS user-config dir holding state and config.
	AppDirName = "app-tail"
	// ConfigFileName lives inside the state dir.
	ConfigFileName = "config.json"
	// RedactedSecret is what the API returns in place of a stored secret.
	RedactedSecret = "********"
)

// Settings holds process-wide configuration. Secrets are write-only across the API:
// they are stored here but never serialized outward (see Redacted).
type Settings struct {
	StateDir string `json:"stateDir"`
	UIListen string `json:"uiListenAddr"`

	// AdvancedNetworking is the switch for the module owning each connection's control
	// URL. It is off on a fresh install so the settings for a self-hosted coordination
	// server stay out of the way of the many more people who use Tailscale's. It is
	// global rather than per-connection because it is a statement about how much of the
	// app this installation wants on screen, not about any one network.
	AdvancedNetworking bool `json:"advancedNetworking"`

	// ProxyEnabled is the switch for the module below it. Off on a fresh install: a
	// bound proxy port lets any process on this machine reach everything this node's
	// ACLs allow, which is a far broader grant than the per-port forwards and has to
	// be asked for.
	//
	// Where each instance binds, what it will reach and what it demands to be shown are
	// per-instance and live on the instance; this switch is the one fact about the
	// installation, and it decides whether any of them run at all.
	ProxyEnabled bool `json:"proxy.enabled"`
	// ProxySystem asks this machine's own proxy configuration to point at the proxy,
	// so programs that read it need no per-program setup. Off by default, and on most
	// platforms it is advice rather than an action -- see internal/sysproxy.
	ProxySystem bool `json:"proxy.system"`

	// AutoMapEnabled is the switch for the module below it. Off on a fresh install:
	// it opens a listener per peer-and-port pair, which is a visible change to the
	// machine that has to be asked for.
	AutoMapEnabled bool `json:"automap.enabled"`
	// AutoMapPorts are the remote ports mapped on every peer.
	AutoMapPorts []string `json:"automap.ports"`
	// AutoMapMax bounds how many mappings exist at once; the surplus is reported.
	AutoMapMax int `json:"automap.max"`
	// AutoMapPortBase is where the search for a free local port starts.
	AutoMapPortBase int `json:"automap.portBase"`

	// RoutesEnabled is the switch for the routing module. What it governs are each
	// connection's own node preferences, so they reach a tailnet rather than only this
	// process -- which is why they are opt-in like every other module. The switch is
	// global because a module decides how much of the app is on screen, which is a
	// statement about this installation rather than about any one network.
	RoutesEnabled bool `json:"routes.enabled"`

	// ExitNodeEnabled is the switch for the exit-node module, whose settings are each
	// connection's own node preferences.
	ExitNodeEnabled bool `json:"exitNode.enabled"`

	// DNSEnabled is the switch for the DNS module, whose one setting is each
	// connection's own node preference.
	DNSEnabled bool `json:"dns.enabled"`
	// DNSZone is the parent of every connection's own name suffix, so a host on the
	// connection whose short name is "office" is db.office.<zone>. It is what makes two
	// networks that carry the same addresses both reachable by name at once: the address
	// is ambiguous and the name is not.
	DNSZone string `json:"dns.zone"`

	// SystemDNSEnabled is the switch for the machine-wide resolver, which is a different
	// feature from the one above and deliberately a different module: this one changes how
	// every program on this machine resolves names, and it works with no tailnet at all.
	SystemDNSEnabled bool `json:"systemDns.enabled"`
	// SystemDNSProfile is which set of resolvers the machine is pointed at, by the id of a
	// profile in DNSProfiles or of one of the built-ins. "system" is the profile that
	// changes nothing.
	SystemDNSProfile string `json:"systemDns.profile"`
	// SystemDNSBootstrapProfile is the profile whose resolvers look up a resolver named by
	// hostname, by id, on the same catalog as SystemDNSProfile. "system" means the network's
	// own resolvers do it. Only the entries in it that carry a literal address are used: one
	// named by hostname would need the lookup it is there to perform.
	SystemDNSBootstrapProfile string `json:"systemDns.bootstrapProfile"`
	// SystemDNSLocalSuffixes are name suffixes that go to the network's own resolver
	// rather than to the chosen profile, on top of the ones app-tail routes there by
	// shape. It is what makes a name that exists only on this network keep resolving.
	SystemDNSLocalSuffixes []string `json:"systemDns.localSuffixes"`
	// SystemDNSRetryOnNXDOMAIN asks the network's own resolver again for a name the
	// chosen profile said does not exist. Off, because a resolver that filters a domain
	// filters it by answering that it does not exist, and asking a second resolver is how
	// a blocklist stops blocking.
	SystemDNSRetryOnNXDOMAIN bool `json:"systemDns.retryOnNxdomain"`
	// SystemDNSListenAddr is where app-tail's own resolver listens and what this machine
	// is pointed at. It is loopback, so nothing off this machine can reach it, and it is
	// settable because something else on a given machine may already hold the default.
	SystemDNSListenAddr string `json:"systemDns.listenAddr"`

	// DNSBlockEnabled is the switch for the blocking module. The two switches below say
	// where blocking applies; this one says whether the lists are fetched and compiled
	// at all.
	DNSBlockEnabled bool `json:"dnsBlock.enabled"`
	// DNSBlockOwn filters what app-tail itself resolves, which is everything its proxies
	// dial by name. A forward hands its target straight to a dialer and never passes
	// that point, so a forward is not filtered.
	DNSBlockOwn bool `json:"dnsBlock.own"`
	// DNSBlockSystem filters what this machine resolves. It reaches nothing unless the
	// machine-wide resolver above is also on, since that is what points the machine at
	// app-tail in the first place.
	DNSBlockSystem bool `json:"dnsBlock.system"`
	// DNSBlockLists are the ids of the lists that are switched on, from the built-in
	// catalog or from Blocklists.
	DNSBlockLists []string `json:"dnsBlock.lists"`
	// DNSBlockAnswer is what a blocked name is answered with: "nxdomain", "sinkhole" or
	// "refused".
	DNSBlockAnswer string `json:"dnsBlock.answer"`
	// DNSBlockRefreshHours is how old a list may get before it is fetched again.
	DNSBlockRefreshHours int `json:"dnsBlock.refreshHours"`
	// DNSBlockAllow are names never blocked, whatever any list says. It is what a false
	// positive is fixed with, so it beats every list.
	DNSBlockAllow []string `json:"dnsBlock.allow"`
	// DNSBlockDeny are names always blocked, with no list involved.
	DNSBlockDeny []string `json:"dnsBlock.deny"`

	// IPSEnabled is the switch for traffic inspection. The switches below say which
	// signals are examined; this one says whether the rules are compiled at all.
	IPSEnabled bool `json:"ips.enabled"`
	// IPSMode is what happens to a connection that matches: "detect" records it and
	// carries it, "prevent" refuses it.
	IPSMode string `json:"ips.mode"`
	// IPSNames examines the name a program asked for, which is what the proxy and
	// app-tail's own resolver see. A connection dialled straight at an address never had
	// a name here, so it is the switch below that reaches it.
	IPSNames bool `json:"ips.names"`
	// IPSDestinations examines where a connection is bound, which is all the network
	// interface and the subnet router ever have.
	IPSDestinations bool `json:"ips.destinations"`
	// IPSAnomaly watches what a series of connections adds up to rather than what any one
	// of them is bound for: port scans, fanning out, and data leaving inside DNS queries.
	// It matches against no list, so it is the one signal that works on a fresh install.
	//
	// It is the only part of inspection that keeps a record of where traffic went, held in
	// memory for a minute and never written down, which is why it has a switch of its own.
	IPSAnomaly bool `json:"ips.anomaly"`
	// IPSHandshake reads the opening bytes of a connection, which is where the name lives
	// on traffic dialled straight at an address: the server name inside a TLS hello and the
	// host of a plain HTTP request. It is the only signal that reaches a program that never
	// asked app-tail's resolver for anything.
	//
	// It reads a few kilobytes at the start of each connection and nothing after, so what it
	// costs is paid once per connection rather than per byte carried.
	IPSHandshake bool `json:"ips.handshake"`
	// IPSFingerprints records which family of TLS software opened a connection, alongside
	// the name it asked for. It is a note on a finding rather than something matched
	// against: the fingerprint describes the program, is shared by everything built on the
	// same library, and is changed by anyone who wants it changed.
	IPSFingerprints bool `json:"ips.fingerprints"`
	// IPSPayload reads the same opening bytes against the patterns in IPSSignatures, which is
	// the only part of inspection that looks at what a connection carries rather than at
	// where it is going. It needs IPSHandshake: there is no window to read without it.
	IPSPayload bool `json:"ips.payload"`
	// IPSSignatures are the byte patterns matched against what a connection carries, written
	// as a name, an equals sign, and the bytes as a quoted string.
	//
	// There is no feed behind these and no built-in set. No maintained corpus of stream
	// signatures exists to download, so what is matched against is the user's own -- which is
	// what makes this the one control that can answer whether a particular string left this
	// machine in the clear.
	IPSSignatures []string `json:"ips.signatures"`
	// IPSLists are the ids of the address feeds that are switched on, from the built-in
	// catalog or from IPSFeeds.
	IPSLists []string `json:"ips.lists"`
	// IPSRefreshHours is how old a feed's downloaded copy may get before it is fetched
	// again.
	IPSRefreshHours int `json:"ips.refreshHours"`
	// IPSAllow are names and networks never matched, whatever any rule says. It is what a
	// false positive is fixed with, so it beats every other entry.
	IPSAllow []string `json:"ips.allow"`
	// IPSDeny are names and networks always matched. Each entry is a domain, an address,
	// or a network in CIDR form.
	IPSDeny []string `json:"ips.deny"`
	// IPSIntercept is which encrypted connections are opened so what they carry can be read:
	// "off", "only" the destinations in IPSInterceptOnly, or everything "except" the ones in
	// IPSInterceptExcept.
	//
	// Opening a connection means terminating it here and presenting a certificate signed by a
	// root this machine generated, which works only on machines where somebody has installed
	// that root themselves. Nothing happens until IPSInterceptAgreed is also set.
	IPSIntercept string `json:"ips.intercept"`
	// IPSInterceptAgreed records the person using this machine having read what interception
	// does and asked for it. It is separate from the mode so that no upgrade, import or
	// restored settings file can start it: a mode without this is a mode that opens nothing.
	IPSInterceptAgreed bool `json:"ips.interceptAgreed"`
	// IPSInterceptOnly are the destinations opened in "only" mode, in the same form as
	// IPSDeny.
	IPSInterceptOnly []string `json:"ips.interceptOnly"`
	// IPSInterceptExcept are the destinations left alone in "except" mode. Empty is the
	// shipped list, which covers the software that verifies its own certificates and breaks
	// when it is opened; a list written here replaces it entirely.
	IPSInterceptExcept []string `json:"ips.interceptExcept"`

	// SecurityEnabled is the switch for the security module, whose settings are each
	// connection's own node preferences.
	SecurityEnabled bool `json:"security.enabled"`

	// InterfaceEnabled is the switch for the one module that changes the machine rather than
	// only this process. Everything else app-tail offers is contained: this installs a
	// network interface, routes and resolver files that outlive a crash, so it is the
	// only module whose switch is also a change to what the README promises.
	InterfaceEnabled bool `json:"interface.enabled"`
	// InterfaceMode is which stack the connections are reached over. Userspace is what the
	// app installs as; "tun" puts the tailnet on an interface of its own, and "fabric" puts
	// every connection on one interface at once.
	InterfaceMode NetworkMode `json:"interface.mode"`
	// InterfaceName is the interface to create, empty for the platform default. It
	// exists because a fixed name is what makes an abandoned interface identifiable
	// after an unclean exit, which is what `app-tail tun doctor` reports on.
	InterfaceName string `json:"interface.name"`
	// InterfaceVirtualPool are the ranges a connection is presented from when its own addresses
	// are already taken, empty for the built-in pool. It is configurable because the whole
	// point of moving a network is that its real addresses collided with something, and
	// the built-in pool can collide too on a machine that is already using it.
	InterfaceVirtualPool []netip.Prefix `json:"interface.virtualPool"`

	// TailnetRouteRepair puts back the route for the tailnet's own address range when this
	// machine loses it while still carrying the tailnet's addresses.
	//
	// On by default, because the state it repairs is one nothing else on the machine reports
	// and nothing else on the machine fixes: the tailnet client goes on saying it is
	// connected, its own probes to every peer keep answering, and every ordinary program
	// sending tailnet traffic gets a timeout. It is a setting at all because it is app-tail
	// writing a route for a client that is usually not app-tail's own.
	TailnetRouteRepair bool `json:"tailnet.repairRoutes"`

	// EgressMode is where traffic no connection carries leaves through, and EgressTunnelID
	// which connection when that is one of them. The pair is deliberately two fields: a
	// connection id left behind by a choice that has since been changed back must not
	// silently become the answer again the next time the mode is switched over.
	EgressMode EgressMode `json:"egress.mode"`
	// EgressTunnelID is the connection carrying internet-facing traffic. It is read only
	// while EgressMode is EgressTunnel.
	EgressTunnelID string `json:"egress.tunnelId"`
	// EgressMultiTunnelIDs are the connections carrying it together, read only while
	// EgressMode is EgressMulti. Empty means every connection that is running, which is
	// what somebody switching the mode on without choosing anything means by it.
	//
	// It is a list of ids rather than a set because the order is the user's own and is the
	// order a chain is built in; spread reads only the membership.
	EgressMultiTunnelIDs []string `json:"egress.multi.tunnelIds"`
	// EgressMultiShape is how those connections carry it together, read only while
	// EgressMode is EgressMulti. One list serves both shapes: a second field for the chain's
	// order would be the same fact stored twice, and the two would disagree.
	EgressMultiShape EgressShape `json:"egress.multi.shape"`
	// EgressKillSwitch holds internet traffic here rather than letting it out over this
	// machine's own network when the connection chosen to carry it cannot. It is read only
	// while EgressMode is EgressTunnel: carrying the traffic across several connections is
	// held whether or not this is on, and sending it out of this machine directly is the
	// setting that says the machine's own network is where it goes.
	EgressKillSwitch bool `json:"egress.killSwitch"`

	// TrafficLatency asks the agent to measure the round trip to each device. Off by
	// default: it is the only part of the traffic view that sends packets rather than
	// only counting the ones already crossing.
	TrafficLatency bool `json:"traffic.latency"`

	// TrafficSmooth draws the graphs from a running mean of each reading and the six before
	// it rather than from the raw per-second readings. On by default: a once-a-second rate
	// is spiky enough that the shape of a transfer is hard to see through the sampling
	// noise. It changes only what is drawn -- the figures the agent reports are the
	// measured ones either way.
	TrafficSmooth bool `json:"traffic.smooth"`

	// TelemetryEnabled is the switch for the log of what the agent did. Off by default
	// like every other module: an app that starts recording its own history without
	// being asked has decided something about the user's machine on their behalf.
	TelemetryEnabled bool `json:"telemetry.enabled"`
	// TelemetryEventRetentionDays is how long an entry survives. The log is also bounded
	// by a fixed number of entries, so this is the limit that binds on a quiet machine
	// and the size limit is the one that binds on a busy one.
	TelemetryEventRetentionDays int `json:"telemetry.eventLog.retentionDays"`

	StartAtLogin      bool `json:"startAtLogin"`
	ShowTray          bool `json:"showTray"`
	AutoOpenDashboard bool `json:"autoOpenDashboard"`

	UDPSessionTimeoutSec int `json:"udpSessionTimeoutSec"`
	UDPBufferBytes       int `json:"udpBufferBytes"`

	// MachineID is generated once per install and feeds the {id} hostname token.
	MachineID string `json:"machineId"`

	// Shelved holds what a module's settings were at the moment its switch went off,
	// keyed by the field's JSON key, so turning the module back on returns the
	// configuration rather than a set of defaults. Secrets are never shelved: turning a
	// module off forgets its credentials, and a copy of one that no surface shows and no
	// switch reaches would be exactly that.
	//
	// It is not a registry field. Nothing chooses these values, so nothing can present
	// them: they are the app's own record of what it took away.
	Shelved map[string]json.RawMessage `json:"shelvedSettings,omitempty"`
}

// Forward is one persisted port mapping.
type Forward struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// TunnelID is the connection this forward crosses: which private network the target
	// is on, or which one the service is published to. A document written before there
	// could be more than one carries nothing here, and applyDefaults reads that as the
	// only connection there was.
	TunnelID   string    `json:"tunnelId,omitempty"`
	Direction  Direction `json:"direction"`
	Protocol   Protocol  `json:"protocol"`
	BindAddr   string    `json:"bindAddr"`
	ListenPort int       `json:"listenPort"`
	Target     string    `json:"target"`
	Enabled    bool      `json:"enabled"`
	// UDPTimeoutSec of 0 inherits Settings.UDPSessionTimeoutSec.
	UDPTimeoutSec int `json:"udpTimeoutSec"`
	// ExposeToNetwork lets a to_local forward bind an address other machines can reach.
	// The port answers everything on those networks with no authentication in front of
	// it, so it takes this explicit yes rather than following from the address alone.
	ExposeToNetwork bool `json:"exposeToNetwork"`
}

// Connection is the id of the connection this forward crosses. A stored document has it
// filled in, so this only answers for a forward assembled in memory -- and it answers the
// way the document would have been filled, which is what keeps one rule for what an
// unnamed connection means.
func (f Forward) Connection() string {
	if f.TunnelID == "" {
		return PrimaryTunnelID
	}
	return f.TunnelID
}

// Config is the whole config.json document.
type Config struct {
	// Version is the document's shape, migrated forward once on load. A document with
	// no version is the shape that predates connections being data; see migrate.go.
	Version  int      `json:"version,omitempty"`
	Settings Settings `json:"settings"`
	// Tunnels are the private networks this app connects to. Every install has at least
	// the one it was built around; the migration synthesizes it from the settings that
	// used to describe the only tailnet there could be.
	Tunnels []Tunnel `json:"tunnels,omitempty"`
	// Proxies are the loopback listeners local programs reach those networks through,
	// each with its own permissions. Every install has at least the one the migration
	// synthesizes from the settings that used to describe the only proxy there could be.
	Proxies []ProxyInstance `json:"proxies,omitempty"`
	// Routes are the per-destination exceptions to where this machine's internet traffic
	// goes. The egress setting is the one answer for everything no private network
	// carries; these name the destinations that go another way. An empty list is the
	// ordinary install and changes nothing.
	Routes   []routing.Rule `json:"routes,omitempty"`
	Forwards []Forward      `json:"forwards"`
	// Presets holds user-defined service templates alongside the built-in catalog.
	Presets []Preset `json:"presets"`
	// DNSProfiles holds user-defined resolver sets alongside the built-in catalog.
	DNSProfiles []DNSProfile `json:"dnsProfiles"`
	// Blocklists holds user-added domain blocklists alongside the built-in catalog.
	// Which of them are switched on is a setting, not a field here, so a list can be
	// kept without being applied.
	Blocklists []Blocklist `json:"blocklists,omitempty"`
	// IPSFeeds holds user-added address feeds alongside the built-in catalog, on the same
	// terms as Blocklists: which of them are switched on is a setting, so a feed can be
	// kept without being downloaded.
	IPSFeeds []IPSFeed `json:"ipsFeeds,omitempty"`
	// AutoMap is the local port assigned to each peer-and-port pair the automatic
	// mapping module has produced, keyed "<tunnelID>/<stableNodeID>/<remotePort>" --
	// the connection is part of the key because a device id is only unique within the
	// network that issued it. It is stored
	// rather than recomputed because a local port that moved between runs would break
	// every bookmark and ssh_config entry naming it -- and point at a different peer.
	AutoMap map[string]int `json:"autoMap,omitempty"`
	// AutoMapOff are the derived forwards, by the id the module gives them, that somebody
	// switched off. The module still produces them, so the row stays on screen and can be
	// switched back on, and the assignment above still holds the port -- a device switched
	// off must not lose the number every bookmark naming it uses.
	//
	// It is a list of ids rather than of assignment keys because the id is what a click on
	// the row carries, and it is a function of the connection, the device and the remote
	// port -- so it survives a restart and an assignment that was forgotten and made again.
	AutoMapOff []string `json:"autoMapOff,omitempty"`
}

// Preset is a service template used to prefill the add-forward flow.
type Preset struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Protocol   Protocol `json:"protocol"`
	RemotePort int      `json:"remotePort"`
	// BuiltIn entries ship with the binary and cannot be deleted.
	BuiltIn bool `json:"builtIn"`
}

// DNSProfile is one set of upstream resolvers the system-wide switch can point this
// machine at.
//
// Servers are in order and the order is the whole meaning: the first is the one every
// name goes to, and the rest are tried only when it does not answer at all. A backup is
// a fallback for an unreachable server, never a second opinion on an answer -- an answer
// of "no such name" is the answer, which is what keeps a filtering resolver filtering.
type DNSProfile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Servers are addresses, tls:// endpoints or https:// endpoints. The grammar lives
	// in internal/dnsprofiles, which is also what dials them.
	Servers []string `json:"servers,omitempty"`
	// BuiltIn entries ship with the binary and can be neither edited nor deleted.
	BuiltIn bool `json:"builtIn"`
}

// Blocklist is one list of domains app-tail refuses to resolve.
//
// A list is a file somebody else maintains, fetched on a schedule and kept on disk so it
// keeps blocking when the network it came from is unreachable. Format says how its lines
// are written; the grammar lives in internal/dnsblock, which is also what compiles it.
type Blocklist struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	// Format is "hosts", "abp", or "auto" to read the file and decide.
	Format string `json:"format,omitempty"`
	// BuiltIn entries ship with the binary and can be neither edited nor deleted. They
	// can be switched on and off like any other, which is the whole point of shipping
	// them.
	BuiltIn bool `json:"builtIn"`
}

// IPSFeed is one list of addresses and networks traffic inspection matches connections
// against.
//
// It carries no format, unlike a Blocklist: every feed of this kind is one address or one
// network per line with comments, and a feed that is not is one this side cannot use
// whatever it declares.
type IPSFeed struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	// BuiltIn entries ship with the binary and can be neither edited nor deleted. They can
	// be switched on and off like any other, which is the whole point of shipping them.
	BuiltIn bool `json:"builtIn"`
}

// UDPBufferSize resolves the read buffer size for UDP forwards.
func (s Settings) UDPBufferSize() int {
	if s.UDPBufferBytes > 0 {
		return s.UDPBufferBytes
	}
	return DefaultUDPBufferBytes
}

// AutoMapPortList resolves the remote ports to map on every peer. An unset list means
// the default rather than "map nothing": a module switched on that mapped nothing would
// read as broken.
func (s Settings) AutoMapPortList() ([]int, error) {
	if len(s.AutoMapPorts) == 0 {
		return []int{DefaultAutoMapPort}, nil
	}
	return ParsePortList(s.AutoMapPorts)
}

// AutoMapLimit resolves how many mappings may exist at once.
func (s Settings) AutoMapLimit() int {
	if s.AutoMapMax > 0 {
		return s.AutoMapMax
	}
	return DefaultAutoMapMax
}

// AutoMapBase resolves where the search for a free local port starts.
func (s Settings) AutoMapBase() int {
	if s.AutoMapPortBase > 0 {
		return s.AutoMapPortBase
	}
	return DefaultAutoMapPortBase
}

// TunSelected reports whether the node should run on a real network interface. It is the
// module's answer rather than the stored mode alone: a mode left behind by a module that
// was switched off must read as userspace everywhere, because that is the stack the node
// would actually be built on.
func (s Settings) TunSelected() bool {
	return s.InterfaceEnabled && s.InterfaceMode == NetworkTUN
}

// FabricSelected reports whether every connection should be carried on one interface.
//
// It and TunSelected are never both true, and not only because one setting names both: the
// privileged side refuses a second interface, so a machine that tried to run them together
// would have one of them fail to start rather than two interfaces disagreeing about the
// routing table.
func (s Settings) FabricSelected() bool {
	return s.InterfaceEnabled && s.InterfaceMode == NetworkFabric
}

// EgressTunnel is the connection this machine's internet-facing traffic is to leave
// through, or "" for this machine's own network.
//
// It reads the mode rather than the id alone, so a connection named by a choice that was
// later switched back to direct carries nothing: a stored id is a note of what was chosen
// last, and treating it as the answer would send traffic somewhere nobody currently asks
// for.
func (s Settings) EgressTunnel() string {
	if s.EgressMode != EgressTunnel {
		return ""
	}
	return s.EgressTunnelID
}

// EgressSpread reports that this machine's internet traffic is spread across several
// connections, and names the ones chosen. An empty list with true is "every connection that
// is running", which is what the mode means when nothing was picked.
//
// The two are returned together because the empty list means two opposite things depending on
// the mode: nothing chosen while spreading is every connection, and nothing chosen while not
// spreading is nothing at all.
func (s Settings) EgressSpread() (members []string, on bool) {
	if s.EgressMode != EgressMulti || s.EgressMultiShape == EgressCascade {
		return nil, false
	}
	return slices.Clone(s.EgressMultiTunnelIDs), true
}

// EgressShared reports that this machine's internet traffic is carried by several connections
// together, whichever shape they carry it in, and names the ones chosen.
//
// It is what the surfaces that treat the two shapes alike ask: which connections are part of
// this, and is any connection outside the set carrying anything. How they carry it is
// EgressSpread's and EgressChain's question.
func (s Settings) EgressShared() (members []string, on bool) {
	if s.EgressMode != EgressMulti {
		return nil, false
	}
	return slices.Clone(s.EgressMultiTunnelIDs), true
}

// EgressChain reports that this machine's internet traffic goes through several connections
// in order, and names them in that order: the first carries the second's own packets, and the
// traffic leaves through the last.
//
// A chain has no "every connection that is running" reading. Order is the whole of what a
// chain is, and a set of connections nobody put in an order does not have one, so an empty
// list is refused where it is written rather than resolved to something here.
func (s Settings) EgressChain() (hops []string, on bool) {
	if s.EgressMode != EgressMulti || s.EgressMultiShape != EgressCascade {
		return nil, false
	}
	return slices.Clone(s.EgressMultiTunnelIDs), true
}

// EgressExit is the one connection this machine's internet traffic finally leaves through
// while it is chained, which is the last hop. Everything before it carries the hop after it
// and nothing else.
func (s Settings) EgressExit() string {
	hops, chained := s.EgressChain()
	if !chained || len(hops) == 0 {
		return ""
	}
	return hops[len(hops)-1]
}

// EgressCarrierOf is the connection whose own packets carry this one's, and "" for a
// connection that sends its packets over this machine's own network.
//
// Only a chain produces one: spreading gives every chosen connection this machine's own
// network to leave by, which is what lets them run at their own speeds at the same time.
func (s Settings) EgressCarrierOf(id string) string {
	hops, chained := s.EgressChain()
	if !chained {
		return ""
	}
	for i, hop := range hops {
		if hop == id && i > 0 {
			return hops[i-1]
		}
	}
	return ""
}

// EgressHeld reports that traffic no connection carries must be held rather than sent out
// over this machine's own network when nothing is available to carry it.
//
// Carrying the traffic across several connections is always held: choosing several is a
// statement about who may see the traffic, and falling back to the ISP link would answer that
// statement with the one destination it excludes.
//
// Sending it through one connection keeps its documented behaviour -- what is chosen there is
// a route, and a route that is down leaves the machine on the network it was already on --
// until the kill switch says otherwise, which is the whole of what that switch is for.
//
// Going out of this machine directly is never held whatever the switch says. That mode is the
// statement that this machine's own network is where the traffic goes, so there is nothing to
// hold it from.
func (s Settings) EgressHeld() bool {
	switch s.EgressMode {
	case EgressMulti:
		return true
	case EgressTunnel:
		return s.EgressKillSwitch
	default:
		return false
	}
}

// InterfaceSelected reports whether this machine is to be put on the networks at all, by
// either of the two ways of doing it. It is what the paths that care about the privileged
// helper ask, rather than either mode by name.
func (s Settings) InterfaceSelected() bool {
	return s.TunSelected() || s.FabricSelected()
}

// InterfaceModeChosen is the mode the interface switch turns on: the stored mode while the
// module is on, and while it is off the one the shelf remembers for it, which is what the
// switch puts back. The stored mode is at its default the whole time the module is off, so
// a client deciding what to write beside the switch reads this instead: a machine arranged
// for the one-interface mode keeps that arrangement across a switch off and on.
func (s Settings) InterfaceModeChosen() NetworkMode {
	if s.InterfaceEnabled {
		return s.InterfaceMode
	}
	raw, ok := s.Shelved["interface.mode"]
	if !ok {
		return s.InterfaceMode
	}
	var mode NetworkMode
	if err := json.Unmarshal(raw, &mode); err != nil || !slices.Contains(NetworkModes, mode) {
		// An entry this build cannot read is one the switch would drop rather than restore,
		// so it is not what the switch turns on.
		return s.InterfaceMode
	}
	return mode
}

// SortPrefixes returns the prefixes in a stable order, or nil when there are none. The
// order is what makes two route lists comparable: the set is what matters, and a stored
// list the user typed in a different order than the node reports them in is the same
// advertisement, not a change to push.
func SortPrefixes(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	return out
}

// Clone returns a deep copy so callers can hand out snapshots without sharing slices.
func (c *Config) Clone() *Config {
	out := &Config{Version: c.Version, Settings: c.Settings}
	// A connection carries a pointer to its type's own settings, so cloning the slice
	// alone would hand every snapshot the same block and an edit to one connection's
	// device name would appear in all of them.
	if c.Tunnels != nil {
		out.Tunnels = make([]Tunnel, len(c.Tunnels))
		for i, t := range c.Tunnels {
			out.Tunnels[i] = t.Clone()
		}
	}
	// A proxy instance carries its ordered rule list, and a rule carries its port list, so
	// the same reasoning applies one level deeper: a shallow copy would let a caller
	// reorder a snapshot's rules and change what the running instance allows.
	if c.Proxies != nil {
		out.Proxies = make([]ProxyInstance, len(c.Proxies))
		for i, p := range c.Proxies {
			out.Proxies[i] = p.Clone()
		}
	}
	out.Settings.AutoMapPorts = append([]string(nil), c.Settings.AutoMapPorts...)
	out.Settings.SystemDNSLocalSuffixes = slices.Clone(c.Settings.SystemDNSLocalSuffixes)
	out.Settings.DNSBlockLists = slices.Clone(c.Settings.DNSBlockLists)
	out.Settings.DNSBlockAllow = slices.Clone(c.Settings.DNSBlockAllow)
	out.Settings.DNSBlockDeny = slices.Clone(c.Settings.DNSBlockDeny)
	out.Settings.IPSLists = slices.Clone(c.Settings.IPSLists)
	out.Settings.IPSSignatures = slices.Clone(c.Settings.IPSSignatures)
	out.Settings.IPSAllow = slices.Clone(c.Settings.IPSAllow)
	out.Settings.IPSDeny = slices.Clone(c.Settings.IPSDeny)
	out.Settings.IPSInterceptOnly = slices.Clone(c.Settings.IPSInterceptOnly)
	out.Settings.IPSInterceptExcept = slices.Clone(c.Settings.IPSInterceptExcept)
	out.Settings.InterfaceVirtualPool = slices.Clone(c.Settings.InterfaceVirtualPool)
	out.Settings.EgressMultiTunnelIDs = slices.Clone(c.Settings.EgressMultiTunnelIDs)
	out.Settings.Shelved = maps.Clone(c.Settings.Shelved)
	// A routing rule holds no slice of its own, so one Clone of the list is the whole
	// copy -- but it has to be a copy: order is the meaning here, and a caller reordering
	// a snapshot would reorder where the running machine sends its traffic.
	out.Routes = routing.Clone(c.Routes)
	out.Forwards = append([]Forward(nil), c.Forwards...)
	out.Presets = append([]Preset(nil), c.Presets...)
	// Copied a field at a time rather than with one append: DNSProfile carries a slice,
	// so a shallow copy would hand every snapshot the same backing array and a caller
	// editing one profile's servers would edit them everywhere.
	if c.DNSProfiles != nil {
		out.DNSProfiles = make([]DNSProfile, len(c.DNSProfiles))
		for i, p := range c.DNSProfiles {
			out.DNSProfiles[i] = p
			out.DNSProfiles[i].Servers = slices.Clone(p.Servers)
		}
	}
	out.Blocklists = slices.Clone(c.Blocklists)
	out.IPSFeeds = slices.Clone(c.IPSFeeds)
	out.AutoMap = maps.Clone(c.AutoMap)
	out.AutoMapOff = append([]string(nil), c.AutoMapOff...)
	return out
}

// FindForward returns the forward with the given id and whether it was found.
func (c *Config) FindForward(id string) (Forward, bool) {
	for _, f := range c.Forwards {
		if f.ID == id {
			return f, true
		}
	}
	return Forward{}, false
}

// EnabledForwards returns only the forwards the manager should be running.
func (c *Config) EnabledForwards() []Forward {
	var out []Forward
	for _, f := range c.Forwards {
		if f.Enabled {
			out = append(out, f)
		}
	}
	return out
}
