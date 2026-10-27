// SPDX-License-Identifier: MIT

package config

// What a connection is configurable by. It is a second table over a second entity, and it
// exists rather than living in settingsFields because that table is global: a per-instance
// field there would multiply the CLI flags, the tray menu and the generated schema by the
// number of connections.
//
// Everything the settings table buys, this one inherits -- one validator, one schema, one
// patch decoder, write-only secrets by construction -- so a field added here appears on
// the right form with a label, help, validation and a declared restart cost, and nothing
// per-type is hand-written.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
)

// TunnelField is a field of one stored connection.
type TunnelField = FieldOf[Tunnel]

// tunnelFields is the authored table; its order is the display order.
//
// Type is deliberately read-only. What a connection speaks decides which fields even
// apply to it, so changing it in place would leave the settings of the old type stored
// against an entity that no longer has them; adding a connection of the other type and
// removing this one is the honest shape of that change.
var tunnelFields = []TunnelField{
	{
		JSONKey: "name", Kind: KindString,
		Restart: RestartNone, Write: WritePatch,
		Label: "Name", Group: GroupConnection, Tier: TierBasic,
		Example: "Work",
		Help: "What this connection is called on screen. It has no other meaning: two " +
			"connections may share a name.",
		get:      func(t *Tunnel) any { return t.Name },
		set:      func(t *Tunnel, v any) { t.Name = typed[string](v) },
		validate: displayableName,
	},
	{
		JSONKey: "slug", Kind: KindString,
		Restart: RestartNone, Write: WritePatch,
		Label: "Short name", Group: GroupConnection, Tier: TierBasic,
		Example: "work",
		Help: "The short handle this connection is known by, and the label that will name " +
			"it in DNS. Lowercase letters, digits and hyphens.",
		get:      func(t *Tunnel) any { return t.Slug },
		set:      func(t *Tunnel, v any) { t.Slug = typed[string](v) },
		validate: validateSlugValue,
	},
	{
		JSONKey: "type", Kind: KindEnum,
		Restart: RestartNone, Write: WriteNone,
		Label: "Type", Group: GroupConnection, Tier: TierBasic,
		Options: tunnelTypeOptions(),
		Help:    "What protocol this connection speaks. It is fixed when the connection is added.",
		get:     func(t *Tunnel) any { return string(t.Type) },
	},
	{
		JSONKey: "enabled", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch,
		Label: "Connect to this network", Group: GroupConnection, Tier: TierBasic,
		Default: true,
		Help: "Whether this connection should be up. Switching it off stops it and leaves " +
			"everything you configured in place, which is what to do when you want to stop " +
			"using a network without forgetting it.",
		get: func(t *Tunnel) any { return t.Enabled },
		set: func(t *Tunnel, v any) { t.Enabled = typed[bool](v) },
	},

	// The tailnet fields. Each one is what makes this connection a different device from
	// the next: two connections sharing a name, a key or a coordination server would be
	// one device enrolling twice.
	{
		JSONKey: "hostname", CLIName: "hostname", Kind: KindString, Variant: string(TunnelTailscale),
		Restart: RestartNode, Write: WritePatch, Pinnable: []string{EnvHostname},
		Label: "Device name", Group: GroupIdentity, Tier: TierBasic,
		ExampleFrom: "effectiveHostname",
		Help:        "Device name on the tailnet. Leave empty to render the hostname template.",
		get:         func(t *Tunnel) any { return t.TS().Hostname },
		set:         func(t *Tunnel, v any) { t.ts().Hostname = typed[string](v) },
	},
	{
		JSONKey: "hostnameTemplate", CLIName: "hostname-template", Kind: KindString, Variant: string(TunnelTailscale),
		Restart: RestartNode, Write: WritePatch, Pinnable: []string{EnvHostnameTemplate},
		Label: "Hostname template", Group: GroupIdentity, Tier: TierAdvanced,
		Default: DefaultHostnameTemplate,
		Help:    "Template used when no explicit hostname is set (tokens: {hostname}, {id}).",
		get:     func(t *Tunnel) any { return t.TS().HostnameTemplate },
		set:     func(t *Tunnel, v any) { t.ts().HostnameTemplate = typed[string](v) },
	},
	{
		JSONKey: "effectiveHostname", Kind: KindString, Variant: string(TunnelTailscale),
		Restart: RestartNone, Write: WriteNone, Derived: true,
		Label: "Effective device name", Group: GroupIdentity, Tier: TierBasic,
		Help: "The name this connection actually presents after the template renders " +
			"(read-only).",
		derive: func(t Tunnel, app *Settings) any {
			return EffectiveHostname(t.TS(), app.MachineID)
		},
	},
	{
		JSONKey: "tags", CLIName: "tags", Kind: KindStringList, Variant: string(TunnelTailscale),
		Restart: RestartNode, Write: WritePatch, Pinnable: []string{EnvTags},
		Label: "Tags", Group: GroupIdentity, Tier: TierAdvanced,
		Example: DefaultTag,
		Default: []string{DefaultTag},
		Help: "Tailnet tags to advertise, comma separated. Required when enrolling with " +
			"an OAuth client secret, and the tags must already exist in the tailnet.",
		get:      func(t *Tunnel) any { return append([]string(nil), t.TS().Tags...) },
		set:      func(t *Tunnel, v any) { t.ts().Tags = append([]string(nil), typed[[]string](v)...) },
		validate: tagsAreQualified,
	},
	{
		JSONKey: "advertiseTagsOnLogin", CLIName: "advertise-tags-on-login", Kind: KindBool, Variant: string(TunnelTailscale),
		Restart: RestartNode, Write: WritePatch, Pinnable: []string{EnvAdvertiseTagsOnLogin},
		Label: "Advertise tags on browser login", Group: GroupIdentity, Tier: TierAdvanced,
		Help: "Advertise the tags during an interactive browser login. The signed-in user " +
			"must own them in tagOwners or the login is refused.",
		get: func(t *Tunnel) any { return t.TS().AdvertiseTagsOnLogin },
		set: func(t *Tunnel, v any) { t.ts().AdvertiseTagsOnLogin = typed[bool](v) },
	},
	{
		JSONKey: "authKey", ViewKey: "hasAuthKey", CLIName: "auth-key", Kind: KindSecret, Variant: string(TunnelTailscale),
		Restart: RestartNode, Write: WritePatch, Pinnable: []string{EnvAuthKey, EnvTSAuthKey},
		Label: "Auth key", Group: GroupAuth, Tier: TierBasic,
		Help: "Tailscale auth key for non-interactive enrollment. Write-only: a stored " +
			"key is never sent back out.",
		get:     func(t *Tunnel) any { return t.TS().AuthKey },
		set:     func(t *Tunnel, v any) { t.ts().AuthKey = typed[string](v) },
		present: func(t *Tunnel) bool { return t.TS().EffectiveAuthKey() != "" },
	},
	{
		JSONKey: "oauthClientSecret", ViewKey: "hasOAuthClientSecret", CLIName: "oauth-client-secret",
		Kind:    KindSecret,
		Variant: string(TunnelTailscale),
		Restart: RestartNode, Write: WritePatch,
		Pinnable: []string{EnvOAuthSecret, EnvTSClientSecret},
		Label:    "OAuth client secret", Group: GroupAuth, Tier: TierAdvanced,
		Help: "OAuth client secret for fleet enrollment. Needs only the auth_keys scope, " +
			"restricted to your tag. Write-only.",
		get:     func(t *Tunnel) any { return t.TS().OAuthClientSecret },
		set:     func(t *Tunnel, v any) { t.ts().OAuthClientSecret = typed[string](v) },
		present: func(t *Tunnel) bool { return t.TS().OAuthClientSecret != "" },
	},
	{
		JSONKey: "oauthClientSecretFile", CLIName: "oauth-client-secret-file", Kind: KindSecretFile, Variant: string(TunnelTailscale),
		Restart: RestartNode, Write: WritePatch, Pinnable: []string{EnvOAuthSecretFile},
		Label: "OAuth client secret file", Group: GroupAuth, Tier: TierAdvanced,
		Example: "/path/to/secret",
		Help: "Absolute path to a file holding the OAuth client secret. Read at enrollment " +
			"and preferred over the inline value, so a secrets manager can own it.",
		get:           func(t *Tunnel) any { return t.TS().OAuthClientSecretFile },
		set:           func(t *Tunnel, v any) { t.ts().OAuthClientSecretFile = typed[string](v) },
		validateWrite: absolutePathOrEmpty,
	},
	{
		JSONKey: "controlURL", CLIName: "control-url", Kind: KindURL, Variant: string(TunnelTailscale),
		Restart: RestartNode, Write: WritePatch, Pinnable: []string{EnvControlURL},
		Label: "Control server URL", Group: GroupTailnet, Tier: TierAdvanced,
		Module:  ModuleAdvancedNetworking,
		Example: TailscaleControlURL,
		Help:    "Coordination server URL. Leave empty unless you run Headscale or similar.",
		get:     func(t *Tunnel) any { return t.TS().ControlURL },
		set:     func(t *Tunnel, v any) { t.ts().ControlURL = typed[string](v) },
	},
	{
		JSONKey: "ephemeral", CLIName: "ephemeral", Kind: KindBool, Variant: string(TunnelTailscale),
		Restart: RestartNode, Write: WritePatch, Pinnable: []string{EnvEphemeral},
		Label: "Ephemeral node", Group: GroupTailnet, Tier: TierAdvanced,
		Help: "Remove this device from the tailnet when the agent exits.",
		get:  func(t *Tunnel) any { return t.TS().Ephemeral },
		set:  func(t *Tunnel, v any) { t.ts().Ephemeral = typed[bool](v) },
	},

	// The node preferences. Each one is a request this connection makes of its own node,
	// so two connections hold their own: which subnets to accept, which peer carries the
	// rest of the traffic and what this device tells the network about itself are answers
	// about one tailnet rather than about this machine.
	{
		JSONKey: "exitNode.nodeId", CLIName: "exit-node-id", Kind: KindNodeRef, Variant: string(TunnelTailscale),
		Restart: RestartPrefs, Write: WritePatch, Module: ModuleExitNode,
		Label: "Device to route through", Group: GroupExitNode, Tier: TierBasic,
		OptionsFrom: OptionsExitNodes,
		Help: "The device your traffic leaves from, chosen from the ones your tailnet " +
			"offers as exit nodes. While automatic selection or rotation is on this is " +
			"the device to fall back to rather than the one in use.",
		get: func(t *Tunnel) any { return t.TS().ExitNodeID },
		set: func(t *Tunnel, v any) { t.ts().ExitNodeID = typed[string](v) },
	},
	{
		JSONKey: "exitNode.auto", CLIName: "exit-node-auto", Kind: KindBool, Variant: string(TunnelTailscale),
		Restart: RestartPrefs, Write: WritePatch, Module: ModuleExitNode,
		Label: "Let Tailscale choose", Group: GroupExitNode, Tier: TierBasic,
		Tray: true,
		Help: "Let the tailnet pick the exit node and keep re-picking it. Only devices " +
			"your network marks as suggestable are considered, which on most tailnets " +
			"means Tailscale's own Mullvad nodes rather than one you run yourself.",
		get: func(t *Tunnel) any { return t.TS().ExitNodeAuto },
		set: func(t *Tunnel, v any) { t.ts().ExitNodeAuto = typed[bool](v) },
	},
	{
		JSONKey: "exitNode.allowLanAccess", CLIName: "exit-node-allow-lan", Kind: KindBool, Variant: string(TunnelTailscale),
		Restart: RestartPrefs, Write: WritePatch, Module: ModuleExitNode,
		Label: "Keep reaching this machine's own network", Group: GroupExitNode, Tier: TierBasic,
		Tray: true,
		Help: "Keep the printers, NAS and routers on the network this machine is plugged " +
			"into reachable while the exit node carries everything else. Leaving it off " +
			"is the stricter choice: nothing at all leaves this machine directly.",
		get: func(t *Tunnel) any { return t.TS().ExitNodeAllowLANAccess },
		set: func(t *Tunnel, v any) { t.ts().ExitNodeAllowLANAccess = typed[bool](v) },
	},
	{
		JSONKey: "exitNode.onFailure", CLIName: "exit-node-on-failure", Kind: KindEnum, Variant: string(TunnelTailscale),
		Restart: RestartNone, Write: WritePatch, Module: ModuleExitNode,
		Label: "When it goes offline", Group: GroupExitNode, Tier: TierAdvanced,
		Default: string(FailureHold),
		Options: []EnumOption{
			{
				Value: string(FailureHold), Label: "Stop sending traffic",
				Help: "Keep the device selected. Traffic through app-tail stops until it " +
					"comes back, which is what you want if the exit node is there to keep " +
					"this machine's own address out of it.",
			},
			{
				Value: string(FailureNext), Label: "Move to another exit node",
				Help: "Switch to another device your tailnet offers. Traffic keeps flowing " +
					"and still leaves from the tailnet, but not from the device you chose.",
			},
			{
				Value: string(FailureOff), Label: "Go direct",
				Help: "Stop using an exit node. Connectivity comes back and this machine's " +
					"own address is used again, which gives up what the exit node was for.",
			},
		},
		Help: "What to do when the exit node in use stops being reachable.",
		get:  func(t *Tunnel) any { return string(t.TS().ExitNodeOnFailure) },
		set:  func(t *Tunnel, v any) { t.ts().ExitNodeOnFailure = ExitNodeFailurePolicy(typed[string](v)) },
	},
	{
		JSONKey: "exitNode.rotate.enabled", CLIName: "exit-node-rotate", Kind: KindBool, Variant: string(TunnelTailscale),
		Restart: RestartNone, Write: WritePatch, Module: ModuleExitNode,
		Label: "Move between exit nodes", Group: GroupExitNode, Tier: TierAdvanced,
		Help: "Change exit node on a schedule, so no single one sees all of this device's " +
			"traffic. Every switch drops the connections going through the old device: " +
			"downloads stop, SSH sessions end, and anything tied to the previous address " +
			"has to sign in again.",
		get: func(t *Tunnel) any { return t.TS().ExitNodeRotate },
		set: func(t *Tunnel, v any) { t.ts().ExitNodeRotate = typed[bool](v) },
	},
	{
		JSONKey: "exitNode.rotate.strategy", CLIName: "exit-node-rotate-strategy", Kind: KindEnum, Variant: string(TunnelTailscale),
		Restart: RestartNone, Write: WritePatch, Module: ModuleExitNode,
		Label: "How to choose the next one", Group: GroupExitNode, Tier: TierAdvanced,
		Default: string(RotateRoundRobin),
		Options: []EnumOption{
			{
				Value: string(RotateRoundRobin), Label: "Each in turn",
				Help: "Walk the available devices in a fixed order, so every one of them " +
					"carries a share and the sequence is predictable.",
			},
			{
				Value: string(RotateRandom), Label: "At random",
				Help: "Pick at random from the devices other than the current one, so the " +
					"order carries no pattern.",
			},
			{
				Value: string(RotateLatency), Label: "Fastest first",
				Help: "Prefer whichever device answers fastest right now. This trades some " +
					"of the spread for speed: a consistently close device wins often.",
			},
		},
		Help: "Which exit node the schedule moves to next.",
		get:  func(t *Tunnel) any { return string(t.TS().ExitNodeRotateStrategy) },
		set:  func(t *Tunnel, v any) { t.ts().ExitNodeRotateStrategy = RotateStrategy(typed[string](v)) },
	},
	{
		JSONKey: "exitNode.rotate.intervalSec", CLIName: "exit-node-rotate-interval", Kind: KindInt, Variant: string(TunnelTailscale),
		Restart: RestartNone, Write: WritePatch, Module: ModuleExitNode,
		Label: "How long to stay on one (s)", Group: GroupExitNode, Tier: TierAdvanced,
		Default: DefaultExitNodeRotateIntervalSec, Constraint: between(0, 86400),
		Help: "How long one exit node is used before the next is chosen. The lower limit " +
			"is a minute because every switch drops the connections through the old " +
			"device, and rotating faster than that is an outage this device inflicts on " +
			"itself. Zero uses the default.",
		get:      func(t *Tunnel) any { return t.TS().ExitNodeRotateIntervalSec },
		set:      func(t *Tunnel, v any) { t.ts().ExitNodeRotateIntervalSec = typed[int](v) },
		validate: rotateIntervalSec,
	},
	{
		JSONKey: "exitNode.rotate.pauseOnActive", CLIName: "exit-node-rotate-pause", Kind: KindBool, Variant: string(TunnelTailscale),
		Restart: RestartNone, Write: WritePatch, Module: ModuleExitNode,
		Label: "Wait for connections to finish", Group: GroupExitNode, Tier: TierAdvanced,
		Default: true,
		Help: "Hold a scheduled switch back while connections are still open through the " +
			"current exit node, so a download in progress is not cut off. The hold is " +
			"bounded by the setting below.",
		get: func(t *Tunnel) any { return t.TS().ExitNodeRotatePauseOnActive },
		set: func(t *Tunnel, v any) { t.ts().ExitNodeRotatePauseOnActive = typed[bool](v) },
	},
	{
		JSONKey: "exitNode.rotate.maxDeferrals", CLIName: "exit-node-rotate-max-deferrals", Kind: KindInt, Variant: string(TunnelTailscale),
		Restart: RestartNone, Write: WritePatch, Module: ModuleExitNode,
		Label: "Turns to skip while busy", Group: GroupExitNode, Tier: TierAdvanced,
		Default: DefaultExitNodeRotateMaxDeferrals, Constraint: between(0, 100),
		Help: "How many scheduled switches may be skipped while connections stay open " +
			"before one happens anyway. Without a limit a machine that is never idle " +
			"would keep one exit node forever, which is the opposite of rotating.",
		get: func(t *Tunnel) any { return t.TS().ExitNodeRotateMaxDeferrals },
		set: func(t *Tunnel, v any) { t.ts().ExitNodeRotateMaxDeferrals = typed[int](v) },
	},
	{
		JSONKey: "routes.accept", CLIName: "routes-accept", Kind: KindBool, Variant: string(TunnelTailscale),
		Restart: RestartPrefs, Write: WritePatch, Module: ModuleRouting,
		Label: "Reach networks other devices advertise", Group: GroupRouting, Tier: TierBasic,
		Tray: true,
		Help: "Accept the subnet routes devices on your tailnet advertise, such as a home " +
			"LAN behind a subnet router. Those networks become reachable through app-tail's " +
			"proxy and its port forwards; other programs on this machine will not see them " +
			"unless you point them at the proxy.",
		get: func(t *Tunnel) any { return t.TS().RoutesAccept },
		set: func(t *Tunnel, v any) { t.ts().RoutesAccept = typed[bool](v) },
	},
	{
		JSONKey: "routes.advertise", CLIName: "routes-advertise", Kind: KindCidrList, Variant: string(TunnelTailscale),
		Restart: RestartPrefs, Write: WritePatch, Module: ModuleRouting,
		Label: "Networks to offer the tailnet", Group: GroupRouting, Tier: TierBasic,
		Example: "10.0.0.0/24, 192.168.1.0/24",
		Help: "Private networks this device offers to carry for the rest of your tailnet, " +
			"comma separated. Advertising puts them in the admin console for approval; " +
			"nothing reaches them until an admin approves the routes and you turn on " +
			"carrying traffic below.",
		get:      func(t *Tunnel) any { return t.TS().RoutesAdvertise },
		set:      func(t *Tunnel, v any) { t.ts().RoutesAdvertise = typed[[]netip.Prefix](v) },
		validate: advertisableRoutes,
	},
	{
		JSONKey: "routes.serve", CLIName: "routes-serve", Kind: KindBool, Variant: string(TunnelTailscale),
		Restart: RestartNone, Write: WritePatch, Module: ModuleRouting,
		Label: "Carry traffic for the networks above", Group: GroupRouting, Tier: TierBasic,
		Tray: true,
		Help: "Answer the connections your tailnet sends here for an approved network. " +
			"app-tail routes in userspace, so only TCP is carried: DNS, video calls, " +
			"QUIC, VPNs and file shares all fail across these routes. Connections leave " +
			"this machine from this machine's own address, so the far end sees this " +
			"device rather than the one that called it.",
		get: func(t *Tunnel) any { return t.TS().RoutesServe },
		set: func(t *Tunnel, v any) { t.ts().RoutesServe = typed[bool](v) },
	},
	{
		JSONKey: "routes.netfilter", Kind: KindString, Variant: string(TunnelTailscale),
		Restart: RestartNone, Write: WriteNone,
		Derived: true, Module: ModuleRouting,
		Label: "Firewall and address translation", Group: GroupRouting, Tier: TierAdvanced,
		Help: "The official client configures the host firewall for the routes it carries, " +
			"through settings named no-snat, netfilter-mode and netfilter-kind. app-tail " +
			"has none of them because it never touches the firewall.",
		derive: func(Tunnel, *Settings) any { return NetfilterNotApplicable },
	},
	{
		JSONKey: "routes.advertiseExitNode", CLIName: "advertise-exit-node", Kind: KindBool, Variant: string(TunnelTailscale),
		Restart: RestartPrefs, Write: WritePatch, Module: ModuleRouting,
		Label: AdvertiseExitNodeLabel, Group: GroupRouting, Tier: TierAdvanced,
		Help: "Offer this device to your tailnet as an exit node, for an admin to approve. " +
			"app-tail routes in userspace, so it cannot carry the UDP other devices would " +
			"send through it -- DNS, video calls and QUIC all fail. Useful for exercising " +
			"the approval flow; not a working exit node.",
		get: func(t *Tunnel) any { return t.TS().RoutesAdvertiseExitNode },
		set: func(t *Tunnel, v any) { t.ts().RoutesAdvertiseExitNode = typed[bool](v) },
	},
	{
		JSONKey: "dns.suffix", Kind: KindString,
		Restart: RestartNone, Write: WriteNone, Derived: true,
		Label: "Names on this connection end in", Group: GroupDNS, Tier: TierBasic,
		Help: "The suffix that reaches this network by name: a host called db here answers " +
			"at db followed by this. It is what lets this network and another one that uses " +
			"the same addresses both be reached at once, since a name says which one you " +
			"meant. Change it by changing the short name above, or the zone in Settings.",
		derive: func(t Tunnel, app *Settings) any { return t.DNSSuffix(app) },
	},
	{
		JSONKey: "dns.useTailnet", CLIName: "dns-use-tailnet", Kind: KindBool, Variant: string(TunnelTailscale),
		Restart: RestartPrefs, Write: WritePatch, Module: ModuleDNS,
		Label: "Resolve names with your tailnet's DNS", Group: GroupDNS, Tier: TierBasic,
		Tray: true,
		Help: "Point app-tail's own resolver at the nameservers your tailnet publishes, " +
			"including split-DNS domains aimed at a private nameserver. This applies to " +
			"names app-tail looks up -- through its proxy and its forwards -- and to " +
			"nothing else: no resolv.conf, no scutil entry and no NRPT rule is written, " +
			"so every other program on this machine resolves exactly as it does now. " +
			"Changing what the rest of the machine resolves with is the System resolver " +
			"module, which is a separate switch.",
		get: func(t *Tunnel) any { return t.TS().DNSUseTailnet },
		set: func(t *Tunnel, v any) { t.ts().DNSUseTailnet = typed[bool](v) },
	},
	{
		JSONKey: "security.shieldsUp", CLIName: "shields-up", Kind: KindBool, Variant: string(TunnelTailscale),
		Restart: RestartPrefs, Write: WritePatch, Module: ModuleSecurity,
		Label: "Refuse incoming tailnet connections", Group: GroupSecurity, Tier: TierBasic,
		Tray: true,
		Help: "Drop every connection other devices open to this one, whatever your tailnet's " +
			"ACLs allow. This device can still reach others. Any forward that listens on " +
			"the tailnet stops answering while this is on, and the forwards table says so.",
		get: func(t *Tunnel) any { return t.TS().ShieldsUp },
		set: func(t *Tunnel, v any) { t.ts().ShieldsUp = typed[bool](v) },
	},
	{
		JSONKey: "security.postureChecking", CLIName: "posture-checking", Kind: KindBool, Variant: string(TunnelTailscale),
		Restart: RestartPrefs, Write: WritePatch, Module: ModuleSecurity,
		Label: "Report this device's posture to your tailnet", Group: GroupSecurity,
		Tier: TierAdvanced,
		Help: "Send identifying details about this machine -- its serial number, operating " +
			"system version and any device-management identifiers -- to your tailnet, for " +
			"admins to write access rules against. That information leaves this machine, " +
			"so it is off unless you turn it on.",
		get: func(t *Tunnel) any { return t.TS().PostureChecking },
		set: func(t *Tunnel, v any) { t.ts().PostureChecking = typed[bool](v) },
	},

	// The WireGuard fields. A WireGuard connection is a key pair, the addresses this
	// device holds inside the network, and one server to dial -- there is no enrollment
	// and no account, so nothing here resembles the tailnet's identity block.
	{
		JSONKey: "wg.privateKey", ViewKey: "wg.hasPrivateKey", Kind: KindSecret, Variant: string(TunnelWireGuard),
		Restart: RestartNode, Write: WritePatch,
		Label: "Private key", Group: GroupServer, Tier: TierBasic,
		Help: "This device's own key, as wg genkey writes it. It is the whole of this " +
			"device's identity on the network, so it is write-only: a stored key is never " +
			"sent back out.",
		get:      func(t *Tunnel) any { return t.WG().PrivateKey },
		set:      func(t *Tunnel, v any) { t.wg().PrivateKey = typed[string](v) },
		present:  func(t *Tunnel) bool { return strings.TrimSpace(t.WG().PrivateKey) != "" },
		validate: optionalWireGuardKey,
	},
	{
		JSONKey: "wg.publicKey", Kind: KindString, Variant: string(TunnelWireGuard),
		Restart: RestartNone, Write: WriteNone, Derived: true,
		Label: "Public key", Group: GroupServer, Tier: TierBasic,
		Help: "The key to give the server, derived from the private key above. It is " +
			"derived rather than stored so the two can never disagree: a saved public key " +
			"that no longer matches would look right here and never complete a handshake.",
		derive: func(t Tunnel, _ *Settings) any { return t.WG().PublicKey() },
	},
	{
		JSONKey: "wg.peer.publicKey", Kind: KindString, Variant: string(TunnelWireGuard),
		Restart: RestartNode, Write: WritePatch,
		Label: "Server public key", Group: GroupServer, Tier: TierBasic,
		Example: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		Help: "The server's own key, from the configuration it gave you. It is not a " +
			"secret: it is what the server publishes, and this is the only thing that " +
			"decides which server this connection will talk to.",
		get:      func(t *Tunnel) any { return t.WG().Peer.PublicKey },
		set:      func(t *Tunnel, v any) { t.wg().Peer.PublicKey = typed[string](v) },
		validate: optionalWireGuardKey,
	},
	{
		JSONKey: "wg.peer.presharedKey", ViewKey: "wg.peer.hasPresharedKey", Kind: KindSecret, Variant: string(TunnelWireGuard),
		Restart: RestartNode, Write: WritePatch,
		Label: "Pre-shared key", Group: GroupServer, Tier: TierAdvanced,
		Help: "An extra symmetric key mixed into the handshake, if the server uses one. " +
			"Leave it empty otherwise: a wrong value fails in exactly the same way a wrong " +
			"public key does.",
		get:      func(t *Tunnel) any { return t.WG().Peer.PresharedKey },
		set:      func(t *Tunnel, v any) { t.wg().Peer.PresharedKey = typed[string](v) },
		present:  func(t *Tunnel) bool { return strings.TrimSpace(t.WG().Peer.PresharedKey) != "" },
		validate: optionalWireGuardKey,
	},
	{
		JSONKey: "wg.peer.endpoint", Kind: KindString, Variant: string(TunnelWireGuard),
		Restart: RestartNode, Write: WritePatch,
		Label: "Server address", Group: GroupServer, Tier: TierBasic,
		Example: "vpn.example.com:51820",
		Help: "Where the server answers, as an address or name and a port. A name is " +
			"looked up when the connection starts and again when this machine changes " +
			"network, which is what lets a server on a changing address stay reachable.",
		get:      func(t *Tunnel) any { return t.WG().Peer.Endpoint },
		set:      func(t *Tunnel, v any) { t.wg().Peer.Endpoint = typed[string](v) },
		validate: optionalWireGuardEndpoint,
	},
	{
		JSONKey: "wg.addresses", Kind: KindInterfaceAddrList, Variant: string(TunnelWireGuard),
		Restart: RestartNode, Write: WritePatch,
		Label: "Addresses on this network", Group: GroupAddressing, Tier: TierBasic,
		Example: "10.0.0.2/24",
		Help: "The addresses this device holds inside the network, comma separated, copied " +
			"from the Address line of the configuration the server gave you. Other devices " +
			"there reach this one at these.",
		get:      func(t *Tunnel) any { return append([]netip.Prefix(nil), t.WG().Addresses...) },
		set:      func(t *Tunnel, v any) { t.wg().Addresses = typed[[]netip.Prefix](v) },
		validate: distinctInterfaceAddrs,
	},
	{
		JSONKey: "wg.peer.allowedIPs", Kind: KindCidrList, Variant: string(TunnelWireGuard),
		Restart: RestartNode, Write: WritePatch,
		Label: "Networks this connection carries", Group: GroupAddressing, Tier: TierBasic,
		Example: "10.0.0.0/24, 192.168.1.0/24",
		Help: "The networks reachable through this server, comma separated, from the " +
			"AllowedIPs line of its configuration. It is both what this app routes here and " +
			"what the server is trusted to send from, so a range that does not belong to " +
			"this network makes the server able to answer for it. Entering 0.0.0.0/0 says " +
			"the server carries everything; whether this machine's own traffic actually " +
			"leaves through it stays a separate choice.",
		get:      func(t *Tunnel) any { return append([]netip.Prefix(nil), t.WG().Peer.AllowedIPs...) },
		set:      func(t *Tunnel, v any) { t.wg().Peer.AllowedIPs = typed[[]netip.Prefix](v) },
		validate: carriedNetworks,
	},
	{
		JSONKey: "wg.dns", Kind: KindIPList, Variant: string(TunnelWireGuard),
		Restart: RestartNode, Write: WritePatch, Module: ModuleDNS,
		Label: "Resolvers inside this network", Group: GroupDNS, Tier: TierBasic,
		Example: "10.0.0.1",
		Help: "The nameservers to ask for names on this network, from the DNS line of the " +
			"server's configuration. They are used for the names app-tail looks up through " +
			"this connection and for nothing else: no resolver configuration is written " +
			"anywhere on this machine, so every other program keeps resolving as it does now.",
		get:      func(t *Tunnel) any { return append([]netip.Addr(nil), t.WG().DNS...) },
		set:      func(t *Tunnel, v any) { t.wg().DNS = typed[[]netip.Addr](v) },
		validate: reachableResolvers,
	},
	{
		JSONKey: "wg.mtu", Kind: KindInt, Variant: string(TunnelWireGuard),
		Restart: RestartNode, Write: WritePatch,
		Label: "Packet size (MTU)", Group: GroupAdvanced, Tier: TierAdvanced,
		Default: DefaultWireGuardMTU, Constraint: between(MinWireGuardMTU, MaxWireGuardMTU),
		Help: "The largest packet this connection carries. The default leaves room for " +
			"WireGuard's own headers on an ordinary link; lower it only if large transfers " +
			"stall while small ones work, which is what a path that cannot carry this size " +
			"looks like.",
		get: func(t *Tunnel) any { return t.WG().MTU },
		set: func(t *Tunnel, v any) { t.wg().MTU = typed[int](v) },
	},
	{
		JSONKey: "wg.peer.keepaliveSec", Kind: KindInt, Variant: string(TunnelWireGuard),
		Restart: RestartNode, Write: WritePatch,
		Label: "Keepalive (s)", Group: GroupAdvanced, Tier: TierAdvanced,
		Default: DefaultWireGuardKeepaliveSec, Constraint: between(0, MaxWireGuardKeepaliveSec),
		Help: "How often to send an empty packet so a router in the way keeps the path " +
			"open. Zero sends none, which is right only when the server never has to be the " +
			"one to start a conversation.",
		get: func(t *Tunnel) any { return t.WG().Peer.KeepaliveSec },
		set: func(t *Tunnel, v any) { t.wg().Peer.KeepaliveSec = typed[int](v) },
	},

	// The OpenVPN fields. An OpenVPN connection is carried by the stock openvpn program
	// rather than by code inside this process, so what is stored is what that program has
	// to be told -- and the networks and resolvers are written here rather than taken from
	// the server, because a pushed route or resolver is a server reconfiguring the machine
	// it is a guest on.
	{
		JSONKey: "ovpn.remote", Kind: KindString, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Server address", Group: GroupServer, Tier: TierBasic,
		Example: "vpn.example.com:1194",
		Help: "Where the server answers, as an address or name and a port, from the remote " +
			"line of the configuration it gave you. Leave the port off and 1194 is used, " +
			"which is what an OpenVPN server answers on unless somebody moved it.",
		get:      func(t *Tunnel) any { return t.OVPN().Remote },
		set:      func(t *Tunnel, v any) { t.ovpn().Remote = typed[string](v) },
		validate: optionalOpenVPNRemote,
	},
	{
		JSONKey: "ovpn.proto", Kind: KindEnum, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Transport", Group: GroupServer, Tier: TierBasic,
		Default: OpenVPNProtoUDP,
		Options: []EnumOption{
			{
				Value: OpenVPNProtoUDP, Label: "UDP",
				Help: "What an OpenVPN server runs unless its administrator changed it. It " +
					"carries a tunnel better than TCP does, because a tunnel inside TCP " +
					"stalls whenever the outer connection retransmits.",
			},
			{
				Value: OpenVPNProtoTCP, Label: "TCP",
				Help: "Used where UDP is blocked. It gets through more networks and is " +
					"slower and less even under loss.",
			},
		},
		Help: "The transport the server answers on, from the proto line of its configuration.",
		get:  func(t *Tunnel) any { return t.OVPN().EffectiveProto() },
		set:  func(t *Tunnel, v any) { t.ovpn().Proto = typed[string](v) },
	},
	{
		JSONKey: "ovpn.ca", Kind: KindText, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Certificate authority", Group: GroupServer, Tier: TierBasic,
		Help: "The authority the server's certificate is checked against, in PEM, from the " +
			"<ca> section of its configuration. It is not a secret: it is what the server's " +
			"administrator publishes, and it is the whole of what decides which server this " +
			"connection will trust.",
		get:      func(t *Tunnel) any { return t.OVPN().CA },
		set:      func(t *Tunnel, v any) { t.ovpn().CA = typed[string](v) },
		validate: optionalOpenVPNPEM,
	},
	{
		JSONKey: "ovpn.cert", Kind: KindText, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Device certificate", Group: GroupAuth, Tier: TierBasic,
		Help: "This device's own certificate, in PEM, from the <cert> section. Leave it empty " +
			"for a server that identifies you by a username and password instead.",
		get:      func(t *Tunnel) any { return t.OVPN().Cert },
		set:      func(t *Tunnel, v any) { t.ovpn().Cert = typed[string](v) },
		validate: optionalOpenVPNPEM,
	},
	{
		JSONKey: "ovpn.key", ViewKey: "ovpn.hasKey", Kind: KindSecretText, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Device private key", Group: GroupAuth, Tier: TierBasic,
		Help: "The private key for the certificate above, in PEM, from the <key> section. It " +
			"is the whole of this device's identity on the network, so it is write-only: a " +
			"stored key is never sent back out.",
		get:      func(t *Tunnel) any { return t.OVPN().Key },
		set:      func(t *Tunnel, v any) { t.ovpn().Key = typed[string](v) },
		present:  func(t *Tunnel) bool { return strings.TrimSpace(t.OVPN().Key) != "" },
		validate: optionalOpenVPNPEM,
	},
	{
		JSONKey: "ovpn.keyPassphrase", ViewKey: "ovpn.hasKeyPassphrase", Kind: KindSecret, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Private key passphrase", Group: GroupAuth, Tier: TierAdvanced,
		Help: "The passphrase that unlocks an encrypted private key. Leave it empty for a key " +
			"that has none. It is handed over when the connection asks for it and is never " +
			"written to a file.",
		get:      func(t *Tunnel) any { return t.OVPN().KeyPassphrase },
		set:      func(t *Tunnel, v any) { t.ovpn().KeyPassphrase = typed[string](v) },
		present:  func(t *Tunnel) bool { return t.OVPN().KeyPassphrase != "" },
		validate: openVPNCredential,
	},
	{
		JSONKey: "ovpn.authUserPass", Kind: KindBool, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "This server asks for a username and password", Group: GroupAuth, Tier: TierBasic,
		Help: "Whether the server signs this connection in with an account, which its " +
			"configuration says with an auth-user-pass line. With it on and no username " +
			"below, the connection stops rather than starting and waiting at a prompt " +
			"nothing is reading.",
		get: func(t *Tunnel) any { return t.OVPN().AuthUserPass },
		set: func(t *Tunnel, v any) { t.ovpn().AuthUserPass = typed[bool](v) },
	},
	{
		JSONKey: "ovpn.username", Kind: KindString, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Username", Group: GroupAuth, Tier: TierBasic,
		Help: "The account this connection signs in with. It is handed over when the server " +
			"asks and is never written to a file.",
		get:      func(t *Tunnel) any { return t.OVPN().Username },
		set:      func(t *Tunnel, v any) { t.ovpn().Username = typed[string](v) },
		validate: openVPNCredential,
	},
	{
		JSONKey: "ovpn.password", ViewKey: "ovpn.hasPassword", Kind: KindSecret, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Password", Group: GroupAuth, Tier: TierBasic,
		Help:     "The password for that account. Write-only, and handed over the same way.",
		get:      func(t *Tunnel) any { return t.OVPN().Password },
		set:      func(t *Tunnel, v any) { t.ovpn().Password = typed[string](v) },
		present:  func(t *Tunnel) bool { return t.OVPN().Password != "" },
		validate: openVPNCredential,
	},
	{
		JSONKey: "ovpn.tlsCrypt", ViewKey: "ovpn.hasTLSCrypt", Kind: KindSecretText, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Control channel key (tls-crypt)", Group: GroupSecurity, Tier: TierAdvanced,
		Help: "The static key from the <tls-crypt> section, which encrypts everything the " +
			"connection says before the certificates are even exchanged. A server that uses " +
			"one will not answer without it.",
		get:      func(t *Tunnel) any { return t.OVPN().TLSCrypt },
		set:      func(t *Tunnel, v any) { t.ovpn().TLSCrypt = typed[string](v) },
		present:  func(t *Tunnel) bool { return strings.TrimSpace(t.OVPN().TLSCrypt) != "" },
		validate: optionalOpenVPNStaticKey,
	},
	{
		JSONKey: "ovpn.tlsAuth", ViewKey: "ovpn.hasTLSAuth", Kind: KindSecretText, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Control channel key (tls-auth)", Group: GroupSecurity, Tier: TierAdvanced,
		Help: "The older form of the key above, from the <tls-auth> section. It signs what the " +
			"connection says rather than encrypting it. Use whichever section the server's " +
			"configuration carries; no configuration carries both.",
		get:      func(t *Tunnel) any { return t.OVPN().TLSAuth },
		set:      func(t *Tunnel, v any) { t.ovpn().TLSAuth = typed[string](v) },
		present:  func(t *Tunnel) bool { return strings.TrimSpace(t.OVPN().TLSAuth) != "" },
		validate: optionalOpenVPNStaticKey,
	},
	{
		JSONKey: "ovpn.keyDirection", Kind: KindEnum, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Control channel key direction", Group: GroupSecurity, Tier: TierAdvanced,
		Options: []EnumOption{
			{
				Value: OpenVPNKeyDirectionNone, Label: "Not set",
				Help: "What a tls-crypt key uses, and what a tls-auth key uses when the " +
					"configuration has no key-direction line.",
			},
			{Value: OpenVPNKeyDirectionServer, Label: "0", Help: "The half a server uses."},
			{Value: OpenVPNKeyDirectionClient, Label: "1", Help: "The half a client uses, which is what a key-direction line in a client configuration says."},
		},
		Help: "Which half of a tls-auth key this side uses, from the key-direction line. It " +
			"applies to a tls-auth key only.",
		get: func(t *Tunnel) any { return t.OVPN().KeyDirection },
		set: func(t *Tunnel, v any) { t.ovpn().KeyDirection = typed[string](v) },
	},
	{
		JSONKey: "ovpn.verifyServerCert", Kind: KindBool, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Require a server certificate", Group: GroupSecurity, Tier: TierBasic,
		Default: true,
		Help: "Refuse a certificate that is not marked as a server's, which is what stops " +
			"another client of the same network presenting its own certificate and being " +
			"taken for the server. Turn it off only for a server old enough not to mark them.",
		get: func(t *Tunnel) any { return t.OVPN().VerifyServerCert },
		set: func(t *Tunnel, v any) { t.ovpn().VerifyServerCert = typed[bool](v) },
	},
	{
		JSONKey: "ovpn.verifyName", Kind: KindString, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Name on the server's certificate", Group: GroupSecurity, Tier: TierAdvanced,
		Example: "vpn.example.com",
		Help: "The name the server's certificate must carry, from a verify-x509-name line. " +
			"Leave it empty to accept any certificate the authority above signed, which is " +
			"the right answer when that authority signs nothing else.",
		get:      func(t *Tunnel) any { return t.OVPN().VerifyName },
		set:      func(t *Tunnel, v any) { t.ovpn().VerifyName = typed[string](v) },
		validate: openVPNVerifyName,
	},
	{
		JSONKey: "ovpn.verifyNameType", Kind: KindEnum, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "How to match that name", Group: GroupSecurity, Tier: TierAdvanced,
		Default: OpenVPNVerifySubject,
		Options: []EnumOption{
			{Value: OpenVPNVerifyName, Label: "The whole common name", Help: "The certificate's common name must be exactly the name above."},
			{Value: OpenVPNVerifyNamePrefix, Label: "The start of the common name", Help: "The certificate's common name must begin with the name above."},
			{Value: OpenVPNVerifySubject, Label: "The full subject", Help: "The certificate's whole subject line must be exactly the name above."},
		},
		Help: "Which part of the server's certificate the name above is matched against.",
		get:  func(t *Tunnel) any { return t.OVPN().EffectiveVerifyNameType() },
		set:  func(t *Tunnel, v any) { t.ovpn().VerifyNameType = typed[string](v) },
	},
	{
		JSONKey: "ovpn.routes", Kind: KindCidrList, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Networks this connection carries", Group: GroupAddressing, Tier: TierBasic,
		Example: "10.8.0.0/24, 192.168.1.0/24",
		Help: "The networks reachable through this server, comma separated. They are written " +
			"here rather than taken from the server, because a route a server pushes is a " +
			"server deciding what this machine does with its own traffic. The connection " +
			"reports the routes the server offers, so they can be read off it and added. " +
			"Entering 0.0.0.0/0 says the server carries everything; whether this machine's " +
			"own traffic actually leaves through it stays a separate choice.",
		get:      func(t *Tunnel) any { return append([]netip.Prefix(nil), t.OVPN().Routes...) },
		set:      func(t *Tunnel, v any) { t.ovpn().Routes = typed[[]netip.Prefix](v) },
		validate: carriedNetworks,
	},
	{
		JSONKey: "ovpn.dns", Kind: KindIPList, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch, Module: ModuleDNS,
		Label: "Resolvers inside this network", Group: GroupDNS, Tier: TierBasic,
		Example: "10.8.0.1",
		Help: "The nameservers to ask for names on this network, from the dhcp-option DNS " +
			"lines of the server's configuration. They are used for the names app-tail looks " +
			"up through this connection and for nothing else.",
		get:      func(t *Tunnel) any { return append([]netip.Addr(nil), t.OVPN().DNS...) },
		set:      func(t *Tunnel, v any) { t.ovpn().DNS = typed[[]netip.Addr](v) },
		validate: reachableResolvers,
	},
	{
		JSONKey: "ovpn.cipher", Kind: KindString, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Data cipher", Group: GroupAdvanced, Tier: TierAdvanced,
		Example: "AES-256-GCM",
		Help: "The cipher to offer for the traffic itself. Leave it empty and the two sides " +
			"negotiate one, which is right for every server new enough to do so; fill it in " +
			"only for one whose configuration pins a cipher line.",
		get:      func(t *Tunnel) any { return t.OVPN().Cipher },
		set:      func(t *Tunnel, v any) { t.ovpn().Cipher = typed[string](v) },
		validate: optionalOpenVPNToken,
	},
	{
		JSONKey: "ovpn.auth", Kind: KindString, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Packet digest", Group: GroupAdvanced, Tier: TierAdvanced,
		Example: "SHA256",
		Help: "The digest that authenticates each packet, from an auth line. It does nothing " +
			"on a cipher that authenticates its own data, which every modern one does.",
		get:      func(t *Tunnel) any { return t.OVPN().Auth },
		set:      func(t *Tunnel, v any) { t.ovpn().Auth = typed[string](v) },
		validate: optionalOpenVPNToken,
	},
	{
		JSONKey: "ovpn.mtu", Kind: KindInt, Variant: string(TunnelOpenVPN),
		Restart: RestartNode, Write: WritePatch,
		Label: "Packet size (MTU)", Group: GroupAdvanced, Tier: TierAdvanced,
		Constraint: between(0, MaxOpenVPNMTU),
		Help: "The largest packet this connection carries. Zero leaves it to the connection, " +
			"which is what a tun-mtu line overrides. Lower it only if large transfers stall " +
			"while small ones work.",
		get:      func(t *Tunnel) any { return t.OVPN().MTU },
		set:      func(t *Tunnel, v any) { t.ovpn().MTU = typed[int](v) },
		validate: openVPNMTU,
	},
}

// tunnelTypeOptions is the type picker's choices, derived from the one type list so a
// type this build can connect and a type a picker offers cannot come apart.
func tunnelTypeOptions() []EnumOption {
	out := make([]EnumOption, 0, len(TunnelTypes))
	for _, t := range TunnelTypes {
		out = append(out, EnumOption{Value: string(t), Label: t.Label()})
	}
	return out
}

// validateSlugValue applies the DNS-label rule to a patched value. Uniqueness is not
// checked here: it is a fact about the whole document rather than about this value, so it
// belongs to the document's own validation, which sees the other connections.
func validateSlugValue(v any) error {
	if ok, why := ValidSlug(typed[string](v)); !ok {
		return errors.New(why)
	}
	return nil
}

// absolutePathOrEmpty refuses a relative path. A relative one is read from wherever the
// agent was started, which for a service is a directory nobody chose. A stored one is
// refused by readSecretFile when it is read.
func absolutePathOrEmpty(v any) error {
	path := strings.TrimSpace(typed[string](v))
	if path != "" && !filepath.IsAbs(path) {
		return fmt.Errorf("must be an absolute path, got %q", path)
	}
	return nil
}

// MaxTunnelNameLen bounds the display name. It is generous but finite: the name is
// rendered in a rail, a tray menu and a status line, none of which can show more.
const MaxTunnelNameLen = 120

func displayableName(v any) error {
	name := typed[string](v)
	if strings.TrimSpace(name) == "" {
		return errors.New("must not be empty")
	}
	if len(name) > MaxTunnelNameLen {
		return fmt.Errorf("must be at most %d characters, got %d", MaxTunnelNameLen, len(name))
	}
	return nil
}

// tunnelRegistry is the tunnel table with its lookups built once. It is variant-aware:
// what a connection is configurable by depends on what it speaks, so a field of another
// protocol is absent from the form, refused by name on a write, and never stored.
var tunnelRegistry = NewVariantRegistry(tunnelFields, func(t *Tunnel) string {
	return string(t.Type)
})

// NewTunnel returns a connection of this type with every field at its declared default,
// which is what a freshly added one starts from.
func NewTunnel(id, slug, name string, kind TunnelType) Tunnel {
	t := Tunnel{ID: id, Slug: slug, Name: name, Type: kind, Enabled: true}
	tunnelRegistry.Defaults(&t)
	// Defaults writes the name and slug too, since they are ordinary fields; the caller's
	// are what this connection is called.
	t.Slug, t.Name = slug, name
	return t
}

// TunnelSchema is the connection form's field metadata, with each field's availability
// resolved against this installation.
func TunnelSchema(app *Settings) []FieldSchema { return tunnelRegistry.SchemaFor(app) }

// TunnelSchemaStatic is the same table with availability left unresolved, which is what
// the generated TypeScript renders: a checked-in file cannot know an installation, and a
// resolved answer baked into it would describe a machine that is not the one running it.
func TunnelSchemaStatic() []FieldSchema { return tunnelRegistry.Schema() }

// TunnelFieldByName resolves a connection field's name -- a CLI name or a JSON key -- to
// the schema that serves it, for a caller holding a name somebody typed rather than a
// field.
//
// Every kind of connection's fields are searched. Which of them a particular connection
// accepts is the write's answer rather than the lookup's, so naming a WireGuard field on
// an OpenVPN connection is refused with that reason instead of as an unknown name.
func TunnelFieldByName(key string) (FieldSchema, bool) {
	for _, s := range TunnelSchemaStatic() {
		if s.Key == key || (s.CLIName != "" && s.CLIName == key) {
			return s, true
		}
	}
	return FieldSchema{}, false
}

// ParseTunnelValue turns a command-line string into the typed value a connection field
// stores, and returns the JSON key a patch carries it under.
//
// It is the connection form's counterpart to ParseSettingValue, and exists for the same
// reason: a value typed at a terminal passes exactly the rule a value typed into the
// dashboard passes, because both go through the field's own parser.
func ParseTunnelValue(key, raw string) (string, any, error) {
	f, ok := tunnelRegistry.ByCLIName(key)
	if !ok {
		if f, ok = tunnelRegistry.ByJSONKey(key); !ok {
			return "", nil, fmt.Errorf("%q is not a known connection setting", key)
		}
	}
	v, err := f.ParseCLIValue(raw)
	return f.JSONKey, v, err
}

// BuildTunnelView projects a stored connection onto the map the API returns. app is the
// installation's own settings, which a derived field can depend on: a connection's
// rendered device name is its template against this machine's identity.
func BuildTunnelView(t Tunnel, app *Settings) map[string]any { return tunnelRegistry.View(t, app) }

// ApplyTunnelPatch overlays the fields a request carried onto t. It does not check that
// the result is unique across the document; Config.Validate does, and the store runs it
// on every write.
func ApplyTunnelPatch(t *Tunnel, app *Settings, patch map[string]json.RawMessage) error {
	return tunnelRegistry.ApplyPatch(t, app, patch)
}

// PrefsFields are every connection field the node's own preferences carry, in registry
// order. They are what a full push sends, which is the only way most of them are ever
// applied: tsnet has no plumbing that would set them from the server parameters.
func PrefsFields() []TunnelField {
	var out []TunnelField
	for _, f := range tunnelFields {
		if f.Restart == RestartPrefs {
			out = append(out, f)
		}
	}
	return out
}

// PrefValues reports one connection's stored value for every pref-backed field, keyed by
// its JSON key. It is the stored half of the stored-versus-live comparison a consumer
// renders, and it always answers -- the document is the source of truth, so a node that is
// down makes the live half unknown but never this one.
//
// The values are the ones this connection would actually push, so a field whose module is
// off reads as its default here rather than as the value stored under a switch that is
// off.
func PrefValues(app *Settings, t Tunnel) map[string]any {
	effective := t
	if ts := t.TS(); t.Type == TunnelTailscale {
		ts.TailnetPrefs = app.TailnetPrefsOf(t)
		effective.Tailscale = &ts
	}
	out := make(map[string]any)
	for _, f := range PrefsFields() {
		out[f.JSONKey] = f.get(&effective)
	}
	return out
}

// AdoptPrefValues folds a node's own preferences into t, for every pref-backed field
// whose live value differs from this app's default, and turns on the module each one
// belongs to. It returns the keys it took, in registry order.
//
// This runs once per connection, before this app has ever pushed to its node. Without it,
// a node someone already enrolled with `tailscale up --accept-routes` would have that
// turned off by the first reconcile -- a setting the user never touched here, changed by
// installing this app. Taking the value instead makes the app show what the node is
// already doing, which is also the only way the user can then see it to change it.
//
// The modules it turns on are the installation's, which is what makes an adopted value
// reachable: a preference stored under a switch that is off is one the user can neither
// see nor change.
func AdoptPrefValues(app *Settings, t *Tunnel, live map[string]any) []string {
	var taken []string
	for _, f := range PrefsFields() {
		v, ok := live[f.JSONKey]
		if !ok || f.set == nil || !tunnelRegistry.applies(f, t) {
			continue
		}
		if reflect.DeepEqual(v, f.defaultValue()) {
			continue
		}
		f.set(t, v)
		enableModule(app, f.Module)
		taken = append(taken, f.JSONKey)
	}
	return taken
}
