// SPDX-License-Identifier: MIT

package config

// Presentation and availability metadata for the settings registry: the section and
// tier a setting is shown under, the optional feature module that owns it, and the
// bounds its value must satisfy. These are the members of SettingField that describe a
// setting rather than store it, and they are what let the dashboard, the tray and the
// CLI render the same settings without any of them keeping a second list.

import (
	"encoding/json"
	"fmt"
	"runtime"
	"slices"
	"strings"
)

// Tier separates the settings that matter to everyone from the ones only a power user
// should be shown. A consumer puts TierAdvanced behind a disclosure rather than
// dropping it: an unreachable setting is worse than a crowded form.
type Tier int

const (
	TierBasic Tier = iota
	TierAdvanced
)

func (t Tier) String() string {
	if t == TierAdvanced {
		return "advanced"
	}
	return "basic"
}

// lastTier is the final declared tier, which is how far the decoder looks.
const lastTier = TierAdvanced

// MarshalJSON renders the tier as its name so the schema endpoint and generated TS
// read a word rather than an opaque integer.
func (t Tier) MarshalJSON() ([]byte, error) { return json.Marshal(t.String()) }

func (t *Tier) UnmarshalJSON(raw []byte) error {
	v, err := unmarshalNamed(raw, lastTier, "tier")
	if err != nil {
		return err
	}
	*t = v
	return nil
}

// namedEnum is an integer enum whose String method is its wire form.
type namedEnum interface {
	~int
	fmt.Stringer
}

// unmarshalNamed decodes an enum written as the word its own String method produces.
//
// Every one of these types marshals as a name so a schema reads as words rather than
// opaque integers, and every Go consumer of that schema -- the CLI is one -- has to be
// able to read it back. The accepted names are taken off the values themselves rather
// than from a second table, so a name cannot be renamed on one side only; last is how far
// the walk goes, and the schema round-trip test is what keeps it current.
func unmarshalNamed[T namedEnum](raw []byte, last T, what string) (T, error) {
	var name string
	if err := json.Unmarshal(raw, &name); err != nil {
		return 0, fmt.Errorf("a %s must be written as its name, got %s", what, raw)
	}
	for v := T(0); v <= last; v++ {
		if v.String() == name {
			return v, nil
		}
	}
	return 0, fmt.Errorf("%q is not a known %s", name, what)
}

// Group is the section a setting is displayed under.
type Group int

const (
	GroupIdentity Group = iota
	GroupAuth
	GroupTailnet
	GroupForwarding
	GroupProxy
	GroupAutoMap
	GroupExitNode
	GroupRouting
	GroupDNS
	GroupSystemDNS
	GroupSecurity
	GroupInterface
	GroupTraffic
	GroupTelemetry
	GroupApplication
	GroupAbout
	// GroupConnection holds what one connection is called. It is a section of the
	// connection form rather than of the settings document, and it is in this enum
	// because both forms are rendered from the same field metadata.
	GroupConnection
	// GroupMode holds how app-tail runs on this machine, which is a reading of the
	// switches the other sections own rather than a set of switches of its own.
	GroupMode
	// GroupServer holds where one connection dials and what it presents when it gets
	// there. It is separate from GroupTailnet because a coordination server and a VPN
	// gateway are answers to different questions: one hands out an identity, the other
	// is the far end of the tunnel itself.
	GroupServer
	// GroupAddressing holds the addresses a connection holds and the networks it carries.
	GroupAddressing
	// GroupAdvanced holds the settings a connection works without: packet size, keepalive,
	// and the rest of what is only touched when something specific is wrong.
	GroupAdvanced
	// GroupEgress holds where traffic no connection carries leaves through. It is a
	// section of the settings document rather than of any connection's form: which
	// connection carries the internet is a fact about this machine, and asking it on one
	// connection's page would hide it from the others.
	GroupEgress
	// GroupDNSBlock holds which names are refused rather than resolved. It is its own
	// section rather than part of either DNS section because it applies to both of them
	// at once: one set of lists, and a switch per resolver saying where they are in force.
	GroupDNSBlock
	// GroupIPS holds what is examined about the traffic app-tail carries, and what
	// happens when something matches. It is separate from GroupDNSBlock because the two
	// answer different questions about the same lists: blocking decides what this machine
	// is allowed to look up, and this decides what it is allowed to connect to once it
	// has an address -- which is the half a program dialling an address directly skips.
	GroupIPS
)

func (g Group) String() string {
	switch g {
	case GroupAuth:
		return "auth"
	case GroupTailnet:
		return "tailnet"
	case GroupForwarding:
		return "forwarding"
	case GroupProxy:
		return "proxy"
	case GroupAutoMap:
		return "automap"
	case GroupExitNode:
		return "exitnode"
	case GroupRouting:
		return "routing"
	case GroupDNS:
		return "dns"
	case GroupSystemDNS:
		return "systemdns"
	case GroupSecurity:
		return "security"
	case GroupInterface:
		return "interface"
	case GroupTraffic:
		return "traffic"
	case GroupTelemetry:
		return "telemetry"
	case GroupApplication:
		return "application"
	case GroupAbout:
		return "about"
	case GroupConnection:
		return "connection"
	case GroupMode:
		return "mode"
	case GroupServer:
		return "server"
	case GroupAddressing:
		return "addressing"
	case GroupAdvanced:
		return "advanced"
	case GroupEgress:
		return "egress"
	case GroupDNSBlock:
		return "dnsblock"
	case GroupIPS:
		return "ips"
	default:
		return "identity"
	}
}

// lastGroup is the final declared section, which is how far the decoder looks.
const lastGroup = GroupIPS

func (g Group) MarshalJSON() ([]byte, error) { return json.Marshal(g.String()) }

func (g *Group) UnmarshalJSON(raw []byte) error {
	v, err := unmarshalNamed(raw, lastGroup, "settings section")
	if err != nil {
		return err
	}
	*g = v
	return nil
}

// GroupInfo describes one settings section for a consumer that renders the sections
// itself rather than inferring them from the fields.
type GroupInfo struct {
	ID          Group  `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// settingsGroups is the authored section list; its order is the display order.
var settingsGroups = []GroupInfo{
	{GroupConnection, "Connection", "What this connection is called, here and in DNS."},
	{GroupIdentity, "Identity", "How this device names and tags itself on the tailnet."},
	{GroupAuth, "Authentication", "The credentials this device enrolls with."},
	{GroupTailnet, "Tailnet", "Which coordination server this device joins, and how it registers."},
	{GroupServer, "Server",
		"The far end of this connection: where it dials, and the keys the two sides " +
			"recognise each other by."},
	{GroupAddressing, "Addressing",
		"The addresses this device holds inside the network, and which networks the " +
			"connection carries."},
	{GroupForwarding, "Forwarding", "Defaults applied to every port forward this app runs."},
	{GroupProxy, "Proxy", "A loopback proxy that reaches the whole tailnet, for programs you point at it."},
	{GroupAutoMap, "Automatic ports",
		"Give every device on the tailnet a fixed local port, so a peer's SSH or web port " +
			"is reachable at localhost without configuring anything per device."},
	{GroupExitNode, "Exit node",
		"Send this device's other traffic out through a device on your tailnet, so it " +
			"leaves from there instead of from here."},
	{GroupRouting, "Subnet routes",
		"Reach the private networks other devices on the tailnet advertise, such as a " +
			"home LAN behind a subnet router."},
	{GroupDNS, "DNS",
		"Which resolver app-tail uses for the names it looks up. It configures nothing " +
			"outside this app: every other program on this machine keeps resolving as it does now."},
	{GroupSystemDNS, "System resolver",
		"Which resolver this whole machine uses. This and the network interface are the two " +
			"parts of app-tail that change the machine rather than only itself: while it is " +
			"on, every program here resolves names through app-tail, and it is put back when " +
			"app-tail stops."},
	{GroupDNSBlock, "Blocking",
		"Refuse names that appear on lists you choose -- advertising, tracking, malware -- " +
			"instead of resolving them. The lists are downloaded, kept on this machine and " +
			"matched here, so nothing about which names you look up leaves this device."},
	{GroupIPS, "Traffic inspection",
		"Examine the connections app-tail carries and report the ones that match the domains " +
			"and addresses you name, or refuse them outright. It sees what app-tail itself " +
			"carries -- the network interface in fabric mode, the proxy, and connections other " +
			"devices route through this one -- and nothing this machine sends any other way."},
	{GroupSecurity, "Security",
		"What this device accepts from the tailnet and what it reports back about itself."},
	{GroupInterface, "Network interface",
		"Create a real network interface, so the addresses and names on your connections " +
			"work in every program on this machine -- either the tailnet on its own, or " +
			"every connection at once. This and the system resolver are the two parts of " +
			"app-tail that change the machine rather than only itself."},
	{GroupTraffic, "Live traffic",
		"What this machine is carrying right now: how much is moving, which devices it " +
			"is moving to, and what has crossed recently."},
	{GroupTelemetry, "Logs",
		"Keep a history of what this app did and what it carried, so a fault that has " +
			"already passed can still be looked at. Nothing is recorded until you turn it " +
			"on, and everything recorded stays on this machine."},
	{GroupAdvanced, "Advanced",
		"Settings this connection works without. They are here for the network that " +
			"needs one of them, and are best left alone otherwise."},
	{GroupApplication, "Application", "How the app itself behaves on this machine."},
	{GroupAbout, "About", "Facts about this install."},
	{GroupMode, "How app-tail runs here",
		"Which programs on this machine can reach your networks, and how much of the " +
			"machine app-tail touches to arrange it."},
	{GroupEgress, "Internet traffic",
		"Where everything your connections do not carry goes: out of this machine the " +
			"way it always has, or through one of your connections so it leaves from " +
			"there instead."},
}

// SettingsGroups returns the display sections in order.
func SettingsGroups() []GroupInfo { return settingsGroups }

// GroupsFor returns the sections these fields name, in display order.
//
// A schema describes one entity, and a section no field of that entity is in is a heading
// a client would draw over nothing. Serving the whole list instead would put every settings
// section on a connection form.
func GroupsFor(fields []FieldSchema) []GroupInfo {
	named := make(map[Group]bool, len(fields))
	for _, f := range fields {
		named[f.Group] = true
	}
	out := make([]GroupInfo, 0, len(named))
	for _, g := range settingsGroups {
		if named[g.ID] {
			out = append(out, g)
		}
	}
	return out
}

// OptionsExitNodes names the runtime choice list of devices the tailnet offers as exit
// nodes. A setting declares it in OptionsFrom; whoever renders the setting fills it from
// the exit-node endpoint, since this package has no way to know what a tailnet offers.
const OptionsExitNodes = "exitNodes"

// OptionsTunnels names the runtime choice list of this install's own connections. A setting
// declares it in OptionsFrom; whoever renders the setting fills it from the connections
// endpoint. It is a runtime source rather than a declared enum for the same reason the two
// below are: the choices are whatever the user has added, and a stored id naming a
// connection that has since been removed still has to load.
const OptionsTunnels = "tunnels"

// OptionsDNSProfiles names the runtime choice list of resolver profiles: the built-ins plus
// whatever the user has added. A setting declares it in OptionsFrom; whoever renders the
// setting fills it from the profiles endpoint, since this package holds the stored profiles
// but not the catalog that names and orders them.
const OptionsDNSProfiles = "dnsProfiles"

// OptionsDNSBootstrap names the same catalog offered as the resolver that looks up another
// resolver's hostname. It is a separate source rather than the same list because the entries
// mean different things there: the one that changes nothing about this machine is the one
// that sends the lookup to this network, and a profile whose resolvers are all named by
// hostname cannot answer the question at all.
const OptionsDNSBootstrap = "dnsBootstrap"

// FeatureModule is an optional capability the user opts into. ModuleCore is the zero
// value and is always available: the app installs carrying only its core settings, and
// every other module stays hidden and unwritable until its switch is turned on.
type FeatureModule int

const (
	ModuleCore FeatureModule = iota
	ModuleAdvancedNetworking
	ModuleProxy
	ModuleAutoMap
	ModuleExitNode
	ModuleRouting
	ModuleDNS
	ModuleSystemDNS
	ModuleDNSBlock
	ModuleSecurity
	ModuleInterface
	ModuleTelemetry
	ModuleIPS
)

func (m FeatureModule) String() string {
	switch m {
	case ModuleAdvancedNetworking:
		return "advancedNetworking"
	case ModuleProxy:
		return "proxy"
	case ModuleAutoMap:
		return "automap"
	case ModuleExitNode:
		return "exitNode"
	case ModuleRouting:
		return "routing"
	case ModuleDNS:
		return "dns"
	case ModuleSystemDNS:
		return "systemDns"
	case ModuleDNSBlock:
		return "dnsBlock"
	case ModuleSecurity:
		return "security"
	case ModuleInterface:
		return "interface"
	case ModuleTelemetry:
		return "telemetry"
	case ModuleIPS:
		return "ips"
	default:
		return "core"
	}
}

// lastModule is the final declared module, which is how far the decoder looks.
const lastModule = ModuleIPS

func (m FeatureModule) MarshalJSON() ([]byte, error) { return json.Marshal(m.String()) }

func (m *FeatureModule) UnmarshalJSON(raw []byte) error {
	v, err := unmarshalNamed(raw, lastModule, "module")
	if err != nil {
		return err
	}
	*m = v
	return nil
}

// ModuleInfo describes one optional module. SwitchKey names the ordinary registry
// field that turns it on, so a consumer can offer the switch beside the settings it
// governs without knowing anything module-specific.
type ModuleInfo struct {
	ID          FeatureModule `json:"id"`
	Label       string        `json:"label"`
	Description string        `json:"description"`
	SwitchKey   string        `json:"switchKey"`
}

// featureModules is the authored module list. ModuleCore is deliberately absent: it is
// not optional and has no switch.
var featureModules = []ModuleInfo{
	{
		ID:    ModuleAdvancedNetworking,
		Label: "Advanced networking",
		Description: "Settings for joining a coordination server other than Tailscale's, " +
			"such as a self-hosted Headscale.",
		SwitchKey: "advancedNetworking",
	},
	{
		ID:    ModuleProxy,
		Label: "Tailnet proxy",
		Description: "Run a loopback SOCKS5 and HTTP proxy so any program on this machine " +
			"can reach tailnet devices by IP and MagicDNS name, without a VPN interface.",
		SwitchKey: "proxy.enabled",
	},
	{
		ID:    ModuleAutoMap,
		Label: "Automatic ports",
		Description: "Open a fixed local port for every device on the tailnet, so peer.local:22 " +
			"becomes localhost:14002 and stays there across restarts.",
		SwitchKey: "automap.enabled",
	},
	{
		ID:    ModuleExitNode,
		Label: "Exit node",
		Description: "Route this device's other traffic through a device on your tailnet. " +
			"app-tail routes in userspace, so this applies to what goes through its proxy " +
			"and its forwards rather than to every program on this machine.",
		SwitchKey: "exitNode.enabled",
	},
	{
		ID:    ModuleRouting,
		Label: "Subnet routes",
		Description: "Reach the private networks other devices advertise. app-tail routes in " +
			"userspace, so those networks are reachable through its proxy and its forwards " +
			"rather than from every program on this machine.",
		SwitchKey: "routes.enabled",
	},
	{
		ID:    ModuleDNS,
		Label: "Tailnet DNS",
		Description: "Resolve names with your tailnet's own DNS, including split-DNS domains " +
			"pointed at a private nameserver. This applies to what app-tail looks up; it " +
			"changes nothing about how other programs on this machine resolve names.",
		SwitchKey: "dns.enabled",
	},
	{
		ID:    ModuleSystemDNS,
		Label: "System resolver",
		Description: "Choose which DNS servers this whole machine uses, including DNS over TLS " +
			"and DNS over HTTPS, and switch between them in one click. Names that belong to " +
			"the network you are on keep resolving through that network. This is one of the " +
			"two modules that change the machine rather than only app-tail: it needs " +
			"administrator rights once, and it puts your settings back when it is switched off.",
		SwitchKey: "systemDns.enabled",
	},
	{
		ID:    ModuleDNSBlock,
		Label: "Blocking",
		Description: "Refuse names on lists you choose -- Hagezi, StevenBlack, OISD, threat " +
			"feeds -- rather than resolving them. The lists are downloaded and matched on " +
			"this machine, and two separate switches say where they apply: to what app-tail " +
			"itself looks up, and to what the whole machine looks up.",
		SwitchKey: "dnsBlock.enabled",
	},
	{
		ID:    ModuleSecurity,
		Label: "Security",
		Description: "Block incoming tailnet connections, and choose whether this device " +
			"reports posture information about itself back to your tailnet.",
		SwitchKey: "security.enabled",
	},
	{
		ID:    ModuleInterface,
		Label: "Network interface",
		Description: "Create a real network interface so tailnet addresses and MagicDNS " +
			"names work in every program on this machine, with nothing to configure per " +
			"program. This is the only module that changes the machine: it needs a " +
			"privileged helper, and it writes routes and resolver files outside app-tail's " +
			"own directory.",
		SwitchKey: "interface.enabled",
	},
	{
		ID:    ModuleTelemetry,
		Label: "Logs",
		Description: "Keep a history of what this app did: the tailnet node connecting and " +
			"dropping, forwards starting and stopping, the resolver being claimed and put " +
			"back, and every settings change. It records nothing until you turn it on, " +
			"keeps what it records in memory only unless you also turn on storing it, and " +
			"sends none of it anywhere.",
		SwitchKey: "telemetry.enabled",
	},
	{
		ID:    ModuleIPS,
		Label: "Traffic inspection",
		Description: "Examine every connection app-tail carries against lists of names and " +
			"addresses, and report the ones that match. It starts by reporting only: nothing " +
			"is refused until you say so, so you can see what it would have stopped before it " +
			"stops anything. It reads what app-tail carries and nothing else, and matches it " +
			"on this machine.",
		SwitchKey: "ips.enabled",
	},
}

// FeatureModules returns the optional modules in display order.
func FeatureModules() []ModuleInfo { return featureModules }

// ModulesFor returns the modules these fields are gated on, in display order.
//
// An entity whose fields are gated on a switch it does not itself hold cannot tell which
// switch that is, and a form that cannot tell has only the availability it was served --
// which stops being true the moment the switch moves. Serving the whole list instead would
// name modules no field of this entity belongs to.
func ModulesFor(fields []FieldSchema) []ModuleInfo {
	named := make(map[FeatureModule]bool, len(fields))
	for _, f := range fields {
		named[f.Module] = true
	}
	out := make([]ModuleInfo, 0, len(named))
	for _, m := range featureModules {
		if named[m.ID] {
			out = append(out, m)
		}
	}
	return out
}

// ModuleLabel is a module's human name, for a message that has to explain why a
// setting is unavailable.
func ModuleLabel(m FeatureModule) string {
	for _, info := range featureModules {
		if info.ID == m {
			return info.Label
		}
	}
	return m.String()
}

// moduleSwitchByModule maps each module to the registry field whose value turns it on.
var moduleSwitchByModule = indexModuleSwitches(settingsFields)

func indexModuleSwitches(fields []SettingField) map[FeatureModule]SettingField {
	index := make(map[FeatureModule]SettingField, len(fields))
	for _, f := range fields {
		if f.ModuleSwitch != ModuleCore {
			index[f.ModuleSwitch] = f
		}
	}
	return index
}

// onThisPlatform reports whether this setting does anything on the running OS.
func (f FieldOf[T]) onThisPlatform() bool {
	if len(f.Platforms) == 0 {
		return true
	}
	return slices.Contains(f.Platforms, runtime.GOOS)
}

// PlatformLabel is a GOOS value as a person names it.
func PlatformLabel(goos string) string {
	switch goos {
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	default:
		return goos
	}
}

// platformList renders the platforms a setting applies to as prose, since the reason
// carrying it is shown verbatim wherever the setting would have been.
func platformList(goos []string) string {
	labels := make([]string, len(goos))
	for i, name := range goos {
		labels[i] = PlatformLabel(name)
	}
	switch len(labels) {
	case 1:
		return labels[0]
	case 2:
		return labels[0] + " and " + labels[1]
	default:
		return strings.Join(labels[:len(labels)-1], ", ") + " and " + labels[len(labels)-1]
	}
}

// moduleSwitchFor returns the field whose value decides whether a module is on.
func moduleSwitchFor(m FeatureModule) (SettingField, bool) {
	f, ok := moduleSwitchByModule[m]
	return f, ok
}

// Available reports whether this field can be seen and written, and why not when it
// cannot. A field whose module is switched off is hidden from every surface and rejected
// by name if patched, which is what makes "install minimally, opt in to the rest"
// mechanical rather than a promise.
//
// It takes the global settings whatever entity the field belongs to, because both gates
// it applies are facts about the installation rather than about the entity: which OS is
// running, and which modules the user turned on.
//
// The reason names the module by its label rather than by the switch's wire key: it is
// rendered verbatim by the dashboard, the tray and the CLI, each of which calls that
// switch something different, and only the label is a word all three show. A client that
// needs to reach the control itself reads SwitchKey off the module table.
func (f FieldOf[T]) Available(s *Settings) (bool, string) {
	// Before the module check: a setting this platform cannot act on stays unavailable
	// however the modules are set, so naming a switch to turn on would send someone
	// after a change that cannot help.
	if !f.onThisPlatform() {
		return false, fmt.Sprintf("not available on %s; this setting applies to %s",
			PlatformLabel(runtime.GOOS), platformList(f.Platforms))
	}
	if f.Module == ModuleCore {
		return true, ""
	}
	sw, ok := moduleSwitchFor(f.Module)
	if !ok {
		// Nothing can turn this module on, so its settings fail closed rather than
		// being exposed with no switch governing them.
		return false, fmt.Sprintf("belongs to the %s module, which has no switch to turn on", ModuleLabel(f.Module))
	}
	if !typed[bool](sw.get(s)) {
		return false, fmt.Sprintf("needs the %s module turned on", ModuleLabel(f.Module))
	}
	return true, ""
}

// Constraint is a setting's declared bounds. It is the one place a limit is written:
// the patch decoder, the CLI parser and the document validator all check against it,
// and the schema carries it so a client renders the same limit instead of discovering
// it from a rejected save.
type Constraint struct {
	// Min and Max are pointers so that a bound of zero is expressible; a setting with
	// neither accepts anything its type holds.
	Min *int `json:"min,omitempty"`
	Max *int `json:"max,omitempty"`
}

// between declares an inclusive range.
func between(lo, hi int) Constraint { return Constraint{Min: &lo, Max: &hi} }

// atLeast declares a lower bound with no upper one.
func atLeast(lo int) Constraint { return Constraint{Min: &lo} }

// check applies the declared bounds to a typed value, returning the bare reason. The
// phrasings are the ones these settings have always been rejected with, so a client or
// a test that matches on them keeps working.
func (c Constraint) check(v any) error {
	n, ok := v.(int)
	if !ok {
		return nil
	}
	switch {
	case c.Min != nil && c.Max != nil:
		if n < *c.Min || n > *c.Max {
			return fmt.Errorf("must be %d-%d, got %d", *c.Min, *c.Max, n)
		}
	case c.Min != nil:
		if n < *c.Min {
			return fmt.Errorf("must be >= %d, got %d", *c.Min, n)
		}
	case c.Max != nil:
		if n > *c.Max {
			return fmt.Errorf("must be <= %d, got %d", *c.Max, n)
		}
	}
	return nil
}
