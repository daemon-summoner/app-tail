// SPDX-License-Identifier: MIT

package config

// How app-tail runs on this machine, read off the switches that decide it.
//
// The switches stay independent -- the proxy and the network interface layer, and one
// does not turn the other off -- so this is not a fourth switch beside them. It is the
// one-word answer to "what is app-tail doing to this machine", derived in one place so
// the dashboard, the tray and the CLI cannot each reach a different one.

// RunMode is how much of this machine app-tail is arranged to serve.
type RunMode string

const (
	// RunStandalone touches nothing outside app-tail. Forwards still open their local
	// ports; nothing else on the machine reaches the networks.
	RunStandalone RunMode = "standalone"
	// RunProxy serves programs that are pointed at app-tail's proxy, and still changes
	// nothing about the machine.
	RunProxy RunMode = "proxy"
	// RunInterface puts the machine itself on the tailnet, which needs the privileged
	// helper.
	RunInterface RunMode = "interface"
	// RunFabric puts the machine on every connected network at once, on one interface
	// that ends each flow and re-dials it inside the network the address belonged to. It
	// is the only arrangement that reaches two networks carrying the same addresses.
	RunFabric RunMode = "fabric"
)

// runModeOptions is the mode list in the order it is offered, least to most of the
// machine touched, with the switches each mode is a name for.
//
// Choosing a mode writes Applies, and PrimaryMode reads the result back, so the two
// halves are this one table. Splitting them would produce a picker that does not stay
// where it is put, and the test beside this file is what holds them together.
var runModeOptions = []EnumOption{
	{
		Value: string(RunStandalone), Label: "Standalone",
		Help: "app-tail changes nothing about this machine. Your forwards open local " +
			"ports; nothing else here can reach your networks.",
		// The interface module is switched off rather than left selected-but-idle, which
		// is what puts its own settings back to their defaults: a stored mode still
		// reading "tun" under a machine that touches nothing is a setting nobody can see
		// and nobody turned on.
		Applies: map[string]any{
			"proxy.enabled":     false,
			"interface.enabled": false,
		},
	},
	{
		Value: string(RunProxy), Label: "Proxy",
		Help: "Programs you point at app-tail reach your networks. Nothing else on this " +
			"machine is touched, and no administrator rights are needed.",
		Applies: map[string]any{
			"proxy.enabled":     true,
			"interface.enabled": false,
		},
	},
	{
		Value: string(RunInterface), Label: "Network interface for the tailnet",
		Help: "Every program on this machine reaches your tailnet by name and address, over " +
			"a real network interface that carries every protocol. Only the tailnet: your " +
			"other connections stay reachable through forwards and the proxy. Installs a " +
			"network interface and needs administrator rights once.",
		// The proxy is deliberately absent: the two layer, and a machine on the interface
		// may still want a proxy for a program that is pointed at one. Turning it off here
		// would take away a running service nobody asked to stop.
		Applies: map[string]any{
			"interface.enabled": true,
			"interface.mode":    string(NetworkTUN),
		},
	},
	{
		Value: string(RunFabric), Label: "One interface for every network",
		Help: "Every program on this machine reaches every connected network, including two " +
			"networks that use the same addresses. app-tail ends each connection at the " +
			"interface and opens it again inside the right network, so only TCP and UDP " +
			"cross and every byte passes through app-tail. Needs administrator rights once.",
		Applies: map[string]any{
			"interface.enabled": true,
			"interface.mode":    string(NetworkFabric),
		},
	},
}

// PrimaryMode reports how app-tail is arranged to run.
//
// An interface wins over the proxy when both are on, because it is the larger statement
// about the machine: a machine on an interface is on the network whether or not anything
// is pointed at the proxy. Which other modules are also running is a separate question,
// and the mode screen asks it separately rather than folding it in here.
func PrimaryMode(s Settings) RunMode {
	switch {
	case s.FabricSelected():
		return RunFabric
	case s.TunSelected():
		return RunInterface
	case s.ProxyEnabled:
		return RunProxy
	default:
		return RunStandalone
	}
}
