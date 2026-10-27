// SPDX-License-Identifier: MIT

package tunnel

// The one status vocabulary every tunnel reports in, so the dashboard, the tray and the
// CLI cannot describe the same connection differently.
//
// Off is a state with a body, not the absence of one, and not a fault: a tunnel the user
// has not enabled is working exactly as configured. Keeping it in the same enum as Failed
// is what stops a surface from rendering "not connected" in the colour it uses for
// "broken".

// State is what a tunnel is doing right now.
type State string

const (
	// StateOff means the tunnel is not enabled. Nothing is wrong.
	StateOff State = "off"
	// StateStarting means it is coming up but has not yet reached the point where it
	// knows whether it needs anything from the user.
	StateStarting State = "starting"
	// StateNeedsLogin means it cannot proceed without a person: an interactive login, a
	// device approval, a credential that was never supplied.
	StateNeedsLogin State = "needs-login"
	// StateConnecting means it has what it needs and is negotiating.
	StateConnecting State = "connecting"
	// StateConnected means traffic will cross.
	StateConnected State = "connected"
	// StateDegraded means traffic crosses but something the user asked for is not
	// happening -- a selected exit node that is offline, a route that was never
	// approved. It is the state most worth reporting on its own, because everything
	// looks fine from every other angle.
	StateDegraded State = "degraded"
	// StateFailed means it tried and could not.
	StateFailed State = "failed"
	// StateStopping means it is on the way down.
	StateStopping State = "stopping"
)

// Live reports whether traffic can cross right now. Degraded counts: something the user
// asked for is not happening, but connections still work, and refusing to dial would
// turn a partial outage into a total one.
func (s State) Live() bool { return s == StateConnected || s == StateDegraded }

// Label is the state as a person reads it, never as a bare word from the wire. Every
// surface shows the word as well as the colour, because a colour alone is unreadable to
// anyone who cannot distinguish the hues and to anyone reading a log.
func (s State) Label() string {
	switch s {
	case StateOff:
		return "Off"
	case StateStarting:
		return "Starting"
	case StateNeedsLogin:
		return "Needs sign-in"
	case StateConnecting:
		return "Connecting"
	case StateConnected:
		return "Connected"
	case StateDegraded:
		return "Connected with problems"
	case StateFailed:
		return "Failed"
	case StateStopping:
		return "Stopping"
	default:
		return string(s)
	}
}

// Status is the cached view of one tunnel. It is a value type, so a caller always holds
// an immutable snapshot rather than something the tunnel's own goroutine is rewriting.
type Status struct {
	State State
	// Detail explains a state that needs explaining, in a sentence shown verbatim: why
	// it failed, what it is waiting for, which part is degraded. Empty when the state
	// speaks for itself.
	Detail string
	// AuthURL is where a person completes an interactive login. Only ever set alongside
	// StateNeedsLogin.
	AuthURL string
	// Addrs are this tunnel's own addresses inside the network.
	Addrs []string
	// Names are the DNS names the network knows this device by.
	Names []string
	// Limits are the things this tunnel does not carry, stated up front and never
	// cleared. They are not errors: a userspace tunnel that cannot pass ICMP is working
	// as designed, and a user who learns that by hitting it files a bug instead.
	Limits []string
}
