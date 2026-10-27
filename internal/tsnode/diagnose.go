// SPDX-License-Identifier: MIT

package tsnode

import (
	"fmt"
	"strings"
)

// Diagnose explains why a node with a non-interactive credential is not Running.
// Landing in NeedsLogin with an OAuth secret or auth key in hand always means the
// credential or the tailnet policy is wrong, and the backend's own error is too
// vague to act on, so this names the causes worth checking.
//
// It returns an empty string when the situation needs no explanation.
func Diagnose(mode AuthMode, state string, tags []string, backendErr string) string {
	switch state {
	case StateNeedsMachineAuth:
		return "This node joined but is waiting for approval. Your tailnet has device approval " +
			"enabled: approve it in the admin console under Machines."
	case StateNeedsLogin, StateStopped, StateNoState:
	default:
		return ""
	}

	switch mode {
	case AuthOAuth:
		var b strings.Builder
		b.WriteString("An OAuth client secret is configured but the node could not enroll. Check that ")
		if len(tags) == 0 {
			b.WriteString("a tag is set (an OAuth identity is ownerless and must be tagged), that ")
		} else {
			fmt.Fprintf(&b, "%s exists in your tailnet (see Tag setup on the dashboard), that ", strings.Join(tags, " and "))
		}
		b.WriteString("the OAuth client owns that tag and has the auth_keys scope, and that device " +
			"approval (if enabled) has approved this node.")
		if backendErr != "" {
			fmt.Fprintf(&b, " The control plane said: %s", backendErr)
		}
		return b.String()
	case AuthKey:
		msg := "An auth key is configured but the node could not enroll. The key may be expired, " +
			"already used (make it reusable), or missing pre-authorization for a tailnet with device approval."
		if backendErr != "" {
			msg += " The control plane said: " + backendErr
		}
		return msg
	case AuthInteractive:
		// A browser login legitimately idles in NeedsLogin until the user clicks the
		// link, so only speak up once control has actually reported an error. The
		// exact rejection text is server-generated, so this never pattern-matches it;
		// it always names the fix and the escape hatch.
		if backendErr == "" {
			return ""
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Sign-in with advertised tags failed. The control plane said: %s.", backendErr)
		if len(tags) > 0 {
			fmt.Fprintf(&b, " If that mentions tags, %s does not exist in your tailnet yet: "+
				"open Tag setup on the dashboard for the steps, or turn off ", strings.Join(tags, " and "))
		} else {
			b.WriteString(" Turn off ")
		}
		b.WriteString(`"Advertise tags on login" in Settings and sign in untagged.`)
		return b.String()
	default:
		return ""
	}
}

// diagnose refreshes the cached problem explanation for the current state.
func (n *Node) diagnose(state string) {
	// Non-interactive credentials always warrant an explanation when they stall; an
	// interactive login does only when it opted into advertising tags, since that is
	// the one interactive path that can be rejected by the control plane.
	interactiveTagged := n.params.Mode == AuthInteractive && len(n.params.AdvertiseTags) > 0
	if !n.params.NonInteractive() && !interactiveTagged {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	// Preserve any error the backend reported; it is the most specific signal we have.
	backendErr := n.status.Problem
	if state == StateRunning {
		n.status.Problem = ""
		return
	}
	if msg := Diagnose(n.params.Mode, state, n.params.AdvertiseTags, backendErr); msg != "" {
		n.status.Problem = msg
	}
}
