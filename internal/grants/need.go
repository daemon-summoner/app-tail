// SPDX-License-Identifier: MIT

package grants

import (
	"errors"
	"slices"
	"strings"
)

// Kind is which approval a change is missing. The values cross the helper's socket and reach
// the dashboard, so they are part of the protocol: a client acts on the kind and shows the
// reason.
type Kind string

const (
	KindFullTunnel      Kind = "full-tunnel"
	KindRoute           Kind = "route"
	KindSystemDNS       Kind = "system-dns"
	KindDNSDomain       Kind = "dns-domain"
	KindOpenVPNRemote   Kind = "openvpn-remote"
	KindTLSInterception Kind = "tls-interception"
)

// Need is one approval a change is missing.
type Need struct {
	Kind Kind `json:"kind"`
	// Value is what the approval has to name: a range for a route, a domain, or a server as
	// host:port. Empty for the kinds that are a single yes or no.
	Value string `json:"value,omitempty"`
	// CASHA256 is, for an OpenVPN server, the certificates its connection trusts, which the
	// approval has to name as well.
	CASHA256 []string `json:"caSha256,omitempty"`
	// Reason is the sentence a person reads: what would change about this machine.
	Reason string `json:"reason"`
}

// Flag is the `tun grant` argument that approves this need.
func (n Need) Flag() string {
	switch n.Kind {
	case KindFullTunnel:
		return "--full-tunnel"
	case KindRoute:
		return "--route=" + n.Value
	case KindSystemDNS:
		return "--system-dns"
	case KindDNSDomain:
		return "--dns-domain=" + n.Value
	case KindOpenVPNRemote:
		return "--openvpn=" + n.Value + "=" + strings.Join(n.CASHA256, ",")
	case KindTLSInterception:
		return "--tls-interception"
	}
	return ""
}

// GrantArgs is the command line, after the program name, that approves every need: what an
// approval flow runs with administrator rights.
func GrantArgs(needs []Need) []string {
	return append([]string{"tun", "grant"}, GrantFlags(needs)...)
}

// GrantFlags is the `tun grant` flags that approve every need, each once.
func GrantFlags(needs []Need) []string {
	var flags []string
	for _, need := range needs {
		if flag := need.Flag(); flag != "" && !slices.Contains(flags, flag) {
			flags = append(flags, flag)
		}
	}
	return flags
}

// ErrNeedsGrant is what every refusal for a missing approval matches, for a caller that only
// needs to know the answer was "not yet approved" rather than "broken".
var ErrNeedsGrant = errors.New("this change needs an administrator's approval")

// MissingGrants is a change refused because an administrator has not approved all of it.
// It matches ErrNeedsGrant.
type MissingGrants struct {
	Needs []Need
}

func (m *MissingGrants) Error() string {
	var b strings.Builder
	b.WriteString(ErrNeedsGrant.Error())
	for i, need := range m.Needs {
		if i == 0 {
			b.WriteString(": ")
		} else {
			b.WriteString("; ")
		}
		b.WriteString(need.Reason)
	}
	b.WriteString(". An administrator approves it with `app-tail ")
	b.WriteString(strings.Join(GrantArgs(m.Needs), " "))
	b.WriteString("`")
	return b.String()
}

// Is makes the refusal match ErrNeedsGrant.
func (m *MissingGrants) Is(target error) bool { return target == ErrNeedsGrant }

// appendNeed adds a need unless one with the same kind and value is already there: one
// approval answers both, and a person asked twice for the same thing reads it as two.
func appendNeed(needs []Need, need Need) []Need {
	for _, have := range needs {
		if have.Kind == need.Kind && have.Value == need.Value {
			return needs
		}
	}
	return append(needs, need)
}
