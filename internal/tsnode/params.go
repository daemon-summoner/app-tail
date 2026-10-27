// SPDX-License-Identifier: MIT

package tsnode

import (
	"fmt"
	"reflect"

	"github.com/sellitus/app-tail/internal/config"
)

// AuthMode is the credential path a node uses to join the tailnet.
type AuthMode string

const (
	// AuthOAuth exchanges a fleet OAuth client secret for a tagged auth key. Zero-touch.
	AuthOAuth AuthMode = "oauth"
	// AuthKey uses a pre-made auth key. Headless, one credential per fleet or node.
	AuthKey AuthMode = "authkey"
	// AuthInteractive falls back to the browser login flow.
	AuthInteractive AuthMode = "interactive"
)

// ServerParams is the subset of tsnet.Server configuration this app derives from
// settings. Keeping it a plain struct makes credential selection testable without
// standing up a tsnet server.
type ServerParams struct {
	Hostname      string
	Dir           string
	ControlURL    string
	AuthKey       string
	ClientSecret  string
	AdvertiseTags []string
	Ephemeral     bool
	Mode          AuthMode
	// Network is the stack the node runs on. The zero value is userspace, so a caller
	// that knows nothing about interfaces gets the contained node it expects.
	Network config.NetworkMode
	// InterfaceName is the interface to create in TUN mode, empty for the platform
	// default. It is ignored in userspace mode, where there is no interface.
	InterfaceName string
}

// TUN reports whether these parameters describe a node on a real network interface.
func (p ServerParams) TUN() bool { return p.Network == config.NetworkTUN }

// SameAs reports whether two parameter sets describe the same node.
//
// It is what tells an edit to a connection from a change of identity: every field here is
// baked into the node at enrollment, so a difference in any of them means the running node
// is on a different network, under a different name, or as a different device, and no
// amount of reconciling turns it into the one that is now configured.
// It compares the whole value rather than the fields that matter today, so a member added
// later is covered without anyone having to remember this.
func (p ServerParams) SameAs(q ServerParams) bool { return reflect.DeepEqual(p, q) }

// BuildServerParams selects the auth path from the credentials present, in the
// priority order OAuth > auth key > interactive, and renders the node's hostname.
// oauthSecret is passed separately because it may have been read from a file.
//
// ts is one connection's own tailnet settings and s is the installation's. They are
// separate arguments because they answer different questions: which network this node
// joins and who it joins as comes from the connection, and whether this machine runs an
// interface at all comes from the installation, which is one answer for all of them.
func BuildServerParams(ts config.TailscaleTunnel, s config.Settings, stateDir, oauthSecret string) (ServerParams, error) {
	p := ServerParams{
		Hostname:   config.EffectiveHostname(ts, s.MachineID),
		Dir:        stateDir,
		ControlURL: ts.ControlURL,
		Ephemeral:  ts.Ephemeral,
		Network:    config.NetworkUserspace,
	}
	// TunSelected rather than the stored mode: a mode left behind by a switched-off
	// module must not decide which stack the node is built on.
	if s.TunSelected() {
		p.Network = config.NetworkTUN
		p.InterfaceName = s.InterfaceName
	}
	if p.Hostname == "" {
		return ServerParams{}, fmt.Errorf("could not derive a hostname for this node")
	}

	// Both credentials are checked here, the last point before either is handed to the
	// node, so one that arrived by the environment is held to the same shape as one that
	// came from the document or a file.
	switch {
	case oauthSecret != "":
		if err := config.CheckCredentialShape("the OAuth client secret", oauthSecret); err != nil {
			return ServerParams{}, err
		}
		// An OAuth identity is ownerless, so the control plane requires a tag.
		// Without one, enrollment fails with an opaque error at the control plane.
		if len(ts.Tags) == 0 {
			return ServerParams{}, fmt.Errorf("an OAuth client secret requires at least one tag (set tags or %s)", config.EnvTags)
		}
		p.Mode = AuthOAuth
		p.ClientSecret = oauthSecret
		p.AdvertiseTags = append([]string(nil), ts.Tags...)
	case ts.EffectiveAuthKey() != "":
		if err := config.CheckCredentialShape("the auth key", ts.EffectiveAuthKey()); err != nil {
			return ServerParams{}, err
		}
		p.Mode = AuthKey
		p.AuthKey = ts.EffectiveAuthKey()
		// A tagged auth key already carries its tags; advertising them again is
		// rejected by the control plane, so tags are deliberately not set here.
	default:
		p.Mode = AuthInteractive
		// A browser login is owned by the person signing in, so tags are advertised
		// only when they opt in. The login user must own these tags in tagOwners or
		// the control plane rejects the enrollment.
		if ts.AdvertiseTagsOnLogin && len(ts.Tags) > 0 {
			p.AdvertiseTags = append([]string(nil), ts.Tags...)
		}
	}
	return p, nil
}

// NonInteractive reports whether the node is expected to reach Running without a
// browser. Landing in NeedsLogin on this path means the credential is misconfigured.
func (p ServerParams) NonInteractive() bool {
	return p.Mode == AuthOAuth || p.Mode == AuthKey
}
