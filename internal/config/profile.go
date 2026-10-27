// SPDX-License-Identifier: MIT

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/tailscale/hujson"
)

// ProfileForwardIDPrefix marks forwards created from a provisioning profile.
// Reconciliation only ever removes forwards carrying this prefix, so operator-created
// forwards on a provisioned node are never touched by a profile update.
const ProfileForwardIDPrefix = "fp_"

// Profile is a distributable fleet template: the settings every node in a fleet shares
// plus the forwards it should come up running. It carries a reference to the OAuth
// secret rather than the secret itself.
type Profile struct {
	Settings ProfileSettings  `json:"settings"`
	Forwards []ProfileForward `json:"forwards"`
}

// ProfileSettings uses pointers so a profile can leave a field alone rather than
// resetting it to a zero value.
type ProfileSettings struct {
	HostnameTemplate      *string   `json:"hostnameTemplate"`
	Tags                  *[]string `json:"tags"`
	Ephemeral             *bool     `json:"ephemeral"`
	AdvertiseTagsOnLogin  *bool     `json:"advertiseTagsOnLogin"`
	ControlURL            *string   `json:"controlURL"`
	OAuthClientSecretFile *string   `json:"oauthClientSecretFile"`
	UIListenAddr          *string   `json:"uiListenAddr"`
	ShowTray              *bool     `json:"showTray"`
	AutoOpenDashboard     *bool     `json:"autoOpenDashboard"`
	StartAtLogin          *bool     `json:"startAtLogin"`
	UDPSessionTimeoutSec  *int      `json:"udpSessionTimeoutSec"`
	UDPBufferBytes        *int      `json:"udpBufferBytes"`
}

// ProfileForward declares one forward. Targets should use MagicDNS names so a single
// profile resolves correctly on every node in the fleet regardless of IPs.
type ProfileForward struct {
	Name          string    `json:"name"`
	Direction     Direction `json:"direction"`
	Protocol      Protocol  `json:"protocol"`
	BindAddr      string    `json:"bindAddr"`
	ListenPort    int       `json:"listenPort"`
	Target        string    `json:"target"`
	Enabled       *bool     `json:"enabled"`
	UDPTimeoutSec int       `json:"udpTimeoutSec"`
	// ExposeToNetwork is required for a bindAddr other machines can reach, as on a
	// stored forward.
	ExposeToNetwork bool `json:"exposeToNetwork"`
}

// LoadProfile reads and parses a provisioning profile.
func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile %s: %w", path, err)
	}
	// Accept comments and trailing commas so a distributed fleet profile can document
	// itself inline; Standardize rewrites them to spaces before the strict decode.
	standard, err := hujson.Standardize(data)
	if err != nil {
		return nil, fmt.Errorf("parse profile %s: %w", path, err)
	}
	var p Profile
	if err := json.Unmarshal(standard, &p); err != nil {
		return nil, fmt.Errorf("parse profile %s: %w", path, err)
	}
	return &p, nil
}

// toForward converts a declared forward into a stored one with a deterministic id
// derived from its endpoint identity, which is what makes re-provisioning a no-op.
func (pf ProfileForward) toForward() Forward {
	f := Forward{
		Name:            pf.Name,
		Direction:       pf.Direction,
		Protocol:        pf.Protocol,
		BindAddr:        pf.BindAddr,
		ListenPort:      pf.ListenPort,
		Target:          pf.Target,
		Enabled:         true,
		UDPTimeoutSec:   pf.UDPTimeoutSec,
		ExposeToNetwork: pf.ExposeToNetwork,
	}
	if pf.Enabled != nil {
		f.Enabled = *pf.Enabled
	}
	if f.Direction == ToLocal && f.BindAddr == "" {
		f.BindAddr = DefaultBindAddr
	}
	f.ID = profileForwardID(f)
	return f
}

func profileForwardID(f Forward) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%d\x00%s", f.Direction, f.Protocol, f.BindAddr, f.ListenPort, f.Target)
	return ProfileForwardIDPrefix + hex.EncodeToString(h.Sum(nil))[:8]
}

// Apply merges the profile into cfg: declared settings overwrite local ones, and the
// set of profile-managed forwards is reconciled to exactly what the profile declares.
// Forwards the operator added locally are preserved.
func (p *Profile) Apply(cfg *Config) error {
	ps := p.Settings
	// A profile written before connections were a list names the tailnet without saying
	// which, so it means the one every install has.
	if ps.HostnameTemplate != nil || ps.Tags != nil || ps.Ephemeral != nil ||
		ps.AdvertiseTagsOnLogin != nil || ps.ControlURL != nil || ps.OAuthClientSecretFile != nil {
		primary, err := cfg.PrimaryTailscale()
		if err != nil {
			return err
		}
		if ps.HostnameTemplate != nil {
			primary.HostnameTemplate = *ps.HostnameTemplate
		}
		if ps.Tags != nil {
			primary.Tags = append([]string(nil), (*ps.Tags)...)
		}
		if ps.Ephemeral != nil {
			primary.Ephemeral = *ps.Ephemeral
		}
		if ps.AdvertiseTagsOnLogin != nil {
			primary.AdvertiseTagsOnLogin = *ps.AdvertiseTagsOnLogin
		}
		if ps.ControlURL != nil {
			primary.ControlURL = *ps.ControlURL
		}
		if ps.OAuthClientSecretFile != nil {
			primary.OAuthClientSecretFile = *ps.OAuthClientSecretFile
		}
	}
	if ps.UIListenAddr != nil {
		cfg.Settings.UIListen = *ps.UIListenAddr
	}
	if ps.ShowTray != nil {
		cfg.Settings.ShowTray = *ps.ShowTray
	}
	if ps.AutoOpenDashboard != nil {
		cfg.Settings.AutoOpenDashboard = *ps.AutoOpenDashboard
	}
	if ps.StartAtLogin != nil {
		cfg.Settings.StartAtLogin = *ps.StartAtLogin
	}
	if ps.UDPSessionTimeoutSec != nil {
		cfg.Settings.UDPSessionTimeoutSec = *ps.UDPSessionTimeoutSec
	}
	if ps.UDPBufferBytes != nil {
		cfg.Settings.UDPBufferBytes = *ps.UDPBufferBytes
	}

	declared := make([]Forward, 0, len(p.Forwards))
	seen := make(map[string]struct{}, len(p.Forwards))
	for i, pf := range p.Forwards {
		f := pf.toForward()
		if err := ValidateForward(f); err != nil {
			return fmt.Errorf("profile forward %d (%s): %w", i, pf.Name, err)
		}
		if _, dup := seen[f.ID]; dup {
			return fmt.Errorf("profile forward %d (%s): duplicate endpoint %s", i, pf.Name, Endpoint(f))
		}
		seen[f.ID] = struct{}{}
		declared = append(declared, f)
	}

	kept := make([]Forward, 0, len(cfg.Forwards)+len(declared))
	for _, f := range cfg.Forwards {
		if isProfileManaged(f.ID) {
			continue // replaced wholesale by the declared set below
		}
		if _, clash := seen[f.ID]; clash {
			continue
		}
		kept = append(kept, f)
	}
	cfg.Forwards = append(kept, declared...)
	return nil
}

func isProfileManaged(id string) bool {
	return len(id) > len(ProfileForwardIDPrefix) && id[:len(ProfileForwardIDPrefix)] == ProfileForwardIDPrefix
}

// Provision applies a profile through the store so the merge is validated and
// persisted atomically. Re-running it with the same profile is a no-op.
func Provision(store *Store, p *Profile) (*Config, error) {
	return store.Update(func(c *Config) error { return p.Apply(c) })
}

// SuggestName builds a readable default name for a forward when the user gave none.
func SuggestName(f Forward) string {
	return fmt.Sprintf("%s (%s)", f.Target, f.Protocol)
}
