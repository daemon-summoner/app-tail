// SPDX-License-Identifier: MIT

package tsnode

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
)

func baseSettings() config.Settings {
	s := config.Defaults().Settings
	s.MachineID = "abc123"
	return s
}

// baseTailnet is the settings of the connection the node joins with. The defaults come
// from the connection every install has, so a field this test does not name holds what a
// real install holds rather than a zero value.
func baseTailnet(t *testing.T) config.TailscaleTunnel {
	t.Helper()
	tn, ok := config.Defaults().Tunnel(config.PrimaryTunnelID)
	if !ok {
		t.Fatal("a fresh configuration carries no primary connection")
	}
	ts := tn.TS()
	ts.Hostname = "test-node"
	return ts
}

func TestBuildServerParamsSelectsAuthPath(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*config.TailscaleTunnel)
		oauthSecret string
		wantMode    AuthMode
		wantKey     string
		wantSecret  string
		wantTags    []string
	}{
		{
			name:        "oauth secret wins and advertises tags",
			mutate:      func(ts *config.TailscaleTunnel) { ts.AuthKey = "tskey-auth-also-set" },
			oauthSecret: "tskey-client-secret",
			wantMode:    AuthOAuth,
			wantSecret:  "tskey-client-secret",
			wantTags:    []string{config.DefaultTag},
		},
		{
			name:     "auth key when no oauth secret",
			mutate:   func(ts *config.TailscaleTunnel) { ts.AuthKey = "tskey-auth-xyz" },
			wantMode: AuthKey,
			wantKey:  "tskey-auth-xyz",
			wantTags: nil,
		},
		{
			name:     "interactive when no credential",
			mutate:   func(*config.TailscaleTunnel) {},
			wantMode: AuthInteractive,
		},
		{
			name:     "whitespace-only auth key is not a credential",
			mutate:   func(ts *config.TailscaleTunnel) { ts.AuthKey = "   " },
			wantMode: AuthInteractive,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := baseTailnet(t)
			tc.mutate(&ts)
			p, err := BuildServerParams(ts, baseSettings(), "/state", tc.oauthSecret)
			if err != nil {
				t.Fatalf("BuildServerParams: %v", err)
			}
			if p.Mode != tc.wantMode {
				t.Errorf("mode = %q, want %q", p.Mode, tc.wantMode)
			}
			if p.AuthKey != tc.wantKey {
				t.Errorf("AuthKey = %q, want %q", p.AuthKey, tc.wantKey)
			}
			if p.ClientSecret != tc.wantSecret {
				t.Errorf("ClientSecret = %q, want %q", p.ClientSecret, tc.wantSecret)
			}
			if !reflect.DeepEqual(p.AdvertiseTags, tc.wantTags) {
				t.Errorf("AdvertiseTags = %v, want %v", p.AdvertiseTags, tc.wantTags)
			}
			if p.Dir != "/state" {
				t.Errorf("Dir = %q, want /state", p.Dir)
			}
		})
	}
}

func TestBuildServerParamsRequiresTagsWithOAuth(t *testing.T) {
	// Omitting the tag is the single most common zero-touch enrollment failure,
	// so it must be caught before the node ever contacts the control plane.
	ts := baseTailnet(t)
	ts.Tags = nil
	_, err := BuildServerParams(ts, baseSettings(), "/state", "tskey-client-secret")
	if err == nil {
		t.Fatal("BuildServerParams accepted an OAuth secret with no tags")
	}
	if !strings.Contains(err.Error(), "tag") {
		t.Errorf("error %q does not explain that a tag is required", err)
	}
}

func TestBuildServerParamsDoesNotAdvertiseTagsWithAuthKey(t *testing.T) {
	// A tagged auth key already carries its tags; re-advertising them is rejected
	// by the control plane.
	ts := baseTailnet(t)
	ts.AuthKey = "tskey-auth-xyz"
	ts.Tags = []string{"tag:app-tail"}
	p, err := BuildServerParams(ts, baseSettings(), "/state", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.AdvertiseTags) != 0 {
		t.Errorf("AdvertiseTags = %v, want none for the auth-key path", p.AdvertiseTags)
	}
}

func TestBuildServerParamsAdvertisesTagsOnLogin(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*config.TailscaleTunnel)
		wantMode AuthMode
		wantTags []string
	}{
		{
			name:     "interactive with the toggle on advertises the configured tags",
			mutate:   func(ts *config.TailscaleTunnel) { ts.AdvertiseTagsOnLogin = true },
			wantMode: AuthInteractive,
			wantTags: []string{config.DefaultTag},
		},
		{
			name:     "interactive with the toggle off advertises nothing",
			mutate:   func(ts *config.TailscaleTunnel) { ts.AdvertiseTagsOnLogin = false },
			wantMode: AuthInteractive,
			wantTags: nil,
		},
		{
			name: "toggle on but no tags advertises nothing",
			mutate: func(ts *config.TailscaleTunnel) {
				ts.AdvertiseTagsOnLogin = true
				ts.Tags = nil
			},
			wantMode: AuthInteractive,
			wantTags: nil,
		},
		{
			name: "toggle is ignored on the auth-key path",
			mutate: func(ts *config.TailscaleTunnel) {
				ts.AdvertiseTagsOnLogin = true
				ts.AuthKey = "tskey-auth-xyz"
			},
			wantMode: AuthKey,
			wantTags: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := baseTailnet(t)
			tc.mutate(&ts)
			p, err := BuildServerParams(ts, baseSettings(), "/state", "")
			if err != nil {
				t.Fatalf("BuildServerParams: %v", err)
			}
			if p.Mode != tc.wantMode {
				t.Errorf("mode = %q, want %q", p.Mode, tc.wantMode)
			}
			if !reflect.DeepEqual(p.AdvertiseTags, tc.wantTags) {
				t.Errorf("AdvertiseTags = %v, want %v", p.AdvertiseTags, tc.wantTags)
			}
		})
	}
}

func TestBuildServerParamsRendersHostname(t *testing.T) {
	t.Run("explicit hostname is sanitized", func(t *testing.T) {
		ts := baseTailnet(t)
		ts.Hostname = "My Build Box"
		p, err := BuildServerParams(ts, baseSettings(), "/state", "")
		if err != nil {
			t.Fatal(err)
		}
		if p.Hostname != "my-build-box" {
			t.Errorf("Hostname = %q, want my-build-box", p.Hostname)
		}
	})

	t.Run("template renders when no explicit hostname", func(t *testing.T) {
		ts := baseTailnet(t)
		ts.Hostname = ""
		ts.HostnameTemplate = "app-tail-{id}"
		p, err := BuildServerParams(ts, baseSettings(), "/state", "")
		if err != nil {
			t.Fatal(err)
		}
		if p.Hostname != "app-tail-abc123" {
			t.Errorf("Hostname = %q, want app-tail-abc123", p.Hostname)
		}
	})
}

func TestBuildServerParamsPassesThroughNodeOptions(t *testing.T) {
	ts := baseTailnet(t)
	ts.ControlURL = "https://headscale.example.com"
	ts.Ephemeral = true
	p, err := BuildServerParams(ts, baseSettings(), "/state", "")
	if err != nil {
		t.Fatal(err)
	}
	if p.ControlURL != "https://headscale.example.com" {
		t.Errorf("ControlURL = %q, want the configured value", p.ControlURL)
	}
	if !p.Ephemeral {
		t.Error("Ephemeral was not carried through")
	}
}

func TestNonInteractive(t *testing.T) {
	tests := []struct {
		mode AuthMode
		want bool
	}{
		{AuthOAuth, true},
		{AuthKey, true},
		{AuthInteractive, false},
	}
	for _, tc := range tests {
		if got := (ServerParams{Mode: tc.mode}).NonInteractive(); got != tc.want {
			t.Errorf("NonInteractive(%q) = %v, want %v", tc.mode, got, tc.want)
		}
	}
}

// The node is built on the stack the module selects, and only while the module is on. A
// mode left behind by a module somebody switched off would otherwise decide which stack the
// node runs on -- silently putting an interface on a machine whose owner turned the feature
// off and never changed the mode back.
func TestOnlyASelectedInterfaceModeDecidesTheStackTheNodeRunsOn(t *testing.T) {
	tests := []struct {
		name          string
		enabled       bool
		mode          config.NetworkMode
		wantNetwork   config.NetworkMode
		wantInterface string
	}{
		{
			name: "the mode this app installs as", mode: config.NetworkUserspace,
			wantNetwork: config.NetworkUserspace,
		},
		{
			name:    "the module on and the interface mode chosen",
			enabled: true, mode: config.NetworkTUN,
			wantNetwork: config.NetworkTUN, wantInterface: "utun9",
		},
		{
			name:    "the module on and the contained mode chosen",
			enabled: true, mode: config.NetworkUserspace,
			wantNetwork: config.NetworkUserspace,
		},
		{
			name: "the mode left behind by a module that was switched off",
			mode: config.NetworkTUN, wantNetwork: config.NetworkUserspace,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := baseSettings()
			s.InterfaceEnabled = tc.enabled
			s.InterfaceMode = tc.mode
			s.InterfaceName = "utun9"

			got, err := BuildServerParams(baseTailnet(t), s, t.TempDir(), "")
			if err != nil {
				t.Fatalf("BuildServerParams: %v", err)
			}
			if got.Network != tc.wantNetwork {
				t.Errorf("the node would be built on the %q stack, want %q", got.Network, tc.wantNetwork)
			}
			// On the contained stack this names an interface nothing creates, and the
			// status that reports it also says there is none.
			if got.InterfaceName != tc.wantInterface {
				t.Errorf("the node was given the interface name %q, want %q", got.InterfaceName, tc.wantInterface)
			}
		})
	}
}

// The auth key is handed to the control server as it stands. Something that is not
// shaped like a Tailscale credential -- a pasted paragraph, a value an environment
// variable picked up from somewhere else -- is refused before it leaves, and the refusal
// does not repeat it into a log.
func TestAnAuthKeyThatIsNotACredentialShapeIsRefused(t *testing.T) {
	for _, key := range []string{"hunter2", "tskey-auth-abc def", "-----BEGIN OPENSSH PRIVATE KEY-----"} {
		ts := baseTailnet(t)
		ts.AuthKey = key
		p, err := BuildServerParams(ts, baseSettings(), "/state", "")
		if err == nil {
			t.Errorf("BuildServerParams accepted auth key %q and would send it as %q", key, p.AuthKey)
			continue
		}
		if strings.Contains(err.Error(), key) {
			t.Errorf("the refusal repeats the value: %v", err)
		}
	}
}

func TestAnOAuthSecretThatIsNotACredentialShapeIsRefused(t *testing.T) {
	_, err := BuildServerParams(baseTailnet(t), baseSettings(), "/state", "hunter2")
	if err == nil {
		t.Fatal("BuildServerParams accepted an OAuth secret that is not shaped like one")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("the refusal repeats the value: %v", err)
	}
}
