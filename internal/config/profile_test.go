// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const fleetProfileJSON = `{
  "settings": {
    "hostnameTemplate": "fleet-{hostname}-{id}",
    "tags": ["tag:app-tail", "tag:fleet"],
    "ephemeral": false,
    "controlURL": "https://controlplane.example.com",
    "oauthClientSecretFile": "/run/secrets/oauth",
    "udpSessionTimeoutSec": 45
  },
  "forwards": [
    {"name": "Fleet DNS", "direction": "to_local", "protocol": "udp", "listenPort": 5353, "target": "dns-server:53"},
    {"name": "Metrics", "direction": "to_local", "protocol": "tcp", "listenPort": 9100, "target": "metrics-gw:9100"}
  ]
}`

// tailnetOf is the tailnet settings of the connection a profile writes to.
func tailnetOf(t *testing.T, cfg *Config) TailscaleTunnel {
	t.Helper()
	held, ok := cfg.Tunnel(PrimaryTunnelID)
	if !ok {
		t.Fatalf("the document holds no %q connection", PrimaryTunnelID)
	}
	return held.TS()
}

func writeProfile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadProfileAndApply(t *testing.T) {
	p, err := LoadProfile(writeProfile(t, fleetProfileJSON))
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}

	cfg := Defaults()
	if err := p.Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// A profile's tailnet settings land on the connection this app has always run.
	ts := tailnetOf(t, cfg)
	if ts.HostnameTemplate != "fleet-{hostname}-{id}" {
		t.Errorf("hostnameTemplate = %q, want the profile value", ts.HostnameTemplate)
	}
	if !reflect.DeepEqual(ts.Tags, []string{"tag:app-tail", "tag:fleet"}) {
		t.Errorf("tags = %v, want the profile tags", ts.Tags)
	}
	if ts.OAuthClientSecretFile != "/run/secrets/oauth" {
		t.Errorf("oauthClientSecretFile = %q, want the profile reference", ts.OAuthClientSecretFile)
	}
	if cfg.Settings.UDPSessionTimeoutSec != 45 {
		t.Errorf("udpSessionTimeoutSec = %d, want 45", cfg.Settings.UDPSessionTimeoutSec)
	}
	if len(cfg.Forwards) != 2 {
		t.Fatalf("got %d forwards, want 2", len(cfg.Forwards))
	}
	for _, f := range cfg.Forwards {
		if !isProfileManaged(f.ID) {
			t.Errorf("forward %q should be marked profile-managed", f.ID)
		}
		if !f.Enabled {
			t.Errorf("forward %q should default to enabled", f.Name)
		}
	}
	// Declared forwards must be immediately usable.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("provisioned config does not validate: %v", err)
	}
}

func TestApplyAdvertiseTagsOnLogin(t *testing.T) {
	p, err := LoadProfile(writeProfile(t, `{"settings":{"advertiseTagsOnLogin":true},"forwards":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Defaults()
	if tailnetOf(t, cfg).AdvertiseTagsOnLogin {
		t.Fatal("the default should be false, or this test proves nothing")
	}
	if err := p.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if !tailnetOf(t, cfg).AdvertiseTagsOnLogin {
		t.Error("a profile setting advertiseTagsOnLogin:true did not apply")
	}
}

func TestApplyLeavesUnsetSettingsAlone(t *testing.T) {
	p, err := LoadProfile(writeProfile(t, `{"settings":{"tags":["tag:only"]},"forwards":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Defaults()
	primary, err := cfg.PrimaryTailscale()
	if err != nil {
		t.Fatal(err)
	}
	primary.ControlURL = "https://local.example.com"
	cfg.Settings.UDPBufferBytes = 4096

	if err := p.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if got := tailnetOf(t, cfg).ControlURL; got != "https://local.example.com" {
		t.Errorf("controlURL = %q; a profile that omits a field must not reset it", got)
	}
	if cfg.Settings.UDPBufferBytes != 4096 {
		t.Errorf("udpBufferBytes = %d, want the untouched local value 4096", cfg.Settings.UDPBufferBytes)
	}
}

func TestProvisionIsIdempotent(t *testing.T) {
	// The fleet acceptance criterion: re-running provision changes nothing on disk.
	profilePath := writeProfile(t, fleetProfileJSON)
	p, err := LoadProfile(profilePath)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ConfigFileName)
	store, err := Open(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Provision(store, p); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	first, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Provision(store, p); err != nil {
		t.Fatalf("second Provision: %v", err)
	}
	second, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Errorf("re-provisioning changed the config file:\nfirst:\n%s\nsecond:\n%s", first, second)
	}

	// A fresh process must also converge to the same document.
	reopened, err := Open(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Provision(reopened, p); err != nil {
		t.Fatalf("Provision after restart: %v", err)
	}
	third, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(third) {
		t.Error("provisioning after a restart produced a different config")
	}
}

func TestApplyReconcilesProfileForwardsButKeepsLocalOnes(t *testing.T) {
	cfg := Defaults()
	local := validForward()
	local.ID = "f_local"
	local.ListenPort = 4444
	cfg.Forwards = []Forward{local}

	first, err := LoadProfile(writeProfile(t, fleetProfileJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Forwards) != 3 {
		t.Fatalf("got %d forwards, want 1 local + 2 declared", len(cfg.Forwards))
	}

	// The fleet drops the metrics forward; the node must drop it too, but keep the local one.
	second, err := LoadProfile(writeProfile(t, `{
      "settings": {},
      "forwards": [
        {"name": "Fleet DNS", "direction": "to_local", "protocol": "udp", "listenPort": 5353, "target": "dns-server:53"}
      ]
    }`))
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Apply(cfg); err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, f := range cfg.Forwards {
		names = append(names, f.Name)
	}
	if len(cfg.Forwards) != 2 {
		t.Fatalf("got forwards %v, want the local one plus Fleet DNS", names)
	}
	if _, ok := cfg.FindForward("f_local"); !ok {
		t.Errorf("profile reconciliation deleted the operator's own forward (have %v)", names)
	}
	for _, f := range cfg.Forwards {
		if f.Name == "Metrics" {
			t.Error("a forward the profile no longer declares was left running")
		}
	}
}

func TestApplyRejectsInvalidProfileForward(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			"bad direction",
			`{"settings":{},"forwards":[{"name":"x","direction":"sideways","protocol":"tcp","listenPort":80,"target":"a:80"}]}`,
			"direction",
		},
		{
			"missing target port",
			`{"settings":{},"forwards":[{"name":"x","direction":"to_local","protocol":"tcp","listenPort":80,"target":"a"}]}`,
			"target",
		},
		{
			"duplicate endpoint within the profile",
			`{"settings":{},"forwards":[
               {"name":"a","direction":"to_local","protocol":"tcp","listenPort":80,"target":"a:80"},
               {"name":"b","direction":"to_local","protocol":"tcp","listenPort":80,"target":"a:80"}]}`,
			"duplicate endpoint",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := LoadProfile(writeProfile(t, tc.body))
			if err != nil {
				t.Fatal(err)
			}
			err = p.Apply(Defaults())
			if err == nil {
				t.Fatal("Apply accepted an invalid profile")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestProfileForwardExplicitlyDisabled(t *testing.T) {
	p, err := LoadProfile(writeProfile(t, `{"settings":{},"forwards":[
       {"name":"staged","direction":"to_local","protocol":"tcp","listenPort":80,"target":"a:80","enabled":false}]}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Defaults()
	if err := p.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Forwards[0].Enabled {
		t.Error("a profile forward declared enabled:false came up enabled")
	}
}

func TestLoadProfileAcceptsHuJSONComments(t *testing.T) {
	// A distributed profile documents itself inline; comments and a trailing comma
	// must not stop it loading.
	body := `{
      // fleet-wide settings
      "settings": {
        "tags": ["tag:app-tail"], // the group every node joins
      },
      "forwards": [
        {"name": "DNS", "direction": "to_local", "protocol": "udp", "listenPort": 5353, "target": "dns:53"},
      ],
    }`
	p, err := LoadProfile(writeProfile(t, body))
	if err != nil {
		t.Fatalf("LoadProfile rejected commented HuJSON: %v", err)
	}
	if p.Settings.Tags == nil || !reflect.DeepEqual(*p.Settings.Tags, []string{"tag:app-tail"}) {
		t.Errorf("tags = %v, want the commented profile's tags", p.Settings.Tags)
	}
	if len(p.Forwards) != 1 {
		t.Fatalf("got %d forwards, want 1", len(p.Forwards))
	}
}

// The shipped example must stay loadable and valid, so a schema change that would
// break every operator who copied it fails the build here first.
func TestShippedFleetProfileExampleApplies(t *testing.T) {
	p, err := LoadProfile(filepath.Join("..", "..", "examples", "fleet-profile.json"))
	if err != nil {
		t.Fatalf("the shipped examples/fleet-profile.json does not load: %v", err)
	}
	cfg := Defaults()
	if err := p.Apply(cfg); err != nil {
		t.Fatalf("the shipped example does not apply: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the shipped example produces an invalid config: %v", err)
	}
}

func TestLoadProfileRejectsGarbage(t *testing.T) {
	if _, err := LoadProfile(writeProfile(t, "{not json")); err == nil {
		t.Fatal("LoadProfile accepted a malformed document")
	}
	if _, err := LoadProfile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("LoadProfile accepted a missing file")
	}
}

func TestProfileForwardIDIsStableAndEndpointDerived(t *testing.T) {
	a := ProfileForward{Direction: ToLocal, Protocol: TCP, ListenPort: 80, Target: "a:80"}.toForward()
	b := ProfileForward{Direction: ToLocal, Protocol: TCP, ListenPort: 80, Target: "a:80"}.toForward()
	if a.ID != b.ID {
		t.Errorf("identical declarations produced different ids %q and %q", a.ID, b.ID)
	}
	// Renaming is cosmetic and must not orphan the running forward.
	renamed := ProfileForward{Name: "different", Direction: ToLocal, Protocol: TCP, ListenPort: 80, Target: "a:80"}.toForward()
	if renamed.ID != a.ID {
		t.Errorf("renaming changed the id: %q vs %q", renamed.ID, a.ID)
	}
	moved := ProfileForward{Direction: ToLocal, Protocol: TCP, ListenPort: 81, Target: "a:80"}.toForward()
	if moved.ID == a.ID {
		t.Error("forwards on different ports must not share an id")
	}
}

// A fleet profile publishing a forward to the local network has to say so in the same
// words the dashboard does; the address alone is refused there and so it is here.
func TestAProfileForwardOnTheNetworkNeedsExposeToNetwork(t *testing.T) {
	p, err := LoadProfile(writeProfile(t, `{"settings":{},"forwards":[
       {"name":"lan","direction":"to_local","protocol":"tcp","bindAddr":"0.0.0.0","listenPort":80,"target":"a:80"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(Defaults()); err == nil || !strings.Contains(err.Error(), "exposeToNetwork") {
		t.Fatalf("error = %v, want a network-facing profile forward refused without exposeToNetwork", err)
	}

	p, err = LoadProfile(writeProfile(t, `{"settings":{},"forwards":[
       {"name":"lan","direction":"to_local","protocol":"tcp","bindAddr":"0.0.0.0","listenPort":80,"target":"a:80","exposeToNetwork":true}]}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Defaults()
	if err := p.Apply(cfg); err != nil {
		t.Fatalf("a profile forward exposed on purpose was refused: %v", err)
	}
	if !cfg.Forwards[0].ExposeToNetwork {
		t.Error("exposeToNetwork from the profile did not reach the stored forward")
	}
}
