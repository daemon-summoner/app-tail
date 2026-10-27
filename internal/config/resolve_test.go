// SPDX-License-Identifier: MIT

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func envFrom(m map[string]string) Getenv {
	return func(k string) string { return m[k] }
}

func ptr[T any](v T) *T { return &v }

// storedDocument is a first-run document with the tailnet fields a test wants set on the
// connection that now holds them.
func storedDocument(t *testing.T, mutate func(*TailscaleTunnel)) *Config {
	t.Helper()
	cfg := Defaults()
	ts, err := cfg.PrimaryTailscale()
	if err != nil {
		t.Fatalf("a first-run document has no primary connection: %v", err)
	}
	if mutate != nil {
		mutate(ts)
	}
	return cfg
}

// resolvedTailnet is what the precedence chain produced for the connection every install
// has, which is where the tailnet env vars and flags land.
func resolvedTailnet(t *testing.T, r Runtime) TailscaleTunnel {
	t.Helper()
	ts, err := r.PrimaryTailnet()
	if err != nil {
		t.Fatalf("resolving the tailnet: %v", err)
	}
	return ts
}

func TestResolvePrecedence(t *testing.T) {
	stored := storedDocument(t, func(ts *TailscaleTunnel) {
		ts.Hostname = "from-file"
		ts.ControlURL = "https://file.example.com"
		ts.Tags = []string{"tag:from-file"}
	})
	stored.Settings.UIListen = "127.0.0.1:1111"

	t.Run("file wins over built-in default", func(t *testing.T) {
		got, err := Resolve(Flags{}, envFrom(nil), stored, "/state", "/state/config.json")
		if err != nil {
			t.Fatal(err)
		}
		if h := resolvedTailnet(t, got).Hostname; h != "from-file" {
			t.Errorf("hostname = %q, want from-file", h)
		}
		if got.Settings.UIListen != "127.0.0.1:1111" {
			t.Errorf("uiListenAddr = %q, want the stored value", got.Settings.UIListen)
		}
	})

	t.Run("env wins over file", func(t *testing.T) {
		env := envFrom(map[string]string{
			EnvHostname:   "from-env",
			EnvControlURL: "https://env.example.com",
			EnvUIAddr:     "127.0.0.1:2222",
			EnvTags:       "tag:from-env",
		})
		got, err := Resolve(Flags{}, env, stored, "/state", "/state/config.json")
		if err != nil {
			t.Fatal(err)
		}
		ts := resolvedTailnet(t, got)
		if ts.Hostname != "from-env" {
			t.Errorf("hostname = %q, want from-env", ts.Hostname)
		}
		if ts.ControlURL != "https://env.example.com" {
			t.Errorf("controlURL = %q, want the env value", ts.ControlURL)
		}
		if got.Settings.UIListen != "127.0.0.1:2222" {
			t.Errorf("uiListenAddr = %q, want the env value", got.Settings.UIListen)
		}
		if !reflect.DeepEqual(ts.Tags, []string{"tag:from-env"}) {
			t.Errorf("tags = %v, want [tag:from-env]", ts.Tags)
		}
	})

	t.Run("flags win over env", func(t *testing.T) {
		env := envFrom(map[string]string{
			EnvHostname:   "from-env",
			EnvControlURL: "https://env.example.com",
			EnvUIAddr:     "127.0.0.1:2222",
			EnvTags:       "tag:from-env",
		})
		flags := Flags{
			Hostname:   ptr("from-flag"),
			ControlURL: ptr("https://flag.example.com"),
			UIAddr:     ptr("127.0.0.1:3333"),
			Tags:       ptr("tag:from-flag,tag:extra"),
		}
		got, err := Resolve(flags, env, stored, "/state", "/state/config.json")
		if err != nil {
			t.Fatal(err)
		}
		ts := resolvedTailnet(t, got)
		if ts.Hostname != "from-flag" {
			t.Errorf("hostname = %q, want from-flag", ts.Hostname)
		}
		if ts.ControlURL != "https://flag.example.com" {
			t.Errorf("controlURL = %q, want the flag value", ts.ControlURL)
		}
		if got.Settings.UIListen != "127.0.0.1:3333" {
			t.Errorf("uiListenAddr = %q, want the flag value", got.Settings.UIListen)
		}
		if !reflect.DeepEqual(ts.Tags, []string{"tag:from-flag", "tag:extra"}) {
			t.Errorf("tags = %v, want two flag tags", ts.Tags)
		}
	})

	t.Run("empty flag values do not clobber env", func(t *testing.T) {
		env := envFrom(map[string]string{EnvHostname: "from-env"})
		got, err := Resolve(Flags{Hostname: ptr("")}, env, stored, "/state", "/state/config.json")
		if err != nil {
			t.Fatal(err)
		}
		if h := resolvedTailnet(t, got).Hostname; h != "from-env" {
			t.Errorf("hostname = %q, want from-env", h)
		}
	})
}

func TestResolveSecrets(t *testing.T) {
	stored := storedDocument(t, nil)

	t.Run("tailscale-native env names are honored", func(t *testing.T) {
		env := envFrom(map[string]string{
			EnvTSClientSecret: "tskey-client-native",
			EnvTSAuthKey:      "tskey-auth-native",
		})
		got, err := Resolve(Flags{}, env, stored, "/state", "/state/config.json")
		if err != nil {
			t.Fatal(err)
		}
		ts := resolvedTailnet(t, got)
		if ts.OAuthClientSecret != "tskey-client-native" {
			t.Errorf("oauth secret = %q, want the TS_CLIENT_SECRET value", ts.OAuthClientSecret)
		}
		if ts.AuthKey != "tskey-auth-native" {
			t.Errorf("auth key = %q, want the TS_AUTHKEY value", ts.AuthKey)
		}
	})

	t.Run("app-specific env name wins over the native one", func(t *testing.T) {
		env := envFrom(map[string]string{
			EnvTSClientSecret: "tskey-client-native",
			EnvOAuthSecret:    "tskey-client-app",
			EnvTSAuthKey:      "tskey-auth-native",
			EnvAuthKey:        "tskey-auth-app",
		})
		got, err := Resolve(Flags{}, env, stored, "/state", "/state/config.json")
		if err != nil {
			t.Fatal(err)
		}
		ts := resolvedTailnet(t, got)
		if ts.OAuthClientSecret != "tskey-client-app" {
			t.Errorf("oauth secret = %q, want the app-specific value", ts.OAuthClientSecret)
		}
		if ts.AuthKey != "tskey-auth-app" {
			t.Errorf("auth key = %q, want the app-specific value", ts.AuthKey)
		}
	})
}

func TestResolveBooleans(t *testing.T) {
	stored := storedDocument(t, nil)

	t.Run("env booleans parse", func(t *testing.T) {
		env := envFrom(map[string]string{EnvEphemeral: "true", EnvHeadless: "1"})
		got, err := Resolve(Flags{}, env, stored, "/state", "/state/config.json")
		if err != nil {
			t.Fatal(err)
		}
		if !resolvedTailnet(t, got).Ephemeral {
			t.Error("ephemeral should be true")
		}
		if !got.Headless {
			t.Error("headless should be true")
		}
	})

	t.Run("a malformed boolean is rejected loudly", func(t *testing.T) {
		env := envFrom(map[string]string{EnvEphemeral: "yes-please"})
		if _, err := Resolve(Flags{}, env, stored, "/state", "/state/config.json"); err == nil {
			t.Fatal("Resolve silently accepted a malformed boolean")
		}
	})

	t.Run("headless flag cannot be turned off by env", func(t *testing.T) {
		env := envFrom(map[string]string{EnvHeadless: "false"})
		got, err := Resolve(Flags{Headless: ptr(true)}, env, stored, "/state", "/state/config.json")
		if err != nil {
			t.Fatal(err)
		}
		if !got.Headless {
			t.Error("--headless must win over APPTAIL_HEADLESS=false")
		}
	})

	t.Run("ephemeral flag overrides env", func(t *testing.T) {
		env := envFrom(map[string]string{EnvEphemeral: "true"})
		got, err := Resolve(Flags{Ephemeral: ptr(false)}, env, stored, "/state", "/state/config.json")
		if err != nil {
			t.Fatal(err)
		}
		if resolvedTailnet(t, got).Ephemeral {
			t.Error("--ephemeral=false must win over APPTAIL_EPHEMERAL=true")
		}
	})

	t.Run("advertise-tags-on-login parses from env", func(t *testing.T) {
		env := envFrom(map[string]string{EnvAdvertiseTagsOnLogin: "true"})
		got, err := Resolve(Flags{}, env, stored, "/state", "/state/config.json")
		if err != nil {
			t.Fatal(err)
		}
		if !resolvedTailnet(t, got).AdvertiseTagsOnLogin {
			t.Error("advertiseTagsOnLogin should be true")
		}
	})

	t.Run("advertise-tags-on-login flag overrides env", func(t *testing.T) {
		env := envFrom(map[string]string{EnvAdvertiseTagsOnLogin: "true"})
		got, err := Resolve(Flags{AdvertiseTagsOnLogin: ptr(false)}, env, stored, "/state", "/state/config.json")
		if err != nil {
			t.Fatal(err)
		}
		if resolvedTailnet(t, got).AdvertiseTagsOnLogin {
			t.Error("--advertise-tags-on-login=false must win over the env value")
		}
	})
}

func TestResolveRejectsInvalidResult(t *testing.T) {
	stored := storedDocument(t, nil)
	// An override that would expose the dashboard off-loopback must fail at resolve time,
	// not silently at bind time.
	if _, err := Resolve(Flags{UIAddr: ptr("0.0.0.0:8377")}, envFrom(nil), stored, "/state", "/s/c.json"); err == nil {
		t.Fatal("Resolve accepted a non-loopback UI address")
	}
}

func TestResolveStateDirPrecedence(t *testing.T) {
	env := envFrom(map[string]string{EnvStateDir: "/env/state"})

	// A resolved path is a path this machine can open, so it is spelled the host's way.
	// What the assertions are about is which source won, not how a separator is written.
	fromEnv := filepath.FromSlash("/env/state")
	fromFlag := filepath.FromSlash("/flag/state")

	got, err := ResolveStateDir(Flags{}, env)
	if err != nil {
		t.Fatal(err)
	}
	if got != fromEnv {
		t.Errorf("state dir = %q, want %q", got, fromEnv)
	}

	got, err = ResolveStateDir(Flags{StateDir: ptr("/flag/state")}, env)
	if err != nil {
		t.Fatal(err)
	}
	if got != fromFlag {
		t.Errorf("state dir = %q, want %q", got, fromFlag)
	}

	got, err = ResolveStateDir(Flags{}, envFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	want, err := DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("state dir = %q, want the OS default %q", got, want)
	}
}

func TestResolveConfigPathPrecedence(t *testing.T) {
	if got := ResolveConfigPath(Flags{}, envFrom(nil), "/state"); got != filepath.Join("/state", ConfigFileName) {
		t.Errorf("config path = %q, want it inside the state dir", got)
	}
	env := envFrom(map[string]string{EnvConfig: "/env/app.json"})
	fromEnv := filepath.FromSlash("/env/app.json")
	if got := ResolveConfigPath(Flags{}, env, "/state"); got != fromEnv {
		t.Errorf("config path = %q, want %q", got, fromEnv)
	}
	fromFlag := filepath.FromSlash("/flag/app.json")
	if got := ResolveConfigPath(Flags{ConfigPath: ptr("/flag/app.json")}, env, "/state"); got != fromFlag {
		t.Errorf("config path = %q, want %q", got, fromFlag)
	}
}

func TestParseTags(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"tag:app-tail", []string{"tag:app-tail"}},
		{"app-tail", []string{"tag:app-tail"}},
		{"tag:a, tag:b", []string{"tag:a", "tag:b"}},
		{"a,b", []string{"tag:a", "tag:b"}},
		{" , tag:a , ", []string{"tag:a"}},
		{"", nil},
	}
	for _, tc := range tests {
		if got := ParseTags(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParseTags(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestLoadOAuthSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oauth.secret")
	if err := os.WriteFile(path, []byte("tskey-client-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("file wins over the inline secret", func(t *testing.T) {
		got, err := LoadOAuthSecret(TailscaleTunnel{OAuthClientSecret: "tskey-client-inline", OAuthClientSecretFile: path})
		if err != nil {
			t.Fatal(err)
		}
		if got != "tskey-client-from-file" {
			t.Errorf("secret = %q, want the trimmed file contents", got)
		}
	})

	t.Run("inline secret used when no file is set", func(t *testing.T) {
		got, err := LoadOAuthSecret(TailscaleTunnel{OAuthClientSecret: " tskey-client-inline "})
		if err != nil {
			t.Fatal(err)
		}
		if got != "tskey-client-inline" {
			t.Errorf("secret = %q, want the trimmed inline secret", got)
		}
	})

	t.Run("a missing secret file is a loud failure", func(t *testing.T) {
		if _, err := LoadOAuthSecret(TailscaleTunnel{OAuthClientSecretFile: filepath.Join(dir, "nope")}); err == nil {
			t.Fatal("LoadOAuthSecret silently ignored a missing secret file")
		}
	})

	t.Run("an empty secret file is a loud failure", func(t *testing.T) {
		empty := filepath.Join(dir, "empty.secret")
		if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOAuthSecret(TailscaleTunnel{OAuthClientSecretFile: empty}); err == nil {
			t.Fatal("LoadOAuthSecret accepted an empty secret file")
		}
	})
}

func TestEffectiveHostname(t *testing.T) {
	explicit := TailscaleTunnel{Hostname: "My Box", HostnameTemplate: DefaultHostnameTemplate}
	if got := EffectiveHostname(explicit, "abc"); got != "my-box" {
		t.Errorf("EffectiveHostname = %q, want the sanitized explicit hostname", got)
	}

	templated := TailscaleTunnel{HostnameTemplate: "app-tail-{id}"}
	if got := EffectiveHostname(templated, "abc123"); got != "app-tail-abc123" {
		t.Errorf("EffectiveHostname = %q, want the rendered template", got)
	}
}

// A document carrying connections but none this build calls the primary one has nowhere to
// put the tailnet inputs. Applying them to whichever connection is listed first would point
// a fleet's credentials at an arbitrary network, so the inputs are refused by name instead.
func TestTailnetInputsWithNoConnectionToLandOnAreRefusedRatherThanGuessedAt(t *testing.T) {
	stored := &Config{
		Version:  ConfigVersion,
		Settings: Defaults().Settings,
		Tunnels:  []Tunnel{NewTunnel("tn_lab", "lab", "Lab", TunnelWireGuard)},
	}

	for _, tc := range []struct {
		name  string
		flags Flags
		env   map[string]string
	}{
		{name: "an auth key in the environment", env: map[string]string{EnvAuthKey: "tskey-auth-fake"}},
		{name: "a control server in the environment", env: map[string]string{EnvControlURL: "https://hs.example.com"}},
		{name: "a device name on the command line", flags: Flags{Hostname: ptr("laptop")}},
		{name: "a tag list on the command line", flags: Flags{Tags: ptr("tag:ci")}},
		{name: "a control server on the command line", flags: Flags{ControlURL: ptr("https://hs.example.com")}},
		{name: "an ephemeral switch on the command line", flags: Flags{Ephemeral: ptr(true)}},
		{name: "a tag-on-login switch on the command line", flags: Flags{AdvertiseTagsOnLogin: ptr(false)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Resolve(tc.flags, envFrom(tc.env), stored, "/state", "/s/c.json"); err == nil {
				t.Error("the input was accepted with no connection it could belong to")
			}
		})
	}

	// Nothing naming the tailnet is not an error: a machine with only a WireGuard
	// connection is an ordinary install, and refusing to start it would be absurd.
	got, err := Resolve(Flags{}, envFrom(nil), stored, "/state", "/s/c.json")
	if err != nil {
		t.Fatalf("a document with no tailnet connection was refused outright: %v", err)
	}
	if len(got.Tunnels) != 1 || got.Tunnels[0].ID != "tn_lab" {
		t.Errorf("connections = %+v, want the stored one carried through untouched", got.Tunnels)
	}
}

// A document with no connections at all is what a hand-edited or partly written file looks
// like. It resolves to no connections rather than to a synthesized one, because inventing a
// connection here would put a network on screen that nothing in the document asked for.
func TestADocumentWithNoConnectionsResolvesToNone(t *testing.T) {
	stored := &Config{Version: ConfigVersion, Settings: Defaults().Settings}

	got, err := Resolve(Flags{}, envFrom(nil), stored, "/state", "/s/c.json")
	if err != nil {
		t.Fatalf("resolving a document with no connections: %v", err)
	}
	if len(got.Tunnels) != 0 {
		t.Errorf("connections = %+v, want none invented", got.Tunnels)
	}
}

// The remaining tailnet inputs, each proved to land where it is meant to. They are one test
// because the failure they share is the one that matters: an override read into the wrong
// field is a value silently ignored, and every one of these is a deployment input somebody
// set expecting it to take effect.
func TestEveryTailnetOverrideLandsOnTheConnectionItNames(t *testing.T) {
	stored := storedDocument(t, nil)

	got, err := Resolve(Flags{}, envFrom(map[string]string{
		EnvHostnameTemplate: "{{.Host}}-ci",
		EnvOAuthSecretFile:  "/run/secrets/oauth",
		EnvTSClientSecret:   "tskey-client-fake",
	}), stored, "/state", "/s/c.json")
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}

	ts := resolvedTailnet(t, got)
	if ts.HostnameTemplate != "{{.Host}}-ci" {
		t.Errorf("hostnameTemplate = %q, want the value from the environment", ts.HostnameTemplate)
	}
	if ts.OAuthClientSecretFile != "/run/secrets/oauth" {
		t.Errorf("oauthClientSecretFile = %q, want the path from the environment", ts.OAuthClientSecretFile)
	}
	if ts.OAuthClientSecret != "tskey-client-fake" {
		t.Errorf("oauthClientSecret is not the one the Tailscale-native variable carried")
	}
	// Nothing resolved here is written back: the file still holds what it held.
	if stored.Tunnels[0].TS().HostnameTemplate == "{{.Host}}-ci" {
		t.Error("a runtime-only override was written into the stored document")
	}
}

// A boolean that is not one has to fail at resolve time naming the variable. Read as false
// it would silently drop a switch somebody set, which on this particular one is the
// difference between a device that enrolls with its tags and one that does not.
func TestABooleanEnvironmentValueThatIsNotOneIsRefusedByName(t *testing.T) {
	stored := storedDocument(t, nil)

	_, err := Resolve(Flags{}, envFrom(map[string]string{EnvAdvertiseTagsOnLogin: "yes-please"}),
		stored, "/state", "/s/c.json")

	if err == nil {
		t.Fatal("a value that is not a boolean was accepted")
	}
	if !strings.Contains(err.Error(), EnvAdvertiseTagsOnLogin) {
		t.Errorf("error = %v, want it to name the variable that has to be fixed", err)
	}
}

// The runtime values are read as a whole document by everything that needs the whole
// configuration, and that document must carry the connections and proxies rather than the
// settings alone -- assembled from half the runtime it would report a machine with no
// networks configured.
func TestTheRuntimeReadsBackAsAWholeDocument(t *testing.T) {
	stored := storedDocument(t, nil)
	stored.Tunnels = append(stored.Tunnels, NewTunnel("tn_lab", "lab", "Lab", TunnelWireGuard))

	got, err := Resolve(Flags{}, envFrom(nil), stored, "/state", "/s/c.json")
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}

	doc := got.Document()
	if doc.Version != ConfigVersion {
		t.Errorf("version = %d, want %d", doc.Version, ConfigVersion)
	}
	if len(doc.Tunnels) != len(got.Tunnels) {
		t.Errorf("the document carries %d connections, want the %d that resolved",
			len(doc.Tunnels), len(got.Tunnels))
	}
	if len(doc.Proxies) != len(got.Proxies) {
		t.Errorf("the document carries %d proxies, want the %d that resolved",
			len(doc.Proxies), len(got.Proxies))
	}
	if doc.Settings.StateDir != got.Settings.StateDir {
		t.Errorf("the document's state directory is %q, want the resolved %q",
			doc.Settings.StateDir, got.Settings.StateDir)
	}
}

// Whatever LoadOAuthSecret returns is handed to the control server. A path that names
// any other file -- a password database, a private key -- would send that file to
// whoever runs the server, so only something shaped like a Tailscale credential leaves,
// and the refusal never repeats what the file held.
func TestASecretFileThatIsNotACredentialIsNeverSent(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, body []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	const private = "root:x:0:0:root:/root:/bin/bash"

	cases := map[string]string{
		"a file of something else":       write("passwd", []byte(private+"\n")),
		"a credential followed by more":  write("two-lines", []byte("tskey-auth-kABC-def\n"+private+"\n")),
		"a credential with spaces in it": write("spaces", []byte("tskey-auth- "+private)),
		"a credential longer than any real one": write("long",
			[]byte("tskey-auth-"+strings.Repeat("a", 600))),
		"a file larger than any credential": write("large",
			append([]byte("tskey-auth-kABC-def\n"), bytes.Repeat([]byte(private+"\n"), 200)...)),
		"a directory": dir,
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := LoadOAuthSecret(TailscaleTunnel{OAuthClientSecretFile: path})
			if err == nil {
				t.Fatalf("LoadOAuthSecret returned %q for a file that holds no credential", got)
			}
			if strings.Contains(err.Error(), "root:") {
				t.Errorf("the refusal repeats the file's contents: %v", err)
			}
		})
	}
}

// A device or a pipe behind the path is never read: a device can be endless and a pipe
// can block the start forever, and neither is a file a secrets manager writes.
func TestASecretFileThatPointsAtADeviceIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("there is no /dev/zero to point at on Windows")
	}
	link := filepath.Join(t.TempDir(), "secret")
	if err := os.Symlink("/dev/zero", link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOAuthSecret(TailscaleTunnel{OAuthClientSecretFile: link}); err == nil {
		t.Fatal("LoadOAuthSecret read a device as a secret file")
	}
}

// A relative path is read from wherever the process happens to have been started, which
// for a service is a directory nobody chose.
func TestARelativeSecretFileIsRefused(t *testing.T) {
	_, err := LoadOAuthSecret(TailscaleTunnel{OAuthClientSecretFile: "oauth.secret"})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("error = %v, want a relative secret file refused for not being absolute", err)
	}
}

// Every form Tailscale issues has to keep working: auth keys, OAuth client secrets with
// the options the tailscale client reads after a question mark, keys wrapped for
// tailnet lock, and the older keys with no kind in their name.
func TestRealCredentialShapesAreAccepted(t *testing.T) {
	shapes := []string{
		"tskey-auth-kABCDEF1CNTRL-0123456789abcdefghijklmnopqrstuv",
		"tskey-client-kABCDEF1CNTRL-0123456789abcdefghijklmnopqrstuv",
		"tskey-client-kABCDEF1CNTRL-0123?ephemeral=false&preauthorized=true&baseURL=https://api.example.com:8443/",
		"tskey-auth-kABC1CNTRL-nonce--TLAbCd+ef/GH12-Zz9+/xY",
		"tskey-0123456789abcdef",
	}
	for _, shape := range shapes {
		if err := CheckCredentialShape("auth key", shape); err != nil {
			t.Errorf("CheckCredentialShape(%q) = %v, want it accepted", shape, err)
		}
		path := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(path, []byte(shape+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := LoadOAuthSecret(TailscaleTunnel{OAuthClientSecretFile: path})
		if err != nil || got != shape {
			t.Errorf("LoadOAuthSecret = %q, %v, want %q", got, err, shape)
		}
	}
}
