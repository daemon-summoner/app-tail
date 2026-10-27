// SPDX-License-Identifier: MIT

package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/sellitus/app-tail/internal/routing"
)

// Environment variables honored by the resolver. TS_AUTHKEY and TS_CLIENT_SECRET keep
// their Tailscale-native names so existing deployment tooling works unchanged.
const (
	EnvConfig               = "APPTAIL_CONFIG"
	EnvStateDir             = "APPTAIL_STATE_DIR"
	EnvUIAddr               = "APPTAIL_UI_ADDR"
	EnvHostname             = "APPTAIL_HOSTNAME"
	EnvHostnameTemplate     = "APPTAIL_HOSTNAME_TEMPLATE"
	EnvTags                 = "APPTAIL_TAGS"
	EnvControlURL           = "APPTAIL_CONTROL_URL"
	EnvEphemeral            = "APPTAIL_EPHEMERAL"
	EnvAdvertiseTagsOnLogin = "APPTAIL_ADVERTISE_TAGS_ON_LOGIN"
	EnvHeadless             = "APPTAIL_HEADLESS"
	EnvOAuthSecret          = "APPTAIL_OAUTH_CLIENT_SECRET"
	EnvOAuthSecretFile      = "APPTAIL_OAUTH_CLIENT_SECRET_FILE"
	EnvAuthKey              = "APPTAIL_AUTH_KEY"
	EnvTSAuthKey            = "TS_AUTHKEY"
	EnvTSClientSecret       = "TS_CLIENT_SECRET"
)

// Flags carries command-line overrides. A nil field means the flag was not passed,
// which is what lets flags outrank env without clobbering it when absent.
type Flags struct {
	ConfigPath           *string
	StateDir             *string
	UIAddr               *string
	Hostname             *string
	Tags                 *string
	ControlURL           *string
	Ephemeral            *bool
	AdvertiseTagsOnLogin *bool
	Headless             *bool
	Verbose              *bool

	// NoElevate withholds every request for administrator rights, wherever the process
	// would otherwise make one. It is not layered into Runtime like the fields above,
	// because it is not a setting: it says how this one invocation may behave, and
	// writing it into the stored settings would make one run's answer permanent.
	NoElevate *bool
}

// Runtime holds the configuration the process actually runs with, after layering
// flags over environment over the config file over built-in defaults.
type Runtime struct {
	ConfigPath string
	StateDir   string
	Headless   bool
	Verbose    bool
	Settings   Settings
	// Tunnels are the stored connections with the same overrides layered on. The env
	// vars and flags that name a tailnet predate there being more than one, so they
	// name the primary connection; nothing here creates a connection, because a stray
	// variable that joins a network is a different class of accident from one that
	// changes a device name.
	Tunnels []Tunnel
	// Proxies are the stored proxy instances, unchanged. They are here so a reader of the
	// runtime document sees the whole of it: nothing overrides a proxy, because a rule
	// injected by the environment would widen what a local program reaches with nothing in
	// the stored document saying so.
	Proxies []ProxyInstance
	// Routes are the stored per-destination exceptions to where this machine's internet
	// traffic goes, unchanged for the same reason the proxies are: a rule injected by the
	// environment would move traffic onto a connection with nothing in the stored document
	// saying so.
	Routes []routing.Rule
}

// Document is the runtime values as a configuration document, which is the form anything
// reading the whole configuration takes. It is assembled rather than stored because the
// overrides layered into these fields are runtime-only and must never reach the file.
func (r Runtime) Document() *Config {
	return &Config{
		Version:  ConfigVersion,
		Settings: r.Settings,
		Tunnels:  r.Tunnels,
		Proxies:  r.Proxies,
		Routes:   r.Routes,
	}
}

// PrimaryTailnet returns the tailnet settings the node this process runs joins with,
// overrides included.
//
// Its absence is an error rather than a zero value: an empty TailscaleTunnel is a
// connection with no credentials and no control server, which enrolls as a brand new
// device on Tailscale's own coordination server. Starting that silently is how a machine
// leaves the network it was on.
func (r Runtime) PrimaryTailnet() (TailscaleTunnel, error) {
	for _, t := range r.Tunnels {
		if t.ID == PrimaryTunnelID {
			return t.TS(), nil
		}
	}
	return TailscaleTunnel{}, fmt.Errorf("connection %q is missing, so there is no tailnet to join", PrimaryTunnelID)
}

// Getenv looks up an environment variable. os.Getenv satisfies it; tests pass a map.
type Getenv func(string) string

// OSGetenv is the production environment source.
func OSGetenv(key string) string { return os.Getenv(key) }

// ResolveStateDir determines where state lives, honoring flag > env > default.
// It runs before the config file is read, since the file lives inside that directory.
func ResolveStateDir(flags Flags, getenv Getenv) (string, error) {
	if flags.StateDir != nil && *flags.StateDir != "" {
		return filepath.Clean(*flags.StateDir), nil
	}
	if v := strings.TrimSpace(getenv(EnvStateDir)); v != "" {
		return filepath.Clean(v), nil
	}
	dir, err := DefaultStateDir()
	if err != nil {
		return "", err
	}
	return dir, nil
}

// ResolveConfigPath determines which config file to use, honoring flag > env > state dir.
func ResolveConfigPath(flags Flags, getenv Getenv, stateDir string) string {
	if flags.ConfigPath != nil && *flags.ConfigPath != "" {
		return filepath.Clean(*flags.ConfigPath)
	}
	if v := strings.TrimSpace(getenv(EnvConfig)); v != "" {
		return filepath.Clean(v)
	}
	return filepath.Join(stateDir, ConfigFileName)
}

// Resolve layers flags over environment over stored settings. Overrides are runtime-only:
// they shape this process without being written back to the config file, so an image can
// carry defaults while deploy-time values are injected per host.
func Resolve(flags Flags, getenv Getenv, stored *Config, stateDir, configPath string) (Runtime, error) {
	s := stored.Settings
	s.StateDir = stateDir

	if v := strings.TrimSpace(getenv(EnvUIAddr)); v != "" {
		s.UIListen = v
	}
	if flags.UIAddr != nil && *flags.UIAddr != "" {
		s.UIListen = *flags.UIAddr
	}

	tunnels, err := resolveTunnels(flags, getenv, stored)
	if err != nil {
		return Runtime{}, err
	}

	headless := false
	if v := strings.TrimSpace(getenv(EnvHeadless)); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Runtime{}, invalid(EnvHeadless, "must be a boolean, got %q", v)
		}
		headless = b
	}
	if flags.Headless != nil && *flags.Headless {
		headless = true
	}

	verbose := flags.Verbose != nil && *flags.Verbose

	if err := s.Validate(); err != nil {
		return Runtime{}, err
	}

	return Runtime{
		ConfigPath: configPath,
		StateDir:   stateDir,
		Headless:   headless,
		Verbose:    verbose,
		Settings:   s,
		Tunnels:    tunnels,
		Proxies:    clonedProxies(stored.Proxies),
		Routes:     routing.Clone(stored.Routes),
	}, nil
}

// clonedProxies copies the stored proxy instances. Nothing overrides them -- an
// environment variable that hands a local program a wider grant is precisely the accident
// this whole layer refuses -- but they are copied all the same, so nothing holding the
// runtime document can reach into the stored one.
func clonedProxies(stored []ProxyInstance) []ProxyInstance {
	if len(stored) == 0 {
		return nil
	}
	out := make([]ProxyInstance, len(stored))
	for i, p := range stored {
		out[i] = p.Clone()
	}
	return out
}

// resolveTunnels copies the stored connections and layers the tailnet overrides onto the
// primary one. Copying first is what keeps the overrides runtime-only: an image can carry
// defaults while deploy-time values are injected per host, and nothing here is ever
// written back to the document.
func resolveTunnels(flags Flags, getenv Getenv, stored *Config) ([]Tunnel, error) {
	if len(stored.Tunnels) == 0 {
		return nil, nil
	}
	out := make([]Tunnel, len(stored.Tunnels))
	for i, t := range stored.Tunnels {
		out[i] = t.Clone()
	}

	held := &Config{Tunnels: out}
	primary, err := held.PrimaryTailscale()
	if err != nil {
		// A document with connections but no primary one is a document nothing here
		// names, so these inputs have no destination and saying so is the only honest
		// answer. Silently applying them to the first connection would point a fleet's
		// credentials at whichever network happened to be listed first.
		if envNamesTheTailnet(getenv) || flagsNameTheTailnet(flags) {
			return nil, err
		}
		return out, nil
	}

	if v := strings.TrimSpace(getenv(EnvHostname)); v != "" {
		primary.Hostname = v
	}
	if flags.Hostname != nil && *flags.Hostname != "" {
		primary.Hostname = *flags.Hostname
	}

	if v := strings.TrimSpace(getenv(EnvHostnameTemplate)); v != "" {
		primary.HostnameTemplate = v
	}

	if v := strings.TrimSpace(getenv(EnvControlURL)); v != "" {
		primary.ControlURL = v
	}
	if flags.ControlURL != nil && *flags.ControlURL != "" {
		primary.ControlURL = *flags.ControlURL
	}

	if v := strings.TrimSpace(getenv(EnvTags)); v != "" {
		primary.Tags = ParseTags(v)
	}
	if flags.Tags != nil && *flags.Tags != "" {
		primary.Tags = ParseTags(*flags.Tags)
	}

	if v := strings.TrimSpace(getenv(EnvEphemeral)); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, invalid(EnvEphemeral, "must be a boolean, got %q", v)
		}
		primary.Ephemeral = b
	}
	if flags.Ephemeral != nil {
		primary.Ephemeral = *flags.Ephemeral
	}

	if v := strings.TrimSpace(getenv(EnvAdvertiseTagsOnLogin)); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, invalid(EnvAdvertiseTagsOnLogin, "must be a boolean, got %q", v)
		}
		primary.AdvertiseTagsOnLogin = b
	}
	if flags.AdvertiseTagsOnLogin != nil {
		primary.AdvertiseTagsOnLogin = *flags.AdvertiseTagsOnLogin
	}

	// Secrets: the app-specific name wins over the Tailscale-native one when both are set.
	if v := strings.TrimSpace(getenv(EnvTSClientSecret)); v != "" {
		primary.OAuthClientSecret = v
	}
	if v := strings.TrimSpace(getenv(EnvOAuthSecret)); v != "" {
		primary.OAuthClientSecret = v
	}
	if v := strings.TrimSpace(getenv(EnvOAuthSecretFile)); v != "" {
		primary.OAuthClientSecretFile = v
	}
	if v := strings.TrimSpace(getenv(EnvTSAuthKey)); v != "" {
		primary.AuthKey = v
	}
	if v := strings.TrimSpace(getenv(EnvAuthKey)); v != "" {
		primary.AuthKey = v
	}

	return out, nil
}

// tailnetEnvVars are the variables that name the tailnet rather than the app.
var tailnetEnvVars = []string{
	EnvHostname, EnvHostnameTemplate, EnvTags, EnvControlURL, EnvEphemeral,
	EnvAdvertiseTagsOnLogin, EnvOAuthSecret, EnvOAuthSecretFile, EnvAuthKey,
	EnvTSAuthKey, EnvTSClientSecret,
}

func envNamesTheTailnet(getenv Getenv) bool {
	for _, name := range tailnetEnvVars {
		if strings.TrimSpace(getenv(name)) != "" {
			return true
		}
	}
	return false
}

func flagsNameTheTailnet(flags Flags) bool {
	return (flags.Hostname != nil && *flags.Hostname != "") ||
		(flags.Tags != nil && *flags.Tags != "") ||
		(flags.ControlURL != nil && *flags.ControlURL != "") ||
		flags.Ephemeral != nil || flags.AdvertiseTagsOnLogin != nil
}

// ParseTags splits a comma-separated tag list, normalizing bare names to the
// "tag:" prefix the control plane expects.
func ParseTags(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		t := strings.TrimSpace(part)
		if t == "" {
			continue
		}
		if !strings.HasPrefix(t, "tag:") {
			t = "tag:" + t
		}
		out = append(out, t)
	}
	return out
}

// maxCredentialLen bounds a credential. The longest form Tailscale issues, an auth key
// wrapped for tailnet lock, is a few hundred characters.
const maxCredentialLen = 512

// maxSecretFileSize bounds what is read from oauthClientSecretFile: a secret plus a
// trailing newline is far smaller, and anything larger is a different file.
const maxSecretFileSize = 4 << 10

// credentialShape is what every Tailscale credential looks like: tskey-, then letters,
// digits and the separators the forms use ("-", "_", and the "+" and "/" of the base64
// tail a tailnet-lock wrapped key carries), then optionally the "?name=value&..." options
// an OAuth client secret may hold. No whitespace, so a file with a second line never
// passes as one.
var credentialShape = regexp.MustCompile(`^tskey-[A-Za-z0-9_+/-]+(\?[A-Za-z0-9=&._:/%-]*)?$`)

// CheckCredentialShape refuses a value that is not shaped like a Tailscale credential.
// Whatever passes is sent to the control server, so this is what keeps the contents of
// some other file, or a value pasted into the wrong field, from being sent there. The
// error names what was checked and never the value itself, so a refusal cannot leak the
// thing it refused into a log.
func CheckCredentialShape(what, value string) error {
	if len(value) > maxCredentialLen || !credentialShape.MatchString(value) {
		return fmt.Errorf("%s is not a Tailscale credential (one starts with tskey- and is at most %d characters with no spaces), so it was not used",
			what, maxCredentialLen)
	}
	return nil
}

// LoadOAuthSecret returns one connection's OAuth client secret, reading it from
// OAuthClientSecretFile when one is configured. The file form is preferred so the
// secret can come from a secrets manager instead of the config document.
//
// Either way the result must be shaped like a Tailscale credential: it is sent to the
// control server, and a path naming any other file would otherwise send that file there.
func LoadOAuthSecret(s TailscaleTunnel) (string, error) {
	if path := strings.TrimSpace(s.OAuthClientSecretFile); path != "" {
		secret, err := readSecretFile(path)
		if err != nil {
			return "", err
		}
		if err := CheckCredentialShape("the contents of oauthClientSecretFile "+path, secret); err != nil {
			return "", err
		}
		return secret, nil
	}
	secret := strings.TrimSpace(s.OAuthClientSecret)
	if secret == "" {
		return "", nil
	}
	if err := CheckCredentialShape("oauthClientSecret", secret); err != nil {
		return "", err
	}
	return secret, nil
}

// readSecretFile reads a small regular file named by an absolute path, trimmed.
//
// The checks are made on the open file rather than on the path, so a path swapped for a
// link to something else between the check and the read is still caught. The open does
// not block, so a pipe behind the path is refused rather than waited on forever.
func readSecretFile(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("oauthClientSecretFile %s must be an absolute path", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", fmt.Errorf("read oauthClientSecretFile %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("read oauthClientSecretFile %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("oauthClientSecretFile %s is not a regular file", path)
	}
	if info.Size() > maxSecretFileSize {
		return "", fmt.Errorf("oauthClientSecretFile %s is %d bytes, larger than any secret (at most %d)",
			path, info.Size(), maxSecretFileSize)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSecretFileSize+1))
	if err != nil {
		return "", fmt.Errorf("read oauthClientSecretFile %s: %w", path, err)
	}
	if len(data) > maxSecretFileSize {
		return "", fmt.Errorf("oauthClientSecretFile %s grew past %d bytes while it was read", path, maxSecretFileSize)
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", fmt.Errorf("oauthClientSecretFile %s is empty", path)
	}
	return secret, nil
}

// EffectiveHostname resolves one connection's device name: an explicit hostname wins,
// otherwise the template is rendered against this machine's name and install id.
func EffectiveHostname(ts TailscaleTunnel, machineID string) string {
	if h := SanitizeHostname(ts.Hostname); h != "" {
		return h
	}
	return RenderHostname(ts.HostnameTemplate, OSHostname(), machineID)
}
