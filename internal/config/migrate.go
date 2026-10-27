// SPDX-License-Identifier: MIT

package config

// Moving a stored document forward to the shape this build expects.
//
// Migration runs once on load, before defaults and before validation, and it is
// deliberately the only place that knows what an older document looked like. Everything
// downstream reads the current shape and nothing carries an "or the old way" branch,
// which is what keeps the cost of the next version's migration to this file alone.
//
// A migration never drops what it could not interpret. The document is written back only
// after the whole app has loaded it successfully, and a copy of the original is kept
// beside it, so an install that is downgraded has something to go back to.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/sellitus/app-tail/internal/secretstore"
)

// ConfigVersion is the document shape this build writes.
//
//   - 1 (or absent): one tailnet, described entirely by the settings document. There was
//     no way to name it, because there was only ever one.
//   - 2: connections are data. The tailnet becomes a Tunnel with an id that forwards,
//     access rules and automatic mappings can name.
//   - 3: the tailnet's own identity and credentials move onto that connection, so a
//     second tailnet can have its own.
//   - 4: forwards and automatic port assignments name the connection they belong to,
//     so a device on one network can no longer be confused with a device on another.
//   - 5: the node preferences -- routes, exit node, tailnet DNS, shields -- move onto
//     the connection whose node holds them, so a second tailnet answers for its own.
//   - 6: the proxy becomes an instance with permissions of its own, so a second one can
//     carry a different program with a different reach.
//   - 7: the settings that create a network interface are named for the interface rather
//     than for the tun device behind one of them, since the group now governs two ways of
//     putting this machine on its connections.
const ConfigVersion = 8

// migrate brings cfg up to ConfigVersion, reporting whether anything changed. A document
// already at the current version reports no change, so loading an unchanged config never
// rewrites the file.
//
// Whatever its version, a document loses every settings block a connection carries for a
// type other than its own. Nothing reads such a block, and Validate refuses one, so keeping
// it would cost the user the whole document; its credentials would otherwise stay in
// config.json, since only the connection's own type's are moved into secrets.json. The
// file loses it on the next write. It runs before the steps below so a block a step writes
// onto a connection of the wrong type is still refused rather than silently dropped.
//
// raw is the document exactly as it was read. A step that moves a value out of a field
// this build no longer has needs it: the decode drops what it does not recognize, so by
// the time cfg exists the old value is already gone.
//
// Anything below the current version changes, because the version itself is written even
// where a step found nothing of its own to do -- a document that stayed at the old number
// would be migrated again on every load.
// A step that cannot complete is an error rather than a skip: every one of them moves
// something the app needs, so proceeding would write a document with the value silently
// gone and the version claiming the move had happened.
func migrate(cfg *Config, raw []byte) (bool, error) {
	dropBlocksOfOtherTypes(cfg)
	if cfg.Version >= ConfigVersion {
		return false, nil
	}
	// Version 0 and 1 are the same shape: the field did not exist before this migration,
	// so an absent version and an explicit 1 both mean "before connections were data".
	if cfg.Version < 2 {
		migrateToTunnels(cfg)
	}
	if cfg.Version < 3 {
		if err := migrateTailnetOntoItsConnection(cfg, raw); err != nil {
			return false, err
		}
	}
	if cfg.Version < 4 {
		migrateForwardsOntoTheirConnection(cfg)
	}
	if cfg.Version < 5 {
		if err := migratePrefsOntoTheirConnection(cfg, raw); err != nil {
			return false, err
		}
	}
	if cfg.Version < 6 {
		if err := migrateProxyIntoAnInstance(cfg, raw); err != nil {
			return false, err
		}
	}
	if cfg.Version < 7 {
		if err := migrateInterfaceSettings(cfg, raw); err != nil {
			return false, err
		}
	}
	if cfg.Version < 8 {
		turnOnTailnetRouteRepair(cfg)
	}
	cfg.Version = ConfigVersion
	return true, nil
}

// legacyTailnetSettings are the settings that described the one tailnet before a
// connection could be named. Every field is a pointer so an absent key and a stored empty
// value stay distinguishable: writing an empty hostname over a rendered template would
// change the device's name on the tailnet.
type legacyTailnetSettings struct {
	Hostname              *string   `json:"hostname"`
	HostnameTemplate      *string   `json:"hostnameTemplate"`
	Tags                  *[]string `json:"tags"`
	AdvertiseTagsOnLogin  *bool     `json:"advertiseTagsOnLogin"`
	AuthKey               *string   `json:"authKey"`
	OAuthClientSecret     *string   `json:"oauthClientSecret"`
	OAuthClientSecretFile *string   `json:"oauthClientSecretFile"`
	ControlURL            *string   `json:"controlURL"`
	Ephemeral             *bool     `json:"ephemeral"`
}

// migrateTailnetOntoItsConnection moves the tailnet's identity and credentials from the
// settings document onto the connection that has always been running them.
//
// It is read out of the raw document rather than out of cfg because this build's Settings
// no longer has these fields, so the decode has already discarded them. Losing them would
// present an enrolled machine with an empty device name and no credential, which is a
// fresh login for a tailnet it is already a member of.
func migrateTailnetOntoItsConnection(cfg *Config, raw []byte) error {
	var doc struct {
		Settings legacyTailnetSettings `json:"settings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("read the tailnet settings to move: %w", err)
	}
	primary, err := cfg.PrimaryTailscale()
	if err != nil {
		return fmt.Errorf("move the tailnet settings: %w", err)
	}
	held := doc.Settings
	assign(&primary.Hostname, held.Hostname)
	assign(&primary.HostnameTemplate, held.HostnameTemplate)
	assign(&primary.AdvertiseTagsOnLogin, held.AdvertiseTagsOnLogin)
	assign(&primary.AuthKey, held.AuthKey)
	assign(&primary.OAuthClientSecret, held.OAuthClientSecret)
	assign(&primary.OAuthClientSecretFile, held.OAuthClientSecretFile)
	assign(&primary.ControlURL, held.ControlURL)
	assign(&primary.Ephemeral, held.Ephemeral)
	if held.Tags != nil {
		primary.Tags = append([]string(nil), (*held.Tags)...)
	}
	return nil
}

// legacyPrefsSettings are the node preferences the settings document carried while there
// was one node to hold them. Pointers, for the same reason as legacyTailnetSettings: an
// absent key must not overwrite the default a stored false would legitimately set.
type legacyPrefsSettings struct {
	RoutesAccept                *bool                  `json:"routes.accept"`
	RoutesAdvertiseExitNode     *bool                  `json:"routes.advertiseExitNode"`
	RoutesAdvertise             *[]netip.Prefix        `json:"routes.advertise"`
	RoutesServe                 *bool                  `json:"routes.serve"`
	ExitNodeID                  *string                `json:"exitNode.nodeId"`
	ExitNodeAuto                *bool                  `json:"exitNode.auto"`
	ExitNodeAllowLANAccess      *bool                  `json:"exitNode.allowLanAccess"`
	ExitNodeOnFailure           *ExitNodeFailurePolicy `json:"exitNode.onFailure"`
	ExitNodeRotate              *bool                  `json:"exitNode.rotate.enabled"`
	ExitNodeRotateStrategy      *RotateStrategy        `json:"exitNode.rotate.strategy"`
	ExitNodeRotateIntervalSec   *int                   `json:"exitNode.rotate.intervalSec"`
	ExitNodeRotatePauseOnActive *bool                  `json:"exitNode.rotate.pauseOnActive"`
	ExitNodeRotateMaxDeferrals  *int                   `json:"exitNode.rotate.maxDeferrals"`
	DNSUseTailnet               *bool                  `json:"dns.useTailnet"`
	ShieldsUp                   *bool                  `json:"security.shieldsUp"`
	PostureChecking             *bool                  `json:"security.postureChecking"`
}

// migratePrefsOntoTheirConnection moves the node preferences from the settings document
// onto the connection whose node has always been holding them, and moves the record of
// whether they were adopted along with them.
//
// Adoption travels with the preferences because it is a fact about one node: it records
// that this install has already read what that node was doing before it pushed anything.
// Left on the document, a second connection would find the flag already set by the first
// and skip its own adoption, silently turning off whatever its node was configured with.
func migratePrefsOntoTheirConnection(cfg *Config, raw []byte) error {
	var doc struct {
		Settings     legacyPrefsSettings `json:"settings"`
		PrefsAdopted bool                `json:"prefsAdopted"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("read the node preferences to move: %w", err)
	}
	primary, err := cfg.PrimaryTailscale()
	if err != nil {
		return fmt.Errorf("move the node preferences: %w", err)
	}
	held := doc.Settings
	assign(&primary.RoutesAccept, held.RoutesAccept)
	assign(&primary.RoutesAdvertiseExitNode, held.RoutesAdvertiseExitNode)
	assign(&primary.RoutesServe, held.RoutesServe)
	assign(&primary.ExitNodeID, held.ExitNodeID)
	assign(&primary.ExitNodeAuto, held.ExitNodeAuto)
	assign(&primary.ExitNodeAllowLANAccess, held.ExitNodeAllowLANAccess)
	assign(&primary.ExitNodeOnFailure, held.ExitNodeOnFailure)
	assign(&primary.ExitNodeRotate, held.ExitNodeRotate)
	assign(&primary.ExitNodeRotateStrategy, held.ExitNodeRotateStrategy)
	assign(&primary.ExitNodeRotateIntervalSec, held.ExitNodeRotateIntervalSec)
	assign(&primary.ExitNodeRotatePauseOnActive, held.ExitNodeRotatePauseOnActive)
	assign(&primary.ExitNodeRotateMaxDeferrals, held.ExitNodeRotateMaxDeferrals)
	assign(&primary.DNSUseTailnet, held.DNSUseTailnet)
	assign(&primary.ShieldsUp, held.ShieldsUp)
	assign(&primary.PostureChecking, held.PostureChecking)
	if held.RoutesAdvertise != nil {
		primary.RoutesAdvertise = append([]netip.Prefix(nil), (*held.RoutesAdvertise)...)
	}

	for i := range cfg.Tunnels {
		if cfg.Tunnels[i].ID == PrimaryTunnelID {
			cfg.Tunnels[i].PrefsAdopted = doc.PrefsAdopted
		}
	}
	return nil
}

// legacyProxySettings are the proxy settings that described the one listener before there
// could be more than one. Pointers, for the same reason as the two above: an absent key
// must not overwrite a default that a stored false or empty string legitimately sets.
type legacyProxySettings struct {
	Listen         *string          `json:"proxy.listenAddr"`
	Scope          *ProxyScope      `json:"proxy.scope"`
	ResolveVia     *ProxyResolveVia `json:"proxy.resolveVia"`
	RequireToken   *bool            `json:"proxy.requireToken"`
	Token          *string          `json:"proxy.token"`
	DialTimeoutSec *int             `json:"proxy.dialTimeoutSec"`
}

// migrateProxyIntoAnInstance turns the one proxy into the first instance, carrying its
// address, its credential and -- as rules -- the reach its scope described.
//
// The scope is the part that matters. It was a two-valued setting meaning "the tailnet" or
// "anything", and both readings are grants: the first carries the one connection there
// was, the second also carries what this machine reaches on its own. Writing them as rules
// is what makes them separately revocable, and reading them as anything else would either
// widen a proxy the user deliberately kept narrow or cut off a browser that was pointed
// entirely at it.
//
// proxy.enabled stays in the settings and is untouched: it is the module switch for the
// feature, not a fact about one listener.
func migrateProxyIntoAnInstance(cfg *Config, raw []byte) error {
	// A document that already names the default instance is one a newer build wrote and an
	// older one then loaded. Adding a second under the same id would make every lookup of
	// it ambiguous.
	if _, exists := cfg.Proxy(DefaultProxyID); exists {
		return nil
	}

	var doc struct {
		Settings legacyProxySettings `json:"settings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("read the proxy settings to move: %w", err)
	}
	held := doc.Settings

	scope := ScopeTailnet
	assign(&scope, held.Scope)
	rules := reachOneConnection(PrimaryTunnelID)
	if scope == ScopeAll {
		rules = reachThisMachineToo(rules)
	}

	// Enabled rather than read off proxy.enabled: the module switch already decides
	// whether any proxy runs, and starting the one instance an upgrade has in the off
	// position would turn the module switch on into a proxy that still listens nowhere.
	instance := defaultProxy(true, DefaultProxyListenAddr, rules)
	assign(&instance.ListenAddr, held.Listen)
	assign(&instance.ResolveVia, held.ResolveVia)
	assign(&instance.RequireToken, held.RequireToken)
	assign(&instance.Token, held.Token)
	assign(&instance.DialTimeoutSec, held.DialTimeoutSec)
	if instance.ListenAddr == "" {
		instance.ListenAddr = DefaultProxyListenAddr
	}

	cfg.Proxies = append([]ProxyInstance{instance}, cfg.Proxies...)
	return nil
}

// legacyInterfaceSettings are the interface settings under the keys they had while the
// only interface app-tail could create was the tailnet's own tun device. Pointers, for the
// same reason as the tables above: an absent key must not overwrite a default that a
// stored false or empty value legitimately sets.
type legacyInterfaceSettings struct {
	Enabled       *bool           `json:"tun.enabled"`
	Mode          *NetworkMode    `json:"tun.mode"`
	InterfaceName *string         `json:"tun.interfaceName"`
	VirtualPool   *[]netip.Prefix `json:"tun.virtualPool"`
}

// migrateInterfaceSettings moves the interface settings onto the keys they are named by
// now.
//
// The rename is the whole of it: the group creates two different interfaces -- the
// tailnet's own, and the one carrying every connection at once -- and naming the group
// after the tun device behind the first made the second read as a setting on the wrong
// feature. Nothing about what any of them does changes.
//
// It reads the raw document because this build's Settings no longer has the old keys, so
// the decode has already dropped them. Losing them would take a machine that is on a
// network interface back to running inside app-tail alone, without saying so.
func migrateInterfaceSettings(cfg *Config, raw []byte) error {
	var doc struct {
		Settings legacyInterfaceSettings `json:"settings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("read the interface settings to rename: %w", err)
	}
	held := doc.Settings
	assign(&cfg.Settings.InterfaceEnabled, held.Enabled)
	assign(&cfg.Settings.InterfaceMode, held.Mode)
	assign(&cfg.Settings.InterfaceName, held.InterfaceName)
	if held.VirtualPool != nil {
		cfg.Settings.InterfaceVirtualPool = append([]netip.Prefix(nil), (*held.VirtualPool)...)
	}
	return nil
}

// turnOnTailnetRouteRepair puts the tailnet-route repair into the position a fresh install gets
// it in.
//
// A switch is needed rather than a default because a switch that defaults on is the one kind of
// default the back-fill cannot apply: an absent key and a stored false decode to the same value,
// so a document written before the field existed is indistinguishable from one where the user
// turned the feature off. The version says which, and this is the version where it appeared --
// every document below it predates the field.
//
// Doing nothing instead would leave the feature on for machines installed after it shipped and
// off for every machine already running, which is exactly backwards: the installs that have been
// running longest are the ones that have had time to lose the route.
func turnOnTailnetRouteRepair(cfg *Config) {
	cfg.Settings.TailnetRouteRepair = true
}

// assign writes a stored value over a destination, leaving it alone when the old document
// did not carry the key at all.
func assign[T any](dst *T, src *T) {
	if src != nil {
		*dst = *src
	}
}

// migrateToTunnels gives the one tailnet an identity.
//
// The tailnet itself is untouched: its settings stay exactly where they were, because
// this version only makes the connection nameable. What changes is that everything which
// points at "the tailnet" now points at a connection id, so pointing at a different one
// later is a change to the pointer rather than to the thing pointing.
func migrateToTunnels(cfg *Config) {
	// A document that already names the primary connection is one a newer build wrote and
	// an older one then loaded. Adding a second with the same id would make every lookup
	// of it ambiguous.
	if _, exists := cfg.Tunnel(PrimaryTunnelID); exists {
		return
	}
	cfg.Tunnels = append([]Tunnel{primaryTunnel()}, cfg.Tunnels...)
}

// migrateForwardsOntoTheirConnection points every forward and every automatic port
// assignment at the connection they have always been on.
//
// The forwards would be filled in by applyDefaults anyway; the assignments would not. Their
// key is "<device>/<port>", and a device id is only unique within one network, so the same
// key on a second tailnet would hand that network's device the local port this one's device
// already has -- moving a bookmark onto a different machine, which is the single failure
// this module's stored assignments exist to prevent. Rewriting the keys here is what keeps
// every existing port exactly where it is.
func migrateForwardsOntoTheirConnection(cfg *Config) {
	for i := range cfg.Forwards {
		if cfg.Forwards[i].TunnelID == "" {
			cfg.Forwards[i].TunnelID = PrimaryTunnelID
		}
	}
	if len(cfg.AutoMap) == 0 {
		return
	}
	moved := make(map[string]int, len(cfg.AutoMap))
	for key, port := range cfg.AutoMap {
		// A key that already names a connection is one a newer build wrote. Prefixing it
		// again would orphan the assignment and hand the device a different port.
		if strings.Count(key, "/") >= 2 {
			moved[key] = port
			continue
		}
		moved[PrimaryTunnelID+"/"+key] = port
	}
	cfg.AutoMap = moved
}

// backupSuffix is what a pre-migration copy is called. It carries the version it holds,
// so a second migration later does not overwrite the copy someone may still need.
func backupSuffix(version int) string {
	return fmt.Sprintf(".v%d.bak", max(version, 1))
}

// backupBeforeMigration copies the config file beside itself before the migrated document
// is first written. It is best-effort in one specific sense only: a copy that cannot be
// made is reported to the caller, which refuses to migrate rather than rewriting a
// document with no way back. Nothing here silently proceeds.
//
// The copy carries no credential. The original may hold them inline, from a build that kept
// them there, and a second plaintext copy is exactly what moving them into secrets.json is
// meant to end. Restoring it keeps the credentials secrets.json holds for its connections.
func backupBeforeMigration(path string, from int) error {
	backup := path + backupSuffix(from)
	// A backup already there is from an earlier migration of the same document. Keeping
	// it is the point: overwriting it with a copy that has already been migrated once
	// would destroy the only copy of the original shape.
	if _, err := os.Stat(backup); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("check for %s: %w", filepath.Base(backup), err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config before migrating: %w", err)
	}
	data, err = scrubSecrets(data)
	if err != nil {
		return err
	}
	if err := os.WriteFile(backup, data, FileMode); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(backup), err)
	}
	return restrictToOwner(backup)
}

// scrubSavedCopies takes the credentials out of every copy of the config kept beside it --
// pre-migration backups and documents set aside by a load, a restore or a reset -- that
// still holds them inline, as the copies older builds made do.
//
// A copy restores with the credentials file paired with it, or with secrets.json when it has
// none (see secretsFor), and the scrub keeps that working. When the file a copy would restore
// with lacks any credential the restore would give it today, those credentials are written to
// the copy's own paired file first, so restoring the copy brings back exactly what it did.
//
// It returns the copies that do not decode as a config document. Those are left exactly as
// they are, since nothing can tell which of their values are credentials.
func scrubSavedCopies(path string) ([]string, error) {
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	var unread []string
	for _, entry := range entries {
		if entry.IsDir() || savedKind(filepath.Base(path), entry.Name()) == "" {
			continue
		}
		saved := filepath.Join(dir, entry.Name())
		readable, err := scrubSavedCopy(path, saved)
		if err != nil {
			return unread, err
		}
		if !readable {
			unread = append(unread, saved)
		}
	}
	return unread, nil
}

// scrubSavedCopy is scrubSavedCopies for the one copy at saved, reporting false for a copy
// that does not decode as a config document.
func scrubSavedCopy(path, saved string) (bool, error) {
	raw, err := os.ReadFile(saved)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", filepath.Base(saved), err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return false, nil
	}
	// Brought to the shape a restore would bring it to, which is where this build reads
	// credentials from.
	if _, err := migrate(&cfg, raw); err != nil {
		return false, nil
	}
	scrubbed, err := scrubSecrets(raw)
	if err != nil {
		return true, err
	}
	if bytes.Equal(scrubbed, raw) {
		return true, nil
	}

	restoresWith, _, err := secretsFor(path, saved)
	if err != nil {
		return true, err
	}
	held, err := loadSecrets(restoresWith)
	if err != nil {
		return true, err
	}
	// What a restore of the copy runs with today: its inline credentials, and the file's
	// for the fields it leaves empty.
	mergeSecrets(&cfg, held)
	needed := collectSecrets(&cfg)
	if !holdsEvery(held, needed) {
		partner, ok := pairedSecretsPath(path, saved)
		if !ok {
			return true, fmt.Errorf("%s has no name for a credentials file of its own", filepath.Base(saved))
		}
		if err := secretstore.Save(partner, needed); err != nil {
			return true, err
		}
	}
	return true, replaceKeepingTime(saved, scrubbed)
}

// holdsEvery reports whether held has every credential in want, each with the same value.
func holdsEvery(held, want secretstore.Secrets) bool {
	for kind, ids := range want {
		for id, fields := range ids {
			for key, value := range fields {
				if held[kind][id][key] != value {
					return false
				}
			}
		}
	}
	return true
}

// replaceKeepingTime puts data at path through a temp file renamed over it, keeping the
// file's timestamp. A saved copy's timestamp is when it was saved, and the newest-first
// order a restore picks a copy by.
func replaceKeepingTime(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	tmp, err := writeTempFile(filepath.Dir(path), ".config-*.json", data)
	if err != nil {
		return err
	}
	if err := os.Chtimes(tmp, info.ModTime(), info.ModTime()); err != nil {
		return errors.Join(fmt.Errorf("keep the timestamp of %s: %w", filepath.Base(path), err), os.Remove(tmp))
	}
	if err := os.Rename(tmp, path); err != nil {
		return errors.Join(fmt.Errorf("replace %s: %w", filepath.Base(path), err), os.Remove(tmp))
	}
	return nil
}
