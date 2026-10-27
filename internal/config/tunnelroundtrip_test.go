// SPDX-License-Identifier: MIT

package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// A value for every field the connection form can write, keyed the way the form keys it.
//
// Booleans and pickers are not here: both are answered from the field's own declaration
// below, so a new choice on an existing picker needs no edit. Everything else does, and a
// field with no value here fails by name rather than being skipped -- the whole point of
// this test is that nothing gets to sit in the table unexercised.
//
// The certificate and key material is assembled from its parts on the same terms as the
// fixtures in the file reader's tests: a literal key-shaped block in a source file is what
// a secret scanner reports and an on-access scanner quarantines.
// A tls-auth or tls-crypt key is hexadecimal between its wrapper lines. This is a counting
// pattern rather than key material, and it is repeated rather than written out for the same
// reason the wrapper lines are assembled: a run of hexadecimal that long in a source file is
// what a secret scanner reports.
var ovpnStaticKeyBody = strings.Repeat("0123456789abcdef", 2)

var tunnelFormWrites = map[string]any{
	"name":                         "Renamed",
	"slug":                         "renamed",
	"hostname":                     "workstation",
	"hostnameTemplate":             "{{.User}}-laptop",
	"tags":                         []string{"tag:server"},
	"authKey":                      "tskey-auth-abcdef1234-0123456789abcdef",
	"oauthClientSecret":            "tskey-client-abcdef1234-0123456789abcdef",
	"oauthClientSecretFile":        "/etc/app-tail/oauth-secret",
	"controlURL":                   "https://headscale.example.com",
	"exitNode.nodeId":              "nodeid-abcdef",
	"exitNode.rotate.intervalSec":  900,
	"exitNode.rotate.maxDeferrals": 3,
	"routes.advertise":             []string{"192.168.7.0/24"},
	"wg.privateKey":                testPrivateKey,
	"wg.peer.publicKey":            testPeerKey,
	"wg.peer.presharedKey":         testPeerKey,
	"wg.peer.endpoint":             "gateway.example.com:51820",
	"wg.addresses":                 []string{"10.9.0.2/32"},
	"wg.peer.allowedIPs":           []string{"10.9.0.0/24"},
	"wg.dns":                       []string{"10.9.0.1"},
	"wg.mtu":                       1380,
	"wg.peer.keepaliveSec":         25,
	"ovpn.remote":                  "vpn.example.com:1194",
	"ovpn.ca":                      ovpnCAPEM,
	"ovpn.cert":                    ovpnCertPEM,
	"ovpn.key":                     ovpnKeyPEM,
	"ovpn.keyPassphrase":           "unlock the key",
	"ovpn.username":                "someone",
	"ovpn.password":                "a password",
	"ovpn.tlsCrypt":                staticKeyBlock(ovpnStaticKeyBody),
	"ovpn.tlsAuth":                 staticKeyBlock(ovpnStaticKeyBody),
	"ovpn.verifyName":              "vpn.example.com",
	"ovpn.routes":                  []string{"10.8.0.0/24"},
	"ovpn.dns":                     []string{"10.8.0.1"},
	"ovpn.cipher":                  "AES-256-GCM",
	"ovpn.auth":                    "SHA256",
	"ovpn.mtu":                     1400,
}

// sameEncoded compares two view values the way a client sees them, which is after encoding.
// A stored []string and a written []any are the same answer to the reader and differ only
// in how this test happened to write the value down.
func sameEncoded(t *testing.T, got, want any) bool {
	t.Helper()
	a, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("encoding what the view holds: %v", err)
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("encoding what was written: %v", err)
	}
	return string(a) == string(b)
}

// everyModuleOn is this machine's settings with every optional module turned on, read from
// the module list itself so a module added later is covered without an edit here.
//
// Which fields a module gates is settled by the module's own tests. What is asked here is
// whether a field that IS available goes where it says it goes, so every one of them has to
// be reachable or the answer is only about the modules that happen to ship on by default.
func everyModuleOn(t *testing.T) Settings {
	t.Helper()
	app := Defaults().Settings
	on := make(map[string]any)
	for _, m := range FeatureModules() {
		on[m.SwitchKey] = true
	}
	if err := ApplySettingsPatch(&app, patchOf(t, on)); err != nil {
		t.Fatalf("turning every module on: %v", err)
	}
	return app
}

// writeAndRead saves one field and hands back what the connection's own view then reports
// for it, so every assertion below travels the path a save from the form travels.
func writeAndRead(t *testing.T, typ TunnelType, key, viewKey string, value any) (any, bool) {
	t.Helper()
	app := everyModuleOn(t)
	tun := NewTunnel("tn_a1b2c3", "office", "Office", typ)
	if err := ApplyTunnelPatch(&tun, &app, patchOf(t, map[string]any{key: value})); err != nil {
		t.Errorf("writing %s = %v: %v", key, value, err)
		return nil, false
	}
	got, held := BuildTunnelView(tun, &app)[viewKey]
	if !held {
		t.Errorf("%s was written and the view has no %q, so the form would render an empty "+
			"control over a stored value", key, viewKey)
		return nil, false
	}
	return got, true
}

// Every field the form offers is stored where that field's own reader looks.
//
// The failure this guards against is the one that survives review: a row whose get and set
// closures name different members. The save is accepted, the dashboard reports it applied,
// the form reads back the value it already had, and nothing the connection runs on ever
// changes. The table is long enough and regular enough that a copy-paste between two rows
// is the likeliest edit anybody makes to it.
func TestEveryFieldTheFormOffersIsStoredWhereItsOwnReaderLooks(t *testing.T) {
	app := everyModuleOn(t)

	for _, typ := range TunnelTypes {
		t.Run(string(typ), func(t *testing.T) {
			for _, f := range TunnelSchema(&app) {
				if f.Variant != "" && f.Variant != string(typ) {
					continue
				}
				if f.Write != WritePatch {
					continue
				}
				switch f.Kind {
				case KindBool:
					// Both ways round: a set that ignores its argument passes a one-way check.
					for _, want := range []bool{true, false} {
						got, ok := writeAndRead(t, typ, f.Key, f.ViewKey, want)
						if ok && got != any(want) {
							t.Errorf("%s reads back as %v after writing %v", f.Key, got, want)
						}
					}
				case KindEnum:
					if len(f.Options) == 0 {
						t.Errorf("%s is a picker with nothing to pick", f.Key)
						continue
					}
					for _, opt := range f.Options {
						got, ok := writeAndRead(t, typ, f.Key, f.ViewKey, opt.Value)
						if ok && got != any(opt.Value) {
							t.Errorf("%s reads back as %v after choosing %q", f.Key, got, opt.Value)
						}
					}
				case KindSecret, KindSecretText:
					// A secret is never sent back out, so what the view owes the form is
					// whether one is held -- and it must say so only once one is.
					value, held := tunnelFormWrites[f.Key]
					if !held {
						t.Errorf("%s has no value in this test, so nothing proves the form can write it", f.Key)
						continue
					}
					if got, ok := writeAndRead(t, typ, f.Key, f.ViewKey, value); ok && got != any(true) {
						t.Errorf("%s reads back as %v with a secret stored, want true", f.Key, got)
					}
					if got, ok := writeAndRead(t, typ, f.Key, f.ViewKey, ""); ok && got != any(false) {
						t.Errorf("%s reads back as %v with no secret stored, want false", f.Key, got)
					}
				default:
					value, held := tunnelFormWrites[f.Key]
					if !held {
						t.Errorf("%s has no value in this test, so nothing proves the form can write it", f.Key)
						continue
					}
					got, ok := writeAndRead(t, typ, f.Key, f.ViewKey, value)
					if ok && !sameEncoded(t, got, value) {
						t.Errorf("%s reads back as %v after writing %v", f.Key, got, value)
					}
				}
			}
		})
	}
}
