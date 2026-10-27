// SPDX-License-Identifier: MIT

package wgtunnel

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
)

// Fixed keys rather than generated ones: these tests are about the exact text a device is
// configured with, and the conversion from what a person pastes to what the device reads
// is the thing being checked.
const (
	testPrivateKey   = "aBhtG18wo5eIJXAkl7L4L3RyKNwzZuBAK1zSHnRRRXc="
	testPublicKey    = "vGKFmWU/gzcgTHFI9DMBGaGqjRWTKJhCXV/2NAB6dHM="
	testPresharedKey = "Ry0M2rNVGGQrrmJKKIY0F0EySFf9r0mAJvpDCkzQeGE="
)

func sampleDevice() Device {
	return Device{
		PrivateKey: testPrivateKey,
		Peer: Peer{
			PublicKey:    testPublicKey,
			Endpoint:     netip.MustParseAddrPort("198.51.100.7:51820"),
			AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
			KeepaliveSec: 25,
		},
	}
}

// hexOf is what the device expects a key to look like, derived here independently of the
// code under test so a key that is passed through unconverted fails.
func hexOf(t *testing.T, key string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatalf("the test's own key %q is not base64: %v", key, err)
	}
	return hex.EncodeToString(raw)
}

// The device takes its whole configuration as this text and applies a default for anything
// absent, so a value that never reaches it is a connection running on something nobody
// asked for rather than an error.
func TestTheRenderedConfigurationCarriesEveryValueTheDeviceNeeds(t *testing.T) {
	text, err := sampleDevice().UAPI()
	if err != nil {
		t.Fatalf("rendering a complete configuration failed: %v", err)
	}

	want := []string{
		"private_key=" + hexOf(t, testPrivateKey),
		"public_key=" + hexOf(t, testPublicKey),
		"endpoint=198.51.100.7:51820",
		"persistent_keepalive_interval=25",
		"allowed_ip=10.0.0.0/24",
		// Both replacements, which are what make applying a configuration leave exactly
		// what it names rather than merging it with whatever was there before.
		"replace_peers=true",
		"replace_allowed_ips=true",
	}
	for _, line := range want {
		if !strings.Contains(text, line+"\n") {
			t.Errorf("the configuration has no %q line:\n%s", line, text)
		}
	}

	// The device's own format: the peer's block opens at its public key, so anything
	// belonging to the device has to come first or it is read as the peer's.
	if strings.Index(text, "private_key=") > strings.Index(text, "public_key=") {
		t.Errorf("this device's own key is written after the peer's block opens:\n%s", text)
	}
}

// A pre-shared key the user never set must not appear at all: an all-zero one is a
// different configuration from none, and the server would refuse every handshake.
func TestThePresharedKeyIsWrittenOnlyWhenThereIsOne(t *testing.T) {
	text, err := sampleDevice().UAPI()
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if strings.Contains(text, "preshared_key") {
		t.Errorf("a configuration with no pre-shared key still carries the line:\n%s", text)
	}

	held := sampleDevice()
	held.Peer.PresharedKey = testPresharedKey
	text, err = held.UAPI()
	if err != nil {
		t.Fatalf("rendering with a pre-shared key failed: %v", err)
	}
	if !strings.Contains(text, "preshared_key="+hexOf(t, testPresharedKey)+"\n") {
		t.Errorf("a configuration with a pre-shared key does not carry it:\n%s", text)
	}
}

// No fixed port: two connections on one machine would collide on one, and a client never
// has to be reachable from outside.
func TestTheDeviceIsNotGivenAFixedPort(t *testing.T) {
	text, err := sampleDevice().UAPI()
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if strings.Contains(text, "listen_port") {
		t.Errorf("the configuration pins a port:\n%s", text)
	}
}

// Pointing a running connection at a server that moved must not disturb anything else about
// it. A render that replaced the peer would throw away the session keys the two sides have
// already agreed on, so a server that merely changed address would cost a fresh handshake
// and a gap in traffic every time this ran.
func TestMovingAServerChangesTheAddressAndNothingElse(t *testing.T) {
	text, err := MoveEndpoint(testPublicKey, netip.MustParseAddrPort("203.0.113.9:51820"))
	if err != nil {
		t.Fatalf("rendering the move failed: %v", err)
	}

	want := "public_key=" + hexOf(t, testPublicKey) + "\nupdate_only=true\nendpoint=203.0.113.9:51820\n"
	if text != want {
		t.Errorf("the move renders as:\n%s\nwant:\n%s", text, want)
	}
}

// update_only, so a peer that is somehow no longer on the device is not created here with no
// allowed addresses -- a connection that hands shakes and then drops everything.
func TestMovingAServerNeverCreatesOne(t *testing.T) {
	text, err := MoveEndpoint(testPublicKey, netip.MustParseAddrPort("203.0.113.9:51820"))
	if err != nil {
		t.Fatalf("rendering the move failed: %v", err)
	}
	if !strings.Contains(text, "update_only=true") {
		t.Errorf("the move would create a peer that is not there:\n%s", text)
	}
}

func TestAMoveWithNothingToMoveToIsRefused(t *testing.T) {
	cases := []struct {
		name     string
		key      string
		endpoint netip.AddrPort
		want     string
	}{
		{"no server key", "", netip.MustParseAddrPort("203.0.113.9:51820"), "server's public key"},
		{"an unresolved address", testPublicKey, netip.AddrPort{}, "server's address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text, err := MoveEndpoint(tc.key, tc.endpoint)
			if err == nil {
				t.Fatalf("a move with %s rendered anyway:\n%s", tc.name, text)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal is %q, which does not say %q", err, tc.want)
			}
		})
	}
}

// Each of these produces a device that starts and carries nothing, which is the failure
// worth catching here: it looks like a working connection from every angle except the one
// where traffic crosses. Each must be refused, naming the value that is wrong.
func TestAConfigurationThatCouldNotCarryTrafficIsRefusedByName(t *testing.T) {
	cases := []struct {
		name  string
		spoil func(d *Device)
		want  string
	}{
		{"no private key", func(d *Device) { d.PrivateKey = "" }, "private key"},
		{"a private key that is not a key", func(d *Device) { d.PrivateKey = "hunter2" }, "private key"},
		{"a key of the wrong length", func(d *Device) { d.PrivateKey = "c2hvcnQ=" }, "private key"},
		{"no server key", func(d *Device) { d.Peer.PublicKey = "" }, "server's public key"},
		{"an unresolved server address", func(d *Device) { d.Peer.Endpoint = netip.AddrPort{} }, "server's address"},
		{"nothing to carry", func(d *Device) { d.Peer.AllowedIPs = nil }, "drop everything sent through it"},
		{"a pre-shared key that is not a key", func(d *Device) { d.Peer.PresharedKey = "not a key" }, "pre-shared key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			held := sampleDevice()
			tc.spoil(&held)
			text, err := held.UAPI()
			if err == nil {
				t.Fatalf("a configuration with %s rendered anyway:\n%s", tc.name, text)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal is %q, which does not say %q", err, tc.want)
			}
		})
	}
}
