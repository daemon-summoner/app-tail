// SPDX-License-Identifier: MIT

package ovpntunnel

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
)

// The one ordering guarantee the whole search rests on: whatever else is tried, the settings as
// they were entered are tried first and unchanged. Anything else would be this app quietly
// dialling somewhere the person who configured it did not ask for.
func TestTheSettingsAsStoredAreAlwaysTheFirstThingTried(t *testing.T) {
	base := Run{Remote: "vpn.example.com:53", Proto: config.OpenVPNProtoUDP, TLSCrypt: "key"}
	attempts := attemptsFor(base, false)
	if len(attempts) < 2 {
		t.Fatalf("a connection with a key and a port got %d attempts, want the stored one and alternatives", len(attempts))
	}
	if !attempts[0].stored() {
		t.Errorf("the first attempt is %q, want the settings as they are stored", attempts[0].what)
	}
	if !reflect.DeepEqual(attempts[0].run, base) {
		t.Errorf("the first attempt changed the stored settings:\n got %+v\nwant %+v", attempts[0].run, base)
	}
	for _, a := range attempts[1:] {
		if a.what == "" {
			t.Error("an attempt other than the first reports no change, so nothing would be reported to the user")
		}
	}
}

// The host is never one of the things tried. A wrong port, key or digest is a copying mistake;
// a different host is a different server, and choosing one for somebody is not this app's to do.
func TestNoAttemptDialsADifferentHost(t *testing.T) {
	base := Run{Remote: "vpn.example.com:53", Proto: config.OpenVPNProtoUDP, TLSAuth: "key"}
	for _, a := range attemptsFor(base, false) {
		if !strings.HasPrefix(a.run.Remote, "vpn.example.com:") {
			t.Errorf("an attempt dials %q, want the configured host", a.run.Remote)
		}
	}
}

// A key filed under tls-crypt when the server signs a tls-auth channel is the failure nothing
// can see: the two files are identical in form, and the server answers a wrong one with
// silence. So the same key read the other way has to be among the things tried, with the
// client's own key direction and with the digests such a channel may be signed with.
func TestAKeyIsTriedInTheOtherSlot(t *testing.T) {
	crypt := attemptsFor(Run{Remote: "vpn.example.com:1194", Proto: config.OpenVPNProtoUDP, TLSCrypt: "key"}, false)
	var found bool
	for _, a := range crypt {
		if a.run.TLSAuth != "key" {
			continue
		}
		found = true
		if a.run.TLSCrypt != "" {
			t.Error("an attempt reading the key as a tls-auth key left it in the tls-crypt slot too")
		}
		if a.run.KeyDirection != config.OpenVPNKeyDirectionClient {
			t.Errorf("a tls-auth attempt uses key direction %q, want the client's half", a.run.KeyDirection)
		}
	}
	if !found {
		t.Error("a tls-crypt key was never tried as a tls-auth key")
	}

	auth := attemptsFor(Run{Remote: "vpn.example.com:1194", Proto: config.OpenVPNProtoUDP, TLSAuth: "key"}, false)
	found = false
	for _, a := range auth {
		if a.run.TLSCrypt == "key" {
			found = true
			if a.run.TLSAuth != "" || a.run.KeyDirection != "" {
				t.Error("an attempt reading the key as a tls-crypt key kept the tls-auth settings, which openvpn refuses")
			}
		}
	}
	if !found {
		t.Error("a tls-auth key was never tried as a tls-crypt key")
	}
}

// A digest the configuration states is the server's own answer to which digest it uses. Trying
// others against it would be this app disagreeing with the file it was given.
func TestADigestThatIsConfiguredIsNeverChanged(t *testing.T) {
	base := Run{Remote: "vpn.example.com:1194", Proto: config.OpenVPNProtoUDP, TLSAuth: "key", Auth: "SHA256"}
	for _, a := range attemptsFor(base, false) {
		if a.run.Auth != "SHA256" {
			t.Errorf("an attempt signs the control channel with %q, want the configured digest", a.run.Auth)
		}
	}
}

// Every attempt at one address shares an endpoint number, because an address that turns out to
// carry something other than an OpenVPN server condemns all of them at once.
func TestAttemptsAtOneAddressShareAnEndpoint(t *testing.T) {
	attempts := attemptsFor(Run{Remote: "vpn.example.com:53", Proto: config.OpenVPNProtoUDP, TLSCrypt: "key"}, false)
	where := map[int]string{}
	for _, a := range attempts {
		addr := a.run.Remote + "/" + a.run.Proto
		if seen, ok := where[a.endpoint]; ok && seen != addr {
			t.Errorf("endpoint %d covers both %s and %s", a.endpoint, seen, addr)
		}
		where[a.endpoint] = addr
	}
	if len(where) < 2 {
		t.Errorf("attempts cover %d addresses, want the configured one and the standard ones", len(where))
	}
}

// A connection with nothing to vary is left alone rather than restarted pointlessly.
func TestAConnectionWithNothingToVaryIsTriedOnce(t *testing.T) {
	attempts := attemptsFor(Run{Remote: "not-a-host-port", Proto: config.OpenVPNProtoUDP}, false)
	if len(attempts) != 1 || !attempts[0].stored() {
		t.Errorf("got %d attempts, want only the settings as they are stored", len(attempts))
	}
}

// Which reasons move the search along, and which of them condemn the address rather than the
// material. A reason that says the server was reached and said no must move nothing: trying
// other addresses for a refused account would leave the account still refused and the user
// reading about ports.
func TestOnlyAReasonThatSaysTheServerWasNeverReachedMovesTheSearch(t *testing.T) {
	for _, tc := range []struct {
		notice       string
		wantUnreach  bool
		wantEndpoint bool
	}{
		{
			notice:       "TLS Error: client->client or server->server connection attempted from [AF_INET]187.14.251.144:53",
			wantUnreach:  true,
			wantEndpoint: true,
		},
		{notice: "Connection refused (errno=61)", wantUnreach: true, wantEndpoint: true},
		{notice: "No route to host", wantUnreach: true, wantEndpoint: true},
		{notice: "Network is unreachable", wantUnreach: true, wantEndpoint: true},
		{notice: "TLS Error: TLS key negotiation failed to occur within 60 seconds", wantUnreach: true},
		{notice: "Server poll timeout, restarting", wantUnreach: true},
		{notice: "Connection reset, restarting", wantUnreach: true},
		{notice: "AUTH_FAILED"},
		{notice: "VERIFY X509NAME ERROR: CN=elsewhere, must be CN=here"},
		{notice: "certificate verify failed"},
		{notice: "private key password verification failed"},
		{notice: "Options error: Unrecognized option"},
	} {
		t.Run(tc.notice, func(t *testing.T) {
			endpoint, unreached := reachFailure(tc.notice)
			if unreached != tc.wantUnreach {
				t.Errorf("unreached is %v, want %v", unreached, tc.wantUnreach)
			}
			if endpoint != tc.wantEndpoint {
				t.Errorf("the address is condemned: %v, want %v", endpoint, tc.wantEndpoint)
			}
		})
	}
}
