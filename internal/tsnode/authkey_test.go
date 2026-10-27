// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// oauthServer stands in for the control plane. It is a real HTTP server rather than a
// substituted client because the exchange is two requests with a token carried between
// them, and the bug this guards against -- sending the key request without the token, or
// with the wrong body -- is only visible from the server's side.
type oauthServer struct {
	*httptest.Server

	// keyBody is the request body the key endpoint received, so a test can assert on what
	// the control plane was actually asked for rather than on what this app meant to ask.
	keyBody keyCreateRequest
	// keyRaw is the same body before decoding. A field left out entirely and a field sent
	// as false decode identically, and the two mean different things to a server that has
	// its own default -- so the difference is only visible here.
	keyRaw string
	// authHeader is the Authorization header the key request carried.
	authHeader string
	// tokenCalls and keyCalls count the two halves of the exchange.
	tokenCalls, keyCalls int

	// keyStatus and keyReply let a test make the control plane refuse.
	keyStatus int
	keyReply  string
}

func newOAuthServer(t *testing.T) *oauthServer {
	t.Helper()
	s := &oauthServer{keyStatus: http.StatusOK, keyReply: `{"key":"tskey-auth-minted"}`}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		s.tokenCalls++
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"access_token":"tok-123","token_type":"Bearer","expires_in":3600}`)); err != nil {
			t.Errorf("write the token reply: %v", err)
		}
	})
	mux.HandleFunc("/api/v2/tailnet/-/keys", func(w http.ResponseWriter, r *http.Request) {
		s.keyCalls++
		s.authHeader = r.Header.Get("Authorization")
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read the key request: %v", err)
		}
		s.keyRaw = string(raw)
		if err := json.Unmarshal(raw, &s.keyBody); err != nil {
			t.Errorf("decode the key request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.keyStatus)
		if _, err := w.Write([]byte(s.keyReply)); err != nil {
			t.Errorf("write the key reply: %v", err)
		}
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// secretFor builds a client secret pointed at this test server.
func (s *oauthServer) secretFor(extra string) string {
	secret := oauthSecretPrefix + "abc123?baseURL=" + s.URL
	if extra != "" {
		secret += "&" + extra
	}
	return secret
}

// The whole exchange: a client secret becomes a token, the token becomes a key scoped to
// this node's tags, and the key is what the node enrols with. A break anywhere in it is a
// node that cannot join a tailnet at all.
func TestAnOAuthSecretBecomesATaggedAuthKey(t *testing.T) {
	server := newOAuthServer(t)
	in := ServerParams{ClientSecret: server.secretFor(""), AdvertiseTags: []string{"tag:app-tail"}}

	out, err := ResolveCredential(context.Background(), in)
	if err != nil {
		t.Fatalf("ResolveCredential: %v", err)
	}

	if out.AuthKey != "tskey-auth-minted" {
		t.Errorf("the node was given %q to enrol with, want the minted key", out.AuthKey)
	}
	// Cleared so nothing downstream spends the same secret again.
	if out.ClientSecret != "" {
		t.Errorf("the client secret survived the exchange as %q", out.ClientSecret)
	}
	if server.tokenCalls != 1 || server.keyCalls != 1 {
		t.Errorf("the exchange made %d token and %d key requests, want one of each",
			server.tokenCalls, server.keyCalls)
	}
	if !strings.HasPrefix(server.authHeader, "Bearer ") {
		t.Errorf("the key request carried Authorization %q, want the token from the first call", server.authHeader)
	}

	got := server.keyBody.Capabilities.Devices.Create
	if !reflect.DeepEqual(got.Tags, []string{"tag:app-tail"}) {
		t.Errorf("the key was asked for with tags %v, want this node's own %v", got.Tags, in.AdvertiseTags)
	}
	// One key is minted per start, so a reusable one would be a credential outliving its
	// purpose. It is sent explicitly rather than omitted, because an absent field leaves
	// the answer to the control plane's own default rather than to this app.
	if got.Reusable {
		t.Error("the key was asked for as reusable, so one start's credential would outlive that start")
	}
	if !strings.Contains(server.keyRaw, `"reusable"`) {
		t.Errorf("the key request was %s, which leaves out reusable and so leaves it to the control plane's default", server.keyRaw)
	}
	if !got.Ephemeral {
		t.Error("the key was not asked for as ephemeral, which is the documented default")
	}
	if got.Preauthorized {
		t.Error("the key was asked for as preauthorized, which is not the documented default")
	}
}

// The options a secret carries have to mean the same thing here as they do to the
// tailscale client, because people paste the same string into both.
func TestTheOptionsOnASecretReachTheControlPlane(t *testing.T) {
	tests := []struct {
		name                     string
		extra                    string
		wantEphem, wantPreauthed bool
	}{
		{name: "the defaults are ephemeral and not preauthorized", wantEphem: true},
		{name: "ephemeral can be turned off", extra: "ephemeral=false"},
		{
			name: "preauthorized can be turned on", extra: "preauthorized=true",
			wantEphem: true, wantPreauthed: true,
		},
		{
			name: "and both at once", extra: "ephemeral=false&preauthorized=true",
			wantPreauthed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newOAuthServer(t)
			in := ServerParams{ClientSecret: server.secretFor(tt.extra), AdvertiseTags: []string{"tag:x"}}
			if _, err := ResolveCredential(context.Background(), in); err != nil {
				t.Fatalf("ResolveCredential: %v", err)
			}
			got := server.keyBody.Capabilities.Devices.Create
			if got.Ephemeral != tt.wantEphem {
				t.Errorf("ephemeral reached the control plane as %v, want %v", got.Ephemeral, tt.wantEphem)
			}
			if got.Preauthorized != tt.wantPreauthed {
				t.Errorf("preauthorized reached the control plane as %v, want %v", got.Preauthorized, tt.wantPreauthed)
			}
		})
	}
}

// An OAuth client secret can only ever create a tagged node. Sending the exchange without
// tags would spend the secret on a request the control plane refuses, and the refusal it
// gives back says nothing about tags.
func TestAnUntaggedNodeIsRefusedBeforeTheSecretIsSpent(t *testing.T) {
	server := newOAuthServer(t)
	_, err := ResolveCredential(context.Background(), ServerParams{ClientSecret: server.secretFor("")})
	if err == nil {
		t.Fatal("an OAuth secret with no tags was accepted")
	}
	if !strings.Contains(err.Error(), "tag") {
		t.Errorf("the refusal said %q, which does not name what is missing", err)
	}
	if server.tokenCalls != 0 || server.keyCalls != 0 {
		t.Errorf("the control plane was contacted %d and %d times before the local check, want none",
			server.tokenCalls, server.keyCalls)
	}
}

// Pasting an OAuth secret into the auth key field is a thing people do, and the control
// plane's rejection of it is unrecognisable. The exchange is attempted for either field.
func TestASecretPastedIntoTheAuthKeyFieldIsStillExchanged(t *testing.T) {
	server := newOAuthServer(t)
	out, err := ResolveCredential(context.Background(), ServerParams{
		AuthKey:       server.secretFor(""),
		AdvertiseTags: []string{"tag:x"},
	})
	if err != nil {
		t.Fatalf("ResolveCredential: %v", err)
	}
	if out.AuthKey != "tskey-auth-minted" {
		t.Errorf("the node was given %q to enrol with, want the minted key", out.AuthKey)
	}
}

// Anything that is not an OAuth secret comes back untouched, so every caller can call this
// unconditionally instead of deciding first whether it applies.
func TestAnythingThatIsNotASecretPassesThroughUnchanged(t *testing.T) {
	tests := []struct {
		name string
		in   ServerParams
	}{
		{name: "an ordinary auth key", in: ServerParams{AuthKey: "tskey-auth-real"}},
		{name: "no credential at all", in: ServerParams{}},
		{
			name: "and a key that merely looks similar",
			in:   ServerParams{AuthKey: "tskey-client", AdvertiseTags: []string{"tag:x"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := ResolveCredential(context.Background(), tt.in)
			if err != nil {
				t.Fatalf("ResolveCredential: %v", err)
			}
			if !reflect.DeepEqual(out, tt.in) {
				t.Errorf("ResolveCredential changed %+v into %+v", tt.in, out)
			}
		})
	}
}

// A refusal from the control plane has to arrive with the control plane's own sentence.
// This is the one failure a user can act on -- a revoked secret, a tag they do not own --
// and replacing it with a generic message throws that away.
func TestARefusalCarriesTheControlPlanesOwnReason(t *testing.T) {
	server := newOAuthServer(t)
	server.keyStatus = http.StatusForbidden
	server.keyReply = `{"message":"tag:app-tail is not owned by this client"}`

	_, err := ResolveCredential(context.Background(), ServerParams{
		ClientSecret:  server.secretFor(""),
		AdvertiseTags: []string{"tag:app-tail"},
	})
	if err == nil {
		t.Fatal("a refused exchange was reported as success")
	}
	if !strings.Contains(err.Error(), "not owned by this client") {
		t.Errorf("the failure said %q, which loses the control plane's own reason", err)
	}
}

// A 200 with no key in it is a success this app must not treat as one: the node would go
// on to enrol with an empty credential and report an unrelated failure much later.
func TestAnAnswerWithNoKeyIsAFailure(t *testing.T) {
	server := newOAuthServer(t)
	server.keyReply = `{}`

	_, err := ResolveCredential(context.Background(), ServerParams{
		ClientSecret:  server.secretFor(""),
		AdvertiseTags: []string{"tag:x"},
	})
	if err == nil {
		t.Fatal("an answer carrying no key was accepted")
	}
	if !strings.Contains(err.Error(), "did not return it") {
		t.Errorf("the failure said %q, which does not say what was missing", err)
	}
}

// An option nobody implemented is a refusal rather than a silent no-op. A secret written
// for a future release, pasted into this one, would otherwise mint a key with properties
// the user did not ask for -- a long-lived one where they wanted an ephemeral node.
func TestAnUnknownOptionOnASecretIsRefused(t *testing.T) {
	// Every secret below that can carry one is pointed at an address nothing answers on.
	// These must be refused by the options written on them alone, and a regression that let
	// one through must fail here rather than reach the real control plane from a unit test.
	dead := newOAuthServer(t)
	dead.Close()
	base := "baseURL=" + dead.URL + "&"

	tests := []struct {
		name, secret, wantPhrase string
	}{
		{
			name:       "an option this build does not know",
			secret:     oauthSecretPrefix + "abc?" + base + "exitNode=true",
			wantPhrase: "does not know",
		},
		{
			name:       "a value that is not true or false",
			secret:     oauthSecretPrefix + "abc?" + base + "ephemeral=sometimes",
			wantPhrase: "not true or false",
		},
		{
			name:       "a value that is not true or false on the other option either",
			secret:     oauthSecretPrefix + "abc?" + base + "preauthorized=maybe",
			wantPhrase: "not true or false",
		},
		{
			// No baseURL on this one: the query is unparseable by construction, so there is
			// nowhere to put one and nothing that could ever dial.
			name:       "and options that will not parse at all",
			secret:     oauthSecretPrefix + "abc?%zz",
			wantPhrase: "read the options",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ResolveCredential(context.Background(), ServerParams{
				ClientSecret:  tt.secret,
				AdvertiseTags: []string{"tag:x"},
			})
			if err == nil {
				t.Fatalf("%q was accepted", tt.secret)
			}
			if !strings.Contains(err.Error(), tt.wantPhrase) {
				t.Errorf("the refusal said %q, which does not mention %q", err, tt.wantPhrase)
			}
		})
	}
}

// A 200 that is not JSON is what a captive portal, a corporate TLS proxy or a gateway
// error page answers with, and every one of those is more likely than a control plane
// misbehaving. Enrolling on whatever fell out of that would spend the secret for nothing.
func TestAnAnswerThatIsNotJSONIsAFailureRatherThanAnEmptyKey(t *testing.T) {
	server := newOAuthServer(t)
	server.keyReply = "<html><body>502 Bad Gateway</body></html>"

	_, err := ResolveCredential(context.Background(), ServerParams{
		ClientSecret:  server.secretFor(""),
		AdvertiseTags: []string{"tag:x"},
	})
	if err == nil {
		t.Fatal("an answer that is not JSON was accepted")
	}
	if !strings.Contains(err.Error(), "read the control plane's answer") {
		t.Errorf("the failure said %q, which does not say which step could not be completed", err)
	}
}

// An API host nothing answers on is the ordinary case of a machine that is offline, or a
// self-hosted baseURL that has moved. The secret is unspent and the node has no key, so the
// failure has to name the exchange rather than surface as an enrolment error later.
func TestAnUnreachableControlPlaneIsReportedAsAFailedExchange(t *testing.T) {
	server := newOAuthServer(t)
	// Closed rather than never started, so the address is one this machine really has
	// nothing listening on rather than a port something else may have taken.
	gone := server.URL
	server.Close()

	_, err := ResolveCredential(context.Background(), ServerParams{
		ClientSecret:  oauthSecretPrefix + "abc123?baseURL=" + gone,
		AdvertiseTags: []string{"tag:x"},
	})
	if err == nil {
		t.Fatal("an exchange with nothing on the other end was reported as success")
	}
	if !strings.Contains(err.Error(), "exchange the OAuth client secret") {
		t.Errorf("the failure said %q, which does not name the step that could not be completed", err)
	}
}
