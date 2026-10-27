// SPDX-License-Identifier: MIT

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A JSON Pointer treats "/" as a path separator and "~" as its own escape, so a token
// carrying either has to be encoded or the patch addresses the wrong place entirely.
// Every existing case escapes to itself, so the encoding is currently unproven.
func TestPointerTokensAreEscapedPerRFC6901(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{"nothing to escape", "tag:app-tail", "tag:app-tail"},
		{"a slash becomes ~1", "tag:team/ops", "tag:team~1ops"},
		{"a tilde becomes ~0", "tag:a~b", "tag:a~0b"},
		// Order matters: escaping "/" first and then "~" would turn "a/b" into "a~01b".
		{"a tilde and a slash together", "tag:a~b/c", "tag:a~0b~1c"},
		{"several of each", "~/~/", "~0~1~0~1"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapePointer(tt.token); got != tt.want {
				t.Errorf("escapePointer(%q) = %q, want %q", tt.token, got, tt.want)
			}
		})
	}
}

// The behavioural half: an unescaped "/" makes JSON Patch descend into a nested object
// rather than create the key. The bootstrap then reports success over a policy that
// grants the tag nothing, and the user's nodes silently cannot enroll.
func TestATagContainingAPointerMetacharacterLandsUnderItsOwnKey(t *testing.T) {
	const tag = "tag:team/ops"
	// A policy that already has a tagOwners object, so the patch addresses a child key
	// rather than creating the parent.
	const existing = `{"tagOwners":{"tag:other":["autogroup:admin"]}}`

	plan, err := PlanBootstrap([]byte(existing), Options{
		Tag:       tag,
		Owners:    []string{"autogroup:admin"},
		GrantDsts: []string{"*"},
	})
	if err != nil {
		t.Fatalf("PlanBootstrap: %v", err)
	}
	if !plan.AddTagOwner {
		t.Fatal("the plan does not add the tag owner at all")
	}

	updated, err := Apply([]byte(existing), plan)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	var got struct {
		TagOwners map[string]json.RawMessage `json:"tagOwners"`
	}
	if err := json.Unmarshal(standardized(t, updated), &got); err != nil {
		t.Fatalf("read the patched policy %s: %v", updated, err)
	}

	if _, ok := got.TagOwners[tag]; !ok {
		t.Fatalf("tagOwners has no %q key: %s\nan unescaped separator put the owners "+
			"under a nested object, so the tag grants nothing", tag, updated)
	}
	if _, ok := got.TagOwners["tag:team"]; ok {
		t.Errorf("the patch created a nested %q entry: %s", "tag:team", updated)
	}
	if _, ok := got.TagOwners["tag:other"]; !ok {
		t.Errorf("the existing tag owner was lost: %s", updated)
	}
}

// The tailnet name goes into the request path. A name with a slash -- which an
// org-scoped tailnet has -- would otherwise address a different endpoint entirely and
// the bootstrap would report a 404 the user cannot explain.
func TestTheTailnetNameIsEscapedIntoTheACLPath(t *testing.T) {
	tests := []struct {
		tailnet string
		want    string
	}{
		{"example.com", "/api/v2/tailnet/example.com/acl"},
		{"tail1234.ts.net", "/api/v2/tailnet/tail1234.ts.net/acl"},
		{"org/team", "/api/v2/tailnet/org%2Fteam/acl"},
		{"-", "/api/v2/tailnet/-/acl"},
	}

	for _, tt := range tests {
		t.Run(tt.tailnet, func(t *testing.T) {
			c := NewClient("https://api.tailscale.com", tt.tailnet, http.DefaultClient)
			if got := c.aclPath(); got != tt.want {
				t.Errorf("aclPath = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- save responses -------------------------------------------------------

// The control API answers a successful policy write with any of three statuses
// depending on the endpoint version. Treating one of them as a failure would tell the
// user their bootstrap failed after it had already been written, and a re-run then
// finds nothing to do -- which reads as the bootstrap silently doing nothing.
func TestEverySuccessfulSaveStatusIsAccepted(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v2/oauth/token" {
					fmt.Fprint(w, `{"access_token":"tok-abc"}`)
					return
				}
				w.WriteHeader(status)
			}))
			t.Cleanup(srv.Close)

			c := NewClient(srv.URL, "example.com", srv.Client())
			if err := c.Authenticate(context.Background(), "id", "secret"); err != nil {
				t.Fatalf("Authenticate: %v", err)
			}

			err := c.Save(context.Background(), Document{ETag: `"v1"`}, []byte(`{}`))
			if err != nil {
				t.Errorf("Save = %v for a %d response, want it accepted", err, status)
			}
		})
	}
}

// A save the API refuses has to carry the API's own words. "save failed (400 Bad
// Request)" alone leaves the user with a rejected policy and no idea which rule the
// control plane objected to.
func TestARefusedSaveCarriesTheControlPlanesReason(t *testing.T) {
	const reason = `{"message":"invalid grant: dst \"*\" requires ip"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			fmt.Fprint(w, `{"access_token":"tok-abc"}`)
			return
		}
		http.Error(w, reason, http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "example.com", srv.Client())
	if err := c.Authenticate(context.Background(), "id", "secret"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	err := c.Save(context.Background(), Document{ETag: `"v1"`}, []byte(`{}`))

	if err == nil {
		t.Fatal("Save reported success over a refusal")
	}
	if !strings.Contains(err.Error(), "requires ip") {
		t.Errorf("err = %v, want the control plane's own message", err)
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("err = %v, want it to carry the status", err)
	}
}

// --- token failures -------------------------------------------------------

// The token endpoint is the first thing a bootstrap touches, and a body that is not
// JSON -- an HTML error page from a proxy, a plain-text gateway message -- is exactly
// what a misconfigured base URL produces. It has to be reported rather than parsed.
func TestATokenResponseThatIsNotJSONIsReportedRatherThanParsed(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{
			name:   "an html error page behind a proxy",
			status: http.StatusBadGateway,
			body:   "<html><body>502 Bad Gateway</body></html>",
			want:   "502",
		},
		{
			name:   "a 200 carrying something that is not a token document",
			status: http.StatusOK,
			body:   "not json at all",
			want:   "parse oauth token response",
		},
		{
			name:   "a 200 carrying valid json with no token",
			status: http.StatusOK,
			body:   `{"token_type":"Bearer"}`,
			want:   "no access token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}))
			t.Cleanup(srv.Close)

			c := NewClient(srv.URL, "example.com", srv.Client())
			err := c.Authenticate(context.Background(), "id", "secret")

			if err == nil {
				t.Fatal("Authenticate succeeded against a response carrying no token")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to mention %q", err, tt.want)
			}
			// A client that thinks it is authenticated would go on to send a bearer
			// token of "" and get an opaque 401 on the next call instead.
			if _, err := c.Fetch(context.Background()); err == nil ||
				!strings.Contains(err.Error(), "not authenticated") {
				t.Errorf("Fetch after a failed Authenticate = %v, want it refused as unauthenticated", err)
			}
		})
	}
}

// A control-plane error body is shown to the user in a terminal. An unbounded one --
// a stack trace, an HTML page -- would bury the prompt, and an empty one would print
// a bare "failed ()" that says nothing at all.
func TestAnErrorBodyIsTrimmedToSomethingReadable(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"empty", "", "(empty response body)"},
		{"whitespace only", "   \n\t ", "(empty response body)"},
		{"short", "policy rejected", "policy rejected"},
		{"surrounded by whitespace", "\n  policy rejected  \n", "policy rejected"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := summarize([]byte(tt.body)); got != tt.want {
				t.Errorf("summarize(%q) = %q, want %q", tt.body, got, tt.want)
			}
		})
	}

	long := strings.Repeat("x", 900)
	got := summarize([]byte(long))
	if len(got) > 520 {
		t.Errorf("a %d-byte body summarized to %d bytes; a terminal message has to stay "+
			"readable", len(long), len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Error("a truncated body does not say it was truncated, so the user cannot " +
			"tell a cut-off message from a complete one")
	}
}

// --- multi-tag bootstrap --------------------------------------------------

// BootstrapAll plans every tag against one fetched document. A failure planning any of
// them must abandon the whole write: a partial policy would grant some tags and not
// others while reporting neither.
func TestBootstrapAllAbandonsTheWholeWriteWhenOneTagCannotBePlanned(t *testing.T) {
	control := newFakeControl(`{"tagOwners":{}}`)
	client := control.start(t)

	_, err := BootstrapAll(context.Background(), client, []Options{
		{Tag: "tag:app-tail", Owners: []string{"autogroup:admin"}, GrantDsts: []string{"*"}},
		{Tag: "", Owners: []string{"autogroup:admin"}}, // invalid: no tag
	}, false)

	if err == nil {
		t.Fatal("BootstrapAll succeeded with an unplannable option set")
	}
	if control.saveCount() != 0 {
		t.Errorf("the policy was written %d times despite the failure; the tailnet "+
			"would carry half the intended change", control.saveCount())
	}
}

// A dry run is what the dashboard's preview renders. Writing during one would apply a
// change the user has not confirmed yet.
func TestADryRunReportsWhatWouldChangeWithoutWritingAnything(t *testing.T) {
	control := newFakeControl(`{"tagOwners":{}}`)
	client := control.start(t)

	result, err := BootstrapAll(context.Background(), client, []Options{
		{Tag: "tag:app-tail", Owners: []string{"autogroup:admin"}, GrantDsts: []string{"*"}},
	}, true)
	if err != nil {
		t.Fatalf("BootstrapAll: %v", err)
	}

	if !result.Changed {
		t.Error("the dry run reported nothing would change, so the dashboard would " +
			"offer no apply button for a policy that needs one")
	}
	if len(result.Updated) != 0 {
		t.Error("a dry run produced a document to write")
	}
	if control.saveCount() != 0 {
		t.Errorf("a dry run wrote the policy %d times", control.saveCount())
	}
}

// standardized converts a HuJSON policy to plain JSON so a test can decode it.
func standardized(t *testing.T, document []byte) []byte {
	t.Helper()
	out, err := standardize(document)
	if err != nil {
		t.Fatalf("standardize %s: %v", document, err)
	}
	return out
}
