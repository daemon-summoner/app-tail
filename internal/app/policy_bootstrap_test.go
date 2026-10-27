// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/policy"
)

// fakeControlPlane is Tailscale's policy API reduced to the two endpoints a bootstrap
// touches. It records every write, so a test can prove a preview wrote nothing and an
// apply wrote once -- the guarantee that makes the setup dialog safe to open twice.
type fakeControlPlane struct {
	mu        sync.Mutex
	document  string
	saves     int
	lastSave  string
	lastPath  string
	tokenFail int // when set, the OAuth exchange fails with this status
}

func newFakeControlPlane(document string) *fakeControlPlane {
	return &fakeControlPlane{document: document}
}

// factory returns the Options.NewPolicyClient the agent should use. Only the base URL
// is redirected: the tailnet the caller asked for is passed through, so a test can
// still observe which tailnet the agent addressed.
func (c *fakeControlPlane) factory(t *testing.T) func(string, string) *policy.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(srv.Close)
	return func(_, tailnet string) *policy.Client {
		return policy.NewClient(srv.URL, tailnet, srv.Client())
	}
}

func (c *fakeControlPlane) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/v2/oauth/token" {
		if c.tokenFail != 0 {
			http.Error(w, `{"message":"this OAuth client has no policy_file scope"}`, c.tokenFail)
			return
		}
		fmt.Fprint(w, `{"access_token":"tok-abc","token_type":"Bearer","expires_in":3600}`)
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/acl") {
		http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastPath = r.URL.Path
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Type", "application/hujson")
		fmt.Fprint(w, c.document)
	case http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusInternalServerError)
			return
		}
		c.saves++
		c.lastSave = string(body)
		c.document = string(body)
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "unexpected method "+r.Method, http.StatusMethodNotAllowed)
	}
}

func (c *fakeControlPlane) saveCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saves
}

func (c *fakeControlPlane) written() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastSave
}

func (c *fakeControlPlane) addressedPath() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastPath
}

// newBootstrapAgent builds an agent whose ACL bootstrap writes to control rather than
// the real tailnet. A nil control leaves the shipped factory in place.
func newBootstrapAgent(t *testing.T, control *fakeControlPlane, mutate func(*config.TailscaleTunnel)) *Agent {
	t.Helper()
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	rt, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if mutate != nil {
		mutate(runtimeTailnetOf(t, &rt))
	}

	opts := Options{Store: store, Runtime: rt, Getenv: emptyEnv, Logger: quietLogger()}
	if control != nil {
		opts.NewPolicyClient = control.factory(t)
	}
	agent, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return agent
}

// bootstrapRequest carries everything the fake control plane accepts, so each test
// varies only the field it is about.
func bootstrapRequest() httpapi.PolicyBootstrapRequest {
	return httpapi.PolicyBootstrapRequest{
		ClientID:     "client-id",
		ClientSecret: "client-secret-with-policy-file-scope",
		Tailnet:      "example.com",
		Owners:       []string{"autogroup:admin"},
		GrantDsts:    []string{"*"},
	}
}

// The preview is what the dashboard renders before the user commits. Writing during
// one would apply a tailnet-wide ACL change nobody confirmed, and nothing in the app
// can undo it.
func TestPreviewingTheACLBootstrapWritesNothing(t *testing.T) {
	control := newFakeControlPlane(`{"tagOwners":{}}`)
	agent := newBootstrapAgent(t, control, func(ts *config.TailscaleTunnel) {
		ts.Tags = []string{"tag:app-tail"}
	})

	view, err := agent.Policy().Preview(context.Background(), bootstrapRequest())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}

	if !view.Changed {
		t.Error("the preview reported nothing would change, so the dashboard would offer " +
			"no apply button for a policy that needs one")
	}
	if control.saveCount() != 0 {
		t.Errorf("the preview wrote the policy %d times", control.saveCount())
	}
}

// Apply is the write, and its result is what the confirmation dialog renders. Every
// flag drives a separate line, so a swapped pair would tell the user a grant was added
// when only the tag owner was.
func TestApplyingTheACLBootstrapWritesOnceAndReportsWhatItDid(t *testing.T) {
	control := newFakeControlPlane(`{"tagOwners":{}}`)
	agent := newBootstrapAgent(t, control, func(ts *config.TailscaleTunnel) {
		ts.Tags = []string{"tag:app-tail"}
	})

	view, err := agent.Policy().Apply(context.Background(), bootstrapRequest())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if control.saveCount() != 1 {
		t.Fatalf("the policy was written %d times, want exactly 1", control.saveCount())
	}
	if !view.Changed {
		t.Error("Apply wrote the policy but reported nothing changed")
	}
	// Both halves are needed for a node to enroll and then reach anything: the tag
	// owner lets it claim the tag, the grant lets the tagged node carry traffic.
	if !view.AddTagOwner {
		t.Error("AddTagOwner is false over a policy with no tagOwners entry; the dialog " +
			"would not tell the user the tag was claimed")
	}
	if !view.AddGrant {
		t.Error("AddGrant is false despite a requested grant destination")
	}
	if view.Summary == "" {
		t.Error("the confirmation carries no summary, so the dialog renders blank")
	}
	if written := control.written(); !strings.Contains(written, "tag:app-tail") {
		t.Errorf("the written policy does not carry the tag:\n%s", written)
	}
}

// Re-running is the documented safe operation -- the setup dialog offers it every time
// it opens. A second apply reporting another change would have the user believe their
// policy is rewritten on every visit.
func TestRerunningTheBootstrapOverASatisfiedPolicyChangesNothing(t *testing.T) {
	control := newFakeControlPlane(`{"tagOwners":{}}`)
	agent := newBootstrapAgent(t, control, func(ts *config.TailscaleTunnel) {
		ts.Tags = []string{"tag:app-tail"}
	})

	if _, err := agent.Policy().Apply(context.Background(), bootstrapRequest()); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	first := control.saveCount()

	view, err := agent.Policy().Apply(context.Background(), bootstrapRequest())
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	if view.Changed {
		t.Error("re-running reported another change over a policy that already satisfies it")
	}
	if got := control.saveCount(); got != first {
		t.Errorf("the second run wrote the policy again (%d writes, was %d)", got, first)
	}
}

// The configured tags are used when the request names none: that is how the
// dashboard's one-click path calls it, having already taken the tags in the settings
// drawer. Every one of them has to reach the policy, or half the fleet cannot enroll.
func TestTheConfiguredTagsAreUsedWhenTheRequestNamesNone(t *testing.T) {
	control := newFakeControlPlane(`{"tagOwners":{}}`)
	agent := newBootstrapAgent(t, control, func(ts *config.TailscaleTunnel) {
		ts.Tags = []string{"tag:fleet-a", "tag:fleet-b"}
	})

	req := bootstrapRequest()
	req.Tags = nil
	if _, err := agent.Policy().Apply(context.Background(), req); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	written := control.written()
	for _, tag := range []string{"tag:fleet-a", "tag:fleet-b"} {
		if !strings.Contains(written, tag) {
			t.Errorf("the written policy is missing %q; nodes carrying it cannot enroll:\n%s",
				tag, written)
		}
	}
}

// A tag named in the request wins, which is what lets an operator prepare a policy for
// a fleet this machine is not itself part of.
func TestATagNamedInTheRequestOverridesTheConfiguredOnes(t *testing.T) {
	control := newFakeControlPlane(`{"tagOwners":{}}`)
	agent := newBootstrapAgent(t, control, func(ts *config.TailscaleTunnel) {
		ts.Tags = []string{"tag:local-only"}
	})

	req := bootstrapRequest()
	req.Tags = []string{"tag:other-fleet"}
	if _, err := agent.Policy().Apply(context.Background(), req); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	written := control.written()
	if !strings.Contains(written, "tag:other-fleet") {
		t.Errorf("the requested tag was not written:\n%s", written)
	}
	if strings.Contains(written, "tag:local-only") {
		t.Errorf("the local tag was written despite an explicit request:\n%s", written)
	}
}

// A tag the policy planner rejects has to be refused here, naming the field -- the
// alternative is a raw error from the control plane against a dialog with no idea
// which input was wrong.
func TestAnUnusableTagIsRefusedAsAFieldErrorBeforeAnyWrite(t *testing.T) {
	control := newFakeControlPlane(`{"tagOwners":{}}`)
	agent := newBootstrapAgent(t, control, nil)

	req := bootstrapRequest()
	req.Tags = []string{"not-a-tag"}

	_, err := agent.Policy().Apply(context.Background(), req)

	var invalid *config.ValidationError
	if !errors.As(err, &invalid) {
		t.Fatalf("err = %v (%T), want a *config.ValidationError so it maps to 400", err, err)
	}
	if invalid.Field != "tags" {
		t.Errorf("Field = %q, want %q so the dialog highlights the tags input", invalid.Field, "tags")
	}
	if control.saveCount() != 0 {
		t.Error("an unusable tag still reached a write")
	}
}

// One bad tag abandons the whole write. A partial policy would grant some tags and not
// others while the dialog reported neither, and the fleet would half-enroll.
func TestOneUnusableTagAbandonsTheWholeWrite(t *testing.T) {
	control := newFakeControlPlane(`{"tagOwners":{}}`)
	agent := newBootstrapAgent(t, control, nil)

	req := bootstrapRequest()
	req.Tags = []string{"tag:good", "missing-prefix"}

	if _, err := agent.Policy().Apply(context.Background(), req); err == nil {
		t.Fatal("a tag list with an unusable entry was accepted")
	}
	if control.saveCount() != 0 {
		t.Errorf("the policy was written %d times despite the refusal; the tailnet would "+
			"carry half the intended change", control.saveCount())
	}
	if strings.Contains(control.written(), "tag:good") {
		t.Error("the valid tag was written before the invalid one was noticed")
	}
}

// A credential the control plane rejects is the caller's mistake, not a server fault:
// it comes back as a field error the dialog shows inline, and the secret must never
// travel in it -- the error text reaches a browser and a log.
func TestARejectedCredentialIsAFieldErrorThatNeverCarriesTheSecret(t *testing.T) {
	control := newFakeControlPlane(`{"tagOwners":{}}`)
	control.tokenFail = http.StatusUnauthorized
	agent := newBootstrapAgent(t, control, func(ts *config.TailscaleTunnel) {
		ts.Tags = []string{"tag:app-tail"}
	})

	_, err := agent.Policy().Apply(context.Background(), bootstrapRequest())

	var invalid *config.ValidationError
	if !errors.As(err, &invalid) {
		t.Fatalf("err = %v (%T), want a *config.ValidationError", err, err)
	}
	if invalid.Field != "oauthClient" {
		t.Errorf("Field = %q, want %q so the dialog highlights the credential",
			invalid.Field, "oauthClient")
	}
	if !strings.Contains(err.Error(), "policy_file") {
		t.Errorf("err = %v, want the control plane's own reason", err)
	}
	if strings.Contains(err.Error(), "client-secret-with-policy-file-scope") {
		t.Fatalf("the error carries the OAuth secret: %v", err)
	}
	if control.saveCount() != 0 {
		t.Error("a rejected credential still wrote the policy")
	}
}

// The tailnet from the request is the one addressed, because an operator with access
// to several picks which to prepare. Ignoring it would silently write to whichever
// tailnet the credential happens to default to.
func TestTheRequestedTailnetIsTheOneAddressed(t *testing.T) {
	control := newFakeControlPlane(`{"tagOwners":{}}`)
	agent := newBootstrapAgent(t, control, func(ts *config.TailscaleTunnel) {
		ts.Tags = []string{"tag:app-tail"}
	})

	req := bootstrapRequest()
	req.Tailnet = "acme.example.org"
	if _, err := agent.Policy().Preview(context.Background(), req); err != nil {
		t.Fatalf("Preview: %v", err)
	}

	if got := control.addressedPath(); !strings.Contains(got, "acme.example.org") {
		t.Errorf("the bootstrap addressed %q, want the requested tailnet", got)
	}
}

// The agent must build a working policy client when no factory is supplied -- that is
// the shipped path, and a nil default would panic on the first bootstrap a user runs.
func TestTheDefaultPolicyClientPointsAtTheRealControlPlane(t *testing.T) {
	agent := newBootstrapAgent(t, nil, nil)

	client := agent.newPolicyClient(policy.DefaultBaseURL, "example.com")

	if client == nil {
		t.Fatal("the default factory produced no client; the first bootstrap would panic")
	}
	if client.BaseURL != strings.TrimRight(policy.DefaultBaseURL, "/") {
		t.Errorf("BaseURL = %q, want the real control plane %q", client.BaseURL, policy.DefaultBaseURL)
	}
	if client.Tailnet != "example.com" {
		t.Errorf("Tailnet = %q, want the tailnet the caller asked for", client.Tailnet)
	}
}

// The plan view is copied field by field into the confirmation dialog. A swapped or
// dropped flag is invisible in Go -- they are all bools -- and shows up only as a
// dialog describing a change that did not happen.
func TestThePlanViewCarriesEachFlagFromThePlanItReports(t *testing.T) {
	tests := []struct {
		name            string
		document        string
		grantDsts       []string
		wantAddTagOwner bool
		wantAddGrant    bool
		wantChanged     bool
	}{
		{
			name:            "an empty policy needs both halves",
			document:        `{"tagOwners":{}}`,
			grantDsts:       []string{"*"},
			wantAddTagOwner: true,
			wantAddGrant:    true,
			wantChanged:     true,
		},
		{
			name:            "no grant was asked for, so only the tag owner is added",
			document:        `{"tagOwners":{}}`,
			grantDsts:       nil,
			wantAddTagOwner: true,
			wantAddGrant:    false,
			wantChanged:     true,
		},
		{
			name:            "a policy that already owns the tag needs only the grant",
			document:        `{"tagOwners":{"tag:app-tail":["autogroup:admin"]}}`,
			grantDsts:       []string{"*"},
			wantAddTagOwner: false,
			wantAddGrant:    true,
			wantChanged:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control := newFakeControlPlane(tt.document)
			agent := newBootstrapAgent(t, control, func(ts *config.TailscaleTunnel) {
				ts.Tags = []string{"tag:app-tail"}
			})

			req := bootstrapRequest()
			req.GrantDsts = tt.grantDsts

			view, err := agent.Policy().Preview(context.Background(), req)
			if err != nil {
				t.Fatalf("Preview: %v", err)
			}

			if view.AddTagOwner != tt.wantAddTagOwner {
				t.Errorf("AddTagOwner = %v, want %v", view.AddTagOwner, tt.wantAddTagOwner)
			}
			if view.AddGrant != tt.wantAddGrant {
				t.Errorf("AddGrant = %v, want %v", view.AddGrant, tt.wantAddGrant)
			}
			if view.Changed != tt.wantChanged {
				t.Errorf("Changed = %v, want %v", view.Changed, tt.wantChanged)
			}

			// The view reaches the dashboard as JSON; a field added without a tag
			// would silently never arrive.
			encoded, err := json.Marshal(view)
			if err != nil {
				t.Fatalf("the plan view does not encode: %v", err)
			}
			for _, key := range []string{"summary", "addTagOwner", "addGrant", "changed"} {
				if !strings.Contains(string(encoded), `"`+key+`"`) {
					t.Errorf("the encoded view has no %q key: %s", key, encoded)
				}
			}
		})
	}
}
