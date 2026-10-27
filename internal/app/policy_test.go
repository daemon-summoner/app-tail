// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
)

// newPolicyAgent builds an agent whose effective settings the test can shape before
// exercising the policy facade. The facade's guards run before any network call, so
// these tests never reach the Tailscale API.
func newPolicyAgent(t *testing.T, mutate func(ts *config.TailscaleTunnel)) *Agent {
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
	agent, err := New(Options{Store: store, Runtime: rt, Getenv: emptyEnv, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return agent
}

// A self-hosted control server manages its own ACLs, so the one-click path must
// refuse rather than send the credential to api.tailscale.com for a tailnet it does
// not govern.
func TestPolicyRefusedForACustomControlServer(t *testing.T) {
	agent := newPolicyAgent(t, func(ts *config.TailscaleTunnel) {
		ts.ControlURL = "https://headscale.example.com"
	})
	_, err := agent.Policy().Preview(context.Background(), httpapi.PolicyBootstrapRequest{
		ClientID: "id", ClientSecret: "secret", Tags: []string{"tag:app-tail"},
	})
	if err == nil {
		t.Fatal("Preview proceeded against a custom control server")
	}
	if !strings.Contains(err.Error(), "custom control server") {
		t.Fatalf("error %v does not explain the custom control server", err)
	}
}

// With no tags configured and none supplied, there is nothing to add to the policy;
// the facade must say so as a 400-mapped validation error, not attempt a bootstrap.
func TestPolicyRequiresAtLeastOneTag(t *testing.T) {
	agent := newPolicyAgent(t, func(ts *config.TailscaleTunnel) { ts.Tags = nil })
	_, err := agent.Policy().Preview(context.Background(), httpapi.PolicyBootstrapRequest{
		ClientID: "id", ClientSecret: "secret",
	})
	if err == nil {
		t.Fatal("Preview proceeded with no tags to add")
	}
	var validation *config.ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error %v is not a validation error, so it would not map to 400", err)
	}
	if !strings.Contains(err.Error(), "no tags are configured") {
		t.Fatalf("error %v does not explain the missing tags", err)
	}
}

// The Tailscale control plane (empty or the explicit URL) is allowed through the
// guard; a missing OAuth client id is then reported as a 400-mapped validation error
// rather than a bare network failure. This proves both the allow path and the
// credential-to-400 mapping without a network call.
func TestPolicyAllowsTailscaleControlAndValidatesTheCredential(t *testing.T) {
	cases := []struct {
		name       string
		controlURL string
	}{
		{"default control url", ""},
		{"explicit tailscale control url", "https://controlplane.tailscale.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agent := newPolicyAgent(t, func(ts *config.TailscaleTunnel) { ts.ControlURL = tc.controlURL })
			_, err := agent.Policy().Apply(context.Background(), httpapi.PolicyBootstrapRequest{
				ClientSecret: "secret", Tags: []string{"tag:app-tail"},
			})
			if err == nil {
				t.Fatal("Apply proceeded with no OAuth client id")
			}
			var validation *config.ValidationError
			if !errors.As(err, &validation) {
				t.Fatalf("error %v is not a validation error, so it would not map to 400", err)
			}
			if !strings.Contains(err.Error(), "client id") {
				t.Fatalf("error %v does not name the missing client id", err)
			}
		})
	}
}
