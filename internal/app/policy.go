// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/policy"
)

// tailscaleControlURL is Tailscale's hosted control plane. An empty ControlURL
// resolves to it inside tsnet, so both forms mean "the Tailscale policy API can
// speak for this tailnet". Anything else is a self-hosted control server (Headscale),
// whose ACLs this API cannot edit.
const tailscaleControlURL = "https://controlplane.tailscale.com"

// policyAPI presents the agent as the management API's ACL bootstrap. The admin
// OAuth credential arrives per request and is used once; it is never stored.
type policyAPI struct{ a *Agent }

var _ httpapi.PolicyAPI = policyAPI{}

// Policy exposes the agent as the management API's ACL bootstrap.
func (a *Agent) Policy() httpapi.PolicyAPI { return policyAPI{a: a} }

// Preview reports what the bootstrap would change without writing anything.
func (pa policyAPI) Preview(ctx context.Context, req httpapi.PolicyBootstrapRequest) (httpapi.PolicyPlanView, error) {
	return pa.run(ctx, req, true)
}

// Apply performs the bootstrap, writing the tagOwners and grant the fleet needs.
func (pa policyAPI) Apply(ctx context.Context, req httpapi.PolicyBootstrapRequest) (httpapi.PolicyPlanView, error) {
	return pa.run(ctx, req, false)
}

func (pa policyAPI) run(ctx context.Context, req httpapi.PolicyBootstrapRequest, dryRun bool) (httpapi.PolicyPlanView, error) {
	// The bootstrap writes the policy of the tailnet this agent's node is on, so its
	// control server and its tags are the ones that decide what can be written and what
	// the tags default to.
	tailnet, err := pa.a.primaryTailnet()
	if err != nil {
		return httpapi.PolicyPlanView{}, err
	}

	// A self-hosted control server manages its own ACL policy; the Tailscale policy
	// API cannot reach it, so the one-click path is unavailable there.
	if url := strings.TrimSpace(tailnet.ControlURL); url != "" && url != tailscaleControlURL {
		return httpapi.PolicyPlanView{}, httpapi.Unavailable("one-click ACL setup",
			"a custom control server is configured; edit its ACL policy directly")
	}

	tags := req.Tags
	if len(tags) == 0 {
		tags = tailnet.Tags
	}
	if len(tags) == 0 {
		return httpapi.PolicyPlanView{}, &config.ValidationError{
			Field: "tags", Message: "no tags are configured, so there is nothing to add to the policy"}
	}

	opts := make([]policy.Options, 0, len(tags))
	for _, tag := range tags {
		o := policy.Options{
			Tag:       tag,
			Owners:    req.Owners,
			GrantDsts: req.GrantDsts,
			GrantIPs:  req.GrantIPs,
		}
		if err := o.Validate(); err != nil {
			return httpapi.PolicyPlanView{}, &config.ValidationError{Field: "tags", Message: err.Error()}
		}
		opts = append(opts, o)
	}

	client := pa.a.newPolicyClient(policy.DefaultBaseURL, req.Tailnet)
	if err := client.Authenticate(ctx, req.ClientID, req.ClientSecret); err != nil {
		// A rejected credential is the caller's mistake, not a server fault: surface it
		// as a 400 the dashboard shows inline. The error text never contains the secret.
		return httpapi.PolicyPlanView{}, &config.ValidationError{Field: "oauthClient", Message: err.Error()}
	}

	mode := "apply"
	if dryRun {
		mode = "preview"
	}
	// Log the operation, never the credential.
	pa.a.logger.Info("tailnet acl bootstrap requested", "mode", mode, "tags", tags)

	result, err := policy.BootstrapAll(ctx, client, opts, dryRun)
	if err != nil {
		return httpapi.PolicyPlanView{}, err
	}
	return httpapi.PolicyPlanView{
		Summary:     result.Plan.Summary(),
		AddTagOwner: result.Plan.AddTagOwner,
		AddGrant:    result.Plan.AddGrant,
		Changed:     result.Changed,
		Notes:       result.Plan.Notes,
	}, nil
}
