// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"runtime"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// The privileged side refuses a change an administrator has not approved and names what is
// missing. Those refusals are heard where the requests are made -- the client every session
// to the helper goes through -- and kept in a.pending by the change that was refused, so the
// dashboard can list them and one prompt can approve them all. Traffic interception is the one
// change decided on this side, in ipsInterceptTarget, and it reports into the same list.

// tlsInterceptionSource is the one change approved on this side of the helper rather than by it.
var tlsInterceptionSource = grants.Source{Feature: grants.FeatureTLSInterception, Change: "intercept"}

// loadMachineGrants reads this machine's approvals file.
func loadMachineGrants() (grants.Document, error) {
	path, err := grants.Path()
	if err != nil {
		return grants.Document{}, err
	}
	return grants.Load(path)
}

// prunePendingApprovals drops what a switched-off feature was waiting for. A feature that is
// off asks for nothing, so an approval it was refused is no longer one anybody needs; left in
// the list it would put a change in front of the administrator that nothing will make.
func (a *Agent) prunePendingApprovals() {
	s := a.settings()
	openvpn := make(map[string]bool)
	for _, t := range a.runtimeTunnels() {
		if t.Enabled && t.Type == config.TunnelOpenVPN {
			openvpn[t.ID] = true
		}
	}
	intercepting := false
	if target, err := a.ipsInterceptSettings(); err == nil {
		intercepting = target.on
	}
	a.pending.Retain(func(f grants.Feature) bool {
		if id, ok := f.OpenVPNID(); ok {
			return openvpn[id]
		}
		switch f {
		case grants.FeatureInterface:
			return s.TunSelected()
		case grants.FeatureFabric:
			return s.FabricSelected()
		case grants.FeatureSystemDNS:
			return dnsprofiles.OverrideWanted(s)
		case grants.FeatureTLSInterception:
			return intercepting
		}
		// A feature this build does not name came from a refusal this build reported, so it is
		// kept where somebody can see it rather than dropped unexplained.
		return true
	})
}

// approvalsView is what is waiting, or nil when nothing is.
func (a *Agent) approvalsView() *httpapi.ApprovalsView {
	waiting := a.pending.Needs()
	if len(waiting) == 0 {
		return nil
	}
	return &httpapi.ApprovalsView{Needs: waiting, Command: grants.CommandLine(runtime.GOOS, needsOf(waiting))}
}

func needsOf(waiting []grants.PendingNeed) []grants.Need {
	out := make([]grants.Need, len(waiting))
	for i, w := range waiting {
		out[i] = w.Need
	}
	return out
}

// ApproveNetworkChanges asks an administrator to approve every change this machine is waiting
// on, then tries each refused feature again and answers with what is still waiting.
//
// The list approved is this agent's own, read here: the prompt describes exactly the changes
// this machine asked for, and nothing a caller says can add to it.
func (a *Agent) ApproveNetworkChanges(ctx context.Context) (httpapi.ApprovalsView, error) {
	a.prunePendingApprovals()
	waiting := a.pending.Needs()
	if len(waiting) == 0 {
		return httpapi.ApprovalsView{Needs: []grants.PendingNeed{}}, nil
	}
	// Bounded like the setup prompt, and for its reason: this is answered over HTTP, and a
	// prompt left sitting would outlast the server's write timeout.
	askCtx, cancel := context.WithTimeout(ctx, interfaceSetupTimeout)
	err := a.approveGrants(askCtx, a.hostLogf, needsOf(waiting))
	cancel()
	switch {
	case errors.Is(err, tsnode.ErrDeclined):
		return httpapi.ApprovalsView{}, httpapi.ErrApprovalDeclined
	case errors.Is(err, tsnode.ErrApproveByHand):
		return httpapi.ApprovalsView{}, httpapi.ApprovalByHand(err)
	case err != nil:
		return httpapi.ApprovalsView{}, err
	}
	a.logger.Info("an administrator approved the network changes app-tail was waiting on", "changes", len(waiting))

	if err := a.retryApproved(ctx, waiting); err != nil {
		return httpapi.ApprovalsView{}, err
	}
	view := httpapi.ApprovalsView{Needs: []grants.PendingNeed{}}
	if now := a.approvalsView(); now != nil {
		view = *now
	}
	return view, nil
}

// retryApproved tries again each feature that was waiting. Most retry by themselves on the
// next pass -- the resolver and the shared interface keep trying a change that was refused, and
// interception reads the approvals every pass -- but two do not: an OpenVPN connection that
// failed to start waits out its back-off, and the interface's routes were refused inside the
// node's network engine, which does not send them again until something about them changes.
func (a *Agent) retryApproved(ctx context.Context, waiting []grants.PendingNeed) error {
	rebuild := false
	for _, w := range waiting {
		for _, f := range w.Features {
			if id, ok := f.OpenVPNID(); ok {
				a.askRetry(id)
			}
			if f == grants.FeatureInterface {
				rebuild = true
			}
		}
	}
	if rebuild && a.settings().TunSelected() {
		if err := a.RestartNode(ctx); err != nil {
			return err
		}
	}
	a.reconcileNow(ctx)
	return nil
}

// Approvals is the agent as the approvals dependency the API and the tray share.
func (a *Agent) Approvals() httpapi.Approvals { return approvalsAPI{a: a} }

// approvalsAPI is the agent as the API's approvals dependency.
type approvalsAPI struct{ a *Agent }

func (p approvalsAPI) Pending() *httpapi.ApprovalsView { return p.a.approvalsView() }

func (p approvalsAPI) Approve(ctx context.Context) (httpapi.ApprovalsView, error) {
	return p.a.ApproveNetworkChanges(ctx)
}
