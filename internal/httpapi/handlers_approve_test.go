// SPDX-License-Identifier: MIT

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/tsnode"
)

type fakeApprovals struct {
	pending  *ApprovalsView
	after    ApprovalsView
	err      error
	approved int
}

func (f *fakeApprovals) Pending() *ApprovalsView { return f.pending }

func (f *fakeApprovals) Approve(context.Context) (ApprovalsView, error) {
	f.approved++
	return f.after, f.err
}

var waitingRoute = ApprovalsView{
	Needs: []grants.PendingNeed{{
		Need:     grants.Need{Kind: grants.KindRoute, Value: "203.0.113.0/24", Reason: "send 203.0.113.0/24 through app-tail"},
		Features: []grants.Feature{grants.FeatureInterface},
	}},
	Command: "sudo app-tail tun grant --route=203.0.113.0/24",
}

func approvalsServer(f *fakeApprovals) *Server {
	return New(Options{Auth: testKeys, Deps: Deps{
		Node:      &fakeNode{status: tsnode.Status{BackendState: tsnode.StateRunning}},
		Approvals: f,
	}})
}

func serve(s *Server, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newAPIRequest(method, target, nil))
	return rec
}

// Every page polls the status, and the refusals come from several features at once, so the
// status is where the dashboard learns there is something to approve.
func TestTheStatusSaysWhatIsWaitingForAnAdministrator(t *testing.T) {
	waiting := waitingRoute
	rec := serve(approvalsServer(&fakeApprovals{pending: &waiting}), http.MethodGet, "/api/status")
	requireStatus(t, rec, http.StatusOK)

	got := decode[StatusView](t, rec)
	if got.Approvals == nil || len(got.Approvals.Needs) != 1 {
		t.Fatalf("approvals = %+v, want the one waiting route", got.Approvals)
	}
	need := got.Approvals.Needs[0]
	if need.Kind != grants.KindRoute || need.Reason == "" || len(need.Features) != 1 || need.Features[0] != grants.FeatureInterface {
		t.Errorf("the waiting approval reads %+v, want its kind, reason and the feature that asked", need)
	}
	if got.Approvals.Command != waitingRoute.Command {
		t.Errorf("command = %q, want %q", got.Approvals.Command, waitingRoute.Command)
	}
}

func TestTheStatusLeavesApprovalsOutWhenNothingIsWaiting(t *testing.T) {
	rec := serve(approvalsServer(&fakeApprovals{}), http.MethodGet, "/api/status")
	requireStatus(t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), `"approvals"`) {
		t.Errorf("the status names approvals with nothing waiting: %s", rec.Body)
	}
}

func TestApprovingAnswersWithWhatIsStillWaitingAfterTheRetry(t *testing.T) {
	f := &fakeApprovals{after: ApprovalsView{Needs: []grants.PendingNeed{}}}
	rec := serve(approvalsServer(f), http.MethodPost, "/api/tun/approve")
	requireStatus(t, rec, http.StatusOK)

	if f.approved != 1 {
		t.Errorf("the approval ran %d times, want once", f.approved)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"needs":[],"command":""}` {
		t.Errorf("body = %s, want an empty list a client can read without a nil check", body)
	}
}

// A dismissed prompt is an answer the person gave, and the dashboard says so differently from
// a failure: it can be asked again, and nothing is broken.
func TestADismissedApprovalPromptIsAConflictNotAFailure(t *testing.T) {
	rec := serve(approvalsServer(&fakeApprovals{err: ErrApprovalDeclined}), http.MethodPost, "/api/tun/approve")
	body := requireError(t, rec, http.StatusConflict, "dismissed")
	if body.Ref != "" {
		t.Errorf("a dismissed prompt carries log reference %q, as if it were a fault", body.Ref)
	}
}

// Where app-tail cannot raise the prompt, the answer is the command to run instead.
func TestAMachineThatCannotAskForApprovalAnswersWithTheCommandToRun(t *testing.T) {
	byHand := ApprovalByHand(errors.New("run `sudo app-tail tun grant --route=203.0.113.0/24` in a terminal"))
	rec := serve(approvalsServer(&fakeApprovals{err: byHand}), http.MethodPost, "/api/tun/approve")
	body := requireError(t, rec, http.StatusNotImplemented, "sudo app-tail tun grant --route=203.0.113.0/24")
	if body.Ref != "" {
		t.Errorf("the command to run carries log reference %q, as if it were a fault", body.Ref)
	}
}

func TestAnApprovalThatFailedOtherwiseIsAServerError(t *testing.T) {
	rec := serve(approvalsServer(&fakeApprovals{err: errors.New("osascript could not start")}), http.MethodPost, "/api/tun/approve")
	requireError(t, rec, http.StatusInternalServerError, "osascript")
}

// The route raises an administrator prompt, so a page on another site must not reach it.
func TestApprovingRejectsACrossOriginRequest(t *testing.T) {
	f := &fakeApprovals{}
	req := newAPIRequest(http.MethodPost, "/api/tun/approve", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	approvalsServer(f).Handler().ServeHTTP(rec, req)

	if rec.Code == http.StatusOK || f.approved != 0 {
		t.Errorf("a cross-origin request reached the approval: status %d, %d prompts", rec.Code, f.approved)
	}
}
