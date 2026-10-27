// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/fabric"
	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// recordingApprover stands in for the administrator prompt, which a suite must never raise.
type recordingApprover struct {
	mu     sync.Mutex
	asked  [][]grants.Need
	answer error
}

func (r *recordingApprover) approve(_ context.Context, _ func(string, ...any), needs []grants.Need) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asked = append(r.asked, slices.Clone(needs))
	return r.answer
}

func (r *recordingApprover) prompts() [][]grants.Need {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.asked)
}

var labServer = grants.Need{
	Kind: grants.KindOpenVPNRemote, Value: "vpn.example.com:1194", CASHA256: []string{"aa"},
	Reason: "start an OpenVPN connection to vpn.example.com:1194, a server nobody has approved",
}

func approvalsHarness(t *testing.T, approver *recordingApprover) *harness {
	t.Helper()
	return newHarnessWith(t, seedOpenVPN(nil), func(o *Options) {
		o.ApproveGrants = approver.approve
		o.LoadGrants = func() (grants.Document, error) { return grants.None(), nil }
	})
}

func approve(t *testing.T, h *harness) (int, string) {
	t.Helper()
	resp, body := h.request(http.MethodPost, "/api/tun/approve", nil)
	return resp.StatusCode, string(body)
}

// The prompt approves the agent's own list -- what the privileged side refused for the features
// still switched on -- and then the refused connection is tried again rather than left to wait
// out its back-off.
func TestApprovingAsksForWhatWasRefusedAndTriesTheConnectionAgain(t *testing.T) {
	approver := &recordingApprover{}
	h := approvalsHarness(t, approver)
	waitFor(t, 5*time.Second, "the connection to start", func() bool {
		return len(h.openvpns.connectionsFor(ovpnTunnelID)) == 1
	})
	h.agent.pending.Refused(grants.Source{Feature: grants.OpenVPNFeature(ovpnTunnelID), Change: "run-openvpn"},
		[]grants.Need{labServer})
	// A connection that no longer exists asks for nothing, so its refusal is not put in front of
	// the administrator.
	h.agent.pending.Refused(grants.Source{Feature: grants.OpenVPNFeature("tn_removed"), Change: "run-openvpn"},
		[]grants.Need{{Kind: grants.KindFullTunnel, Reason: "carry all of this machine's internet traffic"}})

	status, body := approve(t, h)
	if status != http.StatusOK {
		t.Fatalf("approve = %d %s, want 200", status, body)
	}
	prompts := approver.prompts()
	if len(prompts) != 1 {
		t.Fatalf("the prompt was raised %d times, want once", len(prompts))
	}
	if len(prompts[0]) != 1 || prompts[0][0].Kind != labServer.Kind || prompts[0][0].Value != labServer.Value ||
		!slices.Equal(prompts[0][0].CASHA256, labServer.CASHA256) {
		t.Errorf("the prompt asked for %+v, want only the refused server", prompts[0])
	}
	waitFor(t, 5*time.Second, "the refused connection to be built again", func() bool {
		return len(h.openvpns.connectionsFor(ovpnTunnelID)) >= 2
	})
	var view httpapi.ApprovalsView
	if err := json.Unmarshal([]byte(body), &view); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if view.Needs == nil {
		t.Errorf("body = %s, want a list a client can read without a nil check", body)
	}
}

// Nothing waiting is no prompt: an administrator dialog with nothing in it is a password
// asked for no reason.
func TestApprovingWithNothingWaitingRaisesNoPrompt(t *testing.T) {
	approver := &recordingApprover{}
	h := approvalsHarness(t, approver)

	status, body := approve(t, h)
	if status != http.StatusOK || strings.TrimSpace(body) != `{"needs":[],"command":""}` {
		t.Errorf("approve = %d %s, want 200 and nothing waiting", status, body)
	}
	if n := len(approver.prompts()); n != 0 {
		t.Errorf("the prompt was raised %d times with nothing to approve", n)
	}
}

// A dismissed prompt is a distinct, readable answer, and the refusal stays listed so the person
// can ask again.
func TestADismissedPromptIsAConflictAndTheRefusalStaysListed(t *testing.T) {
	approver := &recordingApprover{answer: tsnode.ErrDeclined}
	h := approvalsHarness(t, approver)
	h.agent.pending.Refused(grants.Source{Feature: grants.OpenVPNFeature(ovpnTunnelID), Change: "run-openvpn"},
		[]grants.Need{labServer})

	status, body := approve(t, h)
	if status != http.StatusConflict || !strings.Contains(body, "dismissed") {
		t.Errorf("approve = %d %s, want 409 saying the prompt was dismissed", status, body)
	}
	if h.agent.approvalsView() == nil {
		t.Error("the refusal was forgotten when the prompt was dismissed")
	}
}

// Where app-tail cannot raise the prompt, the answer names the command to run instead.
func TestAMachineWithoutAPromptAnswersWithTheCommand(t *testing.T) {
	command := grants.CommandLine("linux", []grants.Need{labServer})
	approver := &recordingApprover{answer: fmt.Errorf("%w: run `%s` in a terminal", tsnode.ErrApproveByHand, command)}
	h := approvalsHarness(t, approver)
	h.agent.pending.Refused(grants.Source{Feature: grants.OpenVPNFeature(ovpnTunnelID), Change: "run-openvpn"},
		[]grants.Need{labServer})

	status, body := approve(t, h)
	if status != http.StatusNotImplemented || !strings.Contains(body, "tun grant") {
		t.Errorf("approve = %d %s, want 501 naming the command", status, body)
	}
}

// The status every page polls carries the list and the command, and nothing when nothing waits.
func TestTheStatusCarriesWhatIsWaitingForAnAdministrator(t *testing.T) {
	h := approvalsHarness(t, &recordingApprover{})
	if _, body := h.get("/api/status"); strings.Contains(string(body), `"approvals"`) {
		t.Fatalf("status names approvals with nothing waiting: %s", body)
	}
	h.agent.pending.Refused(grants.Source{Feature: grants.OpenVPNFeature(ovpnTunnelID), Change: "run-openvpn"},
		[]grants.Need{labServer})

	_, body := h.get("/api/status")
	var status httpapi.StatusView
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if status.Approvals == nil || len(status.Approvals.Needs) != 1 || !strings.Contains(status.Approvals.Command, "tun grant") {
		t.Errorf("approvals = %+v, want the refused server and the command that approves it", status.Approvals)
	}
}

// A refusal is only listed if the session that heard it reports into the agent's list, so the
// node's interface and the shared interface are both handed that list when they are built.
func TestTheNodeAndTheSharedInterfaceReportRefusalsIntoTheAgentsList(t *testing.T) {
	var mu sync.Mutex
	var nodeObservers, fabricObservers []grants.Observer
	h := newHarnessWith(t, nil, func(o *Options) {
		build := o.NewNode
		o.NewNode = func(opts tsnode.Options) NodeController {
			mu.Lock()
			nodeObservers = append(nodeObservers, opts.Grants)
			mu.Unlock()
			return build(opts)
		}
		o.OpenFabric = func(_ context.Context, opts fabric.LiveOptions) (fabricLive, error) {
			mu.Lock()
			fabricObservers = append(fabricObservers, opts.Grants)
			mu.Unlock()
			return nil, errors.New("not opened in a test")
		}
	})
	if _, err := h.agent.openFabric(context.Background(), fabric.LiveOptions{}); err == nil {
		t.Fatal("the substituted interface opened")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(nodeObservers) == 0 || len(fabricObservers) != 1 {
		t.Fatalf("built %d nodes and %d interfaces, want at least one of each", len(nodeObservers), len(fabricObservers))
	}
	for i, got := range append(nodeObservers, fabricObservers...) {
		if got != grants.Observer(h.agent.pending) {
			t.Errorf("session %d reports refusals to %v, want the agent's own list", i, got)
		}
	}
}

// A feature that is switched off asks for nothing, so what it was refused leaves the list
// before the prompt is built; a feature still on keeps its refusal, and one this build does
// not name is kept where somebody can see it.
func TestOnlyFeaturesStillOnKeepTheirRefusalsListed(t *testing.T) {
	h := approvalsHarness(t, &recordingApprover{})
	need := func(value string) []grants.Need {
		return []grants.Need{{Kind: grants.KindRoute, Value: value, Reason: "send " + value + " through app-tail"}}
	}
	refusals := map[grants.Feature]string{
		grants.FeatureInterface:              "203.0.113.0/26",
		grants.FeatureFabric:                 "203.0.113.64/26",
		grants.FeatureSystemDNS:              "203.0.113.128/26",
		grants.FeatureTLSInterception:        "203.0.113.192/26",
		grants.OpenVPNFeature("tn_removed"):  "198.51.100.0/26",
		grants.OpenVPNFeature(ovpnTunnelID):  "198.51.100.64/26",
		grants.Feature("a-later-builds-one"): "198.51.100.128/26",
	}
	for feature, value := range refusals {
		h.agent.pending.Refused(grants.Source{Feature: feature, Change: "set-routes"}, need(value))
	}

	h.agent.prunePendingApprovals()

	var left []string
	for _, w := range h.agent.pending.Needs() {
		left = append(left, w.Value)
	}
	slices.Sort(left)
	want := []string{"198.51.100.128/26", "198.51.100.64/26"}
	if !slices.Equal(left, want) {
		t.Errorf("left waiting %v, want only the enabled connection's and the unnamed feature's %v", left, want)
	}
}
