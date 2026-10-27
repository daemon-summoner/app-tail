// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func healthRoute(status int, body string) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"GET /healthz": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			if _, err := w.Write([]byte(body)); err != nil {
				panic(err)
			}
		},
	}
}

// A healthcheck that prints the problem and still exits 0 is worse than none: the
// orchestrator restarting the container is the entire point of the command.
func TestHealthFailsWhenTheAgentIsNotReady(t *testing.T) {
	h := newHarness(t, healthRoute(http.StatusServiceUnavailable,
		`{"status":"unhealthy","backendState":"NeedsLogin","reason":"tailnet node is not running"}`))

	err := h.run("health")
	if err == nil {
		t.Fatal("health reported success while the agent was unhealthy")
	}
	// The reason is the only thing that tells an operator what to fix.
	if !strings.Contains(err.Error(), "tailnet node is not running") {
		t.Errorf("error %q does not carry the agent's reason", err)
	}
	if !strings.Contains(err.Error(), "NeedsLogin") {
		t.Errorf("error %q does not carry the backend state", err)
	}
}

func TestHealthSucceedsWhenTheAgentIsReady(t *testing.T) {
	h := newHarness(t, healthRoute(http.StatusOK, `{"status":"ok","backendState":"Running"}`))

	if err := h.run("health"); err != nil {
		t.Fatalf("health on a healthy agent: %v", err)
	}
	if out := h.stdout.String(); !strings.Contains(out, "healthy") {
		t.Errorf("stdout = %q, want it to say healthy", out)
	}
}

// --json exists for machine consumers, which read the body; they must not have to
// choose between parsing the reply and getting a usable exit code.
func TestHealthJSONStillExitsNonZeroWhenUnhealthy(t *testing.T) {
	h := newHarness(t, healthRoute(http.StatusServiceUnavailable,
		`{"status":"unhealthy","reason":"one or more enabled forwards are not listening"}`))

	err := h.run("health", "--json")
	if err == nil {
		t.Fatal("health --json reported success while the agent was unhealthy")
	}
	if out := h.stdout.String(); !strings.Contains(out, "not listening") {
		t.Errorf("stdout = %q, want the JSON body on stdout", out)
	}
}

// A wedged agent answering 500 is not the same as an agent confidently reporting
// itself unhealthy, and collapsing the two would hide a broken deployment.
func TestHealthTreatsAnUnexpectedStatusAsAnError(t *testing.T) {
	h := newHarness(t, healthRoute(http.StatusInternalServerError, `{"error":"boom"}`))

	err := h.run("health")
	if err == nil {
		t.Fatal("health accepted an unexpected status as an answer")
	}
	if strings.Contains(err.Error(), "unhealthy:") {
		t.Errorf("error %q reads as a health verdict rather than a failed call", err)
	}
}

func TestHealthAsksTheHealthzEndpoint(t *testing.T) {
	h := newHarness(t, healthRoute(http.StatusOK, `{"status":"ok"}`))
	if err := h.run("health"); err != nil {
		t.Fatalf("health: %v", err)
	}
	got := h.recorded()
	if len(got) != 1 || got[0].Method != http.MethodGet || got[0].Path != "/healthz" {
		t.Fatalf("requests = %+v, want one GET /healthz", got)
	}
}

// The healthy --json path is the one an orchestrator's readiness probe takes every
// few seconds. Returning the reason unconditionally there -- an easy inversion given
// the branch structure -- would report a working agent as failing forever.
func TestHealthJSONExitsZeroWhenHealthy(t *testing.T) {
	h := newHarness(t, healthRoute(http.StatusOK, `{"status":"ok","backendState":"Running"}`))

	if err := h.run("health", "--json"); err != nil {
		t.Fatalf("health --json on a healthy agent: %v", err)
	}
	out := h.stdout.String()
	if !strings.Contains(out, `"status"`) {
		t.Errorf("stdout = %q, want the JSON body", out)
	}
	if !strings.Contains(out, "Running") {
		t.Errorf("stdout = %q, want the backend state in the body", out)
	}
}

// An agent that reports itself unhealthy without saying why still has to produce a
// message an operator can act on, rather than a bare "unhealthy:" with nothing after
// the colon.
func TestHealthSaysSomethingWhenTheAgentGivesNoReason(t *testing.T) {
	h := newHarness(t, healthRoute(http.StatusServiceUnavailable, `{"status":"unhealthy"}`))

	err := h.run("health")
	if err == nil {
		t.Fatal("health reported success while the agent was unhealthy")
	}
	if strings.TrimSpace(strings.TrimPrefix(err.Error(), "unhealthy:")) == "" {
		t.Errorf("error %q says only that it is unhealthy", err)
	}
}

// A dead agent is the case a container healthcheck hits first, and it must not read
// as a health verdict: "unhealthy" invites the operator to look at the tailnet, while
// the truth is that nothing answered at all.
func TestHealthReportsAnUnreachableAgentAsAFailedCall(t *testing.T) {
	h := newHarness(t, healthRoute(http.StatusOK, `{"status":"ok"}`))
	// The config still records the address; the listener behind it is gone. That is
	// exactly a crashed agent whose config file outlived it.
	h.server.Close()

	err := h.run("health")
	if err == nil {
		t.Fatal("health succeeded against an agent that was not listening")
	}
	if !errors.Is(err, ErrNoAgent) {
		t.Errorf("error %q does not wrap ErrNoAgent, so callers cannot tell it apart", err)
	}
	if strings.Contains(err.Error(), "unhealthy:") {
		t.Errorf("error %q reads as a health verdict rather than an unreachable agent", err)
	}
}

// A body that is not JSON means the CLI is talking to something that is not this
// agent -- a different service on a reused port, or a proxy's error page. Reporting
// that as a decode failure is what stops it being read as a real health answer.
func TestHealthRefusesABodyItCannotDecode(t *testing.T) {
	h := newHarness(t, healthRoute(http.StatusOK, "<html>not this agent</html>"))

	err := h.run("health")
	if err == nil {
		t.Fatal("health accepted a non-JSON body as an answer")
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("error %q does not say the reply could not be decoded", err)
	}
}

// Flag and argument mistakes have to fail before the command reaches the network,
// or a typo becomes a healthcheck that silently probes the wrong thing.
func TestHealthRejectsBadInvocations(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"an unknown flag", []string{"health", "--jsonn"}},
		{"a positional argument", []string{"health", "extra"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, healthRoute(http.StatusOK, `{"status":"ok"}`))
			args := append(append([]string{tt.args[0]}, h.cfg()...), tt.args[1:]...)
			if err := h.exec(args...); err == nil {
				t.Fatal("health accepted the invocation")
			}
			if got := h.recorded(); len(got) != 0 {
				t.Errorf("health made %d request(s) despite a bad invocation: %+v", len(got), got)
			}
		})
	}
}

// health is what a container healthcheck runs, so an agent it cannot even locate
// must exit non-zero rather than fall back to probing a default port -- under
// network_mode: host that default belongs to whichever app-tail owns 8377.
func TestHealthFailsWhenNoAgentAddressIsRecorded(t *testing.T) {
	h := newHarness(t, healthRoute(http.StatusOK, `{"status":"ok"}`))
	fresh := filepath.Join(t.TempDir(), "config.json")

	err := h.exec("health", "--config", fresh)
	if err == nil {
		t.Fatal("health succeeded with no recorded agent address")
	}
	if !errors.Is(err, ErrNoAgent) {
		t.Errorf("error %q does not wrap ErrNoAgent", err)
	}
	if got := h.recorded(); len(got) != 0 {
		t.Errorf("health reached an agent it should not have found: %+v", got)
	}
}

// The --json path writes the body before deciding the exit code. A write that fails
// -- a closed pipe, the usual `app-tail health --json | head` -- must surface, not be
// discarded in favour of reporting on the health verdict alone.
func TestHealthJSONReportsAFailedWrite(t *testing.T) {
	h := newHarness(t, healthRoute(http.StatusOK, `{"status":"ok","backendState":"Running"}`))
	env := h.env()
	env.Stdout = brokenWriter{}

	args := append([]string{"health"}, h.cfg()...)
	err := Run(context.Background(), append(args, "--json"), env)
	if err == nil {
		t.Fatal("health --json reported success after its output could not be written")
	}
	if !strings.Contains(err.Error(), "broken pipe") {
		t.Errorf("error %q does not carry the write failure", err)
	}
}

// brokenWriter is a stdout that always fails, standing in for a closed pipe.
type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// NewClient takes a base URL without validating it. A URL that cannot be turned into
// a request has to surface as an error from the call, because the alternative is a
// nil request reaching the transport.
func TestHealthReportsABaseURLItCannotBuildARequestFrom(t *testing.T) {
	// A DEL byte is not permitted in a URL, so request construction fails before
	// anything is dialled.
	_, err := NewClient("http://127.0.0.1:8377/\x7f").Health(context.Background())
	if err == nil {
		t.Fatal("Health succeeded against an unusable base URL")
	}
	if !strings.Contains(err.Error(), "build the request") {
		t.Errorf("error %q does not say the request could not be built", err)
	}
}

// A reply that is cut off mid-body is not a health verdict. Reading it as one would
// mean a truncated 200 decodes to the zero HealthView and reports a state the agent
// never claimed.
func TestHealthReportsATruncatedReply(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /healthz": func(w http.ResponseWriter, _ *http.Request) {
			// Promising far more than is written makes the server close the connection
			// short, which the client sees as an unexpected EOF while reading.
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", "4096")
			if _, err := w.Write([]byte(`{"status":"ok"`)); err != nil {
				return
			}
		},
	})

	err := h.run("health")
	if err == nil {
		t.Fatal("health accepted a truncated reply as an answer")
	}
	if strings.Contains(err.Error(), "unhealthy:") {
		t.Errorf("error %q reads as a health verdict rather than a failed read", err)
	}
}
