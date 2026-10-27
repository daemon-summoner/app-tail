// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
)

// An agent that is not running is the single most common thing a CLI user hits, so the
// failure has to be recognisable: the caller branches on ErrNoAgent to print "start the
// agent first" instead of a raw dial error, and the address has to be in the message or
// the user cannot tell which agent was missed.
func TestACommandAgainstAStoppedAgentReportsThatNoAgentIsRunning(t *testing.T) {
	// Bind, record the address, then stop: the config carries a real port nothing is
	// listening on, which is exactly what a crashed agent leaves behind.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := strings.TrimPrefix(dead.URL, "http://")
	dead.Close()

	client := NewAuthenticatedClient("http://"+addr, "atk1_"+strings.Repeat("A", 43))

	_, err := client.Status(context.Background())

	if !errors.Is(err, ErrNoAgent) {
		t.Fatalf("err = %v, want it to wrap ErrNoAgent so the CLI can explain the outage", err)
	}
	if !strings.Contains(err.Error(), addr) {
		t.Errorf("err = %v, want it to name the address it tried", err)
	}
}

// Discover is what stops the CLI guessing a port. Each refusal has to name the config
// file, because the fix is always "start the agent" or "point --config elsewhere" and
// the user needs to know which file was consulted.
func TestDiscoverRefusesEveryAddressItCannotDialAndSaysWhy(t *testing.T) {
	tests := []struct {
		name   string
		listen string
		want   string
	}{
		{"never started", "", "start the agent first"},
		{"bound to an OS-assigned port that is not resolved yet", "127.0.0.1:0", "no bound port"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			store, err := config.Open(path)
			if err != nil {
				t.Fatalf("open config: %v", err)
			}
			if tt.listen != "" {
				if _, err := store.Update(func(c *config.Config) error {
					c.Settings.UIListen = tt.listen
					return nil
				}); err != nil {
					t.Fatalf("seed the address: %v", err)
				}
			}

			client, err := Discover(store)

			if err == nil {
				t.Fatalf("Discover returned a client for %q", tt.listen)
			}
			if client != nil {
				t.Error("Discover returned both a client and an error")
			}
			if !errors.Is(err, ErrNoAgent) {
				t.Errorf("err = %v, want it to wrap ErrNoAgent", err)
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("err = %v, want it to name the config file it read", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// A stored address does become a usable client, which is the whole point of the agent
// persisting it. Without this the refusals above would pass against a Discover that
// never succeeds.
func TestDiscoverBuildsAClientForTheAddressTheAgentRecorded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store, err := config.Open(path)
	if err != nil {
		t.Fatalf("open config: %v", err)
	}
	if _, err := store.Update(func(c *config.Config) error {
		c.Settings.UIListen = "127.0.0.1:18377"
		return nil
	}); err != nil {
		t.Fatalf("seed the address: %v", err)
	}
	agentKeys(t, filepath.Dir(path))

	client, err := Discover(store)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if got := client.BaseURL(); got != "http://127.0.0.1:18377" {
		t.Errorf("BaseURL = %q, want the recorded address as an http URL", got)
	}
}

// A config file the CLI cannot read must stop the command rather than fall through to
// a default port. Guessing 8377 under `network_mode: host` would talk to whichever
// other app-tail owns it -- and then toggle its forwards.
func TestAConfigThatCannotBeOpenedStopsTheCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := writeFile(path, "{not json"); err != nil {
		t.Fatalf("seed a broken config: %v", err)
	}

	env := Env{Stdout: &strings.Builder{}, Stderr: &strings.Builder{}, Getenv: func(string) string { return "" }}

	client, err := connect(env, path, dir)

	if err == nil {
		t.Fatal("a broken config still produced a client")
	}
	if client != nil {
		t.Error("connect returned both a client and an error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("err = %v, want it to name the file it could not read", err)
	}
}

// --- error bodies ---------------------------------------------------------

// The agent's own explanation is what makes a CLI failure actionable. Each shape a
// reply can take has to end up as something the user can read: an enveloped message
// verbatim, a proxy's raw page rather than silence, and a bare status when there is
// genuinely nothing else to say.
func TestTheAgentsExplanationSurvivesEveryReplyShape(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		want    string
		notWant string
	}{
		{
			name:   "the agent's own error envelope",
			status: http.StatusConflict,
			body:   `{"error":"a forward already listens on 127.0.0.1:2222"}`,
			want:   "already listens on 127.0.0.1:2222",
			// The envelope message stands alone; prefixing it with the status would
			// read as two errors stacked.
			notWant: "HTTP 409",
		},
		{
			name:   "a proxy's plain-text page",
			status: http.StatusBadGateway,
			body:   "upstream connect error",
			want:   "upstream connect error",
		},
		{
			name:   "an envelope with an empty message falls back to the body",
			status: http.StatusInternalServerError,
			body:   `{"error":""}`,
			want:   "500",
		},
		{
			name:   "no body at all",
			status: http.StatusForbidden,
			body:   "",
			want:   "no explanation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, client := newAgentServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				if _, err := w.Write([]byte(tt.body)); err != nil {
					t.Errorf("write body: %v", err)
				}
			})

			_, err := client.Status(context.Background())

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("err = %v (%T), want an *APIError carrying the status", err, err)
			}
			if apiErr.Status != tt.status {
				t.Errorf("Status = %d, want %d", apiErr.Status, tt.status)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %q, want it to contain %q", err, tt.want)
			}
			if tt.notWant != "" && strings.Contains(err.Error(), tt.notWant) {
				t.Errorf("err = %q, want it not to contain %q", err, tt.notWant)
			}
		})
	}
}

// An unbounded error body would bury the shell prompt under a stack trace or an HTML
// page. It has to be cut, and say that it was cut, or a truncated message reads as a
// complete one.
func TestAnEnormousErrorBodyIsTrimmedAndSaysSo(t *testing.T) {
	huge := strings.Repeat("stack frame ", 500)
	_, client := newAgentServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte(huge)); err != nil {
			t.Errorf("write body: %v", err)
		}
	})

	_, err := client.Status(context.Background())

	if err == nil {
		t.Fatal("a 500 was reported as success")
	}
	if len(err.Error()) > 400 {
		t.Errorf("a %d-byte body produced a %d-byte message; the terminal has to stay readable",
			len(huge), len(err.Error()))
	}
	if !strings.Contains(err.Error(), "...") {
		t.Error("the truncated body does not say it was cut, so it reads as the whole story")
	}
}

// A 2xx carrying something that is not the expected document has to fail rather than
// decode into a zero value. Silently reporting an empty status would show the node as
// stopped when the agent is answering fine and the CLI is simply out of date.
func TestASuccessCarryingAnUndecodableBodyIsReported(t *testing.T) {
	_, client := newAgentServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte("<html>not json</html>")); err != nil {
			t.Errorf("write body: %v", err)
		}
	})

	_, err := client.Status(context.Background())

	if err == nil {
		t.Fatal("an undecodable 200 was accepted as a status")
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("err = %v, want it to say the reply could not be decoded", err)
	}
}

// A cancelled context has to stop the request. Without it a hung agent would hold the
// CLI -- and any healthcheck wrapping it -- until the request timeout, long after the
// caller gave up.
func TestACancelledCommandStopsWaitingOnTheAgent(t *testing.T) {
	release := make(chan struct{})
	keys, token := agentKeys(t, t.TempDir())
	srv := httptest.NewServer(answerHello(t, keys, token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})))
	client := NewAuthenticatedClient(srv.URL, token)
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.Status(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want it to carry the cancellation", err)
	}
}

// The record beside the config is where the agent actually is; the setting is where it was
// asked to be. A CLI that preferred the setting would talk to whatever holds that port
// while the agent runs on the one the system assigned it.
func TestDiscoverPrefersWhereTheAgentIsOverWhereItWasAskedToBe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store, err := config.Open(path)
	if err != nil {
		t.Fatalf("open config: %v", err)
	}
	if _, err := store.Update(func(c *config.Config) error {
		c.Settings.UIListen = "127.0.0.1:18377"
		return nil
	}); err != nil {
		t.Fatalf("seed the configured address: %v", err)
	}
	if err := config.WriteDashboardAddr(path, "127.0.0.1:19999"); err != nil {
		t.Fatalf("record where the agent bound: %v", err)
	}
	agentKeys(t, filepath.Dir(path))

	client, err := Discover(store)

	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if got := client.BaseURL(); got != "http://127.0.0.1:19999" {
		t.Errorf("BaseURL = %q, want the port the agent is on rather than the one it asked for", got)
	}
}
