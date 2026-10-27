// SPDX-License-Identifier: MIT

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
)

// proxyCommands is every proxy-facing command, in the shape the argument checks need:
// the location flag has to sit after the subcommand and before any terminating --.
var proxyCommands = []struct {
	name    string
	command []string
	rest    []string
}{
	{name: "proxy status", command: []string{"proxy", "status"}},
	{name: "proxy system", command: []string{"proxy", "system"}},
	{name: "proxy probe", command: []string{"proxy", "probe"}, rest: []string{"peer:22"}},
	{name: "proxy connect", command: []string{"proxy", "connect"}, rest: []string{"peer", "22"}},
	{name: "exec", command: []string{"exec"}, rest: []string{"--", "true"}},
}

// A mistyped flag is a mistake in the command, and running anyway would act on a default
// the user believed they had overridden -- reading the wrong agent, or printing the human
// form to something parsing JSON.
func TestEveryProxyCommandRefusesAFlagItDoesNotKnow(t *testing.T) {
	for _, tc := range proxyCommands {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, proxyRoutes(t, listeningView("127.0.0.1:1080")))

			err := Run(t.Context(), invocation(tc.command, h.cfg(), []string{"--not-a-flag"}, tc.rest), h.env())

			if !errors.Is(err, ErrUsage) {
				t.Errorf("err = %v, want a usage error rather than the command running", err)
			}
		})
	}
}

// An extra word is usually a quoting mistake -- a destination that lost its quotes, a
// stray argument from a shell loop. Ignoring it would act on the first one silently.
func TestTheProxyCommandsThatTakeNoArgumentsRefuseOne(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command []string
	}{
		{name: "proxy status", command: []string{"proxy", "status"}},
		{name: "proxy system", command: []string{"proxy", "system"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, proxyRoutes(t, listeningView("127.0.0.1:1080")))

			err := Run(t.Context(), invocation(tc.command, h.cfg(), []string{"unexpected"}), h.env())

			if !errors.Is(err, ErrUsage) {
				t.Errorf("err = %v, want a usage error naming the extra argument", err)
			}
		})
	}
}

// Where the agent is gets typed last: a command is written as the thing to do and only
// then aimed at a particular agent, and an `ssh ProxyCommand` line puts %h %p directly
// after the subcommand with nowhere earlier to put a flag. A flag read only when it
// comes first would be taken for one of those arguments -- reported as a miscount of
// them, and with the right count reached instead by acting on the default agent.
func TestTheProxyCommandsReadWhereTheAgentIsAfterTheirArguments(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command []string
		rest    []string
		routes  map[string]http.HandlerFunc
	}{
		{
			name:    "proxy system",
			command: []string{"proxy", "system"},
			rest:    []string{"off"},
			routes: systemRoutes(t, httpapi.SystemProxyView{
				Platform: "darwin",
			}),
		},
		{
			name:    "proxy probe",
			command: []string{"proxy", "probe"},
			rest:    []string{"peer:22"},
			routes: map[string]http.HandlerFunc{
				"POST /api/proxy/probe": func(w http.ResponseWriter, _ *http.Request) {
					writeJSONResponse(t, w, http.StatusOK,
						httpapi.ProxyProbeResult{Address: "peer:22", Reachable: true, ViaTailnet: true})
				},
			},
		},
		{
			name:    "proxy connect",
			command: []string{"proxy", "connect"},
			rest:    []string{"peer", "22"},
			routes:  proxyRoutes(t, listeningView(connectServer(t, acceptAndEcho))),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.routes)
			env := h.env()
			// proxy connect pipes this process's input to the destination and ends when
			// it does, so an empty one is what makes the tunnel close on its own.
			env.Stdin = strings.NewReader("")

			// The flag comes after the arguments, which is the order under test.
			err := Run(t.Context(), invocation(tc.command, tc.rest, h.cfg()), env)

			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if len(h.recorded()) == 0 {
				t.Error("the command reached no agent, so the flag naming one was read as an argument")
			}
		})
	}
}

// The probe takes exactly one destination: none is nothing to probe, and two is a
// quoting mistake that would silently probe only the first.
func TestProxyProbeNeedsExactlyOneDestination(t *testing.T) {
	for _, args := range [][]string{{}, {"peer:22", "other:22"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			h := newHarness(t, proxyRoutes(t, listeningView("127.0.0.1:1080")))

			err := Run(t.Context(), invocation([]string{"proxy", "probe"}, h.cfg(), args), h.env())

			if !errors.Is(err, ErrUsage) {
				t.Errorf("err = %v, want a usage error", err)
			}
		})
	}
}

// The agent refusing is not the same as the proxy refusing, and every command has to
// pass the agent's own sentence through: a command that reported its own guess would
// send the user after the wrong thing.
func TestEveryProxyCommandPassesOnTheAgentsRefusal(t *testing.T) {
	for _, tc := range proxyCommands {
		t.Run(tc.name, func(t *testing.T) {
			routes := map[string]http.HandlerFunc{
				"GET /api/proxy": func(w http.ResponseWriter, _ *http.Request) {
					writeJSONResponse(t, w, http.StatusServiceUnavailable,
						map[string]any{"error": "the tailnet node is not running"})
				},
				"GET /api/proxy/system": func(w http.ResponseWriter, _ *http.Request) {
					writeJSONResponse(t, w, http.StatusServiceUnavailable,
						map[string]any{"error": "the tailnet node is not running"})
				},
				"POST /api/proxy/probe": func(w http.ResponseWriter, _ *http.Request) {
					writeJSONResponse(t, w, http.StatusServiceUnavailable,
						map[string]any{"error": "the tailnet node is not running"})
				},
			}
			h := newHarness(t, routes)

			err := Run(t.Context(), invocation(tc.command, h.cfg(), tc.rest), h.env())

			if err == nil {
				t.Fatal("the command reported success while the agent was refusing")
			}
			if !strings.Contains(err.Error(), "the tailnet node is not running") {
				t.Errorf("err = %v, want the agent's own reason", err)
			}
		})
	}
}

// --json exists so a script does not parse the human form, which is free to change. A
// command that printed prose under the flag would break every such script silently.
func TestTheProxyCommandsThatTakeJSONPrintTheAgentsAnswerVerbatim(t *testing.T) {
	t.Run("proxy status", func(t *testing.T) {
		view := listeningView("127.0.0.1:1080")
		h := newHarness(t, proxyRoutes(t, view))

		if err := Run(t.Context(), invocation([]string{"proxy", "status"}, h.cfg(), []string{"--json"}), h.env()); err != nil {
			t.Fatalf("proxy status --json: %v", err)
		}

		var got httpapi.ProxyView
		if err := json.Unmarshal([]byte(h.out()), &got); err != nil {
			t.Fatalf("the output is not JSON: %v\n%s", err, h.out())
		}
		if got.Listening != view.Listening || got.SocksURL != view.SocksURL {
			t.Errorf("printed %+v, want the agent's own view", got)
		}
	})

	t.Run("proxy probe", func(t *testing.T) {
		result := httpapi.ProxyProbeResult{Address: "peer:22", Reachable: true, ViaTailnet: true}
		h := newHarness(t, map[string]http.HandlerFunc{
			"POST /api/proxy/probe": func(w http.ResponseWriter, _ *http.Request) {
				writeJSONResponse(t, w, http.StatusOK, result)
			},
		})

		if err := Run(t.Context(), invocation([]string{"proxy", "probe"}, h.cfg(), []string{"--json", "peer:22"}), h.env()); err != nil {
			t.Fatalf("proxy probe --json: %v", err)
		}

		var got httpapi.ProxyProbeResult
		if err := json.Unmarshal([]byte(h.out()), &got); err != nil {
			t.Fatalf("the output is not JSON: %v\n%s", err, h.out())
		}
		if got != result {
			t.Errorf("printed %+v, want the agent's own result %+v", got, result)
		}
	})

	// A destination that cannot be reached is still an answer under --json: the script
	// reads the result, and the non-zero status is what a shell branches on. Printing
	// nothing would leave it with only the status and no reason.
	t.Run("proxy probe reporting a failure", func(t *testing.T) {
		result := httpapi.ProxyProbeResult{Address: "peer:22", Error: "no route to host"}
		h := newHarness(t, map[string]http.HandlerFunc{
			"POST /api/proxy/probe": func(w http.ResponseWriter, _ *http.Request) {
				writeJSONResponse(t, w, http.StatusOK, result)
			},
		})

		if err := Run(t.Context(), invocation([]string{"proxy", "probe"}, h.cfg(), []string{"--json", "peer:22"}), h.env()); err != nil {
			t.Fatalf("proxy probe --json: %v", err)
		}
		if !strings.Contains(h.out(), "no route to host") {
			t.Errorf("output is %q, want the reason the destination was unreachable", h.out())
		}
	})
}

// The status output is a table, and a row the agent left empty is a fact it does not
// have rather than one whose value is blank. Printing "SOCKS5:" with nothing after it
// reads as the proxy having no address.
func TestProxyStatusLeavesOutTheRowsTheAgentHasNoValueFor(t *testing.T) {
	view := listeningView("127.0.0.1:1080")
	view.PACURL = ""
	h := newHarness(t, proxyRoutes(t, view))

	if err := Run(t.Context(), invocation([]string{"proxy", "status"}, h.cfg()), h.env()); err != nil {
		t.Fatalf("proxy status: %v", err)
	}
	if strings.Contains(h.out(), "Auto-config") {
		t.Errorf("output names a row the agent has no value for:\n%s", h.out())
	}
	if !strings.Contains(h.out(), "SOCKS5") {
		t.Errorf("output dropped a row the agent did fill:\n%s", h.out())
	}
}

// A proxy that is working but degraded is the state most worth surfacing: everything
// else on screen says it is fine, so the reason has to appear beside it.
func TestProxyStatusShowsTheWarningBesideAWorkingProxy(t *testing.T) {
	view := listeningView("127.0.0.1:1080")
	view.Capability.Degraded = true
	view.Capability.Reason = "the tailnet node is not running, so every connection is refused"
	h := newHarness(t, proxyRoutes(t, view))

	if err := Run(t.Context(), invocation([]string{"proxy", "status"}, h.cfg()), h.env()); err != nil {
		t.Fatalf("proxy status: %v", err)
	}
	if !strings.Contains(h.out(), "the tailnet node is not running") {
		t.Errorf("a degraded proxy printed no warning:\n%s", h.out())
	}
}

// "On but not listening" is neither of the other two states, and the advice for it is
// different from both: nothing to turn on, and no address to paste.
func TestProxyStatusSeparatesNotListeningFromSwitchedOff(t *testing.T) {
	view := httpapi.ProxyView{
		Enabled:    true,
		Capability: httpapi.Capability{Reason: "listen tcp 127.0.0.1:1080: address already in use"},
	}
	h := newHarness(t, proxyRoutes(t, view))

	if err := Run(t.Context(), invocation([]string{"proxy", "status"}, h.cfg()), h.env()); err != nil {
		t.Fatalf("proxy status: %v", err)
	}
	out := h.out()
	if !strings.Contains(out, "address already in use") {
		t.Errorf("output does not carry the agent's reason:\n%s", out)
	}
	if strings.Contains(out, "proxy.enabled") {
		t.Errorf("output tells the user to switch on a module that is already on:\n%s", out)
	}
}

// The dashboard's own address is kept off the proxy so a child that calls the app-tail
// API does not send that call through the proxy back to this machine. With no auto-config
// URL there is no address to add, and a stray comma would make an entry of the empty
// string, which some clients read as "proxy nothing".
func TestTheDashboardIsOnlyExcludedFromTheProxyWhenItsAddressIsKnown(t *testing.T) {
	tests := []struct {
		name   string
		pacURL string
		want   string
	}{
		{name: "the agent published one", pacURL: "http://127.0.0.1:8377/proxy.pac", want: "localhost,127.0.0.1,::1,127.0.0.1:8377"},
		{name: "the agent published none", pacURL: "", want: "localhost,127.0.0.1,::1"},
		{name: "not a URL this can read", pacURL: "socks5h://127.0.0.1:1080", want: "localhost,127.0.0.1,::1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			view := listeningView("127.0.0.1:1080")
			view.PACURL = tc.pacURL

			var got string
			for _, pair := range proxyEnv(view, "") {
				if name, value, _ := strings.Cut(pair, "="); name == "NO_PROXY" {
					got = value
				}
			}
			if got != tc.want {
				t.Errorf("NO_PROXY = %q, want %q", got, tc.want)
			}
		})
	}
}

// envWithoutAnAgent is a config file in a fresh directory, which records no dashboard
// address -- what a machine with app-tail installed but never started looks like.
func envWithoutAnAgent(t *testing.T) (Env, string) {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.json")
	if _, err := config.Open(configPath); err != nil {
		t.Fatalf("open config: %v", err)
	}
	return Env{
		Stdout: io.Discard,
		Stderr: io.Discard,
		Getenv: func(string) string { return "" },
	}, configPath
}

// No agent running is the single most common thing a user hits, and every command has to
// name it as that rather than as a failure of what was asked for: the fix is "start the
// agent", which no other message points at.
func TestEveryProxyCommandSaysWhenNoAgentIsRunning(t *testing.T) {
	for _, tc := range proxyCommands {
		t.Run(tc.name, func(t *testing.T) {
			// A config file in a fresh directory records no dashboard address, which is
			// what a machine with the agent installed but not started looks like.
			env, configPath := envWithoutAnAgent(t)

			err := Run(t.Context(), invocation(tc.command, []string{"--config", configPath}, tc.rest), env)

			if !errors.Is(err, ErrNoAgent) {
				t.Errorf("err = %v, want it to wrap ErrNoAgent so the outage is recognisable", err)
			}
		})
	}
}

// The refusal a browser or ssh sees is whatever this returns, so it has to end up with a
// reason in every case: the header the proxy sets, the body it wrote, or -- when it sent
// neither -- the status line, which at least says which kind of refusal it was.
func TestATunnelRefusalAlwaysCarriesAReason(t *testing.T) {
	tests := []struct {
		name  string
		serve func(*http.Request, net.Conn)
		want  string
	}{
		{
			name:  "the proxy set the reason header",
			serve: refuse(http.StatusForbidden, "destination is outside the proxy's scope"),
			want:  "outside the proxy's scope",
		},
		{
			name: "the reason is only in the body",
			serve: func(_ *http.Request, conn net.Conn) {
				body := "the tailnet node is not running"
				fmt.Fprintf(conn, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: %d\r\n\r\n%s",
					len(body), body)
			},
			want: "the tailnet node is not running",
		},
		{
			name: "the proxy gave no reason at all",
			serve: func(_ *http.Request, conn net.Conn) {
				fmt.Fprint(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			},
			want: "502",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proxyAddr := connectServer(t, tc.serve)
			h := newHarness(t, proxyRoutes(t, listeningView(proxyAddr)))

			err := Run(t.Context(), invocation([]string{"proxy", "connect"}, h.cfg(), []string{"peer", "22"}), h.env())

			if err == nil {
				t.Fatal("a refused tunnel was reported as established")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to carry %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "peer:22") {
				t.Errorf("err = %v, want it to name the destination that was refused", err)
			}
		})
	}
}

// A tunnel ending is not a failure -- it is how every session finishes -- so these have
// to read as the ordinary end. Reporting them would make `ssh` through the proxy exit
// non-zero on every clean logout.
func TestTheOrdinaryEndOfATunnelIsNotReportedAsAFailure(t *testing.T) {
	ordinary := []error{
		io.EOF,
		net.ErrClosed,
		os.ErrClosed,
		fmt.Errorf("read from the peer: %w", io.EOF),
	}
	for _, err := range ordinary {
		if !isClosed(err) {
			t.Errorf("isClosed(%v) = false, so a clean logout would exit non-zero", err)
		}
	}

	real := []error{
		errors.New("connection reset by peer"),
		fmt.Errorf("send to the peer: %w", errors.New("broken pipe")),
	}
	for _, err := range real {
		if isClosed(err) {
			t.Errorf("isClosed(%v) = true, so a dropped connection would look like a clean exit", err)
		}
	}
}

// The shell sees the child's status, so the error carrying it has to say what happened
// rather than read as an app-tail failure -- and it has to name the number, since that
// is the only thing distinguishing one non-zero exit from another.
func TestTheChildsExitStatusIsReportedAsTheChildsOwn(t *testing.T) {
	err := &ExitError{Code: 7}
	if got := err.Error(); !strings.Contains(got, "7") {
		t.Errorf("Error() = %q, want it to name the status the command chose", got)
	}
}

// A proxy that is on and not listening for a reason the agent could not name still needs
// a sentence: an error whose reason half is empty reads as a bug in app-tail.
func TestAProxyThatIsUnusableForNoStatedReasonStillExplainsItself(t *testing.T) {
	err := proxyNotListening(httpapi.ProxyView{Enabled: true})
	if err == nil {
		t.Fatal("a proxy that is not listening was reported as usable")
	}
	if strings.HasSuffix(err.Error(), ": ") || strings.HasSuffix(err.Error(), ":") {
		t.Errorf("err = %q, which trails off where the reason should be", err)
	}
	if strings.Contains(err.Error(), "proxy.enabled") {
		t.Errorf("err = %q, telling the user to switch on a module that is already on", err)
	}
}

// The stored password is what the child authenticates with. Running without it produces
// an authentication failure from the proxy with nothing on screen naming the setting to
// fill in, so this has to be caught before the command runs.
func TestExecRefusesToRunWhenTheRequiredPasswordIsNotStored(t *testing.T) {
	view := listeningView("127.0.0.1:1080")
	view.RequiresPassword = true
	h := newHarness(t, proxyRoutes(t, view))

	err := Run(t.Context(), invocation([]string{"exec"}, h.cfg(), []string{"--", "true"}), h.env())

	if err == nil {
		t.Fatal("the command ran with no password against a proxy that requires one")
	}
	if !strings.Contains(err.Error(), "proxy.token") {
		t.Errorf("err = %v, want it to name the setting that stores the password", err)
	}
}

// `proxy system off` is the undo, and `--json` describes the read. Combining them would
// silently perform the undo and print nothing a script could act on, which is the worst
// possible outcome for a flag whose purpose is machine-readable output.
func TestProxySystemRefusesTheCombinationsThatWouldMeanTwoThings(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "off asked for as JSON", args: []string{"--json", "off"}},
		{name: "a word that is not off", args: []string{"on"}},
		{name: "off with something after it", args: []string{"off", "extra"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, systemRoutes(t, httpapi.SystemProxyView{Supported: true, Platform: "darwin"}))

			err := Run(t.Context(), invocation([]string{"proxy", "system"}, h.cfg(), tc.args), h.env())

			if !errors.Is(err, ErrUsage) {
				t.Errorf("err = %v, want a usage error rather than one of the two meanings being picked", err)
			}
		})
	}
}

// The agent owns both the stored setting and the record of what this machine's proxy
// settings were, so a refusal from it means neither was changed. Reporting success would
// leave the machine pointed at a proxy the user just took it off.
func TestProxySystemOffReportsTheAgentsRefusalRatherThanSuccess(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/proxy/system": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, httpapi.SystemProxyView{Supported: true, Platform: "darwin"})
		},
		"PUT /api/settings": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusInternalServerError,
				map[string]any{"error": "the stored settings could not be written"})
		},
	})

	err := Run(t.Context(), invocation([]string{"proxy", "system"}, h.cfg(), []string{"off"}), h.env())

	if err == nil {
		t.Fatal("the command reported the settings put back while the agent refused")
	}
	if !strings.Contains(err.Error(), "could not be written") {
		t.Errorf("err = %v, want the agent's own reason", err)
	}
}

// An error reading the system state is not the same as the agent being stopped: the
// second has a fallback that clears the setting locally, and taking it for a stopped
// agent would hide a real failure behind a message about starting the agent.
func TestProxySystemOffSeparatesAFailedReadFromAStoppedAgent(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/proxy/system": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusInternalServerError,
				map[string]any{"error": "the system proxy state could not be read"})
		},
	})

	err := Run(t.Context(), invocation([]string{"proxy", "system"}, h.cfg(), []string{"off"}), h.env())

	if err == nil {
		t.Fatal("the command reported success while the agent could not read the state")
	}
	if !strings.Contains(err.Error(), "could not be read") {
		t.Errorf("err = %v, want the agent's own reason rather than a fallback", err)
	}
}

// The proxy the agent named is the one the tunnel goes through, and a tunnel that could
// not even reach it is a different problem from one the proxy refused: the first is the
// agent's address being stale, the second is the destination.
func TestAConnectThatCannotReachTheProxyNamesTheProxyRatherThanThePeer(t *testing.T) {
	// A port nothing is listening on, which is what a stale recorded address leaves.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	proxyAddr := dead.Addr().String()
	dead.Close()

	h := newHarness(t, proxyRoutes(t, listeningView(proxyAddr)))

	err = Run(t.Context(), invocation([]string{"proxy", "connect"}, h.cfg(), []string{"peer", "22"}), h.env())

	if err == nil {
		t.Fatal("a tunnel was reported through a proxy that is not listening")
	}
	if !strings.Contains(err.Error(), proxyAddr) {
		t.Errorf("err = %v, want it to name the proxy address it could not reach", err)
	}
	// The dial error underneath already carries the address, so the address alone does
	// not say which end failed. The sentence has to attribute it, or the user goes and
	// debugs the peer.
	if !strings.Contains(err.Error(), "app-tail proxy") {
		t.Errorf("err = %v, want it to say the proxy is what could not be reached", err)
	}
}

// A proxy that answers with something that is not an HTTP response has been replaced by
// something else on that port. Reading it as a tunnel would hand whatever is there the
// user's traffic.
func TestAProxyThatAnswersWithNonsenseIsNotTreatedAsATunnel(t *testing.T) {
	proxyAddr := connectServer(t, func(_ *http.Request, conn net.Conn) {
		fmt.Fprint(conn, "not an http response at all\r\n")
	})
	h := newHarness(t, proxyRoutes(t, listeningView(proxyAddr)))

	err := Run(t.Context(), invocation([]string{"proxy", "connect"}, h.cfg(), []string{"peer", "22"}), h.env())

	if err == nil {
		t.Fatal("a tunnel was established through something that is not the proxy")
	}
	if !strings.Contains(err.Error(), "peer:22") {
		t.Errorf("err = %v, want it to name the destination that was being asked for", err)
	}
}

// Output that could not be written is not output. Exiting zero would tell a script the
// status was reported when nothing reached it.
func TestProxyStatusReportsStdoutFailingRatherThanExitingCleanly(t *testing.T) {
	h := newHarness(t, proxyRoutes(t, listeningView("127.0.0.1:1080")))
	env := h.env()
	env.Stdout = brokenWriter{}

	err := Run(t.Context(), invocation([]string{"proxy", "status"}, h.cfg()), env)

	if err == nil {
		t.Fatal("proxy status exited cleanly with nothing written")
	}
}

// A command that is not on PATH never ran, so there is no status of its own to pass
// through -- and reporting one would make "typo in the command name" indistinguishable
// from "the command ran and failed".
func TestExecSeparatesACommandThatCouldNotStartFromOneThatFailed(t *testing.T) {
	h := newHarness(t, proxyRoutes(t, listeningView("127.0.0.1:1080")))

	err := Run(t.Context(), invocation([]string{"exec"}, h.cfg(), []string{"--", "app-tail-no-such-command"}), h.env())

	if err == nil {
		t.Fatal("exec reported success for a command that does not exist")
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		t.Errorf("err = %v, reported as a status the command chose when it never ran", err)
	}
	if !strings.Contains(err.Error(), "app-tail-no-such-command") {
		t.Errorf("err = %v, want it to name the command that could not be started", err)
	}
}

// stubTunnel stands in for the connection to the proxy, so each half of it can be made
// to fail on demand. A real one fails only on timing this test could not arrange, and a
// tunnel that reported the wrong end -- or reported nothing -- sends a user off to debug
// a peer that is fine.
type stubTunnel struct {
	reads         io.Reader
	writes        io.Writer
	closeWriteErr error
}

func (s *stubTunnel) Read(b []byte) (int, error)       { return s.reads.Read(b) }
func (s *stubTunnel) Write(b []byte) (int, error)      { return s.writes.Write(b) }
func (s *stubTunnel) Close() error                     { return nil }
func (s *stubTunnel) CloseWrite() error                { return s.closeWriteErr }
func (s *stubTunnel) LocalAddr() net.Addr              { return stubAddr{} }
func (s *stubTunnel) RemoteAddr() net.Addr             { return stubAddr{} }
func (s *stubTunnel) SetDeadline(time.Time) error      { return nil }
func (s *stubTunnel) SetReadDeadline(time.Time) error  { return nil }
func (s *stubTunnel) SetWriteDeadline(time.Time) error { return nil }

type stubAddr struct{}

func (stubAddr) Network() string { return "tcp" }
func (stubAddr) String() string  { return "127.0.0.1:1080" }

// heldOpen is a peer that has sent nothing and not hung up, which is what the answering
// half of a tunnel looks like while the sending half is still working. It ends when the
// test does, so the goroutine reading it does not outlive it.
func heldOpen(t *testing.T) io.Reader {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	return holdingReader{release}
}

type holdingReader struct{ release <-chan struct{} }

func (r holdingReader) Read([]byte) (int, error) {
	<-r.release
	return 0, io.EOF
}

// The half close is what tells the peer the request is over while its answer is still
// coming, so a request-then-response protocol depends on it. One that failed has to be
// reported: the peer is left waiting for a request it will never see finish, and a
// command that exited cleanly would make that look like the peer hanging.
func TestATunnelReportsAHalfCloseThatFailed(t *testing.T) {
	env := Env{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard}
	upstream := &stubTunnel{
		reads:         heldOpen(t),
		writes:        io.Discard,
		closeWriteErr: errors.New("the socket was already gone"),
	}

	err := pipe(env, upstream)

	if err == nil {
		t.Fatal("the tunnel exited cleanly after it could not tell the peer the request was over")
	}
	if !strings.Contains(err.Error(), "the socket was already gone") {
		t.Errorf("err = %v, want it to carry why the half close failed", err)
	}
}

// Which end failed is the whole content of the message: "send" and "receive" send a user
// to opposite halves of the problem, so a failure to send must never be reported as one.
func TestATunnelSaysWhichEndOfItFailed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		env      Env
		upstream *stubTunnel
		want     string
	}{{
		name: "nothing could be sent",
		env:  Env{Stdin: iotest.ErrReader(errors.New("the input went away")), Stdout: io.Discard},
		want: "send to the peer",
	}, {
		name:     "nothing could be handed back",
		env:      Env{Stdin: strings.NewReader(""), Stdout: brokenWriter{}},
		upstream: &stubTunnel{reads: strings.NewReader("SSH-2.0-peer\r\n")},
		want:     "receive from the peer",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := tc.upstream
			if upstream == nil {
				upstream = &stubTunnel{reads: heldOpen(t)}
			}
			if upstream.writes == nil {
				upstream.writes = io.Discard
			}

			err := pipe(tc.env, upstream)

			if err == nil {
				t.Fatalf("the tunnel exited cleanly after %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}
}

// %h in an ssh ProxyCommand is whatever the user's config carries, so a host that cannot
// go into a request reaches this command. It has to be named: without it the failure is
// indistinguishable from the proxy being down, which is a different thing to go and fix.
func TestProxyConnectNamesAHostItCouldNotAskFor(t *testing.T) {
	proxyAddr := connectServer(t, acceptAndEcho)
	h := newHarness(t, proxyRoutes(t, listeningView(proxyAddr)))

	err := Run(t.Context(), invocation([]string{"proxy", "connect"}, h.cfg(), []string{"pe\ner", "22"}), h.env())

	if err == nil {
		t.Fatal("a host that cannot go into a request was reported as connected")
	}
	if !strings.Contains(err.Error(), "pe\ner") {
		t.Errorf("err = %v, want it to name the host that could not be asked for", err)
	}
}
