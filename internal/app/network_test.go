// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/forward"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/subnets"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// newQuietAgent builds an agent that is never run, for the paths that are about how the
// node is chosen rather than about the agent's own lifecycle.
func newQuietAgent(t *testing.T, newNode func(tsnode.Options) NodeController) *Agent {
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
	agent, err := New(Options{
		Store: store, Runtime: rt, Getenv: emptyEnv, Logger: quietLogger(),
		Version: "test", NewNode: newNode, Provision: refuseElevation,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return agent
}

// refuseElevation stands in for the step that obtains administrator rights. The real one
// raises the system's password dialog on any machine whose privileged helper is missing or
// left by an earlier build, which is most developer machines most of the time, and a suite
// must never raise one -- a test run that stops for a password is a test run nobody can put
// in CI or leave unattended. Refusing rather than succeeding is what keeps the paths under
// test honest: a machine that was not set up stays not set up.
func refuseElevation(context.Context, func(string, ...any), tsnode.Rights, bool, string) error {
	return errors.New("this suite does not ask the machine for administrator rights")
}

// The stub above is what keeps `go test` from stopping for a password on a machine whose
// helper is stale, and dropping it from the options would not fail anything -- the suite
// would simply start raising a dialog on the machines where the repair path fires, which is
// the machines where it is hardest to notice as a test problem.
func TestTheTestAgentNeverAsksThisMachineForAdministratorRights(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })

	err := agent.provision(context.Background(), func(string, ...any) {}, tsnode.RightsInterface, true, "")

	if err == nil || !strings.Contains(err.Error(), "does not ask the machine") {
		t.Fatalf("the test agent's setup step reported %v, want the suite's own refusal -- "+
			"the real one raises the system password dialog", err)
	}
}

// tunParams is what the settings produce when the interface mode is asked for.
func tunParams() tsnode.ServerParams {
	return tsnode.ServerParams{
		Hostname:      "app-tail-test",
		Network:       config.NetworkTUN,
		InterfaceName: "utun9",
	}
}

// By the time a start fails the previous node has already released the state directory, so
// there is no going back to it. Coming up contained is the deliberate trade: a working
// node in a mode the user did not choose beats no tailnet at all -- provided the
// substitution is visible, which is the rest of this test.
func TestAFailedInterfaceStartComesUpContainedAndSaysWhy(t *testing.T) {
	rec := &recordingNodes{}
	agent := newQuietAgent(t, rec.factory())

	failed := newFakeNode()
	cause := errors.New("open the network interface: operation not permitted")

	if err := agent.retryContained(context.Background(), tunParams(), failed, cause); err != nil {
		t.Fatalf("the contained retry also failed: %v", err)
	}

	// The node that could not start held a descriptor and a state directory; leaving it
	// open would keep the replacement from binding either.
	if !failed.wasClosed() {
		t.Error("the node that could not start was left open")
	}

	built := rec.snapshot()
	if len(built) != 1 {
		t.Fatalf("the retry built %d nodes, want exactly one replacement", len(built))
	}
	replacement := built[0]
	if replacement.params.Network != config.NetworkUserspace {
		t.Errorf("the replacement was built for the %q mode, want the contained one", replacement.params.Network)
	}
	// Carried over from the mode that failed, it would name an interface the contained
	// node never creates -- and would be reported on a status that says there is none.
	if replacement.params.InterfaceName != "" {
		t.Errorf("the replacement carried the interface name %q from the mode that failed", replacement.params.InterfaceName)
	}
	if !replacement.started {
		t.Error("the replacement was built and never started")
	}

	// The whole trade depends on the substitution being visible.
	if got := agent.networkModeFallback(); !strings.Contains(got, "operation not permitted") {
		t.Errorf("the recorded reason is %q, which does not carry the failure that caused the fallback", got)
	}
	if got := agent.NodeAPI().Status().NetworkFallback; !strings.Contains(got, "operation not permitted") {
		t.Errorf("the status reports %q, so nothing a user can see would say the mode was substituted", got)
	}
}

// A contained node that fails to start has nowhere to fall back to, and retrying it in the
// mode it is already in would be a second attempt at the same thing.
func TestAFailedContainedStartIsNotRetried(t *testing.T) {
	rec := &recordingNodes{}
	agent := newQuietAgent(t, rec.factory())

	cause := errors.New("the control plane refused this key")
	params := tsnode.ServerParams{Hostname: "app-tail-test", Network: config.NetworkUserspace}

	err := agent.retryContained(context.Background(), params, newFakeNode(), cause)
	if !errors.Is(err, cause) {
		t.Fatalf("the failure was reported as %v, want the original cause", err)
	}
	if built := rec.snapshot(); len(built) != 0 {
		t.Errorf("the retry built %d nodes for a mode that was already contained", len(built))
	}
	if got := agent.networkModeFallback(); got != "" {
		t.Errorf("a contained failure recorded the mode fallback %q, which would claim a substitution that never happened", got)
	}
}

// When the fallback fails too there is no node at all, and both failures matter: the
// interface one is what the user has to fix, and the contained one is why there is nothing
// running in the meantime.
func TestWhenTheFallbackAlsoFailsBothReasonsAreReported(t *testing.T) {
	containedFailure := errors.New("the state directory is locked by another process")
	agent := newQuietAgent(t, func(tsnode.Options) NodeController {
		node := newFakeNode()
		node.startErr = containedFailure
		return node
	})

	cause := errors.New("no privileged helper is installed")
	err := agent.retryContained(context.Background(), tunParams(), newFakeNode(), cause)
	if err == nil {
		t.Fatal("a retry that could not start a node reported success")
	}
	if !errors.Is(err, cause) {
		t.Errorf("the report %q drops the interface failure, which is the one the user has to fix", err)
	}
	if !errors.Is(err, containedFailure) {
		t.Errorf("the report %q drops the contained failure, which is why there is no node at all", err)
	}
}

// A reason must not outlive the machine state that produced it: a helper installed after a
// refusal would otherwise leave the node reporting that it is still missing, forever.
func TestPreparingParametersClearsAStaleFallbackReason(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.setNetworkFallback("no privileged helper is installed")

	params := tsnode.ServerParams{Hostname: "app-tail-test", Network: config.NetworkUserspace}
	got, err := agent.prepareParams(context.Background(), params)
	if err != nil {
		t.Fatalf("prepareParams: %v", err)
	}
	if got.Network != config.NetworkUserspace {
		t.Errorf("prepareParams changed the mode to %q", got.Network)
	}
	if reason := agent.networkModeFallback(); reason != "" {
		t.Errorf("the stale reason %q survived a successful preparation", reason)
	}
}

// The mode is narrowed before anything is torn down, which is the whole reason the check
// lives here: discovered after the teardown, a machine with no privileged side would be
// left with no tailnet at all rather than with a contained node that says why.
func TestAMachineThatCannotCarryTheInterfaceModeIsNarrowedBeforeAnythingIsTornDown(t *testing.T) {
	ctx := context.Background()
	// Asked of the same preflight the narrowing consults, so this skips exactly when the
	// branch under test cannot fire -- a machine already holding the rights, or one with
	// the helper installed.
	if tsnode.Preflight(ctx, tunParams(), func(string, ...any) {}) == nil {
		t.Skip("this machine can carry the interface mode, so the narrowing under test never fires here")
	}
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })

	got, err := agent.prepareParams(ctx, tunParams())
	if err != nil {
		t.Fatalf("preparing parameters refused outright, leaving the machine with no node: %v", err)
	}
	if got.Network != config.NetworkUserspace {
		t.Errorf("the parameters still ask for the %q mode on a machine that cannot run it", got.Network)
	}
	// Carried into a contained node it would name an interface nothing creates, on a
	// status that also says there is none.
	if got.InterfaceName != "" {
		t.Errorf("the parameters carry the interface name %q for a mode that creates none", got.InterfaceName)
	}
	if agent.networkModeFallback() == "" {
		t.Error("the mode was substituted with no reason recorded, so nothing a user can see would say why")
	}
}

// A credential the node could never enrol with is not a reason to narrow the mode. Coming
// up contained on it would replace a failure naming the secret with one naming the network
// mode, and send whoever reads it to install a helper they do not need.
func TestACredentialThatCannotBeResolvedStopsThePreparationRatherThanNarrowingTheMode(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.setNetworkFallback("no privileged helper is installed")

	// Reachable from a secret file rather than from a stored setting: Validate reads the
	// path, never the bytes behind it.
	params := tunParams()
	params.AdvertiseTags = []string{"tag:app-tail"}
	params.ClientSecret = "tskey-client-abc123?ephemeral=perhaps"

	got, err := agent.prepareParams(context.Background(), params)
	if err == nil {
		t.Fatalf("a secret whose options do not parse was accepted, giving %+v", got)
	}
	if !strings.Contains(err.Error(), "ephemeral") {
		t.Errorf("the refusal is %q, which does not name the part of the secret that is wrong", err)
	}
	if got.Network != "" {
		t.Errorf("parameters came back alongside the refusal, asking for the %q mode", got.Network)
	}
	if reason := agent.networkModeFallback(); strings.Contains(reason, "ephemeral") {
		t.Errorf("a credential failure was recorded as the mode substitution %q, which it is not", reason)
	}
}

// The privileged side reports most of what it does through this rather than through return
// values: installing a route and writing a resolver file are separate steps, and a failure
// between them is only ever visible in a log. A process holding root that cannot say what
// it did is worse than one that will not start.
func TestThePrivilegedSidesOwnReportingReachesTheAgentsLog(t *testing.T) {
	var log bytes.Buffer
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.logger = slog.New(slog.NewTextHandler(&log, nil))

	agent.hostLogf("installed %d routes on %s", 3, "utun9")

	if got := log.String(); !strings.Contains(got, "installed 3 routes on utun9") {
		t.Errorf("the privileged side's line came out as %q, so the values it reported are not in it", got)
	}
}

// The node that could not start is closed on the way past, and a close that fails must not
// stop the replacement. Closing is a courtesy here -- the descriptor and the state
// directory -- while the replacement is the reason this path exists at all.
func TestANodeThatWillNotCloseStillGetsAReplacement(t *testing.T) {
	rec := &recordingNodes{}
	agent := newQuietAgent(t, rec.factory())

	failed := newFakeNode()
	failed.closeErr = errors.New("the network interface is still in use")
	cause := errors.New("open the network interface: operation not permitted")

	if err := agent.retryContained(context.Background(), tunParams(), failed, cause); err != nil {
		t.Fatalf("a close that failed stopped the contained retry, leaving no node at all: %v", err)
	}
	if built := rec.snapshot(); len(built) != 1 {
		t.Errorf("the retry built %d nodes after a close that failed, want the replacement", len(built))
	}
}

// The substitution is reported whatever the node's own state, because this is the case
// where the node is working and is not doing what was asked: nothing else on the status
// would hint that the machine is not carrying tailnet addresses.
func TestTheSubstitutionIsReportedEvenWhileTheNodeIsRunning(t *testing.T) {
	node := newFakeNode()
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return node })
	agent.mu.Lock()
	agent.node = node
	agent.mu.Unlock()

	node.mu.Lock()
	node.status.BackendState = tsnode.StateRunning
	node.mu.Unlock()
	agent.setNetworkFallback("no privileged helper is installed")

	status := agent.NodeAPI().Status()
	if !status.Running() {
		t.Fatal("the node was not reported as running, so this is not the case under test")
	}
	if status.NetworkFallback == "" {
		t.Error("a running node reported no substitution, so a user would see a healthy node quietly in the wrong mode")
	}
}

// A secret whose options do not parse can never mint a key. This is the shape a credential
// failure really arrives in: validation reads the path, never the bytes behind it, so the
// secret passes every write path and is discovered at the moment a node is built from it.
const unusableSecret = "tskey-client-abc123?ephemeral=perhaps"

// A plain auth key is carried through untouched: nothing is exchanged for it, so a node
// can be built from one with no control plane in reach.
const usableSecret = "tskey-auth-abc123"

// seedSecretFile points the stored settings at a secret file and writes its first
// contents, returning the path so a test can change what is behind it later.
func seedSecretFile(t *testing.T, store *config.Store, dir, contents string) string {
	t.Helper()
	path := filepath.Join(dir, "oauth-secret")
	writeSecretFile(t, path, contents)
	if _, err := store.Update(func(c *config.Config) error {
		tailnetOf(t, c).OAuthClientSecretFile = path
		tailnetOf(t, c).Tags = []string{"tag:app-tail"}
		return nil
	}); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	return path
}

func writeSecretFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write the secret file: %v", err)
	}
}

// A credential that cannot be resolved stops the start outright. Enrolling with the raw
// secret would put an unusable one on the wire and turn a sentence about the secret into
// the control plane's own refusal, which names nothing the user configured.
func TestAStartWithACredentialThatCannotBeResolvedBuildsNoNode(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	seedSecretFile(t, store, stateDir, unusableSecret)

	rt, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}
	rec := &recordingNodes{}
	agent, err := New(Options{
		Store: store, Runtime: rt, Getenv: emptyEnv, Logger: quietLogger(),
		Version: "test", NewNode: rec.factory(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()

	// Waited on rather than called inline: a start that got past the credential would run
	// until something cancelled it, and this failure has to be the one reported.
	select {
	case runErr := <-done:
		if runErr == nil {
			t.Fatal("Run reported success although the credential could never enrol a node")
		}
		if !strings.Contains(runErr.Error(), "ephemeral") {
			t.Errorf("Run failed with %v, which does not name the part of the secret that is wrong", runErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the agent came up on a credential that could never enrol a node")
	}
	if built := rec.snapshot(); len(built) != 0 {
		t.Errorf("%d nodes were built from a credential that could not be resolved", len(built))
	}
}

// The credential is resolved before the running node is given up, which is the same
// ordering the mode check depends on and matters for the same reason: a restart releases
// the state directory before the replacement can bind it, so a refusal discovered after
// that point leaves the machine with no tailnet at all.
func TestARestartRefusedForItsCredentialKeepsTheNodeThatIsRunning(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	secretPath := seedSecretFile(t, store, stateDir, usableSecret)

	rt, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}

	rec := &recordingNodes{}
	agent, err := New(Options{
		Store: store, Runtime: rt, Getenv: emptyEnv, Logger: quietLogger(),
		Version: "test", NewNode: rec.factory(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- agent.Run(ctx) }()
	waitFor(t, 5*time.Second, "the agent to start its first node", func() bool {
		built := rec.snapshot()
		return len(built) == 1 && built[0].wasStarted()
	})
	running := rec.snapshot()[0]

	// Broken after the node is up, the way a secrets manager rotating a file underneath a
	// running agent breaks it. The settings never change -- only the bytes behind the path
	// they already name.
	writeSecretFile(t, secretPath, unusableSecret)

	err = agent.RestartNode(context.Background())
	if err == nil {
		t.Fatal("the restart reported success on a credential that could never enrol a node")
	}
	if !strings.Contains(err.Error(), "ephemeral") {
		t.Errorf("the restart failed with %v, which does not name the part of the secret that is wrong", err)
	}
	if running.wasClosed() {
		t.Error("the node that was already running was torn down for a replacement that was never going to be built")
	}
	if built := rec.snapshot(); len(built) != 1 {
		t.Errorf("%d nodes exist after the refused restart, want only the one that was already running", len(built))
	}
	if problem := agent.nodeProblem(); !strings.Contains(problem, "ephemeral") {
		t.Errorf("the recorded problem is %q, so the dashboard has nothing to show for the refused restart", problem)
	}

	cancel()
	<-runErr
}

// Obtaining the rights for the interface mode raises the system's password dialog, so when
// it fires is a decision in its own right: on the write that asks for the mode, and on
// nothing else. A dialog on every save, or at every login, is how an app teaches people to
// dismiss its prompts without reading them.
func TestTheMachineIsSetUpOnlyByTheWriteThatAsksForTheInterfaceMode(t *testing.T) {
	tests := []struct {
		name       string
		before     bool
		after      bool
		wantPrompt bool
	}{
		{name: "asking for the mode sets the machine up", after: true, wantPrompt: true},
		{name: "saving again while it is already on prompts for nothing", before: true, after: true},
		{name: "turning it off prompts for nothing", before: true},
		{name: "a save that never mentions the mode prompts for nothing"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
			calls := 0
			agent.provision = func(context.Context, func(string, ...any), tsnode.Rights, bool, string) error {
				calls++
				return nil
			}

			agent.provisionRights(context.Background(), tunSettings(tc.before), tunSettings(tc.after))

			want := 0
			if tc.wantPrompt {
				want = 1
			}
			if calls != want {
				t.Errorf("the machine setup ran %d times, want %d", calls, want)
			}
		})
	}
}

// A machine that could not be set up is not a failed settings write -- the setting was
// stored and it is the mode that could not be arranged -- but it cannot be silent either:
// this reason is the only thing standing between the user and a node that comes up in a
// mode they did not choose for no visible reason.
func TestAMachineThatCouldNotBeSetUpSaysSoWhereTheModeIsReported(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.provision = func(context.Context, func(string, ...any), tsnode.Rights, bool, string) error {
		return errors.New("the request for administrator rights was declined")
	}

	agent.provisionRights(context.Background(), tunSettings(false), tunSettings(true))

	if got := agent.networkModeFallback(); !strings.Contains(got, "declined") {
		t.Errorf("the recorded reason is %q, which does not say why the mode is not in force", got)
	}
}

// The dialog a write raises installs the helper and approves what the settings use, and the
// settings are the ones in the file this agent runs from -- the file the write was stored in.
func TestTheSetupAWriteAsksForApprovesTheConfigTheAgentRunsFrom(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	var got []string
	agent.provision = func(_ context.Context, _ func(string, ...any), _ tsnode.Rights, _ bool, configPath string) error {
		got = append(got, configPath)
		return nil
	}

	agent.provisionRights(context.Background(), tunSettings(false), tunSettings(true))

	if want := []string{agent.store.Path()}; !slices.Equal(got, want) {
		t.Errorf("the setup was given configs %q, want the agent's own %q", got, want)
	}
}

// The write that turns the mode on is answered over HTTP as well, so the dialog it raises
// is bounded exactly like the setup request's -- and the machine it arranged has to come
// back clean for the same reason the button's does.
func TestTheSetupAWriteAsksForIsBoundedAndReportedAsWell(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	var deadline time.Time
	var hadDeadline bool
	agent.provision = func(ctx context.Context, _ func(string, ...any), _ tsnode.Rights, _ bool, _ string) error {
		deadline, hadDeadline = ctx.Deadline()
		return nil
	}
	agent.setNetworkFallback("no privileged helper is installed")

	agent.provisionRights(context.Background(), tunSettings(false), tunSettings(true))

	if !hadDeadline {
		t.Fatal("the setup a write asks for runs unbounded, so an unanswered dialog reaches the server's write timeout")
	}
	if left := time.Until(deadline); left > interfaceSetupTimeout {
		t.Errorf("the setup is bounded at %v, want no more than %v", left, interfaceSetupTimeout)
	}
	if got := agent.networkModeFallback(); got != "" {
		t.Errorf("the machine still reports %q after the write that asked for the mode set it up", got)
	}
}

// tunSettings is a settings document with the interface mode selected, or not. Both keys
// travel together because the mode is not selected without the module switch beside it.
func tunSettings(selected bool) config.Settings {
	s := config.Defaults().Settings
	if selected {
		s.InterfaceEnabled = true
		s.InterfaceMode = config.NetworkTUN
	}
	return s
}

// The dashboard's caller asked for the arrangement, so the reason it failed is owed to it
// directly -- and recorded as well, because the card that reports the mode is where somebody
// looks next. The settings path only records: nobody asked it for an arrangement.
func TestTheDashboardIsToldWhyItsSetupFailedAndSoIsTheCard(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.provision = func(context.Context, func(string, ...any), tsnode.Rights, bool, string) error {
		return errors.New("the request for administrator rights was declined")
	}

	err := agent.InterfaceSetup().SetUpInterface(context.Background())

	if err == nil {
		t.Fatal("the dashboard was told the machine is ready when nothing was arranged")
	}
	if !strings.Contains(err.Error(), "declined") {
		t.Errorf("the dashboard was told %q, which does not carry why it failed", err)
	}
	if got := agent.networkModeFallback(); !strings.Contains(got, "declined") {
		t.Errorf("the recorded reason is %q, so the card still reports the mode with no explanation", got)
	}
}

// A machine that was set up must come back clean: the card is about to be reloaded, and a
// leftover reason there would report a mode as unavailable on a machine that just arranged
// it.
func TestASuccessfulSetupIsReportedAsOneAndBoundedInTime(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	var deadline time.Time
	var hadDeadline bool
	agent.provision = func(ctx context.Context, _ func(string, ...any), _ tsnode.Rights, _ bool, _ string) error {
		deadline, hadDeadline = ctx.Deadline()
		return nil
	}
	// The state a machine is in when somebody presses the button: a refusal was recorded,
	// and pressing it is what answers that refusal.
	agent.setNetworkFallback("no privileged helper is installed")

	if err := agent.InterfaceSetup().SetUpInterface(context.Background()); err != nil {
		t.Fatalf("SetUpInterface = %v, want a machine that is ready", err)
	}

	if got := agent.networkModeFallback(); got != "" {
		t.Errorf("the machine still reports %q after being set up, so the card says the mode is unavailable on a machine that just arranged it", got)
	}

	// The dialog blocks until it is answered, and this request is answered over HTTP: past
	// the server's own write timeout the caller gets a reset connection instead of a
	// sentence about what happened.
	if !hadDeadline {
		t.Fatal("the setup runs unbounded, so an unanswered dialog reaches the server's write timeout")
	}
	if left := time.Until(deadline); left > interfaceSetupTimeout {
		t.Errorf("the setup is bounded at %v, want no more than %v", left, interfaceSetupTimeout)
	}
}

// --no-elevate is a standing answer to the one question this path asks, and the answer has
// to reach the step that would raise the dialog. Sending true from here would have the
// arrangement prompt in spite of the flag, which is the app doing the thing the user
// disabled and the opposite of what the flag's own help text promises.
func TestAProcessToldNotToElevateSaysSoOnEveryWayIn(t *testing.T) {
	tests := []struct {
		name      string
		noElevate *bool
		want      bool
	}{
		{name: "--no-elevate withholds the dialog", noElevate: ptr(true)},
		{name: "the flag set false leaves it available", noElevate: ptr(false), want: true},
		{name: "no flag at all leaves it available", want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stateDir := t.TempDir()
			store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
			if err != nil {
				t.Fatalf("open store: %v", err)
			}
			rt, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			var asked []bool
			agent, err := New(Options{
				Store: store, Runtime: rt, Getenv: emptyEnv, Logger: quietLogger(),
				Version: "test",
				NewNode: func(tsnode.Options) NodeController { return newFakeNode() },
				Flags:   config.Flags{NoElevate: tc.noElevate},
				Provision: func(_ context.Context, _ func(string, ...any), _ tsnode.Rights, mayElevate bool, _ string) error {
					asked = append(asked, mayElevate)
					return nil
				},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			// Both ways in, because either one carrying the wrong answer breaks the promise.
			if err := agent.InterfaceSetup().SetUpInterface(context.Background()); err != nil {
				t.Fatalf("SetUpInterface: %v", err)
			}
			agent.provisionRights(context.Background(), tunSettings(false), tunSettings(true))

			if len(asked) != 2 {
				t.Fatalf("the arrangement ran %d times, want both ways in to reach it", len(asked))
			}
			for i, got := range asked {
				if got != tc.want {
					t.Errorf("way in %d was told it may elevate = %v, want %v", i+1, got, tc.want)
				}
			}
		})
	}
}

// A machine the arrangement reported as ready must not be left with a reason it is not.
// The flag withholds the dialog, not the answer, so a process carrying it on a machine that
// is already able reports the mode as available like any other.
func TestAnArrangementThatSucceededLeavesNoReasonBehind(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	rt, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	agent, err := New(Options{
		Store: store, Runtime: rt, Getenv: emptyEnv, Logger: quietLogger(),
		Version: "test",
		NewNode: func(tsnode.Options) NodeController { return newFakeNode() },
		Flags:   config.Flags{NoElevate: ptr(true)},
		Provision: func(context.Context, func(string, ...any), tsnode.Rights, bool, string) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	agent.setNetworkFallback("no privileged helper is installed")

	if err := agent.InterfaceSetup().SetUpInterface(context.Background()); err != nil {
		t.Fatalf("SetUpInterface on an able machine = %v, want it reported as ready", err)
	}

	if got := agent.networkModeFallback(); got != "" {
		t.Errorf("the machine still reports %q, so the card says the mode is unavailable on one that is ready", got)
	}
}

// The bound on the setup exists to keep a password dialog inside the HTTP answer that is
// waiting on it. Nothing else ties the two numbers together, so a shorter write timeout
// would turn a dialog left sitting into a reset connection with no sentence about why.
func TestTheSetupFinishesInsideTheAnswerThatIsWaitingForIt(t *testing.T) {
	if interfaceSetupTimeout >= httpapi.WriteTimeout {
		t.Errorf("the setup is bounded at %v and the answer carrying it at %v, so a dialog left sitting reaches the caller as a reset connection",
			interfaceSetupTimeout, httpapi.WriteTimeout)
	}
}

// readyReport is a machine that could carry the interface mode right now.
func readyReport() tsnode.InterfaceReport {
	return tsnode.InterfaceReport{
		Platform:  "darwin",
		Supported: true,
		Interface: "utun9",
		Helper: tsnode.InterfaceHelperReport{
			Design: true, Installable: true, Installed: true, Running: true, Version: "test",
		},
	}
}

// The card exists for the state where the settings and the machine disagree: a node that
// asked for the interface and got the contained mode reports Running, has an address, and
// answers every other field exactly as one that asked for nothing. A view built from the
// settings alone would call that mode on.
func TestTheCardReportsTheModeInForceAndNotTheOneAskedFor(t *testing.T) {
	// A node that is up and healthy in the mode it was not asked for: the state where
	// every other field on the status is indistinguishable from success.
	node := newFakeNode()
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return node })
	agent.mu.Lock()
	agent.node = node
	agent.mu.Unlock()
	node.mu.Lock()
	node.status.BackendState = tsnode.StateRunning
	node.status.Network = config.NetworkUserspace
	node.mu.Unlock()

	agent.runtime.Settings = tunSettings(true)
	agent.inspect = func(context.Context, func(string, ...any)) tsnode.InterfaceReport { return readyReport() }
	// A start that failed rather than a machine that cannot: the machine read below is
	// ready, and a reason naming the machine would be retired against it instead of
	// reported -- which is the whole of the test below this one.
	agent.setStartFallback("open the network interface: operation not permitted")

	view := agent.InterfaceSetup().View(context.Background())

	if view.InForce {
		t.Error("a running node in the contained mode was reported as running on the interface")
	}
	if view.Mode != string(config.NetworkUserspace) {
		t.Errorf("the mode in force is %q, want the one the node is really on", view.Mode)
	}
	if view.Configured != string(config.NetworkTUN) {
		t.Errorf("the configured mode is %q, want the one the settings ask for", view.Configured)
	}
	if !strings.Contains(view.Fallback, "operation not permitted") ||
		!strings.Contains(view.Capability.Reason, "operation not permitted") {
		t.Errorf("nothing says why the mode is not in force: fallback %q, reason %q", view.Fallback, view.Capability.Reason)
	}
	if view.Capability.Degraded != true || !view.Capability.Available {
		t.Errorf("a machine that can carry the mode but is not on it reported %+v", view.Capability)
	}
}

// The machine is read on every call and not remembered from the node's start. A helper
// installed in a terminal since is exactly the change somebody refreshes the page to see,
// and a card answering from a snapshot would keep telling them to install what they just did.
func TestTheCardReadsTheMachineEachTimeItIsAsked(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.runtime.Settings = tunSettings(true)
	missing := readyReport()
	missing.Helper.Running = false
	missing.Helper.Installed = false
	missing.Helper.Problem = "the privileged helper is not installed. Run `app-tail tun setup`"

	reports := []tsnode.InterfaceReport{missing, readyReport()}
	reads := 0
	agent.inspect = func(context.Context, func(string, ...any)) tsnode.InterfaceReport {
		report := reports[min(reads, len(reports)-1)]
		reads++
		return report
	}

	first := agent.InterfaceSetup().View(context.Background())
	if first.Helper.Running || !strings.Contains(first.Capability.Reason, "app-tail tun setup") {
		t.Errorf("a machine with no helper reported %+v, which names nothing to run", first.Capability)
	}

	second := agent.InterfaceSetup().View(context.Background())
	if !second.Helper.Running {
		t.Errorf("the helper installed since the last read was not picked up: %+v", second.Helper)
	}
	if reads != 2 {
		t.Errorf("the machine was read %d times for 2 requests", reads)
	}
}

// A module that is off is not a broken machine. Reporting it as degraded would put a
// warning on a dashboard belonging to somebody who chose the mode app-tail ships in, which
// is the posture the whole project defaults to.
func TestAnInterfaceModuleThatIsOffIsNotReportedAsAProblem(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.runtime.Settings = tunSettings(false)
	agent.inspect = func(context.Context, func(string, ...any)) tsnode.InterfaceReport { return readyReport() }

	view := agent.InterfaceSetup().View(context.Background())

	if view.Enabled || view.InForce {
		t.Errorf("a module that is off was reported as enabled=%t inForce=%t", view.Enabled, view.InForce)
	}
	if !view.Capability.Available || view.Capability.Degraded {
		t.Errorf("a module that is off reported %+v, which reads as something being wrong", view.Capability)
	}
	if len(view.Capability.Limits) == 0 {
		t.Error("the limits are absent, so what the mode would change is only learned by turning it on")
	}
}

// The card reports the mode the switch turns on while the module is off, so a dashboard
// writing the mode beside the switch keeps the one-interface arrangement the shelf holds
// rather than replacing it with the tailnet-only one.
func TestAModuleThatIsOffReportsTheModeItsSwitchTurnsOn(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	s := tunSettings(false)
	s.Shelved = map[string]json.RawMessage{"interface.mode": json.RawMessage(`"fabric"`)}
	agent.runtime.Settings = s
	agent.inspect = func(context.Context, func(string, ...any)) tsnode.InterfaceReport { return readyReport() }

	view := agent.InterfaceSetup().View(context.Background())

	if view.Enabled {
		t.Fatal("a module that is off was reported as enabled")
	}
	if view.Configured != string(config.NetworkFabric) {
		t.Errorf("the configured mode is %q, want the shelved %q the switch turns on", view.Configured, config.NetworkFabric)
	}
}

// A platform with no interface mode at all must say so rather than offer a switch that
// cannot work: the remedy for "not supported here" is not the remedy for "not installed".
func TestAPlatformWithoutTheModeReportsItAsUnavailable(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.runtime.Settings = tunSettings(true)
	agent.inspect = func(context.Context, func(string, ...any)) tsnode.InterfaceReport {
		return tsnode.InterfaceReport{Platform: "plan9", Supported: false}
	}

	view := agent.InterfaceSetup().View(context.Background())

	if view.Capability.Available {
		t.Errorf("a platform that cannot run the mode offered it: %+v", view.Capability)
	}
	if !strings.Contains(view.Capability.Reason, "network interface") {
		t.Errorf("the reason %q does not say the platform is the obstacle", view.Capability.Reason)
	}
}

// The state a one-click control exists for: the module is on, the machine can carry the
// mode, and the mode is simply not chosen. That is ready and degraded at once -- the two
// answer different questions, and a surface that read only the capability sentence would
// refuse to offer the switch exactly when it should.
func TestAMachineReadyForTheModeWithTheModeUnchosenIsReadyAndSaysWhyItIsNotOn(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	settings := tunSettings(true)
	settings.InterfaceMode = config.NetworkUserspace
	agent.runtime.Settings = settings
	agent.inspect = func(context.Context, func(string, ...any)) tsnode.InterfaceReport { return readyReport() }

	view := agent.InterfaceSetup().View(context.Background())

	if !view.Ready || view.Blocker != "" {
		t.Errorf("a machine that could be switched over reported ready=%t blocker=%q", view.Ready, view.Blocker)
	}
	if !view.Capability.Degraded || !strings.Contains(view.Capability.Reason, "inside app-tail") {
		t.Errorf("the reason %q does not say the mode is the thing that is unset (%+v)", view.Capability.Reason, view.Capability)
	}
}

// The other half of the same disagreement: a node that really is on the interface must be
// reported as such. Without this the card could report every state as "not in force" and
// still pass the test above.
func TestANodeThatIsOnTheInterfaceIsReportedAsInForce(t *testing.T) {
	node := newFakeNode()
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return node })
	agent.mu.Lock()
	agent.node = node
	agent.mu.Unlock()
	node.mu.Lock()
	node.status.BackendState = tsnode.StateRunning
	node.status.Network = config.NetworkTUN
	node.mu.Unlock()

	agent.runtime.Settings = tunSettings(true)
	agent.inspect = func(context.Context, func(string, ...any)) tsnode.InterfaceReport { return readyReport() }

	view := agent.InterfaceSetup().View(context.Background())

	if !view.InForce || view.Mode != string(config.NetworkTUN) {
		t.Errorf("a node carrying the machine's tailnet addresses reported inForce=%t mode=%q", view.InForce, view.Mode)
	}
	if view.Capability.Degraded || !view.Capability.Available {
		t.Errorf("a mode that is working reported %+v", view.Capability)
	}
}

// The reason a node came up contained is a snapshot of the machine at the moment it was
// built, and the machine moves on without it: the official client that forced the
// contained mode gets disconnected, the helper gets installed. Left standing, the card
// keeps explaining a condition the user has already cleared and offers nothing to do
// about it. What is left on a machine that reads ready is a node that has not been
// restarted, which is the one thing still worth saying.
func TestAMachineReasonIsRetiredByAFreshReadOfTheMachine(t *testing.T) {
	node := newFakeNode()
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return node })
	agent.mu.Lock()
	agent.node = node
	agent.mu.Unlock()
	node.mu.Lock()
	node.status.BackendState = tsnode.StateRunning
	node.status.Network = config.NetworkUserspace
	node.mu.Unlock()

	agent.runtime.Settings = tunSettings(true)
	blocked := readyReport()
	blocked.Conflict = "the official Tailscale client is connected on this machine"

	reports := []tsnode.InterfaceReport{blocked, readyReport()}
	reads := 0
	agent.inspect = func(context.Context, func(string, ...any)) tsnode.InterfaceReport {
		report := reports[min(reads, len(reports)-1)]
		reads++
		return report
	}
	// The reason recorded when the node was built names something that is no longer what
	// is in the way -- the exact state a machine lands in when one blocker replaces
	// another between a node's start and the card being read.
	agent.setNetworkFallback("app-tail needs administrator rights to run on a network " +
		"interface. Quit app-tail and start it again, and it will ask for them.")

	// While the conflict is still there the card has to keep naming it: it is what the
	// user has to act on, and a card that went quiet would read as the mode working.
	first := agent.InterfaceSetup().View(context.Background())
	if !strings.Contains(first.Capability.Reason, "Tailscale") {
		t.Errorf("the card stopped naming a conflict that is still there: %+v", first.Capability)
	}
	// The superseded reason must not ride along beside the live one. Two explanations of
	// one state is how somebody is told to restart for a prompt that the line under it
	// says will not come -- and the stale one names rights, which is not what is wrong.
	if first.Fallback != "" {
		t.Errorf("a blocked machine still reports the superseded reason %q beside its blocker", first.Fallback)
	}
	if got := agent.NodeAPI().Status().NetworkFallback; got != "" {
		t.Errorf("the node status still reports the superseded reason: %q", got)
	}

	second := agent.InterfaceSetup().View(context.Background())
	if second.Fallback != "" {
		t.Errorf("the card still reports %q after the machine read ready again", second.Fallback)
	}
	if strings.Contains(second.Capability.Reason, "Tailscale") {
		t.Errorf("the card still names the cleared conflict: %q", second.Capability.Reason)
	}
	if !strings.Contains(second.Capability.Reason, "Restart") {
		t.Errorf("the card says nothing about the restart that would move the node onto the interface: %q",
			second.Capability.Reason)
	}
	// Cleared at the source, because the node's status carries the same string and a card
	// that disagreed with the status would send the reader to the other one.
	if got := agent.NodeAPI().Status().NetworkFallback; got != "" {
		t.Errorf("the node status still reports the retired reason: %q", got)
	}
}

// A start that failed is not a fact about the machine, so re-reading the machine says
// nothing about it. Retiring it would drop the only account of a real failure and leave
// the card advising a restart that is about to fail the same way.
func TestAFailedStartSurvivesAReadyMachine(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.runtime.Settings = tunSettings(true)
	agent.inspect = func(context.Context, func(string, ...any)) tsnode.InterfaceReport { return readyReport() }
	agent.setStartFallback("open the network interface: operation not permitted")

	for i := range 2 {
		view := agent.InterfaceSetup().View(context.Background())
		if !strings.Contains(view.Fallback, "operation not permitted") {
			t.Fatalf("read %d dropped the failed start: %q", i+1, view.Fallback)
		}
	}
}

// repairAgent builds an agent whose machine answers the preflight with why, and records
// every request for the rights to put it right. want is what the machine says once the
// repair has run, so a test can drive both a repair that took and one that did not.
func repairAgent(t *testing.T, why, after error, noElevate *bool) (*Agent, *[]bool) {
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
	asked := &[]bool{}
	repaired := false
	agent, err := New(Options{
		Store: store, Runtime: rt, Getenv: emptyEnv, Logger: quietLogger(),
		Version: "test",
		NewNode: func(tsnode.Options) NodeController { return newFakeNode() },
		Flags:   config.Flags{NoElevate: noElevate},
		Preflight: func(context.Context, tsnode.ServerParams, func(string, ...any)) error {
			if repaired {
				return after
			}
			return why
		},
		Provision: func(_ context.Context, _ func(string, ...any), _ tsnode.Rights, mayElevate bool, _ string) error {
			*asked = append(*asked, mayElevate)
			repaired = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return agent, asked
}

// The one machine fault app-tail repairs without being asked. Replacing the app leaves the
// privileged helper installed for the binary that is gone, so the mode the user turned on
// silently becomes the contained one -- and on macOS the tailnet's names stop resolving
// machine-wide. Nothing on the machine puts the two back in step on its own, so a start
// that only records the reason leaves the user in a terminal to get back what they had.
func TestAHelperLeftByAnEarlierBuildIsReplacedWithoutSendingTheUserToATerminal(t *testing.T) {
	why := tsnode.WithNextStep(tsnode.ErrHelperFromAnotherBuild)
	agent, asked := repairAgent(t, why, nil, nil)

	got, err := agent.prepareParams(context.Background(), tunParams())
	if err != nil {
		t.Fatalf("prepareParams: %v", err)
	}

	if len(*asked) != 1 {
		t.Fatalf("the rights were asked for %d times, want exactly one prompt", len(*asked))
	}
	if !(*asked)[0] {
		t.Error("the repair was told it may not elevate, so it could never raise the prompt that fixes this")
	}
	// The whole point: the mode survives the upgrade rather than being narrowed away.
	if got.Network != config.NetworkTUN {
		t.Errorf("the repaired machine was still narrowed to the %q mode", got.Network)
	}
	if got.InterfaceName != tunParams().InterfaceName {
		t.Errorf("the interface name came back as %q, so the repaired node creates a different one", got.InterfaceName)
	}
	if reason := agent.networkModeFallback(); reason != "" {
		t.Errorf("the machine still reports %q after the repair took, so the card says a working mode is unavailable", reason)
	}
}

// A repair that did not take is not a reason to start on an interface that does not exist.
// The machine is read again rather than assumed fixed, and what it says the second time is
// what the user is shown.
func TestARepairThatDidNotTakeStillComesUpContainedAndSaysWhy(t *testing.T) {
	why := tsnode.WithNextStep(tsnode.ErrHelperFromAnotherBuild)
	stillBroken := errors.New("the privileged helper was installed but is not answering")
	agent, asked := repairAgent(t, why, stillBroken, nil)

	got, err := agent.prepareParams(context.Background(), tunParams())
	if err != nil {
		t.Fatalf("prepareParams: %v", err)
	}

	if len(*asked) != 1 {
		t.Fatalf("the rights were asked for %d times, want one attempt", len(*asked))
	}
	if got.Network != config.NetworkUserspace {
		t.Errorf("the parameters still ask for the %q mode on a machine the repair did not fix", got.Network)
	}
	if reason := agent.networkModeFallback(); !strings.Contains(reason, "not answering") {
		t.Errorf("the recorded reason is %q, which is the state before the repair rather than after it", reason)
	}
}

// The prompt is a question, and a node rebuild is not a reason to ask it again. Restarting
// the node runs the same preparation, so without the guard a machine that cannot be
// repaired raises a password dialog on every restart the user performs.
func TestTheRightsAreAskedForOnceARunHoweverManyTimesTheNodeIsRebuilt(t *testing.T) {
	why := tsnode.WithNextStep(tsnode.ErrHelperFromAnotherBuild)
	agent, asked := repairAgent(t, why, why, nil)

	for range 3 {
		if _, err := agent.prepareParams(context.Background(), tunParams()); err != nil {
			t.Fatalf("prepareParams: %v", err)
		}
	}

	if len(*asked) != 1 {
		t.Errorf("the rights were asked for %d times across three rebuilds, want one", len(*asked))
	}
}

// --no-elevate is a standing answer to the question this repair asks. Raising the dialog
// in spite of it is the app doing the thing the user turned off, which is worse than the
// mode staying broken until they ask for it.
func TestARepairIsNotAttemptedWhenTheProcessWasToldNotToAskForRights(t *testing.T) {
	why := tsnode.WithNextStep(tsnode.ErrHelperFromAnotherBuild)
	agent, asked := repairAgent(t, why, nil, ptr(true))

	got, err := agent.prepareParams(context.Background(), tunParams())
	if err != nil {
		t.Fatalf("prepareParams: %v", err)
	}

	if len(*asked) != 0 {
		t.Errorf("the rights were asked for %d times by a process started with --no-elevate", len(*asked))
	}
	if got.Network != config.NetworkUserspace {
		t.Errorf("the mode was left as %q without the repair that would have made it work", got.Network)
	}
}

// Every other refusal is reported and lived with. Which ones those are is tsnode's to say
// and is pinned there; what matters here is that the agent asks rather than deciding for
// itself. A machine that never had a helper is the case that would otherwise be prompted
// at every login, which is the habit that teaches people to dismiss the dialog --
// including the one time it was the fix.
func TestARefusalTheSetupWouldNotFixIsReportedRatherThanPromptedFor(t *testing.T) {
	why := errors.New("the privileged helper is not running: no helper is installed")
	agent, asked := repairAgent(t, why, nil, nil)

	got, err := agent.prepareParams(context.Background(), tunParams())
	if err != nil {
		t.Fatalf("prepareParams: %v", err)
	}

	if len(*asked) != 0 {
		t.Errorf("a refusal the setup would not fix raised %d password prompts at start", len(*asked))
	}
	if got.Network != config.NetworkUserspace {
		t.Errorf("the parameters still ask for the %q mode on a machine that cannot carry it", got.Network)
	}
	if reason := agent.networkModeFallback(); !strings.Contains(reason, "no helper is installed") {
		t.Errorf("the recorded reason is %q, which does not carry what the machine said", reason)
	}
}

// Turning the mode on raises the dialog, and the write ends in a reconcile that rebuilds
// the node -- which prepares its parameters again and finds the same machine. Without the
// run being counted, dismissing the first dialog is answered with a second one for the
// question just answered, inside a single user action.
func TestTurningTheModeOnDoesNotRaiseASecondDialogWhenTheFirstWasDismissed(t *testing.T) {
	why := tsnode.WithNextStep(tsnode.ErrHelperFromAnotherBuild)
	agent, asked := repairAgent(t, why, why, nil)

	// The way in a user takes, which prompts on purpose.
	agent.provisionRights(context.Background(), tunSettings(false), tunSettings(true))
	// What the write does next.
	if _, err := agent.prepareParams(context.Background(), tunParams()); err != nil {
		t.Fatalf("prepareParams: %v", err)
	}

	if len(*asked) != 1 {
		t.Errorf("turning the mode on raised %d password dialogs, want the one the user asked for", len(*asked))
	}
}

// The same for the card's own button, which is the other way a user asks for the dialog.
func TestPressingTheSetupButtonDoesNotRaiseASecondDialogOnTheNextRebuild(t *testing.T) {
	why := tsnode.WithNextStep(tsnode.ErrHelperFromAnotherBuild)
	agent, asked := repairAgent(t, why, why, nil)

	if err := agent.InterfaceSetup().SetUpInterface(context.Background()); err != nil {
		t.Fatalf("SetUpInterface: %v", err)
	}
	if _, err := agent.prepareParams(context.Background(), tunParams()); err != nil {
		t.Fatalf("prepareParams: %v", err)
	}

	if len(*asked) != 1 {
		t.Errorf("the button raised %d password dialogs, want the one the user pressed for", len(*asked))
	}
}

// The sentence this card leads with is the only thing that says why the mode is not doing
// anything, and the wrong one sends a user to change a setting that is already right. The
// case worth pinning is the mode that is neither this one nor userspace: with every
// connection on one interface, the tailnet is on an interface too, so saying it is kept
// inside app-tail is false.
func TestTheInterfaceCardSaysWhichOtherModeIsInForce(t *testing.T) {
	ready := httpapi.InterfaceView{Ready: true}
	supported := tsnode.InterfaceReport{Supported: true}

	tests := []struct {
		name     string
		settings config.Settings
		want     string
	}{
		{
			name:     "every connection on one interface",
			settings: config.Settings{InterfaceEnabled: true, InterfaceMode: config.NetworkFabric},
			want:     "every connection over one interface",
		},
		{
			name:     "the tailnet kept inside app-tail",
			settings: config.Settings{InterfaceEnabled: true, InterfaceMode: config.NetworkUserspace},
			want:     "keep the tailnet inside app-tail",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := interfaceCapability(tc.settings, ready, supported)
			if !strings.Contains(got.Reason, tc.want) {
				t.Errorf("the card says %q, want it to name %q", got.Reason, tc.want)
			}
			if !got.Available || !got.Degraded {
				t.Errorf("available = %v, degraded = %v; want a mode that is ready and not in force",
					got.Available, got.Degraded)
			}
		})
	}
}

// stuckAgent builds an agent whose node is up inside app-tail because this machine could
// not carry the network interface the settings ask for, which is the one state the
// recovery exists for. blocker is what the machine answers each time it is read.
func stuckAgent(t *testing.T, rec *recordingNodes, blocker func() error) *Agent {
	t.Helper()
	agent := newQuietAgent(t, rec.factory())
	agent.runtime.Settings = tunSettings(true)
	agent.preflight = func(context.Context, tsnode.ServerParams, func(string, ...any)) error {
		return blocker()
	}

	node := newFakeNode()
	node.mu.Lock()
	node.status.BackendState = tsnode.StateRunning
	node.status.Network = config.NetworkUserspace
	node.mu.Unlock()
	// Published the way a start publishes one, so a reconcile driven from here finds the
	// same node, manager and router beside each other that the running agent would.
	agent.publishNode(node,
		forward.NewManager(forwardNets{tunnels: agent.tunnels}, agent.settings, agent.logger),
		subnets.New(node, agent.primaryPrefs, agent.logger))
	agent.setNetworkFallback("the official Tailscale client is connected on this machine")
	return agent
}

// The mode is chosen when a node is built and never looked at again, so a machine that was
// busy at start keeps the tailnet inside app-tail for as long as the process lives. The
// blocker clears outside app-tail -- the other client is quit, the helper is installed --
// and nothing about that reaches this process, so the node is only moved by looking again.
func TestANodeStuckInsideAppTailMovesOntoTheInterfaceOnceTheMachineCanCarryOne(t *testing.T) {
	rec := &recordingNodes{}
	blocked := true
	agent := stuckAgent(t, rec, func() error {
		if blocked {
			return errors.New("the official Tailscale client is connected on this machine")
		}
		return nil
	})

	agent.recoverInterfaceMode(context.Background())
	if built := rec.snapshot(); len(built) != 0 {
		t.Fatalf("a machine that still cannot carry the mode had %d nodes rebuilt on it", len(built))
	}

	blocked = false
	agent.recoverInterfaceMode(context.Background())

	built := rec.snapshot()
	if len(built) != 1 {
		t.Fatalf("the cleared machine had %d nodes built, want exactly one replacement", len(built))
	}
	if got := built[0].params.Network; got != config.NetworkTUN {
		t.Errorf("the replacement was built for the %q mode, want the network interface", got)
	}
	if reason := agent.networkModeFallback(); reason != "" {
		t.Errorf("the node moved onto the interface and still reports %q", reason)
	}
}

// Everything the recovery must not do, each for its own reason: a rebuild costs the tailnet
// its identity for as long as it takes, so it happens only where it is the answer.
func TestTheNodeIsLeftAloneWhereARebuildWouldNotMoveItOntoTheInterface(t *testing.T) {
	ready := func() error { return nil }

	tests := []struct {
		name  string
		setUp func(*Agent)
	}{
		{
			// Reading the machine again cannot speak to a start that failed on a machine
			// that looked able, so retrying on it rebuilds the node on a schedule against
			// a reason no read will ever retire.
			"a start that failed rather than a machine that could not",
			func(a *Agent) { a.setStartFallback("open the network interface: operation not permitted") },
		},
		{
			// Nothing to recover: the node is on the interface the settings ask for.
			"a node already on the interface",
			func(a *Agent) {
				node := a.currentNode().(*fakeNode)
				node.mu.Lock()
				node.status.Network = config.NetworkTUN
				node.mu.Unlock()
			},
		},
		{
			// The contained mode is what these settings ask for, so the node is in the
			// mode it should be in.
			"settings that do not ask for the interface",
			func(a *Agent) { a.runtime.Settings = tunSettings(false) },
		},
		{
			// Nothing to move onto the interface. The next node built is built from the
			// settings, which already ask for it.
			"no node at all",
			func(a *Agent) {
				a.mu.Lock()
				a.node = nil
				a.mu.Unlock()
			},
		},
		{
			// A node that is not up is not a node in the wrong mode. Whatever is keeping
			// it down is what has to clear first, and rebuilding does not clear it.
			"a node that is not running",
			func(a *Agent) {
				node := a.currentNode().(*fakeNode)
				node.mu.Lock()
				node.status.BackendState = tsnode.StateNeedsLogin
				node.mu.Unlock()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordingNodes{}
			agent := stuckAgent(t, rec, ready)
			tc.setUp(agent)

			agent.recoverInterfaceMode(context.Background())

			if built := rec.snapshot(); len(built) != 0 {
				t.Errorf("%d nodes were rebuilt", len(built))
			}
			if got := agent.interfaceRecoveryWake(); got != 0 {
				t.Errorf("the loop is scheduled to look again in %s, so it rebuilds on a timer", got)
			}
		})
	}
}

// Reading the machine means opening a connection to the privileged side, and the blocker
// is usually a person: somebody who just quit the other client is watching, and a blocker
// still there after a quarter of an hour is one nobody is standing over.
func TestTheMachineIsReadOnASlowingScheduleWhileTheNodeIsStuck(t *testing.T) {
	rec := &recordingNodes{}
	agent := stuckAgent(t, rec, func() error {
		return errors.New("the official Tailscale client is connected on this machine")
	})

	first := agent.interfaceRecoveryWake()
	if first != interfaceRecheckFirst {
		t.Fatalf("the first read is scheduled in %s, want %s", first, interfaceRecheckFirst)
	}

	agent.recoverInterfaceMode(context.Background())
	if second := agent.interfaceRecoveryWake(); second <= first {
		t.Errorf("the second read is scheduled in %s, no later than the first at %s", second, first)
	}
	for range 10 {
		agent.recoverInterfaceMode(context.Background())
	}
	if got := agent.interfaceRecoveryWake(); got != interfaceRecheckMax {
		t.Errorf("a machine nobody is fixing is read every %s, want the ladder to stop at %s", got, interfaceRecheckMax)
	}

	// A fallback that clears ends the ladder rather than leaving the next one starting
	// from the rung this one reached.
	agent.setNetworkFallback("")
	if got := agent.interfaceRecoveryWake(); got != 0 {
		t.Fatalf("a node with nothing to recover is read again in %s, want no schedule at all", got)
	}
	agent.setNetworkFallback("the official Tailscale client is connected on this machine")
	if got := agent.interfaceRecoveryWake(); got != interfaceRecheckFirst {
		t.Errorf("the next fallback is read in %s, want the bottom rung at %s", got, interfaceRecheckFirst)
	}
}

// The recovery only ever runs from the loop's timer, so a stuck node that arms no timer is
// a recovery that never happens.
func TestTheLoopArmsItsTimerForANodeWaitingOnTheMachine(t *testing.T) {
	rec := &recordingNodes{}
	agent := stuckAgent(t, rec, func() error {
		return errors.New("the official Tailscale client is connected on this machine")
	})
	// The bottom rung, shortened so the test watches the schedule instead of waiting one
	// out. The agent is not running, so nothing else touches this.
	agent.interfaceRecovery.first = 20 * time.Millisecond

	wake := time.NewTimer(time.Hour)
	wake.Stop()
	agent.applyAndSchedule(context.Background(), wake)

	select {
	case <-wake.C:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop armed no timer for a node waiting on the machine, so it waits for a manual restart forever")
	}
}

// A rebuild gives up the running identity before it can fail, so a recovery that fails
// leaves the tailnet down. What went wrong is then the only account of why it stopped,
// and it is owed to the places a node's problem is already reported.
func TestARecoveryThatCannotRebuildTheNodeSaysWhy(t *testing.T) {
	rec := &recordingNodes{}
	agent := stuckAgent(t, rec, func() error { return nil })
	build := rec.factory()
	agent.newNode = func(o tsnode.Options) NodeController {
		node := build(o).(*fakeNode)
		node.startErr = errors.New("open the network interface: operation not permitted")
		return node
	}

	agent.recoverInterfaceMode(context.Background())

	if problem := agent.nodeProblem(); !strings.Contains(problem, "operation not permitted") {
		t.Errorf("the node reports %q after a rebuild that failed, so nothing says why the tailnet went away", problem)
	}
}
