// SPDX-License-Identifier: MIT

package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/sysproxy"
	"github.com/sellitus/app-tail/internal/tsproxy"
)

// connectTimeout bounds the handshake with the local proxy. The proxy is on loopback,
// so a slower answer than this is a wedged agent, not a slow network. The tunnel it
// establishes is deliberately not bounded: an SSH session lasts as long as it lasts.
const connectTimeout = 30 * time.Second

// Proxy reads the tailnet proxy's state.
func (c *Client) Proxy(ctx context.Context) (httpapi.ProxyView, error) {
	var out httpapi.ProxyView
	err := c.do(ctx, http.MethodGet, "/api/proxy", nil, &out)
	return out, err
}

// SystemProxy reads what this machine's own proxy configuration says.
func (c *Client) SystemProxy(ctx context.Context) (httpapi.SystemProxyView, error) {
	var out httpapi.SystemProxyView
	err := c.do(ctx, http.MethodGet, "/api/proxy/system", nil, &out)
	return out, err
}

// ProbeProxy asks the agent to dial one destination through the proxy.
func (c *Client) ProbeProxy(ctx context.Context, address string) (httpapi.ProxyProbeResult, error) {
	var out httpapi.ProxyProbeResult
	body := map[string]string{"address": address}
	err := c.do(ctx, http.MethodPost, "/api/proxy/probe", body, &out)
	return out, err
}

// runProxy dispatches the proxy subcommands.
func runProxy(ctx context.Context, args []string, env Env) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return usagef("proxy needs a subcommand: status, system, connect or probe")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "status":
		return runProxyStatus(ctx, rest, env)
	case "system":
		return runProxySystem(ctx, rest, env)
	case "connect":
		return runProxyConnect(ctx, rest, env)
	case "probe":
		return runProxyProbe(ctx, rest, env)
	default:
		return usagef("unknown proxy subcommand %q; use status, system, connect or probe", sub)
	}
}

func runProxyStatus(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("proxy status", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "proxy status"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.Proxy(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, view)
	}

	if !view.Enabled {
		fmt.Fprintln(env.Stdout, "The tailnet proxy is off.")
		fmt.Fprintln(env.Stdout, "Turn it on with: app-tail settings set proxy.enabled true")
		return nil
	}
	if view.Listening == "" {
		fmt.Fprintf(env.Stdout, "The tailnet proxy is on but not listening: %s\n", view.Capability.Reason)
		return nil
	}

	rows := [][2]string{
		{"Listening", view.Listening},
		{"Carries", view.ScopeCarries},
		{"SOCKS5", view.SocksURL},
		{"HTTP", view.HTTPURL},
		{"Auto-config", view.PACURL},
		{"Connections", fmt.Sprintf("%d open, %d refused, %d failed",
			view.Counters.Active, view.Counters.Refused, view.Counters.Failed)},
	}
	if view.Capability.Degraded {
		rows = append(rows, [2]string{"Warning", view.Capability.Reason})
	}

	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		if row[1] == "" {
			continue
		}
		fmt.Fprintf(writer, "%s:\t%s\n", row[0], row[1])
	}
	if err := writer.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(env.Stdout)
	for _, s := range view.Snippets {
		fmt.Fprintf(env.Stdout, "%s:\n  %s\n", s.Label, strings.ReplaceAll(s.Command, "\n", "\n  "))
	}
	return nil
}

// runProxySystem reports, and can undo, the change the app makes to this machine's own
// proxy configuration.
//
// `off` is the reason this command exists rather than leaving the job to
// `settings set proxy.system false`: that needs a running agent, and the case a user is
// most likely to be in is the one where the agent is gone and the machine is still
// pointed at a port nothing answers on. So it asks the agent when there is one, and puts
// the setting back itself when there is not.
func runProxySystem(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("proxy system", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	rest, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(rest) > 1 || (len(rest) == 1 && rest[0] != "off") {
		return usagef("proxy system takes no argument, or `off` to put this machine's proxy settings back")
	}
	if len(rest) == 1 {
		if *asJSON {
			return usagef("proxy system off reports what it did in words; --json applies to `proxy system`")
		}
		return turnSystemProxyOff(ctx, loc, env)
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.SystemProxy(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, view)
	}
	printSystemProxy(env, view)
	return nil
}

func printSystemProxy(env Env, view httpapi.SystemProxyView) {
	switch {
	case view.Applied:
		fmt.Fprintf(env.Stdout, "This machine's proxy settings point at app-tail (%s).\n", view.AutoConfigURL)
		fmt.Fprintln(env.Stdout, "Put them back with: app-tail proxy system off")
	case !view.Supported:
		fmt.Fprintf(env.Stdout, "app-tail does not change proxy settings on %s: %s\n",
			config.PlatformLabel(view.Platform), view.Capability.Reason)
	case view.Enabled:
		fmt.Fprintf(env.Stdout, "The setting is on but not in force: %s\n", view.Capability.Reason)
	default:
		fmt.Fprintln(env.Stdout, "This machine's proxy settings are untouched.")
		if view.AutoConfigURL != "" {
			fmt.Fprintf(env.Stdout, "Something else points them at %s.\n", view.AutoConfigURL)
		}
	}

	for _, limit := range view.Capability.Limits {
		fmt.Fprintf(env.Stdout, "  - %s\n", limit)
	}
	if len(view.Manual) == 0 {
		return
	}
	fmt.Fprintln(env.Stdout)
	fmt.Fprintln(env.Stdout, "To change it yourself (`app-tail proxy status` lists the per-program ways):")
	for _, cmd := range view.Manual {
		fmt.Fprintf(env.Stdout, "%s:\n  %s\n", cmd.Label, cmd.Command)
	}
}

// turnSystemProxyOff puts this machine's proxy settings back and stops the agent from
// reapplying them.
//
// The stored setting is turned off first: restoring while the setting is still on would
// have the next reconcile undo the restore, and a user running this twice and watching
// it not take is worse than either failure alone.
func turnSystemProxyOff(ctx context.Context, loc location, env Env) error {
	client, err := loc.connect(env)
	if err == nil {
		// Reaching the agent is the request, not the constructor: connect only reads a
		// recorded address, so a stopped agent surfaces here -- and that case is the one
		// this command exists for, not a failure to report.
		view, viewErr := client.SystemProxy(ctx)
		if errors.Is(viewErr, ErrNoAgent) {
			err = viewErr
		} else if viewErr != nil {
			return viewErr
		} else {
			return turnSystemProxyOffViaAgent(ctx, client, view, env)
		}
	}

	// No agent to ask. The setting still has to be cleared, or starting the app again
	// would point this machine straight back at a proxy the user just took it off.
	store, stateDir, storeErr := loc.storeAndDir(env)
	if storeErr != nil {
		// Both causes are wrapped: either one alone explains nothing, since the whole
		// point of this path is that the agent was unreachable.
		return fmt.Errorf("no running agent (%w) and the stored settings could not be opened: %w", err, storeErr)
	}
	if _, storeErr := store.Update(func(c *config.Config) error {
		c.Settings.ProxySystem = false
		return nil
	}); storeErr != nil {
		return fmt.Errorf("turn the setting off in %s: %w", store.Path(), storeErr)
	}

	if err := sysproxy.New(stateDir, slog.New(slog.DiscardHandler)).Clear(); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "This machine's proxy settings have been put back, without a running agent.")
	return nil
}

// turnSystemProxyOffViaAgent hands the job to the running agent, which owns both the
// stored setting and the restore record.
func turnSystemProxyOffViaAgent(ctx context.Context, client *Client, view httpapi.SystemProxyView, env Env) error {
	if !view.Supported {
		// Nothing here ever wrote the setting, so there is nothing to put back and the
		// write below would be refused as a setting this platform does not offer.
		fmt.Fprintf(env.Stdout, "app-tail does not change proxy settings on %s, so there is nothing to put back.\n",
			config.PlatformLabel(view.Platform))
		return nil
	}
	patch := map[string]json.RawMessage{"proxy.system": json.RawMessage(`false`)}
	if _, err := client.UpdateSettings(ctx, patch); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "This machine's proxy settings have been put back.")
	return nil
}

func runProxyProbe(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("proxy probe", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	rest, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return usagef("proxy probe needs one destination, as HOST:PORT")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	result, err := client.ProbeProxy(ctx, rest[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, result)
	}

	if !result.Reachable {
		return fmt.Errorf("%s is not reachable through the proxy: %s", result.Address, result.Error)
	}
	via := "outside the tailnet"
	if result.ViaTailnet {
		via = "through the tailnet"
	}
	fmt.Fprintf(env.Stdout, "%s is reachable %s at %s (%dms)\n",
		result.Address, via, result.ResolvedAddr, result.ElapsedMs)
	return nil
}

// runProxyConnect pipes stdin and stdout through the proxy to one destination.
//
// This is what makes `ssh -o ProxyCommand="app-tail proxy connect %h %p"` work
// identically on macOS, Linux and Windows -- the usual `nc -X 5` recipe does not exist
// on Windows, and neither does a shell that could substitute one.
func runProxyConnect(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("proxy connect", env)
	loc := addLocationFlags(fs)
	rest, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 2 {
		return usagef("proxy connect needs a host and a port, as `app-tail proxy connect HOST PORT`")
	}
	host, port := rest[0], rest[1]
	if _, err := strconv.Atoi(port); err != nil {
		return usagef("port %q is not a number", port)
	}

	client, store, err := loc.connectWithStore(env)
	if err != nil {
		return err
	}
	view, err := client.Proxy(ctx)
	if err != nil {
		return err
	}
	if view.Listening == "" {
		return proxyNotListening(view)
	}

	password := ""
	if view.RequiresPassword {
		password = proxyPassword(store)
		if password == "" {
			return errors.New("the proxy requires a password but none is stored; set one with `app-tail settings set proxy.token`")
		}
	}

	var d net.Dialer
	upstream, err := connectThrough(ctx, d.DialContext, view.Listening, net.JoinHostPort(host, port), password)
	if err != nil {
		return err
	}
	defer upstream.Close()

	return pipe(env, upstream)
}

// dialFunc opens the connection to the proxy's front end. It is a parameter rather than a
// direct net.Dialer call because every failure after the dial has to give the socket back,
// and a stand-in dialer is the only way to reach those paths from a test.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// connectThrough opens a tunnel to address through the proxy's HTTP front end.
func connectThrough(ctx context.Context, dial dialFunc, proxyAddr, address, password string) (_ net.Conn, err error) {
	dialCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	conn, err := dial(dialCtx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("reach the app-tail proxy at %s: %w", proxyAddr, err)
	}
	// The caller is handed the socket only on the last line, so anything that goes wrong
	// between here and there closes it. A leaked one holds a port on the proxy for as
	// long as this process lives.
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	req, err := http.NewRequestWithContext(dialCtx, http.MethodConnect, "http://"+address, nil)
	if err != nil {
		return nil, fmt.Errorf("build the tunnel request for %s: %w", address, err)
	}
	req.Host = address
	if password != "" {
		req.SetBasicAuth(tsproxy.ProxyUser, password)
		req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
		req.Header.Del("Authorization")
	}
	if err = req.Write(conn); err != nil {
		return nil, fmt.Errorf("ask the proxy for %s: %w", address, err)
	}

	// The reader is buffered, so anything it read past the response header belongs to
	// the tunnel. Discarding it would silently drop the first bytes a peer sent.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("read the proxy's answer for %s: %w", address, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, tunnelRefused(address, resp)
	}
	if br.Buffered() == 0 {
		return conn, nil
	}
	return &bufferedConn{Conn: conn, r: io.MultiReader(io.LimitReader(br, int64(br.Buffered())), conn)}, nil
}

// tunnelRefused turns the proxy's refusal into the sentence it gave, since the proxy
// already knows which of "the node is down" and "that is out of scope" applies and the
// two call for opposite actions.
func tunnelRefused(address string, resp *http.Response) error {
	reason := resp.Header.Get(tsproxy.ConnectErrorHeader)
	if reason == "" {
		// A body that cannot be read is simply not a reason; the status line below is
		// what covers that case.
		if body, err := io.ReadAll(io.LimitReader(resp.Body, 4096)); err == nil {
			reason = strings.TrimSpace(string(body))
		}
	}
	if reason == "" {
		reason = resp.Status
	}
	return fmt.Errorf("the proxy refused %s: %s", address, reason)
}

// bufferedConn replays bytes the response reader consumed ahead of the tunnel.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// pipe copies between the caller's stdio and the tunnel until either end finishes.
//
// The upstream half is what decides the command is over: stdin on a pipe may never
// reach EOF, so waiting for both would hang after the peer hung up.
func pipe(env Env, upstream net.Conn) error {
	var once sync.Once
	done := make(chan error, 2)
	finish := func(err error) { once.Do(func() { done <- err }) }

	go func() {
		_, err := io.Copy(upstream, env.Stdin)
		// A half close tells the peer the request is over while its answer is still
		// arriving, which is what a request-then-response protocol needs.
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			if cerr := cw.CloseWrite(); cerr != nil && err == nil {
				err = cerr
			}
		}
		if err != nil && !isClosed(err) {
			finish(fmt.Errorf("send to the peer: %w", err))
		}
	}()

	go func() {
		_, err := io.Copy(env.Stdout, upstream)
		if err != nil && !isClosed(err) {
			finish(fmt.Errorf("receive from the peer: %w", err))
			return
		}
		finish(nil)
	}()

	return <-done
}

// isClosed reports the ordinary end of a tunnel, which is not a failure to report.
func isClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed)
}

// runExec runs a command with every proxy variable set, and nothing else on the machine
// changed. It is the zero-configuration way to use the tailnet from a program that has
// no proxy setting of its own.
func runExec(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("exec", env)
	loc := addLocationFlags(fs)
	// The scope is a property of the proxy, not of one connection: SOCKS5 has no
	// channel to carry a per-connection one. This flag therefore refuses to run rather
	// than widening the proxy for everything else on the machine -- and a widening that
	// had to be undone afterwards would stay in force if this process were killed.
	scope := fs.String("scope", "", "refuse to run unless the proxy's scope is `tailnet` or all")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return usagef("exec needs a command to run, as `app-tail exec -- curl https://peer.your-tailnet.ts.net/`")
	}

	client, store, err := loc.connectWithStore(env)
	if err != nil {
		return err
	}
	view, err := client.Proxy(ctx)
	if err != nil {
		return err
	}
	if view.Listening == "" {
		return proxyNotListening(view)
	}
	if err := scopeSatisfies(*scope, view.Scope); err != nil {
		return err
	}

	password := ""
	if view.RequiresPassword {
		stored := proxyPassword(store)
		if stored == "" {
			return errors.New("the proxy requires a password but none is stored; set one with `app-tail settings set proxy.token`")
		}
		// The child is pointed at a proxy of its own rather than at this account's, so the
		// password that opens this account's proxy is never written into an environment the
		// child, everything it starts, and anything that dumps one can read.
		relay, err := tsproxy.StartRelay(view.Listening, stored, execLogger(env))
		if err != nil {
			return err
		}
		defer relay.Close()
		view.Listening, password = relay.Addr(), relay.Password()
	}

	cmd := exec.CommandContext(ctx, rest[0], rest[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = env.Stdin, env.Stdout, env.Stderr
	cmd.Env = append(os.Environ(), proxyEnv(view, password)...)

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// The child ran and chose its own status. Reporting that as an app-tail
			// failure would make every non-zero exit look like a proxy problem.
			return &ExitError{Code: exitErr.ExitCode()}
		}
		return fmt.Errorf("run %s: %w", rest[0], err)
	}
	return nil
}

// execLogger carries the failures of the proxy standing in front of the command to the
// terminal that started it. It is set at warning level: a refused connection is already
// reported to the program that asked for it, and repeating every one here would bury the
// command's own output.
func execLogger(env Env) *slog.Logger {
	return slog.New(slog.NewTextHandler(env.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// ExitError carries a child process's exit status so the shell sees what it would have
// seen without app-tail in front of it.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("the command exited with status %d", e.Code) }

// proxyEnv is every variable a program might read, in the forms each expects.
func proxyEnv(view httpapi.ProxyView, password string) []string {
	cfg := tsproxy.SnippetConfig{ProxyAddr: view.Listening, RequiresPassword: password != ""}
	socks, httpProxy := tsproxy.SOCKSURL(cfg), tsproxy.HTTPURL(cfg)
	if password != "" {
		socks = withPassword(socks, password)
		httpProxy = withPassword(httpProxy, password)
	}

	// Loopback stays off the proxy, and so does the dashboard: without it a child that
	// calls the app-tail API sends that call through the proxy back to this machine.
	noProxy := "localhost,127.0.0.1,::1"
	if host := hostOf(view.PACURL); host != "" {
		noProxy += "," + host
	}

	out := []string{}
	for _, name := range []string{"ALL_PROXY", "all_proxy"} {
		out = append(out, name+"="+socks)
	}
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		out = append(out, name+"="+httpProxy)
	}
	for _, name := range []string{"NO_PROXY", "no_proxy"} {
		out = append(out, name+"="+noProxy)
	}
	return out
}

// withPassword substitutes the real credential for the stand-in the API hands out.
func withPassword(rawURL, password string) string {
	return strings.Replace(rawURL, ":PASSWORD@", ":"+password+"@", 1)
}

// hostOf pulls the authority out of a URL without failing on an empty one.
func hostOf(rawURL string) string {
	rest, found := strings.CutPrefix(rawURL, "http://")
	if !found {
		return ""
	}
	host, _, _ := strings.Cut(rest, "/")
	return host
}

// scopeSatisfies refuses ahead of time when the proxy's rules plainly cannot carry what
// the caller requires.
//
// It refuses only what it knows: the proxy itself decides every destination against its
// own rules and names the rule that decided, so a rule set this cannot summarise is passed
// through rather than guessed at. Refusing on a guess would block a program the proxy would
// have carried, which is worse than letting the proxy answer.
func scopeSatisfies(required, actual string) error {
	if required == "" {
		return nil
	}
	switch config.ProxyScope(required) {
	case config.ScopeTailnet:
		// Every summarised scope carries one whole connection, so this is satisfied.
		return nil
	case config.ScopeAll:
		if config.ProxyScope(actual) != config.ScopeTailnet {
			return nil
		}
		return fmt.Errorf(
			"the proxy carries one connection and not this machine's own network, but --scope all " +
				"was required; give it a rule that reaches this machine (this changes the proxy for " +
				"every program using it, which is why it is not done for one command)")
	default:
		return usagef("unknown scope %q; use tailnet or all", required)
	}
}

// proxyPassword is the stored password for the default proxy, which is the instance every
// single-proxy command speaks to. Empty when the instance is gone or holds no password,
// which the caller reports in the terms that say what to set.
func proxyPassword(store *config.Store) string {
	held, ok := store.Get().Proxy(config.DefaultProxyID)
	if !ok {
		return ""
	}
	return held.Token
}

// proxyNotListening explains a proxy that cannot be used, in the terms that say what
// to do about it.
func proxyNotListening(view httpapi.ProxyView) error {
	if !view.Enabled {
		return errors.New("the tailnet proxy is off; turn it on with `app-tail settings set proxy.enabled true`")
	}
	reason := view.Capability.Reason
	if reason == "" {
		reason = "it is switched on but not listening"
	}
	return fmt.Errorf("the tailnet proxy is not usable: %s", reason)
}
