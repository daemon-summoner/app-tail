// SPDX-License-Identifier: MIT

package app

// The connections module: what the stored document says about each private network this
// app attaches to, merged with what the live one is doing.
//
// The two halves come from two places on purpose. Configuration is in the store, so it
// survives a restart and a node that never came up; liveness is in the tunnel registry,
// so a connection that is configured and down is reported as configured and down rather
// than as missing. Merging them here is what stops a client from having to.

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// tunnelsAPI presents the connection list to the management API.
type tunnelsAPI struct{ a *Agent }

var _ httpapi.Tunnels = tunnelsAPI{}

// TunnelsAPI exposes the connection list.
func (a *Agent) TunnelsAPI() httpapi.Tunnels { return tunnelsAPI{a: a} }

// List returns every stored connection, in the order the document holds them, which is
// the order every surface lists them in.
func (t tunnelsAPI) List() []httpapi.TunnelView {
	app := t.a.settings()
	stored := t.a.store.Get().Tunnels
	out := make([]httpapi.TunnelView, 0, len(stored))
	for _, held := range stored {
		out = append(out, t.view(held, &app))
	}
	return out
}

func (t tunnelsAPI) Get(id string) (httpapi.TunnelView, error) {
	held, ok := t.a.store.Get().Tunnel(id)
	if !ok {
		return httpapi.TunnelView{}, fmt.Errorf("connection %q: %w", id, config.ErrNotFound)
	}
	app := t.a.settings()
	return t.view(held, &app), nil
}

func (t tunnelsAPI) Schema() []config.FieldSchema {
	s := t.a.settings()
	return t.a.fillOptions(config.TunnelSchema(&s))
}

// Types are the kinds of network a connection can be added as, in the order a picker
// offers them.
func (t tunnelsAPI) Types() []httpapi.TunnelTypeInfo {
	out := make([]httpapi.TunnelTypeInfo, 0, len(config.TunnelTypes))
	for _, kind := range config.TunnelTypes {
		if !t.a.startable[kind] {
			continue
		}
		out = append(out, httpapi.TunnelTypeInfo{Value: kind, Label: kind.Label()})
	}
	return out
}

// Create adds a connection. It is stored first and started by the reconcile that follows,
// which is the same order every other module comes up in: what is configured is a fact
// about the document, and what is running is a fact about this process.
func (t tunnelsAPI) Create(ctx context.Context, spec httpapi.TunnelSpec) (httpapi.TunnelView, error) {
	if !t.a.startable[spec.Type] {
		return httpapi.TunnelView{}, &config.ValidationError{
			Field: "type",
			Message: fmt.Sprintf("this build cannot bring up a %q connection; it can add %s",
				spec.Type, tunnelTypeList(t.a.startable)),
		}
	}
	id, err := config.NewTunnelID()
	if err != nil {
		return httpapi.TunnelView{}, err
	}

	name := strings.TrimSpace(spec.Name)
	if name == "" {
		name = spec.Type.Label()
	}
	if _, err := t.a.store.Update(func(c *config.Config) error {
		slug := spec.Slug
		if slug == "" {
			slug = config.SuggestSlug(name, slugsInUse(c.Tunnels))
		}
		c.Tunnels = append(c.Tunnels, config.NewTunnel(id, slug, name, spec.Type))
		return nil
	}); err != nil {
		return httpapi.TunnelView{}, err
	}

	t.adopt(ctx)
	return t.Get(id)
}

// Update applies a patch to one connection. The whole document is validated by the store,
// so a rename onto a slug another connection already answers for is refused here rather
// than discovered later by a resolver with two answers to one question.
//
// A write that moved the connection to another control server drops its stored credential
// (see config.Store.UpdateReporting); the view returned says so in Detail, since this
// answer is the only place the person who made the change is looking.
func (t tunnelsAPI) Update(ctx context.Context, id string, patch map[string]json.RawMessage) (httpapi.TunnelView, error) {
	app := t.a.settings()
	_, report, err := t.a.store.UpdateReporting(func(c *config.Config) error {
		for i := range c.Tunnels {
			if c.Tunnels[i].ID != id {
				continue
			}
			return config.ApplyTunnelPatch(&c.Tunnels[i], &app, patch)
		}
		return fmt.Errorf("connection %q: %w", id, config.ErrNotFound)
	}, config.CredentialWritesIn(id, patch)...)
	if err != nil {
		return httpapi.TunnelView{}, err
	}
	t.adopt(ctx)
	view, err := t.Get(id)
	if err != nil {
		return httpapi.TunnelView{}, err
	}
	for _, cleared := range report.ClearedCredentials {
		if cleared.TunnelID != id {
			continue
		}
		notice := cleared.Notice()
		t.a.logger.Warn(notice, "connection", id)
		sentence := strings.ToUpper(notice[:1]) + notice[1:] + "."
		if view.Detail == "" {
			view.Detail = sentence
		} else {
			view.Detail = sentence + " " + view.Detail
		}
	}
	return view, nil
}

// Import writes the configuration file a server issued onto one connection.
//
// The file replaces that connection's settings rather than merging with them: it describes a
// whole connection, and a resolver or a carried network left behind from a previous server
// would be a route this connection still claims with nothing on screen saying where it came
// from. What the file cannot be honoured for is refused before anything is written.
func (t tunnelsAPI) Import(ctx context.Context, id, file string) (httpapi.TunnelView, error) {
	held, ok := t.a.store.Get().Tunnel(id)
	if !ok {
		return httpapi.TunnelView{}, fmt.Errorf("connection %q: %w", id, config.ErrNotFound)
	}
	// Parsed before anything is written, and the settings it produces are carried into the
	// update as a closure so each kind writes its own block. The two file formats have
	// nothing in common but the fact that a server issues them.
	var apply func(into *config.Tunnel)
	switch held.Type {
	case config.TunnelWireGuard:
		imported, err := config.ParseWireGuardQuick(file)
		if err != nil {
			return httpapi.TunnelView{}, &config.ValidationError{Field: "file", Message: err.Error()}
		}
		apply = func(into *config.Tunnel) { into.WireGuard = &imported }
	case config.TunnelOpenVPN:
		imported, err := config.ParseOpenVPNFile(file)
		if err != nil {
			return httpapi.TunnelView{}, &config.ValidationError{Field: "file", Message: err.Error()}
		}
		apply = func(into *config.Tunnel) { into.OpenVPN = &imported }
	default:
		return httpapi.TunnelView{}, &config.ValidationError{
			Field: "file",
			Message: fmt.Sprintf("a configuration file can be imported into a WireGuard or an "+
				"OpenVPN connection; this one is %s", held.Type.Label()),
		}
	}

	if _, err := t.a.store.Update(func(c *config.Config) error {
		for i := range c.Tunnels {
			if c.Tunnels[i].ID != id {
				continue
			}
			apply(&c.Tunnels[i])
			return nil
		}
		return fmt.Errorf("connection %q: %w", id, config.ErrNotFound)
	}); err != nil {
		return httpapi.TunnelView{}, err
	}

	t.adopt(ctx)
	return t.Get(id)
}

// Retry builds one connection again now.
//
// It exists because a connection can be running and carrying nothing -- a WireGuard peer that
// stopped answering, an openvpn program that is up and signed out -- and an ordinary reconcile
// leaves that alone, because nothing about what the connection was built from has changed. The
// automatic ladder in supervise.go covers a connection that is down; this covers the one that
// is up and wrong, and gives somebody watching a way to say "now" instead of waiting out a
// backoff they cannot see.
func (t tunnelsAPI) Retry(ctx context.Context, id string) (httpapi.TunnelView, error) {
	held, ok := t.a.store.Get().Tunnel(id)
	if !ok {
		return httpapi.TunnelView{}, fmt.Errorf("connection %q: %w", id, config.ErrNotFound)
	}
	if why := whyNotRetryable(held, t.a.startable); why != "" {
		return httpapi.TunnelView{}, &config.ValidationError{Field: "id", Message: why}
	}

	t.a.askRetry(id)
	// Waited on rather than poked, so the answer describes the attempt that was asked for
	// instead of the state it was in before -- which is what lets the screen show the outcome
	// on the reply rather than a moment later.
	t.a.reconcileNow(ctx)
	return t.Get(id)
}

// whyNotRetryable is why a connection cannot be built again now, and the empty string when it
// can. It is one function rather than a rule in the refusal and another in the view, because
// those two disagreeing is a button that is offered and then says no.
func whyNotRetryable(held config.Tunnel, startable map[config.TunnelType]bool) string {
	switch {
	case held.ID == config.PrimaryTunnelID:
		return "the primary connection is brought up with this machine's own tailnet settings " +
			"rather than as one of the connections beside it. Switch the network off and on " +
			"again to build it afresh."
	case !held.Enabled:
		return fmt.Sprintf("%s is switched off. Switch it on to bring it up.", held.Name)
	case !startable[held.Type]:
		return fmt.Sprintf("%s is a %s connection, which this build cannot bring up on this "+
			"machine.", held.Name, held.Type.Label())
	}
	return ""
}

// Delete removes a connection and, through the reconcile it ends with, stops it.
func (t tunnelsAPI) Delete(ctx context.Context, id string) error {
	// Refused before the store is touched, because the refusal is about what this
	// connection is rather than about the document: the environment, the flags, a fleet
	// profile and every settings key that names the tailnet all write to the primary
	// connection, and a document without it refuses those inputs with nowhere to put them.
	if id == config.PrimaryTunnelID {
		return &config.ValidationError{
			Field: "id",
			Message: "the primary connection cannot be removed: it is where this " +
				"installation's own tailnet settings, environment variables and flags are " +
				"applied. Switch it off instead to stop it.",
		}
	}
	if _, err := t.a.store.Update(func(c *config.Config) error {
		for i, held := range c.Tunnels {
			if held.ID != id {
				continue
			}
			// A forward crossing this connection would be left naming a network that is not
			// there, which the document refuses -- and that refusal, arriving from the
			// validator, names a field rather than the thing the user has to do. Saying it
			// here is what turns it into an instruction. Deleting them instead is not on
			// offer: a forward is configuration somebody wrote, and taking it away as a side
			// effect of removing a network is not a choice to make on their behalf.
			if crossing := forwardsCrossing(c, id); len(crossing) > 0 {
				return &config.ValidationError{
					Field: "id",
					Message: fmt.Sprintf("%d forward(s) cross this connection (%s). Move them to "+
						"another connection or remove them first.", len(crossing), strings.Join(crossing, ", ")),
				}
			}
			// Same shape as the forwards above, and refused rather than cleared on the user's
			// behalf: clearing it would put every request this machine makes back on the ISP
			// link as a side effect of removing something else, which is the one outcome
			// choosing a connection for internet traffic exists to prevent.
			if c.Settings.EgressTunnel() == id {
				return &config.ValidationError{
					Field: "id",
					Message: fmt.Sprintf("this machine's internet traffic goes through %s. Point it "+
						"at another connection, or back out of this machine, before removing it.",
						held.Name),
				}
			}
			// Named in the set sharing internet traffic. Dropping it from the set here would
			// be the same silent widening: the remaining connections would take over its share
			// of the destinations without anybody saying so, and a set the user chose is a
			// statement about who may see the traffic rather than a list to edit for them.
			if members, spreadOn := c.Settings.EgressSpread(); spreadOn && slices.Contains(members, id) {
				return &config.ValidationError{
					Field: "id",
					Message: fmt.Sprintf("this machine's internet traffic is shared across %s. Take it "+
						"out of that set before removing it.", held.Name),
				}
			}
			c.Tunnels = append(c.Tunnels[:i], c.Tunnels[i+1:]...)
			return nil
		}
		return fmt.Errorf("connection %q: %w", id, config.ErrNotFound)
	}); err != nil {
		return err
	}

	t.adopt(ctx)
	return nil
}

// Peers are the devices on one connection, read from the node actually running it.
//
// The primary connection's node is the one the rest of the app is built on; every other
// connection has its own. Asking the right one is the whole point: two tailnets can hold
// devices with the same name, and answering from the wrong node would offer a device the
// selected network cannot reach.
func (t tunnelsAPI) Peers(ctx context.Context, id string) ([]tsnode.Peer, error) {
	if _, ok := t.a.store.Get().Tunnel(id); !ok {
		return nil, fmt.Errorf("connection %q: %w", id, config.ErrNotFound)
	}
	node := t.a.nodeOf(id)
	if node == nil {
		// Nothing is running this connection, so it has no device list rather than an empty
		// one. Saying so is what stops a form presenting "no devices" for a network that is
		// merely switched off.
		return nil, fmt.Errorf("connection %q: %w", id, tsnode.ErrNotRunning)
	}
	return node.Peers(ctx)
}

// nodeOf is the node running one connection, nil when nothing is.
func (a *Agent) nodeOf(id string) NodeController {
	if id == config.PrimaryTunnelID {
		if node := a.currentNode(); node != nil {
			return node
		}
		return nil
	}
	if running, ok := a.runningTunnel(id); ok {
		return running.node
	}
	return nil
}

// adopt republishes the connection list this process runs on and waits for the engine to
// act on it, so a caller that just wrote one is answered with what is running rather than
// with what was about to be started.
//
// Re-resolving is not optional bookkeeping: the precedence chain is what projects the
// environment and the flags onto the primary connection, and a runtime left holding the
// previous list would rebuild the node under the identity the write just replaced.
func (t tunnelsAPI) adopt(ctx context.Context) {
	if _, err := t.a.adoptSettings(); err != nil {
		// The write already succeeded and the document is valid -- Store.Update validated
		// it -- so this is the precedence chain failing on a document it just accepted.
		// Reported rather than returned: the connection exists, and the caller being told
		// its creation failed would leave them deleting something that is already there.
		t.a.logger.Error("could not re-read the connections after writing one", "error", err)
	}
	t.a.reconcileNow(ctx)
}

// forwardsCrossing names the stored forwards on one connection, as a refusal lists them.
// Only a handful are named: a message listing forty is one nobody reads.
func forwardsCrossing(c *config.Config, id string) []string {
	const shown = 3
	var names []string
	for _, f := range c.Forwards {
		if f.Connection() != id {
			continue
		}
		if len(names) == shown {
			names = append(names, "and others")
			break
		}
		label := f.Name
		if label == "" {
			label = config.Endpoint(f)
		}
		names = append(names, strconv.Quote(label))
	}
	return names
}

// slugsInUse is the set of DNS labels the stored connections already answer for.
func slugsInUse(tunnels []config.Tunnel) map[string]bool {
	taken := make(map[string]bool, len(tunnels))
	for _, held := range tunnels {
		taken[held.Slug] = true
	}
	return taken
}

// tunnelTypeList is every type a connection may be added as, as an error names them.
func tunnelTypeList(startable map[config.TunnelType]bool) string {
	names := make([]string, 0, len(config.TunnelTypes))
	for _, kind := range config.TunnelTypes {
		if startable[kind] {
			names = append(names, strconv.Quote(string(kind)))
		}
	}
	return strings.Join(names, ", ")
}

// view merges one stored connection with whatever the live one reports. app is the
// installation's settings, which a derived field of the connection may read: this
// machine's identity is part of the device name a connection renders.
func (t tunnelsAPI) view(held config.Tunnel, app *config.Settings) httpapi.TunnelView {
	out := httpapi.TunnelView{
		ID:        held.ID,
		Type:      held.Type,
		TypeLabel: held.Type.Label(),
		Name:      held.Name,
		Slug:      held.Slug,
		Enabled:   held.Enabled,
		Removable: held.ID != config.PrimaryTunnelID,
		Retryable: whyNotRetryable(held, t.a.startable) == "",
		Settings:  config.BuildTunnelView(held, app),
	}

	// A connection with nothing running under it is off, not broken. It is the state a
	// disabled connection is in and the state every connection is in before the agent has
	// finished starting, and reporting either as a failure would be a fault where there is
	// none.
	status := tunnel.Status{State: tunnel.StateOff}
	switch live, running := t.a.tunnels.Get(held.ID); {
	case running:
		status = live.Status()
		// Asked of the connection itself rather than derived from the status: only the kinds
		// that see their own packets, or are told about them by whatever does, count anything,
		// and a kind that counts nothing reports nothing here rather than zero.
		if metered, ok := live.(tunnel.Metered); ok {
			carried := metered.Carried()
			out.Health = &httpapi.TunnelHealth{
				Up:            carried.Up,
				Down:          carried.Down,
				Since:         carried.Since,
				LastHandshake: carried.LastHandshake,
				Dropped:       carried.Dropped,
			}
		}
	default:
		// A connection that is meant to be up and is not registered either failed to start
		// or has not been reached yet. The recorded reason is the only thing that tells
		// those apart, and without it a connection that cannot start reads as one that is
		// switched off -- a fault presented as a choice the user made.
		switch problem := t.a.tunnelProblem(held.ID); {
		case problem != "":
			status = tunnel.Status{State: tunnel.StateFailed, Detail: problem}
		case held.Enabled && !t.a.startable[held.Type]:
			// Only a document written by another version or edited by hand gets here, since
			// adding one of these is refused. It stays off rather than failed -- nothing is
			// broken -- but the reason is stated, or it reads as a connection that was
			// switched off by somebody.
			status.Detail = "This build cannot bring up a " + held.Type.Label() +
				" connection, so it is not running."
		}
	}
	out.State = string(status.State)
	out.StateLabel = status.State.Label()
	out.Live = status.State.Live()
	out.Detail = status.Detail
	out.AuthURL = status.AuthURL
	out.Addrs = status.Addrs
	out.Names = status.Names
	out.Limits = status.Limits
	if running, up := t.a.runningTunnel(held.ID); up && len(running.limits) > 0 {
		// A fresh slice: appending onto what the connection itself reported would write into
		// the tunnel's own backing array.
		out.Limits = append(append([]string{}, out.Limits...), running.limits...)
	}
	return out
}
