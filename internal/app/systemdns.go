// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsfwd"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/sockerr"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// systemDNSRunner owns the machine-wide resolver: the claim on this machine's name
// resolution, the loopback sockets queries arrive on, and the forwarder that answers them.
//
// It is separate from the tailnet node and outlives it. A node rebuild, a sign-out, or
// every Tailscale module being switched off changes nothing here: the machine's resolver is
// this app's second machine-level feature and it stands on its own.
//
// Everything below runs on the lifecycle goroutine except the view, which request
// goroutines read, so the mutex guards the whole thing rather than one field.
type systemDNSRunner struct {
	logger *slog.Logger
	// open claims this machine's name resolution. It is a seam because the real one asks
	// for administrator rights, which a test suite must never do.
	open func(ctx context.Context, logf func(format string, args ...any)) (tsnode.SystemDNSRights, error)
	// probe asks whether this network answers plain DNS itself. It is a seam because the
	// real one puts a packet on the network, which a test suite must not depend on.
	probe func(ctx context.Context) (bool, error)
	// question hands every name asked about to traffic inspection, which reads a run of
	// them rather than any one. Nil is a runner built without inspection, which is what a
	// test that is about resolution gets.
	question func(name string)

	mu sync.Mutex

	rights tsnode.SystemDNSRights
	fwd    *dnsfwd.Forwarder
	// serving is what every serve loop runs under, and stopServing ends all of them, which
	// close their sockets on the way out.
	serving     context.Context
	stopServing context.CancelFunc
	// listen is the socket opened for the listen setting, and wanted the address it was
	// asked for, so a changed setting is noticed even when the helper had to land somewhere
	// else.
	listen resolverSocket
	wanted netip.AddrPort
	// spare answers exactly as listen does on a second address, opened the first time the
	// answers change. Moving this machine from one to the other is what makes every cache on
	// it drop what the old answers left: flushing reaches the system's own cache alone, and a
	// browser with a DNS client of its own lets go of its cache only when the resolver
	// address it was configured with changes.
	spare resolverSocket
	// retired are sockets still answering because this machine may be pointed at them,
	// closed once it has been pointed somewhere else.
	retired []resolverSocket
	// pointed is the address this machine was last pointed at, and answers what the
	// forwarder answered from when it was.
	pointed netip.Addr
	answers answerSource

	// resolvers is the fingerprint of what the pools were built from -- the profile's
	// servers and the network's own resolvers. Rebuilding on every reconcile would drop a
	// live DNS-over-TLS connection every few seconds.
	resolvers string

	// applied reports the override really installed on this machine, profile the one it
	// was installed for, and base what this machine resolves with underneath it.
	applied bool
	profile config.DNSProfile
	base    tsnode.BaseResolvers

	// reason is why the machine is not pointed at app-tail, and failure the last thing
	// that went wrong trying. unreachable is the profile answering nothing, which is the
	// shape of walking onto a network that wants you to sign in first.
	reason      string
	failure     string
	unreachable string

	// retry says the last pass wanted the override and could not put it up for a reason a
	// later pass may not meet: a resolver hostname the network did not answer for yet, a
	// socket that would not bind. It is what arms the timer that comes back for it.
	retry bool

	// partial says the last failure was a restore that reached every network service it
	// could. The machine is as far back as it can be put until those services return, and
	// the record app-tail left names them, so this is reported and not exited on.
	partial bool

	// intercepted is this network answering plain DNS itself, checked whenever a profile
	// with a plain resolver is built. It is the difference between "your queries go to the
	// server you picked" and "they go wherever this network sends port 53", and without it
	// the card reports a switch that took effect while nothing about resolution changed.
	intercepted string

	// bootstrap is how the hostnames in the chosen profile were turned into addresses, empty
	// when the profile has none. It is reported because the two paths are not equivalent: an
	// encrypted bootstrap decides the address by certificate, and the fallback to this
	// network's own resolvers hands that decision to the network. bootstrapDegraded is that
	// second path having been taken without the user asking for it, which is a warning rather
	// than a note.
	bootstrap         string
	bootstrapDegraded bool
}

// systemDNSTarget is what the settings ask for, resolved against the profile catalog.
type systemDNSTarget struct {
	on      bool
	profile config.DNSProfile
	rules   dnsfwd.Rules
	// tunnels resolves a name inside one of app-tail's own connections, for the names the
	// rules say this machine reaches by address.
	tunnels dnsfwd.TunnelResolver
	retry   bool
	// blocking names the set of names the blocklist stops, zero while it stops none.
	blocking uint64
	listen   netip.AddrPort
	// bootstrap is the profile whose resolvers look up a resolver named by hostname. It is
	// zero when the network's own resolvers are to do it, which is both what the System
	// default profile means here and what an unusable choice falls back to.
	bootstrap config.DNSProfile
	// bootstrapWhy is why bootstrap is zero, when it is zero for a reason worth reporting
	// rather than because the user chose System default.
	bootstrapWhy string
	// reason is why nothing should be applied, and is what the card shows while the
	// override is off.
	reason string
}

func newSystemDNSRunner(logger *slog.Logger, open func(ctx context.Context, logf func(format string, args ...any)) (tsnode.SystemDNSRights, error),
	question func(name string)) *systemDNSRunner {

	return &systemDNSRunner{logger: logger, open: open, probe: dnsfwd.PlainDNSIntercepted, question: question}
}

// applySystemDNS points this machine's resolver at app-tail, or puts it back.
//
// It runs first in the reconcile and is the one step that ignores whether the tailnet node
// is up: a machine that is signed out, or that has every tailnet feature switched off, must
// still resolve names.
func (a *Agent) applySystemDNS(ctx context.Context) {
	runner := a.currentSystemDNS()
	if runner == nil {
		return
	}
	runner.apply(ctx, a.systemDNSTarget(ctx))
}

// systemDNSTarget reads the settings and the catalog into what the runner should do.
func (a *Agent) systemDNSTarget(ctx context.Context) systemDNSTarget {
	c := a.store.Get()
	s := c.Settings

	// The connections this process runs rather than the stored list, and the settings it runs
	// with, so the suffixes the resolver claims are the ones the route lookup answers for.
	held := a.runtimeTunnels()
	suffixes := tunnelSuffixesOf(held, a.settings())
	// Which of them this machine reaches by address, which is what decides between answering
	// a name on a connection and refusing it. It is read from what the interface is really
	// carrying rather than from the mode that was asked for: a mode that is on and has not
	// come up yet reaches nothing, and claiming otherwise would answer names with addresses
	// that go nowhere.
	table, carried := a.fabricAddressing()
	for i := range suffixes {
		suffixes[i].Carried = carried[suffixes[i].ID]
	}

	target := systemDNSTarget{
		retry: s.SystemDNSRetryOnNXDOMAIN,
		rules: dnsfwd.Rules{
			LocalSuffixes:   slices.Clone(s.SystemDNSLocalSuffixes),
			TunnelSuffixes:  suffixes,
			VirtualPrefixes: virtualPrefixesOf(table, held),
		},
		tunnels: fabricResolver{a: a},
	}
	// Set whether or not the machine-wide resolver is on: the rules are built here for
	// every pass, and a matcher left out of them is a switch that reads as on and blocks
	// nothing. The runner answers nothing while blocking is off or paused.
	if block := a.blocklistTarget(); block.system {
		if runner := a.currentBlocklists(); runner != nil {
			target.rules.Block = runner
			target.rules.BlockAnswer = block.answer
			target.blocking = runner.blocking()
		}
	}
	if !s.SystemDNSEnabled {
		target.reason = "the machine-wide resolver is switched off, so this machine resolves names the way it always did"
		return target
	}

	id := s.SystemDNSProfile
	if id == "" {
		id = config.DefaultSystemDNSProfile
	}
	profile, ok := dnsprofiles.ByID(c.DNSProfiles, id)
	if !ok {
		target.reason = fmt.Sprintf("the chosen resolver profile (%q) no longer exists, so this machine's own resolver is left alone", id)
		return target
	}
	target.profile = profile
	if profile.ID == dnsprofiles.SystemID {
		target.reason = "the chosen profile is System default, which leaves this machine exactly as it is"
		return target
	}
	if dnsprofiles.NeedsTailnet(profile.ID) {
		servers, err := a.tailnetResolvers(ctx)
		if err != nil {
			// The machine is left resolving the way it already does. Pointing it at a
			// profile with no resolvers would be pointing it at nothing at all, and this is
			// the ordinary state of a machine that is signed out or still starting.
			target.reason = err.Error()
			return target
		}
		target.profile.Servers = servers
	}

	listen, err := netip.ParseAddrPort(s.SystemDNSListenAddr)
	if err != nil {
		// The registry refuses an unparseable address at write time, so reaching here means
		// a hand-edited document. Falling back to the default beats refusing to resolve.
		a.logger.Warn("the address to listen for DNS on could not be read; using the default",
			"value", s.SystemDNSListenAddr, "error", err)
		listen = netip.MustParseAddrPort(config.DefaultSystemDNSListenAddr)
	}
	target.listen = listen
	target.bootstrap, target.bootstrapWhy = a.bootstrapProfile(ctx, c)
	target.on = true
	return target
}

// bootstrapProfile is the profile whose resolvers turn a hostname upstream into an address,
// and why it is not the one the settings name when it is not.
//
// A zero profile means the network's own resolvers do it. That is the honest fallback rather
// than a failure: the alternative to a bootstrap that cannot be reached is not resolving
// anything at all, and on a network that wants you to sign in first, its own resolver is the
// only one that answers. What it is never allowed to be is quiet, which is what the reason
// carried alongside it is for.
func (a *Agent) bootstrapProfile(ctx context.Context, c *config.Config) (config.DNSProfile, string) {
	id := c.Settings.SystemDNSBootstrapProfile
	if id == "" {
		id = config.DefaultSystemDNSBootstrapProfile
	}
	if id == dnsprofiles.SystemID {
		return config.DNSProfile{}, ""
	}
	profile, ok := dnsprofiles.ByID(c.DNSProfiles, id)
	if !ok {
		return config.DNSProfile{}, fmt.Sprintf("the profile chosen to look resolver hostnames up through (%q) no longer exists", id)
	}
	if dnsprofiles.NeedsTailnet(profile.ID) {
		servers, err := a.tailnetResolvers(ctx)
		if err != nil {
			return config.DNSProfile{}, fmt.Sprintf("%s cannot look resolver hostnames up: %v", profile.Name, err)
		}
		profile.Servers = servers
	}
	if len(dnsprofiles.Dialable(profile)) == 0 {
		// Every resolver in it is named by a hostname, so it would need the lookup it is
		// there to perform. Nothing about this is recoverable at run time -- it is a profile
		// the user has to edit -- so it says which profile and why.
		return config.DNSProfile{}, fmt.Sprintf("%s cannot look resolver hostnames up: every resolver in it is named by a hostname, which would need the lookup it is there to do", profile.Name)
	}
	return profile, ""
}

// tailnetResolvers reads the nameservers the tailnet publishes, which is what the Tailnet
// DNS profile resolves through.
//
// They are read on every pass rather than stored: the admin console is where they are
// changed, and a copy kept in this machine's configuration would go stale the moment
// somebody changed them for the tailnet. Every failure names what is missing, because each
// one is a state the user can act on -- sign in, wait for the node, or configure a
// nameserver in the admin console.
func (a *Agent) tailnetResolvers(ctx context.Context) ([]string, error) {
	node := a.currentNode()
	if node == nil || !node.Status().Running() {
		return nil, fmt.Errorf("the Tailnet DNS profile resolves through your tailnet's own nameservers, and the tailnet node is not running")
	}
	tailnet, err := node.TailnetDNS(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the nameservers your tailnet publishes: %w", err)
	}

	listen := a.settings().SystemDNSListenAddr
	out := make([]string, 0, len(tailnet.Resolvers))
	for _, server := range tailnet.Resolvers {
		u, err := dnsprofiles.ParseUpstream(server)
		if err != nil {
			// A resolver the admin console accepted and this grammar does not is worth
			// saying out loud once: it is the one entry that will be missing from the list
			// the card shows, and silence would make that look like the tailnet's doing.
			a.logger.Warn("a nameserver your tailnet publishes cannot be used", "server", server, "error", err)
			continue
		}
		if addr, ok := u.Endpoint(); ok && addr.String() == listen {
			// app-tail's own listen address. Forwarding to it would be this forwarder
			// asking itself, which answers nothing and holds the query until it times out.
			a.logger.Warn("your tailnet publishes app-tail's own resolver address, which app-tail will not forward to itself", "server", server)
			continue
		}
		out = append(out, server)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("your tailnet publishes no nameserver app-tail can resolve through; add one in the Tailscale admin console under DNS, or pick another profile")
	}
	if len(out) > dnsprofiles.MaxServers {
		// The pool tries them in order and a long list is a long wait before the first
		// answer; the ones past the limit would only ever be reached with everything ahead
		// of them down.
		out = out[:dnsprofiles.MaxServers]
	}
	return out, nil
}

// underlying is what this machine resolves with beneath the override, and whether the
// override is really installed. It is what a caller that must not ask app-tail's own
// resolver -- the blocklist downloader -- resolves through instead.
func (r *systemDNSRunner) underlying() (tsnode.BaseResolvers, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.base, r.applied
}

// needsAnotherPass reports the machine pointed at app-tail with nothing behind the address,
// or an override that was wanted and could not be put up.
//
// The first is what a serve loop stopping on its own leaves: the override stands, so every
// name asked about on this machine goes to a socket nobody is reading. The second is a pass
// that failed on something the next one may find changed -- a network that was not up when
// the profile's resolver hostnames were looked up. The reconcile loop is event-driven, so
// without this term in downCount no timer is ever armed, and on an idle machine the card
// shows the failure until something else happens to ask for a pass.
func (r *systemDNSRunner) needsAnotherPass() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return (r.applied && r.fwd == nil) || r.retry
}

func (a *Agent) currentSystemDNS() *systemDNSRunner {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.systemDNS
}

// apply brings the machine to the target state. Every failure leaves the machine resolving
// names some way -- either through app-tail or through what it had before -- and says what
// went wrong on the card rather than in a log nobody opens.
func (r *systemDNSRunner) apply(ctx context.Context, target systemDNSTarget) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.retry = false
	if !target.on {
		r.release(ctx, target.reason)
		return
	}

	// A claim refused is rights this process does not have, which no timer changes: the
	// elevation flow asks for a pass when it has them. Everything after it is retried.
	if err := r.claim(ctx); err != nil {
		r.failure = err.Error()
		r.reason = err.Error()
		r.applied = false
		return
	}
	if err := r.bind(ctx, target.listen); err != nil {
		r.failure = err.Error()
		r.reason = err.Error()
		r.applied = false
		r.retry = true
		return
	}

	base, err := r.rights.Base(ctx)
	if err != nil {
		// Keep whatever was read last: a base list that went unreadable for one pass is a
		// network in the middle of changing, and dropping the network's own resolvers would
		// send this machine's private names to a public resolver.
		r.logger.Warn("reading this machine's own resolvers failed", "error", err)
		r.failure = fmt.Sprintf("this machine's own resolvers could not be read: %v", err)
		base = r.base
	} else {
		r.failure = ""
	}
	r.base = base

	if target.profile.ID != r.profile.ID {
		// A different profile has its own reachability; carrying the last one's failure
		// over would put a stale warning on a resolver nobody has asked anything yet.
		r.unreachable = ""
	}
	if err := r.configure(ctx, target, base); err != nil {
		r.failure = resolverFailure(err)
		r.reason = r.failure
		r.applied = false
		r.retry = true
		return
	}

	answers := answersOf(target)
	point, stayed := r.pointAt(ctx, answers)
	if err := r.rights.Apply(ctx, []netip.Addr{point}); err != nil {
		r.logger.Warn("pointing this machine at app-tail's resolver failed", "error", err)
		// Undo the part that landed. The record is written before the first service is touched
		// and the apply goes on to every service after one fails, so "some of them pointed at
		// app-tail, the rest not, and an error returned" is a real state -- and one this
		// runner would otherwise carry as applied=false, which is what sends the agent's own
		// lookups back through net.DefaultResolver and into the forwarder this pass never
		// finished configuring.
		// An undo that fails too is the state the card most needs to describe -- some
		// services pointed at app-tail with nothing about to put them back -- so both are
		// named rather than the first alone.
		if restoreErr := r.rights.Restore(ctx); restoreErr != nil {
			r.logger.Warn("undoing a resolver override that only partly landed failed", "error", restoreErr)
			err = fmt.Errorf("%w; undoing the part that landed failed too: %w", err, restoreErr)
		}
		r.applied = false
		r.failure = err.Error()
		r.reason = fmt.Sprintf("this machine's resolver could not be changed: %v", err)
		r.retry = true
		return
	}
	r.applied = true
	r.pointed, r.answers = point, answers
	r.profile = target.profile
	r.reason = ""
	if stayed != nil {
		// Reported rather than retried: every name is answered the new way, and what is left
		// is programs answering from their own caches until those expire.
		r.logger.Warn("the answers changed and this machine stayed on the same resolver address", "error", stayed)
		if r.failure != "" {
			r.failure += "; "
		}
		r.failure += stayed.Error()
	}
	// Only now: until the machine was pointed away from them, these were answering for it.
	for _, s := range r.retired {
		s.stop()
	}
	r.retired = nil
}

// pointAt picks the address to point this machine at, and says why it is the same address
// when the answers changed and it could not be another.
//
// While the answers stay the same it is wherever the machine already points, since
// rewriting every network service's resolver costs seconds. When they change it is the other
// of the two addresses: what the caches on this machine hold came from the old answers, and
// a changed resolver address is the one signal every one of them drops its cache on. A
// machine that is not pointed here yet gets that change from the move itself.
func (r *systemDNSRunner) pointAt(ctx context.Context, answers answerSource) (netip.Addr, error) {
	here := r.listen.addr.Addr()
	if r.spare.open() && r.pointed == r.spare.addr.Addr() {
		here = r.spare.addr.Addr()
	}
	if !r.applied || r.pointed != here || answers == r.answers {
		return here, nil
	}
	if !r.spare.open() {
		spare, err := r.openSocket(ctx, netip.AddrPort{})
		if err != nil {
			return here, fmt.Errorf("app-tail could not open a second address to move this machine to, so programs keep answering from what they cached until it expires: %w", err)
		}
		if spare.addr.Addr() == here {
			// A second port on the same address is not a change any cache sees: resolver
			// settings carry addresses alone.
			spare.stop()
			return here, fmt.Errorf("the only second address app-tail was given is %s, the one this machine already uses, so programs keep answering from what they cached until it expires", here)
		}
		r.spare = spare
	}
	if here == r.listen.addr.Addr() {
		return r.spare.addr.Addr(), nil
	}
	return r.listen.addr.Addr(), nil
}

// resolverFailure is a failure to build the resolvers as the card should say it.
//
// A connection this machine's own policy refused -- a firewall or an antivirus deciding
// app-tail may not use the network -- is the one cause no resolver setting changes, and it
// reads on Windows as "forbidden by its access permissions" against every resolver in turn,
// which sends the user to their router. The message names what to allow instead, and keeps
// the detail after it.
func resolverFailure(err error) string {
	if sockerr.PermissionDenied(err) {
		return "this machine's firewall or antivirus is refusing app-tail's network connections; allow app-tail in it. " + err.Error()
	}
	return err.Error()
}

// claim opens the privileged side, once, and keeps it. Holding it is what makes the
// restore happen when this process dies: the machine-side session goes with the connection.
func (r *systemDNSRunner) claim(ctx context.Context) error {
	if r.rights != nil {
		return nil
	}
	rights, err := r.open(ctx, func(format string, args ...any) {
		r.logger.Info("system resolver: " + fmt.Sprintf(format, args...))
	})
	if err != nil {
		return fmt.Errorf("claim this machine's name resolution: %w", err)
	}
	r.rights = rights
	return nil
}

// bind opens the DNS sockets and starts answering on them.
//
// Bind first, override second, always: a machine pointed at an address nothing is listening
// on resolves nothing at all, and that is the state this whole feature has to never reach.
func (r *systemDNSRunner) bind(ctx context.Context, want netip.AddrPort) error {
	if r.fwd != nil && r.wanted == want {
		return nil
	}
	started := r.fwd == nil
	if started {
		r.fwd = dnsfwd.New(dnsfwd.Config{
			Logf:            func(format string, args ...any) { r.logger.Debug(fmt.Sprintf(format, args...)) },
			OnProfileHealth: r.noteHealth,
			OnQuestion:      r.question,
		})
		// Detached from the reconcile's context: serving lasts until the module is switched
		// off or the agent stops, not until this pass returns.
		r.serving, r.stopServing = context.WithCancel(context.WithoutCancel(ctx))
		// The pools belong to the forwarder that was just replaced, so the fingerprint has to
		// go with it or the new one would be left with no resolvers at all.
		r.resolvers = ""
	}

	var sock resolverSocket
	if r.spare.open() && r.spare.addr == want {
		// Already answering there, so nothing new is opened.
		sock, r.spare = r.spare, resolverSocket{}
	} else {
		opened, err := r.openSocket(ctx, want)
		if err != nil {
			if started {
				r.stopSockets()
			}
			return fmt.Errorf("listen for DNS on %s: %w", want, err)
		}
		sock = opened
	}
	// The listen address changed under a running forwarder, and the machine moves to it. The
	// old sockets keep answering until it has, which is the last step of the pass: closed
	// first, they would leave the machine pointed at nothing for as long as rewriting its
	// resolver setting takes.
	for _, old := range []resolverSocket{r.listen, r.spare} {
		if old.open() {
			r.retired = append(r.retired, old)
		}
	}
	r.listen, r.spare, r.wanted = sock, resolverSocket{}, want
	return nil
}

// openSocket opens one more address and starts answering on it with the forwarder.
func (r *systemDNSRunner) openSocket(ctx context.Context, want netip.AddrPort) (resolverSocket, error) {
	pc, ln, bound, err := r.rights.OpenResolver(ctx, want)
	if err != nil {
		return resolverSocket{}, err
	}
	fwd := r.fwd
	serveCtx, stop := context.WithCancel(r.serving)
	go r.serve(serveCtx, bound, "packet", func() error { return fwd.ServePacket(serveCtx, pc) })
	go r.serve(serveCtx, bound, "stream", func() error { return fwd.ServeStream(serveCtx, ln) })
	return resolverSocket{addr: bound, stop: stop}, nil
}

// resolverSocket is one loopback address app-tail answers DNS on.
type resolverSocket struct {
	addr netip.AddrPort
	// stop ends its two serve loops, which close the sockets on their way out.
	stop context.CancelFunc
}

func (s resolverSocket) open() bool { return s.addr.IsValid() }

func (r *systemDNSRunner) serve(ctx context.Context, at netip.AddrPort, what string, run func() error) {
	err := run()
	if err == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// Checked under the lock: a socket stopped while this loop waited for it was stopped on
	// purpose, and tearing down now would take the sockets that replaced it.
	if ctx.Err() != nil {
		return
	}
	r.logger.Error("answering DNS stopped", "address", at, "socket", what, "error", err)
	if r.applied && at.Addr() != r.pointed {
		// Not the address this machine uses, which keeps answering: only this socket goes,
		// and the next change of answers opens another to move to.
		idle := true
		switch {
		case at == r.spare.addr:
			r.spare.stop()
			r.spare = resolverSocket{}
		case at == r.listen.addr && r.spare.addr.Addr() == r.pointed:
			r.listen.stop()
			r.listen, r.spare = r.spare, resolverSocket{}
		default:
			idle = false
		}
		if idle {
			r.failure = fmt.Sprintf("app-tail stopped answering DNS on its second address %s (%s socket: %v); this machine keeps resolving on %s", at, what, err, r.pointed)
			return
		}
	}
	// The machine is pointed at a socket nobody is reading. The next reconcile rebinds.
	r.stopSockets()
	r.failure = fmt.Sprintf("app-tail stopped answering DNS on its %s socket: %v", what, err)
}

// configure rebuilds the resolver pools when what they were built from has changed, and
// hands the forwarder the rules it routes by on every pass.
func (r *systemDNSRunner) configure(ctx context.Context, target systemDNSTarget, base tsnode.BaseResolvers) error {
	rules := target.rules
	rules.SearchDomains = slices.Clone(base.SearchDomains)

	fingerprint := resolverFingerprint(target.profile, target.bootstrap, base)
	if fingerprint == r.resolvers {
		cfg := r.fwd.Config()
		rules.HaveLocal = cfg.Local.Len() > 0
		cfg.Rules = rules
		cfg.Tunnels = target.tunnels
		cfg.RetryOnNXDOMAIN = target.retry
		r.fwd.Configure(cfg)
		return nil
	}

	local, err := plainPool(base.Nameservers)
	if err != nil {
		return err
	}
	boot, err := newBootstrap(target, local)
	if err != nil {
		return errors.Join(err, local.Close())
	}
	profile, err := profilePool(ctx, target.profile, boot)
	// Closed either way: it exists to answer the lookups above and holds live sockets of its
	// own, which nothing after this point reads.
	closeErr := boot.close()
	if err != nil {
		return errors.Join(err, closeErr, local.Close())
	}
	if closeErr != nil {
		r.logger.Debug("closing the resolvers used to look up resolver hostnames failed", "error", closeErr)
	}
	rules.HaveLocal = local.Len() > 0
	r.bootstrap, r.bootstrapDegraded = boot.note, boot.degraded()
	// Here rather than on every pass: what the answer depends on is the profile and the
	// network, which are exactly the two things this fingerprint is made of.
	r.intercepted = r.checkIntercepted(ctx, target.profile)

	r.fwd.Configure(dnsfwd.Config{
		Rules:           rules,
		Tunnels:         target.tunnels,
		Profile:         profile,
		Local:           local,
		RetryOnNXDOMAIN: target.retry,
		Logf:            func(format string, args ...any) { r.logger.Debug(fmt.Sprintf(format, args...)) },
		OnProfileHealth: r.noteHealth,
		OnQuestion:      r.question,
	})
	r.resolvers = fingerprint
	return nil
}

// checkIntercepted asks whether this network answers plain DNS on its own behalf, and says
// what that means for the profile that was just built.
//
// Only a profile with a plain resolver is affected: DNS over TLS and DNS over HTTPS are
// verified against the server's certificate, so a device on the path can block them but
// never answer for them. It is checked because the failure is otherwise invisible -- the
// card would say this machine resolves through Cloudflare while every query is answered by
// the router, which is the app claiming something it cannot do.
func (r *systemDNSRunner) checkIntercepted(ctx context.Context, p config.DNSProfile) string {
	if !profileUsesPlain(p) {
		return ""
	}
	intercepted, err := r.probe(ctx)
	if err != nil {
		// Nothing answered, which is the network behaving. The reason is worth a log line
		// and nothing more: it is a probe of a state that is not a problem.
		r.logger.Debug("this network did not answer for an address nothing lives at", "reason", err)
		return ""
	}
	if !intercepted {
		return ""
	}
	r.logger.Warn("this network answers plain DNS itself, so the plain resolvers in the chosen profile are not the ones answering", "profile", p.Name)
	return "This network answers plain DNS itself: a query addressed to a server that does " +
		"not exist came back answered. The resolvers in this profile that use plain DNS are " +
		"not the ones answering it -- this network's own resolver is. Write them as tls:// " +
		"or https:// addresses, which reach the server you picked or fail loudly, or choose " +
		"a profile that already does."
}

// profileUsesPlain reports a profile with at least one resolver reached over plain DNS. An
// address that does not parse is left out rather than assumed: it is reported as its own
// failure where the pool is built.
func profileUsesPlain(p config.DNSProfile) bool {
	for _, s := range p.Servers {
		if u, err := dnsprofiles.ParseUpstream(s); err == nil && u.Protocol == dnsprofiles.Plain {
			return true
		}
	}
	return false
}

// release puts the machine back and lets go of everything. It is what a switched-off
// module, a deleted profile and shutdown all end at.
func (r *systemDNSRunner) release(ctx context.Context, reason string) {
	var errs []error
	// Kept apart from the rest: a restore that reached every service it could is as far as
	// this machine can be put back until the ones it could not come back, and the record it
	// leaves is what the next run with the rights finishes from.
	var partial error
	rights := r.rights
	if rights != nil {
		// Before the sockets close, which is the order bind takes on the way in and for the
		// same reason it gives: between a socket closing and the machine being pointed back at
		// its own resolvers, nothing here resolves any name at all. Putting a resolver setting
		// back shells out once per network service, so that window is seconds rather than
		// instants, and a process killed inside it leaves the override standing.
		if err := rights.Restore(ctx); err != nil {
			if tsnode.PartialSystemDNSRestore(err) {
				partial = err
			} else {
				errs = append(errs, err)
			}
		}
	}

	r.stopSockets()
	r.resolvers = ""
	r.pointed, r.answers = netip.Addr{}, answerSource{}

	if rights != nil {
		if err := rights.Close(); err != nil {
			errs = append(errs, err)
		}
		r.rights = nil
		if err := errors.Join(append(errs, partial)...); err != nil {
			// Named on the card either way, and only the first of these is a failed teardown:
			// a partial restore is the recorded, recoverable state, so close does not turn it
			// into a failed run.
			r.partial = len(errs) == 0
			r.logger.Warn("restoring this machine's own resolver failed", "error", err)
			r.failure = fmt.Sprintf("this machine's own resolver could not be put back: %v", err)
			r.applied, r.reason = false, r.failure
			return
		}
	}
	r.partial = false
	r.applied, r.reason, r.failure, r.unreachable, r.intercepted, r.bootstrap = false, reason, "", "", "", ""
	r.bootstrapDegraded = false
	r.profile, r.base = config.DNSProfile{}, tsnode.BaseResolvers{}
}

// stopSockets ends the serve loops and forgets the forwarder. The sockets are closed by
// the loops themselves, which is what keeps a half-closed socket from outliving them.
func (r *systemDNSRunner) stopSockets() {
	if r.stopServing != nil {
		r.stopServing()
	}
	if r.fwd != nil {
		if err := r.fwd.Close(); err != nil {
			r.logger.Debug("closing the resolver connections failed", "error", err)
		}
	}
	r.fwd, r.serving, r.stopServing = nil, nil, nil
	r.listen, r.spare, r.retired, r.wanted = resolverSocket{}, resolverSocket{}, nil, netip.AddrPort{}
}

// close stops answering and puts this machine back. It is the shutdown path, and it runs
// whether or not the module is on: what was written outside this process is not forgotten
// by anything short of a restore.
func (r *systemDNSRunner) close(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rights == nil {
		r.stopSockets()
		return nil
	}
	r.release(ctx, "app-tail is stopping")
	// A partial restore is logged and left on the record rather than returned: an adapter
	// switched off before quitting is an ordinary thing to do, and reporting it here would
	// turn that quit into a failed run -- which exits non-zero and skips a restart the user
	// asked for. The next start with the rights finishes the job.
	if r.failure != "" && !r.partial {
		return errors.New(r.failure)
	}
	return nil
}

// noteHealth records the chosen profile answering nothing, which is what a captive portal
// looks like from here: every name the user types fails while the network's own resolver
// still answers the sign-in page.
func (r *systemDNSRunner) noteHealth(healthy bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if healthy {
		r.unreachable = ""
		return
	}
	r.unreachable = "the resolvers in this profile are not answering"
	if err != nil {
		r.unreachable += ": " + err.Error()
	}
	r.logger.Warn("the chosen resolver profile is not answering", "error", err)
}

// snapshot is what the API reports. It is a copy: the caller is a request goroutine and
// everything above runs on the lifecycle one.
type systemDNSSnapshot struct {
	applied           bool
	listen            string
	profile           config.DNSProfile
	base              tsnode.BaseResolvers
	reason            string
	failure           string
	unreachable       string
	intercepted       string
	bootstrap         string
	bootstrapDegraded bool
	stats             dnsfwd.Stats
}

func (r *systemDNSRunner) snapshot() systemDNSSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := systemDNSSnapshot{
		applied:           r.applied,
		profile:           r.profile,
		base:              tsnode.BaseResolvers{Nameservers: slices.Clone(r.base.Nameservers), SearchDomains: slices.Clone(r.base.SearchDomains)},
		reason:            r.reason,
		failure:           r.failure,
		unreachable:       r.unreachable,
		intercepted:       r.intercepted,
		bootstrap:         r.bootstrap,
		bootstrapDegraded: r.bootstrapDegraded,
	}
	// The socket this machine is pointed at, which after a change of answers is the spare.
	at := r.listen.addr
	if r.applied && r.spare.open() && r.pointed == r.spare.addr.Addr() {
		at = r.spare.addr
	}
	if at.IsValid() {
		out.listen = at.String()
	}
	if r.fwd != nil {
		out.stats = r.fwd.Stats()
	}
	return out
}

// resolverFingerprint is what the pools were built from. Two passes with the same
// fingerprint reuse the connections already open, which for DNS over TLS is the difference
// between one handshake and one per reconcile.
func resolverFingerprint(p, boot config.DNSProfile, base tsnode.BaseResolvers) string {
	var b strings.Builder
	b.WriteString(profileIdentity(p))
	// The bootstrap belongs here because it decides which addresses the profile's hostnames
	// resolved to. Leaving it out would keep pools pinned to addresses the previous choice
	// found, and switching the bootstrap resolver would appear to do nothing.
	b.WriteString("\x02")
	b.WriteString(profileIdentity(boot))
	b.WriteString("\x01")
	for _, addr := range base.Nameservers {
		b.WriteString(addr.String())
		b.WriteString(",")
	}
	return b.String()
}

// profileIdentity names a profile by what it resolves with: its id and its servers.
func profileIdentity(p config.DNSProfile) string {
	var b strings.Builder
	b.WriteString(p.ID)
	for _, s := range p.Servers {
		b.WriteString("\x00")
		b.WriteString(s)
	}
	return b.String()
}

// answerSource is what decides the answer to a name this machine asks about, so two passes
// with different ones may answer the same name differently and every cache on the machine
// holds answers that are no longer true.
//
// The network's own resolvers are left out: they change with the network, and the system
// drops its caches on a network change by itself. So are app-tail's own connections, whose
// names sit under suffixes nothing outside them resolves and which come and go often enough
// that moving the machine every time would rewrite its resolver setting for nothing.
type answerSource struct {
	profile  string
	blocking uint64
	// blockAnswer is only set while something is blocked: with nothing on the list it
	// answers no name, and changing it changes nothing.
	blockAnswer   dnsfwd.BlockAnswer
	localSuffixes string
	retry         bool
}

func answersOf(t systemDNSTarget) answerSource {
	out := answerSource{
		profile:       profileIdentity(t.profile),
		blocking:      t.blocking,
		localSuffixes: strings.Join(t.rules.LocalSuffixes, "\x00"),
		retry:         t.retry,
	}
	if t.blocking != 0 {
		out.blockAnswer = t.rules.BlockAnswer
	}
	return out
}

// plainPool builds the network's own resolvers, which are always plain DNS: they are what
// DHCP handed out, and DHCP has no way to say anything else.
func plainPool(addrs []netip.Addr) (*dnsfwd.Pool, error) {
	ups := make([]dnsfwd.Upstream, 0, len(addrs))
	for _, addr := range addrs {
		u, err := dnsprofiles.ParseUpstream(netip.AddrPortFrom(addr, 53).String())
		if err != nil {
			return nil, fmt.Errorf("read this machine's own resolver %s: %w", addr, err)
		}
		built, err := dnsfwd.NewUpstream(u, nil)
		if err != nil {
			return nil, fmt.Errorf("use this machine's own resolver %s: %w", addr, err)
		}
		ups = append(ups, built)
	}
	return dnsfwd.NewPool(ups, nil), nil
}

// bootstrap turns a resolver's hostname into addresses.
//
// A resolver named by hostname cannot be dialled until something resolves that name, and the
// two resolvers that cannot do it are the obvious ones: app-tail's own forwarder, which is
// waiting on this answer, and the resolver being looked up. What is left is a third one, and
// which third one it is matters. This network's own resolver is on the far side of whatever
// the network does to DNS -- on a network that answers port 53 itself, that one lookup is the
// last part of the chain the network still gets to answer, and an answer of its choosing
// takes the chosen resolver off the air. It cannot make it resolve somewhere wrong: the
// certificate is checked against the hostname either way. An encrypted resolver at a literal
// address is not answerable from the path at all, so that is what is asked first.
//
// The fallback to the network's own resolvers stays, because the alternative to a bootstrap
// that cannot be reached is a machine resolving nothing, and a network that wants you to sign
// in first answers only its own resolver. It is reported rather than taken quietly.
type bootstrap struct {
	// name is the profile the encrypted resolvers came from; empty when there are none.
	name string
	// pool is those resolvers, nil when the chosen profile could not supply any.
	pool *dnsfwd.Pool
	// local is this network's own resolvers: the fallback, and the only option without a pool.
	local *dnsfwd.Pool
	// why is what stopped the chosen profile from supplying a pool, for the report.
	why string
	// note is what happened, once a lookup has happened. Empty means nothing needed one.
	note string
	// fellBack keeps a later success from overwriting a report of the fallback: with two
	// hostnames in one profile, the one the network resolved is the fact worth carrying.
	fellBack bool
}

// newBootstrap builds the encrypted side of the bootstrap, which is every resolver in the
// chosen profile that carries a literal address. It is not built at all when the profile the
// machine is switching to has no hostname in it, since there would be nothing to look up.
func newBootstrap(target systemDNSTarget, local *dnsfwd.Pool) (*bootstrap, error) {
	b := &bootstrap{name: target.bootstrap.Name, local: local, why: target.bootstrapWhy}
	if !profileNeedsLookup(target.profile) || target.bootstrap.ID == "" {
		return b, nil
	}
	var ups []dnsfwd.Upstream
	for _, u := range dnsprofiles.Dialable(target.bootstrap) {
		built, err := dnsfwd.NewUpstream(u, nil)
		if err != nil {
			var errs []error
			for _, open := range ups {
				errs = append(errs, open.Close())
			}
			return nil, errors.Join(fmt.Errorf("%s, chosen to look resolver hostnames up: %w", target.bootstrap.Name, err), errors.Join(errs...))
		}
		ups = append(ups, built)
	}
	b.pool = dnsfwd.NewPool(ups, nil)
	return b, nil
}

// lookup resolves one hostname, through the encrypted resolvers when there are any and
// through this network's own when there are not or when they did not answer.
func (b *bootstrap) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if b.pool != nil {
		addrs, err := dnsfwd.LookupAddrs(ctx, b.pool, host)
		if err == nil {
			if !b.fellBack {
				b.note = fmt.Sprintf("Resolver hostnames were looked up through %s.", b.name)
			}
			return addrs, nil
		}
		if b.local.Len() == 0 {
			// Nothing else to ask. The failure is the answer, and it is the caller's to
			// report: a profile whose resolvers cannot be found is a profile that cannot be
			// applied.
			return nil, fmt.Errorf("%s could not look up %s, and this network published no resolver to ask instead: %w", b.name, host, err)
		}
		b.fellBack = true
		b.note = fmt.Sprintf("%s was looked up through this network's own resolvers: %s did not answer (%v).", host, b.name, err)
		addrs, localErr := dnsfwd.LookupAddrs(ctx, b.local, host)
		if localErr != nil {
			// Both are named. The fallback alone reads as the network's resolver being the
			// one asked, and the encrypted one failing first is the half that says the
			// machine could reach neither.
			return nil, fmt.Errorf("%s did not answer (%w), and neither did this network's own resolvers: %w", b.name, err, localErr)
		}
		return addrs, nil
	}
	if !b.fellBack {
		b.note = "Resolver hostnames were looked up through this network's own resolvers"
		if b.why != "" {
			b.note += ", because " + b.why
		}
		b.note += "."
	}
	return dnsfwd.LookupAddrs(ctx, b.local, host)
}

// degraded reports the lookup having gone to this network's own resolvers without the user
// having asked for that. Choosing System default here is a decision, not a fault, and
// reporting it as one would teach the reader to ignore the warning that matters.
func (b *bootstrap) degraded() bool {
	if b.note == "" {
		return false
	}
	return b.fellBack || (b.pool == nil && b.why != "")
}

func (b *bootstrap) close() error {
	if b.pool == nil {
		return nil
	}
	return b.pool.Close()
}

// profileNeedsLookup reports a profile with at least one resolver named by hostname, which is
// the only case a bootstrap resolver is built for.
func profileNeedsLookup(p config.DNSProfile) bool {
	for _, s := range p.Servers {
		u, err := dnsprofiles.ParseUpstream(s)
		if err != nil {
			continue
		}
		if _, ok := u.Endpoint(); !ok {
			return true
		}
	}
	return false
}

// profilePool builds the resolvers the user chose, pinning any hostname through the bootstrap
// resolver first. Asking our own forwarder where its upstream lives would be a query to a
// resolver that is waiting on the answer.
func profilePool(ctx context.Context, p config.DNSProfile, boot *bootstrap) (*dnsfwd.Pool, error) {
	parsed, err := dnsprofiles.Upstreams(p)
	if err != nil {
		return nil, err
	}

	var ups []dnsfwd.Upstream
	// The resolvers built so far are live sockets, so an abandoned build closes them and
	// reports what closing them cost alongside the reason it stopped -- a failure to release
	// one is a descriptor this process keeps for its whole life.
	closeAll := func() error {
		var errs []error
		for _, u := range ups {
			errs = append(errs, u.Close())
		}
		return errors.Join(errs...)
	}
	for _, u := range parsed {
		pinned := []dnsprofiles.Upstream{u}
		if _, ok := u.Endpoint(); !ok {
			addrs, err := boot.lookup(ctx, u.Host)
			if err != nil {
				return nil, errors.Join(fmt.Errorf("%s: %w", p.Name, err), closeAll())
			}
			pinned = pinned[:0]
			for _, addr := range addrs {
				pinned = append(pinned, u.WithAddr(addr))
			}
		}
		for _, one := range pinned {
			built, err := dnsfwd.NewUpstream(one, nil)
			if err != nil {
				return nil, errors.Join(fmt.Errorf("%s: %w", p.Name, err), closeAll())
			}
			ups = append(ups, built)
		}
	}
	return dnsfwd.NewPool(ups, nil), nil
}

// systemDNSView is the machine-wide resolver as every surface reads it.
//
// It is built whether or not the module is on, because the interesting states are the ones
// where the switch and the machine disagree: a profile chosen but the rights never
// arranged, a profile whose resolvers answer nothing, an override still in place from a
// run that was killed.
func (a *Agent) systemDNSView(ctx context.Context) *httpapi.DNSSystemView {
	c := a.store.Get()
	s := c.Settings

	id := s.SystemDNSProfile
	if id == "" {
		id = config.DefaultSystemDNSProfile
	}
	view := &httpapi.DNSSystemView{
		Enabled:         s.SystemDNSEnabled,
		Profile:         id,
		RetryOnNXDOMAIN: s.SystemDNSRetryOnNXDOMAIN,
		LocalSuffixes:   slices.Clone(s.SystemDNSLocalSuffixes),
	}
	profile, known := dnsprofiles.ByID(c.DNSProfiles, id)
	if known {
		view.ProfileLabel = profile.Name
		if dnsprofiles.NeedsTailnet(profile.ID) {
			// The profile stores no servers, so the card would show a resolver list that is
			// empty while queries are going somewhere. What it resolves through is whatever
			// the tailnet publishes right now, and that is what has to be on the card.
			servers, err := a.tailnetResolvers(ctx)
			if err != nil {
				view.Error = err.Error()
			}
			profile.Servers = servers
		}
		// The card is drawn from an answer every local process can ask for, so the part of a
		// resolver URL that identifies this account does not travel with it.
		view.Servers = dnsprofiles.Hidden(profile.Servers)
		view.Protocols = profileProtocols(profile)
	} else {
		view.Error = fmt.Sprintf("the chosen resolver profile (%q) no longer exists", id)
	}

	if runner := a.currentSystemDNS(); runner != nil {
		snap := runner.snapshot()
		view.Applied = snap.applied
		view.Listen = snap.listen
		view.Unreachable = snap.unreachable
		view.Intercepted = snap.intercepted
		view.Bootstrap, view.BootstrapDegraded = snap.bootstrap, snap.bootstrapDegraded
		view.Queries = httpapi.DNSSystemStats{
			Total:     snap.stats.Queries,
			ToProfile: snap.stats.ToProfile,
			ToLocal:   snap.stats.ToLocal,
			Answered:  snap.stats.AnsweredHere,
			Failed:    snap.stats.Failures,
			Blocked:   snap.stats.Blocked,
		}
		if len(snap.base.Nameservers) > 0 || len(snap.base.SearchDomains) > 0 {
			view.Base = &httpapi.DNSBaseView{
				Nameservers:   addrStrings(snap.base.Nameservers),
				SearchDomains: slices.Clone(snap.base.SearchDomains),
			}
			// The network's own suffixes go to the network too, and a user reading the card
			// has no other way to learn that theirs are not the only ones.
			for _, domain := range snap.base.SearchDomains {
				if !slices.Contains(view.LocalSuffixes, domain) {
					view.LocalSuffixes = append(view.LocalSuffixes, domain)
				}
			}
		}
		if view.Error == "" {
			view.Error = snap.failure
		}
	}

	report := a.inspect(ctx, a.hostLogf)
	ready, blocker := report.ResolverReady()
	view.Ready, view.Blocker = ready, blocker
	// The one blocker a button can fix. Everything else -- a busy port, an unsupported
	// platform, a helper from another build already reported as its own problem -- is not
	// something asking for administrator rights would change.
	view.NeedsSetup = !ready && report.Supported && report.Helper.Design &&
		!report.Helper.Running && report.ResolverBusy == ""
	if report.StaleOverride != "" && !view.Applied && view.Error == "" {
		view.Error = report.StaleOverride
	}

	view.Capability = systemDNSCapability(s, view, known)
	return view
}

// systemDNSCapability states whether this machine is really resolving names through the
// chosen profile and, when it is not, why -- so the dashboard, the tray and the CLI cannot
// reach different conclusions.
//
// The order is the ladder a user climbs: what the platform can do, then what has been
// arranged, then what was chosen, then what is actually happening.
func systemDNSCapability(s config.Settings, view *httpapi.DNSSystemView, known bool) httpapi.Capability {
	limits := []string{
		"While this is on, every program on this machine resolves names through app-tail. " +
			"It is put back when you switch it off, when app-tail stops, and the next time " +
			"app-tail starts if it was killed.",
		"Names that belong to the network you are on -- single names, .local, this network's " +
			"own search domains, reverse lookups for private addresses -- keep going to that " +
			"network's resolver rather than to your chosen one.",
		"An answer of \"no such name\" from your resolver is the answer, so a resolver that " +
			"blocks a domain keeps blocking it.",
		"A program with a resolver of its own -- a browser's secure DNS set to a named " +
			"provider, a VPN client -- asks that one instead, and nothing here reaches it.",
		"Switching the profile or what is blocked moves this machine between two of " +
			"app-tail's addresses, which is what makes every program drop the names it had " +
			"cached. Connections already open stay open until they close.",
	}
	switch {
	case !view.Ready && view.Blocker != "":
		return httpapi.Capability{Reason: view.Blocker, Limits: limits}
	case !s.SystemDNSEnabled:
		return httpapi.Capability{
			Available: true,
			Reason: "The machine-wide resolver is off, so every program here resolves names " +
				"the way it always did.",
			Limits: limits,
		}
	case !known:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: view.Error,
			Limits: limits,
		}
	case view.Profile == dnsprofiles.SystemID:
		return httpapi.Capability{
			Available: true,
			Reason: "System default is chosen, which leaves this machine's own resolver " +
				"exactly as it is. Pick another profile to switch it.",
			Limits: limits,
		}
	case !view.Applied:
		reason := view.Error
		if reason == "" {
			reason = "this machine has not been pointed at app-tail's resolver yet"
		}
		return httpapi.Capability{Available: true, Degraded: true, Reason: reason, Limits: limits}
	case view.Unreachable != "":
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "This machine is resolving through app-tail, but " + view.Unreachable +
				". If you are on a network that wants you to sign in, its own sign-in page " +
				"still resolves.",
			Limits: limits,
		}
	case view.Intercepted != "":
		// Behind an unreachable profile and ahead of a plain failure: the override is
		// installed and answering, so the honest report is not that something broke, it is
		// that the answers are not coming from where the picker says they are.
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: view.Intercepted,
			Limits: limits,
		}
	case view.Error != "":
		return httpapi.Capability{Available: true, Degraded: true, Reason: view.Error, Limits: limits}
	}
	return httpapi.Capability{Available: true, Limits: limits}
}

// SetUpSystem arranges the administrator rights the machine-wide resolver needs.
//
// The failure is returned rather than only recorded, for the reason the interface setup
// returns it: this is a request whose whole purpose was the arrangement, so a caller that
// asked for it is owed the reason directly.
func (d dnsAPI) SetUpSystem(ctx context.Context) error {
	a := d.a
	if a.rightsAtRestart() {
		return ErrRightsAtRestart
	}
	ctx, cancel := context.WithTimeout(ctx, interfaceSetupTimeout)
	defer cancel()
	// Recorded for the reason the interface setup records it: this request is somebody
	// asking for the dialog, and what the record stops is a second one from the reconcile
	// that follows.
	a.noteRightsRequested()
	if err := a.provision(ctx, a.hostLogf, tsnode.RightsResolver, a.mayElevate(), a.store.Path()); err != nil {
		a.logger.Warn("could not set this machine up for the machine-wide resolver", "error", err)
		return err
	}
	a.logger.Info("this machine is set up for the machine-wide resolver")
	// The rights are what the runner was waiting for, so the switch takes effect now
	// rather than on whatever poll happens next.
	a.reconcileNow(ctx)
	return nil
}

// profileProtocols is how this profile's resolvers are reached, in the order they are
// tried and without repeats. It is the one thing an address alone does not make obvious:
// tls:// and https:// look like ordinary URLs to a reader in a hurry.
func profileProtocols(p config.DNSProfile) []string {
	var out []string
	for _, s := range p.Servers {
		u, err := dnsprofiles.ParseUpstream(s)
		if err != nil {
			continue
		}
		if !slices.Contains(out, string(u.Protocol)) {
			out = append(out, string(u.Protocol))
		}
	}
	return out
}

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return out
}
