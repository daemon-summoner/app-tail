// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"slices"
	"time"

	"tailscale.com/net/dns"
	"tailscale.com/util/dnsname"

	"github.com/sellitus/app-tail/internal/sockerr"
	"github.com/sellitus/app-tail/internal/sysdns"
	"github.com/sellitus/app-tail/internal/udpsock"
)

// The machine-wide resolver half of the boundary.
//
// It needs rights for exactly two things, and neither of them is arbitrary: binding a DNS
// socket on port 53, and changing what this machine's network services resolve names
// through. Both are bounded here rather than by the caller -- the caller is unprivileged
// and the helper is not, so a bound a caller could state is a bound a caller can widen.

// The protocols a resolver socket can be. They are the two DNS runs on and there is no
// third, so an unknown value is refused rather than defaulted.
const (
	protoUDP = "udp"
	protoTCP = "tcp"
)

// resolverFallbacks is where the helper will put a resolver socket when the caller's
// preferred address is taken. They are loopback addresses on port 53, and nothing outside
// this machine can reach any of them.
//
// 127.0.0.1 is deliberately not on the list: a machine that already runs something on it --
// dnsmasq, a container runtime, another DNS client -- would have that thing displaced by
// whichever of the two started second, and the symptom is name resolution that works until a
// reboot reorders them.
//
// macOS assigns 127.0.0.1 and nothing else, so every address here is refused with "can't
// assign requested address" until it is aliased onto lo0. That is what bindResolverLadder
// arranges, and why binding a resolver socket is machine state that has to be given back.
var resolverFallbacks = []netip.AddrPort{
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 153}), 53),
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 154}), 53),
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 155}), 53),
}

// SystemResolver is what the privileged side does for the machine-wide resolver. It is
// separate from Host because the two have separate lifetimes: the interface comes and goes
// with the node, and the machine's resolver setting outlives every one of those rebuilds.
//
// The lifecycle is: open the sockets, then point the machine at them -- bind first, override
// second, never the reverse. A machine pointed at an address nothing is listening on
// resolves no names at all.
type SystemResolver interface {
	// OpenResolverPacket binds the UDP half of a resolver socket and hands it back. want is
	// the caller's preferred address and may be the zero value for "wherever you can".
	OpenResolverPacket(ctx context.Context, want netip.AddrPort) (net.PacketConn, error)
	// OpenResolverStream binds the TCP half, on the same address as the UDP half. DNS
	// answers that do not fit in a datagram are retried over TCP, so a machine with only
	// the UDP half resolves small names and fails on large ones.
	OpenResolverStream(ctx context.Context, want netip.AddrPort) (net.Listener, error)
	// SetSystemDNS points this machine's network services at resolvers, every one of which
	// must be a loopback address. A nil or empty list restores what the machine had
	// before, which is the only other thing this offers: pointing a machine at no resolver
	// at all is not a setting app-tail installs.
	SetSystemDNS(ctx context.Context, resolvers []netip.Addr) error
	// BaseSystemDNS reports what this machine resolves names with when app-tail is not in
	// the path, which is where names the chosen profile does not answer for go. It changes
	// nothing, so it is answered on any connection.
	BaseSystemDNS(ctx context.Context) (sysdns.Base, error)
}

// ResolverSession is a held claim on this machine's name resolution: the operations plus the
// connection that carries them. Dropping it is what puts the machine back -- on the helper
// path because the connection closing is the dead-man's switch, and in this process because
// Close restores before it returns.
type ResolverSession interface {
	SystemResolver
	Close() error
}

// OpenSystemResolver claims this machine's name resolution, in this process when it already
// holds the rights and over the helper socket when it does not.
//
// It is a second connection rather than the node's: the two sessions have separate lifetimes,
// and sharing one would mean every rebuild of the node dropping this machine's resolver for
// as long as the restart takes.
func OpenSystemResolver(ctx context.Context, opts Options) (ResolverSession, error) {
	host, err := Open(ctx, opts)
	if err != nil {
		return nil, err
	}
	session, ok := host.(ResolverSession)
	if !ok {
		return nil, errors.Join(
			fmt.Errorf("this build's privileged side (%T) cannot change how this machine resolves names", host),
			host.Close(),
		)
	}
	return session, nil
}

// checkResolverListen bounds what the helper will bind.
//
// Loopback, because a resolver reachable from the network is an open resolver, and an
// unprivileged caller that could ask a root process to open one has been handed something
// far larger than this feature. Port 53 or an unprivileged port, because 53 is the one
// privileged port this feature needs: without the port rule the operation would read as
// "bind any port under 1024", and an unprivileged caller could take 88, 443 or 631 on
// loopback and answer for whatever the machine sends there.
func checkResolverListen(addr netip.AddrPort) error {
	if !addr.IsValid() {
		return errors.New("no address to listen on")
	}
	if !addr.Addr().IsLoopback() {
		return fmt.Errorf("app-tail will only listen for DNS on a loopback address, and %s is not one: a resolver on any other address is reachable from the network", addr.Addr())
	}
	if port := addr.Port(); port != 0 && port != 53 && port < 1024 {
		return fmt.Errorf("app-tail will only listen for DNS on port 53 or on an unprivileged port, not on port %d", port)
	}
	return nil
}

// checkSystemResolvers bounds what the helper will point this machine at.
//
// Every address must be loopback, which bounds the worst an unprivileged caller can get out
// of this operation to pointing the machine at another port on its own loopback -- something
// it could already arrange by binding one. Without it, the operation would be "redirect this
// machine's name resolution anywhere", which is the whole machine.
func checkSystemResolvers(addrs []netip.Addr) error {
	for _, addr := range addrs {
		if !addr.IsValid() {
			return errors.New("one of the resolver addresses is not an address")
		}
		if !addr.IsLoopback() {
			return fmt.Errorf("app-tail will only point this machine at a resolver on its own loopback, and %s is not one", addr)
		}
	}
	return nil
}

// maxDNSEntries bounds one resolver configuration. A machine has a handful of resolvers and
// a handful of search domains; past this the request is a caller growing a root process's
// work rather than configuring name resolution.
const maxDNSEntries = 64

// checkInterfaceDNS bounds the resolver configuration the engine installs for its own
// interface.
//
// The addresses are deliberately not restricted to loopback the way checkSystemResolvers
// does: this configuration carries whichever resolvers the tailnet was told to use, and
// those are ordinary internet addresses. What is checked instead is that every value is
// the kind of thing it claims to be, because a domain here is written into the machine's
// resolver configuration by a root process -- on macOS as a line inside /etc/resolver and
// as the name of the file itself. The domain type this arrives as is a bare string with no
// validation of its own, and a domain carrying a newline or a slash is not a domain: it is
// a line the caller gets to write into a root-owned file.
func checkInterfaceDNS(cfg dns.OSConfig) error {
	if len(cfg.Nameservers) > maxDNSEntries {
		return fmt.Errorf("a resolver configuration of %d resolvers is more than this machine will be given", len(cfg.Nameservers))
	}
	for _, addr := range cfg.Nameservers {
		switch {
		case !addr.IsValid():
			return errors.New("one of the resolver addresses is not an address")
		case addr.IsUnspecified():
			return fmt.Errorf("%s names no resolver and cannot be one", addr)
		case addr.IsMulticast():
			return fmt.Errorf("%s is multicast, which is not a resolver this machine can ask", addr)
		}
	}
	if total := len(cfg.SearchDomains) + len(cfg.MatchDomains); total > maxDNSEntries {
		return fmt.Errorf("a resolver configuration of %d domains is more than this machine will be given", total)
	}
	for _, domain := range slices.Concat(cfg.SearchDomains, cfg.MatchDomains) {
		if err := checkDNSDomain(domain); err != nil {
			return err
		}
	}
	return nil
}

// checkDNSDomain refuses a domain that is not one.
//
// The label rules come from dnsname, which is what every domain this app produces itself
// already went through. The character rule is this side's: dnsname deliberately allows any
// byte inside a label, and the bytes that matter here are the ones that stop being a name
// when a root process writes them out -- a newline starts a second directive, a space ends
// the domain early, and a slash or colon changes which file is written.
func checkDNSDomain(domain dnsname.FQDN) error {
	text := string(domain)
	if _, err := dnsname.ToFQDN(text); err != nil {
		return fmt.Errorf("%q is not a domain name: %w", text, err)
	}
	for _, r := range text {
		switch {
		case r <= ' ' || r == 0x7f:
			return fmt.Errorf("%q holds a character that is not part of a domain name and would be written into this machine's resolver configuration as its own line", text)
		case r == '/' || r == '\\' || r == ':':
			return fmt.Errorf("%q holds a %q, which is not part of a domain name and decides which file this machine's resolver configuration is written to", text, r)
		}
	}
	return nil
}

// resolverCandidates is the order the helper tries: what the caller asked for first, then
// its own fallbacks. The caller's address is not repeated further down the list.
func resolverCandidates(want netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(resolverFallbacks)+1)
	if want.IsValid() {
		out = append(out, want)
	}
	for _, fallback := range resolverFallbacks {
		if fallback != want {
			out = append(out, fallback)
		}
	}
	return out
}

// bindResolverPair takes both halves of one address at once.
//
// Both or neither: a pair split across two addresses is a resolver that answers small
// queries at one address and large ones at another, and nothing that asks this machine a
// question knows to look in two places.
func bindResolverPair(ctx context.Context, addr netip.AddrPort) (net.PacketConn, net.Listener, error) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", addr.String())
	if err != nil {
		return nil, nil, err
	}
	// Every program on this machine asks its questions here, and a client that asks one and
	// stops listening for the answer is ordinary. On a platform that reports that back as a
	// failure of this socket, one such client would end the whole machine's name resolution.
	if err := udpsock.SilenceUnreachable(pc); err != nil {
		return nil, nil, errors.Join(err, pc.Close())
	}
	// The TCP half goes on whatever the UDP half actually got, which matters when the
	// caller asked for port 0: the two would otherwise land on different ports.
	bound, err := netip.ParseAddrPort(pc.LocalAddr().String())
	if err != nil {
		return nil, nil, errors.Join(fmt.Errorf("read back the address the resolver socket bound: %w", err), pc.Close())
	}
	ln, err := lc.Listen(ctx, "tcp", bound.String())
	if err != nil {
		return nil, nil, errors.Join(err, pc.Close())
	}
	return pc, ln, nil
}

// needsLoopbackAlias reports the one bind failure that is not a fact about who holds the
// address: the address is not assigned to this machine's loopback at all, which is the
// normal state of every address but 127.0.0.1 on macOS. It is arranged rather than reported.
func needsLoopbackAlias(err error) bool {
	return sockerr.AddressNotAssigned(err)
}

// DetectResolverBusy names what is already holding every address app-tail would listen on,
// empty when one of them is free.
//
// A permission failure is not a busy port: it means this side does not hold the rights,
// which is the helper's whole job and says nothing about whether the address is taken. An
// unassigned address is not a busy port either -- it is one the helper adds to the loopback
// interface when it binds.
//
// On a platform with a helper the answer comes from the helper and the unprivileged agent
// computes nothing. On one without, this process is the privileged side and asks directly.
func DetectResolverBusy(ctx context.Context) string {
	var taken []string
	for _, addr := range resolverFallbacks {
		pc, ln, err := bindResolverPair(ctx, addr)
		if err == nil {
			closeQuietly(pc, ln)
			return ""
		}
		if sockerr.PermissionDenied(err) || needsLoopbackAlias(err) {
			return ""
		}
		taken = append(taken, fmt.Sprintf("%s (%v)", addr, err))
	}
	return "every address app-tail would listen for DNS on is already in use: " + joinSemicolon(taken)
}

func joinSemicolon(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}

// closeQuietly drops sockets opened only to find out whether they could be. Nothing here
// has anything to report a failure to, and a probe that could not be closed is a leaked
// descriptor rather than a fact about the machine.
func closeQuietly(closers ...io.Closer) {
	for _, c := range closers {
		if c != nil {
			c.Close()
		}
	}
}

// OpenResolverPacket hands over the UDP half of a resolver socket: the one a stream call
// already bound, or the first half of a new pair.
func (l *Local) OpenResolverPacket(ctx context.Context, want netip.AddrPort) (net.PacketConn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, errors.New("this session has already been torn down")
	}
	if l.resolverPacket == nil {
		if err := l.bindResolver(ctx, want); err != nil {
			return nil, err
		}
	}
	pc := l.resolverPacket
	l.resolverPacket = nil
	return pc, nil
}

// OpenResolverStream hands over the TCP half, on the address its UDP half is on.
func (l *Local) OpenResolverStream(ctx context.Context, want netip.AddrPort) (net.Listener, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, errors.New("this session has already been torn down")
	}
	if l.resolverStream == nil {
		if err := l.bindResolver(ctx, want); err != nil {
			return nil, err
		}
	}
	ln := l.resolverStream
	l.resolverStream = nil
	return ln, nil
}

// bindResolver takes both halves of one new address. The caller holds the lock.
//
// Both are bound by the first call and the other is kept for the second, rather than each
// call walking the ladder on its own: two independent walks can land on two addresses when
// something else holds one protocol of the first candidate, and the result is a machine
// pointed at an address that answers only half of what it is asked.
//
// A session binds as many pairs as it is asked for, one after another, because the caller
// moves this machine between two of them to make every cache on it let go of old answers.
// Each half is handed over exactly once. A half still held from an earlier pair is one
// whose partner the caller took and then asked past, so it is closed rather than kept.
func (l *Local) bindResolver(ctx context.Context, want netip.AddrPort) error {
	if want.IsValid() {
		if err := checkResolverListen(want); err != nil {
			return err
		}
	}
	if errs := l.closeUnclaimedResolver(); len(errs) > 0 {
		return errors.Join(errs...)
	}
	pc, ln, _, err := bindResolverLadder(ctx, resolverCandidates(want), bindResolverPair, l.systemDNS().HoldLoopback)
	if err != nil {
		return err
	}
	l.resolverPacket, l.resolverStream = pc, ln
	return nil
}

// closeUnclaimedResolver closes whichever half of the last pair was never handed over. The
// caller holds the lock.
func (l *Local) closeUnclaimedResolver() []error {
	var errs []error
	if l.resolverPacket != nil {
		if err := l.resolverPacket.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close the resolver's UDP socket: %w", err))
		}
		l.resolverPacket = nil
	}
	if l.resolverStream != nil {
		if err := l.resolverStream.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close the resolver's TCP socket: %w", err))
		}
		l.resolverStream = nil
	}
	return errs
}

// bindPair and holdLoopback are the two things the ladder does, passed in so the walk itself
// -- which is where the ordering mistakes live -- is exercised without a privileged machine.
type bindPair func(ctx context.Context, addr netip.AddrPort) (net.PacketConn, net.Listener, error)

type holdLoopback func(ctx context.Context, addr netip.Addr) error

// bindResolverLadder walks the candidates and returns the first pair it could take.
//
// An address that is not assigned to this machine's loopback is added to it and tried once
// more, because on macOS that is the state of every address app-tail listens on. The retry
// is once per candidate: a second failure after the address was added is a fact about the
// address rather than about its assignment, and walking on is what finds a free one.
func bindResolverLadder(
	ctx context.Context,
	candidates []netip.AddrPort,
	bind bindPair,
	hold holdLoopback,
) (net.PacketConn, net.Listener, netip.AddrPort, error) {
	var failures []error
	for _, candidate := range candidates {
		pc, ln, err := bind(ctx, candidate)
		if err != nil && needsLoopbackAlias(err) {
			if holdErr := hold(ctx, candidate.Addr()); holdErr != nil {
				failures = append(failures, errors.Join(err, holdErr))
				continue
			}
			pc, ln, err = bind(ctx, candidate)
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		bound, err := netip.ParseAddrPort(pc.LocalAddr().String())
		if err != nil {
			closeQuietly(pc, ln)
			return nil, nil, netip.AddrPort{}, fmt.Errorf("read back the address the resolver socket bound: %w", err)
		}
		return pc, ln, bound, nil
	}
	return nil, nil, netip.AddrPort{}, fmt.Errorf("listen for DNS on this machine's loopback: %w", errors.Join(failures...))
}

// SetSystemDNS points this machine's network services at the resolvers, or restores what
// they had when the list is empty.
func (l *Local) SetSystemDNS(ctx context.Context, resolvers []netip.Addr) error {
	if err := checkSystemResolvers(resolvers); err != nil {
		return err
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return errors.New("this session has already been torn down")
	}
	manager := l.systemDNS()
	// Released for the call itself: changing a machine's resolver shells out once per
	// network service, and holding the session's lock across it would block the teardown
	// that exists to undo it.
	l.mu.Unlock()

	if len(resolvers) == 0 {
		if err := manager.Clear(ctx); err != nil {
			return err
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		l.systemDNSApplied = false
		return l.releaseSystemDNS()
	}
	// Before the override, so this machine never carries one without a way back from a crash.
	if l.bootRepair != nil {
		if err := l.bootRepair(); err != nil {
			return fmt.Errorf("set up the repair that puts this machine's resolver back if app-tail stops without doing it: %w", err)
		}
	}
	// Held for as long as the override stands, so a repair can tell this session's override
	// from one nobody is serving.
	if err := l.holdSystemDNS(ctx); err != nil {
		return err
	}
	// Recorded before the change rather than after it: a failure partway through has
	// already changed some of this machine's services, and a teardown that believed
	// nothing had been applied would leave those pointed at app-tail.
	l.mu.Lock()
	l.systemDNSApplied = true
	l.mu.Unlock()
	return manager.Apply(ctx, resolvers)
}

// holdSystemDNS takes the serving lock for this session unless it already holds it.
func (l *Local) holdSystemDNS(ctx context.Context) error {
	l.mu.Lock()
	needed := l.holdServing != nil && l.releaseServing == nil
	l.mu.Unlock()
	if !needed {
		return nil
	}
	release, err := l.holdServing(ctx)
	if err != nil {
		return fmt.Errorf("point this machine at app-tail's resolver: %w", err)
	}
	l.mu.Lock()
	l.releaseServing = release
	l.mu.Unlock()
	return nil
}

// releaseSystemDNS gives the serving lock up. The caller holds the lock.
func (l *Local) releaseSystemDNS() error {
	if l.releaseServing == nil {
		return nil
	}
	release := l.releaseServing
	l.releaseServing = nil
	if err := release(); err != nil {
		return fmt.Errorf("let go of the resolver lock: %w", err)
	}
	return nil
}

// BaseSystemDNS reports what this machine resolves names with without app-tail in the path.
func (l *Local) BaseSystemDNS(ctx context.Context) (sysdns.Base, error) {
	l.mu.Lock()
	manager := l.systemDNS()
	l.mu.Unlock()
	return manager.Base(ctx)
}

// systemResolver is what this session asks of the machine's own resolver: to be pointed at
// app-tail, put back, read for what it had, and to carry the loopback address app-tail
// listens on.
type systemResolver interface {
	Apply(ctx context.Context, addrs []netip.Addr) error
	Clear(ctx context.Context) error
	Base(ctx context.Context) (sysdns.Base, error)
	HoldLoopback(ctx context.Context, addr netip.Addr) error
}

// systemDNS returns this session's resolver manager, building it on first use. The caller
// holds the lock.
func (l *Local) systemDNS() systemResolver {
	if l.sysdns == nil {
		l.sysdns = sysdns.New(sysdns.DefaultRecordPath(), l.logf)
	}
	return l.sysdns
}

// closeSystemDNS puts this machine's resolver back and releases any socket that was bound
// and never handed over. The caller holds the lock.
//
// It runs first in the teardown, before the interface: a machine pointed at app-tail's
// resolver while app-tail's resolver is being taken down resolves nothing, and the window
// where that is true is exactly as long as this ordering makes it.
func (l *Local) closeSystemDNS() []error {
	var errs []error
	if l.systemDNSApplied {
		ctx, cancel := context.WithTimeout(context.Background(), systemDNSRestoreTimeout)
		defer cancel()
		if err := l.systemDNS().Clear(ctx); err != nil {
			errs = append(errs, fmt.Errorf("restore this machine's resolver: %w", err))
		}
		l.systemDNSApplied = false
		// Released even after a failed restore: this session is going, and the lock it leaves
		// free is what lets the repair finish the job.
		if err := l.releaseSystemDNS(); err != nil {
			errs = append(errs, err)
		}
	}
	// A socket that was bound and never asked for belongs to nobody: the caller that would
	// have taken it is gone, and a listening socket on port 53 with nothing behind it is
	// worse than no socket at all.
	return append(errs, l.closeUnclaimedResolver()...)
}

// RepairSystemDNS puts this machine's resolver back from whatever a previous run recorded,
// then hands back to its network any service still pointed only at an address app-tail
// listens on, and reports whether it changed anything.
//
// The first half covers a machine that was pointed at app-tail and then lost the process
// without running any of its code -- a kill, a panic, a power cut. The record is root-owned
// and read by whatever holds the rights next: the macOS and Linux helper, the Windows
// boot-time task, or the next agent. The second half is what the record cannot cover: a
// service it lost while the override stood is pointed at a loopback address nothing listens
// on, and this machine resolves no names through it. Both are only safe while no app-tail is
// serving this machine, which the caller has to know: the helper asks its session gate, and
// every other caller runs before an agent has started or because there is none.
//
// A repair holds the serving lock while it runs and does nothing while anyone else holds it,
// reporting ErrResolverServed: an app-tail serving this machine puts back what it changed when
// it stops, and one applying its override waits for the repair to finish.
func RepairSystemDNS(ctx context.Context, logf func(format string, args ...any)) (bool, error) {
	recordPath := sysdns.DefaultRecordPath()
	return repairUnlessServed(ctx, func() (func() error, bool, error) { return trySystemDNSServing(recordPath) },
		sysdns.New(recordPath, logf))
}

// ErrResolverServed is a repair refusing because an app-tail is serving this machine's
// resolver.
var ErrResolverServed = errors.New("an app-tail is serving this machine's resolver and puts it back itself when it stops")

func repairUnlessServed(ctx context.Context, hold func() (func() error, bool, error), manager recordedResolver) (bool, error) {
	release, held, err := hold()
	if err != nil {
		return false, err
	}
	if !held {
		return false, ErrResolverServed
	}
	changed, err := repairSystemDNS(ctx, manager)
	return changed, errors.Join(err, release())
}

// trySystemDNSServing takes the serving lock beside the record at recordPath without waiting.
func trySystemDNSServing(recordPath string) (func() error, bool, error) {
	serving, held, err := sysdns.TryHoldServing(recordPath)
	if err != nil || !held {
		return nil, held, err
	}
	return serving.Release, true, nil
}

const (
	// servingWait bounds how long applying an override waits for the serving lock. A repair
	// holding it is bounded by systemDNSRestoreTimeout, so outlasting that by a margin means
	// another app-tail is serving this machine rather than a repair finishing.
	servingWait = systemDNSRestoreTimeout + 5*time.Second
	// servingPoll is how often the wait asks again.
	servingPoll = 250 * time.Millisecond
)

// holdSystemDNSServing takes the serving lock for a session about to point this machine at
// app-tail, waiting out a repair in progress.
func holdSystemDNSServing(ctx context.Context) (func() error, error) {
	ctx, cancel := context.WithTimeout(ctx, servingWait)
	defer cancel()
	ticker := time.NewTicker(servingPoll)
	defer ticker.Stop()
	for {
		release, held, err := trySystemDNSServing(sysdns.DefaultRecordPath())
		if err != nil {
			return nil, err
		}
		if held {
			return release, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("another app-tail is serving this machine's resolver, or a repair of it is still running: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

// recordedResolver is the part of the resolver manager a repair uses, so the order and the
// joining of its two halves are checked without a machine to change.
type recordedResolver interface {
	Installed() (bool, error)
	Clear(ctx context.Context) error
	ReleaseStrays(ctx context.Context, ours []netip.Addr) ([]string, error)
}

func restoreRecorded(ctx context.Context, manager recordedResolver) (bool, error) {
	installed, err := manager.Installed()
	if err != nil {
		return false, err
	}
	if !installed {
		return false, nil
	}
	if err := manager.Clear(ctx); err != nil {
		return true, err
	}
	return true, nil
}

// repairSystemDNS runs the sweep even when the restore failed: a record naming an adapter
// that is unplugged fails every restore, and that must not leave the services it does not
// name pointed at nothing.
func repairSystemDNS(ctx context.Context, manager recordedResolver) (bool, error) {
	restored, err := restoreRecorded(ctx, manager)
	released, strayErr := manager.ReleaseStrays(ctx, ownResolverAddrs())
	return restored || len(released) > 0, errors.Join(err, strayErr)
}

// ownResolverAddrs are the addresses this helper can listen for DNS on whatever the caller
// asked for, which is what makes a service pointed only at them app-tail's.
func ownResolverAddrs() []netip.Addr {
	out := make([]netip.Addr, 0, len(resolverFallbacks))
	for _, fallback := range resolverFallbacks {
		out = append(out, fallback.Addr())
	}
	return out
}

// PartialSystemDNSRestore reports a restore that put this machine back everywhere it could
// reach, leaving a record of the services it could not. It answers for both sides of the
// privilege boundary: the helper's sentence is rebuilt as the sentinel when it crosses.
func PartialSystemDNSRestore(err error) bool {
	return errors.Is(err, sysdns.ErrPartialRestore)
}

// SystemDNSOverridden reports whether a previous run left this machine pointed at app-tail
// and it still is.
//
// It asks the machine as well as the record, because a record survives a restore that could
// not reach one of its services -- an adapter switched off, a dock unplugged -- and that entry
// stays until the adapter comes back. Answering from the record alone would turn an adapter
// that is really gone into a prompt for administrator rights at every start, forever.
func SystemDNSOverridden(ctx context.Context) (bool, error) {
	return sysdns.New(sysdns.DefaultRecordPath(), func(string, ...any) {}).Overridden(ctx)
}

// DetectStaleOverride names a machine whose name resolution a previous run left pointed at
// app-tail, empty when there is nothing to put back.
//
// A record this process is not allowed to read reports nothing rather than a guess: the file
// is root-owned on macOS and Linux, so the answer from an unprivileged process there is
// "cannot tell", and reporting that as a stale override would put a warning on every machine
// that never used the feature. Any other failure is reported, because on Windows -- the one
// platform that asks this question unprivileged and acts on it -- the record is deliberately
// readable by users, so a failure there is a real one, and a machine whose record cannot be
// acted on is a machine whose override cannot be removed.
func DetectStaleOverride(ctx context.Context) string {
	return staleOverrideMessage(SystemDNSOverridden(ctx))
}

// staleOverrideMessage is DetectStaleOverride's answer for what the record and the machine
// said, kept apart from the reading so every answer can be checked without a record.
func staleOverrideMessage(overridden bool, err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return ""
	case err != nil:
		return "app-tail cannot tell whether this machine's name resolution is still pointed at itself " +
			"from an earlier run: " + err.Error()
	case !overridden:
		return ""
	}
	return "this machine's name resolution is still pointed at app-tail from an earlier run, " +
		"and app-tail will put it back the next time it starts with administrator rights"
}

// requestedListen reads the caller's preferred address out of a request. An absent one is
// the zero value, which means "wherever you can" rather than a failure: the helper's own
// ladder is the answer to that.
func requestedListen(text string) (netip.AddrPort, error) {
	if text == "" {
		return netip.AddrPort{}, nil
	}
	addr, err := netip.ParseAddrPort(text)
	if err != nil {
		// Quoted, because the platform's own message names neither the value nor the field:
		// "not an ip:port" alone leaves whoever reads the log with no way to tell which
		// address was refused.
		return netip.AddrPort{}, fmt.Errorf("read %q as the address to listen for DNS on: %w", text, err)
	}
	return addr, nil
}

// parseResolvers reads the addresses to point this machine at. They cross as text because
// that is what the rest of this protocol does, and an address that does not parse is
// refused rather than skipped: a list silently shortened by one is a machine pointed
// somewhere the caller did not ask for.
func parseResolvers(list []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(list))
	for _, text := range list {
		addr, err := netip.ParseAddr(text)
		if err != nil {
			return nil, fmt.Errorf("read the resolver address %q: %w", text, err)
		}
		out = append(out, addr)
	}
	return out, nil
}

// formatResolvers is the other direction, on the caller's side.
func formatResolvers(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return out
}

// socketFile is the part of a listening socket that can cross the boundary: the descriptor
// underneath it.
type socketFile interface {
	File() (*os.File, error)
	Close() error
}

// handOverResolver sends a bound socket's descriptor to the caller and closes this side's
// copy.
//
// The copy goes as soon as the descriptor is across, which is the opposite of what the
// interface does and for the opposite reason: an interface has to be takeable back, and a
// listening socket has to go away when the process using it does. A copy kept here would
// hold port 53 for as long as the helper runs, which is until the machine is shut down.
func handOverResolver(conn *net.UnixConn, sock socketFile, addr string, logf func(format string, args ...any)) error {
	file, err := sock.File()
	if err != nil {
		closeQuietly(sock)
		return writeMessage(conn, response{Error: fmt.Sprintf("hand over the resolver socket: %v", err)})
	}
	defer func() {
		if err := file.Close(); err != nil {
			logf("could not close this side's copy of the resolver descriptor: %v", err)
		}
		if err := sock.Close(); err != nil {
			logf("could not close this side's copy of the resolver socket: %v", err)
		}
	}()
	return writeWithFile(conn, response{Listen: addr}, file)
}
