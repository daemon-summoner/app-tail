// SPDX-License-Identifier: MIT

// Package sysdns points this machine's own resolver at an address app-tail is listening
// on, and puts back what was there before.
//
// It is the half of the system-wide DNS switch that touches the machine, and everything
// in it runs with administrator rights: on macOS and Linux inside the privileged helper,
// on Windows inside the elevated process. Nothing here decides which resolver to use or
// speaks DNS -- that is internal/dnsfwd, which is unprivileged and knows nothing about
// network services.
//
// Every value replaced is written down before it is replaced, and put back at the next
// start as well as at exit. That is a best effort by construction: a process that is
// killed cannot restore anything, which is why the record is on disk and why the helper
// reads it before it does anything else.
//
// The setting is per network service, because a laptop that docks has several and each
// carries its own. A service someone else changed after we wrote it is left alone: putting
// the older value back over a newer one is the same mistake in the other direction.
package sysdns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/sellitus/app-tail/internal/fileown"
)

// RecordFileName remembers what was replaced. It lives beside no config file: the process
// that writes it is root, and a record a user can edit is a list of commands root will
// carry out later.
const RecordFileName = "systemdns-restore.json"

const (
	// dirMode and fileMode keep the record readable and writable only by root.
	dirMode  = 0o700
	fileMode = 0o600
)

// tailnetResolvers are the addresses a tailnet client points a machine at. They are
// filtered out of the base set: forwarding to them would send every name the user looks up
// back through the tailnet resolver, which forwards it back to us.
var tailnetResolvers = []netip.Addr{
	netip.MustParseAddr("100.100.100.100"),
	netip.MustParseAddr("fd7a:115c:a1e0::53"),
}

// Service is one network service that carries a resolver setting -- Wi-Fi, an ethernet
// port, a VPN.
type Service struct {
	// ID identifies the service across renames, and is the key the record is written
	// under.
	ID string `json:"id"`
	// Name is what the platform's own tools call it, and what a set command takes.
	Name string `json:"name"`
}

// Base is what a machine would resolve names with if app-tail were not here.
type Base struct {
	// Nameservers are the resolvers the network published, in order.
	Nameservers []netip.Addr `json:"nameservers,omitempty"`
	// SearchDomains are the suffixes the network published, which is how a name this
	// network made up is recognised.
	SearchDomains []string `json:"searchDomains,omitempty"`
}

// machineResolver is this machine's own resolver configuration.
//
// It is an interface so the bookkeeping below -- which is where the mistakes that lose
// someone's original settings live -- is exercised on every platform rather than only on
// the ones with an implementation.
type machineResolver interface {
	// supported reports that this platform can be changed, and why not when it cannot.
	supported() (bool, string)
	// services lists the services worth writing to: active, enabled, and not app-tail's
	// or another tailnet client's own.
	services(ctx context.Context) ([]Service, error)
	// get reads the resolvers one service is currently set to, empty when the service is
	// following the network's own.
	get(ctx context.Context, s Service) ([]netip.Addr, error)
	// set points a service at the addresses. An empty list restores it to the network's
	// own, which is not the same as writing an empty one.
	set(ctx context.Context, s Service, addrs []netip.Addr) error
	// base reports what a service would resolve with if nothing had overridden it. It is
	// read from a different place than get writes to, which is what makes it readable
	// while our own override is in place.
	base(ctx context.Context, s Service) (Base, error)
	// flush makes a change take effect now. Every platform caches answers, and a switch
	// whose effect arrives when the cache expires reads as a switch that did nothing.
	flush(ctx context.Context) error
	// holdLoopback makes one address of this machine's own loopback bindable, and
	// releaseLoopback gives it back.
	//
	// macOS assigns 127.0.0.1 and nothing else, so every other address in 127/8 is refused
	// with "can't assign requested address" until an alias exists -- which is the whole
	// reason this pair is on the interface. A platform that assigns the range already
	// refuses both, loudly: silently succeeding would record a claim on machine state that
	// was never made.
	holdLoopback(ctx context.Context, addr netip.Addr) error
	releaseLoopback(ctx context.Context, addr netip.Addr) error
}

// Manager applies and restores this machine's resolver configuration.
type Manager struct {
	machine    machineResolver
	recordPath string
	logf       func(format string, args ...any)

	// mu serialises whole operations. Each one is several seconds of shell-outs, and two
	// running at once would interleave their reads and writes into a record that describes
	// neither.
	mu sync.Mutex
}

// New builds a manager writing its record to path. An empty path uses the platform's own.
func New(path string, logf func(format string, args ...any)) *Manager {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if path == "" {
		path = DefaultRecordPath()
	}
	return &Manager{machine: newMachineResolver(logf), recordPath: path, logf: logf}
}

// Supported reports whether this platform's resolver can be pointed anywhere, and why not
// when it cannot. The reason is shown to the user, so it names what is missing rather than
// the platform.
func (m *Manager) Supported() (bool, string) { return m.machine.supported() }

// record is what was replaced, per service, and what replaced it.
//
// Wrote is kept alongside Prior so restoring can tell "the value we set is still there"
// from "someone changed it since".
type record struct {
	Services map[string]serviceRecord `json:"services"`
	// Loopback are the addresses app-tail added to this machine's loopback interface so it
	// could listen on them. They are machine state like the resolver setting, written down
	// for the same reason and put back on the same paths.
	Loopback []string `json:"loopback,omitempty"`
	// Ours is every address app-tail has pointed a service at while this record stood. Wrote
	// is only the last of them, and app-tail moves between addresses when its answers
	// change: a service whose write to the new one failed, or that a quit reached first, is
	// still on the old one, and a restore reading Wrote alone would take that for someone
	// else's setting and leave it pointed at an address nothing listens on.
	Ours []string `json:"ours,omitempty"`
}

type serviceRecord struct {
	Name  string   `json:"name"`
	Prior []string `json:"prior"`
	Wrote []string `json:"wrote"`
}

func (r record) empty() bool { return len(r.Services) == 0 && len(r.Loopback) == 0 }

// wroteHere reports whether a service set to current is still set by app-tail: to what it
// wrote last, or to addresses it has written before. An empty list is nobody's override:
// it is the network's own resolvers.
func (r record) wroteHere(current []netip.Addr, wrote []netip.Addr) bool {
	return sameAddrs(current, wrote) || onlyOurs(current, r.Ours)
}

// overriding reports that this machine's name resolution is pointed at app-tail. A record
// holding only a loopback address is app-tail having arranged somewhere to listen and
// nothing more, which changes nothing about how any name is resolved.
func (r record) overriding() bool { return len(r.Services) > 0 }

// Apply points every eligible service at addrs, remembering what each pointed at before.
//
// Applying twice is not an error and does not overwrite what was remembered: the first
// application is the one that saw the user's own setting, and a second that recorded our
// own address as "prior" would make restoring a no-op forever.
func (m *Manager) Apply(ctx context.Context, addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return errors.New("point this machine's resolver somewhere: no address was given")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if supported, reason := m.machine.supported(); !supported {
		return fmt.Errorf("point this machine's resolver at app-tail: %s", reason)
	}

	states, err := m.read(ctx)
	if err != nil {
		return err
	}
	rec, err := m.readRecord()
	if err != nil {
		return err
	}

	changes := plan(states, addrs, rec)
	next := merge(rec, changes)
	// Written before the change, never after: a crash between the two would otherwise
	// leave the machine pointing at app-tail with nothing remembering what it replaced,
	// and the next boot would have no way back.
	if err := m.writeRecord(next); err != nil {
		return err
	}
	_, err = m.perform(ctx, changes)
	return err
}

// Clear puts back whatever each service had before, and is safe to call when nothing was
// ever applied. It is the whole of the way back, and it runs at exit, at the next start,
// and before the helper is uninstalled.
func (m *Manager) Clear(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, err := m.readRecord()
	if err != nil {
		return err
	}
	if rec.empty() {
		return nil
	}
	if supported, reason := m.machine.supported(); !supported {
		// Nothing here could have applied it, so nothing here should restore it. The
		// record is dropped so this does not repeat on every start.
		m.logf("dropping a resolver record this platform cannot act on: %s", reason)
		return m.removeRecord()
	}

	states := make([]state, 0, len(rec.Services))
	for id, sr := range rec.Services {
		service := Service{ID: id, Name: sr.Name}
		current, err := m.machine.get(ctx, service)
		if err != nil {
			// A service that has gone -- an unplugged dock, a removed VPN -- carries no
			// setting to restore, and refusing to restore the rest because of it would
			// leave the machine pointed at a resolver that is not running.
			m.logf("could not read the resolver setting for %s, leaving it alone: %v", sr.Name, err)
			continue
		}
		states = append(states, state{Service: service, Current: current})
	}

	changes := planRestore(states, rec)
	settled, err := m.perform(ctx, changes)
	// Narrowed to what is still to put back, always, and before anything can return: a
	// service dropped above carries no change, so retiring it with the rest is how an adapter
	// that was down at exit comes back pointed at app-tail with nothing left on the machine
	// that remembers what it had.
	remaining := unsettled(rec, settled)
	if err != nil {
		if writeErr := m.writeRecord(remaining); writeErr != nil {
			m.logf("could not narrow the resolver record to what is still to put back: %v", writeErr)
		}
		return err
	}
	if err := m.releaseLoopback(ctx, rec); err != nil {
		if writeErr := m.writeRecord(remaining); writeErr != nil {
			m.logf("could not narrow the resolver record to what is still to put back: %v", writeErr)
		}
		return err
	}
	// The addresses are off the loopback, so the record must stop saying to take them off.
	remaining.Loopback = nil
	if remaining.empty() {
		return m.removeRecord()
	}
	if err := m.writeRecord(remaining); err != nil {
		return err
	}
	return &PartialRestoreError{Services: serviceNames(remaining)}
}

// ReleaseStrays points every active service that resolves only through addresses app-tail
// listens on back at its network's own resolvers, and reports the names of the ones it
// changed. ours is the set of addresses app-tail could be listening on; whatever the record
// says app-tail has written is added to it.
//
// Clear can only put back what the record names, and a record can lose a service while the
// override stands -- a write that failed after the change, a record from a run that crashed
// between the two, an adapter renamed under it. Such a service is still pointed at a loopback
// address nothing is listening on, and this machine resolves no names through it until
// something notices. The caller decides when nothing is listening: this has no way to know.
//
// A service the record still names is left to Clear, which can put back what it really had
// rather than the network's own. A service whose list mixes in any address that is not ours
// is somebody else's setting and is left alone.
func (m *Manager) ReleaseStrays(ctx context.Context, ours []netip.Addr) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if supported, _ := m.machine.supported(); !supported {
		return nil, nil
	}
	rec, err := m.readRecord()
	if err != nil {
		return nil, err
	}
	services, err := m.machine.services(ctx)
	if err != nil {
		return nil, err
	}
	known := addOurs(formatAddrs(ours), rec.Ours)
	var changes []change
	for _, s := range services {
		if _, recorded := rec.Services[s.ID]; recorded {
			continue
		}
		current, err := m.machine.get(ctx, s)
		if err != nil {
			// Not shown to be app-tail's, so not app-tail's to change, as in Clear.
			m.logf("could not read the resolver setting for %s, leaving it alone: %v", s.Name, err)
			continue
		}
		if !onlyOurs(current, known) {
			continue
		}
		changes = append(changes, change{Service: s, Prior: current})
	}
	settled, err := m.perform(ctx, changes)
	released := make([]string, 0, len(settled))
	for _, c := range changes {
		if settled[c.Service.ID] {
			released = append(released, c.Service.Name)
		}
	}
	return released, err
}

// onlyOurs reports a resolver list made up entirely of addresses in ours. An empty list is
// the network's own resolvers, which is nobody's override.
func onlyOurs(current []netip.Addr, ours []string) bool {
	if len(current) == 0 {
		return false
	}
	for _, addr := range current {
		if !slices.Contains(ours, addr.String()) {
			return false
		}
	}
	return true
}

// Installed reports whether an override is recorded as being in place, which is what
// separates "app-tail changed this machine" from "it is set that way".
func (m *Manager) Installed() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, err := m.readRecord()
	if err != nil {
		return false, err
	}
	return rec.overriding(), nil
}

// Overridden reports whether this machine is pointed at app-tail right now, by asking the
// machine rather than only the record.
//
// Installed answers from the record alone, which is what makes it safe on any path -- and
// also what makes it say yes forever about a service that has been removed from the machine.
// A restore keeps the entry for a service it could not reach, because the alternative is
// losing the only way back for an adapter that is merely unplugged; this is the question that
// keeps that from turning into a prompt at every start for an adapter that is really gone.
func (m *Manager) Overridden(ctx context.Context) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, err := m.readRecord()
	if err != nil {
		return false, err
	}
	if !rec.overriding() {
		return false, nil
	}
	if supported, _ := m.machine.supported(); !supported {
		return false, nil
	}
	for id, sr := range rec.Services {
		current, err := m.machine.get(ctx, Service{ID: id, Name: sr.Name})
		if err != nil {
			// Unreachable is not overridden: the service this names is not resolving anything
			// at all right now, so it is not what is stopping this machine resolving names.
			continue
		}
		if rec.wroteHere(current, parseAddrs(sr.Wrote)) {
			return true, nil
		}
	}
	return false, nil
}

// ErrPartialRestore marks a restore that reached every service it could. It is a sentinel as
// well as a type because the answer crosses the helper socket as a sentence, where the type
// does not survive: both sides have to keep telling this apart from a restore that went
// wrong, since this one leaves a record the next privileged run finishes from.
var ErrPartialRestore = errors.New("this machine's resolver was put back except on the network services app-tail could not reach")

// PartialRestoreError reports a restore that put some services back and could not reach
// others. The record survives naming exactly those, so the next run with the rights finishes
// the job -- which is why this is an error rather than a nil that reads as success.
type PartialRestoreError struct {
	// Services are the names still recorded as pointed at app-tail, in a stable order.
	Services []string
}

func (e *PartialRestoreError) Error() string {
	return fmt.Sprintf("%s (%s). app-tail has kept what they had and will put it back the next "+
		"time it runs with administrator rights", ErrPartialRestore, joinComma(e.Services))
}

func (e *PartialRestoreError) Unwrap() error { return ErrPartialRestore }

// unsettled narrows a record to what a pass did not put back.
func unsettled(rec record, settled map[string]bool) record {
	out := record{
		Services: make(map[string]serviceRecord, len(rec.Services)),
		Loopback: slices.Clone(rec.Loopback),
		Ours:     slices.Clone(rec.Ours),
	}
	for id, sr := range rec.Services {
		if settled[id] {
			continue
		}
		out.Services[id] = sr
	}
	return out
}

// serviceNames lists a record's services by the name they were recorded under. Sorted,
// because the record is a map and a message that reorders itself between two runs reads as
// two different machines.
func serviceNames(rec record) []string {
	out := make([]string, 0, len(rec.Services))
	for _, sr := range rec.Services {
		out = append(out, sr.Name)
	}
	slices.Sort(out)
	return out
}

// HoldLoopback makes addr bindable on this machine's loopback and remembers that it did, so
// the address is given back on every path that puts this machine back.
//
// It exists because macOS assigns 127.0.0.1 alone: the address app-tail listens for DNS on
// is refused until it is aliased onto lo0. Recorded before it is created, for the reason
// Apply records before it writes -- a crash between the two would otherwise leave an address
// on this machine's loopback with nothing remembering to remove it.
func (m *Manager) HoldLoopback(ctx context.Context, addr netip.Addr) error {
	if !addr.IsValid() || !addr.IsLoopback() {
		return fmt.Errorf("app-tail will only add an address to this machine's own loopback, and %s is not one", addr)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, err := m.readRecord()
	if err != nil {
		return err
	}
	text := addr.String()
	if !slices.Contains(rec.Loopback, text) {
		rec.Loopback = append(rec.Loopback, text)
		if err := m.writeRecord(rec); err != nil {
			return err
		}
	}
	// Created even when it was already recorded: a record can outlive the machine state it
	// describes -- a reboot drops every alias -- and the caller is asking because it could
	// not bind.
	return m.machine.holdLoopback(ctx, addr)
}

// releaseLoopback gives back every address the record says app-tail added, after the
// resolver setting has been put back.
//
// That order is not an optimisation: a machine still pointed at an address whose alias has
// been removed resolves no names at all, and the window where that is true is exactly as
// long as this ordering makes it.
func (m *Manager) releaseLoopback(ctx context.Context, rec record) error {
	var errs []error
	for _, text := range rec.Loopback {
		addr, err := netip.ParseAddr(text)
		if err != nil {
			errs = append(errs, fmt.Errorf("read the recorded loopback address %q: %w", text, err))
			continue
		}
		if err := m.machine.releaseLoopback(ctx, addr); err != nil {
			errs = append(errs, fmt.Errorf("give back the loopback address %s: %w", addr, err))
			continue
		}
		m.logf("gave back the loopback address %s", addr)
	}
	return errors.Join(errs...)
}

// Base reports what this machine would resolve names with if app-tail were not here.
//
// It is read while the override is in place, from the layer the override does not write,
// and it is what the forwarder sends a private name to. Our own addresses and a tailnet
// client's are filtered out: forwarding to either is a query that comes back to us.
func (m *Manager) Base(ctx context.Context) (Base, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if supported, reason := m.machine.supported(); !supported {
		return Base{}, fmt.Errorf("read this machine's own resolvers: %s", reason)
	}
	services, err := m.machine.services(ctx)
	if err != nil {
		return Base{}, err
	}
	rec, err := m.readRecord()
	if err != nil {
		return Base{}, err
	}
	var out Base
	var errs []error
	for _, s := range services {
		base, err := m.machine.base(ctx, s)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name, err))
			continue
		}
		// A machine configured by hand keeps its resolvers in the same layer the override
		// writes, so on a platform that cannot read past the override there is nothing left
		// to read once app-tail is in place. What that service answered with before the
		// override is written down, and it is the same answer.
		if len(base.Nameservers) == 0 {
			base.Nameservers = recordedPrior(rec, s.ID)
		}
		for _, addr := range base.Nameservers {
			if !usableBaseResolver(addr) || slices.Contains(out.Nameservers, addr) {
				continue
			}
			out.Nameservers = append(out.Nameservers, addr)
		}
		for _, domain := range base.SearchDomains {
			if domain != "" && !slices.Contains(out.SearchDomains, domain) {
				out.SearchDomains = append(out.SearchDomains, domain)
			}
		}
	}
	if len(out.Nameservers) == 0 && len(errs) > 0 {
		return Base{}, errors.Join(errs...)
	}
	for _, err := range errs {
		m.logf("could not read one service's own resolvers: %v", err)
	}
	return out, nil
}

// recordedPrior reports what one service resolved through before app-tail replaced it. An
// address the record cannot be read as is skipped rather than failing the read: the record
// is a way back, and one unreadable entry in it must not cost the caller the others.
func recordedPrior(rec record, id string) []netip.Addr {
	var out []netip.Addr
	for _, text := range rec.Services[id].Prior {
		if addr, err := netip.ParseAddr(text); err == nil {
			out = append(out, addr)
		}
	}
	return out
}

// usableBaseResolver rejects the addresses that would send a query back to this machine.
//
// A loopback address here is either app-tail's own listener or another local resolver
// which is itself forwarding somewhere; forwarding to it is at best a second hop and at
// worst a loop. The unspecified address is not a resolver at all.
func usableBaseResolver(addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	return !slices.Contains(tailnetResolvers, addr)
}

// state is one service and what it is set to right now.
type state struct {
	Service Service
	Current []netip.Addr
}

// read gathers every eligible service and what it currently resolves through.
func (m *Manager) read(ctx context.Context) ([]state, error) {
	services, err := m.machine.services(ctx)
	if err != nil {
		return nil, err
	}
	if len(services) == 0 {
		return nil, errors.New("this machine has no active network service to point at a resolver")
	}
	states := make([]state, 0, len(services))
	var errs []error
	for _, s := range services {
		current, err := m.machine.get(ctx, s)
		if err != nil {
			errs = append(errs, fmt.Errorf("read the resolver setting for %s: %w", s.Name, err))
			continue
		}
		states = append(states, state{Service: s, Current: current})
	}
	if len(states) == 0 {
		return nil, errors.Join(errs...)
	}
	for _, err := range errs {
		m.logf("skipping one network service: %v", err)
	}
	return states, nil
}

// perform carries out the changes, running every one even after an earlier failure. A
// half-applied override with the rest abandoned is the state that leaves a machine
// resolving on one interface and not on another.
//
// The settled set names the services the record no longer has to answer for: the ones
// written, and the ones skipped because something else owns their setting now. A service
// whose write failed is in neither, which is what lets a restore tell "put back" from
// "reported nothing and changed nothing".
func (m *Manager) perform(ctx context.Context, changes []change) (map[string]bool, error) {
	settled := make(map[string]bool, len(changes))
	var errs []error
	wrote := false
	for _, c := range changes {
		if c.Skip != "" {
			settled[c.Service.ID] = true
			m.logf("leaving %s alone: %s", c.Service.Name, c.Skip)
			continue
		}
		if err := m.machine.set(ctx, c.Service, c.Set); err != nil {
			errs = append(errs, fmt.Errorf("point %s at %s: %w", c.Service.Name, describe(c.Set), err))
			continue
		}
		settled[c.Service.ID] = true
		wrote = true
		m.logf("pointed %s at %s (it was %s)", c.Service.Name, describe(c.Set), describe(c.Prior))
	}
	if wrote {
		// Not joined with the failures above: a cache that could not be flushed is a
		// change that arrives late, not one that did not happen, and reporting it as a
		// failed apply would send the caller into a retry that changes nothing.
		if err := m.machine.flush(ctx); err != nil {
			m.logf("could not flush this machine's resolver cache, so the change may take a moment: %v", err)
		}
	}
	return settled, errors.Join(errs...)
}

// describe renders a resolver list the way a log line should read.
func describe(addrs []netip.Addr) string {
	if len(addrs) == 0 {
		return "this network's own resolvers"
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return joinComma(out)
}

func joinComma(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// readRecord reads what was replaced. A missing file is an empty record rather than a
// failure: it is the ordinary state of a machine nothing has been applied to.
func (m *Manager) readRecord() (record, error) {
	if err := m.haveRecordPath(); err != nil {
		return record{}, err
	}
	raw, err := os.ReadFile(m.recordPath)
	if errors.Is(err, os.ErrNotExist) {
		return record{}, nil
	}
	if err != nil {
		return record{}, fmt.Errorf("read the record of this machine's replaced resolvers: %w", err)
	}
	// The record names the addresses an elevated app-tail points this machine at when it
	// puts the resolver setting back, so a record another account could have written is one
	// this must not act on.
	owned, owner, err := fileown.OwnedByAdministrators(m.recordPath)
	if err != nil {
		return record{}, err
	}
	if !owned {
		return record{}, fmt.Errorf("the record of this machine's replaced resolvers at %s belongs to %s rather than to the administrators group, "+
			"and it names the resolvers app-tail would point this machine at: remove it, then turn the system-wide resolver off and on again", m.recordPath, owner)
	}
	var rec record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return record{}, fmt.Errorf("read the record of this machine's replaced resolvers at %s: %w", m.recordPath, err)
	}
	return rec, nil
}

// haveRecordPath refuses before touching anything when the platform could not say where the
// record belongs. Every operation here reads or writes it, and one that carried on would
// point this machine's resolver somewhere with nothing written down to put it back.
func (m *Manager) haveRecordPath() error {
	if m.recordPath == "" {
		return errors.New("app-tail could not work out where this machine keeps its machine-wide application data, " +
			"so it has nowhere to write down what it replaced and will not change how this machine resolves names")
	}
	return nil
}

func (m *Manager) writeRecord(rec record) error {
	if err := m.haveRecordPath(); err != nil {
		return err
	}
	if err := fileown.MakeRestrictedDir(filepath.Dir(m.recordPath), dirMode); err != nil {
		return fmt.Errorf("make the directory for the resolver record: %w", err)
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("encode the resolver record: %w", err)
	}
	return fileown.WriteRestricted(m.recordPath, append(raw, '\n'), fileMode)
}

func (m *Manager) removeRecord() error {
	if err := os.Remove(m.recordPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the resolver record: %w", err)
	}
	return nil
}
