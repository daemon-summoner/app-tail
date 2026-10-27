// SPDX-License-Identifier: MIT

package hostnet

// The machine state this side installed, written down so the next privileged start can take
// it back.
//
// Everything here is undone by a teardown, and the teardown runs on every path that ends this
// process in an orderly way -- including the one where the agent went away, since losing that
// connection is itself the signal. What none of it survives is this process running none of
// its own code: a kill, a panic, an out-of-memory, a power cut. What is left on the machine
// then is a default route scoped to an interface with nothing tracking it, and a root openvpn
// still holding a network interface with its configuration in a directory nobody will remove.
// Restarting changes nothing, because what was in memory went with the process.
//
// So the same thing sysdns does for this machine's resolver is done here for its routes and
// its child processes: written down before the change, in a file only root can read, and read
// back by whatever holds the rights next -- which on macOS and Linux is the helper at boot,
// before any agent has connected and before the socket it would connect to is open.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sellitus/app-tail/internal/fileown"
	"github.com/sellitus/app-tail/internal/sysdns"
)

// rootStateFileName is what the record is called. It sits beside the resolver's own record,
// in the same root-owned directory and for the same reason: a record a user can edit is a
// list of things root will do later.
const rootStateFileName = "hostnet-reclaim.json"

const (
	// stateDirMode and stateFileMode keep the record readable and writable only by root.
	stateDirMode  = 0o700
	stateFileMode = 0o600
)

// reclaimPollInterval is how often a process being stopped is checked for having gone. The
// process is not a child of this one, so there is nothing to wait on and the only way to know
// is to ask.
const reclaimPollInterval = 50 * time.Millisecond

// DefaultRootStatePath is where the record lives. The directory is the resolver record's own,
// so which root-owned place a platform uses is decided once rather than twice.
func DefaultRootStatePath() string {
	return filepath.Join(filepath.Dir(sysdns.DefaultRecordPath()), rootStateFileName)
}

// stateRecord is everything this side installed on the machine that outlives it.
type stateRecord struct {
	// HostRoutes are the copies of this machine's own default route, which are removed by
	// naming the same three things that installed them.
	HostRoutes []stateRoute `json:"hostRoutes,omitempty"`
	// Scoped is the interface each OpenVPN connection was given a default route on, by
	// connection id. Both address families go on one interface and are taken back together,
	// so the interface is the whole of what has to be remembered.
	Scoped map[string]string `json:"scoped,omitempty"`
	// OpenVPN is the connection each openvpn program was started for, by connection id.
	OpenVPN map[string]stateProcess `json:"openvpn,omitempty"`
}

// stateRoute is one scoped default route, in the terms its removal takes.
type stateRoute struct {
	Interface string `json:"interface"`
	Gateway   string `json:"gateway,omitempty"`
	V6        bool   `json:"v6,omitempty"`
}

// stateProcess is one openvpn program: where its configuration is, and what process number it
// was given.
type stateProcess struct {
	// Dir holds the rendered configuration, which carries a private key. It is removed
	// whether or not the process is still there, because a directory left in the temporary
	// area is a private key left on the disk.
	Dir string `json:"dir"`
	// PID is zero between the configuration being written and the program being started,
	// which is the one window where there is a directory to remove and no process to stop.
	PID int `json:"pid,omitempty"`
}

func (r stateRecord) empty() bool {
	return len(r.HostRoutes) == 0 && len(r.Scoped) == 0 && len(r.OpenVPN) == 0
}

// rootState reads and writes that record.
//
// It has a lock of its own rather than sharing the session's: every write is a read, a change
// and a write of one small file, and the callers hold the session lock across none of it.
type rootState struct {
	mu   sync.Mutex
	path string
	logf func(format string, args ...any)

	// What a reclaim does to the machine, held as fields so a test can stand in for them.
	// Each one is a signal sent or a program run, and what the record is for is precisely the
	// case where the machine refuses -- a process that will not be read, a route that will not
	// come off. Those answers cannot be arranged for on a real machine without root.
	askToClose     func(pid int) error
	killProcess    func(pid int) error
	processAlive   func(pid int) bool
	processArgs    func(ctx context.Context, pid int) (string, error)
	unscopeDefault routeChanger
	// stopGrace is how long a recorded process is given to go after each ask, so a test can
	// reach the case where it never goes without waiting out the real one.
	stopGrace time.Duration
}

// newRootState builds a reader and writer for the record at path.
func newRootState(path string, logf func(format string, args ...any)) *rootState {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &rootState{
		path:           path,
		logf:           logf,
		askToClose:     askToClose,
		killProcess:    killProcess,
		processAlive:   processAlive,
		processArgs:    processArgs,
		unscopeDefault: unscopeDefault,
		stopGrace:      openvpnStopGrace,
	}
}

// setHostRoutes records the copies of this machine's own default route that are on it.
func (s *rootState) setHostRoutes(routes []scopedHostRoute) error {
	return s.update(func(rec *stateRecord) {
		rec.HostRoutes = nil
		for _, route := range routes {
			rec.HostRoutes = append(rec.HostRoutes, stateRoute{
				Interface: route.iface, Gateway: route.gateway, V6: route.v6,
			})
		}
	})
}

// setScope records the interface one connection holds a default route on, an empty name for a
// connection that holds none.
func (s *rootState) setScope(id, iface string) error {
	return s.update(func(rec *stateRecord) {
		if iface == "" {
			delete(rec.Scoped, id)
			return
		}
		if rec.Scoped == nil {
			rec.Scoped = make(map[string]string)
		}
		rec.Scoped[id] = iface
	})
}

// setProcess records one openvpn program. A pid of zero is a configuration written for a
// program that has not been started yet.
func (s *rootState) setProcess(id, dir string, pid int) error {
	return s.update(func(rec *stateRecord) {
		if rec.OpenVPN == nil {
			rec.OpenVPN = make(map[string]stateProcess)
		}
		rec.OpenVPN[id] = stateProcess{Dir: dir, PID: pid}
	})
}

// dropProcess forgets one openvpn program, which is what its exit and the removal of its
// directory leave behind.
func (s *rootState) dropProcess(id string) error {
	return s.update(func(rec *stateRecord) { delete(rec.OpenVPN, id) })
}

// update reads the record, changes it and writes it back, removing the file once there is
// nothing left in it.
func (s *rootState) update(change func(*stateRecord)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.read()
	if err != nil {
		return err
	}
	change(&rec)
	return s.write(rec)
}

func (s *rootState) read() (stateRecord, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		// The ordinary state of a machine this side has installed nothing on.
		return stateRecord{}, nil
	}
	if err != nil {
		return stateRecord{}, fmt.Errorf("read the record of what app-tail installed on this machine: %w", err)
	}
	// The record names directories this side removes and processes it stops, all of it as
	// root, so a record another account could have written is one this must not act on. The
	// mode bits above are what carries that everywhere but Windows, where the directory it
	// lives in can be created by any account before app-tail ever runs elevated.
	owned, owner, err := fileown.OwnedByAdministrators(s.path)
	if err != nil {
		return stateRecord{}, err
	}
	if !owned {
		return stateRecord{}, fmt.Errorf("the record of what app-tail installed on this machine at %s belongs to %s rather than to the administrators group, "+
			"and it names directories app-tail would remove with administrator rights: remove it and start app-tail again", s.path, owner)
	}
	var rec stateRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return stateRecord{}, fmt.Errorf(
			"read the record of what app-tail installed on this machine at %s: %w", s.path, err)
	}
	return rec, nil
}

func (s *rootState) write(rec stateRecord) error {
	if rec.empty() {
		return s.remove()
	}
	if err := fileown.MakeRestrictedDir(filepath.Dir(s.path), stateDirMode); err != nil {
		return fmt.Errorf("make the directory for the record of what app-tail installed: %w", err)
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("encode the record of what app-tail installed: %w", err)
	}
	if err := fileown.WriteRestricted(s.path, append(raw, '\n'), stateFileMode); err != nil {
		return fmt.Errorf("write the record of what app-tail installed: %w", err)
	}
	return nil
}

func (s *rootState) remove() error {
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the record of what app-tail installed: %w", err)
	}
	return nil
}

// RepairPreviousRun undoes what a run that lost its process left on this machine: a resolver
// still pointed at app-tail, routes nothing is tracking, programs nothing is supervising.
//
// Where a helper is installed it has already done this at boot, before any login, and this
// does nothing. Where none is, this process is the privileged side and this is the only pass
// there is -- without it a killed agent leaves every adapter pointed at an address nothing
// answers on, across reboots, until somebody undoes it by hand.
//
// The question is HelperInstalled and not HasHelper, which asks something else: whether the
// split-process design exists on this platform at all. Linux has the design and no install
// step -- there is no one service manager to write a unit for, so the helper is started by
// hand -- so nothing there runs at boot, and a `sudo app-tail` on a Mac that never installed
// one is the same shape. Asking the design rather than the machine is how both came to have
// no startup repair at all.
//
// Doing nothing without the rights is the normal case rather than a failure: the state is
// reported as a stale override either way, and asking for the rights is what the start path
// does about it.
func RepairPreviousRun(ctx context.Context, logf func(format string, args ...any)) {
	repairPreviousRun(Privileged(), HelperInstalled(), func() {
		restorePreviousResolver(ctx, logf)
		reclaimPreviousRun(ctx, newRootState(DefaultRootStatePath(), logf), logf)
	})
}

// repairPreviousRun is the decision above, apart from the machine that answers it, because
// which of the two questions is asked is the whole of what makes this run or not.
func repairPreviousRun(privileged, helperInstalled bool, repair func()) {
	if !privileged || helperInstalled {
		return
	}
	repair()
}

// restorePreviousResolver puts this machine's resolver back from what a previous run left.
//
// The failure is reported and not fatal: refusing to start because an old change could not be
// undone leaves the machine in exactly the state the refusal is about, with nothing left that
// will ever repair it.
func restorePreviousResolver(ctx context.Context, logf func(format string, args ...any)) {
	restored, err := RepairSystemDNS(ctx, logf)
	switch {
	case errors.Is(err, ErrResolverServed):
		logf("left this machine's resolver alone: %v", err)
	case err != nil:
		logf("could not restore this machine's resolver from a previous run: %v", err)
	case restored:
		logf("restored this machine's resolver, which a previous run of app-tail left pointed at itself")
	}
}

func reclaimPreviousRun(ctx context.Context, state *rootState, logf func(format string, args ...any)) {
	reclaimed, err := state.reclaim(ctx)
	switch {
	case err != nil:
		// Reported and not fatal, for the reason the resolver's own restore is: refusing to
		// start leaves the machine in exactly the state the refusal is about, with nothing left
		// that will ever repair it.
		logf("could not take back what a previous run of app-tail left on this machine: %v", err)
	case reclaimed:
		logf("took back the routes and processes a previous run of app-tail left on this machine")
	}
}

// reclaim takes back what a previous run left on this machine, reporting whether there was
// anything to take back.
//
// It is the pass that covers what nothing else does: a run that lost its process without
// getting to undo anything. Every step is written to be the same operation whether or not the
// thing it names is still there, because by the time this runs most of it will not be -- an
// interface that went away took its routes with it, and a reboot took every process.
func (s *rootState) reclaim(ctx context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.read()
	if err != nil {
		return false, err
	}
	if rec.empty() {
		return false, nil
	}

	// The programs first: each one holds an interface, and an interface going away takes the
	// routes on it with it, so stopping them leaves the route removals with less to do rather
	// than more.
	var errs []error
	for _, id := range slices.Sorted(maps.Keys(rec.OpenVPN)) {
		if err := s.reclaimProcess(ctx, id, rec.OpenVPN[id]); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(rec.OpenVPN, id)
	}

	for _, id := range slices.Sorted(maps.Keys(rec.Scoped)) {
		iface := rec.Scoped[id]
		if err := unscopeBoth(ctx, s.unscopeDefault, iface); err != nil {
			errs = append(errs, fmt.Errorf(
				"take back the default route connection %s was given on %s: %w", id, iface, err))
			continue
		}
		s.logf("took back the default route a previous run left on %s for connection %s", iface, id)
		delete(rec.Scoped, id)
	}

	var heldRoutes []stateRoute
	for _, route := range rec.HostRoutes {
		if err := s.unscopeDefault(ctx, route.Interface, route.Gateway, route.V6); err != nil {
			errs = append(errs, fmt.Errorf(
				"take back the copy of this machine's own default route on %s: %w", route.Interface, err))
			heldRoutes = append(heldRoutes, route)
			continue
		}
		s.logf("took back the copy of this machine's own default route a previous run left on %s", route.Interface)
	}
	rec.HostRoutes = heldRoutes

	// Written back whatever happened above: what could not be taken back is still on the
	// machine, so it stays on the list the next start works through.
	if err := s.write(rec); err != nil {
		errs = append(errs, err)
	}
	return true, errors.Join(errs...)
}

// reclaimProcess stops one openvpn program a previous run started and removes the directory
// holding its configuration.
//
// The process number alone is not enough to act on. Numbers are reused, and this record
// outlives reboots, so a signal aimed at the number is aimed at whatever holds it now. What
// makes it safe is the configuration path: it is under a directory made with a random name by
// a root process, it appears in the program's own arguments, and nothing else on the machine
// has it there. A process that does not carry it is not the one that was recorded, and is left
// alone.
func (s *rootState) reclaimProcess(ctx context.Context, id string, p stateProcess) error {
	if err := s.stopReclaimedProcess(ctx, id, p); err != nil {
		return err
	}
	// Removed whether or not there was a process: the configuration carries a private key, and
	// the case with no process left is exactly the case where nothing else will ever remove it.
	if p.Dir == "" {
		return nil
	}
	if err := os.RemoveAll(p.Dir); err != nil {
		return fmt.Errorf("remove the configuration directory connection %s was left with: %w", id, err)
	}
	return nil
}

// stopReclaimedProcess ends the program if the number still names it.
func (s *rootState) stopReclaimedProcess(ctx context.Context, id string, p stateProcess) error {
	if p.PID <= 0 || !s.processAlive(p.PID) {
		return nil
	}
	args, err := s.processArgs(ctx, p.PID)
	if err != nil {
		// Reported rather than acted around: without knowing what the process is, signalling
		// it would be signalling a stranger, and that is worse than leaving it running.
		return fmt.Errorf(
			"could not tell whether process %d is the openvpn a previous run started for connection %s, so it was left alone: %w",
			p.PID, id, err)
	}
	want := openvpnConfigPath(p.Dir, id)
	if !strings.Contains(args, want) {
		s.logf("process %d is not the openvpn a previous run started for connection %s, leaving it alone", p.PID, id)
		return nil
	}

	// Asked to close first, for the reason a stop asks: openvpn answers the signal by telling
	// its server the client is leaving and taking its interface and routes down itself.
	if err := s.askToClose(p.PID); err != nil && !errors.Is(err, os.ErrProcessDone) {
		s.logf("could not ask the openvpn a previous run started for connection %s to close, killing it: %v", id, err)
	} else if s.waitForExit(p.PID) {
		s.logf("stopped the openvpn a previous run left running for connection %s", id)
		return nil
	}
	if err := s.killProcess(p.PID); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("stop the openvpn a previous run started for connection %s: %w", id, err)
	}
	if !s.waitForExit(p.PID) {
		return fmt.Errorf("the openvpn a previous run started for connection %s (process %d) did not stop when killed", id, p.PID)
	}
	s.logf("stopped the openvpn a previous run left running for connection %s", id)
	return nil
}

// waitForExit reports whether the process is gone within the stop grace. There is nothing to
// wait on -- it belongs to a run that has ended, not to this one -- so it is asked about instead.
func (s *rootState) waitForExit(pid int) bool {
	deadline := time.Now().Add(s.stopGrace)
	for {
		if !s.processAlive(pid) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(reclaimPollInterval)
	}
}
