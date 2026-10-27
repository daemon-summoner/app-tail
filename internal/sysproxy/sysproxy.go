// SPDX-License-Identifier: MIT

// Package sysproxy points this machine's own proxy configuration at the app's
// auto-config script, where the platform allows that without privilege.
//
// It is deliberately asymmetric, because the platforms are. On Windows the setting is
// per-user and writable with no elevation. On macOS the equivalent needs an
// administrator, applies per network service and does not survive switching between
// them, so this package will not pretend: it reports the command to run and leads with
// the paths that need no privilege at all. Linux has no single setting to write.
//
// Every value replaced is written down before it is replaced, and put back when the
// module is switched off or on the next start after it was. That is a best effort by
// construction: a process that is killed cannot restore anything, which is why the
// restoring happens at start rather than only at exit.
package sysproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// RestoreFileName sits beside config.json and remembers what was replaced.
const RestoreFileName = "sysproxy-restore.json"

// fileMode keeps the record readable only by its owner, matching the config file it
// sits beside.
const fileMode = 0o600

// Command is something a user runs themselves on a platform this package will not
// change automatically.
type Command struct {
	Label   string `json:"label"`
	Command string `json:"command"`
}

// State is what this machine's proxy configuration says right now.
type State struct {
	// Supported reports that Apply and Clear do anything here. Everything else in this
	// struct is still filled when it is false: that is the case where a user needs the
	// manual commands most.
	Supported bool `json:"supported"`
	// AutoConfigURL is what the machine currently points at, empty when nothing does.
	AutoConfigURL string `json:"autoConfigUrl,omitempty"`
	// Managed reports that the current value is the one this app wrote, which is what
	// separates "we did this" from "something else did, do not touch it".
	Managed bool `json:"managed"`
	// Reason explains an unsupported platform, or a read that failed.
	Reason string `json:"reason,omitempty"`
	// Limits are what this does not reach even where it works. They are properties of
	// the platform, not bugs, so they are stated wherever the switch is offered.
	Limits []string `json:"limits,omitempty"`
	// Manual is what to run by hand to get the same effect where the app will not.
	Manual []Command `json:"manual,omitempty"`
}

// machineProxy is this machine's own proxy configuration. It is an interface so the
// bookkeeping below -- which is where the mistakes that lose someone's original
// settings live -- is exercised on every platform rather than only the one that has an
// implementation.
type machineProxy interface {
	// supported reports that this platform can be changed, and why not when it cannot.
	supported() (bool, string)
	// get reads the current auto-config URL, empty when none is set.
	get() (string, error)
	// set writes the auto-config URL, or removes it when the URL is empty.
	set(url string) error
}

// Manager applies and restores this machine's proxy configuration.
type Manager struct {
	// mu serialises the read-decide-write sequences below. Each of them reads the machine
	// and the record and then writes both, and two running at once -- a reconcile pass and
	// a switch flipped on the dashboard -- can interleave into a record naming app-tail's
	// own URL as the prior value, which restores to nothing forever.
	mu          sync.Mutex
	machine     machineProxy
	restorePath string
	logger      *slog.Logger
}

// New builds a manager writing its restore record beside the config file.
func New(stateDir string, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		machine:     newMachineProxy(),
		restorePath: filepath.Join(stateDir, RestoreFileName),
		logger:      logger,
	}
}

// restoreRecord is what was replaced and what replaced it.
//
// Wrote is kept alongside Prior so restoring can tell "the value we set is still there"
// from "someone changed it since". Putting the old value back over a third party's
// newer one would be the same mistake in the other direction.
type restoreRecord struct {
	Prior string `json:"priorAutoConfigUrl"`
	Wrote string `json:"wroteAutoConfigUrl"`
}

// State reports what this machine's proxy configuration says, and what this package can
// do about it here.
//
// pacURL is the auto-config script's own address, and is what the manual commands are
// built from; an empty one means the proxy is not listening, so there is nothing to point
// anything at yet.
func (m *Manager) State(pacURL string) State {
	m.mu.Lock()
	defer m.mu.Unlock()

	supported, reason := m.machine.supported()
	state := State{
		Supported: supported,
		Reason:    reason,
		Limits:    platformLimits(),
		Manual:    ManualCommands(pacURL),
	}
	if !supported {
		return state
	}

	current, err := m.machine.get()
	if err != nil {
		state.Reason = fmt.Sprintf("this machine's proxy configuration could not be read: %v", err)
		return state
	}
	state.AutoConfigURL = current

	record, err := m.readRecord()
	if err != nil {
		state.Reason = fmt.Sprintf("the record of what was replaced could not be read: %v", err)
		return state
	}
	state.Managed = record != nil && current != "" && record.Wrote == current
	return state
}

// Apply points this machine at pacURL, remembering whatever it pointed at before.
//
// Applying twice is not an error and does not overwrite the remembered value: the first
// application is the one that saw the user's own setting, and a second that recorded
// our own URL as "prior" would make restoring a no-op forever.
func (m *Manager) Apply(pacURL string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if pacURL == "" {
		return errors.New("apply a system proxy: no auto-config URL to point at")
	}
	if supported, reason := m.machine.supported(); !supported {
		return fmt.Errorf("apply a system proxy: %s", reason)
	}

	current, err := m.machine.get()
	if err != nil {
		return fmt.Errorf("read this machine's proxy configuration: %w", err)
	}
	if current == pacURL {
		// Already pointing here. The record still has to exist, or switching the
		// module off would leave the URL behind with nothing to say it was ours.
		return m.ensureRecord(current, pacURL)
	}

	record, err := m.readRecord()
	if err != nil {
		return err
	}
	prior := current
	if record != nil {
		prior = record.Prior
	}

	// Recorded before the change, not after: a crash between the two would otherwise
	// leave the machine pointing at a proxy with nothing remembering what it replaced.
	if err := m.writeRecord(restoreRecord{Prior: prior, Wrote: pacURL}); err != nil {
		return err
	}
	if err := m.machine.set(pacURL); err != nil {
		return fmt.Errorf("point this machine's proxy configuration at %s: %w", pacURL, err)
	}
	m.logger.Info("pointed this machine's proxy configuration at the app", "url", pacURL, "replaced", prior)
	return nil
}

// Clear puts back whatever was there before, and is safe to call when nothing was ever
// applied.
//
// A value that is no longer the one this app wrote is left alone: something else set it
// since, and putting the older value back over it would be this package causing the
// very problem it exists to avoid.
func (m *Manager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	record, err := m.readRecord()
	if err != nil {
		return err
	}
	if record == nil {
		return nil
	}
	if supported, reason := m.machine.supported(); !supported {
		// Nothing here could have applied it, so nothing here should restore it. The
		// record is dropped so this does not repeat on every start.
		m.logger.Debug("dropping a system proxy record this platform cannot act on", "reason", reason)
		return m.removeRecord()
	}

	current, err := m.machine.get()
	if err != nil {
		return fmt.Errorf("read this machine's proxy configuration: %w", err)
	}
	if current != record.Wrote {
		m.logger.Warn("leaving this machine's proxy configuration alone: it was changed since app-tail set it",
			"current", current, "expected", record.Wrote)
		return m.removeRecord()
	}

	if err := m.machine.set(record.Prior); err != nil {
		return fmt.Errorf("restore this machine's proxy configuration to %q: %w", record.Prior, err)
	}
	m.logger.Info("restored this machine's proxy configuration", "restored", record.Prior)
	return m.removeRecord()
}

// ensureRecord writes a record for a value that is already in place.
func (m *Manager) ensureRecord(prior, wrote string) error {
	record, err := m.readRecord()
	if err != nil {
		return err
	}
	if record != nil && record.Wrote == wrote {
		return nil
	}
	if record != nil {
		prior = record.Prior
	}
	return m.writeRecord(restoreRecord{Prior: prior, Wrote: wrote})
}

// readRecord returns the stored record, or nil when there is none.
func (m *Manager) readRecord() (*restoreRecord, error) {
	data, err := os.ReadFile(m.restorePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", m.restorePath, err)
	}
	var record restoreRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("parse %s: %w", m.restorePath, err)
	}
	return &record, nil
}

// writeRecord replaces the record in one step.
//
// Through a temporary file and a rename, because this file is the only thing that remembers
// what this machine's proxy pointed at before app-tail touched it. A record half written by a
// process that died parses as nothing, and a record that parses as nothing leaves the machine
// pointed at app-tail's script with no way back to what the user had.
func (m *Manager) writeRecord(record restoreRecord) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode the system proxy record: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(m.restorePath), ".sysproxy-restore-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", m.restorePath, err)
	}
	name := tmp.Name()
	discard := func(cause error) error {
		return errors.Join(cause, tmp.Close(), os.Remove(name))
	}
	if err := tmp.Chmod(fileMode); err != nil {
		return discard(fmt.Errorf("write %s: %w", m.restorePath, err))
	}
	if _, err := tmp.Write(data); err != nil {
		return discard(fmt.Errorf("write %s: %w", m.restorePath, err))
	}
	if err := tmp.Sync(); err != nil {
		return discard(fmt.Errorf("write %s: %w", m.restorePath, err))
	}
	if err := tmp.Close(); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", m.restorePath, err), os.Remove(name))
	}
	if err := os.Rename(name, m.restorePath); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", m.restorePath, err), os.Remove(name))
	}
	return nil
}

func (m *Manager) removeRecord() error {
	if err := os.Remove(m.restorePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", m.restorePath, err)
	}
	return nil
}

// ManualCommands is how to point this whole machine at pacURL where this package will
// not do it itself, which today means macOS alone.
//
// It is deliberately not a list of ways to point individual programs at the proxy. Those
// need no privilege, they are the proxy's own snippets, and they are already on the same
// card -- offering them twice in one panel is how a reader stops trusting either copy.
// What belongs here is the machine-wide setting: the thing this module exists to do, on
// the platform where it cannot.
func ManualCommands(pacURL string) []Command { return manualCommandsFor(runtime.GOOS, pacURL) }

// manualCommandsFor is ManualCommands with the platform passed in rather than read, so
// what every platform offers is reachable from a test running on any one of them.
func manualCommandsFor(goos, pacURL string) []Command {
	if pacURL == "" {
		// Nothing is listening, so every command here would name an address that answers
		// nothing. An empty list is what tells the caller to say "start the proxy first".
		return nil
	}
	if goos != "darwin" {
		// Windows is written directly, and no other system has one setting to write.
		return nil
	}
	return []Command{{
		Label: "Point this Mac at it (needs an administrator, and covers one network service)",
		// The service is listed rather than assumed: "Wi-Fi" is the common case and the
		// wrong one on any machine using Ethernet, a hotspot or a VPN service.
		Command: "networksetup -listallnetworkservices\n" +
			`sudo networksetup -setautoproxyurl "Wi-Fi" ` + pacURL,
	}, {
		Label:   "Undo it",
		Command: `sudo networksetup -setautoproxystate "Wi-Fi" off`,
	}}
}
