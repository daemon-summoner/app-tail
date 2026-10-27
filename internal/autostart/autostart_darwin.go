// SPDX-License-Identifier: MIT

package autostart

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Kind names the sort of login item this manager installs, as the label beside Path
// in messages and docs.
func (m *Manager) Kind() string { return "launchd LaunchAgent" }

// Path is where the LaunchAgent plist is written.
func (m *Manager) Path() string {
	return filepath.Join(m.Home, "Library", "LaunchAgents", Label+".plist")
}

// Enabled reports whether the LaunchAgent is installed.
func (m *Manager) Enabled() (bool, error) {
	if err := m.Validate(); err != nil {
		return false, err
	}
	return fileExists(m.Path())
}

// SetEnabled writes or removes the LaunchAgent. launchctl is not invoked: the agent
// loads at the next login, and shelling out would fail confusingly when run outside
// a GUI session.
func (m *Manager) SetEnabled(enabled bool) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if !enabled {
		return removeFile(m.Path())
	}
	return writeFile(m.Path(), m.plist())
}

// NeedsReinstall reports whether the installed LaunchAgent has stopped being able to
// start app-tail at all, or starts it in a class macOS throttles.
//
// The rights form of this question is a Windows one: here the privileged work is a
// separate root helper, so the login item never carries rights. What goes wrong on this
// platform is the path. The plist records where the binary was when the item was
// installed, and moving the app afterwards leaves launchd loading an item whose program
// no longer exists -- it fails with EX_CONFIG and holds the job in a penalty box, while
// every surface that asks only whether the plist exists still reports start-at-login as
// on. The item is installed, checked, and dead.
//
// Only a program that has genuinely vanished counts. A path that merely differs from
// this process's own is somebody running a second copy of app-tail, and rewriting the
// item to name whichever binary started last would be a worse bug than the one this
// fixes: it would move the user's login item without being asked.
//
// An item naming this very binary is also stale when its ProcessType is not the one the
// template writes: items from older builds ask for Background, which leaves every relayed
// packet waiting behind whatever else the machine is doing. Rewriting it changes nothing
// but the class, because the path it records is already this one.
//
// This answers whether the item is broken, not whether rewriting it here would help --
// a caller running from a build directory would write a path that dies at the next
// reboot, and declining to say so would leave the surfaces that only report unable to
// mention a login item that is already dead.
func (m *Manager) NeedsReinstall() (bool, error) {
	cause, err := m.reinstallCause()
	return cause != causeNone, err
}

// ReinstallReason names, for a person, why the login item on this platform needs
// installing again.
func (m *Manager) ReinstallReason() string {
	cause, err := m.reinstallCause()
	if err != nil {
		return fmt.Sprintf("The login item could not be read to say what is wrong with it: %v.", err)
	}
	if cause == causeThrottled {
		return "It does not ask launchd for the " + launchdProcessType + " class, so macOS throttles " +
			"app-tail as a background job: every connection it carries lags whenever the machine is busy."
	}
	return "It names a program that is no longer there, so launchd cannot start it: " +
		"app-tail was moved or reinstalled elsewhere after the login item was created."
}

type reinstallCause int

const (
	causeNone reinstallCause = iota
	causeGone
	causeThrottled
)

// reinstallCause reads the installed item once and says which fault, if any, it has.
func (m *Manager) reinstallCause() (reinstallCause, error) {
	if err := m.Validate(); err != nil {
		return causeNone, err
	}
	installed, err := fileExists(m.Path())
	if err != nil || !installed {
		return causeNone, err
	}
	content, err := os.ReadFile(m.Path())
	if err != nil {
		return causeNone, fmt.Errorf("read %s: %w", m.Path(), err)
	}
	program, err := plistProgram(content)
	if err != nil {
		return causeNone, fmt.Errorf("read the program out of %s: %w", m.Path(), err)
	}
	if program == m.ExecPath {
		processType, err := plistProcessType(content)
		if err != nil {
			return causeNone, fmt.Errorf("read the process type out of %s: %w", m.Path(), err)
		}
		if processType != launchdProcessType {
			return causeThrottled, nil
		}
		return causeNone, nil
	}
	exists, err := fileExists(program)
	if err != nil {
		return causeNone, err
	}
	if !exists {
		return causeGone, nil
	}
	return causeNone, nil
}

// plistProgram returns the first ProgramArguments entry of a LaunchAgent: the binary
// launchd runs. It walks the token stream rather than unmarshalling, because a plist is
// a flat run of alternating key and value elements with no structure tying one to the
// next -- the value belonging to a key is simply whatever element follows it.
//
// A plist that does not carry the key, or carries an empty array, is not this app's:
// reporting it as a program that has vanished would delete somebody else's login item.
func plistProgram(content []byte) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(content))
	// launchd accepts the DTD-declared plist doctype, so the decoder has to as well.
	decoder.Strict = false

	atKey := false
	inArgs := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		// The array has to be closed as well as opened. Left set, the flag makes the next
		// scalar anywhere in the file read as the program -- an empty ProgramArguments
		// followed by the Label returns the label, which then fails to stat and takes the
		// login item to be dead.
		if end, ok := token.(xml.EndElement); ok && end.Name.Local == "array" {
			inArgs = false
			continue
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "key":
			var name string
			if err := decoder.DecodeElement(&name, &start); err != nil {
				return "", err
			}
			atKey = name == "ProgramArguments"
		case "array":
			inArgs = atKey
			atKey = false
		case "string":
			var value string
			if err := decoder.DecodeElement(&value, &start); err != nil {
				return "", err
			}
			if inArgs {
				return value, nil
			}
		}
	}
}

// plistProcessType returns the ProcessType a LaunchAgent declares, or "" when it declares
// none. Only a string that directly follows the key counts: a value nested in an array or
// dict belongs to some other key.
func plistProcessType(content []byte) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(content))
	decoder.Strict = false

	atKey := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "key":
			var name string
			if err := decoder.DecodeElement(&name, &start); err != nil {
				return "", err
			}
			atKey = name == "ProcessType"
		case "string":
			var value string
			if err := decoder.DecodeElement(&value, &start); err != nil {
				return "", err
			}
			if atKey {
				return value, nil
			}
		default:
			atKey = false
		}
	}
}
