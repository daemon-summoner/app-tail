// SPDX-License-Identifier: MIT

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// DashboardAddrFileName holds the address a running agent is actually listening on, and
// lives beside the config document rather than in the state directory: the CLI finds an
// agent from the config path it was pointed at, and the two are not always the same place.
//
// It is deliberately not the uiListenAddr setting: that setting is what the user asked for,
// and a port already taken by something else must not be able to rewrite it. The two agree
// on every ordinary run, and differ exactly while the agent is on a port the system
// assigned because the configured one could not be had.
const DashboardAddrFileName = "dashboard-address"

// WriteDashboardAddr records where the agent bound, so the CLI and the tray can find it
// without guessing a port -- which matters because the default asks for any free one.
func WriteDashboardAddr(configPath, addr string) error {
	if strings.TrimSpace(addr) == "" {
		return errors.New("record the dashboard address: no address was bound")
	}
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return fmt.Errorf("record the dashboard address: create state dir %s: %w", dir, err)
	}
	tmpName, err := writeTempFile(dir, ".dashboard-address-*", []byte(addr+"\n"))
	if err != nil {
		return fmt.Errorf("record the dashboard address: %w", err)
	}
	if err := os.Rename(tmpName, DashboardAddrPath(configPath)); err != nil {
		return errors.Join(fmt.Errorf("record the dashboard address: %w", err), os.Remove(tmpName))
	}
	return nil
}

// ReadDashboardAddr reports the address a running agent recorded, or "" when none did.
// A record that says nothing usable is the same answer as no record at all: whatever
// wrote it is gone, and the caller falls back to the configured address.
func ReadDashboardAddr(configPath string) string {
	data, err := os.ReadFile(DashboardAddrPath(configPath))
	if err != nil {
		return ""
	}
	addr := strings.TrimSpace(string(data))
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return ""
	}
	return addr
}

// RemoveDashboardAddr drops the record when the agent stops listening, so nothing sends a
// request to a port this process no longer holds.
func RemoveDashboardAddr(configPath string) error {
	if err := os.Remove(DashboardAddrPath(configPath)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove the dashboard address record: %w", err)
	}
	return nil
}

// DashboardAddrPath is where the record lives for a given config document.
func DashboardAddrPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), DashboardAddrFileName)
}
