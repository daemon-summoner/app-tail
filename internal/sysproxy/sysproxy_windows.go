// SPDX-License-Identifier: MIT

package sysproxy

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// internetSettingsKey is where WinINET keeps this user's proxy configuration. It is under
// HKCU, so writing it needs no elevation -- the whole reason this platform gets an
// automatic path and the others do not.
const internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// autoConfigURLValue names the proxy auto-config script WinINET fetches.
const autoConfigURLValue = "AutoConfigURL"

// The options InternetSetOption takes to notice a settings change. Without both, a
// running browser keeps using the previous configuration until it is restarted, which
// reads as the switch having done nothing.
const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

var (
	wininet             = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOpts = wininet.NewProc("InternetSetOptionW")
)

// windowsRegistry reads and writes the auto-config URL under one HKCU key.
//
// The key is a field rather than the constant directly so the round trip can be
// exercised against a scratch key. A test that used the real one would repoint the
// machine's proxy at whatever it wrote, and leave it there if it died half way.
type windowsRegistry struct {
	path string
}

func newMachineProxy() machineProxy { return windowsRegistry{path: internetSettingsKey} }

func (windowsRegistry) supported() (bool, string) { return true, "" }

func (w windowsRegistry) get() (string, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, w.path, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("open HKCU\\%s: %w", w.path, err)
	}
	defer key.Close()

	value, _, err := key.GetStringValue(autoConfigURLValue)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", autoConfigURLValue, err)
	}
	return value, nil
}

func (w windowsRegistry) set(url string) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, w.path, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open HKCU\\%s for writing: %w", w.path, err)
	}
	defer key.Close()

	if url == "" {
		err = key.DeleteValue(autoConfigURLValue)
		if err != nil && !errors.Is(err, registry.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", autoConfigURLValue, err)
		}
	} else if err := key.SetStringValue(autoConfigURLValue, url); err != nil {
		return fmt.Errorf("write %s: %w", autoConfigURLValue, err)
	}

	if err := notifyChanged(); err != nil {
		// The setting itself is written and is what every program started from now on will
		// read. Saying only that something failed would have the caller report a machine it
		// did not change, so the sentence says which half happened.
		return fmt.Errorf("this machine's proxy setting is written, but programs already "+
			"running were not told to re-read it and keep using the previous one until they "+
			"restart: %w", err)
	}
	return nil
}

// notifyChanged tells running WinINET consumers to re-read the settings.
//
// The procedure is looked up rather than called straight: a LazyProc that cannot find its
// library or its entry point panics inside Call, and this runs on the path that answers a
// dashboard switch. A Windows install without wininet.dll is a refusal, not a crash.
func notifyChanged() error {
	if err := procInternetSetOpts.Find(); err != nil {
		return fmt.Errorf("this Windows installation has no %s in %s: %w",
			procInternetSetOpts.Name, wininet.Name, err)
	}
	for _, option := range []uintptr{internetOptionSettingsChanged, internetOptionRefresh} {
		ret, _, err := procInternetSetOpts.Call(0, option, 0, 0)
		if ret == 0 {
			return fmt.Errorf("tell running programs the proxy settings changed: %w", err)
		}
	}
	return nil
}

func platformLimits() []string {
	return []string{
		"Reaches programs that use the Windows proxy setting, including Edge and Chrome. Firefox has its own setting.",
		"Applies to this Windows user only, and not to services running as another account.",
	}
}
