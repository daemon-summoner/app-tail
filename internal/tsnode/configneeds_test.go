// SPDX-License-Identifier: MIT

package tsnode

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/grants"
)

// The install dialog lists what the config asks for, so the list is worked out from the file
// before the dialog, by this process. A config that moves the default route lists the full
// tunnel; no config lists nothing and never asks the machine for its networks.
func TestTheInstallListsWhatTheConfigAsksForBeforeAnyPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := config.Config{Settings: config.Settings{ExitNodeEnabled: true}}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	noNets := func() ([]netip.Prefix, error) { return nil, nil }

	needs, err := installNeeds(path, noNets)
	if err != nil {
		t.Fatalf("installNeeds = %v", err)
	}
	if len(needs) != 1 || needs[0].Kind != grants.KindFullTunnel {
		t.Errorf("an exit node in the config listed %+v, want the full tunnel alone", needs)
	}

	needs, err = installNeeds("", func() ([]netip.Prefix, error) {
		t.Error("the machine's networks were read for an install that approves nothing")
		return nil, nil
	})
	if err != nil || needs != nil {
		t.Errorf("no config listed %+v, %v; want nothing", needs, err)
	}

	if _, err := installNeeds(filepath.Join(t.TempDir(), "missing.json"), noNets); err == nil {
		t.Error("a config that is not there was taken as asking for nothing")
	}
}
