// SPDX-License-Identifier: MIT

package hostnet

import (
	"fmt"
	"os"
	"sync"

	"github.com/sellitus/app-tail/internal/autostart"
)

// armBootRepair registers the scheduled task that puts this machine's resolver back at boot.
// Windows has no helper starting with the machine, so this task is what stands between a
// crash with System DNS on and a machine that resolves nothing until app-tail is opened.
var armBootRepair = ensureBootRepairTask

var bootRepairArmed struct {
	sync.Mutex
	done bool
}

// ensureBootRepairTask registers the task once per process. A failure is not remembered, so
// the next time System DNS is applied tries again.
func ensureBootRepairTask() error {
	bootRepairArmed.Lock()
	defer bootRepairArmed.Unlock()
	if bootRepairArmed.done {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find this program's path for the boot-time task: %w", err)
	}
	if err := autostart.InstallBootRepair(exe); err != nil {
		return err
	}
	bootRepairArmed.done = true
	return nil
}
