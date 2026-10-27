// SPDX-License-Identifier: MIT

//go:build !windows

package sessionend

// watch does nothing here, and the run is no worse for it: these platforms put the machine
// back from the privileged helper, whose teardown is driven by the agent's connection closing
// -- which the kernel reports the same way for a clean exit, a kill and a power cut. There is
// nothing for a dying process to have remembered to do.
func watch(*Watch) platform { return nil }
