// SPDX-License-Identifier: MIT

//go:build !darwin && !windows

package grants

// Path is where this machine keeps its approvals: the system configuration folder, which only
// root can write.
func Path() (string, error) { return "/etc/app-tail/grants.json", nil }
