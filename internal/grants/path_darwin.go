// SPDX-License-Identifier: MIT

package grants

// Path is where this machine keeps its approvals: beside the privileged helper's other files,
// in a folder only root can write.
func Path() (string, error) { return "/Library/Application Support/app-tail/grants.json", nil }
