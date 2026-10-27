// SPDX-License-Identifier: MIT

package hostnet

import "sync/atomic"

// held is the name of the interface this process opened, empty when it holds none.
//
// It is package state because of who asks. "Is that adapter something a previous run left
// behind" is asked by the doctor command and by the report the dashboard reads, through
// package functions, by callers holding no reference to the side that opened it. On a
// platform whose adapter outlives the process that made it, the question cannot be answered
// without this: app-tail's own live adapter and one a killed run left behind carry the same
// name, and calling the live one a leftover hands the user a command that takes their own
// tunnel down.
var held atomic.Pointer[string]

// setHeldInterface records the interface this process opened, or clears it with an empty name.
func setHeldInterface(name string) { held.Store(&name) }

// HeldInterface is the interface this process opened, empty when it holds none.
func HeldInterface() string {
	name := held.Load()
	if name == nil {
		return ""
	}
	return *name
}
