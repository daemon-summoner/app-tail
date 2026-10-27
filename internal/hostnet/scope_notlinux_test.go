// SPDX-License-Identifier: MIT

//go:build !linux

package hostnet

import "testing"

// goneInterfaceRouting has nothing to stand in for here: an interface that is gone took its
// routes with it, and the removals read which interfaces exist before touching anything.
func goneInterfaceRouting(*testing.T, string) {}
