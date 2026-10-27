// SPDX-License-Identifier: MIT

//go:build !windows

package hostnet

// armBootRepair is nil here: on macOS the helper repairs this machine's resolver at boot and
// keeps watching it, and on Linux the helper that changed it is the one that puts it back.
var armBootRepair func() error
