// SPDX-License-Identifier: MIT

//go:build !darwin && !linux

package hostnet

import "context"

// OpenVPNSupported reports whether this platform runs OpenVPN connections.
//
// It does not. Driving openvpn means starting a program that holds administrator rights and
// then proving it cannot be replaced by something else, and that proof is written per
// platform: the two the app ships this for have their own files. Windows in particular would
// need the whole ownership check rewritten against its own access model, plus a named pipe in
// place of the management socket, and none of that has been written or tested.
//
// Reporting false is what refuses the kind at the point somebody adds one, rather than
// accepting the connection and failing every time it is asked to come up.
func OpenVPNSupported() bool { return false }

// openvpnDevice is the interface openvpn would open. No connection is ever started here.
func openvpnDevice() string { return "" }

// openvpnCandidates is where a root-owned openvpn would be looked for. An empty list is what
// makes looking for one report that this platform has no OpenVPN connections, rather than
// that none is installed.
func openvpnCandidates() []string { return nil }

// processArgs reads what a process was started with, which is asked only to tell a recorded
// openvpn from whatever holds its number now. Nothing here ever starts one, so the refusal is
// the honest answer rather than a reader that would never be right.
func processArgs(context.Context, int) (string, error) { return "", ErrOpenVPNUnsupported }

// openvpnInstallAdvice would be how to install an openvpn this side runs. Nothing is ever
// looked for here, so there is nothing to advise.
func openvpnInstallAdvice() string { return "" }

// openvpnEnv would be the environment openvpn starts with. Nothing is ever started here.
func openvpnEnv() []string { return []string{} }
