// SPDX-License-Identifier: MIT

//go:build !unix

package hostnet

import "os"

// The checks an openvpn program and its management socket have to pass are unix file
// ownership and unix accounts, and there is no OpenVPN connection on a platform without them.
// They report the same refusal the rest of this file's platform does, so a caller that reached
// here gets the reason rather than a check that quietly passed.

func trustedRootProgram(string) error { return ErrOpenVPNUnsupported }

func openvpnManagementUser() (string, error) { return "", ErrOpenVPNUnsupported }

func prepareManagementSocket(string, string) error { return ErrOpenVPNUnsupported }

// terminate has no ask-to-close signal to send here, so it is the kill. Nothing reaches it:
// no connection is ever started on a platform with no OpenVPN support.
func terminate(p *os.Process) error { return p.Kill() }

// askToClose and killProcess take a process number a previous run recorded. No run on this
// platform ever records one, so they report the same refusal as the rest of the file.
func askToClose(int) error { return ErrOpenVPNUnsupported }

func killProcess(int) error { return ErrOpenVPNUnsupported }

// processAlive reports whether a process with this number exists. Nothing here records one to
// ask about, so the answer no connection was ever started is the only one it can give.
func processAlive(int) bool { return false }
