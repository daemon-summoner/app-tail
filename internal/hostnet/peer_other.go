// SPDX-License-Identifier: MIT

//go:build !darwin && !linux

package hostnet

import (
	"errors"
	"net"
)

// HelperCallerCheck is how this platform's helper tells app-tail from other programs.
func HelperCallerCheck() CallerCheck { return CallerCheckUnavailable }

// peerRunsThisProgram refuses every connection: there is no way here to tell which program a
// connecting process runs.
func peerRunsThisProgram(*net.UnixConn) error { return errCannotTellPrograms }

// refuseInjectableHelper has nothing to refuse: this helper accepts root alone.
func refuseInjectableHelper() error { return nil }

var errCannotTellPrograms = errors.New("this helper cannot tell which program a connecting process runs on this platform, so it takes commands from root alone")

// RefuseSameUserDebugging has nothing to do on a platform with no helper to protect.
func RefuseSameUserDebugging() error { return nil }
