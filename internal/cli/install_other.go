// SPDX-License-Identifier: MIT

//go:build !windows

package cli

import (
	"context"
	"fmt"
	"runtime"
)

// installForAllUsers refuses: only Windows starts app-tail itself with administrator rights,
// which is what the install exists to make safe. Everywhere else the privileged work is a
// separate root helper, and installing is the platform's own step.
func installForAllUsers(context.Context, Env, installOptions) error {
	return fmt.Errorf("app-tail install is for Windows only. On %s, follow docs/install.md in the app-tail "+
		"repository, which covers installing a release and building from source", runtime.GOOS)
}
