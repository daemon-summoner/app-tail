// SPDX-License-Identifier: MIT

package relaunch

import (
	"fmt"
	"os"
)

// exec starts a detached copy and returns, because Windows has no way to replace a
// running image. The caller exits immediately afterwards, so there are briefly two
// app-tail processes -- but only the new one ever binds the dashboard port, since the
// old one released it before this was called.
//
// Nothing is waited on: the replacement outlives this process by design, and holding a
// handle to it would keep this one alive to no purpose.
func exec(path string, args []string) error {
	proc, err := os.StartProcess(path, append([]string{path}, args...), &os.ProcAttr{
		Dir:   workingDir(),
		Env:   os.Environ(),
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		return fmt.Errorf("relaunch: start %s again: %w", path, err)
	}
	// Released rather than waited on: this process is about to exit, and a child held
	// by a parent that never reaps it is a handle leak for as long as both live.
	return proc.Release()
}

// workingDir is where the replacement starts: this process's own directory, so a relative
// --state-dir on the command line resolves to what it resolved to before the restart. An
// unreadable one is not worth failing the restart over -- the process default is a working
// answer.
func workingDir() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return wd
}
