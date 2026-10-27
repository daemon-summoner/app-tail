// SPDX-License-Identifier: MIT

package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// pauseWhenDoneFlag keeps a window opened only for the install on screen until Enter is
// pressed. The elevated copy runs in a console window of its own that would otherwise close
// the moment it finished, taking the installed path and any refusal with it.
const pauseWhenDoneFlag = "pause-when-done"

// installOptions are the parsed flags of one install.
type installOptions struct {
	// noElevate is set on the copy the elevation prompt started, and stops it asking again.
	noElevate bool
	// args are the arguments the command was given, carried into the elevated copy.
	args []string
}

// runInstall copies app-tail into Program Files, where only administrators can change it,
// so that it may be started with administrator rights from there. Windows only: everywhere
// else the privileged work is a separate helper and app-tail itself never runs elevated.
func runInstall(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("install", env)
	noElevate := fs.Bool("no-elevate", false, "never ask for administrator rights; fail instead when this process does not have them")
	pause := fs.Bool(pauseWhenDoneFlag, false, "wait for Enter before exiting, so a window opened just for the install keeps its output on screen")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "install"); err != nil {
		return err
	}
	err := installForAllUsers(ctx, env, installOptions{noElevate: *noElevate, args: args})
	if *pause {
		if err != nil {
			fmt.Fprintf(env.Stderr, "app-tail was not installed: %v\n", err)
		}
		return errors.Join(err, waitForEnter(env))
	}
	return err
}

// waitForEnter holds the window open until Enter is pressed. A stdin that is already closed
// is a window nobody is looking at, so it returns at once.
func waitForEnter(env Env) error {
	if env.Stdin == nil {
		return nil
	}
	fmt.Fprint(env.Stdout, "\nPress Enter to close this window.")
	if _, err := bufio.NewReader(env.Stdin).ReadString('\n'); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("wait for Enter: %w", err)
	}
	return nil
}

// installFile is one file the install copies: its name beside the running binary, its name
// in the install folder, and whether the install refuses to go ahead without it.
type installFile struct {
	source   string
	target   string
	required bool
}

// The names files get in the install folder. They are fixed rather than carried over from
// the release archive, whose names carry the version: scripts/windows.sh stops a running
// app-tail by these image names, and a login item pointed at the folder keeps working
// across upgrades.
const (
	installedConsoleExe = "app-tail.exe"
	installedGUIExe     = "app-tail-gui.exe"
	installedWintun     = "wintun.dll"
)

// installPlan lists what to copy, given the running binary's file name and a way to ask
// whether a file is in the folder beside it.
//
// The release ships the agent twice, a console build and one linked -H=windowsgui whose
// name adds "-gui", so whichever of the two is running, the other is looked for beside it.
// The running one is required, being the program doing the install; its twin is copied
// when the build has one. wintun.dll is required: elevating is for the features that need
// it, and an install that left it out could not start them. The notices are copied when
// present, so the installed folder carries the same terms the archive did.
func installPlan(running string, present func(name string) (bool, error)) ([]installFile, error) {
	ext := filepath.Ext(running)
	stem := strings.TrimSuffix(running, ext)
	console, gui := running, stem+"-gui"+ext
	runningIsGUI := strings.HasSuffix(strings.ToLower(stem), "-gui")
	if runningIsGUI {
		console, gui = stem[:len(stem)-len("-gui")]+ext, running
	}

	candidates := []installFile{
		{source: console, target: installedConsoleExe, required: !runningIsGUI},
		{source: gui, target: installedGUIExe, required: runningIsGUI},
		{source: installedWintun, target: installedWintun, required: true},
		{source: "WINTUN-LICENSE.txt", target: "WINTUN-LICENSE.txt"},
		{source: "THIRD_PARTY_LICENSES.txt", target: "THIRD_PARTY_LICENSES.txt"},
	}
	var plan []installFile
	for _, file := range candidates {
		there, err := present(file.source)
		if err != nil {
			return nil, err
		}
		switch {
		case there:
			plan = append(plan, file)
		case file.required:
			return nil, fmt.Errorf("%s is not beside %s, and app-tail cannot be installed without it. Unpack the "+
				"whole release archive into one folder and run the install from there", file.source, running)
		}
	}
	return plan, nil
}

// skippedTargets are the install-folder names this plan does not write, which a previous
// install may have left there.
func skippedTargets(plan []installFile) []string {
	var skipped []string
	for _, name := range []string{installedConsoleExe, installedGUIExe, "WINTUN-LICENSE.txt", "THIRD_PARTY_LICENSES.txt"} {
		if !planWrites(plan, name) {
			skipped = append(skipped, name)
		}
	}
	return skipped
}

// planWrites reports whether the plan writes the install-folder name given.
func planWrites(plan []installFile, target string) bool {
	for _, file := range plan {
		if file.target == target {
			return true
		}
	}
	return false
}

// verifyCopied compares what was read from the source with what is now in the install
// folder, and refuses the install when they differ.
func verifyCopied(target, sourceSum, installedSum string) error {
	if !strings.EqualFold(sourceSum, installedSum) {
		return fmt.Errorf("the installed %s does not match the file it was copied from: SHA-256 %s, expected %s",
			target, installedSum, sourceSum)
	}
	return nil
}
