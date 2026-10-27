// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/sellitus/app-tail/internal/elevate"
	"github.com/sellitus/app-tail/internal/fileown"
	"github.com/sellitus/app-tail/internal/hostnet"
)

// installDirName is the folder app-tail installs itself into under Program Files.
const installDirName = "app-tail"

// installForAllUsers copies the running app-tail, its twin build, wintun.dll and the
// notices into Program Files\app-tail, narrowed so only administrators and the local system
// account can change them, and checks every copy against what was read.
//
// The install itself has to run from wherever the archive was unpacked, which is usually a
// folder this account can write: that exposure is one prompt the user asked for, rather
// than one at every start. Without the rights it asks for them by starting itself again
// under the elevation prompt.
func installForAllUsers(ctx context.Context, env Env, opts installOptions) error {
	if !hostnet.Privileged() {
		return relaunchInstall(env, opts)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find this program's own path to install it: %w", err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return fmt.Errorf("resolve this program's own path to install it: %w", err)
	}
	source := filepath.Dir(exe)
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT_PATH)
	if err != nil {
		return fmt.Errorf("find this machine's Program Files folder: %w", err)
	}
	dest := filepath.Join(root, installDirName)
	if strings.EqualFold(filepath.Clean(source), filepath.Clean(dest)) {
		return fmt.Errorf("this is already the installed copy in %s; run the install from the folder a newer "+
			"release was unpacked into", dest)
	}

	plan, err := installPlan(filepath.Base(exe), func(name string) (bool, error) {
		_, err := os.Stat(filepath.Join(source, name))
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, os.ErrNotExist):
			return false, nil
		default:
			return false, fmt.Errorf("check for %s beside app-tail: %w", name, err)
		}
	})
	if err != nil {
		return err
	}

	// Narrowed before anything is copied in, so no file is ever there with the access the
	// folder would otherwise have handed down.
	if err := fileown.MakeRestrictedDir(dest, 0o755); err != nil {
		return err
	}
	sums := make([]string, 0, len(plan))
	for _, file := range plan {
		if err := ctx.Err(); err != nil {
			return err
		}
		sum, err := installOne(filepath.Join(source, file.source), filepath.Join(dest, file.target), file.target)
		if err != nil {
			return err
		}
		sums = append(sums, sum)
	}
	// A file this install does not write, left by an earlier one, would be a binary from a
	// different build beside this one -- a GUI agent that no longer matches the CLI.
	for _, name := range skippedTargets(plan) {
		stale := filepath.Join(dest, name)
		if err := os.Remove(stale); err == nil {
			fmt.Fprintf(env.Stdout, "Removed %s, left by an earlier install and not part of this one.\n", stale)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s, left by an earlier install: %w", stale, err)
		}
	}

	// The same question every elevation asks, answered for the installed copy: an install
	// that left it replaceable has not done what it is for.
	installed := filepath.Join(dest, installedConsoleExe)
	if !planWrites(plan, installedConsoleExe) {
		installed = filepath.Join(dest, installedGUIExe)
	}
	if replaceable, reason, err := fileown.ReplaceableByOtherAccounts(installed); err != nil {
		return fmt.Errorf("check the installed copy: %w", err)
	} else if replaceable {
		return fmt.Errorf("the files were copied, but %s, so it is not safe to start with administrator rights", reason)
	}

	reportInstall(env, source, dest, plan, sums)
	return nil
}

// relaunchInstall asks for the rights by starting the same install again under the
// elevation prompt. The new copy opens its own console window, so it is told to keep that
// window open until its result has been read.
func relaunchInstall(env Env, opts installOptions) error {
	if opts.noElevate {
		return errors.New("app-tail install needs administrator rights, and this copy was started without them " +
			"after being asked not to request them again. Run it from a terminal opened with \"Run as administrator\"")
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find this program's own path to restart it with administrator rights: %w", err)
	}
	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("read the current directory to restart app-tail in it: %w", err)
	}
	args := append([]string{"install", "--" + pauseWhenDoneFlag}, opts.args...)
	switch err := elevate.Relaunch(elevate.Request{Exe: exe, Args: args, Dir: dir}); {
	case err == nil:
		fmt.Fprintln(env.Stdout, "Installing app-tail in a new window with administrator rights; that window says what it did.")
		return nil
	case errors.Is(err, elevate.ErrDeclined):
		return fmt.Errorf("app-tail was not installed: %w", err)
	default:
		return fmt.Errorf("ask for administrator rights to install app-tail: %w", err)
	}
}

// installOne copies one file into the install folder and returns its SHA-256.
//
// The source is held open with read sharing only while it is read, so nothing can change it
// mid-copy, and wintun.dll is checked against the pinned release before anything is
// written: the interface mode refuses any other copy, and an install that put one where
// only administrators can replace it would leave a broken mode nobody without the rights
// can repair. The installed file is then read back and compared with what was read.
func installOne(source, target, name string) (string, error) {
	data, err := readLocked(source)
	if err != nil {
		return "", err
	}
	sum := sha256Hex(data)
	if name == installedWintun {
		if err := hostnet.CheckWintunPin(runtime.GOARCH, sum); err != nil {
			return "", fmt.Errorf("%s: %w", source, err)
		}
	}
	if err := fileown.WriteRestricted(target, data, 0o755); err != nil {
		return "", fmt.Errorf("%w. If app-tail is running from %s, quit it from the notification area and run the "+
			"install again", err, filepath.Dir(target))
	}
	written, err := os.ReadFile(target)
	if err != nil {
		return "", fmt.Errorf("read back the installed %s: %w", target, err)
	}
	if err := verifyCopied(target, sum, sha256Hex(written)); err != nil {
		return "", err
	}
	return sum, nil
}

// readLocked reads a whole file through a handle that denies other handles the right to
// write, delete or rename it until the read is done.
func readLocked(path string) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encode %q: %w", path, err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s to install it: %w", path, err)
	}
	file := os.NewFile(uintptr(handle), path)
	data, readErr := io.ReadAll(file)
	if err := errors.Join(readErr, file.Close()); err != nil {
		return nil, fmt.Errorf("read %s to install it: %w", path, err)
	}
	return data, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// reportInstall says where app-tail now is, what was put there, and how to start it.
func reportInstall(env Env, source, dest string, plan []installFile, sums []string) {
	fmt.Fprintf(env.Stdout, "Installed app-tail for all users in %s:\n", dest)
	for i, file := range plan {
		fmt.Fprintf(env.Stdout, "  %-26s sha256 %s\n", file.target, sums[i])
	}
	fmt.Fprintln(env.Stdout, "\nOnly administrators can change these files, so app-tail may be started with "+
		"administrator rights from here.")
	console := filepath.Join(dest, installedConsoleExe)
	if planWrites(plan, installedGUIExe) {
		fmt.Fprintf(env.Stdout, "\nStart it:           \"%s\"\n", filepath.Join(dest, installedGUIExe))
	} else {
		fmt.Fprintf(env.Stdout, "\nStart it:           \"%s\" run\n", console)
	}
	if planWrites(plan, installedConsoleExe) {
		fmt.Fprintf(env.Stdout, "Start it at login:  \"%s\" install-autostart\n", console)
	} else {
		fmt.Fprintln(env.Stdout, "Start it at login:  turn it on from the dashboard of the installed copy")
	}
	fmt.Fprintf(env.Stdout, "\nIf start at login was turned on from another folder, turn it on again from the installed "+
		"copy so it starts this one. The copy in %s is no longer needed.\n", source)
}
