// SPDX-License-Identifier: MIT

//go:build unix

package grants

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// maxLinkHops bounds how many symbolic links the path to the file may lead through, so a loop
// of links is a refusal rather than a walk that never ends.
const maxLinkHops = 40

// trust is who may decide what the approvals file says.
//
// In production that is root alone, and every path component is read from the real file
// system. Both are fields so a suite running unprivileged can treat its own account as the
// trusted one, and describe a file as belonging to somebody else, which is the only way to
// reach the refusals without a second account on the machine.
type trust struct {
	trusted  func(uid uint32) bool
	lstat    func(name string) (fs.FileInfo, error)
	readlink func(name string) (string, error)
	// fstat reads the file that was opened, whatever its name now leads to.
	fstat func(f *os.File) (fs.FileInfo, error)
}

var rootOnly = trust{
	trusted:  func(uid uint32) bool { return uid == 0 },
	lstat:    os.Lstat,
	readlink: os.Readlink,
	fstat:    (*os.File).Stat,
}

// Load reads the approvals at path. No file there is a machine with no approvals. A file that
// is there and cannot be relied on is an error: one another account can write, one reached
// through a directory another account can write, or one that does not parse. The caller
// refuses whatever needed an approval in that case, which is what an unreadable approval
// should mean.
func Load(path string) (Document, error) { return rootOnly.load(path) }

func (t trust) load(path string) (Document, error) {
	if !filepath.IsAbs(path) {
		return Document{}, fmt.Errorf("%s is not an absolute path", path)
	}
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return None(), nil
	}
	if err := t.walk(path, 0); err != nil {
		return Document{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return Document{}, fmt.Errorf("read the approvals file: %w", err)
	}
	defer f.Close()
	// The walk read each component by name. Checking what was actually opened closes the gap
	// between the two for the file itself; the directories above it were already shown to be
	// root's alone, so nobody else could have moved anything there in between.
	info, err := t.fstat(f)
	if err != nil {
		return Document{}, fmt.Errorf("read the approvals file: %w", err)
	}
	if err := t.file(path, info); err != nil {
		return Document{}, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return Document{}, fmt.Errorf("read the approvals file: %w", err)
	}
	return Parse(data)
}

// walk checks every directory on the way to path, following symbolic links the way the kernel
// does. Each directory has to belong to a trusted account and be writable by no other, because
// an account that can write a directory can replace anything inside it. A sticky directory is
// the exception: there an account may only rename or remove its own entries, so an entry a
// trusted account owns is safe in it.
func (t trust) walk(path string, hops int) error {
	dir := "/"
	dirInfo, err := t.lstat(dir)
	if err != nil {
		return err
	}
	parts := strings.Split(path, "/")
	for i, name := range parts {
		switch name {
		case "", ".":
			continue
		case "..":
			dir = filepath.Dir(dir)
			if dirInfo, err = t.lstat(dir); err != nil {
				return err
			}
			continue
		}
		child := filepath.Join(dir, name)
		childInfo, err := t.lstat(child)
		if err != nil {
			return err
		}
		if err := t.guards(dir, dirInfo, child, childInfo); err != nil {
			return err
		}
		if childInfo.Mode()&fs.ModeSymlink != 0 {
			if hops >= maxLinkHops {
				return fmt.Errorf("%s leads through more than %d symbolic links", path, maxLinkHops)
			}
			target, err := t.readlink(child)
			if err != nil {
				return err
			}
			if !filepath.IsAbs(target) {
				target = dir + "/" + target
			}
			return t.walk(strings.Join(append([]string{target}, parts[i+1:]...), "/"), hops+1)
		}
		dir, dirInfo = child, childInfo
	}
	return nil
}

// guards decides whether dir keeps the entry child as its owner left it.
func (t trust) guards(dir string, dirInfo fs.FileInfo, child string, childInfo fs.FileInfo) error {
	owner, err := ownerOf(dirInfo, dir)
	if err != nil {
		return err
	}
	if !t.trusted(owner) {
		return fmt.Errorf("the approvals file %s is reached through %s, which belongs to %s rather than to root, so that account could write its own approvals",
			child, dir, describeUser(owner))
	}
	perm := dirInfo.Mode().Perm()
	if perm&0o022 == 0 {
		return nil
	}
	if dirInfo.Mode()&fs.ModeSticky != 0 {
		childOwner, err := ownerOf(childInfo, child)
		if err != nil {
			return err
		}
		if t.trusted(childOwner) {
			return nil
		}
	}
	return fmt.Errorf("the approvals file %s is reached through %s, which accounts other than root can write to (mode %#o), so any of them could write their own approvals",
		child, dir, perm)
}

// file checks the approvals file itself: a regular file only a trusted account can write.
func (t trust) file(path string, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("the approvals file %s is not a regular file: it is %s", path, info.Mode().Type())
	}
	owner, err := ownerOf(info, path)
	if err != nil {
		return err
	}
	if !t.trusted(owner) {
		return fmt.Errorf("the approvals file %s belongs to %s rather than to root, so that account could write its own approvals",
			path, describeUser(owner))
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("the approvals file %s can be written by accounts other than root (mode %#o), so any of them could write their own approvals",
			path, perm)
	}
	return nil
}

func ownerOf(info fs.FileInfo, path string) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("could not read who owns %s", path)
	}
	return stat.Uid, nil
}

// describeUser names an account for a person: its name when it has one, and always its number.
func describeUser(uid uint32) string {
	id := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(id); err == nil && u.Username != "" {
		return "the account " + u.Username + " (" + id + ")"
	}
	return "the account with id " + id
}
