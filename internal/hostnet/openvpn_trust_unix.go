// SPDX-License-Identifier: MIT

//go:build unix

package hostnet

// Deciding whether a program is one this side may run as root.
//
// Looking at the file alone is not enough. A root-owned file in a directory another account
// can write is that account's program in every way that matters: it renames the file away and
// puts its own in its place, or swaps the directory, between the moment this side checks the
// path and the moment it runs it. The same is true one level further out, and of every
// directory a symbolic link on the way leads through, and of every shared library the program
// loads -- a root-owned openvpn that loads its TLS library out of a folder a normal account
// can write runs that account's code with administrator rights.
//
// So the question asked here is whether any account other than root can change what runs, by
// any of those routes. When none can, the gap between checking and running is no longer a
// race anybody can win: nothing an unprivileged account can do moves any part of the answer.

import (
	"debug/elf"
	"debug/macho"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// maxLinkHops bounds how many symbolic links one path may lead through. The kernel refuses a
// path past its own bound with ELOOP; this is the same idea applied before the kernel is asked,
// so a loop of links is a refusal here rather than a walk that never ends.
const maxLinkHops = 40

// programTrust is the policy a program is checked against.
//
// In production exactly one account is trusted -- root -- and every path component is read
// from the real file system. Both are fields so a suite running unprivileged can treat its own
// account as the trusted one and describe a component as belonging to somebody else, which is
// the only way to reach the refusals without a second account on the machine.
type programTrust struct {
	// trusted reports whether an account may own a component of a path a root program is
	// reached through.
	trusted func(uid uint32) bool
	// lstat reads one path component without following it.
	lstat func(name string) (fs.FileInfo, error)
	// dyldFallback is where dyld looks, by file name, for a library that is in none of the
	// places an image names.
	dyldFallback []string
}

// dyldFallbackDirs is dyld's default fallback library path. $HOME/lib, which comes first for
// an ordinary account, is left out: root's home belongs to root.
var dyldFallbackDirs = []string{"/usr/local/lib", "/usr/lib"}

// rootTrust is the policy every program this side runs is checked against.
var rootTrust = programTrust{
	trusted:      func(uid uint32) bool { return uid == 0 },
	lstat:        os.Lstat,
	dyldFallback: dyldFallbackDirs,
}

// trustedRootProgram reports whether the file at path is a program this side will run as root.
//
// It refuses unless no account other than root can change what running that path executes:
// every directory on the way to it (and on the way through any symbolic link), the file
// itself, and every shared library it loads along with every directory the loader searches
// for one. A path with nothing at it reports an error matching os.ErrNotExist, so a caller
// working down a list of candidates can tell "not installed here" from "installed and unsafe".
func trustedRootProgram(path string) error { return rootTrust.program(path) }

// program is trustedRootProgram against this policy.
func (pt programTrust) program(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s is not an absolute path, so which program it names depends on where it is run from", path)
	}
	// Nothing there is "not installed here" whatever the directories on the way are like, and
	// a caller working down a list of candidates needs that answer rather than a refusal of a
	// directory that holds no program at all. Everything after this is checked as if this
	// line had not run.
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := pt.reach(path); err != nil {
		return err
	}
	// The walk above followed every link the way the kernel will. Resolving the path once more
	// and walking the answer again is the same question asked from the far end, which is what
	// the libraries are then read relative to.
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if resolved != path {
		if err := pt.reach(resolved); err != nil {
			return err
		}
	}
	if err := pt.file(resolved, true); err != nil {
		return err
	}
	return pt.libraries(resolved)
}

// reach checks every directory the kernel passes through to get to path.
//
// Each directory has to belong to a trusted account and be writable by no other, because an
// account that can write a directory can replace anything inside it. The one exception is a
// sticky directory such as /tmp: there an account may only rename or remove entries it owns,
// so an entry belonging to a trusted account is safe in it even though everyone can write the
// directory itself.
//
// A symbolic link on the way is allowed when the directory holding it passes -- then only a
// trusted account could have put it there or can change it -- and is then followed, with the
// walk starting again from the top of what it points at.
func (pt programTrust) reach(path string) error {
	return pt.walk(path, 0)
}

func (pt programTrust) walk(path string, hops int) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s is not an absolute path", path)
	}
	dir := "/"
	dirInfo, err := pt.lstat(dir)
	if err != nil {
		return err
	}
	parts := strings.Split(path, "/")
	for i, name := range parts {
		switch name {
		case "", ".":
			continue
		case "..":
			// Every directory above this point was reached without a link -- a link starts
			// the walk again from its target -- so the parent named here is the real one,
			// and it was already checked on the way down.
			dir = filepath.Dir(dir)
			if dirInfo, err = pt.lstat(dir); err != nil {
				return err
			}
			continue
		}
		child := filepath.Join(dir, name)
		childInfo, err := pt.lstat(child)
		if err != nil {
			return err
		}
		if err := pt.guards(dir, dirInfo, child, childInfo); err != nil {
			return err
		}
		if childInfo.Mode()&fs.ModeSymlink != 0 {
			if hops >= maxLinkHops {
				return fmt.Errorf("%s leads through more than %d symbolic links", path, maxLinkHops)
			}
			target, err := os.Readlink(child)
			if err != nil {
				return err
			}
			if !filepath.IsAbs(target) {
				target = dir + "/" + target
			}
			rest := strings.Join(append([]string{target}, parts[i+1:]...), "/")
			return pt.walk(rest, hops+1)
		}
		if i < len(parts)-1 && !childInfo.IsDir() && !onlyEmptyAfter(parts, i) {
			return fmt.Errorf("%s is on the way to %s and is not a directory", child, path)
		}
		dir, dirInfo = child, childInfo
	}
	return nil
}

// onlyEmptyAfter reports whether nothing but empty or "." components follow index i, which is
// what a path with a trailing slash looks like once it is split.
func onlyEmptyAfter(parts []string, i int) bool {
	for _, p := range parts[i+1:] {
		if p != "" && p != "." {
			return false
		}
	}
	return true
}

// guards decides whether dir keeps the entry child as its owner left it.
func (pt programTrust) guards(dir string, dirInfo fs.FileInfo, child string, childInfo fs.FileInfo) error {
	owner, _, err := ownerOf(dirInfo, dir)
	if err != nil {
		return err
	}
	if !pt.trusted(owner) {
		return fmt.Errorf("%s is reached through %s, which belongs to %s rather than to root, so that account can replace anything inside it",
			child, dir, describeUser(owner))
	}
	perm := dirInfo.Mode().Perm()
	if perm&0o022 == 0 {
		return nil
	}
	if dirInfo.Mode()&fs.ModeSticky != 0 {
		childOwner, _, err := ownerOf(childInfo, child)
		if err != nil {
			return err
		}
		if pt.trusted(childOwner) {
			return nil
		}
		return fmt.Errorf("%s sits in %s, which %s can write to, and belongs to %s, so that account can replace it",
			child, dir, writers(dirInfo), describeUser(childOwner))
	}
	return fmt.Errorf("%s is reached through %s, which %s can write to (mode %#o), so any of them can replace what is inside it",
		child, dir, writers(dirInfo), perm)
}

// closedDir checks a directory nothing may be added to: one a loader searches for a library
// by name, where a file another account put there first would be the one loaded.
func (pt programTrust) closedDir(dir string) error {
	if err := pt.reach(dir); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	info, err := pt.lstat(resolved)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is searched for libraries and is not a directory", dir)
	}
	owner, _, err := ownerOf(info, resolved)
	if err != nil {
		return err
	}
	if !pt.trusted(owner) {
		return fmt.Errorf("libraries are looked for in %s, which belongs to %s rather than to root, so that account can put one there",
			dir, describeUser(owner))
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("libraries are looked for in %s, which %s can write to (mode %#o), so any of them can put one there",
			dir, writers(info), perm)
	}
	return nil
}

// file checks the file a resolved path ends at: a regular file, belonging to a trusted
// account, that no other account can write. A program also has to be executable; a library
// does not.
func (pt programTrust) file(path string, program bool) error {
	info, err := pt.lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a program: it is %s", path, info.Mode().Type())
	}
	owner, _, err := ownerOf(info, path)
	if err != nil {
		return err
	}
	if !pt.trusted(owner) {
		return fmt.Errorf("%s belongs to %s rather than to root, so running it would run that account's program with administrator rights",
			path, describeUser(owner))
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s can be written by %s (mode %#o), so what it contains is not decided by root",
			path, writers(info), perm)
	}
	if program && info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", path)
	}
	return nil
}

// libraries checks everything the dynamic loader brings in with the program at path.
func (pt programTrust) libraries(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return fmt.Errorf("read what kind of program %s is: %w", path, err)
	}
	switch {
	case string(magic[:]) == elf.ELFMAG:
		return pt.elfLibraries(path, f)
	case isMachO(magic):
		w := machoWalk{trust: pt, exeDir: filepath.Dir(path), seen: map[string]bool{path: true}}
		return w.image(path, f, nil)
	case magic[0] == '#' && magic[1] == '!':
		return fmt.Errorf("%s is a script, and the interpreter it names is not checked, so it is not run as root", path)
	}
	return fmt.Errorf("%s is not a program this side can read the libraries of, so it is not run as root", path)
}

// isMachO recognises a Mach-O image or a universal file holding several, in either byte order.
func isMachO(magic [4]byte) bool {
	be := uint32(magic[0])<<24 | uint32(magic[1])<<16 | uint32(magic[2])<<8 | uint32(magic[3])
	switch be {
	case macho.Magic32, macho.Magic64, macho.MagicFat, 0xcefaedfe, 0xcffaedfe:
		return true
	}
	return false
}

// Mach-O load commands debug/macho leaves as raw bytes. Each names a library the loader brings
// in, so each is read the same way LC_LOAD_DYLIB is.
const (
	lcReqDyld          = 0x80000000
	lcLoadDylinker     = 0xe
	lcLoadWeakDylib    = 0x18 | lcReqDyld
	lcReexportDylib    = 0x1f | lcReqDyld
	lcLazyLoadDylib    = 0x20
	lcLoadUpwardDylib  = 0x23 | lcReqDyld
	lcDyldEnvironment  = 0x27
	machoSystemLibs    = "/usr/lib/"
	machoSystemLibrary = "/System/"

	machoWritableVolumes = "/System/Volumes/"
)

// machoWalk follows a program's libraries the way dyld does, checking each one it finds.
type machoWalk struct {
	trust  programTrust
	exeDir string
	seen   map[string]bool
}

// machoDep is one library an image asks for.
type machoDep struct {
	name string
	weak bool
}

// image checks one Mach-O file -- the program, or a library it loads -- and recurses into
// every library it brings in that is not part of the operating system. inherited is the run
// path list of the images that loaded this one, which dyld searches after the image's own.
func (w machoWalk) image(path string, r io.ReaderAt, inherited []string) error {
	files, closeAll, err := machoImages(r)
	if err != nil {
		return fmt.Errorf("read the libraries %s loads: %w", path, err)
	}
	defer closeAll()
	loaderDir := filepath.Dir(path)
	for _, f := range files {
		deps, rpaths, env, err := machoLoads(f)
		if err != nil {
			return fmt.Errorf("read the libraries %s loads: %w", path, err)
		}
		if len(env) > 0 {
			return fmt.Errorf("%s sets %q for dyld itself, which can send the loader to folders none of these checks look at, so it is not run as root",
				path, strings.Join(env, ", "))
		}
		var expanded []string
		for _, rp := range rpaths {
			dir, err := w.expand(rp, loaderDir)
			if err != nil {
				return fmt.Errorf("%s searches %q for libraries: %w", path, rp, err)
			}
			expanded = append(expanded, dir)
		}
		search := append(expanded, inherited...)
		for _, dep := range deps {
			if err := w.dependency(path, dep, loaderDir, search); err != nil {
				return err
			}
		}
	}
	return nil
}

// dependency checks one library an image names, in every place dyld could find it.
func (w machoWalk) dependency(from string, dep machoDep, loaderDir string, search []string) error {
	rest, viaRpath := strings.CutPrefix(dep.name, "@rpath/")
	if !viaRpath {
		path, err := w.expand(dep.name, loaderDir)
		if err != nil {
			return fmt.Errorf("%s loads %q: %w", from, dep.name, err)
		}
		if err := w.candidate(from, path, dep.weak, true); err != nil {
			return err
		}
		if !dep.weak || systemLibrary(path) {
			return nil
		}
		if _, err := w.trust.lstat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s may load %s: %w", from, path, err)
		}
		return w.fallback(from, dep.name)
	}
	if len(search) == 0 {
		return fmt.Errorf("%s loads %s and names no folder to look for it in, so it would not start", from, dep.name)
	}
	found := false
	for _, dir := range search {
		path := filepath.Join(dir, rest)
		if systemLibrary(dir) {
			found = true
			continue
		}
		// Every folder on the list is checked rather than only the first one holding the
		// library: one another account can write is a place it can put a copy that is found
		// before the real one.
		if err := w.trust.closedDir(dir); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if parentErr := w.trust.closedDir(filepath.Dir(dir)); parentErr != nil && !errors.Is(parentErr, os.ErrNotExist) {
					return fmt.Errorf("%s loads %s: %w", from, dep.name, parentErr)
				}
				continue
			}
			return fmt.Errorf("%s loads %s: %w", from, dep.name, err)
		}
		if err := w.candidate(from, path, true, false); err != nil {
			return err
		}
		if _, err := w.trust.lstat(path); err == nil {
			found = true
		}
	}
	if found {
		return nil
	}
	if !dep.weak {
		return fmt.Errorf("%s loads %s and it is in none of the folders it names (%s), so it would not start",
			from, dep.name, strings.Join(search, ", "))
	}
	return w.fallback(from, dep.name)
}

// fallback checks the folders dyld searches by file name for a library in none of the places
// its image names: a weak import missing everywhere else is loaded from there when a file by
// that name turns up, so each folder has to be closed and any copy already in one trusted.
func (w machoWalk) fallback(from, name string) error {
	leaf := filepath.Base(name)
	for _, dir := range w.trust.dyldFallback {
		if systemLibrary(dir) {
			continue
		}
		if err := w.trust.closedDir(dir); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("%s may load %s from %s: %w", from, name, dir, err)
			}
			if parentErr := w.trust.closedDir(filepath.Dir(dir)); parentErr != nil && !errors.Is(parentErr, os.ErrNotExist) {
				return fmt.Errorf("%s may load %s from %s: %w", from, name, dir, parentErr)
			}
			continue
		}
		if err := w.candidate(from, filepath.Join(dir, leaf), true, false); err != nil {
			return err
		}
	}
	return nil
}

// candidate checks one place a library may be loaded from. optional is a library whose
// absence is not a failure, which is a weak import or one copy among several run paths.
func (w machoWalk) candidate(from, path string, optional, checkDir bool) error {
	if systemLibrary(path) {
		// The operating system's own libraries live in the dyld shared cache rather than as
		// files, and both places are under System Integrity Protection: nothing on disk to
		// check, and nothing an account can change.
		return nil
	}
	if err := w.trust.reach(path); err != nil {
		if errors.Is(err, os.ErrNotExist) && optional {
			if !checkDir {
				return nil
			}
			if dirErr := w.trust.closedDir(filepath.Dir(path)); dirErr != nil && !errors.Is(dirErr, os.ErrNotExist) {
				return fmt.Errorf("%s may load %s: %w", from, path, dirErr)
			}
			return nil
		}
		return fmt.Errorf("%s loads %s: %w", from, path, err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("%s loads %s: %w", from, path, err)
	}
	if resolved != path {
		if err := w.trust.reach(resolved); err != nil {
			return fmt.Errorf("%s loads %s: %w", from, path, err)
		}
	}
	if err := w.trust.file(resolved, false); err != nil {
		return fmt.Errorf("%s loads %s: %w", from, path, err)
	}
	if w.seen[resolved] {
		return nil
	}
	w.seen[resolved] = true
	f, err := os.Open(resolved)
	if err != nil {
		return fmt.Errorf("%s loads %s: %w", from, path, err)
	}
	defer f.Close()
	return w.image(resolved, f, nil)
}

// expand turns one of dyld's path forms into an absolute path.
func (w machoWalk) expand(name, loaderDir string) (string, error) {
	switch {
	case strings.HasPrefix(name, "@executable_path/"):
		return filepath.Join(w.exeDir, strings.TrimPrefix(name, "@executable_path/")), nil
	case strings.HasPrefix(name, "@loader_path/"):
		return filepath.Join(loaderDir, strings.TrimPrefix(name, "@loader_path/")), nil
	case name == "@executable_path":
		return w.exeDir, nil
	case name == "@loader_path":
		return loaderDir, nil
	case strings.HasPrefix(name, "@"):
		return "", fmt.Errorf("%q is not a path this side knows how dyld resolves", name)
	case !filepath.IsAbs(name):
		return "", fmt.Errorf("%q is relative, so dyld would resolve it against wherever the program was started from", name)
	}
	return name, nil
}

// systemLibrary reports a path under the two prefixes the operating system's own libraries
// live under. The path is cleaned first so a name climbing back out with ".." is not one.
// /System/Volumes holds the writable volumes macOS mounts, the data volume among them, so
// nothing under it is protected the way the rest of /System is.
func systemLibrary(path string) bool {
	clean := filepath.Clean(path)
	if strings.HasPrefix(clean, machoWritableVolumes) {
		return false
	}
	return strings.HasPrefix(clean, machoSystemLibs) || strings.HasPrefix(clean, machoSystemLibrary)
}

// machoImages opens every architecture in a file: one for a thin file, each slice of a
// universal one. All of them are checked because which one runs is the kernel's choice.
func machoImages(r io.ReaderAt) ([]*macho.File, func(), error) {
	fat, err := macho.NewFatFile(r)
	if err == nil {
		files := make([]*macho.File, 0, len(fat.Arches))
		for _, arch := range fat.Arches {
			files = append(files, arch.File)
		}
		return files, func() { fat.Close() }, nil
	}
	if !errors.Is(err, macho.ErrNotFat) {
		return nil, func() {}, err
	}
	f, err := macho.NewFile(r)
	if err != nil {
		return nil, func() {}, err
	}
	return []*macho.File{f}, func() { f.Close() }, nil
}

// machoLoads reads the libraries one image names, the folders it searches for them, and the
// dyld environment variables it sets for itself with LC_DYLD_ENVIRONMENT.
func machoLoads(f *macho.File) (deps []machoDep, rpaths, env []string, err error) {
	for _, load := range f.Loads {
		switch l := load.(type) {
		case *macho.Dylib:
			deps = append(deps, machoDep{name: l.Name})
		case *macho.Rpath:
			rpaths = append(rpaths, l.Path)
		default:
			raw := load.Raw()
			if len(raw) < 12 {
				continue
			}
			cmd := f.ByteOrder.Uint32(raw[0:4])
			switch cmd {
			case lcLoadWeakDylib, lcReexportDylib, lcLazyLoadDylib, lcLoadUpwardDylib, lcLoadDylinker:
				name, err := loadString(raw, f.ByteOrder.Uint32(raw[8:12]))
				if err != nil {
					return nil, nil, nil, err
				}
				deps = append(deps, machoDep{name: name, weak: cmd == lcLoadWeakDylib})
			case lcDyldEnvironment:
				setting, err := loadString(raw, f.ByteOrder.Uint32(raw[8:12]))
				if err != nil {
					return nil, nil, nil, err
				}
				env = append(env, setting)
			}
		}
	}
	return deps, rpaths, env, nil
}

// loadString reads the string a load command points at from inside itself.
func loadString(raw []byte, offset uint32) (string, error) {
	if int(offset) >= len(raw) {
		return "", errors.New("a load command names a string past its own end")
	}
	s := raw[offset:]
	if end := strings.IndexByte(string(s), 0); end >= 0 {
		s = s[:end]
	}
	return string(s), nil
}

// elfLibraries checks what ld.so brings in with an ELF program: the interpreter itself, any
// library named by path, and every folder named by RUNPATH or RPATH along with each copy of a
// needed library found in one -- and the same again for every library found that way. The
// system's own library folders are not on that list: they are root's, and checking them
// would be checking the distribution rather than this program.
func (pt programTrust) elfLibraries(path string, r io.ReaderAt) error {
	w := elfWalk{trust: pt, seen: map[string]bool{path: true}}
	return w.object(path, filepath.Dir(path), r, nil, true)
}

// elfWalk follows a program's libraries the way ld.so does, checking each one it finds.
type elfWalk struct {
	trust programTrust
	seen  map[string]bool
}

// object checks one ELF file -- the program, or a library it loads -- and recurses into every
// library it names that is found in a folder it searches. origin is what $ORIGIN means for
// it. inherited is the RPATH folders of the objects that loaded it, which ld.so also searches
// for its libraries; searching them even where a RUNPATH would have ld.so skip them only ever
// checks more.
func (w elfWalk) object(path, origin string, r io.ReaderAt, inherited []string, program bool) error {
	pt := w.trust
	f, err := elf.NewFile(r)
	if err != nil {
		return fmt.Errorf("read the libraries %s loads: %w", path, err)
	}
	defer f.Close()

	hasDynamic := false
	for _, prog := range f.Progs {
		switch prog.Type {
		case elf.PT_INTERP:
			if !program {
				// ld.so ignores the interpreter a library names.
				continue
			}
			raw, err := io.ReadAll(prog.Open())
			if err != nil {
				return fmt.Errorf("read the loader %s names: %w", path, err)
			}
			interp := strings.TrimRight(string(raw), "\x00")
			if err := pt.reach(interp); err != nil {
				return fmt.Errorf("%s is started by %s: %w", path, interp, err)
			}
			resolved, err := filepath.EvalSymlinks(interp)
			if err != nil {
				return fmt.Errorf("%s is started by %s: %w", path, interp, err)
			}
			if err := pt.reach(resolved); err != nil {
				return fmt.Errorf("%s is started by %s: %w", path, interp, err)
			}
			if err := pt.file(resolved, false); err != nil {
				return fmt.Errorf("%s is started by %s: %w", path, interp, err)
			}
		case elf.PT_DYNAMIC:
			hasDynamic = true
		}
	}
	if hasDynamic && f.SectionByType(elf.SHT_DYNAMIC) == nil {
		return fmt.Errorf("%s loads libraries and has had the table naming them stripped, so which ones cannot be checked", path)
	}

	needed, err := f.DynString(elf.DT_NEEDED)
	if err != nil {
		return fmt.Errorf("read the libraries %s loads: %w", path, err)
	}
	var dirs, rpaths []string
	for _, tag := range []elf.DynTag{elf.DT_RUNPATH, elf.DT_RPATH} {
		values, err := f.DynString(tag)
		if err != nil {
			return fmt.Errorf("read where %s looks for libraries: %w", path, err)
		}
		for _, value := range values {
			for _, dir := range strings.Split(value, ":") {
				expanded, err := expandOrigin(dir, origin)
				if err != nil {
					return fmt.Errorf("%s looks for libraries in %q: %w", path, dir, err)
				}
				dirs = append(dirs, expanded)
				if tag == elf.DT_RPATH {
					rpaths = append(rpaths, expanded)
				}
			}
		}
	}
	for _, dir := range dirs {
		if err := pt.closedDir(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s: %w", path, err)
		} else if errors.Is(err, os.ErrNotExist) {
			if parentErr := pt.closedDir(filepath.Dir(dir)); parentErr != nil && !errors.Is(parentErr, os.ErrNotExist) {
				return fmt.Errorf("%s: %w", path, parentErr)
			}
		}
	}
	// The inherited folders were checked as closed when the object naming them was.
	search := slices.Concat(dirs, inherited)
	passDown := slices.Concat(rpaths, inherited)
	for _, name := range needed {
		var places []string
		if strings.Contains(name, "/") {
			places = []string{name}
		} else {
			for _, dir := range search {
				places = append(places, filepath.Join(dir, name))
			}
		}
		for _, place := range places {
			if !filepath.IsAbs(place) {
				return fmt.Errorf("%s loads %q, which is relative to wherever it is started from", path, place)
			}
			if err := pt.reach(place); err != nil {
				if errors.Is(err, os.ErrNotExist) && !strings.Contains(name, "/") {
					continue
				}
				return fmt.Errorf("%s loads %s: %w", path, place, err)
			}
			resolved, err := filepath.EvalSymlinks(place)
			if err != nil {
				return fmt.Errorf("%s loads %s: %w", path, place, err)
			}
			if err := pt.file(resolved, false); err != nil {
				return fmt.Errorf("%s loads %s: %w", path, place, err)
			}
			if err := w.library(path, place, resolved, passDown); err != nil {
				return err
			}
		}
	}
	return nil
}

// library reads one library found at place, once, for what it loads in turn. ld.so takes
// $ORIGIN from the path it found the library by rather than from where a link leads.
func (w elfWalk) library(from, place, resolved string, inherited []string) error {
	if w.seen[resolved] {
		return nil
	}
	w.seen[resolved] = true
	f, err := os.Open(resolved)
	if err != nil {
		return fmt.Errorf("%s loads %s: %w", from, place, err)
	}
	defer f.Close()
	return w.object(resolved, filepath.Dir(place), f, inherited, false)
}

// expandOrigin substitutes $ORIGIN, the one ld.so variable whose value this side knows. An
// empty entry is the current directory and the other variables depend on the machine, so
// both are refused rather than guessed at.
func expandOrigin(dir, origin string) (string, error) {
	if dir == "" {
		return "", errors.New("an empty entry means wherever the program is started from")
	}
	dir = strings.ReplaceAll(dir, "${ORIGIN}", origin)
	dir = strings.ReplaceAll(dir, "$ORIGIN", origin)
	if strings.Contains(dir, "$") {
		return "", errors.New("it depends on a loader variable this side does not resolve")
	}
	if !filepath.IsAbs(dir) {
		return "", errors.New("it is relative to wherever the program is started from")
	}
	return dir, nil
}

// ownerOf reads who owns a path component and which group it belongs to.
func ownerOf(info fs.FileInfo, path string) (uid, gid uint32, err error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("could not read who owns %s", path)
	}
	return stat.Uid, stat.Gid, nil
}

// writers says who besides the owner can write a path component, for a refusal a person
// reads: every account, or the members of one group.
func writers(info fs.FileInfo) string {
	if info.Mode().Perm()&0o002 != 0 {
		return "every account on this machine"
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "the members of its group"
	}
	return "the members of " + describeGroup(stat.Gid)
}

// describeUser names an account for a person: its name when it has one, and always its number.
func describeUser(uid uint32) string {
	id := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(id); err == nil && u.Username != "" {
		return "the account " + u.Username + " (" + id + ")"
	}
	return "the account with id " + id
}

// describeGroup names a group the same way.
func describeGroup(gid uint32) string {
	id := strconv.FormatUint(uint64(gid), 10)
	if g, err := user.LookupGroupId(id); err == nil && g.Name != "" {
		return "the group " + g.Name + " (" + id + ")"
	}
	return "the group with id " + id
}
