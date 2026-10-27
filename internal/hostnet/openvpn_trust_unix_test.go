// SPDX-License-Identifier: MIT

//go:build unix

package hostnet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// someoneElse is an account id that is neither root nor whoever runs the suite. The tests
// describe a path component as belonging to it; no account by that number has to exist.
const someoneElse = 4242

// testTrust is the policy the suite checks programs against: root and the account running the
// suite are the trusted ones, so files the suite makes count as root's would in production,
// and any path listed in owners is reported as belonging to that account instead.
//
// The production policy is exactly this with only root trusted and nothing rewritten, so a
// refusal reached here is the refusal a real install reaches when another account owns or can
// write the same component.
func testTrust(owners map[string]uint32) programTrust {
	me := uint32(os.Getuid())
	return programTrust{
		trusted: func(uid uint32) bool { return uid == 0 || uid == me },
		lstat: func(name string) (fs.FileInfo, error) {
			info, err := os.Lstat(name)
			if err != nil {
				return nil, err
			}
			uid, ok := owners[name]
			if !ok {
				return info, nil
			}
			stat := *info.Sys().(*syscall.Stat_t)
			stat.Uid = uid
			return ownedBy{FileInfo: info, stat: &stat}, nil
		},
		dyldFallback: dyldFallbackDirs,
	}
}

// ownedBy is a file's details with its owner replaced.
type ownedBy struct {
	fs.FileInfo
	stat *syscall.Stat_t
}

func (o ownedBy) Sys() any { return o.stat }

// realTempDir makes a directory for one test and returns the path the kernel resolves it to.
// The walk records each component by its real name -- on macOS the temporary directory sits
// behind the /var link -- and the owners map has to use the same names.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve the test's directory: %v", err)
	}
	return dir
}

// mkdirMode makes a directory and sets its mode exactly, past whatever umask the suite runs
// under.
func mkdirMode(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("make %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("set the mode of %s: %v", path, err)
	}
}

// writeProgram writes a file with the given contents and mode exactly.
func writeProgram(t *testing.T, path string, body []byte, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("set the mode of %s: %v", path, err)
	}
}

// machoLoad is one load command for a built Mach-O file.
type machoLoad struct {
	cmd  uint32
	name string
}

// machoProgram builds the smallest 64-bit little-endian Mach-O executable debug/macho reads:
// a header and the load commands given, nothing else. LC_RPATH and LC_DYLD_ENVIRONMENT carry
// their string at offset 12; every dylib-family command at offset 24, after the timestamp and
// the two versions.
func machoProgram(loads ...machoLoad) []byte {
	var cmds bytes.Buffer
	for _, l := range loads {
		offset := 24
		if l.cmd == lcRpath || l.cmd == lcDyldEnvironment {
			offset = 12
		}
		size := offset + len(l.name) + 1
		size = (size + 7) &^ 7
		cmd := make([]byte, size)
		binary.LittleEndian.PutUint32(cmd[0:], l.cmd)
		binary.LittleEndian.PutUint32(cmd[4:], uint32(size))
		binary.LittleEndian.PutUint32(cmd[8:], uint32(offset))
		copy(cmd[offset:], l.name)
		cmds.Write(cmd)
	}
	header := make([]byte, 32)
	binary.LittleEndian.PutUint32(header[0:], 0xfeedfacf)
	binary.LittleEndian.PutUint32(header[4:], 0x0100000c)
	binary.LittleEndian.PutUint32(header[12:], 2)
	binary.LittleEndian.PutUint32(header[16:], uint32(len(loads)))
	binary.LittleEndian.PutUint32(header[20:], uint32(cmds.Len()))
	return append(header, cmds.Bytes()...)
}

// elfDyn is one entry of a built ELF file's dynamic table.
type elfDyn struct {
	tag   uint64
	value string
}

// elfProgram builds the smallest 64-bit little-endian ELF executable debug/elf reads. With no
// entries it is a statically linked program: no dynamic table at all. With entries it carries
// a .dynamic section naming its libraries and search folders through a .dynstr string table.
func elfProgram(entries ...elfDyn) []byte {
	const ehsize, shentsize = 64, 64
	header := func(shoff uint64, shnum, shstrndx uint16) []byte {
		h := make([]byte, ehsize)
		copy(h, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
		binary.LittleEndian.PutUint16(h[16:], 2)
		binary.LittleEndian.PutUint16(h[18:], 62)
		binary.LittleEndian.PutUint32(h[20:], 1)
		binary.LittleEndian.PutUint64(h[40:], shoff)
		binary.LittleEndian.PutUint16(h[52:], ehsize)
		binary.LittleEndian.PutUint16(h[54:], 56)
		binary.LittleEndian.PutUint16(h[58:], shentsize)
		binary.LittleEndian.PutUint16(h[60:], shnum)
		binary.LittleEndian.PutUint16(h[62:], shstrndx)
		return h
	}
	if len(entries) == 0 {
		return header(0, 0, 0)
	}

	dynstr := []byte{0}
	var dynamic []byte
	for _, e := range entries {
		entry := make([]byte, 16)
		binary.LittleEndian.PutUint64(entry[0:], e.tag)
		binary.LittleEndian.PutUint64(entry[8:], uint64(len(dynstr)))
		dynamic = append(dynamic, entry...)
		dynstr = append(append(dynstr, e.value...), 0)
	}
	dynamic = append(dynamic, make([]byte, 16)...)
	shstrtab := []byte("\x00.dynstr\x00.dynamic\x00.shstrtab\x00")

	dynstrOff := uint64(ehsize)
	dynamicOff := dynstrOff + uint64(len(dynstr))
	dynamicOff = (dynamicOff + 7) &^ 7
	shstrOff := dynamicOff + uint64(len(dynamic))
	shoff := (shstrOff + uint64(len(shstrtab)) + 7) &^ 7

	section := func(name, typ uint32, off, size uint64, link uint32, entsize uint64) []byte {
		s := make([]byte, shentsize)
		binary.LittleEndian.PutUint32(s[0:], name)
		binary.LittleEndian.PutUint32(s[4:], typ)
		binary.LittleEndian.PutUint64(s[24:], off)
		binary.LittleEndian.PutUint64(s[32:], size)
		binary.LittleEndian.PutUint32(s[40:], link)
		binary.LittleEndian.PutUint64(s[48:], 1)
		binary.LittleEndian.PutUint64(s[56:], entsize)
		return s
	}

	out := make([]byte, shoff)
	copy(out, header(shoff, 4, 3))
	copy(out[dynstrOff:], dynstr)
	copy(out[dynamicOff:], dynamic)
	copy(out[shstrOff:], shstrtab)
	out = append(out, make([]byte, shentsize)...)
	out = append(out, section(1, 3, dynstrOff, uint64(len(dynstr)), 0, 0)...)
	out = append(out, section(9, 6, dynamicOff, uint64(len(dynamic)), 1, 16)...)
	out = append(out, section(18, 3, shstrOff, uint64(len(shstrtab)), 0, 0)...)
	return out
}

const (
	lcLoadDylib = 0xc
	lcRpath     = 0x8000001c
	dtNeeded    = 1
	dtRpath     = 15
	dtRunpath   = 29
)

// refusedNaming checks that a refusal happened, is not the "nothing here" a caller skips past,
// and names the component that made the program unsafe -- the sentence a person reads to know
// what to fix.
func refusedNaming(t *testing.T, err error, what, component string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s was accepted as a program to run as root", what)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s was refused as missing rather than as unsafe: %v", what, err)
	}
	if !strings.Contains(err.Error(), component) {
		t.Errorf("the refusal of %s does not name %s: %v", what, component, err)
	}
}

func TestAProgramInADirectoryAnotherAccountCanWriteIsNotRunAsRoot(t *testing.T) {
	root := realTempDir(t)
	program := machoProgram(machoLoad{lcLoadDylib, "/usr/lib/libSystem.B.dylib"})

	closed := filepath.Join(root, "closed")
	mkdirMode(t, closed, 0o755)
	writeProgram(t, filepath.Join(closed, "openvpn"), program, 0o755)
	if err := testTrust(nil).program(filepath.Join(closed, "openvpn")); err != nil {
		t.Fatalf("a program in a directory only its owner can write was refused: %v", err)
	}

	open := filepath.Join(root, "open")
	mkdirMode(t, open, 0o777)
	writeProgram(t, filepath.Join(open, "openvpn"), program, 0o755)
	err := testTrust(nil).program(filepath.Join(open, "openvpn"))
	refusedNaming(t, err, "a program in a directory every account can write", open)
	if !strings.Contains(err.Error(), "every account") {
		t.Errorf("the refusal does not say who can write the directory: %v", err)
	}

	group := filepath.Join(root, "group")
	mkdirMode(t, group, 0o775)
	writeProgram(t, filepath.Join(group, "openvpn"), program, 0o755)
	err = testTrust(nil).program(filepath.Join(group, "openvpn"))
	refusedNaming(t, err, "a program in a directory its group can write", group)
	if !strings.Contains(err.Error(), "group") {
		t.Errorf("the refusal does not say a group can write the directory: %v", err)
	}

	// Further out counts as much as the directory holding the file: whoever owns a directory
	// two levels up can rename the one in between away and put their own in its place.
	outer := filepath.Join(root, "outer")
	mkdirMode(t, filepath.Join(outer, "inner"), 0o755)
	writeProgram(t, filepath.Join(outer, "inner", "openvpn"), program, 0o755)
	err = testTrust(map[string]uint32{outer: someoneElse}).program(filepath.Join(outer, "inner", "openvpn"))
	refusedNaming(t, err, "a program under a directory another account owns", outer)

	// A sticky directory lets every account add entries but rename or remove only its own, so
	// a trusted entry in one is safe and somebody else's is not.
	sticky := filepath.Join(root, "sticky")
	mkdirMode(t, filepath.Join(sticky, "mine"), 0o755)
	mkdirMode(t, filepath.Join(sticky, "theirs"), 0o755)
	if err := os.Chmod(sticky, 0o777|fs.ModeSticky); err != nil {
		t.Fatalf("make %s sticky: %v", sticky, err)
	}
	writeProgram(t, filepath.Join(sticky, "mine", "openvpn"), program, 0o755)
	writeProgram(t, filepath.Join(sticky, "theirs", "openvpn"), program, 0o755)
	trust := testTrust(map[string]uint32{filepath.Join(sticky, "theirs"): someoneElse})
	if err := trust.program(filepath.Join(sticky, "mine", "openvpn")); err != nil {
		t.Errorf("a trusted entry in a sticky directory was refused: %v", err)
	}
	refusedNaming(t, trust.program(filepath.Join(sticky, "theirs", "openvpn")),
		"a program inside another account's entry in a sticky directory", filepath.Join(sticky, "theirs"))

	// The file itself, last: one its group can write is no safer than a directory that is.
	writable := filepath.Join(closed, "writable")
	writeProgram(t, writable, program, 0o775)
	refusedNaming(t, testTrust(nil).program(writable), "a program its group can write", writable)

	if err := testTrust(nil).program(filepath.Join(closed, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a path with nothing at it = %v, want os.ErrNotExist so a caller can try the next place", err)
	}
}

func TestAProgramReachedThroughAUserOwnedSymlinkIsRefused(t *testing.T) {
	root := realTempDir(t)
	program := machoProgram(machoLoad{lcLoadDylib, "/usr/lib/libSystem.B.dylib"})
	real := filepath.Join(root, "real")
	mkdirMode(t, real, 0o755)
	writeProgram(t, filepath.Join(real, "openvpn"), program, 0o755)

	// A link whose own directory is closed, pointing at a program whose path is closed too:
	// only a trusted account could have made it or can change it.
	links := filepath.Join(root, "links")
	mkdirMode(t, links, 0o755)
	if err := os.Symlink("../real/openvpn", filepath.Join(links, "openvpn")); err != nil {
		t.Fatalf("make the link: %v", err)
	}
	if err := testTrust(nil).program(filepath.Join(links, "openvpn")); err != nil {
		t.Fatalf("a link in a closed directory to a program in a closed directory was refused: %v", err)
	}

	// The same link where another account owns the directory holding it: that account can
	// point it anywhere.
	err := testTrust(map[string]uint32{links: someoneElse}).program(filepath.Join(links, "openvpn"))
	refusedNaming(t, err, "a program reached through a link in another account's directory", links)

	// A link owned by another account, sitting in a sticky directory every account can write:
	// its owner can remove it and make a new one aimed elsewhere.
	sticky := filepath.Join(root, "sticky")
	mkdirMode(t, sticky, 0o777)
	if err := os.Chmod(sticky, 0o777|fs.ModeSticky); err != nil {
		t.Fatalf("make %s sticky: %v", sticky, err)
	}
	theirs := filepath.Join(sticky, "openvpn")
	if err := os.Symlink(filepath.Join(real, "openvpn"), theirs); err != nil {
		t.Fatalf("make the link: %v", err)
	}
	refusedNaming(t, testTrust(map[string]uint32{theirs: someoneElse}).program(theirs),
		"a program reached through a link another account owns", theirs)

	// A directory on the way that is itself a link, leading somewhere another account can
	// write: the walk follows it and refuses the far end.
	open := filepath.Join(root, "open")
	mkdirMode(t, filepath.Join(open, "bin"), 0o755)
	writeProgram(t, filepath.Join(open, "bin", "openvpn"), program, 0o755)
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatalf("open %s: %v", open, err)
	}
	if err := os.Symlink(filepath.Join(open, "bin"), filepath.Join(links, "bin")); err != nil {
		t.Fatalf("make the link: %v", err)
	}
	refusedNaming(t, testTrust(nil).program(filepath.Join(links, "bin", "openvpn")),
		"a program reached through a linked directory every account can write", open)
}

func TestAProgramLinkingAUserWritableLibraryIsRefused(t *testing.T) {
	root := realTempDir(t)
	bin := filepath.Join(root, "bin")
	mkdirMode(t, bin, 0o755)
	open := filepath.Join(root, "open")
	mkdirMode(t, open, 0o777)
	closedLib := filepath.Join(root, "lib")
	mkdirMode(t, closedLib, 0o755)
	library := machoProgram(machoLoad{lcLoadDylib, "/usr/lib/libSystem.B.dylib"})
	writeProgram(t, filepath.Join(open, "libssl.dylib"), library, 0o644)
	writeProgram(t, filepath.Join(closedLib, "libssl.dylib"), library, 0o644)

	check := func(name string, body []byte, owners map[string]uint32) error {
		path := filepath.Join(bin, name)
		writeProgram(t, path, body, 0o755)
		return testTrust(owners).program(path)
	}

	if err := check("closed-dylib", machoProgram(machoLoad{lcLoadDylib, filepath.Join(closedLib, "libssl.dylib")}), nil); err != nil {
		t.Errorf("a program loading a library from a closed directory was refused: %v", err)
	}
	refusedNaming(t, check("open-dylib", machoProgram(machoLoad{lcLoadDylib, filepath.Join(open, "libssl.dylib")}), nil),
		"a program loading a library from a directory every account can write", open)

	// What the library loads counts too: the loader runs it with the same rights.
	writeProgram(t, filepath.Join(closedLib, "libwrap.dylib"),
		machoProgram(machoLoad{lcLoadDylib, filepath.Join(open, "libssl.dylib")}), 0o644)
	refusedNaming(t, check("indirect", machoProgram(machoLoad{lcLoadDylib, filepath.Join(closedLib, "libwrap.dylib")}), nil),
		"a program whose library loads one from a directory every account can write", open)

	// A run path is a folder searched by name, so one another account can write is a place to
	// plant a copy -- whether or not the real library is there too.
	refusedNaming(t, check("rpath", machoProgram(
		machoLoad{lcRpath, open},
		machoLoad{lcRpath, closedLib},
		machoLoad{lcLoadDylib, "@rpath/libssl.dylib"},
	), nil), "a program searching a directory every account can write for its libraries", open)
	if err := check("rpath-closed", machoProgram(
		machoLoad{lcRpath, "@loader_path/../lib"},
		machoLoad{lcLoadDylib, "@rpath/libssl.dylib"},
	), nil); err != nil {
		t.Errorf("a program finding its library through a run path in a closed directory was refused: %v", err)
	}

	// A library file another account owns, in a directory that is otherwise fine.
	owned := filepath.Join(closedLib, "libssl.dylib")
	refusedNaming(t, check("owned-dylib", machoProgram(machoLoad{lcLoadDylib, owned}), map[string]uint32{owned: someoneElse}),
		"a program loading a library another account owns", owned)

	if err := check("missing", machoProgram(machoLoad{lcLoadDylib, filepath.Join(closedLib, "libgone.dylib")}), nil); err == nil {
		t.Error("a program loading a library that is not there was accepted")
	}

	// The same on Linux: RUNPATH names folders ld.so searches, and a library named by path is
	// loaded from exactly there.
	if err := check("static", elfProgram(), nil); err != nil {
		t.Errorf("a statically linked program was refused: %v", err)
	}
	if err := check("elf-closed", elfProgram(elfDyn{dtRunpath, "$ORIGIN/../lib"}, elfDyn{dtNeeded, "libssl.so"}), nil); err != nil {
		t.Errorf("a program searching a closed directory for its libraries was refused: %v", err)
	}
	refusedNaming(t, check("elf-runpath", elfProgram(elfDyn{dtRunpath, open}, elfDyn{dtNeeded, "libssl.so"}), nil),
		"an ELF program searching a directory every account can write", open)
	writeProgram(t, filepath.Join(closedLib, "libssl.so"), library, 0o644)
	refusedNaming(t, check("elf-needed", elfProgram(elfDyn{dtNeeded, filepath.Join(closedLib, "libssl.so")}), map[string]uint32{closedLib: someoneElse}),
		"an ELF program loading a library from another account's directory", closedLib)
	if err := check("elf-relative", elfProgram(elfDyn{dtRunpath, "lib"}, elfDyn{dtNeeded, "libssl.so"}), nil); err == nil {
		t.Error("a program searching a folder relative to wherever it is started was accepted")
	}

	writeProgram(t, filepath.Join(bin, "script"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if err := testTrust(nil).program(filepath.Join(bin, "script")); err == nil {
		t.Error("a script was accepted, though the interpreter it names is not checked")
	}
}

// ld.so reads every library's own RUNPATH, RPATH and NEEDED the same way it reads the
// program's, so a library found in a closed folder can still send it somewhere open.
func TestALibraryAnELFProgramLoadsIsCheckedForWhereItLooksForItsOwn(t *testing.T) {
	root := realTempDir(t)
	bin := filepath.Join(root, "bin")
	mkdirMode(t, bin, 0o755)
	open := filepath.Join(root, "open")
	mkdirMode(t, open, 0o777)
	closedLib := filepath.Join(root, "lib")
	mkdirMode(t, closedLib, 0o755)
	writeProgram(t, filepath.Join(open, "libssl.so"), elfProgram(), 0o644)

	check := func(name string, body []byte, owners map[string]uint32) error {
		path := filepath.Join(bin, name)
		writeProgram(t, path, body, 0o755)
		return testTrust(owners).program(path)
	}

	writeProgram(t, filepath.Join(closedLib, "libwrap.so"),
		elfProgram(elfDyn{dtRunpath, open}, elfDyn{dtNeeded, "libssl.so"}), 0o644)
	refusedNaming(t, check("wrap", elfProgram(elfDyn{dtRunpath, closedLib}, elfDyn{dtNeeded, "libwrap.so"}), nil),
		"a program whose library searches a directory every account can write", open)

	// A library naming another by path is loaded from exactly there, at any depth.
	writeProgram(t, filepath.Join(closedLib, "libbypath.so"),
		elfProgram(elfDyn{dtNeeded, filepath.Join(open, "libssl.so")}), 0o644)
	refusedNaming(t, check("bypath", elfProgram(elfDyn{dtRunpath, closedLib}, elfDyn{dtNeeded, "libbypath.so"}), nil),
		"a program whose library loads one by path from a directory every account can write", open)

	// $ORIGIN in a library is that library's folder, and a library naming itself is read once.
	writeProgram(t, filepath.Join(closedLib, "libself.so"),
		elfProgram(elfDyn{dtRunpath, "$ORIGIN"}, elfDyn{dtNeeded, "libself.so"}, elfDyn{dtNeeded, "libgone.so"}), 0o644)
	if err := check("self", elfProgram(elfDyn{dtRunpath, closedLib}, elfDyn{dtNeeded, "libself.so"}), nil); err != nil {
		t.Errorf("a program whose library searches only its own closed folder was refused: %v", err)
	}

	// A library with no RUNPATH of its own is searched for in the RPATH of whatever loaded it,
	// so a file there another account owns is loaded on the library's behalf.
	inner := filepath.Join(closedLib, "libinner.so")
	writeProgram(t, inner, elfProgram(), 0o644)
	writeProgram(t, filepath.Join(closedLib, "liblegacy.so"), elfProgram(elfDyn{dtNeeded, "libinner.so"}), 0o644)
	refusedNaming(t, check("legacy", elfProgram(elfDyn{dtRpath, closedLib}, elfDyn{dtNeeded, "liblegacy.so"}),
		map[string]uint32{inner: someoneElse}),
		"a program whose library loads one another account owns through the program's RPATH", inner)
}

// Under /System/Volumes sit the writable volumes macOS mounts, the data volume among them, so
// a library reached through one is an ordinary file and not one of the system's own.
func TestALibraryUnderTheDataVolumeIsNotTakenForOneOfTheSystemsOwn(t *testing.T) {
	if !systemLibrary("/System/Library/Frameworks/Security.framework/Security") || !systemLibrary("/usr/lib/libSystem.B.dylib") {
		t.Error("a library under the system's own folders is no longer recognised as one")
	}
	for _, path := range []string{"/System/Volumes/Data/Users/someone/lib/libssl.dylib", "/System/Volumes/Preboot/libssl.dylib"} {
		if systemLibrary(path) {
			t.Errorf("systemLibrary(%q) = true, though that volume is writable", path)
		}
	}

	root := realTempDir(t)
	viaData := filepath.Join("/System/Volumes/Data", root)
	if _, err := os.Stat(viaData); err != nil {
		t.Skipf("the suite's directory is not reachable through the data volume here: %v", err)
	}
	open := filepath.Join(root, "open")
	mkdirMode(t, open, 0o777)
	writeProgram(t, filepath.Join(open, "libssl.dylib"), machoProgram(machoLoad{lcLoadDylib, "/usr/lib/libSystem.B.dylib"}), 0o644)
	program := filepath.Join(root, "openvpn")
	writeProgram(t, program, machoProgram(machoLoad{lcLoadDylib, filepath.Join(viaData, "open", "libssl.dylib")}), 0o755)
	refusedNaming(t, testTrust(nil).program(program),
		"a program loading a library from a directory every account can write, named through the data volume",
		filepath.Join(viaData, "open"))
}

// LC_DYLD_ENVIRONMENT lets a program set DYLD_LIBRARY_PATH and its relatives for itself, which
// sends dyld to folders none of the checks here look at.
func TestAProgramCarryingItsOwnLoaderEnvironmentIsRefused(t *testing.T) {
	root := realTempDir(t)
	lib := filepath.Join(root, "lib")
	mkdirMode(t, lib, 0o755)
	system := machoLoad{lcLoadDylib, "/usr/lib/libSystem.B.dylib"}
	setting := "DYLD_LIBRARY_PATH=/tmp/x"

	program := filepath.Join(root, "openvpn")
	writeProgram(t, program, machoProgram(system, machoLoad{lcDyldEnvironment, setting}), 0o755)
	refusedNaming(t, testTrust(nil).program(program), "a program setting its own dyld environment", setting)

	writeProgram(t, filepath.Join(lib, "libssl.dylib"), machoProgram(system, machoLoad{lcDyldEnvironment, setting}), 0o644)
	writeProgram(t, program, machoProgram(machoLoad{lcLoadDylib, filepath.Join(lib, "libssl.dylib")}), 0o755)
	refusedNaming(t, testTrust(nil).program(program), "a program whose library sets its own dyld environment", setting)
}

// A weak library that is not where an image names it, or an @rpath one in none of its run
// paths, is next looked for by file name in dyld's fallback folders, so those are where the
// program's code comes from.
func TestAMissingWeakLibraryIsCheckedWhereDyldLooksForItNext(t *testing.T) {
	root := realTempDir(t)
	bin := filepath.Join(root, "bin")
	mkdirMode(t, bin, 0o755)
	open := filepath.Join(root, "open")
	mkdirMode(t, open, 0o777)
	closedLib := filepath.Join(root, "lib")
	mkdirMode(t, closedLib, 0o755)
	fallback := filepath.Join(root, "fallback")
	mkdirMode(t, fallback, 0o755)

	check := func(name string, body []byte, fallbackDirs []string, owners map[string]uint32) error {
		path := filepath.Join(bin, name)
		writeProgram(t, path, body, 0o755)
		trust := testTrust(owners)
		trust.dyldFallback = fallbackDirs
		return trust.program(path)
	}
	weak := machoProgram(machoLoad{lcLoadWeakDylib, filepath.Join(closedLib, "libgone.dylib")})
	weakRpath := machoProgram(machoLoad{lcRpath, closedLib}, machoLoad{lcLoadWeakDylib, "@rpath/libgone.dylib"})

	if err := check("weak-closed", weak, []string{fallback, "/usr/lib"}, nil); err != nil {
		t.Errorf("a missing weak library whose fallback folders are closed was refused: %v", err)
	}
	refusedNaming(t, check("weak-open", weak, []string{open, "/usr/lib"}, nil),
		"a missing weak library with a fallback folder every account can write", open)
	refusedNaming(t, check("rpath-open", weakRpath, []string{open}, nil),
		"a missing weak @rpath library with a fallback folder every account can write", open)

	// A copy already sitting in a closed fallback folder is the one loaded, so it is checked
	// like any other library.
	planted := filepath.Join(fallback, "libgone.dylib")
	writeProgram(t, planted, machoProgram(machoLoad{lcLoadDylib, "/usr/lib/libSystem.B.dylib"}), 0o644)
	refusedNaming(t, check("weak-planted", weak, []string{fallback}, map[string]uint32{planted: someoneElse}),
		"a missing weak library found in a fallback folder as a file another account owns", planted)
}

func TestTheSystemsOwnRouteProgramIsTrustedAndASuiteFileIsNot(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the program checked here is the macOS one")
	}
	if err := trustedRootProgram("/sbin/route"); err != nil {
		t.Errorf("the system's own /sbin/route was refused: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root, every file the suite makes belongs to root")
	}
	path := filepath.Join(realTempDir(t), "openvpn")
	writeProgram(t, path, machoProgram(machoLoad{lcLoadDylib, "/usr/lib/libSystem.B.dylib"}), 0o755)
	if err := trustedRootProgram(path); err == nil {
		t.Errorf("a program this account made was accepted as one to run as root")
	}
}
