// SPDX-License-Identifier: MIT

package fileown

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// grantEveryone adds an entry to path's access list letting every account do what rights
// names, beside whatever the list already holds.
func grantEveryone(t *testing.T, path string, rights windows.ACCESS_MASK) {
	t.Helper()
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("look up the everyone group: %v", err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read the access list of %s: %v", path, err)
	}
	held, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("read the access list's entries: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: rights,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, held)
	// The entry holds its SID as a bare address, so nothing else keeps it alive while the
	// list is built out of it.
	runtime.KeepAlive(everyone)
	if err != nil {
		t.Fatalf("build the access list for %s: %v", path, err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatalf("apply the access list to %s: %v", path, err)
	}
}

func privateFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("held\n"), 0o600); err != nil {
		t.Fatalf("write the file: %v", err)
	}
	if err := RestrictToOwner(path); err != nil {
		t.Fatalf("narrow the file: %v", err)
	}
	return path
}

func TestAFileNarrowedToItsOwnerOpensAsPrivate(t *testing.T) {
	f, err := OpenPrivate(privateFile(t))
	if err != nil {
		t.Fatalf("OpenPrivate of a file narrowed to its owner: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// The mode bits cannot say this on Windows: the file looks the same to os.Stat either way.
func TestAFileEveryAccountMayReadIsRefusedWithTheRepair(t *testing.T) {
	path := privateFile(t)
	grantEveryone(t, path, windows.FILE_GENERIC_READ)

	f, err := OpenPrivate(path)
	if err == nil {
		f.Close()
		t.Fatal("a file every account may read was opened as private")
	}
	var loose *NotPrivateError
	if !errors.As(err, &loose) {
		t.Fatalf("OpenPrivate = %v, want a *NotPrivateError", err)
	}
	for _, want := range []string{path, "another account", "icacls", "S-1-1-0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal says %q, want it to mention %q", err, want)
		}
	}
}

func TestAFolderOnlyThisAccountCanWriteIsPrivate(t *testing.T) {
	dir := t.TempDir()
	grantEveryone(t, dir, windows.FILE_GENERIC_READ)
	if err := PrivateDir(dir); err != nil {
		t.Errorf("PrivateDir of a folder others may only read: %v", err)
	}
}

func TestAFolderEveryAccountMayWriteIsRefused(t *testing.T) {
	dir := t.TempDir()
	// On a folder this right is the one to create a file in it.
	grantEveryone(t, dir, windows.FILE_WRITE_DATA)

	err := PrivateDir(dir)
	var loose *NotPrivateError
	if !errors.As(err, &loose) {
		t.Fatalf("PrivateDir of a folder every account may write = %v, want a *NotPrivateError", err)
	}
	if !strings.Contains(err.Error(), "icacls") {
		t.Errorf("the refusal says %q, want the command that repairs it", err)
	}
}
