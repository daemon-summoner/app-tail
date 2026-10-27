// SPDX-License-Identifier: MIT

package fileowntest

import (
	"io/fs"
	"runtime"
	"slices"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// AssertOwnerOnly fails unless no account beyond this one can reach path. Windows answers
// that with the file's access list: it must take nothing from the directory it sits in, and
// every entry must name this account or one that could take ownership of the file anyway.
// The mode bits are inert here, so want is not consulted.
func AssertOwnerOnly(t testing.TB, path string, _ fs.FileMode) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read the access list of %s: %v", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("read the access list's flags: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("the access list of %s still inherits from the directory, so whoever reads that reads this", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("read the access list's entries: %v", err)
	}
	if dacl == nil {
		t.Fatalf("%s carries no access list, which is how a file is left open to everyone", path)
	}

	allowed := allowedTrustees(t)
	if int(dacl.AceCount) > len(allowed) {
		t.Fatalf("the access list of %s carries %d entries, and only %d accounts may appear in it",
			path, dacl.AceCount, len(allowed))
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("read access list entry %d: %v", i, err)
		}
		named := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !slices.ContainsFunc(allowed, named.Equals) {
			t.Errorf("entry %d of %s grants %s, which is neither this account nor one that could "+
				"take the file anyway", i, path, named)
		}
	}
}

// allowedTrustees are the accounts an owner-only file may name: this one, and the two that
// can take ownership of any file on the machine regardless of what its list says.
func allowedTrustees(t testing.TB) []*windows.SID {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("read the account this process runs as: %v", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatalf("look up the administrators group: %v", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("look up the local system account: %v", err)
	}
	return []*windows.SID{user.User.Sid, admins, system}
}

// RequireCanHandToAdministrators skips a case that writes a file through
// fileown.RestrictToAdministrators. That hands the file to the administrators group, which
// only an elevated process may do -- and on a real machine it is the elevated app-tail that
// writes these files. An ordinary process, an administrator's or not, is refused.
func RequireCanHandToAdministrators(t testing.TB) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the file is handed to the administrators group as it is written, which needs an elevated process")
	}
}

// CloseDirectory stops this process from creating anything in dir, and opens it again when
// the test ends so its temporary directory can still be cleared.
//
// A chmod changes nothing here, so the refusal is an entry on the directory's access list
// denying this account the right to add files and directories. The entry is explicit and
// the list stays unprotected, so what the directory inherits is untouched: deleting inside
// it still works, which is what clearing the temporary directory needs whatever happened
// in between.
func CloseDirectory(t testing.TB, dir string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("read the account this process runs as: %v", err)
	}
	entry := func(mode windows.ACCESS_MODE) []windows.EXPLICIT_ACCESS {
		return []windows.EXPLICIT_ACCESS{{
			AccessPermissions: windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA,
			AccessMode:        mode,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
			},
		}}
	}
	setExplicitEntries(t, dir, entry(windows.DENY_ACCESS))
	// Reopened with a grant in the deny's place rather than with no explicit entries at
	// all: SetEntriesInAcl hands back a NULL list for zero entries, which ACLFromEntries
	// then dereferences. The grant itself adds nothing the directory does not inherit.
	t.Cleanup(func() {
		setExplicitEntries(t, dir, entry(windows.GRANT_ACCESS))
		runtime.KeepAlive(user)
	})
	// The entry holds its SID as a bare address, so nothing else keeps it alive while the
	// list is built out of it.
	runtime.KeepAlive(user)
}

// setExplicitEntries replaces the explicit part of dir's access list, leaving what it
// inherits alone.
func setExplicitEntries(t testing.TB, dir string, entries []windows.EXPLICIT_ACCESS) {
	t.Helper()
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("build the access list for %s: %v", dir, err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatalf("apply the access list to %s: %v", dir, err)
	}
}
