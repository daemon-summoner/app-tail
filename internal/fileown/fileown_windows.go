// SPDX-License-Identifier: MIT

// Package fileown narrows a file to the account that owns it, on the one platform where
// creating it with restrictive mode bits does not.
package fileown

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// RestrictToOwner narrows a file to the account that owns it. Windows has no permission
// bits for FileMode to carry, so a file keeps whatever its parent directory hands down
// until an access list is written explicitly.
//
// Administrators and SYSTEM keep their access: either can take ownership of any file on
// the machine, so leaving them out denies nothing while risking a file the account can no
// longer read after one elevated run. What it does deny is every other account, which is
// the property the mode bits carry elsewhere.
func RestrictToOwner(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read the account this process runs as: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("look up the administrators group: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("look up the local system account: %w", err)
	}

	// Running as one of the other two named accounts would otherwise repeat its entry.
	var granted []*windows.SID
	for _, sid := range []*windows.SID{user.User.Sid, admins, system} {
		if !slices.ContainsFunc(granted, sid.Equals) {
			granted = append(granted, sid)
		}
	}
	entries := make([]grant, 0, len(granted))
	for _, sid := range granted {
		entries = append(entries, grant{sid: sid, permissions: windows.GENERIC_ALL})
	}
	return applyAccessList(path, entries, windows.NO_INHERITANCE, nil)
}

// RestrictToAdministrators narrows writing path to the administrators group and the local
// system account, hands the group ownership of it, and leaves every account able to read it.
//
// It is the stronger form, for a file an elevated app-tail reads and acts on later. On
// Windows the account app-tail elevates from is the same account it ran as before, so an
// access list granting that account -- what RestrictToOwner writes -- is a list the
// unelevated half of the same session can rewrite between two elevated runs. Ownership is
// written as well as the access list because ownership is what OwnedByAdministrators reads
// back before acting on the contents.
//
// Reading is what the integrity here does not depend on, and what an unelevated app-tail
// needs: these files record what an elevated run changed about the machine, and the
// unelevated process is the one that has to notice a record is there in order to ask for the
// rights that put the machine back. Denied the read it would report a healthy machine and
// never ask.
func RestrictToAdministrators(path string) error {
	return restrictToAdministrators(path, windows.NO_INHERITANCE)
}

// RestrictTreeToAdministrators does the same to a directory and to everything created
// inside it from then on.
func RestrictTreeToAdministrators(path string) error {
	return restrictToAdministrators(path, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
}

func restrictToAdministrators(path string, inheritance uint32) error {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("look up the administrators group: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("look up the local system account: %w", err)
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return fmt.Errorf("look up the users group: %w", err)
	}
	return applyAccessList(path, []grant{
		{sid: admins, permissions: windows.GENERIC_ALL},
		{sid: system, permissions: windows.GENERIC_ALL},
		// Execute as well as read: on a directory that permission is the right to traverse it,
		// without which the read granted on the files inside cannot be reached.
		{sid: users, permissions: windows.GENERIC_READ | windows.GENERIC_EXECUTE},
	}, inheritance, admins)
}

// The two questions the elevation check asks the machine, held so a test can answer them for
// a machine it is not running on: which folders are protected, and who owns a path.
var (
	knownFolderPath       = windows.KnownFolderPath
	ownedByAdministrators = OwnedByAdministrators
)

// grant is one account and what it may do.
type grant struct {
	sid         *windows.SID
	permissions windows.ACCESS_MASK
}

// applyAccessList gives each granted SID the access named with it and nobody else any,
// optionally setting the owner at the same time.
func applyAccessList(path string, granted []grant, inheritance uint32, owner *windows.SID) error {
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(granted))
	for _, g := range granted {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: g.permissions,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(g.sid),
			},
		})
	}

	acl, err := windows.ACLFromEntries(entries, nil)
	// An entry holds its SID as a bare address, so nothing else keeps these alive while
	// the list is being built out of them.
	runtime.KeepAlive(granted)
	if err != nil {
		return fmt.Errorf("build the access list: %w", err)
	}
	// PROTECTED_DACL_SECURITY_INFORMATION is what drops the entries inherited from the
	// directory. Without it the new entries join them and nothing has been narrowed.
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if owner != nil {
		info |= windows.OWNER_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, nil, acl, nil); err != nil {
		return fmt.Errorf("apply the access list to %s: %w", path, err)
	}
	return nil
}

// OwnedByAdministrators reports whether path belongs to the administrators group or to the
// local system account, and names the account it belongs to when it does not.
//
// The caller uses it to decide whether a file it is about to act on was put there by an
// elevated app-tail or by somebody else: a directory under ProgramData that no elevated
// process has created yet can be created by any account, and that account then owns it.
func OwnedByAdministrators(path string) (bool, string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, "", fmt.Errorf("read who owns %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, "", fmt.Errorf("read who owns %s: %w", path, err)
	}
	for _, known := range []windows.WELL_KNOWN_SID_TYPE{windows.WinBuiltinAdministratorsSid, windows.WinLocalSystemSid} {
		sid, err := windows.CreateWellKnownSid(known)
		if err != nil {
			return false, "", fmt.Errorf("look up a well-known account: %w", err)
		}
		if owner.Equals(sid) {
			return true, "", nil
		}
	}
	return false, accountName(owner), nil
}

// ReplaceableByOtherAccounts reports whether the program at path could be swapped for
// another one by an account without administrator rights, and says why when it could.
//
// It is the question every elevation raises: whatever sits at that path is what receives the
// rights, so a folder a standard account can write is a folder anything running as that
// account can put its own program into -- or its own wintun.dll, which the program loads
// from beside itself. Ownership is what can be asked about that: a folder a standard account
// created belongs to that account, and one under Program Files belongs to the administrators.
//
// Ownership alone is not enough, which is why the location is checked as well: C:\ and
// C:\ProgramData belong to the local system account and still let any user create files in
// them. The folders below are the ones Windows itself keeps writable only by administrators.
//
// The reason it returns is a clause naming the path and the problem, for a caller to finish
// with the consequence and the remedy that belong to what it was about to do.
func ReplaceableByOtherAccounts(path string) (bool, string, error) {
	dir := filepath.Dir(path)
	protected, err := protectedProgramDirs()
	if err != nil {
		return false, "", err
	}
	if !underAny(dir, protected) {
		return true, fmt.Sprintf("app-tail is at %s, which is not one of the folders Windows keeps writable only "+
			"by administrators (%s)", path, strings.Join(protected, ", ")), nil
	}
	for _, each := range []string{dir, path} {
		owned, owner, err := ownedByAdministrators(each)
		if err != nil {
			return false, "", fmt.Errorf("read who owns %s, which is about to be started with administrator rights: %w", each, err)
		}
		if !owned {
			return true, fmt.Sprintf("app-tail is at %s, which belongs to %s rather than to the administrators", each, owner), nil
		}
	}
	return false, "", nil
}

// protectedProgramDirs are the folders a program started with administrator rights may live
// in. A machine that cannot name any of them is an error rather than a pass: this check is
// the only thing between those rights and a program anybody can replace.
func protectedProgramDirs() ([]string, error) {
	var out []string
	for _, folder := range []*windows.KNOWNFOLDERID{
		windows.FOLDERID_ProgramFiles,
		windows.FOLDERID_ProgramFilesX86,
		windows.FOLDERID_Windows,
	} {
		if dir, err := knownFolderPath(folder, windows.KF_FLAG_DEFAULT_PATH); err == nil && dir != "" {
			out = append(out, filepath.Clean(dir))
		}
	}
	if len(out) == 0 {
		return nil, errors.New("this machine did not say where its Program Files folder is, so app-tail cannot " +
			"tell whether it is installed somewhere it may be started with administrator rights")
	}
	return out, nil
}

// underAny reports whether dir is one of the roots or sits inside one. The comparison is
// case-insensitive because the filesystem is, and it is done on whole path elements so that
// C:\Program Files Extra is not read as being under C:\Program Files.
func underAny(dir string, roots []string) bool {
	dir = filepath.Clean(dir)
	for _, root := range roots {
		if strings.EqualFold(dir, root) {
			return true
		}
		prefix := root
		if !strings.HasSuffix(prefix, string(filepath.Separator)) {
			prefix += string(filepath.Separator)
		}
		if len(dir) > len(prefix) && strings.EqualFold(dir[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

// accountName is the name an owner is worth showing under, falling back to the identifier
// itself for an account this machine can no longer resolve -- a deleted local account, or
// one from a domain it cannot reach.
func accountName(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil || account == "" {
		return sid.String()
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}

// transientRenameError reports whether a rename failed in the way an on-access scanner
// holding the file produces. ERROR_FILE_NOT_FOUND is deliberately not here: Go's toolchain
// retries it, but in this package the source file was created by the same call, and a
// rename that cannot find it is a real failure.
func transientRenameError(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == windows.ERROR_ACCESS_DENIED || errno == windows.ERROR_SHARING_VIOLATION
}
