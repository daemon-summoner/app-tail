// SPDX-License-Identifier: MIT

package fileown

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows has no O_NOFOLLOW. A link is followed, and what is checked is the file the handle
// ended up on, which is the one that is then read.
const openNoFollow = 0

func isSymlinkRefusal(error) bool { return false }

// inheritOnlyEntry is the flag on an access list entry that applies only to what is created
// inside a directory.
const inheritOnlyEntry = 0x08

// privateFault says why an opened file is not private, or nil when it is. The mode bits are
// inert here, so the answer is the file's owner and its access list, read from the handle.
func privateFault(f *os.File, _ fs.FileInfo, path string) (*NotPrivateError, error) {
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	return describedFault(sd, path, rightsToReach, `"%USERNAME%:F"`)
}

// PrivateDir refuses a directory another account owns or can put a file into, with a
// *NotPrivateError, since whoever can write it can swap what is kept inside.
func PrivateDir(dir string) error {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read who can reach %s: %w", dir, err)
	}
	fault, err := describedFault(sd, dir, rightsToReplace, `"%USERNAME%:(OI)(CI)F"`)
	if err != nil {
		return fmt.Errorf("read who can reach %s: %w", dir, err)
	}
	if fault != nil {
		return fault
	}
	return nil
}

// describedFault applies accessFault to a security descriptor and puts the answer in words,
// with the icacls line that repairs it. grant is what that line gives this account.
func describedFault(sd *windows.SECURITY_DESCRIPTOR, path string, rights uint32, grant string) (*NotPrivateError, error) {
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, err
	}
	listed := true
	dacl, _, err := sd.DACL()
	switch {
	case errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND), err == nil && dacl == nil:
		listed = false
	case err != nil:
		return nil, err
	}
	var entries []accessEntry
	if listed {
		for i := range uint32(dacl.AceCount) {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, i, &ace); err != nil {
				return nil, err
			}
			entry := accessEntry{kind: ace.Header.AceType, inheritOnly: ace.Header.AceFlags&inheritOnlyEntry != 0}
			// Only these two kinds keep their account where this reads it from.
			if entry.kind == entryAllows || entry.kind == entryDenies {
				entry.account = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
				entry.rights = uint32(ace.Mask)
			}
			entries = append(entries, entry)
		}
	}
	trusted, err := trustedAccounts()
	if err != nil {
		return nil, err
	}

	narrow := fmt.Sprintf(`icacls "%s" /inheritance:r /grant:r %s`, path, grant)
	problem, account := accessFault(owner.String(), listed, entries, trusted, rights)
	switch problem {
	case accessOwnedByAnother:
		return &NotPrivateError{
			Path:   path,
			Reason: fmt.Sprintf("belongs to another account (%s)", accountName(owner)),
			Fix:    fmt.Sprintf(`icacls "%s" /setowner "%%USERNAME%%"`, path),
		}, nil
	case accessUnlisted:
		return &NotPrivateError{Path: path, Reason: "carries no access list, which leaves it open to every account", Fix: narrow}, nil
	case accessUnreadableEntry:
		return &NotPrivateError{Path: path, Reason: "carries an access list entry of a kind app-tail cannot read", Fix: narrow}, nil
	case accessGrantedToAnother:
		name := account
		if sid, err := windows.StringToSid(account); err == nil {
			name = accountName(sid)
		}
		return &NotPrivateError{
			Path:   path,
			Reason: fmt.Sprintf("can be reached by another account (%s)", name),
			Fix:    narrow + " /remove:g *" + account,
		}, nil
	}
	return nil, nil
}

// trustedAccounts are the accounts that may reach a private file: this one, and the two
// that can take ownership of any file on the machine regardless of what its list says.
func trustedAccounts() ([]string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read the account this process runs as: %w", err)
	}
	trusted := []string{user.User.Sid.String()}
	for _, known := range []windows.WELL_KNOWN_SID_TYPE{windows.WinBuiltinAdministratorsSid, windows.WinLocalSystemSid} {
		sid, err := windows.CreateWellKnownSid(known)
		if err != nil {
			return nil, fmt.Errorf("look up a well-known account: %w", err)
		}
		trusted = append(trusted, sid.String())
	}
	return trusted, nil
}
