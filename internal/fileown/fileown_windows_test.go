// SPDX-License-Identifier: MIT

package fileown

import (
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/sellitus/app-tail/internal/fileown/fileowntest"
)

// The elevation check is the only thing between administrator rights and a program anybody
// can replace, so every branch of its decision is pinned here against a machine the test
// describes rather than the one it runs on.

// onAMachineWhere answers the two questions the check asks with what the test says.
func onAMachineWhere(t *testing.T, folders map[*windows.KNOWNFOLDERID]string, owners map[string]string) {
	t.Helper()
	wasFolder, wasOwned := knownFolderPath, ownedByAdministrators
	t.Cleanup(func() { knownFolderPath, ownedByAdministrators = wasFolder, wasOwned })
	knownFolderPath = func(id *windows.KNOWNFOLDERID, _ uint32) (string, error) {
		dir, known := folders[id]
		if !known {
			return "", errors.New("no such folder")
		}
		return dir, nil
	}
	ownedByAdministrators = func(path string) (bool, string, error) {
		owner, known := owners[strings.ToLower(path)]
		if !known {
			return false, "", errors.New("read who owns " + path + ": no such path")
		}
		return owner == "", owner, nil
	}
}

var theUsualFolders = map[*windows.KNOWNFOLDERID]string{
	windows.FOLDERID_ProgramFiles:    `C:\Program Files`,
	windows.FOLDERID_ProgramFilesX86: `C:\Program Files (x86)`,
	windows.FOLDERID_Windows:         `C:\Windows`,
}

// A path is under a protected folder only on whole path elements: a sibling folder whose
// name begins with the same letters is a folder a standard account may have created, and
// the filesystem's own case-insensitivity has to be honoured or an installer that wrote
// "program files" would be refused.
func TestAFolderIsUnderARootOnWholeElementsAndWithoutRegardToCase(t *testing.T) {
	roots := []string{`C:\Program Files`, `C:\Windows`}
	cases := []struct {
		dir  string
		want bool
	}{
		{`C:\Program Files`, true},
		{`c:\program files`, true},
		{`C:\Program Files\app-tail`, true},
		{`C:\PROGRAM FILES\app-tail\bin`, true},
		{`C:\Program Files\`, true},
		{`C:\Program Files Extra`, false},
		{`C:\Program Files Extra\app-tail`, false},
		{`C:\Program`, false},
		{`C:\`, false},
		{`D:\Program Files\app-tail`, false},
		{`C:\Windows\System32`, true},
		{`C:\WindowsApps`, false},
	}
	for _, c := range cases {
		if got := underAny(c.dir, roots); got != c.want {
			t.Errorf("underAny(%q) = %t, want %t", c.dir, got, c.want)
		}
	}
}

func TestAProgramOutsideEveryProtectedFolderIsReplaceableAndTheReasonNamesThem(t *testing.T) {
	onAMachineWhere(t, theUsualFolders, nil)

	replaceable, reason, err := ReplaceableByOtherAccounts(`C:\Users\sam\Downloads\app-tail.exe`)

	if err != nil {
		t.Fatalf("ReplaceableByOtherAccounts: %v", err)
	}
	if !replaceable {
		t.Fatal("a program in Downloads was passed as one only administrators can replace")
	}
	for _, want := range []string{`C:\Users\sam\Downloads\app-tail.exe`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\Windows`} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason = %q, want it to name %s", reason, want)
		}
	}
}

// Location is necessary and not sufficient: a folder under Program Files that a standard
// account created belongs to that account, and so does anything it put there.
func TestAProgramInAProtectedFolderStillHasToBelongToTheAdministrators(t *testing.T) {
	cases := []struct {
		name   string
		owners map[string]string
		want   bool
		reason string
	}{
		{
			name:   "both the folder and the program belong to the administrators",
			owners: map[string]string{`c:\program files\app-tail`: "", `c:\program files\app-tail\app-tail.exe`: ""},
		},
		{
			name:   "the folder belongs to a standard account",
			owners: map[string]string{`c:\program files\app-tail`: `DESKTOP\sam`, `c:\program files\app-tail\app-tail.exe`: ""},
			want:   true,
			reason: `C:\Program Files\app-tail, which belongs to DESKTOP\sam`,
		},
		{
			name:   "the program belongs to a standard account",
			owners: map[string]string{`c:\program files\app-tail`: "", `c:\program files\app-tail\app-tail.exe`: `DESKTOP\sam`},
			want:   true,
			reason: `app-tail.exe, which belongs to DESKTOP\sam`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			onAMachineWhere(t, theUsualFolders, c.owners)

			replaceable, reason, err := ReplaceableByOtherAccounts(`C:\Program Files\app-tail\app-tail.exe`)

			if err != nil {
				t.Fatalf("ReplaceableByOtherAccounts: %v", err)
			}
			if replaceable != c.want {
				t.Errorf("replaceable = %t, want %t (reason %q)", replaceable, c.want, reason)
			}
			if !strings.Contains(reason, c.reason) {
				t.Errorf("reason = %q, want it to say %q", reason, c.reason)
			}
		})
	}
}

// Ownership that cannot be read is not a pass: the check exists to refuse, and an error on
// the way to the answer is reported as one rather than read as "belongs to nobody else".
func TestOwnershipThatCannotBeReadIsAnErrorRatherThanAPass(t *testing.T) {
	onAMachineWhere(t, theUsualFolders, map[string]string{})

	replaceable, _, err := ReplaceableByOtherAccounts(`C:\Program Files\app-tail\app-tail.exe`)

	if err == nil || !strings.Contains(err.Error(), "about to be started with administrator rights") {
		t.Fatalf("err = %v, want the ownership failure named against the elevation", err)
	}
	if replaceable {
		t.Error("a check that failed reported the program as replaceable, which is an answer it does not have")
	}
}

// A machine that cannot name any protected folder is an error rather than a pass, for the
// same reason: with no folder to compare against, every location would be refused or every
// location passed, and only the first is safe -- and it is safest said out loud.
func TestAMachineThatNamesNoProtectedFolderIsAnError(t *testing.T) {
	onAMachineWhere(t, map[*windows.KNOWNFOLDERID]string{}, nil)

	replaceable, _, err := ReplaceableByOtherAccounts(`C:\Program Files\app-tail\app-tail.exe`)

	if err == nil || !strings.Contains(err.Error(), "Program Files") {
		t.Fatalf("err = %v, want it to say the machine did not name its Program Files folder", err)
	}
	if replaceable {
		t.Error("a check with nothing to compare against reported an answer")
	}
	// One folder is enough to decide with.
	onAMachineWhere(t, map[*windows.KNOWNFOLDERID]string{windows.FOLDERID_Windows: `C:\Windows`}, nil)
	if _, _, err := ReplaceableByOtherAccounts(`C:\Users\sam\app-tail.exe`); err != nil {
		t.Errorf("one named folder was refused as none: %v", err)
	}
}

// An owner this machine can no longer name -- a deleted local account, a domain it cannot
// reach -- is shown as its identifier rather than as nothing, so the reason still says who.
func TestAnOwnerThisMachineCannotNameIsShownAsItsIdentifier(t *testing.T) {
	unknown, err := windows.StringToSid("S-1-5-21-1-2-3-4567")
	if err != nil {
		t.Fatalf("StringToSid: %v", err)
	}

	if got := accountName(unknown); got != "S-1-5-21-1-2-3-4567" {
		t.Errorf("accountName = %q, want the identifier itself", got)
	}

	// And one it can name is named, with its domain in front.
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid: %v", err)
	}
	if got := accountName(system); !strings.HasSuffix(got, `\SYSTEM`) {
		t.Errorf("accountName(SYSTEM) = %q, want the domain-qualified name", got)
	}
}

// What RestrictToOwner writes is read back off a real file: the owner keeps everything, and
// the entries the directory would have handed down are gone.
func TestRestrictToOwnerLeavesOnlyTheOwnerAndTheAdministratorsOnTheFile(t *testing.T) {
	fileowntest.RequireCanHandToAdministrators(t)
	path := t.TempDir() + `\secret.key`
	if err := WriteRestricted(path, []byte("k"), 0o600); err != nil {
		t.Fatalf("WriteRestricted: %v", err)
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL: %v", err)
	}
	if acl == nil {
		t.Fatal("the file has no access list at all, which is everyone allowed everything")
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("Control: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("the access list still inherits from the directory, so nothing was narrowed")
	}
}

// The two refusals an on-access scanner produces are the only ones worth waiting on. A
// missing file or a missing directory is the same answer a second later.
func TestOnlyAScannersRefusalCountsAsTransient(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"access denied, wrapped the way os.Rename reports it", &os.LinkError{Op: "rename", Old: "a", New: "b", Err: windows.ERROR_ACCESS_DENIED}, true},
		{"sharing violation", &os.LinkError{Op: "rename", Old: "a", New: "b", Err: windows.ERROR_SHARING_VIOLATION}, true},
		{"file not found", &os.LinkError{Op: "rename", Old: "a", New: "b", Err: windows.ERROR_FILE_NOT_FOUND}, false},
		{"path not found", &os.LinkError{Op: "rename", Old: "a", New: "b", Err: windows.ERROR_PATH_NOT_FOUND}, false},
		{"not an errno at all", errors.New("access denied"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		if got := transientRenameError(tc.err); got != tc.want {
			t.Errorf("%s: transientRenameError = %v, want %v", tc.name, got, tc.want)
		}
	}
}
