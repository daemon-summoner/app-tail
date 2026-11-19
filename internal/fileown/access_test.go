// SPDX-License-Identifier: MIT

package fileown

import "testing"

const (
	thisAccount    = "S-1-5-21-1-2-3-1001"
	otherAccount   = "S-1-5-21-1-2-3-1002"
	administrators = "S-1-5-32-544"
	localSystem    = "S-1-5-18"
	everyone       = "S-1-1-0"
)

var trustedHere = []string{thisAccount, administrators, localSystem}

// The list fileown writes for an owner-only file, and the one a profile folder hands down.
func ownerOnlyList() []accessEntry {
	return []accessEntry{
		{kind: entryAllows, account: thisAccount, rights: rightGenericAll},
		{kind: entryAllows, account: administrators, rights: rightGenericAll},
		{kind: entryAllows, account: localSystem, rights: rightGenericAll},
	}
}

func TestWhoCanReachAFileDecidesWhetherItIsPrivate(t *testing.T) {
	with := func(extra ...accessEntry) []accessEntry { return append(ownerOnlyList(), extra...) }
	cases := []struct {
		name        string
		owner       string
		listed      bool
		entries     []accessEntry
		rights      uint32
		want        accessProblem
		wantAccount string
	}{
		{name: "this account and the two that could take it anyway", owner: thisAccount, listed: true,
			entries: ownerOnlyList(), rights: rightsToReach, want: accessPrivate},
		{name: "owned by the administrators after an elevated run", owner: administrators, listed: true,
			entries: ownerOnlyList(), rights: rightsToReach, want: accessPrivate},
		{name: "owned by another account, who can rewrite the list", owner: otherAccount, listed: true,
			entries: ownerOnlyList(), rights: rightsToReach, want: accessOwnedByAnother, wantAccount: otherAccount},
		{name: "no list at all", owner: thisAccount, listed: false,
			rights: rightsToReach, want: accessUnlisted},
		{name: "everyone may read", owner: thisAccount, listed: true,
			entries: with(accessEntry{kind: entryAllows, account: everyone, rights: rightReadData}),
			rights:  rightsToReach, want: accessGrantedToAnother, wantAccount: everyone},
		{name: "another account may write", owner: thisAccount, listed: true,
			entries: with(accessEntry{kind: entryAllows, account: otherAccount, rights: rightWriteData}),
			rights:  rightsToReach, want: accessGrantedToAnother, wantAccount: otherAccount},
		{name: "a folder everyone may read but not write", owner: thisAccount, listed: true,
			entries: with(accessEntry{kind: entryAllows, account: everyone, rights: rightReadData | rightGenericRead}),
			rights:  rightsToReplace, want: accessPrivate},
		{name: "a folder everyone may create files in", owner: thisAccount, listed: true,
			entries: with(accessEntry{kind: entryAllows, account: everyone, rights: rightWriteData}),
			rights:  rightsToReplace, want: accessGrantedToAnother, wantAccount: everyone},
		{name: "an entry that only applies to what the folder will hold", owner: thisAccount, listed: true,
			entries: with(accessEntry{kind: entryAllows, inheritOnly: true, account: everyone, rights: rightGenericAll}),
			rights:  rightsToReplace, want: accessPrivate},
		{name: "an entry denying another account", owner: thisAccount, listed: true,
			entries: with(accessEntry{kind: entryDenies, account: everyone, rights: rightGenericAll}),
			rights:  rightsToReach, want: accessPrivate},
		{name: "an entry of a kind that cannot be read", owner: thisAccount, listed: true,
			entries: with(accessEntry{kind: 9}),
			rights:  rightsToReach, want: accessUnreadableEntry},
		{name: "a list with nothing in it grants nobody", owner: thisAccount, listed: true,
			rights: rightsToReach, want: accessPrivate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, account := accessFault(tc.owner, tc.listed, tc.entries, trustedHere, tc.rights)
			if got != tc.want || account != tc.wantAccount {
				t.Errorf("accessFault = (%d, %q), want (%d, %q)", got, account, tc.want, tc.wantAccount)
			}
		})
	}
}
