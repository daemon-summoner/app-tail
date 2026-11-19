// SPDX-License-Identifier: MIT

package fileown

import "slices"

// The two kinds of access list entry this package reads. Every other kind lays its account
// out differently, so an entry of another kind is one it cannot say anything about.
const (
	entryAllows uint8 = 0
	entryDenies uint8 = 1
)

// Windows access rights, by the values the access list stores them under.
const (
	rightReadData    uint32 = 0x1
	rightWriteData   uint32 = 0x2 // on a directory: create a file in it
	rightAppendData  uint32 = 0x4 // on a directory: create a directory in it
	rightDeleteChild uint32 = 0x40
	rightDelete      uint32 = 0x10000
	rightWriteList   uint32 = 0x40000
	rightWriteOwner  uint32 = 0x80000
	rightGenericAll  uint32 = 0x10000000
	rightGenericWrt  uint32 = 0x40000000
	rightGenericRead uint32 = 0x80000000

	// rightsToReplace are what let an account put something else at a path: write into it,
	// remove it, or rewrite who may.
	rightsToReplace = rightWriteData | rightAppendData | rightDeleteChild | rightDelete |
		rightWriteList | rightWriteOwner | rightGenericAll | rightGenericWrt

	// rightsToReach adds reading, for a file whose contents are the secret.
	rightsToReach = rightsToReplace | rightReadData | rightGenericRead
)

// accessEntry is one entry of an access list, in terms that need no Windows to compare.
type accessEntry struct {
	kind uint8
	// inheritOnly marks an entry that applies to what is created inside a directory and not
	// to the directory itself.
	inheritOnly bool
	account     string
	rights      uint32
}

// accessProblem is what is wrong with who can reach a file.
type accessProblem int

const (
	accessPrivate accessProblem = iota
	accessOwnedByAnother
	accessUnlisted
	accessUnreadableEntry
	accessGrantedToAnother
)

// accessFault decides whether a file is private to the trusted accounts, and names the
// account that makes it not so when one does.
//
// owner must be trusted because an owner can always rewrite the list. A file with no list at
// all is open to everyone, and an entry of a kind this cannot read is counted against the
// file rather than skipped, since skipping it would pass a grant nobody looked at. Entries
// that deny take nothing from the answer: they can only narrow what the others allow.
func accessFault(owner string, listed bool, entries []accessEntry, trusted []string, rights uint32) (accessProblem, string) {
	if !slices.Contains(trusted, owner) {
		return accessOwnedByAnother, owner
	}
	if !listed {
		return accessUnlisted, ""
	}
	for _, entry := range entries {
		switch {
		case entry.kind == entryDenies:
		case entry.kind != entryAllows:
			return accessUnreadableEntry, ""
		case entry.inheritOnly, entry.rights&rights == 0, slices.Contains(trusted, entry.account):
		default:
			return accessGrantedToAnother, entry.account
		}
	}
	return accessPrivate, ""
}
