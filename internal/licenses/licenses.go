// SPDX-License-Identifier: MIT

// Package licenses carries the third-party notices this binary is required to
// distribute. They are embedded rather than shipped alongside because a notice that
// exists only in an archive the user deleted is not a notice.
package licenses

import (
	_ "embed"
	"strings"
)

//go:embed THIRD_PARTY_LICENSES.txt
var thirdParty string

//go:embed WINTUN_LICENSE.txt
var wintun string

// Filename is the name the notices are written under when a release copies them out
// of the binary, so the archive and `app-tail licenses` agree on what to call them.
const Filename = "THIRD_PARTY_LICENSES.txt"

// WintunFilename is the name the Wintun notice is written under beside the Windows
// binaries, where it accompanies the file it covers.
const WintunFilename = "WINTUN-LICENSE.txt"

// WintunVersion is the release of Wintun this notice was taken from and that the
// Windows archive ships. The two travel together: the terms grant a licence to "the
// precise contents" of a particular download, so a notice from another one covers
// nothing.
const WintunVersion = "0.14.1"

// WintunPreamble introduces the notice, because the file it covers is unlike every
// other dependency here: it is not linked into this binary and is not open source.
const WintunPreamble = "wintun.dll " + WintunVersion + " (WireGuard LLC, https://www.wintun.net)\n" +
	"Shipped beside app-tail.exe rather than linked into it, and loaded at run time only\n" +
	"by the network-interface mode. app-tail uses it through its published API and ships\n" +
	"it unmodified, which is what its terms permit. Its own licence follows.\n"

// ThirdParty returns the full notice text, terminated by exactly one newline.
//
// Callers print it straight to a terminal, and the generator separates modules with
// a blank line -- including after the last one -- so normalizing both ends of that
// is what keeps the shell prompt on the line after the text.
func ThirdParty() string {
	return strings.TrimRight(thirdParty, "\n") + "\n"
}

// Wintun returns the notice for the driver front end the Windows interface mode loads,
// exactly as its vendor distributes it.
//
// It is reproduced byte for byte, carriage returns included: the terms forbid altering
// the notice, and the release checks this copy against the archive the shipped DLL came
// out of, which a reformatting would silently break.
func Wintun() string { return wintun }

// WintunNotice returns the notice with the sentence that explains what it covers.
func WintunNotice() string {
	return WintunPreamble + "\n" + strings.TrimRight(normalizeNewlines(wintun), "\n") + "\n"
}

// normalizeNewlines renders the vendor's carriage returns for a terminal. The stored
// copy keeps them, because that file is compared against the vendor's archive; what is
// printed does not have to carry them into someone's scrollback.
func normalizeNewlines(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}
