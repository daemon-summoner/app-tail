// SPDX-License-Identifier: MIT

package hostnet

import (
	"fmt"
	"strings"
)

// wintunDLL is the driver front end the interface mode loads at run time on Windows. It is
// not linked into the binary and cannot be: it ships as a signed DLL from its own vendor,
// which is the only form its licence permits anyone to distribute.
const wintunDLL = "wintun.dll"

// wintunSHA256 is the SHA-256 of each architecture's wintun.dll in the Wintun release that
// scripts/windows.sh pins (WINTUN_VERSION and WINTUN_ZIP_SHA256 there). The build script
// reads these values back out of this file and refuses to ship a DLL that does not match,
// so the two cannot drift apart.
//
// The interface mode loads this DLL into a process holding administrator rights, so the
// file has to be the one this build was released with, not whatever sits at its path:
// anything able to write that folder could otherwise run its own code as Administrator.
// The keys are GOARCH names; Wintun's own folder for 386 is called x86.
var wintunSHA256 = map[string]string{
	"amd64": "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
	"arm64": "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
	"386":   "d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931",
	"arm":   "daad267411ecdc70a0535e274d2c3e9da3d0084bdac7662cb8424dd4a031b4d9",
}

// CheckWintunPin reports whether a wintun.dll hashing to sum is the release pinned for the
// architecture goarch, and says why not when it is not: what was expected, what was found,
// and how to put the right file in place.
func CheckWintunPin(goarch, sum string) error {
	want, pinned := wintunSHA256[goarch]
	if !pinned {
		return fmt.Errorf("this build has no pinned %s for the %s architecture, so it refuses to load one", wintunDLL, goarch)
	}
	if !strings.EqualFold(sum, want) {
		return fmt.Errorf("%s is not the copy this app-tail release ships: its SHA-256 is %s, expected %s. "+
			"Something replaced it, and it is not loaded into a process with administrator rights. Unpack the "+
			"release archive again and run `app-tail install` from it, which puts app-tail and the right %s "+
			"where only administrators can change them", wintunDLL, strings.ToLower(sum), want, wintunDLL)
	}
	return nil
}
