// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"

	"github.com/sellitus/app-tail/internal/icon"
)

// What the Details tab of the .exe's properties shows, and what an antivirus heuristic
// reads before it looks at anything else. An unsigned executable with no version block,
// no manifest and no company name is the shape a dropper has, and every scanner weights
// it accordingly; naming the product, the publisher and the licence costs nothing and
// removes that signal. The copyright line mirrors LICENSE, which the test pins.
const (
	companyName     = "sellitus"
	productName     = "app-tail"
	fileDescription = "app-tail network agent"
	legalCopyright  = "Copyright (c) 2026 sellitus"
	// assemblyName is the manifest's identity, in the publisher.product form Windows expects.
	assemblyName = "sellitus.app-tail"
)

// windowsResources assembles everything the .exe carries in its resource section: the
// icon, the version block and the application manifest, for the version string the build
// scripts resolved.
func windowsResources(ver string) (*winres.ResourceSet, error) {
	ico, err := buildIcon(icon.WindowsIconSizes())
	if err != nil {
		return nil, err
	}
	rs := &winres.ResourceSet{}
	// Explorer draws the lowest-numbered icon resource, so the mark takes ID 1.
	if err := rs.SetIcon(winres.ID(1), ico); err != nil {
		return nil, fmt.Errorf("add the icon resource: %w", err)
	}
	vi, err := versionInfo(ver)
	if err != nil {
		return nil, err
	}
	rs.SetVersionInfo(vi)
	rs.SetManifest(manifest(ver))
	return rs, nil
}

// versionInfo is the VS_VERSIONINFO block: the four-part numbers Windows compares, and
// the strings it displays. The full version string goes into the string table untouched,
// so a build off an untagged commit still names the commit it came from.
func versionInfo(ver string) (version.Info, error) {
	num := numericVersion(ver)
	vi := version.Info{FileVersion: num, ProductVersion: num, Type: version.App}
	// An exact tag is a release; anything else is a build between two of them.
	vi.Flags.Prerelease = !isReleaseTag(ver)
	for key, value := range map[string]string{
		version.CompanyName:      companyName,
		version.ProductName:      productName,
		version.FileDescription:  fileDescription,
		version.InternalName:     productName,
		version.OriginalFilename: productName + ".exe",
		version.LegalCopyright:   legalCopyright,
		version.FileVersion:      ver,
		version.ProductVersion:   ver,
	} {
		if err := vi.Set(version.LangDefault, key, value); err != nil {
			return version.Info{}, fmt.Errorf("set %s in the version resource: %w", key, err)
		}
	}
	return vi, nil
}

// manifest is the application manifest. Its purpose here is to be present: an .exe
// without one is run under Windows' installer-detection heuristics, which guess from
// the file name whether to demand elevation. AsInvoker says the process starts with the
// rights it was given -- app-tail asks for more itself, through the relaunch in
// internal/elevate, only when the stored settings need them.
func manifest(ver string) winres.AppManifest {
	return winres.AppManifest{
		Identity:       winres.AssemblyIdentity{Name: assemblyName, Version: numericVersion(ver)},
		Description:    fileDescription,
		Compatibility:  winres.Win10AndAbove,
		ExecutionLevel: winres.AsInvoker,
		DPIAwareness:   winres.DPIPerMonitorV2,
		LongPathAware:  true,
	}
}

// numericVersion is the four-part number a version string carries, or all zeros when it
// carries none. Only a tag of the form v1.2 or v1.2.3 counts, with the distance and
// commit git describe appends cut off: a bare commit such as 4233a6b98901 starts with
// digits and would otherwise become file version 4233.0.0.0. The rule is the one
// scripts/version.sh applies for CFBundleShortVersionString.
func numericVersion(ver string) [4]uint16 {
	num, _ := parseVersion(releaseCore(ver))
	return num
}

// isReleaseTag reports whether ver is an exact tag with nothing appended.
func isReleaseTag(ver string) bool {
	core := releaseCore(ver)
	_, ok := parseVersion(core)
	return ok && core == strings.TrimPrefix(ver, "v")
}

// parseVersion reads two or three dot-separated integers, each within what a version
// resource's 16-bit fields hold, and reports whether core had that form at all.
func parseVersion(core string) ([4]uint16, bool) {
	var out [4]uint16
	parts := strings.Split(core, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return out, false
	}
	for i, part := range parts {
		n, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			return [4]uint16{}, false
		}
		out[i] = uint16(n)
	}
	return out, true
}

// releaseCore strips the v prefix and everything from the first - or + on: the describe
// distance, the commit, and the +dirty marker.
func releaseCore(ver string) string {
	core := strings.TrimPrefix(ver, "v")
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	return core
}
