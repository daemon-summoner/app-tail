// SPDX-License-Identifier: MIT

// Package buildinfo resolves the one build identity the whole binary reports.
//
// It lives outside main so the CLI and the API can read the commit and date
// without main having to thread them through, and so the fallback chain below is
// testable on its own.
package buildinfo

import (
	"runtime/debug"
	"strings"
)

// These are set at link time by scripts/version.sh via -ldflags. An unlinked build
// (go build, go test, go run) leaves them empty and falls back to the module's own
// recorded VCS stamps, so `go install ...@v0.1.0` still reports v0.1.0.
var (
	version string
	commit  string
	date    string
)

// Unknown is what every field reports when nothing could be resolved. It reads as
// a word rather than an empty string so a missing stamp shows up in a bug report
// instead of rendering as a blank.
const Unknown = "dev"

// Info is the resolved build identity.
type Info struct {
	// Version is a release tag when one exists, otherwise a VCS-derived string.
	Version string
	// Commit is the full revision the binary was built from, "dev" when unknown.
	Commit string
	// Date is the commit's timestamp in RFC 3339, not the time of the build: two
	// builds of the same commit must agree, or the binaries are not reproducible.
	Date string
	// Dirty reports that the working tree had uncommitted changes at build time.
	Dirty bool
}

// String renders the identity for `app-tail version` and the dashboard header.
func (i Info) String() string {
	s := i.Version
	if i.Dirty {
		s += " (dirty)"
	}
	// An untagged build's version already is the short commit; appending it again
	// would render "fedcba987654 fedcba987654".
	if short := shortCommit(i.Commit); i.Commit != Unknown && !strings.Contains(i.Version, short) {
		s += " " + short
	}
	if i.Date != Unknown {
		s += " " + i.Date
	}
	return s
}

func shortCommit(commit string) string {
	const short = 12
	if len(commit) > short {
		return commit[:short]
	}
	return commit
}

// Get resolves the build identity.
func Get() Info { return resolve(debug.ReadBuildInfo) }

// resolve takes its build-info source as a parameter so the fallback chain can be
// exercised against each stage without linking a binary per case.
func resolve(read func() (*debug.BuildInfo, bool)) Info {
	info := Info{Version: version, Commit: commit, Date: date}

	bi, ok := read()
	if ok {
		// A module built by `go install pkg@v1.2.3` records that tag here, which is
		// what makes an unlinked install self-versioning.
		if info.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			info.Version = bi.Main.Version
		}
		for _, setting := range bi.Settings {
			switch setting.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = setting.Value
				}
			case "vcs.time":
				if info.Date == "" {
					info.Date = setting.Value
				}
			case "vcs.modified":
				info.Dirty = setting.Value == "true"
			}
		}
		if info.Version == "" && info.Commit != "" {
			info.Version = shortCommit(info.Commit)
		}
	}

	if info.Version == "" {
		info.Version = Unknown
	}
	if info.Commit == "" {
		info.Commit = Unknown
	}
	if info.Date == "" {
		info.Date = Unknown
	}
	if strings.HasSuffix(info.Version, "+dirty") {
		info.Version = strings.TrimSuffix(info.Version, "+dirty")
		info.Dirty = true
	}
	return info
}
