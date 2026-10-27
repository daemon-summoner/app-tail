#!/usr/bin/env bash
# Resolves the one build identity every script and the binary agree on.
# Sourced by scripts/lib.sh, never executed directly.
# Override any field by exporting it before sourcing (CI passes APPTAIL_VERSION).

# APPTAIL_DATE is the COMMIT's time, never the build's: two builds of the same
# commit must produce identical binaries or `cmp` cannot verify a release.
APPTAIL_COMMIT="${APPTAIL_COMMIT:-$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)}"
APPTAIL_DATE="${APPTAIL_DATE:-$(git -C "$REPO_ROOT" show -s --format=%cI HEAD 2>/dev/null || echo unknown)}"

if [ -z "${APPTAIL_VERSION:-}" ]; then
	# An exact tag names a release; otherwise git describe appends the distance and
	# commit, and a repo with no tags at all falls back to the bare commit.
	# --abbrev=12 matches internal/buildinfo's own short-commit length, so an untagged
	# build's version and its commit are the same string and String() prints it once.
	APPTAIL_VERSION="$(git -C "$REPO_ROOT" describe --tags --always --abbrev=12 --dirty=+dirty 2>/dev/null || echo dev)"
fi

# A dirty tree has to be visible in the version even when --dirty did not apply,
# which happens when describe fell through to the plain commit.
if [ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ] &&
	[ "${APPTAIL_VERSION%+dirty}" = "$APPTAIL_VERSION" ]; then
	APPTAIL_VERSION="${APPTAIL_VERSION}+dirty"
fi

# CFBundleShortVersionString accepts only one to three dot-separated integers, so
# this is sanitized unconditionally: an untagged build must still produce a bundle
# macOS will launch, not an Info.plist that fails plutil.
apptail_plist_short() {
	local v="${APPTAIL_VERSION#v}"
	v="${v%%[-+]*}"
	# Two or three dot-separated integers and nothing else. The dot is required so a
	# bare commit cannot read as a version -- an all-digit hash like 2777559 would
	# otherwise sail through as a plausible-looking release number.
	if [[ "$v" =~ ^[0-9]+(\.[0-9]+){1,2}$ ]]; then
		printf '%s' "$v"
	else
		printf '0.0.0'
	fi
}
APPTAIL_PLIST_SHORT="${APPTAIL_PLIST_SHORT:-$(apptail_plist_short)}"

# CFBundleVersion is the build identifier and may carry the full string, which is
# where the commit stays visible for a bundle built off a tag.
APPTAIL_PLIST_BUILD="${APPTAIL_PLIST_BUILD:-$APPTAIL_VERSION}"

export APPTAIL_VERSION APPTAIL_COMMIT APPTAIL_DATE APPTAIL_PLIST_SHORT APPTAIL_PLIST_BUILD

# version_ldflags prints the -ldflags value that stamps internal/buildinfo. Callers
# add their own flags (-s -w) around it.
version_ldflags() {
	printf -- '-X %s.version=%s -X %s.commit=%s -X %s.date=%s' \
		"$BUILDINFO_PKG" "$APPTAIL_VERSION" \
		"$BUILDINFO_PKG" "$APPTAIL_COMMIT" \
		"$BUILDINFO_PKG" "$APPTAIL_DATE"
}
