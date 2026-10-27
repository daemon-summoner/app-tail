#!/usr/bin/env bash
# Shared helpers for the root script quartet. Sourced, never executed directly.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export REPO_ROOT
# Windows will not execute an extension-less PE, so the name the scripts build and the
# name they later run have to carry GOEXE. go env is the authority rather than uname:
# the same Git Bash shell can host either GOOS.
BIN_EXE="$(go env GOEXE 2>/dev/null || true)"
export BIN_NAME="app-tail$BIN_EXE"
export BIN_PATH="$REPO_ROOT/$BIN_NAME"
export UI_DIR="$REPO_ROOT/ui"
export UI_DIST="$UI_DIR/dist"
export DEV_UI_ADDR="127.0.0.1:8377"
export BUILDINFO_PKG="github.com/sellitus/app-tail/internal/buildinfo"

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
na() { printf '    \033[33mN/A -- %s\033[0m\n' "$*"; }
fail() {
	printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2
	exit 1
}

# `go install` puts tools here and nothing else adds it to PATH, so the gate would
# report golangci-lint and govulncheck as absent on a machine that has both.
PATH="$PATH:$(go env GOPATH 2>/dev/null)/bin"
export PATH

have() { command -v "$1" >/dev/null 2>&1; }

# shellcheck source=scripts/version.sh
source "$REPO_ROOT/scripts/version.sh"

# ui_packages_stale reports whether ui/node_modules needs (re)installing: it is
# missing, or the lockfile is newer than the manifest npm writes on every install.
# A directory-exists check alone leaves a dependency added by a git pull
# uninstalled, and the build then fails on an import of a package the lockfile
# already carries.
ui_packages_stale() {
	local installed="$UI_DIR/node_modules/.package-lock.json"
	[ -d "$UI_DIR/node_modules" ] || return 0
	[ -f "$installed" ] || return 0
	[ "$UI_DIR/package-lock.json" -nt "$installed" ]
}

# install_ui_packages installs exactly the lockfile. npm install would resolve
# fresh and rewrite it, so a local build could ship different dependency versions
# than the Dockerfile, which installs from the lockfile.
install_ui_packages() {
	if [ -f "$UI_DIR/package-lock.json" ]; then
		(cd "$UI_DIR" && npm ci)
	else
		(cd "$UI_DIR" && npm install)
	fi
}

# Build the SPA into ui/dist. The Go binary embeds that directory, so it must
# exist before any go build/test of the ui package.
build_ui() {
	if ! have npm; then
		na "npm not installed; cannot build UI"
		return 1
	fi
	if ui_packages_stale; then
		step "Installing UI dependencies"
		install_ui_packages || return 1
	fi
	step "Building UI"
	(cd "$UI_DIR" && npm run build)
}

# Build the UI only when dist is missing or older than any source file.
build_ui_if_stale() {
	if [ -f "$UI_DIST/index.html" ]; then
		local newer
		# public/ counts: vite copies it into dist verbatim, so the generated favicon
		# is a build input like any source file. So do tsconfig.json and the lockfile:
		# `npm run build` type-checks before it bundles and installs from the lockfile,
		# and a dist left stale by either one means the Go suite embeds a dashboard that
		# no longer exists in source.
		newer=$(find "$UI_DIR/src" "$UI_DIR/public" "$UI_DIR/index.html" "$UI_DIR/vite.config.ts" \
			"$UI_DIR/package.json" "$UI_DIR/tsconfig.json" "$UI_DIR/package-lock.json" \
			-newer "$UI_DIST/index.html" 2>/dev/null | head -1)
		if [ -z "$newer" ]; then
			info "UI up to date"
			return 0
		fi
	fi
	build_ui
}

build_binary() {
	step "Building $BIN_NAME $APPTAIL_VERSION"
	# -trimpath keeps absolute build paths out of the binary, which is what lets two
	# builds of the same commit on different machines compare equal.
	# Linux builds static: the root helper accepts callers running this same file, and a
	# dynamically linked one would let any program inject code through LD_PRELOAD, so the
	# helper refuses to start from it. macOS needs cgo for the tray.
	local cgo
	cgo="$(go env CGO_ENABLED)"
	if [ "$(go env GOOS)" = linux ]; then
		cgo=0
	fi
	(cd "$REPO_ROOT" && CGO_ENABLED="$cgo" go build -trimpath -ldflags "$(version_ldflags)" -o "$BIN_PATH" .)
	info "$BIN_PATH"
}
