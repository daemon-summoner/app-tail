#!/usr/bin/env bash
# Ship gate: formatting, dependency integrity, the full test suite, linters, vulnerability
# and secret scans, builds for every release target, and a real-binary smoke test.
# Usage: ./verify.sh

# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/scripts/lib.sh"

cd "$REPO_ROOT"

step "gofmt"
UNFORMATTED=$(gofmt -l . 2>/dev/null || true)
[ -z "$UNFORMATTED" ] || fail "unformatted files:"$'\n'"$UNFORMATTED"
info "clean"

step "Dependency integrity"
# A go.mod that tidy would rewrite means the checked-in requirements do not match
# what the code imports, so a fresh clone can resolve different versions.
cp go.mod go.mod.gatebak
cp go.sum go.sum.gatebak
restore_gomod() {
	if [ -f go.mod.gatebak ]; then mv go.mod.gatebak go.mod; fi
	if [ -f go.sum.gatebak ]; then mv go.sum.gatebak go.sum; fi
	return 0
}
trap restore_gomod EXIT
go mod tidy || fail "go mod tidy failed"
DRIFT=""
cmp -s go.mod go.mod.gatebak || DRIFT="go.mod"
cmp -s go.sum go.sum.gatebak || DRIFT="${DRIFT:+$DRIFT and }go.sum"
restore_gomod
trap - EXIT
[ -z "$DRIFT" ] || fail "$DRIFT is stale; run: go mod tidy, then commit the result"
go mod verify >/dev/null || fail "module checksums do not match go.sum"
info "tidy and verified"

step "Third-party notices"
# internal/licenses embeds this file into every binary, so a dependency added without
# regenerating it ships attribution that omits the new module.
"$REPO_ROOT/scripts/licenses.sh" --check >/dev/null || fail "third-party notices are stale; run: scripts/licenses.sh"
info "up to date"

step "UI toolchain"
# The ship gate is the one place a missing frontend toolchain is a failure rather
# than a skip: without it the embedded dashboard is whatever was last built, and
# the linters and tests below cover nothing.
have npm || fail "npm is required by the ship gate; install Node, or use ./test.sh for the inner loop"
if ui_packages_stale; then
	install_ui_packages || fail "UI package install failed"
fi
info "present"

build_ui_if_stale || fail "UI build is required before go build/test (ui embeds ui/dist)"

# Runs the whole suite -- Go with -race, the UI typecheck and the UI tests. Without
# this the gate would pass on a red build.
#
#   APPTAIL_SKIP_TESTS=1   run every other check and leave the suite out, for a build
#                          whose tests already passed elsewhere. Every gate below still
#                          runs, so the artifacts remain linted, scanned and smoke-tested.
if [ "${APPTAIL_SKIP_TESTS:-0}" = "1" ]; then
	step "Test suite"
	na "APPTAIL_SKIP_TESTS=1: suite skipped"
	TESTS_SKIPPED=1
else
	"$REPO_ROOT/test.sh" || fail "test suite failed"
	TESTS_SKIPPED=0
fi

step "shellcheck"
if have shellcheck; then
	shellcheck -x -S style ./*.sh scripts/*.sh || fail "shellcheck reported findings"
	info "clean"
else
	na "shellcheck not installed"
fi

step "golangci-lint"
if have golangci-lint; then
	# Two passes: tray.go and tray_notray.go are mutually exclusive build-tag
	# alternatives, so one run only ever lints one of them.
	golangci-lint run ./... || fail "golangci-lint reported findings"
	golangci-lint run --build-tags notray ./... || fail "golangci-lint (notray) reported findings"
	info "clean (both build-tag sets)"
else
	na "golangci-lint not installed; run: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"
fi

step "UI lint"
(cd "$UI_DIR" && npm run lint) || fail "eslint reported findings"

step "UI colour tokens"
# Every colour belongs to ui/src/styles/tokens.css. A colour literal written into any
# other sheet, or into a component's inline style or SVG attribute, is a colour that
# cannot be re-themed and that no palette review would ever find, so it fails here
# rather than being discovered by a reader who wanted a light theme.
if have rg; then
	stray=$(rg -n --glob '*.css' --glob '*.tsx' --glob '!tokens.css' \
		'#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\(|oklch\(|color-mix\(' "$UI_DIR/src" || true)
	if [ -n "$stray" ]; then
		printf '%s\n' "$stray" >&2
		fail "colour literals outside ui/src/styles/tokens.css"
	fi
	info "all colours come from tokens.css"
else
	na "ripgrep not installed; cannot check for stray colour literals"
fi

step "govulncheck"
if have govulncheck; then
	govulncheck ./... || fail "known vulnerabilities in the dependency graph"
	info "no known vulnerabilities"
else
	na "govulncheck not installed; run: go install golang.org/x/vuln/cmd/govulncheck@latest"
fi

step "gitleaks"
if have gitleaks; then
	# Both modes: the working tree catches a secret staged right now, history catches
	# one that was committed and later deleted -- it stays in the objects either way.
	# The config is named rather than left to discovery so the allowlist in it applies
	# no matter where the scan is invoked from.
	gitleaks dir . -c .gitleaks.toml --no-banner || fail "gitleaks found secrets in the working tree"
	gitleaks git . -c .gitleaks.toml --no-banner || fail "gitleaks found secrets in the git history"
	info "clean (working tree and history)"
else
	na "gitleaks not installed"
fi

step "Cross-platform builds"
# Every target release.sh ships. The tray needs cgo on darwin; the notray tag is
# what server and cross builds use.
for target in "darwin/arm64" "darwin/amd64" "linux/amd64" "linux/arm64" "windows/amd64"; do
	goos="${target%%/*}"
	goarch="${target##*/}"
	GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -tags notray -o /dev/null . ||
		fail "build failed for $target (notray)"
	info "$target (notray) ok"
done
# Windows ships with the tray, and only systray's darwin backend needs cgo -- so this
# is the build the .exe pair actually is, and the one that would break on a change
# that reached for a platform API without a windows implementation.
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o /dev/null . ||
	fail "windows/amd64 build failed with the tray"
info "windows/amd64 (tray) ok"
# The Windows-only half of the session-end watch, tests included: go build leaves
# _windows_test.go files alone and vet does not.
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./internal/sessionend/... ||
	fail "the windows-only session-end code does not vet"
info "windows/amd64 session-end vet ok"
if [ "$(go env GOOS)" = "darwin" ]; then
	CGO_ENABLED=1 go build -trimpath -o /dev/null . || fail "native tray build failed"
	info "native tray build ok"
fi

build_binary

step "docs/cli.md command block"
# internal/cli/registry.go is the one place the command table lives, and the help
# overview is built from it. Diffing the document against the binary's own --help makes
# it a consumer of that table rather than a fourth hand-maintained copy.
DOC_CMDS="$(sed -n '/<!-- commands:begin -->/,/<!-- commands:end -->/p' docs/cli.md | grep '^  app-tail' || true)"
HELP_CMDS="$("$BIN_PATH" --help 2>&1 | sed -n '/^Usage:/,/^$/p' | grep '^  app-tail' || true)"
[ -n "$DOC_CMDS" ] || fail "no commands found between the commands:begin/end markers in docs/cli.md"
[ -n "$HELP_CMDS" ] || fail "could not read the command table out of $BIN_NAME --help"
if [ "$DOC_CMDS" != "$HELP_CMDS" ]; then
	fail "docs/cli.md is out of date with $BIN_NAME --help (< docs, > binary):"$'\n'"$(
		diff <(printf '%s\n' "$DOC_CMDS") <(printf '%s\n' "$HELP_CMDS") || true
	)"
fi
info "matches $BIN_NAME --help"

"$REPO_ROOT/scripts/smoke.sh"

step "Static integration scan"
SCANNER="$HOME/.claude/scripts/meow-verify.sh"
if [ -x "$SCANNER" ]; then
	# --full enumerates via `git ls-files`, so it scans nothing at all until there
	# is a commit. --diff also picks up untracked files, which is every file in a
	# repo with no history.
	if git rev-parse --verify HEAD >/dev/null 2>&1; then
		"$SCANNER" --full --strict || fail "meow-verify reported findings"
	else
		info "no commits yet: scanning tracked and untracked files via --diff"
		"$SCANNER" --diff --strict || fail "meow-verify reported findings"
	fi
else
	na "meow-verify.sh not installed"
fi

if [ "$TESTS_SKIPPED" = "1" ]; then
	step "VERIFY: PASS (tests skipped)"
else
	step "VERIFY: PASS"
fi
