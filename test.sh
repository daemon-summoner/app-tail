#!/usr/bin/env bash
# Run the full test suite. Builds the UI first because the ui package embeds ui/dist.
# Usage: ./test.sh

# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/scripts/lib.sh"

build_ui_if_stale || na "UI not built; ui package tests will fail if it is missing"

step "go test ./..."
cd "$REPO_ROOT"
# -race because the agent's lifecycle, its forward engine and the HTTP handlers all
# touch shared state from different goroutines; -shuffle because test order is not
# part of any contract and a suite that depends on it hides real coupling.
# -covermode=atomic is the mode -race requires.
# The package list is explicit because npm dependencies can ship Go files of their own
# (ui/node_modules/flatted carries a whole package), and ./... would pull third-party
# code nobody here reviews into -race and into the coverage denominator. .golangci.yml
# excludes the same directory for the same reason.
# Read into an array with a while loop rather than mapfile: macOS ships bash 3.2, which
# predates mapfile, and this script runs on the macos CI leg.
GO_PACKAGES=()
while IFS= read -r pkg; do GO_PACKAGES+=("$pkg"); done < <(go list ./... | grep -v '/ui/node_modules/')
[ ${#GO_PACKAGES[@]} -gt 0 ] || fail "go list produced no packages to test"
go test -race -shuffle=on -covermode=atomic -coverprofile=coverage.out "${GO_PACKAGES[@]}"

step "go test (notray)"
# release.sh ships -tags notray for the Linux targets, so the systray-free build is
# what anyone running this on a server actually runs. Without this step nothing ever
# compiles or exercises tray_notray.go.
go test -tags notray ./internal/tray/...

step "windows/amd64 tray compile"
# The Windows .exe files ship with the tray, and this is the only machine that ever
# builds them -- CI runs the tests on windows but release.sh cross-compiles from here.
# Only systray's darwin backend needs cgo, so the whole binary compiles for windows
# with cgo off; a tray change that reached for an API with no windows implementation
# would otherwise not surface until release day.
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o /dev/null . ||
	fail "the windows/amd64 build with the tray failed"
# go build does not typecheck _windows_test.go files, so a Windows-only test that no
# longer compiles would surface only on the windows runner. vet does look at them, and
# every package has some: the per-platform test fixtures live beside the tests they serve.
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./... ||
	fail "the windows-only code and tests do not vet"
info "ok"

# Reported, never gated. A threshold on an already well-tested codebase measures
# nothing and rewards assertion-free tests written to move the number.
step "Coverage"
info "$(go tool cover -func=coverage.out | tail -1)"

step "UI typecheck"
if have npm && [ -d "$UI_DIR/node_modules" ]; then
	(cd "$UI_DIR" && npm run typecheck)
else
	na "npm or node_modules missing"
fi

step "UI tests"
# Run under coverage for the same reason the Go suite is: the number is reported so a
# drop is visible, never gated.
if have npm && [ -d "$UI_DIR/node_modules" ]; then
	(cd "$UI_DIR" && npm run test:coverage)
else
	na "npm or node_modules missing"
fi

step "PASS"
