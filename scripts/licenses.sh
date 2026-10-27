#!/usr/bin/env bash
# Regenerate internal/licenses/THIRD_PARTY_LICENSES.txt from the module cache.
# Usage: scripts/licenses.sh [--check]   (--check fails instead of writing)

# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

cd "$REPO_ROOT" || fail "cannot enter repo root $REPO_ROOT"

MODE="write"
[ "${1:-}" = "--check" ] && MODE="check"

OUT_FILE="$REPO_ROOT/internal/licenses/THIRD_PARTY_LICENSES.txt"
MAIN_MODULE="$(go list -m)"

# Shipping a statically linked binary to anyone is distribution, and every module in
# it carries a notice requirement. The dependency set differs per target -- wintun is
# Windows-only, godbus is Linux-only -- so the notice is the union, not one platform's
# view, or the Windows build would ship without wintun's notice.
collect_modules() {
	local target goos goarch
	for target in "darwin/arm64" "darwin/amd64" "linux/amd64" "linux/arm64" "windows/amd64"; do
		goos="${target%%/*}"
		goarch="${target##*/}"
		GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go list -deps -tags notray \
			-f '{{if .Module}}{{if not .Module.Main}}{{.Module.Path}}	{{.Module.Version}}	{{.Module.Dir}}{{end}}{{end}}' . ||
			fail "go list failed for $target"
	done
	# The tray build pulls cgo-only dependencies the notray builds never see. The target is
	# named rather than read from the host: a union that depended on which machine ran this
	# could not be checked in, because the check would then fail everywhere else.
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go list -deps \
		-f '{{if .Module}}{{if not .Module.Main}}{{.Module.Path}}	{{.Module.Version}}	{{.Module.Dir}}{{end}}{{end}}' . ||
		fail "go list failed for the tray build"
}

# Module authors do not agree on a filename, so the names are discovered rather than
# listed: a fixed list silently ships one notice per module and drops the rest, and
# several modules carry more than one -- modernc.org/sqlite blesses the amalgamation in
# LICENSE-SQLITE, modernc.org/libc credits its upstreams in LICENSE-3RD-PARTY.md. The
# prefixes below are the whole rule; .go is excluded so a module with a license.go
# source file does not have it pasted in as a notice. Sorted, because this file is
# byte-compared by --check and a directory's natural order is not stable across hosts.
# A module with no license file at all is a hard failure: shipping it without its
# notice is the exact thing this script exists to prevent.
find_license_files() {
	local dir="$1" f found=()
	for f in "$dir"/*; do
		[ -f "$f" ] || continue
		case "$(basename "$f" | tr '[:lower:]' '[:upper:]')" in
		*.GO) ;;
		LICENSE* | LICENCE* | COPYING* | NOTICE*) found+=("$f") ;;
		esac
	done
	[ ${#found[@]} -eq 0 ] || printf '%s\n' "${found[@]}" | LC_ALL=C sort
}

step "Collecting modules across every release target"
MODULES="$(collect_modules | sort -u)"
[ -n "$MODULES" ] || fail "no third-party modules found; go list produced nothing"
info "$(printf '%s\n' "$MODULES" | wc -l | tr -d ' ') modules"

TMP="$(mktemp "${TMPDIR:-/tmp}/app-tail-licenses.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

{
	printf 'Third-party licenses for %s\n' "$MAIN_MODULE"
	printf '\n'
	printf 'This binary statically links the Go modules listed below and embeds the dashboard\n'
	printf 'bundle, whose notices close the file. Each module and its full license text\n'
	printf 'follow. Regenerate with scripts/licenses.sh.\n'
	printf '\n'
	printf '%s\n' "$MODULES" | while IFS=$'\t' read -r path version _; do
		printf '  %s %s\n' "$path" "$version"
	done
} >"$TMP"

MISSING=""
while IFS=$'\t' read -r path version dir; do
	[ -n "$path" ] || continue
	[ -d "$dir" ] || fail "module $path@$version is not in the module cache; run: go mod download"

	files="$(find_license_files "$dir")"
	if [ -z "$files" ]; then
		MISSING="${MISSING}${MISSING:+$'\n'}  $path@$version ($dir)"
		continue
	fi

	{
		printf '\n\n'
		printf '================================================================================\n'
		printf '%s %s\n' "$path" "$version"
		printf '================================================================================\n\n'
	} >>"$TMP"
	printf '%s\n' "$files" | while read -r f; do
		[ -n "$f" ] || continue
		{
			printf -- '--- %s ---\n\n' "$(basename "$f")"
			cat "$f"
			printf '\n'
		} >>"$TMP"
	done
done <<<"$MODULES"

[ -z "$MISSING" ] || fail "no license file found for:"$'\n'"$MISSING"

# The dashboard bundle is embedded in the same binary (ui/ui.go), and its typefaces and
# packages carry notice requirements of their own that no Go module covers. ui/ keeps
# them in one file, maintained by hand beside package.json, and it ships here in full.
UI_NOTICES="$REPO_ROOT/ui/THIRD_PARTY_NOTICES.md"
[ -f "$UI_NOTICES" ] || fail "$UI_NOTICES is missing; the dashboard bundle's notices ship in this file"
{
	printf '\n\n'
	printf '================================================================================\n'
	printf 'dashboard bundle (ui/dist)\n'
	printf '================================================================================\n\n'
	printf -- '--- THIRD_PARTY_NOTICES.md ---\n\n'
	cat "$UI_NOTICES"
} >>"$TMP"

mkdir -p "$(dirname "$OUT_FILE")"
if [ "$MODE" = "check" ]; then
	if [ ! -f "$OUT_FILE" ]; then
		fail "$OUT_FILE does not exist; run: scripts/licenses.sh"
	fi
	cmp -s "$TMP" "$OUT_FILE" ||
		fail "third-party notices are stale; run: scripts/licenses.sh, then commit $OUT_FILE"
	step "LICENSES: up to date"
else
	cp "$TMP" "$OUT_FILE"
	step "Wrote $OUT_FILE"
	info "$(wc -l <"$OUT_FILE" | tr -d ' ') lines"
fi
