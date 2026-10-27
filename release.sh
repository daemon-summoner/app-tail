#!/usr/bin/env bash
# Build signed, checksummed release artifacts into dist/: a universal macOS .app with
# the menu-bar tray, Windows console and GUI .exe files, and Linux binaries.
# With no target it builds what this machine runs, installs it where the desktop looks
# for it, and restarts the copy that was already running.
# Usage: ./release.sh [--skip-tests] [macos|windows|linux ...]   (no target = this machine)
# The APPTAIL_* overrides are documented at the line that reads each one.

# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/scripts/lib.sh"
# shellcheck source=scripts/windows.sh
source "$(dirname "$0")/scripts/windows.sh"

cd "$REPO_ROOT" || fail "cannot enter repo root $REPO_ROOT"

# scripts/version.sh (via lib.sh) resolves APPTAIL_VERSION and friends.
VERSION="$APPTAIL_VERSION"
LDFLAGS="-s -w $(version_ldflags)"
OUT="$REPO_ROOT/dist"
NOTICES="$REPO_ROOT/internal/licenses/THIRD_PARTY_LICENSES.txt"

# The version reaches artifact filenames, where a tag is far freer than a filename
# may be, so everything outside the portable set folds to a dash.
SLUG="$(printf '%s' "$VERSION" | tr -c 'A-Za-z0-9._-' '-')"

# Each builder appends what it produced. The SBOM reads the module list back out of
# these, so it describes the shipped artifacts rather than the tree beside them.
BINARIES=()

# sign_macos_app applies a Developer ID when one is configured and an ad-hoc signature
# otherwise. Ad-hoc is not a trust statement -- Gatekeeper still quarantines the
# download -- but lipo strips signatures and macOS refuses to start an unsigned arm64
# binary at all, so it is what makes the universal .app launchable.
sign_macos_app() {
	local app="$1" identity="${APPTAIL_CODESIGN_IDENTITY:-}"
	if [ -n "$identity" ]; then
		codesign --force --options runtime --timestamp --sign "$identity" "$app" ||
			fail "codesign with $identity failed"
		info "signed with $identity (hardened runtime)"
	else
		codesign --force --options runtime --sign - "$app" || fail "ad-hoc codesign failed"
		info "ad-hoc signed with hardened runtime; set APPTAIL_CODESIGN_IDENTITY for a Developer ID"
	fi
	codesign --verify --strict "$app" || fail "the signature on $app did not verify"
}

# ditto rather than zip: it preserves the extended attributes and symlinks a signed
# bundle carries, which zip drops and which notarization then rejects.
archive_macos_app() {
	local app="$1" archive="$2"
	rm -f "$archive"
	ditto -c -k --sequesterRsrc --keepParent "$app" "$archive" ||
		fail "ditto failed to archive $app"
}

# notarize_macos_app submits the archive to Apple, staples the ticket into the bundle,
# and rebuilds the archive so the download carries it. Unconfigured it is a no-op seam:
# adding notarization later is a credential change, not a restructure.
notarize_macos_app() {
	local app="$1" archive="$2" profile="${APPTAIL_NOTARY_PROFILE:-}"
	if [ -z "$profile" ]; then
		na "not notarized (APPTAIL_NOTARY_PROFILE unset); macOS quarantines the download -- README carries the xattr workaround"
		return 0
	fi
	# Apple rejects ad-hoc signatures outright, so the credential that would produce
	# one is a configuration error rather than something to discover at submit time.
	[ -n "${APPTAIL_CODESIGN_IDENTITY:-}" ] ||
		fail "APPTAIL_NOTARY_PROFILE is set but APPTAIL_CODESIGN_IDENTITY is not; Apple will not notarize an ad-hoc signature"
	have xcrun || fail "xcrun is required to notarize; install the Xcode command line tools"
	xcrun notarytool submit "$archive" --keychain-profile "$profile" --wait ||
		fail "notarization failed"
	xcrun stapler staple "$app" || fail "stapling the notarization ticket failed"
	archive_macos_app "$app" "$archive"
	info "notarized, stapled and re-archived"
}

# install_macos_icon renders the .iconset from internal/icon and compiles it into the
# App-Tail.icns that Info.plist's CFBundleIconFile names. Both halves are required: a
# bundle with the key and no file, or the file and no key, shows the generic icon.
install_macos_icon() {
	local app="$1" work="$OUT/.iconset" iconset renderings
	have iconutil || fail "iconutil is required to build the app icon; install the Xcode command line tools"
	rm -rf "$work"
	iconset="$(go run ./internal/icon/gen iconset "$work")" || fail "rendering the .iconset failed"
	renderings="$(find "$iconset" -maxdepth 1 -name '*.png' | wc -l | tr -d ' ')"
	iconutil -c icns "$iconset" -o "$app/Contents/Resources/App-Tail.icns" ||
		fail "iconutil could not compile $iconset"
	rm -rf "$work"
	info "App-Tail.icns ($renderings renderings)"
}

# release_macos builds a universal (arm64 + amd64) binary with the native menu-bar
# tray, wraps it in a menu-bar-only .app, signs it and archives it.
release_macos() {
	if [ "$(go env GOOS)" != "darwin" ]; then
		na "not on macOS; skipping the .app build (the tray needs the macOS SDK)"
		return 0
	fi
	step "macOS universal .app (native menu-bar tray)"
	local arm="$OUT/.arm64" amd="$OUT/.amd64" universal="$OUT/.app-tail"
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CC="clang -arch arm64" \
		go build -trimpath -ldflags "$LDFLAGS" -o "$arm" . || fail "darwin/arm64 build failed"
	if CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 CC="clang -arch x86_64" \
		go build -trimpath -ldflags "$LDFLAGS" -o "$amd" .; then
		lipo -create -output "$universal" "$arm" "$amd" || fail "lipo failed to fuse the two arches"
		info "universal binary (arm64 + amd64)"
	else
		# A file named universal that holds one arch starts on no Intel Mac. Opting into
		# that is fine; degrading into it on a broken toolchain is how it reaches someone.
		[ "${APPTAIL_ALLOW_SINGLE_ARCH:-0}" = "1" ] ||
			fail "the darwin/amd64 cgo build failed, so the .app would be arm64-only; fix the toolchain, or set APPTAIL_ALLOW_SINGLE_ARCH=1 to ship it anyway"
		na "APPTAIL_ALLOW_SINGLE_ARCH=1: shipping arm64-only"
		mv "$arm" "$universal"
	fi
	rm -f "$arm" "$amd"

	local app="$OUT/App-Tail.app"
	mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
	cat >"$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>            <string>App-Tail</string>
    <key>CFBundleDisplayName</key>     <string>App-Tail</string>
    <key>CFBundleIdentifier</key>      <string>com.sellitus.app-tail</string>
    <key>CFBundleExecutable</key>      <string>app-tail</string>
    <key>CFBundleIconFile</key>        <string>App-Tail</string>
    <key>CFBundlePackageType</key>     <string>APPL</string>
    <key>CFBundleShortVersionString</key> <string>${APPTAIL_PLIST_SHORT}</string>
    <key>CFBundleVersion</key>         <string>${APPTAIL_PLIST_BUILD}</string>
    <key>LSUIElement</key>             <true/>
    <key>LSMinimumSystemVersion</key>  <string>11.0</string>
</dict>
</plist>
PLIST
	install -m 0755 "$universal" "$app/Contents/MacOS/$BIN_NAME"
	# The .app is what most people keep; the loose copy beside it is what they delete.
	install -m 0644 "$NOTICES" "$app/Contents/Resources/THIRD_PARTY_LICENSES.txt"
	install_macos_icon "$app"
	rm -f "$universal"
	BINARIES+=("$app/Contents/MacOS/$BIN_NAME")

	# Signing comes after the bundle is assembled: it covers Info.plist and Resources,
	# so writing either afterwards invalidates it.
	sign_macos_app "$app"

	local archive="$OUT/app-tail-$SLUG-darwin-universal.zip"
	archive_macos_app "$app" "$archive"
	notarize_macos_app "$app" "$archive"
	info "App-Tail.app + $(basename "$archive")"
}

# sign_windows_exe applies an Authenticode signature when one is configured.
#
# Unconfigured it is a loud no-op seam, mirroring the macOS path: adding signing later
# is a credential change rather than a restructure. Unlike macOS there is no ad-hoc
# fallback -- Authenticode has no such thing, and an unsigned .exe next to a
# driver-adjacent DLL is what SmartScreen exists to shout about.
#
#   APPTAIL_WINDOWS_SIGN_PFX     path to a PKCS#12 certificate
#   APPTAIL_WINDOWS_SIGN_PASS    its password, empty when it has none
#   APPTAIL_WINDOWS_SIGN_TS      RFC 3161 timestamp URL (default: DigiCert's)
sign_windows_exe() {
	local exe="$1" pfx="${APPTAIL_WINDOWS_SIGN_PFX:-}"
	if [ -z "$pfx" ]; then
		na "$(basename "$exe") is not signed (APPTAIL_WINDOWS_SIGN_PFX unset); SmartScreen warns on the download"
		return 0
	fi
	[ -f "$pfx" ] || fail "APPTAIL_WINDOWS_SIGN_PFX points at $pfx, which is not a file"
	have osslsigncode ||
		fail "osslsigncode is required to sign Windows binaries; install it, or unset APPTAIL_WINDOWS_SIGN_PFX to ship unsigned"

	# osslsigncode cannot sign in place: it reads one file and writes another.
	local signed="$exe.signed"
	osslsigncode sign \
		-pkcs12 "$pfx" -pass "${APPTAIL_WINDOWS_SIGN_PASS:-}" \
		-n "app-tail" -i "https://github.com/sellitus/app-tail" \
		-ts "${APPTAIL_WINDOWS_SIGN_TS:-http://timestamp.digicert.com}" \
		-in "$exe" -out "$signed" ||
		fail "signing $(basename "$exe") failed"
	mv "$signed" "$exe" || fail "could not replace $(basename "$exe") with its signed copy"
	# A signature that does not verify is worse than none: it ships looking trusted and
	# is rejected on the machine it lands on.
	osslsigncode verify -in "$exe" >/dev/null ||
		fail "the signature on $(basename "$exe") did not verify"
	info "signed $(basename "$exe")"
}

# release_windows cross-compiles the .exe pair: one console build and one that opens
# no console window. Both carry the tray -- someone starting the agent from cmd.exe
# should still get a notification-area icon.
release_windows() {
	step "Windows amd64 (console + GUI .exe, with tray)"
	local console="$OUT/app-tail-$SLUG-windows-amd64.exe"
	local gui="$OUT/app-tail-$SLUG-windows-amd64-gui.exe"

	build_windows_exes "$console" "$gui" "$LDFLAGS"
	BINARIES+=("$console" "$gui")
	info "$(basename "$console") (agent + CLI)"
	info "$(basename "$gui") (agent only, no console window)"

	# Signing comes after both builds and before the SBOM reads them back: a signature
	# appends to the file, so anything that rewrites it afterwards invalidates it.
	sign_windows_exe "$console"
	sign_windows_exe "$gui"
	install_wintun "$OUT"
	archive_windows "$console" "$gui"
}

# archive_windows packs the download Windows users actually take: both .exe files with
# wintun.dll and its notice beside them.
#
# The DLL is loaded from the folder holding the .exe and nowhere else, so an archive that
# separated them would produce the one failure this app cannot recover from on its own --
# a network-interface mode that reports a missing driver on a machine where the file was
# downloaded and left in another folder. The loose files stay in dist/ as well, for anyone
# updating one .exe in place.
archive_windows() {
	local console="$1" gui="$2"
	local archive="$OUT/app-tail-$SLUG-windows-amd64.zip"
	have zip || fail "zip is required to build the Windows archive; install it"
	rm -f "$archive"
	# -j because the archive is a flat folder: everything in it has to end up in the same
	# directory for wintun.dll to be found.
	zip -j -q "$archive" "$console" "$gui" "$OUT/wintun.dll" "$OUT/WINTUN-LICENSE.txt" "$NOTICES" ||
		fail "could not build $archive"
	info "$(basename "$archive") (both .exe files + wintun.dll)"
}

# release_linux cross-compiles dashboard-only binaries for the two common arches. The
# tray would build, but it needs a desktop session with a DBus StatusNotifier host,
# which the servers and containers this target is for do not have.
release_linux() {
	step "Linux amd64 + arm64 (dashboard-only)"
	local arch out
	for arch in amd64 arm64; do
		out="$OUT/app-tail-$SLUG-linux-$arch"
		CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
			go build -trimpath -tags notray -ldflags "$LDFLAGS" -o "$out" . ||
			fail "linux/$arch build failed"
		BINARIES+=("$out")
		info "$(basename "$out")"
	done
}

# host_target names the release target this machine runs. WSL is Linux to the Go
# toolchain, but the desktop around it is Windows and a Linux build has nowhere to appear
# there, so it resolves to windows.
host_target() {
	case "$(go env GOOS)" in
	darwin) printf 'macos' ;;
	windows) printf 'windows' ;;
	linux) if is_wsl; then printf 'windows'; else printf 'linux'; fi ;;
	*) return 1 ;;
	esac
}

# INSTALLED is where the install put it, for the closing summary to name.
INSTALLED=""

# stop_unix asks a running app-tail to quit and waits for it. SIGTERM rather than a kill:
# the agent writes its settings out on the way down, and a copy that was killed mid-write
# is what the next start reads.
stop_unix() {
	if ! pkill -x "$BIN_NAME" 2>/dev/null; then
		info "nothing was running"
		return 0
	fi
	local waited=0
	while pgrep -x "$BIN_NAME" >/dev/null 2>&1 && [ "$waited" -lt 50 ]; do
		sleep 0.1
		waited=$((waited + 1))
	done
	if pgrep -x "$BIN_NAME" >/dev/null 2>&1; then
		pkill -9 -x "$BIN_NAME" 2>/dev/null || true
		na "the running $BIN_NAME ignored SIGTERM and was killed"
	else
		info "stopped the running $BIN_NAME"
	fi
}

# start_detached launches the agent and lets go of it, so it outlives this script.
start_detached() {
	local bin="$1" log="$2"
	if have setsid; then
		setsid "$bin" >>"$log" 2>&1 &
	else
		nohup "$bin" >>"$log" 2>&1 &
	fi
	disown 2>/dev/null || true
	info "started $bin (output in $log)"
}

# report_macos_helper says a privileged helper is about to stop matching the build being
# installed, so the password dialog that follows is expected rather than alarming.
#
# The helper is a separate root binary outside the bundle, so installing a new .app leaves
# the old one in place, and it takes commands only from the build it was installed for.
# Nothing here fixes that: this script never asks for a password. The app does, as it
# starts, and replacing it is the one machine fault it repairs unasked -- so this is a
# report and not an instruction. Left unsaid, a release ends with a system authorization
# prompt appearing for no visible reason.
report_macos_helper() {
	local bin="$1" report problem
	# A binary that cannot report on the machine it was just installed on is worth saying
	# out loud: it is the copy about to be launched, and silence here is indistinguishable
	# from a clean answer.
	if ! report="$("$bin" tun doctor -json 2>&1)"; then
		na "the installed app could not report on this machine: $(printf '%s' "$report" | head -n 1)"
		return 0
	fi

	# Structural fields rather than the free text beside them: a helper this platform
	# wants, that is installed, and that does not answer, is wrong however it got there.
	case "$report" in *'"design": true'*) ;; *) return 0 ;; esac
	case "$report" in *'"installed": true'*) ;; *) return 0 ;; esac
	case "$report" in
	*'"running": false'*) ;;
	*)
		info "the privileged helper answers this build"
		return 0
		;;
	esac

	problem=""
	have jq && problem="$(printf '%s' "$report" | jq -r '.helper.problem // ""')"
	[ -n "$problem" ] || problem="the installed privileged helper does not answer this build"
	na "$problem"
	info "app-tail asks for your password as it starts and replaces it; until then this"
	info "machine runs in the contained mode, where tailnet names do not resolve"
}

install_macos_app() {
	local app="$OUT/App-Tail.app" dest="/Applications/App-Tail.app"
	[ -d "$app" ] || fail "there is no App-Tail.app in dist to install"
	# Writing /Applications needs no password for an admin user and this script must never
	# ask for one, so an unwritable directory is reported with the command to run by hand.
	[ -w /Applications ] ||
		fail "/Applications is not writable by $(id -un); install it by hand with: sudo ditto '$app' '$dest'"

	stop_unix
	rm -rf "$dest" || fail "could not remove the previous $dest"
	# ditto rather than cp -R: it keeps the extended attributes the signature covers, which
	# cp drops and Gatekeeper then refuses to launch.
	ditto "$app" "$dest" || fail "could not copy the bundle to $dest"
	INSTALLED="$dest"
	info "$dest"

	# Asked of the copy just installed, which is the build the helper is about to be
	# compared against. Asking the one on PATH would compare against whatever
	# build_install.sh last put there, which is routinely an older build.
	report_macos_helper "$dest/Contents/MacOS/$BIN_NAME"

	if [ "${APPTAIL_NO_RESTART:-0}" = "1" ]; then
		na "APPTAIL_NO_RESTART=1: not launching it"
		return 0
	fi
	open "$dest" || fail "could not launch $dest"
	info "launched it; the icon is in the menu bar"
}

install_linux_home() {
	local dest="$HOME/app-tail" arch bin
	arch="$(go env GOARCH)"
	bin="$OUT/app-tail-$SLUG-linux-$arch"
	[ -f "$bin" ] || fail "this machine is linux/$arch and dist carries no binary for it"

	stop_unix
	mkdir -p "$dest" || fail "could not create $dest"
	# The installed copy carries the plain name: a login item and a shell alias outlive the
	# version that is in the artifact's filename.
	install -m 0755 "$bin" "$dest/$BIN_NAME" || fail "could not install into $dest"
	install -m 0644 "$NOTICES" "$dest/THIRD_PARTY_LICENSES.txt"
	INSTALLED="$dest/$BIN_NAME"
	info "$INSTALLED"

	if [ "${APPTAIL_NO_RESTART:-0}" = "1" ]; then
		na "APPTAIL_NO_RESTART=1: not launching it"
		return 0
	fi
	start_detached "$dest/$BIN_NAME" "$dest/$BIN_NAME.log"
}

# install_release_windows hands the shared installer what this release built.
install_release_windows() {
	install_windows_desktop \
		"$OUT/app-tail-$SLUG-windows-amd64.exe" \
		"$OUT/app-tail-$SLUG-windows-amd64-gui.exe" \
		"$OUT/wintun.dll" "$OUT/WINTUN-LICENSE.txt" "$NOTICES"
	INSTALLED="$WINDOWS_INSTALL_DIR"
}

# install_host puts the build where this machine's desktop looks for it and restarts it.
install_host() {
	case "$HOST_TARGET" in
	macos) install_macos_app ;;
	windows) install_release_windows ;;
	linux) install_linux_home ;;
	esac
}

HOST_TARGET="$(host_target)" ||
	fail "$(go env GOOS) is not a platform this script builds for (want: darwin, linux, windows)"

# --skip-tests leaves the suite out of the ship gate below; every other check in it
# still runs. It sets the variable verify.sh reads, so the two ways in behave alike.
targets=()
for arg in "$@"; do
	case "$arg" in
	--skip-tests) APPTAIL_SKIP_TESTS=1 ;;
	-*) fail "unknown option $arg (want: --skip-tests)" ;;
	macos | windows | linux) targets+=("$arg") ;;
	*) fail "unknown target $arg (want: macos, windows, linux)" ;;
	esac
done
export APPTAIL_SKIP_TESTS="${APPTAIL_SKIP_TESTS:-0}"
[ ${#targets[@]} -eq 0 ] && targets=("$HOST_TARGET")

# Installing is for the target this machine can actually run. A cross-build that never
# names it -- `./release.sh windows` on a Mac -- produces artifacts and touches nothing.
install_wanted=0
if [ "${APPTAIL_NO_INSTALL:-0}" != "1" ]; then
	for t in "${targets[@]}"; do
		if [ "$t" = "$HOST_TARGET" ]; then
			install_wanted=1
		fi
	done
fi

step "Preflight"

# A release names a commit. Work that is not in that commit cannot be checked out
# again, so an artifact built from it claims to be something that does not exist.
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
	[ "${APPTAIL_ALLOW_DIRTY:-0}" = "1" ] ||
		fail "the working tree is dirty; commit it first, or set APPTAIL_ALLOW_DIRTY=1 to ship a +dirty build"
	na "APPTAIL_ALLOW_DIRTY=1: building from a dirty tree"
fi

# Untagged, the version is a bare commit: nothing a colleague can name, compare, or
# find in the CHANGELOG.
if ! git describe --tags --exact-match HEAD >/dev/null 2>&1; then
	[ "${APPTAIL_ALLOW_UNTAGGED:-0}" = "1" ] ||
		fail "HEAD carries no tag; tag the release first, or set APPTAIL_ALLOW_UNTAGGED=1 to ship an untagged build"
	na "APPTAIL_ALLOW_UNTAGGED=1: building an untagged release"
fi
info "version $VERSION"

# Every binary below embeds these notices, so a stale file ships wrong attribution.
# Deliberately outside APPTAIL_SKIP_VERIFY: that skips a gate that ran elsewhere, and
# this is the one obligation distribution itself creates.
"$REPO_ROOT/scripts/licenses.sh" --check || fail "third-party notices are stale; nothing was released"

if [ "${APPTAIL_SKIP_VERIFY:-0}" = "1" ]; then
	na "APPTAIL_SKIP_VERIFY=1: skipping the ship gate (CI runs verify.sh as its own job)"
else
	step "Ship gate"
	# Named here as well as inside the gate: which checks ran is a property of the
	# artifacts, and this output is what accompanies them.
	if [ "$APPTAIL_SKIP_TESTS" = "1" ]; then
		na "--skip-tests: the suite is left out; every other gate still runs"
	fi
	"$REPO_ROOT/verify.sh" || fail "verify.sh failed; nothing was released"
fi

build_ui

rm -rf "$OUT"
mkdir -p "$OUT"
step "Releasing app-tail ${VERSION} -> dist/"

for t in "${targets[@]}"; do
	case "$t" in
	macos) release_macos ;;
	windows) release_windows ;;
	linux) release_linux ;;
	esac
done

[ ${#BINARIES[@]} -gt 0 ] || fail "no binaries were produced for targets: ${targets[*]}"

step "Third-party notices"
install -m 0644 "$NOTICES" "$OUT/THIRD_PARTY_LICENSES.txt"
info "THIRD_PARTY_LICENSES.txt ($(wc -l <"$NOTICES" | tr -d ' ') lines)"

step "SBOM"
MODULES="$OUT/app-tail-$SLUG-modules.txt"
if have syft; then
	syft scan "dir:$REPO_ROOT" -o "spdx-json=$OUT/app-tail-$SLUG-sbom.spdx.json" ||
		fail "syft failed to produce an SBOM"
	info "app-tail-$SLUG-sbom.spdx.json"
else
	na "syft not installed; shipping the go module manifest alone"
fi
# Emitted with or without syft. It needs no tool beyond the Go toolchain and it reads
# the module set out of each shipped binary, so it cannot disagree with what was built.
: >"$MODULES"
for b in "${BINARIES[@]}"; do
	{
		printf '=== %s ===\n' "$(basename "$b")"
		go version -m "$b" || fail "go version -m could not read $b"
		printf '\n'
	} >>"$MODULES"
done
info "$(basename "$MODULES")"

step "Checksums (dist/SHA256SUMS.txt)"
(
	cd "$OUT" || fail "cannot enter output dir $OUT"
	# Glob rather than find -printf, which is GNU-only. The .app is a directory and is
	# skipped by the -f test; its archive carries the checksum instead.
	artifacts=()
	for f in *; do
		[ -f "$f" ] && [ "$f" != "SHA256SUMS.txt" ] && artifacts+=("$f")
	done
	if [ ${#artifacts[@]} -eq 0 ]; then
		na "no file artifacts to checksum"
	elif have shasum; then
		shasum -a 256 "${artifacts[@]}" >SHA256SUMS.txt
		info "wrote SHA256SUMS.txt"
	elif have sha256sum; then
		sha256sum "${artifacts[@]}" >SHA256SUMS.txt
		info "wrote SHA256SUMS.txt"
	else
		na "no sha256 tool found"
	fi
)

step "Artifacts"
find "$OUT" -maxdepth 1 -mindepth 1 ! -name '.*' -exec du -sh {} \; 2>/dev/null | sort -k2

if [ "$install_wanted" = "1" ]; then
	step "Installing the $HOST_TARGET build"
	install_host
else
	na "nothing installed: no target here is what this machine runs ($HOST_TARGET)"
fi

if [ -n "$INSTALLED" ]; then
	cat <<INSTALLED_NOTES

    Installed to $INSTALLED
    The notes below are for the copies in dist/, which are what you hand to somebody else.
INSTALLED_NOTES
fi

cat <<NOTES

    macOS:   unzip app-tail-$SLUG-darwin-universal.zip, then drag App-Tail.app to
             /Applications. It is not notarized, so the first launch needs:
                 xattr -d com.apple.quarantine /Applications/App-Tail.app
    Windows: run app-tail-$SLUG-windows-amd64-gui.exe for the agent with no console
             window, or ...-windows-amd64.exe when you also want the CLI. Then
             "app-tail-$SLUG-windows-amd64.exe install-autostart" to start it at login.
             Keep wintun.dll in the same folder as the .exe: the network-interface
             mode loads it from there, and nothing else needs it. Its terms are in
             WINTUN-LICENSE.txt.
    Linux:   chmod +x app-tail-$SLUG-linux-amd64 && ./app-tail-$SLUG-linux-amd64
             Then "install-autostart" for a login item.

    Verify a download against dist/SHA256SUMS.txt. THIRD_PARTY_LICENSES.txt ships
    beside the binaries, inside App-Tail.app, and behind "app-tail licenses".
NOTES

step "RELEASE: PASS"
