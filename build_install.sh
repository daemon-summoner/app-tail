#!/usr/bin/env bash
# Build the UI + binary and install to a stable location (so login items keep working
# across rebuilds). macOS also gets a menu-bar-only .app wrapper; WSL builds the Windows
# .exe pair and installs it to the Windows desktop.
# Usage: ./build_install.sh

# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/scripts/lib.sh"
# shellcheck source=scripts/windows.sh
source "$(dirname "$0")/scripts/windows.sh"

cd "$REPO_ROOT"

INSTALL_DIR="${APPTAIL_INSTALL_DIR:-$HOME/.local/bin}"

# authorize_root asks for the password once, before anything is built, so the privileged
# step at the end never stops a finished build to ask for it -- and so the ask arrives while
# someone is still watching the terminal rather than several minutes after they walked away.
#
# macOS only: it is the one platform with a privileged helper to install. Declining is a
# loud skip rather than a failure, and leaves the build itself untouched.
authorize_root() {
	[ "$(uname -s)" = "Darwin" ] || return 0
	if ! have sudo; then
		na "no sudo on this machine; the privileged helper cannot be installed from here"
		return 0
	fi
	# Non-interactive callers -- CI, and the verification gates that run this script blind
	# -- must not meet a password prompt that would hang forever.
	if [ ! -t 0 ]; then
		na "not a terminal; skipping the password prompt"
		return 0
	fi
	step "Administrator rights"
	info "macOS asks for your password once here, because the privileged helper runs as root."
	if ! sudo -v; then
		na "administrator rights were declined; the privileged helper will not be installed"
		return 0
	fi
	SUDO_AUTHORIZED=yes

	# A cold build outruns sudo's grace period, so the authorization is renewed until this
	# script exits rather than expiring part way through and prompting a second time.
	while true; do
		sudo -n true 2>/dev/null || exit
		sleep 30
	done &
	SUDO_KEEPALIVE_PID=$!
	trap release_root EXIT
}

# release_root stops renewing the authorization. The grace period then lapses on its own,
# so nothing this script did leaves a shell able to run root commands without asking.
release_root() {
	[ -n "${SUDO_KEEPALIVE_PID:-}" ] || return 0
	kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
	SUDO_KEEPALIVE_PID=""
}

# sign_binary signs what was just built, before anything is copied from it.
#
# It runs here and not later because three things are made from this one file -- the command
# on PATH, the .app bundle, and the privileged helper, which is a copy of it running as root
# -- and the helper is reinstalled by comparing sha256 against this exact file. Signing after
# any of those copies would leave them on different bytes and the helper permanently "not this
# build".
#
# With a Developer ID configured this also turns on the hardened runtime, which is what stops
# another process running as this user from loading code into the agent -- the process the root
# helper takes its instructions from. Ad-hoc is the fallback rather than a trust statement:
# macOS refuses to start an unsigned arm64 binary at all, so something has to sign it.
sign_binary() {
	[ "$(uname -s)" = "Darwin" ] || return 0
	have codesign || {
		na "no codesign on this machine; the binary keeps whatever signature the linker gave it"
		return 0
	}
	local identity="${APPTAIL_CODESIGN_IDENTITY:-}"
	if [ -n "$identity" ]; then
		codesign --force --options runtime --timestamp --sign "$identity" "$BIN_PATH" ||
			fail "codesign with $identity failed"
		info "signed with $identity (hardened runtime)"
	else
		# Hardened runtime needs no Developer ID, and it is what refuses DYLD_INSERT_LIBRARIES
		# and a debugger attaching to the running agent.
		codesign --force --options runtime --sign - "$BIN_PATH" || fail "ad-hoc codesign failed"
		na "ad-hoc signed with hardened runtime; set APPTAIL_CODESIGN_IDENTITY for a Developer ID"
	fi
	codesign --verify --strict "$BIN_PATH" || fail "the signature on $BIN_PATH did not verify"
}

# install_wsl_windows builds the Windows app from a WSL distribution and puts it on the
# Windows desktop.
#
# WSL is Linux to the Go toolchain, but the desktop around it is Windows. A Linux build
# would install a binary whose TUN interface, resolver override and proxy settings apply
# to the WSL VM's own network namespace, where nothing on the Windows side is behind
# them -- so this machine gets the .exe pair release.sh already resolves it to.
install_wsl_windows() {
	local out="$REPO_ROOT/dist/wsl"
	step "Windows amd64 (console + GUI .exe, with tray)"
	info "WSL${WSL_DISTRO_NAME:+ ($WSL_DISTRO_NAME)} on Windows; a Linux build would not reach the Windows desktop"
	rm -rf "$out"
	mkdir -p "$out" || fail "could not create $out"
	build_windows_exes "$out/$BIN_NAME.exe" "$out/$BIN_NAME-gui.exe" "$(version_ldflags)"
	info "$BIN_NAME.exe (agent + CLI)"
	info "$BIN_NAME-gui.exe (agent only, no console window)"
	install_wintun "$out"

	step "Installing to the Windows desktop"
	install_windows_desktop "$out/$BIN_NAME.exe" "$out/$BIN_NAME-gui.exe" \
		"$out/wintun.dll" "$out/WINTUN-LICENSE.txt" \
		"$REPO_ROOT/internal/licenses/THIRD_PARTY_LICENSES.txt"
	info "Enable the login item from the dashboard, or with: $BIN_NAME.exe install-autostart"
}

authorize_root

build_ui

if is_wsl; then
	install_wsl_windows
	step "BUILD+INSTALL: PASS"
	exit 0
fi

build_binary
sign_binary

mkdir -p "$INSTALL_DIR"
install -m 0755 "$BIN_PATH" "$INSTALL_DIR/$BIN_NAME"
step "Installed $INSTALL_DIR/$BIN_NAME"

# A default shell often lacks ~/.local/bin on PATH, so `app-tail` would not resolve
# by name. Hint how to fix it rather than editing the user's profile for them.
case ":$PATH:" in
*":$INSTALL_DIR:"*)
	info "$INSTALL_DIR is on your PATH; run commands with: $BIN_NAME <command>"
	;;
*)
	info "$INSTALL_DIR is not on your PATH. To run app-tail by name, add it:"
	# fish has its own syntax and a dedicated command; the POSIX shells share one line.
	case "$(basename "${SHELL:-}")" in
	fish) info "  fish_add_path $INSTALL_DIR" ;;
	zsh) info "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> $HOME/.zshrc" ;;
	bash) info "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> $HOME/.bashrc" ;;
	*) info "  export PATH=\"$INSTALL_DIR:\$PATH\"   # add to your shell's startup file" ;;
	esac
	info "Then restart your shell. Until then: $INSTALL_DIR/$BIN_NAME <command>"
	;;
esac

# install_helper puts the privileged helper on this machine as a copy of the binary just
# built, whether one was there before or not.
#
# The helper is a copy of this binary running as root, so a rebuild leaves the two on
# different code with nothing to notice: within one commit they report the same version, and
# a released build only diverges once. The app refuses a mismatched helper and reinstalls it
# on its own, which needs the mode toggled; doing it here means the next run of the app is
# already right.
install_helper() {
	[ "$(uname -s)" = "Darwin" ] || return 0
	if [ "${SUDO_AUTHORIZED:-no}" != yes ]; then
		na "no administrator rights here; install the privileged helper with: sudo $INSTALL_DIR/$BIN_NAME tun install-helper"
		return 0
	fi
	if helper_is_this_build; then
		info "The privileged helper is already this build."
		return 0
	fi
	step "Installing the privileged helper"
	# The config is named here because sudo may hand the command root's home, and the
	# approvals --grant writes are computed from this account's config, not root's.
	local config="${APPTAIL_CONFIG:-${APPTAIL_STATE_DIR:-$HOME/Library/Application Support/app-tail}/config.json}"
	if [ -f "$config" ]; then
		sudo "$INSTALL_DIR/$BIN_NAME" tun install-helper --owner "$(id -u)" --grant --config "$config" ||
			fail "could not install the privileged helper"
	else
		sudo "$INSTALL_DIR/$BIN_NAME" tun install-helper --owner "$(id -u)" ||
			fail "could not install the privileged helper"
	fi
}

# helper_is_this_build reports whether the installed helper is already a copy of the binary
# just built, which is the one case where installing it again would change nothing. A
# machine that cannot answer the question is installed to rather than left as it is.
helper_is_this_build() {
	local installed="/Library/PrivilegedHelperTools/app-tail/app-tail-helper"
	[ -f "$installed" ] || return 1
	have shasum || return 1
	[ "$(shasum -a 256 "$installed" | cut -d' ' -f1)" = "$(shasum -a 256 "$BIN_PATH" | cut -d' ' -f1)" ]
}

# APP_RESTART_TIMEOUT_SEC bounds the wait for the old copy to stop. Its shutdown puts
# back everything it changed on this machine, and some of that is network state that
# takes a moment, so this is generous rather than snappy.
APP_RESTART_TIMEOUT_SEC=20

# refresh_installed_app replaces a copy of the .app already in /Applications, which is the
# one a user actually launches -- the freshly built bundle in the repo is not.
#
# Same drift as the privileged helper: without this a rebuild leaves the launched app on
# whatever code it was dragged over with, and nothing says so. The new bundle is staged
# beside it and renamed into place, because a copy written over the running app's own path
# would overwrite the executable of a live process. Only when one is already there: a
# machine that never installed the app is not given one now.
refresh_installed_app() {
	local name installed staged binary running
	name="$(basename "$APP_DIR")"
	installed="/Applications/$name"
	if [ ! -d "$installed" ]; then
		info "Drag it to /Applications, or run: open $APP_DIR"
		return 0
	fi
	binary="$installed/Contents/MacOS/$BIN_NAME"

	# Asked before the replacement, because afterwards a copy still running the old
	# executable is indistinguishable from one already running this build.
	running=no
	pgrep -f "$binary" >/dev/null 2>&1 && running=yes

	staged="/Applications/.$name.new"
	rm -rf "$staged"
	cp -R "$APP_DIR" "$staged" || fail "could not stage $installed (is /Applications writable?)"
	rm -rf "$installed"
	mv "$staged" "$installed" || fail "could not replace $installed"
	step "Replaced $installed with this build"

	# A running copy keeps serving the dashboard and the menu it started with, which looks
	# exactly like a build that changed nothing -- so it is restarted rather than reported.
	[ "$running" = yes ] || return 0
	step "Restarting App-Tail"
	info "The tailnet node reconnects and active forwards are interrupted briefly."

	local login_item=no
	login_item_runs "$binary" && login_item=yes
	# Unloading the job first stops launchd's KeepAlive from starting the old copy again
	# while the wait below is still watching for it to go.
	if [ "$login_item" = yes ] && launchctl print "$LAUNCH_AGENT_TARGET" >/dev/null 2>&1; then
		launchctl bootout "$LAUNCH_AGENT_TARGET" || fail "could not stop the $LAUNCH_AGENT_LABEL login item"
	fi
	# SIGTERM, never SIGKILL: the ordered shutdown is what puts back what the app changed
	# on this machine -- the resolver override, the proxy settings, the interface.
	pkill -f "$binary" || true
	local waited=0
	while pgrep -f "$binary" >/dev/null 2>&1; do
		if [ "$waited" -ge "$((APP_RESTART_TIMEOUT_SEC * 4))" ]; then
			fail "App-Tail did not stop within ${APP_RESTART_TIMEOUT_SEC}s; quit it from the menu bar, then: open $installed"
		fi
		sleep 0.25
		waited=$((waited + 1))
	done

	# Started through its login item, the agent runs in the launchd class that item asks
	# for; `open` would start it as a plain app outside the job, where that class never
	# applies. The item is rewritten first because launchd keeps the definition it loaded,
	# and one written by an older build asks for a class that throttles every connection.
	if [ "$login_item" = yes ]; then
		"$binary" install-autostart >/dev/null || fail "could not rewrite the $LAUNCH_AGENT_LABEL login item"
		launchctl bootstrap "gui/$(id -u)" "$LAUNCH_AGENT_PLIST" ||
			fail "could not start the $LAUNCH_AGENT_LABEL login item; run: open $installed"
		info "App-Tail is running this build, started through its login item."
		return 0
	fi
	open "$installed" || fail "could not launch $installed"
	info "App-Tail is running this build."
}

LAUNCH_AGENT_LABEL=com.sellitus.app-tail
LAUNCH_AGENT_PLIST="$HOME/Library/LaunchAgents/$LAUNCH_AGENT_LABEL.plist"
LAUNCH_AGENT_TARGET="gui/$(id -u)/$LAUNCH_AGENT_LABEL"

# login_item_runs reports whether this user's login item starts exactly this binary. One
# naming another copy of app-tail is left alone: restarting through it would swap which
# copy runs, and rewriting it would move the user's login item without being asked.
login_item_runs() {
	[ -f "$LAUNCH_AGENT_PLIST" ] || return 1
	local program
	program="$(plutil -extract ProgramArguments.0 raw -o - "$LAUNCH_AGENT_PLIST")" ||
		fail "could not read the program out of $LAUNCH_AGENT_PLIST"
	[ "$program" = "$1" ]
}

install_helper

case "$(uname -s)" in
Darwin)
	# LSUIElement keeps the menu-bar agent out of the Dock and app switcher.
	APP_DIR="$REPO_ROOT/App-Tail.app"
	rm -rf "$APP_DIR"
	mkdir -p "$APP_DIR/Contents/MacOS"
	cat >"$APP_DIR/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>            <string>App-Tail</string>
    <key>CFBundleDisplayName</key>     <string>App-Tail</string>
    <key>CFBundleIdentifier</key>      <string>com.sellitus.app-tail</string>
    <key>CFBundleExecutable</key>      <string>app-tail</string>
    <key>CFBundlePackageType</key>     <string>APPL</string>
    <key>CFBundleShortVersionString</key> <string>${APPTAIL_PLIST_SHORT}</string>
    <key>CFBundleVersion</key>         <string>${APPTAIL_PLIST_BUILD}</string>
    <key>LSUIElement</key>             <true/>
    <key>LSMinimumSystemVersion</key>  <string>11.0</string>
</dict>
</plist>
PLIST
	install -m 0755 "$BIN_PATH" "$APP_DIR/Contents/MacOS/$BIN_NAME"
	step "Built $APP_DIR (menu-bar only)"
	refresh_installed_app
	;;
Linux | *)
	info "Enable the login item with: $INSTALL_DIR/$BIN_NAME install-autostart"
	;;
esac

step "BUILD+INSTALL: PASS"
