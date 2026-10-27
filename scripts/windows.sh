#!/usr/bin/env bash
# Windows cross-build and install helpers, shared by release.sh and
# build_install.sh. Sourced, never executed directly.

# WINTUN_VERSION is the Wintun release the Windows builds ship. It is pinned rather
# than tracked: the licence grants rights over "the precise contents" of one download,
# and internal/licenses/WINTUN_LICENSE.txt is that download's notice.
WINTUN_VERSION="0.14.1"
# The SHA-256 of the published archive. Wintun is a driver front end fetched over the
# network at build time, so it is verified against a value in this repository rather
# than trusted because the download succeeded.
WINTUN_ZIP_SHA256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
WINTUN_LICENSE="$REPO_ROOT/internal/licenses/WINTUN_LICENSE.txt"

# sha256_of prints one file's SHA-256, using whichever of the two tools is installed.
sha256_of() {
	if have shasum; then
		shasum -a 256 "$1" | cut -d' ' -f1
	elif have sha256sum; then
		sha256sum "$1" | cut -d' ' -f1
	else
		return 1
	fi
}

# is_wsl reports whether this Linux is a Windows Subsystem for Linux distribution.
is_wsl() {
	[ -n "${WSL_DISTRO_NAME:-}" ] && return 0
	[ -r /proc/sys/kernel/osrelease ] &&
		grep -qiE 'microsoft|wsl' /proc/sys/kernel/osrelease
}

# build_windows_exes cross-compiles the .exe pair into the two paths named: one console
# build and one that opens no console window. Both carry the tray -- someone starting
# the agent from cmd.exe should still get a notification-area icon.
#
# It owns the EXIT trap for its duration. There is no linker flag for a Windows icon:
# go build embeds a .syso it finds in the main package's directory, so the object has to
# sit in the repo root across both builds, and the trap is what removes it when one fails.
build_windows_exes() {
	local console="$1" gui="$2" ldflags="$3"
	local syso="$REPO_ROOT/rsrc_windows_amd64.syso"
	trap 'rm -f "$REPO_ROOT/rsrc_windows_amd64.syso"' EXIT
	# The version rides along in the resource block: the Details tab, and every scanner's
	# first look at an unsigned .exe, read it from there.
	(cd "$REPO_ROOT" && go run ./internal/icon/gen syso "$syso" "$APPTAIL_VERSION") ||
		fail "rendering the Windows resource object failed"

	(cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
		go build -trimpath -ldflags "$ldflags" -o "$console" .) ||
		fail "windows/amd64 build failed"
	# -H=windowsgui suppresses the console window the agent opens, and with it every
	# subcommand's output: the process has no console to write to. Neither binary can
	# be both an agent you start from Explorer and a CLI you run in cmd.exe, so both ship.
	(cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
		go build -trimpath -ldflags "$ldflags -H=windowsgui" -o "$gui" .) ||
		fail "windows/amd64 gui build failed"
	rm -f "$syso"
	trap - EXIT
}

# install_wintun puts the driver front end and its licence in the directory named.
#
# It is not linked in and cannot be: it ships as a signed DLL from WireGuard LLC, whose
# terms permit redistribution only alongside software that uses it through its published
# API -- which is what app-tail does -- and only unmodified, with its notice intact. So
# the archive it comes from is verified by checksum and its contents copied untouched.
#
#   APPTAIL_WINTUN_ZIP   a wintun-$WINTUN_VERSION.zip already on disk, for an offline
#                        or air-gapped build. Checked against the same SHA-256.
install_wintun() {
	local dest="$1" zip="${APPTAIL_WINTUN_ZIP:-}" work
	work="$dest/.wintun"
	mkdir -p "$dest" || fail "could not create $dest"
	rm -rf "$work"
	mkdir -p "$work"

	if [ -n "$zip" ]; then
		[ -f "$zip" ] || fail "APPTAIL_WINTUN_ZIP points at $zip, which is not a file"
		cp "$zip" "$work/wintun.zip" || fail "could not read $zip"
	else
		have curl || fail "curl is required to fetch wintun; install it, or set APPTAIL_WINTUN_ZIP to a local copy"
		curl -fsSL --retry 3 -o "$work/wintun.zip" \
			"https://www.wintun.net/builds/wintun-$WINTUN_VERSION.zip" ||
			fail "could not download wintun $WINTUN_VERSION from wintun.net"
	fi

	local got
	got="$(sha256_of "$work/wintun.zip")" || fail "no sha256 tool available to verify the wintun archive"
	[ "$got" = "$WINTUN_ZIP_SHA256" ] ||
		fail "the wintun archive hashes to $got, not the pinned $WINTUN_ZIP_SHA256; it is not the release this repo carries a notice for"

	have unzip || fail "unzip is required to unpack the wintun archive"
	unzip -q -o "$work/wintun.zip" -d "$work" || fail "could not unpack the wintun archive"

	# The notice in this repo is what `app-tail licenses` prints. If it ever disagrees
	# with the archive being shipped, the binary is telling users the wrong terms.
	cmp -s "$work/wintun/LICENSE.txt" "$WINTUN_LICENSE" ||
		fail "internal/licenses/WINTUN_LICENSE.txt does not match wintun $WINTUN_VERSION; update it in the same commit as WINTUN_VERSION"

	# The agent refuses to load any wintun.dll but the one internal/hostnet/wintun.go pins, so
	# a DLL that disagrees with that value would ship a network-interface mode that never starts.
	assert_wintun_pinned "$work/wintun/bin/amd64/wintun.dll" amd64
	install -m 0644 "$work/wintun/bin/amd64/wintun.dll" "$dest/wintun.dll" ||
		fail "could not place wintun.dll beside the binaries"
	install -m 0644 "$WINTUN_LICENSE" "$dest/WINTUN-LICENSE.txt" ||
		fail "could not place the wintun notice beside the binaries"
	rm -rf "$work"
	info "wintun.dll $WINTUN_VERSION + WINTUN-LICENSE.txt"
}

# WINTUN_PIN_SOURCE is the Go file holding the SHA-256 the agent requires of each
# architecture's wintun.dll before it loads one.
WINTUN_PIN_SOURCE="$REPO_ROOT/internal/hostnet/wintun.go"

# wintun_pinned_sha256 prints the SHA-256 the agent pins for one GOARCH's wintun.dll, read
# out of the Go source so the build and the binary are checking against the same value.
wintun_pinned_sha256() {
	local arch="$1" pin
	pin="$(sed -nE "s/^[[:space:]]*\"$arch\":[[:space:]]*\"([0-9a-f]{64})\",?\$/\\1/p" "$WINTUN_PIN_SOURCE")"
	[ -n "$pin" ] || return 1
	printf '%s' "$pin"
}

# assert_wintun_pinned refuses a wintun.dll the agent would refuse to load.
assert_wintun_pinned() {
	local dll="$1" arch="$2" want got
	want="$(wintun_pinned_sha256 "$arch")" ||
		fail "$WINTUN_PIN_SOURCE has no wintun.dll pin for $arch"
	got="$(sha256_of "$dll")" || fail "no sha256 tool available to verify $dll"
	[ "$got" = "$want" ] ||
		fail "$dll hashes to $got, but $WINTUN_PIN_SOURCE pins $want for $arch; update the pin in the same commit as WINTUN_VERSION"
}

# from_windows_path prints a path Windows gave as one this shell can use.
from_windows_path() {
	if have wslpath; then
		wslpath -u "$1"
	else
		printf '%s' "${1//\\//}"
	fi
}

# windows_folder prints one of Windows' own folders, named as [Environment]::GetFolderPath
# names it, as a path this shell can write to.
windows_folder() {
	local win
	have powershell.exe || return 1
	win="$(powershell.exe -NoProfile -NonInteractive \
		-Command "[Environment]::GetFolderPath('$1')" 2>/dev/null | tr -d '\r')"
	[ -n "$win" ] || return 1
	from_windows_path "$win"
}

# windows_desktop prints the Desktop of the user whose session this is. Windows is asked for
# it rather than assembling %USERPROFILE%\Desktop, because OneDrive redirects the folder and
# the assembled path is then one nobody sees.
windows_desktop() {
	windows_folder Desktop
}

# windows_temp prints this Windows account's temporary folder as a path this shell can write
# to. It is asked of .NET, which reads %TEMP% the way every Windows program does.
windows_temp() {
	local win
	have powershell.exe || return 1
	win="$(powershell.exe -NoProfile -NonInteractive \
		-Command '[System.IO.Path]::GetTempPath()' 2>/dev/null | tr -d '\r')"
	[ -n "$win" ] || return 1
	from_windows_path "$win"
}

# to_windows_path prints the argument in the form a Windows program takes.
to_windows_path() {
	if have wslpath; then
		wslpath -w "$1"
	else
		printf '%s' "$1"
	fi
}

# WINDOWS_STOP_TIMEOUT_SEC bounds the wait for a running copy to go. Its shutdown puts
# back what it changed on this machine -- the resolver override, the interface -- and some
# of that is network state that takes a moment, so this is generous rather than snappy.
WINDOWS_STOP_TIMEOUT_SEC=15

# windows_task_list prints the running image names, once.
#
# Every call crosses into Windows, which costs far more than the poll interval below, so
# the whole list is fetched in one call and both binaries are read out of it rather than
# asking per image per turn.
#
# tasklist is asked rather than reading taskkill's exit status, which is non-zero both for
# a process that is not there and for one this account may not signal. An elevated app-tail
# is the second, and reading the two alike reports "nothing was running" for a copy that is
# running and holding its own .exe open -- a locked file the copy below then fails on,
# after the other .exe has already been replaced.
windows_task_list() {
	tasklist.exe /NH /FO CSV 2>/dev/null | tr -d '\r'
}

# windows_running_images prints which of app-tail's two image names appear in a listing.
windows_running_images() {
	local listing="$1" image
	for image in "$BIN_NAME.exe" "$BIN_NAME-gui.exe"; do
		if printf '%s\n' "$listing" | grep -qiF "\"$image\""; then
			printf '%s\n' "$image"
		fi
	done
}

# windows_exes_gone waits for both image names to leave the task list, and reports whether
# they did. The deadline is wall-clock rather than a count of turns: a turn here is one
# Windows process launch, whose cost is neither fixed nor small, so counting them would
# make the timeout mean whatever the interop happened to cost that day.
windows_exes_gone() {
	local deadline=$((SECONDS + WINDOWS_STOP_TIMEOUT_SEC))
	while true; do
		if [ -z "$(windows_running_images "$(windows_task_list)")" ]; then
			return 0
		fi
		if [ "$SECONDS" -ge "$deadline" ]; then
			return 1
		fi
		sleep 1
	done
}

# stop_windows_exe closes the installed .exe files by name, which is why the install gives
# them stable ones: the version is in the artifact's filename and would not match here.
#
# It refuses rather than reports when a copy will not go: Windows holds a running .exe
# open, so continuing would replace one of the pair and fail on the other, leaving two
# binaries from different builds in one folder.
stop_windows_exe() {
	if ! have taskkill.exe || ! have tasklist.exe; then
		na "taskkill.exe or tasklist.exe is not reachable, so a running app-tail cannot be stopped"
		return 0
	fi
	local image
	local -a running=()
	while IFS= read -r image; do
		[ -n "$image" ] && running+=("$image")
	done < <(windows_running_images "$(windows_task_list)")
	if [ ${#running[@]} -eq 0 ]; then
		info "nothing was running"
		return 0
	fi
	info "stopping ${running[*]}"

	# No /F first: that closes the window, which is the tray agent's own shutdown and the
	# only path that puts back what it changed on this machine.
	#
	# Each round waits only when something was actually asked to close: a taskkill that was
	# refused delivered nothing, and waiting on it would spend the whole timeout -- twice,
	# across the two rounds -- before saying what is in the way.
	local asked=0
	for image in "${running[@]}"; do
		if taskkill.exe /IM "$image" >/dev/null 2>&1; then
			asked=1
		fi
	done
	if [ "$asked" = 1 ] && windows_exes_gone; then
		info "stopped the running app-tail"
		return 0
	fi

	local forced=0
	for image in "${running[@]}"; do
		if taskkill.exe /IM "$image" /F >/dev/null 2>&1; then
			forced=1
		fi
	done
	if [ "$forced" = 1 ] && windows_exes_gone; then
		na "the running app-tail ignored the request to close and was stopped forcefully"
		return 0
	fi

	fail "app-tail is still running and this shell cannot stop it: ${running[*]}. An elevated copy cannot be signalled from an unelevated shell, which is what a machine using the network-interface mode is running. Quit it from the notification area, then run this again."
}

# WINDOWS_INSTALL_DIR is where install_windows_desktop put it, for callers to report.
export WINDOWS_INSTALL_DIR=""

# install_windows_desktop installs the pair, the driver front end and the notices on the
# Windows machine this shell belongs to, and restarts what was running.
#
# They go to Program Files\app-tail, through `app-tail.exe install` under an elevation
# prompt: app-tail elevates itself for the network-interface mode, and refuses to from a
# folder this account can write, where any program running as the same user could swap the
# .exe or plant a wintun.dll beside it and be started as Administrator.
#
#   APPTAIL_WINDOWS_DESKTOP_INSTALL=1   development only: install to a folder on the desktop
#                                       instead, with no prompt. The agent there runs the
#                                       network-interface mode only when started with
#                                       --allow-unprotected-elevation.
install_windows_desktop() {
	local console="$1" gui="$2" dll="$3" dll_license="$4" notices="$5"
	[ -f "$console" ] || fail "there is no $console to install"
	[ -f "$gui" ] || fail "there is no $gui to install"
	assert_wintun_pinned "$dll" amd64

	stop_windows_exe
	if [ "${APPTAIL_WINDOWS_DESKTOP_INSTALL:-0}" = "1" ]; then
		install_windows_to_desktop "$console" "$gui" "$dll" "$dll_license" "$notices"
	else
		install_windows_to_program_files "$console" "$gui" "$dll" "$dll_license" "$notices"
	fi
	info "$WINDOWS_INSTALL_DIR"

	if [ "${APPTAIL_NO_RESTART:-0}" = "1" ]; then
		na "APPTAIL_NO_RESTART=1: not launching it"
		return 0
	fi
	have powershell.exe || fail "powershell.exe is not reachable, so the .exe cannot be launched"
	local launch
	launch="$(to_windows_path "$WINDOWS_INSTALL_DIR/$BIN_NAME-gui.exe")"
	# Single quotes survive a path with spaces in it, which Program Files and OneDrive's
	# desktop both have; a quote inside the path itself is doubled, which is how PowerShell
	# escapes one.
	powershell.exe -NoProfile -NonInteractive \
		-Command "Start-Process -FilePath '${launch//\'/\'\'}'" ||
		fail "could not launch $launch"
	info "launched it; the icon is in the notification area"
}

# stage_windows_files copies the five files into the folder named, under the names they are
# installed with.
stage_windows_files() {
	local dest="$1" console="$2" gui="$3" dll="$4" dll_license="$5" notices="$6"
	mkdir -p "$dest" || fail "could not create $dest"
	install -m 0755 "$console" "$dest/$BIN_NAME.exe" || fail "could not install $BIN_NAME.exe into $dest"
	install -m 0755 "$gui" "$dest/$BIN_NAME-gui.exe" || fail "could not install $BIN_NAME-gui.exe into $dest"
	install -m 0644 "$dll" "$dest/wintun.dll" || fail "could not install wintun.dll into $dest"
	install -m 0644 "$dll_license" "$dest/WINTUN-LICENSE.txt" || fail "could not install WINTUN-LICENSE.txt into $dest"
	install -m 0644 "$notices" "$dest/THIRD_PARTY_LICENSES.txt" || fail "could not install THIRD_PARTY_LICENSES.txt into $dest"
}

# install_windows_to_desktop is the development install: a folder on the desktop, which
# this account can write and the agent therefore will not elevate from by default.
install_windows_to_desktop() {
	local desktop
	desktop="$(windows_desktop)" ||
		fail "could not ask Windows where the desktop is; is powershell.exe on PATH?"
	[ -d "$desktop" ] || fail "Windows named $desktop as the desktop, which is not a directory"

	# A folder rather than loose files on the desktop, because wintun.dll has to sit beside
	# the .exe -- the network-interface mode loads it from there and nowhere else.
	stage_windows_files "$desktop/$BIN_NAME" "$@"
	WINDOWS_INSTALL_DIR="$desktop/$BIN_NAME"
	na "APPTAIL_WINDOWS_DESKTOP_INSTALL=1: installed where this account can write; the network-interface mode starts there only with --allow-unprotected-elevation"
}

# install_windows_to_program_files stages the files in this account's temporary folder and
# has the staged app-tail.exe install itself from there, elevated.
#
# Staged rather than run from the build output, which under WSL is a \\wsl.localhost path an
# elevated process may not be able to reach. `app-tail install` copies, checks each copy
# against what it read, and narrows the folder to the administrators; its window closes when
# it finishes, so the result is read back here from the installed files.
install_windows_to_program_files() {
	have powershell.exe || fail "powershell.exe is not reachable, so app-tail cannot be installed under Program Files"
	local temp program_files stage dest exe
	temp="$(windows_temp)" || fail "could not ask Windows where this account's temporary folder is"
	program_files="$(windows_folder ProgramFiles)" || fail "could not ask Windows where Program Files is"
	[ -d "$program_files" ] || fail "Windows named $program_files as Program Files, which is not a directory"
	stage="$temp/$BIN_NAME-install-$$"
	dest="$program_files/$BIN_NAME"

	rm -rf "$stage"
	stage_windows_files "$stage" "$@"
	exe="$(to_windows_path "$stage/$BIN_NAME.exe")"
	info "approve the administrator prompt to install into Program Files"
	# -Wait holds this shell until the elevated install exits, and its exit code is carried
	# back as PowerShell's own. A declined prompt is an error from Start-Process itself.
	if ! powershell.exe -NoProfile -NonInteractive -Command \
		"\$p = Start-Process -FilePath '${exe//\'/\'\'}' -ArgumentList 'install' -Verb RunAs -Wait -PassThru; exit \$p.ExitCode"; then
		fail "app-tail install did not finish, so nothing was installed under Program Files. To read why, run it in a terminal opened with \"Run as administrator\": \"$exe\" install -- or set APPTAIL_WINDOWS_DESKTOP_INSTALL=1 for a development install on the desktop"
	fi

	local name
	for name in "$BIN_NAME.exe" "$BIN_NAME-gui.exe" wintun.dll WINTUN-LICENSE.txt THIRD_PARTY_LICENSES.txt; do
		[ -f "$dest/$name" ] || fail "app-tail install reported success but $dest/$name is not there"
		[ "$(sha256_of "$dest/$name")" = "$(sha256_of "$stage/$name")" ] ||
			fail "$dest/$name does not match the file that was built"
	done
	rm -rf "$stage"
	WINDOWS_INSTALL_DIR="$dest"
}
