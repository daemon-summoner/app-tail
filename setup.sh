#!/usr/bin/env bash
# Install what this machine needs before app-tail is built and run: the Go and Node
# toolchains, the dashboard's packages, the gate's tools, and a root-owned openvpn for
# OpenVPN connections. Every step checks before it installs, so re-running is cheap.
# Usage: ./setup.sh
#
#   APPTAIL_SKIP_OPENVPN=1   leave openvpn alone

# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/scripts/lib.sh"

cd "$REPO_ROOT"

OS="$(uname -s)"

# GO_MIN is read from go.mod so what this installs cannot drift from what the module
# declares. GO_TOOLCHAIN_MIN is the release from which the go command fetches a newer
# toolchain on its own, which is why an older Go than GO_MIN is still enough to build.
GO_MIN="$(awk '$1 == "go" { print $2; exit }' go.mod)"
GO_TOOLCHAIN_MIN="1.21.0"
# NODE_MIN is what Vite 7 requires of the dashboard build.
NODE_MIN="20.19.0"

# OPENVPN_TARGET is where macOS gets its copy: beside the helper, the first place
# internal/hostnet/openvpn_darwin.go looks. The helper runs openvpn as root and refuses one
# that loads a library from a folder a normal account can change, which is every package
# manager's prefix on a Homebrew machine, so the libraries it needs are copied into
# OPENVPN_LIBDIR and the copy is rewritten to load them from there.
OPENVPN_TARGET="/Library/PrivilegedHelperTools/app-tail/openvpn"
OPENVPN_LIBDIR="/Library/PrivilegedHelperTools/app-tail/openvpn-lib"

# OPENVPN_CANDIDATES mirrors internal/hostnet/openvpn_{darwin,linux}.go. The helper looks in
# a fixed list rather than on PATH, so an openvpn installed anywhere else is one the app
# will not use however well it runs from a shell.
openvpn_candidates() {
	case "$OS" in
	Darwin)
		printf '%s\n' \
			"$OPENVPN_TARGET" \
			/opt/homebrew/sbin/openvpn /opt/homebrew/bin/openvpn \
			/usr/local/sbin/openvpn /usr/local/bin/openvpn \
			/usr/sbin/openvpn /usr/bin/openvpn
		;;
	*)
		printf '%s\n' \
			/usr/sbin/openvpn /usr/bin/openvpn /sbin/openvpn /bin/openvpn \
			/usr/local/sbin/openvpn /usr/local/bin/openvpn
		;;
	esac
}

# PKG is the package manager the toolchain steps install with, empty when there is none this
# script knows. macOS deliberately resolves to Homebrew alone: MacPorts names its packages by
# version (nodejs22) and guessing which one a machine wants would install the wrong thing
# silently. It is still used for openvpn below, where its root-owned prefix earns it.
PKG=""
detect_pkg() {
	local candidate
	case "$OS" in
	Darwin) have brew && PKG="brew" ;;
	*)
		for candidate in apt-get dnf pacman zypper apk; do
			if have "$candidate"; then
				PKG="$candidate"
				break
			fi
		done
		;;
	esac
	return 0
}

# pkg_names is what this machine's package manager calls a dependency. A name that is wrong
# for the manager in front of it is an install that reports success and delivers nothing,
# so every manager is named rather than assumed to agree with the others.
pkg_names() {
	case "$1:$PKG" in
	go:apt-get) echo "golang-go" ;;
	go:dnf) echo "golang" ;;
	go:*) echo "go" ;;
	node:brew) echo "node" ;;
	node:*) echo "nodejs npm" ;;
	shellcheck:dnf | shellcheck:zypper) echo "ShellCheck" ;;
	*) echo "$1" ;;
	esac
}

pkg_install() {
	case "$PKG" in
	brew) brew install "$@" ;;
	apt-get) sudo_run apt-get install -y "$@" ;;
	dnf) sudo_run dnf install -y "$@" ;;
	pacman) sudo_run pacman -S --noconfirm "$@" ;;
	zypper) sudo_run zypper --non-interactive install "$@" ;;
	apk) sudo_run apk add "$@" ;;
	*) return 1 ;;
	esac
}

# install_named installs one dependency by the name its manager uses.
install_named() {
	local what="$1"
	local -a names
	read -r -a names <<<"$(pkg_names "$what")"
	pkg_install "${names[@]}"
}

# SUDO_SKIPPED records that a step needed root and had nobody to ask, so the summary can say
# the machine is not finished rather than letting a printed command pass for a done one.
SUDO_SKIPPED=no

# sudo_run runs one privileged command, or names it when there is no terminal to ask on.
# Non-interactive callers -- CI, and the gates that run this script blind -- must not meet a
# password prompt that would hang forever.
sudo_run() {
	if [ "$(id -u)" -eq 0 ]; then
		"$@"
		return
	fi
	if ! have sudo; then
		SUDO_SKIPPED=yes
		na "this needs root and sudo is not installed; run as root: $*"
		return 1
	fi
	if [ ! -t 0 ]; then
		SUDO_SKIPPED=yes
		na "this needs root and there is no terminal to ask on; run: sudo $*"
		return 1
	fi
	sudo "$@"
}

# can_sudo reports whether a privileged command can run here at all, so a step made of
# several of them can print the whole sequence once rather than stopping the machine at each
# one in turn.
can_sudo() {
	if [ "$(id -u)" -eq 0 ]; then
		return 0
	fi
	have sudo && [ -t 0 ]
}

# version_at_least compares dotted version numbers, so "1.26.7" is understood as newer than
# "1.9.0" -- which a string comparison would get backwards.
version_at_least() {
	local have_v="$1" want_v="$2" oldest
	oldest="$(printf '%s\n%s\n' "$have_v" "$want_v" | sort -V | head -1)"
	[ "$oldest" = "$want_v" ]
}

ensure_go() {
	step "Go toolchain"
	if ! have go; then
		if [ -z "$PKG" ]; then
			fail "Go $GO_MIN+ is required and there is no package manager here; install it from https://go.dev/dl/"
		fi
		info "installing"
		install_named go || fail "could not install Go; install it from https://go.dev/dl/"
		have go || fail "Go is still not on PATH after installing it"
	fi

	local version toolchain
	version="$(go env GOVERSION)"
	version="${version#go}"
	if ! version_at_least "$version" "$GO_TOOLCHAIN_MIN"; then
		fail "Go $version cannot fetch the toolchain this module needs; install Go $GO_MIN+ from https://go.dev/dl/"
	fi
	if version_at_least "$version" "$GO_MIN"; then
		info "go $version"
		return 0
	fi

	# Below GO_MIN the build still works, because the go command downloads the toolchain
	# go.mod names -- unless this machine has turned that off, in which case the build fails
	# later with nothing here having said why.
	toolchain="$(go env GOTOOLCHAIN)"
	if [ "$toolchain" = "local" ]; then
		fail "go $version is older than the $GO_MIN this module needs and GOTOOLCHAIN=local forbids fetching it; upgrade Go, or run: go env -w GOTOOLCHAIN=auto"
	fi
	info "go $version; the go command will fetch $GO_MIN for this module (GOTOOLCHAIN=$toolchain)"
}

ensure_node() {
	step "Node toolchain"
	if ! have npm || ! have node; then
		if [ -z "$PKG" ]; then
			fail "Node $NODE_MIN+ is required to build the dashboard and there is no package manager here; install it from https://nodejs.org/"
		fi
		info "installing"
		install_named node || fail "could not install Node; install it from https://nodejs.org/"
		have npm || fail "npm is still not on PATH after installing Node"
	fi
	local version
	version="$(node -v)"
	version="${version#v}"
	version_at_least "$version" "$NODE_MIN" ||
		fail "node $version is older than the $NODE_MIN Vite 7 needs; upgrade Node, then re-run"
	info "node $version, npm $(npm -v)"
}

ensure_ui_packages() {
	step "Dashboard packages"
	if ! ui_packages_stale; then
		info "already installed"
		return 0
	fi
	install_ui_packages || fail "UI package install failed"
	info "installed"
}

# ensure_go_tools installs the two linters ./verify.sh names by their install command. They
# go to $(go env GOPATH)/bin, which scripts/lib.sh already adds to PATH for every script here.
ensure_go_tools() {
	step "Gate tools (Go)"
	local tool
	for tool in golangci-lint govulncheck; do
		if have "$tool"; then
			info "$tool present"
			continue
		fi
		info "installing $tool"
		case "$tool" in
		golangci-lint) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest ;;
		govulncheck) go install golang.org/x/vuln/cmd/govulncheck@latest ;;
		esac || na "could not install $tool; ./verify.sh will report it as absent"
	done
}

# ensure_scanners installs the tools ./verify.sh and ./release.sh degrade without. They are
# best-effort: not every distribution packages gitleaks or syft, and a machine without them
# still builds, tests and runs app-tail.
ensure_scanners() {
	step "Gate tools (scanners)"
	local tool
	for tool in shellcheck gitleaks syft; do
		if have "$tool"; then
			info "$tool present"
			continue
		fi
		if [ -z "$PKG" ]; then
			na "$tool is absent and there is no package manager here"
			continue
		fi
		info "installing $tool"
		install_named "$tool" || na "$PKG does not package $tool here; ./verify.sh will report it as absent"
	done
}

# stat_owner_mode prints "uid octal-mode" for one file, on either platform's stat.
stat_owner_mode() {
	case "$OS" in
	Darwin) stat -f '%u %Lp' "$1" ;;
	*) stat -c '%u %a' "$1" ;;
	esac
}

# openvpn_ok applies the test internal/hostnet/openvpn_unix.go applies before it runs the
# program as root: a regular file rather than a link, owned by root, writable by nobody
# else, executable. Checked here so this script cannot report a machine as set up while the
# app refuses what was installed on it.
openvpn_ok() {
	local path="$1" owner mode
	if [ -L "$path" ] || [ ! -f "$path" ]; then
		return 1
	fi
	read -r owner mode <<<"$(stat_owner_mode "$path")"
	[ "$owner" = "0" ] || return 1
	[ $((8#$mode & 8#022)) -eq 0 ] || return 1
	[ $((8#$mode & 8#111)) -ne 0 ] || return 1
}

# openvpn_installed prints the first candidate the helper would accept, or nothing.
openvpn_installed() {
	local path
	while read -r path; do
		if openvpn_ok "$path"; then
			echo "$path"
			return 0
		fi
	done < <(openvpn_candidates)
	return 0
}

# openvpn_source names an openvpn on this machine that OPENVPN_TARGET can be filled from.
openvpn_source() {
	local prefix
	if [ -x /opt/local/sbin/openvpn ]; then
		echo /opt/local/sbin/openvpn
		return 0
	fi
	if have brew; then
		prefix="$(brew --prefix openvpn 2>/dev/null || true)"
		if [ -n "$prefix" ] && [ -x "$prefix/sbin/openvpn" ]; then
			echo "$prefix/sbin/openvpn"
		fi
	fi
	return 0
}

# macho_loads prints the libraries one Mach-O file loads, its own install name excluded.
macho_loads() {
	local own
	own="$(otool -D "$1" | tail -n +2)"
	otool -L "$1" | tail -n +2 | awk '{ print $1 }' | while read -r dep; do
		[ "$dep" = "$own" ] || echo "$dep"
	done
}

# system_library is true for a library macOS itself ships, which root already owns.
system_library() {
	case "$1" in
	/usr/lib/* | /System/*) return 0 ;;
	*) return 1 ;;
	esac
}

# rewrite_load runs install_name_tool on file $1 with the rest as its options. Its warning
# that the change invalidates the signature is expected, since stage_openvpn re-signs after.
rewrite_load() {
	local file="$1" out
	shift
	out="$(install_name_tool "$@" "$file" 2>&1)" && return 0
	na "could not point $(basename "$file") at the bundled libraries: $out"
	return 1
}

# stage_openvpn builds the bundle OPENVPN_TARGET and OPENVPN_LIBDIR are installed from in
# directory $2: the openvpn at $1 as "openvpn" and every library it loads from outside the
# system, followed through each library's own loads, in "openvpn-lib". Each load of a copied
# library is rewritten to @loader_path, and every file is re-signed because the rewrite
# invalidates its signature and an unsigned arm64 binary does not run.
stage_openvpn() {
	local source="$1" stage="$2" file dep base real
	mkdir -p "$stage/openvpn-lib"
	cp "$source" "$stage/openvpn"
	chmod u+w "$stage/openvpn"
	local queue=("$stage/openvpn")
	while [ "${#queue[@]}" -gt 0 ]; do
		file="${queue[0]}"
		queue=("${queue[@]:1}")
		while read -r dep; do
			system_library "$dep" && continue
			case "$dep" in
			/*) real="$dep" ;;
			*)
				na "$(basename "$file") loads $dep, a relative library name this script cannot follow"
				return 1
				;;
			esac
			base="$(basename "$dep")"
			if [ ! -f "$stage/openvpn-lib/$base" ]; then
				cp "$real" "$stage/openvpn-lib/$base"
				chmod u+w "$stage/openvpn-lib/$base"
				rewrite_load "$stage/openvpn-lib/$base" -id "@loader_path/$base" || return 1
				queue+=("$stage/openvpn-lib/$base")
			fi
			if [ "$file" = "$stage/openvpn" ]; then
				rewrite_load "$file" -change "$dep" "@loader_path/openvpn-lib/$base" || return 1
			else
				rewrite_load "$file" -change "$dep" "@loader_path/$base" || return 1
			fi
		done < <(macho_loads "$file")
	done
	for file in "$stage/openvpn" "$stage"/openvpn-lib/*; do
		[ -f "$file" ] || continue
		codesign --force --sign - "$file" 2>/dev/null || {
			na "could not re-sign $(basename "$file") after pointing it at the bundled libraries"
			return 1
		}
	done
	"$stage/openvpn" --version >/dev/null 2>&1 || [ $? -eq 1 ] || {
		na "the bundled openvpn does not start; its libraries did not resolve"
		return 1
	}
}

# openvpn_bundle_current is true when what is installed is byte for byte the staged bundle.
openvpn_bundle_current() {
	local stage="$1"
	openvpn_ok "$OPENVPN_TARGET" && cmp -s "$stage/openvpn" "$OPENVPN_TARGET" &&
		diff -rq "$stage/openvpn-lib" "$OPENVPN_LIBDIR" >/dev/null 2>&1
}

# install_openvpn_bundle puts the staged bundle in place, owned by root. The libraries go
# first so the program is never in place loading libraries that are not.
install_openvpn_bundle() {
	local stage="$1" lib
	sudo_run mkdir -p "$OPENVPN_LIBDIR" || return 1
	sudo_run chown root:wheel "$(dirname "$OPENVPN_TARGET")" "$OPENVPN_LIBDIR" || return 1
	sudo_run chmod 0755 "$(dirname "$OPENVPN_TARGET")" "$OPENVPN_LIBDIR" || return 1
	sudo_run find "$OPENVPN_LIBDIR" -mindepth 1 -delete || return 1
	for lib in "$stage"/openvpn-lib/*; do
		[ -f "$lib" ] || continue
		sudo_run install -o root -g wheel -m 0644 "$lib" "$OPENVPN_LIBDIR/" || return 1
	done
	sudo_run install -o root -g wheel -m 0755 "$stage/openvpn" "$OPENVPN_TARGET" || return 1
}

# setup_openvpn_darwin installs openvpn and puts a root-owned, self-contained copy where the
# helper looks. Apple ships no openvpn, and neither package manager installs one that passes
# the helper's test, so the copy is the step that makes an OpenVPN connection able to start.
setup_openvpn_darwin() {
	local source tool
	for tool in otool install_name_tool codesign; do
		have "$tool" || {
			na "$tool is missing; install the Xcode command line tools with: xcode-select --install"
			return 1
		}
	done
	source="$(openvpn_source)"
	if [ -z "$source" ]; then
		if have port; then
			info "installing with MacPorts"
			sudo_run port -N install openvpn || return 1
		elif have brew; then
			info "installing with Homebrew"
			brew install openvpn || fail "brew install openvpn failed"
		else
			na "openvpn is not installed and neither Homebrew nor MacPorts is here to install it; install one from https://brew.sh or https://www.macports.org, then re-run"
			return 1
		fi
		source="$(openvpn_source)"
		[ -n "$source" ] || {
			na "openvpn installed, but not at a path this script knows to copy from"
			return 1
		}
	fi

	local stage status=0
	stage="$(mktemp -d "${TMPDIR:-/tmp}/app-tail-openvpn.XXXXXX")"
	place_openvpn "$source" "$stage" || status=$?
	rm -rf "$stage"
	return "$status"
}

# place_openvpn stages the bundle from $1 in directory $2 and installs it unless the
# installed one is already the same.
place_openvpn() {
	local source="$1" stage="$2"
	stage_openvpn "$source" "$stage" || return 1
	if openvpn_bundle_current "$stage"; then
		info "$OPENVPN_TARGET is already this openvpn"
	elif can_sudo; then
		info "installing $source and the libraries it loads in $(dirname "$OPENVPN_TARGET"), owned by root"
		install_openvpn_bundle "$stage" || return 1
	else
		SUDO_SKIPPED=yes
		na "installing openvpn needs root and there is no terminal to ask on; run ./setup.sh in a terminal"
		return 1
	fi

	openvpn_ok "$OPENVPN_TARGET" ||
		fail "$OPENVPN_TARGET was installed but is not a root-owned program the helper will run"
	local reported
	reported="$("$OPENVPN_TARGET" --version 2>/dev/null | head -1 || true)"
	info "$OPENVPN_TARGET${reported:+ -- $reported}"
}

# setup_openvpn_linux leans on the distribution, which installs a root-owned /usr/sbin/openvpn
# the helper accepts as it is. Nothing is copied.
setup_openvpn_linux() {
	local found
	found="$(openvpn_installed)"
	if [ -n "$found" ]; then
		info "$found"
		return 0
	fi
	if [ -z "$PKG" ]; then
		na "openvpn is not installed and there is no package manager here to install it"
		return 1
	fi
	info "installing"
	install_named openvpn || return 1
	found="$(openvpn_installed)"
	[ -n "$found" ] || {
		na "openvpn installed, but not where the helper looks: $(openvpn_candidates | tr '\n' ' ')"
		return 1
	}
	info "$found"
}

setup_openvpn() {
	step "OpenVPN"
	if [ "${APPTAIL_SKIP_OPENVPN:-0}" = "1" ]; then
		na "left alone (APPTAIL_SKIP_OPENVPN=1)"
		return 0
	fi
	case "$OS" in
	Darwin) setup_openvpn_darwin ;;
	Linux) setup_openvpn_linux ;;
	*)
		na "$OS runs no OpenVPN connections, so nothing to install"
		return 0
		;;
	esac
}

step "Machine"
detect_pkg
info "$OS, $(uname -m), package manager: ${PKG:-none this script knows}"

ensure_go
ensure_node
ensure_ui_packages
ensure_go_tools
ensure_scanners

OPENVPN_READY=yes
setup_openvpn || OPENVPN_READY=no

if [ "$OPENVPN_READY" = yes ] && [ "$SUDO_SKIPPED" = no ]; then
	step "SETUP: PASS"
else
	step "SETUP: PARTIAL"
	[ "$OPENVPN_READY" = yes ] || info "OpenVPN connections will not start until the step above is done"
	[ "$SUDO_SKIPPED" = no ] || info "a step needed root and was printed instead of run; run it, then re-run ./setup.sh"
fi
info "Next: ./build_install.sh"
