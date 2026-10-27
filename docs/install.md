# Installing app-tail

## Install

### From a release

Download the artifact for your platform and check it against `SHA256SUMS.txt`.

**macOS:** unzip `app-tail-<version>-darwin-universal.zip` and drag `App-Tail.app`
to `/Applications`. It is a universal binary (Apple Silicon and Intel).

Releases are ad-hoc signed but **not notarized**, so Gatekeeper quarantines the
download and the first launch is refused. Clear the quarantine flag once:

```
xattr -d com.apple.quarantine /Applications/App-Tail.app
```

The command line is the same program, at `/Applications/App-Tail.app/Contents/MacOS/app-tail`.
Run it by that path, or add that folder to your `PATH` to type `app-tail` on its own:

```
echo 'export PATH="/Applications/App-Tail.app/Contents/MacOS:$PATH"' >> ~/.zshrc
```

The network-interface mode and OpenVPN connections need root rights, which app-tail gets
from a small helper that runs as root, so the app itself never has to. Turning the
network-interface mode on asks for your password once and installs it, and
`app-tail tun setup` does the same from a terminal. It lives at
`/Library/PrivilegedHelperTools/app-tail/app-tail-helper`, started by launchd as
`com.github.sellitus.app-tail.helper`. `sudo app-tail tun install-helper` installs it from a
script, `sudo app-tail tun uninstall-helper` removes it and everything it installed, and
`app-tail tun doctor` reports whether it is there and running. See
[the root helper](modes.md#macos-and-linux-a-small-root-helper).

**Windows:** download `app-tail-<version>-windows-amd64.zip` and unpack it into one
folder. It holds two `.exe` files, because one binary cannot be both:

| File | Use |
|---|---|
| `app-tail-<version>-windows-amd64-gui.exe` | The agent, with no console window. Start this from Explorer. |
| `app-tail-<version>-windows-amd64.exe` | The same agent plus a working CLI. Use this in `cmd.exe` or PowerShell. |

The GUI build is linked `-H=windowsgui`, which suppresses the console window, and
with it every subcommand's output, since the process has no console to write to. The
agent's log goes to `app-tail.log` in the state directory instead.
To use the network-interface mode, [install it in Program Files](#install-for-all-users-in-program-files)
first, then turn on start at login from the installed copy.

`wintun.dll` and `WINTUN-LICENSE.txt` ship in the same archive. Wintun is the small
driver library Windows needs to create a network adapter. Keep the DLL in the folder you
put the `.exe` in: the [network-interface mode](modes.md#the-network-interface-mode) loads
it from the folder holding the `.exe` or from the Windows system folder, and nowhere
else, so a copy elsewhere on `PATH` does not count. Every other mode ignores it entirely.
app-tail checks the DLL's SHA-256 (a fingerprint of the file's exact bytes) against the
copy its release shipped before loading it, and refuses any other file. `app-tail tun
doctor` reports a missing or mismatched copy.

#### Install for all users in Program Files

The network-interface mode and the machine-wide resolver need administrator rights, and
app-tail gets them by restarting itself under an administrator prompt. It only does that
from a folder that only administrators can change. From a folder you can write, like
Downloads or the Desktop, any program running as you could swap the `.exe` or the
`wintun.dll` beside it before you answer the prompt, and that program would then run as
Administrator. So app-tail refuses to ask for the rights there and runs in the contained mode
instead. The refusal starts with `app-tail is not installed where only administrators can
change it` and names the `install` command to run.

To install it properly, unpack the archive into one folder and run, from that folder:

```
app-tail-<version>-windows-amd64.exe install
```

It asks for administrator rights, then copies both `.exe` files, `wintun.dll` and the
notices into `C:\Program Files\app-tail\` as `app-tail.exe` and `app-tail-gui.exe`. Every copy
is checked against its source by SHA-256, and `wintun.dll` must also match the pinned release.
Only Administrators and SYSTEM can change the folder, and every user can run it. The window
it opens prints the installed path and waits for Enter. Start
`C:\Program Files\app-tail\app-tail-gui.exe` from there on. Turn on start at login from that
copy too (`"C:\Program Files\app-tail\app-tail.exe" install-autostart`, or from its
dashboard), so the login item starts the installed one. Once that's done, you can delete the
unpacked folder.

To run one session from an unprotected folder anyway and accept that risk, start it with
`app-tail run --allow-unprotected-elevation`. It prints a warning and asks for the rights.
The flag covers that one run only. It is a command-line flag on purpose, with no environment
variable or setting behind it: a program running as you could set those once and leave them on.

On WSL, `./build_install.sh` stages the build in your Windows temporary folder and installs
it into Program Files the same way, behind one administrator prompt.
`APPTAIL_WINDOWS_DESKTOP_INSTALL=1` installs to a folder on the Desktop instead, for
development.

**Linux:** `chmod +x app-tail-<version>-linux-amd64` and run it, then
`install-autostart` for a login item.

The macOS and Windows binaries carry the tray (the menu-bar or notification-area icon,
described in [the tray](tray.md)). The Linux release binaries are built without it
(`-tags notray`) and are dashboard-only, because the servers and containers they are for
have no DBus StatusNotifier host for an icon to attach to. For a tray on a Linux desktop,
build from source.

Making app-tail the machine's own resolver (System DNS) on Linux needs systemd-resolved,
because app-tail changes the resolver through `resolvectl` and nothing else. On a machine
without it, the rest of app-tail works and that feature says `app-tail can only change this
machine's resolver through systemd-resolved`, followed by what it found missing.

`THIRD_PARTY_LICENSES.txt` ships beside the binaries, inside `App-Tail.app`, and
embedded in the binary itself. `app-tail licenses` prints it, the Wintun terms
included.

### From source

```
./setup.sh             # installs the toolchains, the gate's tools and openvpn
./build_install.sh     # builds the dashboard and the binary, installs it
./run.sh               # runs the agent with its dashboard on 127.0.0.1:8377
```

Needs Go 1.26+ and Node 20.19+ (Vite 7). The dashboard is compiled into the binary
with `go:embed`, so `ui/dist` must exist before `go build` will work. The scripts
above handle that. A bare `go build` in a clean checkout will fail until you have
run `./build_install.sh` or `./test.sh` at least once.

On macOS `./build_install.sh` asks for your password before it builds anything, and
installs the [privileged helper](modes.md#macos-and-linux-a-small-root-helper) as a copy of
the binary it just built. The helper is that binary running as root, so without this a
rebuild leaves the two on different code. Declining the password skips that step and
says so; the build itself is unaffected. Run it in a terminal: a non-interactive
caller is never prompted.

A from-source build on macOS, Windows or Linux includes the tray. `go build` needs
a C toolchain for it on macOS only; elsewhere it cross-compiles with cgo disabled.

### OpenVPN

OpenVPN connections need an `openvpn` program on the machine. The privileged helper
runs it as root, so it accepts only a root-owned program in folders only root can change,
and it refuses one that loads a library from anywhere a normal account can write. It looks
in a fixed list of places rather than searching `PATH`, so a setting or an environment
variable can never choose what runs as root:

| System | Where it looks, in order |
|---|---|
| macOS | `/Library/PrivilegedHelperTools/app-tail/openvpn`, `/opt/homebrew/sbin/openvpn`, `/opt/homebrew/bin/openvpn`, `/usr/local/sbin/openvpn`, `/usr/local/bin/openvpn`, `/usr/sbin/openvpn`, `/usr/bin/openvpn` |
| Linux | `/usr/sbin/openvpn`, `/usr/bin/openvpn`, `/sbin/openvpn`, `/bin/openvpn`, `/usr/local/sbin/openvpn`, `/usr/local/bin/openvpn` |

A Homebrew openvpn fails both tests: it lives in, and loads OpenSSL from, a folder your own
account owns. That is true under `/opt/homebrew` on Apple Silicon and under `/usr/local`
on Intel Macs. app-tail finds it and refuses it rather than running it. The connection's
error starts with `the openvpn program is not installed on this machine`, then says what was
wrong with each copy it found (for example, that a folder on the way to it `belongs to
<you> rather than to root`), and ends with the commands below.

On macOS `./setup.sh` installs openvpn with MacPorts or Homebrew, then copies it and the
libraries it loads to `/Library/PrivilegedHelperTools/app-tail/`, owned by root, with the
copy rewritten to load only those libraries. Re-run it after upgrading openvpn. To do the
same by hand with an openvpn that loads only the system's own libraries, such as the
statically linked one Tunnelblick ships:

```sh
sudo mkdir -p /Library/PrivilegedHelperTools/app-tail
sudo install -o root -g wheel -m 755 /path/to/openvpn /Library/PrivilegedHelperTools/app-tail/openvpn
```

Copying a Homebrew openvpn there is not enough on its own: it still loads its libraries from
Homebrew's folder, so it is refused even from the root-owned one. Use `./setup.sh` for that.

Linux distributions install a root-owned `/usr/sbin/openvpn` that passes as it is. For a
build of your own, put it at `/usr/local/sbin/openvpn` with
`sudo install -o root -g root -m 755 /path/to/openvpn /usr/local/sbin/openvpn`, and keep every
library it loads in root-owned folders.

Each OpenVPN server also needs an administrator's approval once, together with the
certificate authority it is trusted with. See
[Approving network changes](security.md#approving-network-changes).

### First run

Starting the agent with no configuration is fine: it writes its defaults on first
run, picks a free loopback port for the dashboard, and opens the dashboard in a browser,
already signed in, at the tailnet login screen. Approve the device on your tailnet and it
is ready.

The dashboard only answers callers holding the agent's API token, which the agent writes
to `api-token` in the state directory, readable only by your account. The tray menu and
`app-tail dashboard` open it signed in with a one-time link, so you never handle the
token yourself. The [command line guide](cli.md#signing-in) has the details, and
[Reaching the dashboard from another machine](deployment.md#reaching-the-dashboard-from-another-machine)
covers a headless host.

Without a display the agent logs JSON to stderr and runs dashboard-only;
`--headless` forces that mode anywhere.

Credentials you enter (auth keys, WireGuard and OpenVPN keys and passwords, the proxy
password) are kept in `secrets.json` beside `config.json` in the state directory, not in
`config.json` itself. The file is readable only by your account, and on Windows its contents
are also encrypted to your Windows account. See
[Where credentials are stored](security.md#where-credentials-are-stored).

A few changes to this machine's networking (carrying all internet traffic, routes to public
addresses, making app-tail the machine's resolver, OpenVPN servers and traffic interception)
need an administrator's approval before app-tail makes them. The dashboard and the tray
offer an **Approve** button when one is waiting; see
[Approving network changes](security.md#approving-network-changes).

### Upgrading from a build that kept credentials in config.json

Nothing to do. The new build reads credentials still in `config.json`, and its first save
moves them into `secrets.json` and removes them from `config.json`. The copy of the old
document it keeps beside it (`config.json.v<N>.bak`) has its credentials removed too.
Going back to an older build after that means entering the credentials again, because an
older build does not read `secrets.json`.
