# Contributing to app-tail

Thanks for taking an interest. app-tail carries traffic on people's machines and changes
machine-wide settings (DNS, proxy, a network adapter), so the bar for a change is a little
higher than for an ordinary application: everything it turns on, it has to be able to turn
back off.

## Getting set up

```sh
git clone https://github.com/sellitus/app-tail
cd app-tail
./setup.sh          # Go and Node toolchains, the dashboard's packages, the gate's tools
./build_install.sh  # build the binary (and the .app bundle on macOS)
./run.sh            # start the agent; it prints the loopback address of the dashboard
```

`setup.sh` checks before it installs, so re-running it is cheap. It also installs a
root-owned `openvpn` on macOS and Linux, which OpenVPN connections need; set
`APPTAIL_SKIP_OPENVPN=1` to leave the system's alone.

You need Go (the version in `go.mod`, or any Go from 1.21 on with `GOTOOLCHAIN=auto`,
which fetches that version itself) and Node 20.19 or newer, which is what Vite 7 needs
to build the dashboard.

## The four scripts

Every project script runs with no arguments and does the whole job:

| Script | What it does |
|---|---|
| `./build_install.sh` | Build the UI, embed it, build the binary, install it |
| `./run.sh` | Run the agent in its normal mode |
| `./test.sh` | The full suite: Go with `-race -shuffle=on`, the `notray` build, a Windows tray compile, the UI typecheck and the UI tests |
| `./verify.sh` | The ship gate: gofmt, `go mod tidy` drift, third-party notices, the suite, shellcheck, golangci-lint, UI lint, colour tokens, govulncheck, gitleaks over the tree *and* the history, a cross-build for every release target, the `docs/cli.md` command check, a real-binary smoke test and a static integration scan |

**`./verify.sh` must exit 0 before you open a pull request.** CI runs the same checks as
separate jobs, and `release.sh` runs this gate before it will build artifacts.

## What a good change looks like

- **Fail loudly.** A failure that reaches a user has to name what went wrong and what to
  do about it. Nothing swallows an error to keep the output quiet: a machine-wide DNS
  change that silently does nothing is worse than one that refuses with a reason.
- **Everything is reversible.** If a change writes something outside the state directory
  (a resolver, a proxy setting, a registry value, an adapter), it also detects that thing
  on the next start and can undo it. `hostnet.DetectLeftovers` and `UndoFor` are where
  that lives per platform.
- **Tests catch bugs, not lines.** Every test should have an answer to "what specific bug
  would this catch?". Mock only real boundaries: the network, the clock, a subprocess,
  the registry. Mocking app-tail's own code produces a test that passes whatever happens.
- **Comments explain why, not what.** The codebase is unusually heavily commented, but
  only where the reason is not in the code: an invariant, a hazard, a platform quirk, a
  constraint that still binds.
- **Match the file you are in.** Naming, error wording, error handling and structure
  follow whatever is already there.

## Working on a platform you cannot run

Most of app-tail's risk is in the platform splits (`*_darwin.go`, `*_windows.go`,
`*_linux.go`, `*_other.go`). If you change one you cannot run, at minimum:

```sh
GOOS=windows GOARCH=amd64 go vet ./...
GOOS=windows golangci-lint run
```

and say in the pull request which platform you actually exercised. CI runs the tests on
Linux only. For macOS and Windows it cross-compiles every release target and lints each
platform's files under its own `GOOS`, so a reviewer on that platform still has to run it.

## Adding a new kind of connection

A connection kind implements `tunnel.Tunnel` (`internal/tunnel/tunnel.go`). The interface
is deliberately small (dial, listen, listen for packets, identity, lifecycle, status,
routes, addresses), and anything only one kind can do is a capability discovered by type
assertion in `internal/tunnel/capability.go` rather than a method the other kinds have to
answer with "not supported".

The steps, in order:

1. Add the stored type to `config.TunnelType` and `config.TunnelTypes`.
2. Implement `tunnel.Tunnel` in a package under `internal/tunnel/`.
3. Implement whichever capability interfaces genuinely apply, and no others.
4. Register it wherever the existing kinds are constructed, so it is reachable from the
   settings registry, the CLI and the dashboard rather than only from Go.
5. Add validation for its settings in `internal/config/validate.go`.

Report what your tunnel can actually carry from `Routes`, not what it was configured to
want: that method is what decides which connection carries a given address.

## Changing a setting

Every setting lives once, in the registry in `internal/config/settingsfield.go`. The agent,
the CLI, the dashboard and the tray all read it from there. After adding or changing an
entry, run:

```sh
go generate ./internal/config
```

That rewrites two checked-in files from the registry: `ui/src/generated/settingsSchema.ts`
(the dashboard's types) and `docs/settings.md` (the settings reference). Commit both with
the change. A test fails when either is stale:
`internal/config/gen/main_test.go` for the TypeScript and
`internal/config/gen/markdown_test.go` for the reference. Never edit either file by hand.

## Changing the tray menu

The tray is the menu-bar icon on macOS and the notification-area icon on Windows and Linux
desktops. [docs/tray.md](docs/tray.md) describes it for users.

- The menu is built in `internal/tray/menu.go` (labels and layout, with no platform code)
  and driven in `internal/tray/tray.go` (the `!notray` build). `tray_notray.go` is the
  build without one, and has to keep offering the same `Options`.
- A checkbox row for a setting comes from the registry: set `Tray: true` on the field in
  `internal/config/settingsfield.go`. Only an on/off setting that takes effect on the
  click belongs there, never one that needs a restart; a test in `internal/config`
  enforces that.
- Each row sits in its setting's section. The sections, and their order, are
  `trayGroups` in `menu.go`. A group holding a tray setting that is missing from
  `trayGroups` fails `TestEveryGroupHoldingATraySettingBecomesASubmenu`.
- Add or update tests in `internal/tray/*_test.go`, and run `./test.sh`, which also
  builds the `notray` variant and compiles the Windows tray.
- Update [docs/tray.md](docs/tray.md) so it still describes the menu top to bottom.
- Check the menu by hand on macOS, on Windows, and on a Linux desktop build (a source
  build, since the Linux release binaries have no tray), and say which ones you ran in
  the pull request.

## Checks that need a real tailnet

The automated suite runs with no network at all, using fakes at the tailnet boundary. If
your change touches any of the following, exercise it by hand on two real devices and say
so in the pull request:

- Enrollment by all three auth paths: interactive login, `TS_AUTHKEY`, and an OAuth client
  secret with self-tagging.
- A `to_local` forward to SSH on another device, and a `to_tailnet` forward serving HTTP
  to one.
- UDP in both directions.
- A forward to something your ACLs deny. It must surface as a readable error on that
  forward rather than failing silently.
- The macOS menu bar and the Windows notification area: status, the forwards toggle, the
  settings checkboxes, and quit.
- Start-at-login surviving a real reboot.
- Login by QR code from a phone.

## Pull requests

Keep a pull request to one thing. Say what changed, why, and how you verified it,
including which platform you ran on. Every source file carries
`// SPDX-License-Identifier: MIT`; new files need it too.

By contributing you agree that your contribution is licensed under the MIT License, the
same terms as the rest of the project.

## Reporting a security issue

Do not open a public issue. Report it privately through the repository's **Security >
Advisories > Report a vulnerability** form; [SECURITY.md](SECURITY.md) has the details.
