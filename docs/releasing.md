# Releasing

## Cutting a release

```
git tag -a v0.1.0 -m "First internal release"
./release.sh
```

`release.sh` refuses to build from a dirty tree, refuses an untagged commit, refuses
stale third-party notices, and runs the full `./verify.sh` gate before it builds
anything. Each refusal has a named override for the cases where you mean it:
`APPTAIL_ALLOW_DIRTY`, `APPTAIL_ALLOW_UNTAGGED`, `APPTAIL_SKIP_VERIFY` (for CI, which
runs the gate as its own job) and `APPTAIL_ALLOW_SINGLE_ARCH`.

The suite is the slow part of that gate, so it has its own opt-out:

```
./release.sh --skip-tests
```

That leaves out `./test.sh` alone. gofmt, dependency integrity, notice freshness,
shellcheck, golangci-lint, eslint, govulncheck, gitleaks, the five-target cross-build,
the `docs/cli.md`/`--help` check and `scripts/smoke.sh` all still run, so the artifacts stay
gated on everything except the tests. `APPTAIL_SKIP_TESTS=1` is the environment form,
and `./verify.sh` honors it directly; the gate then ends in `VERIFY: PASS (tests
skipped)` rather than a bare pass. Use it when the suite has already passed on this
commit. `APPTAIL_SKIP_VERIFY=1` remains the way to skip the gate entirely.

Output lands in `dist/`: the macOS `.app` and its archive, both Windows `.exe`
files with the `.zip` that ships them beside `wintun.dll`, both Linux binaries,
`THIRD_PARTY_LICENSES.txt`, a module manifest, and `SHA256SUMS.txt`. Binaries are built `-trimpath` and stamped with the **commit**
date rather than the build date, so two builds of one commit compare equal under
`cmp`.

The Windows build also fetches `wintun.dll`, checks it against a pinned SHA-256, and
copies it out with `WINTUN-LICENSE.txt`. The licence file is compared byte for byte
against the one in the archive the DLL came from, because those terms permit
redistributing the DLL only unmodified and only with its notice. `APPTAIL_WINTUN_ZIP`
points at an already-downloaded copy for a build with no network.

Signing is a seam. Ad-hoc by default on macOS, which needs no Apple account and is what
makes the universal binary launchable at all: `lipo` strips signatures and macOS will
not start an unsigned arm64 binary. Set `APPTAIL_CODESIGN_IDENTITY` to a Developer ID
and `APPTAIL_NOTARY_PROFILE` to a stored notarytool credential, and the same script
signs with the hardened runtime, notarizes, staples and re-archives. Windows is
unsigned unless `APPTAIL_WINDOWS_SIGN_PFX` and `APPTAIL_WINDOWS_SIGN_PASS` name a code
signing certificate, in which case both `.exe` files are signed and timestamped; an
unsigned build works but meets SmartScreen on first run, which the interface mode's
consent prompt makes considerably more alarming.

## Repo scripts

| Script | Does |
|---|---|
| `./setup.sh` | install the Go and Node toolchains, the dashboard's packages, the gate's tools and a root-owned `openvpn` |
| `./build_install.sh` | build the dashboard and binary, install it |
| `./run.sh` | build and run the agent locally |
| `./test.sh` | Go suite with `-race -shuffle=on` plus coverage, dashboard typecheck and tests |
| `./verify.sh` | the ship gate: everything below, in order |
| `./release.sh` | build the distributable artifacts |
| `scripts/smoke.sh` | drive the real binary end to end over HTTP |
| `scripts/licenses.sh` | regenerate the third-party notices (`--check` to verify) |
| `scripts/version.sh` | resolve the one build identity every script and the binary agree on |

`./verify.sh` runs, in this order: gofmt, generated-type drift, `go mod tidy` drift
and `go mod verify`, third-party notice freshness, the full `./test.sh`, shellcheck,
golangci-lint (both build-tag sets), eslint, govulncheck, gitleaks over the tree and
the history, a five-target cross-build, then, against a freshly built binary, the
`docs/cli.md` command block versus `--help`, and `scripts/smoke.sh`.

CI runs the same checks on every push across Linux, macOS and Windows, plus the
universal macOS tray build and a Docker image that must start and report its version.
