## What this changes

<!-- One or two sentences. What is different after this lands. -->

## Why

<!-- The problem, not the patch. Link the issue if there is one. -->

## How it was verified

- [ ] `./test.sh` passes
- [ ] `./verify.sh` exits 0
- [ ] For a change to a platform split (`*_darwin.go`, `*_windows.go`, `*_linux.go`,
      `*_other.go`): `GOOS=<target> go vet ./...` and `GOOS=<target> golangci-lint run`
- [ ] For a change to the settings registry: ran `go generate ./internal/config` and
      included the regenerated `ui/src/generated/settingsSchema.ts` and `docs/settings.md`
- [ ] For a change to the tray: updated `docs/tray.md` and checked the menu on each
      platform listed below
- [ ] Docs describe the new behavior (`docs/`, `README.md`, command help)

Ran on: <!-- macOS / Windows / Linux, and which version -->

<!-- If this touches enrollment, forwards over a real network, the tray, start-at-login,
     QR login, the root helper or network-change approvals, say what you exercised by
     hand. The automated suite uses fakes at the tailnet boundary and cannot cover those.
     Screenshots and logs in a pull request are public: redact device names, addresses
     and keys. -->

## Anything a reviewer should look at first

<!-- The part you are least sure about, or the decision that could have gone another way. -->
