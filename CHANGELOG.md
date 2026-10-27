# Changelog

Notable changes per release, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions are
[semantic](https://semver.org/spec/v2.0.0.html).

An entry is written when the tag is cut. `./release.sh` refuses to build from an
untagged commit, so the tag, the entry and the artifacts stay in step.

## Unreleased

**Upgrading:** the dashboard API now needs a token on every call. The tray, the
dashboard and the CLI handle it for you; a script that calls the API directly needs the
two lines in [Calling the API from a script](docs/api.md#calling-the-api-from-a-script).
Features that change this machine's networking beyond the always-safe set ask an
administrator to approve them once; see [Security](#security) below.

### Added

- **Connections beyond Tailscale.** WireGuard and OpenVPN connections sit beside
  tailnets, each with its own switch, and the forwards, the proxy and the network
  interface carry traffic for any of them.
- **Where internet traffic goes** (`egress.mode`): straight out of this machine, through
  one connection, or shared across several, spread between them or chained through them in
  order. `egress.killSwitch` holds traffic rather than letting it out when the chosen
  connection cannot carry it.
- **The fabric interface mode** (`interface.mode: fabric`) puts every network app-tail
  holds on one interface and can present a network at addresses other than its own, which
  makes two networks that both use `10.0.0.0/8` usable at the same time.
- **Traffic inspection** (`ips.enabled`): every connection app-tail carries is checked
  against feeds of known-bad addresses and names, on six levels from Minimum to Ultimate.
  It starts by recording matches only, and refuses nothing until you set `ips.mode` to
  `prevent`. Opening TLS is a separate, opt-in step with a root you install yourself,
  limited by name constraints to what you chose.
- **System resolver profiles** (`systemDns.enabled`): pick the DNS servers this whole
  machine uses, including DNS over TLS and DNS over HTTPS, and switch between them from
  the tray. Names that belong to the network you are on keep resolving through it.
- **A live traffic graph** with figures per device, kept by the agent so it does not
  go blank while the dashboard tab is hidden, with optional round-trip measurements.
- **A fair packet queue on WireGuard connections** (FQ-CoDel), so one large download no
  longer makes every other flow through the same connection wait behind it.
- **`docs/settings.md`**, every setting with its key, CLI flag, default and when a change
  takes effect, generated from the settings registry and checked by a test so it cannot
  fall behind. **`docs/tray.md`** walks through the tray menu.

- **DNS blocking lists.** app-tail refuses names itself, against lists you choose,
  with nothing sent anywhere to decide it. Two independent switches: `dnsBlock.own`
  filters what app-tail resolves for its own connections, `dnsBlock.system` filters
  what this machine resolves through the system-wide resolver. Both read one catalog
  and one compiled matcher, so the two halves cannot disagree.
- **A shipped catalog of forty-five lists from sixteen publishers**, each switchable on
  its own and grouped by who publishes it, with a group opening on the card when
  something inside it is on: Hagezi's five tiers, threat feed, gambling, fake-shop,
  DoH-and-proxy-bypass, hoster, dynamic-DNS and eight native-telemetry lists;
  StevenBlack's unified hosts file and its four variants; OISD Small, Big and Adult;
  1Hosts Lite and Xtra; AdGuard's DNS filter; malware-filter's URLhaus, phishing and
  botnet lists; Phishing Army; abuse.ch's URLhaus export; Peter Lowe; Dan Pollock;
  AdAway; NextDNS's CNAME-cloaking list; Dandelion Sprout's anti-malware list;
  EasyList, EasyPrivacy and Fanboy's Annoyance; NoTrack's tracker list; and hBlock. Lists
  of your own
  are added by name and URL, read as hosts files or Adblock-syntax filter lists.
  Every list reports what it contributed and what it skipped, so one written for a
  browser rather than a resolver is visible rather than assumed. **Show only what's on**
  narrows the card to just the lists that are switched on, every group open, and back.
- **Six levels over that catalog** -- Minimum, Low, Medium, High, Pro and Ultimate --
  offered on the card and as `app-tail dns block level [name]`. Each turns on exactly
  the shipped lists it names and leaves the lists you added alone; a set that is nobody's
  level is reported as one rather than shown as the nearest match. The curation rule is
  that a list whose worst case is a blocked advertiser or malicious host goes in early,
  so every malware, phishing and botnet feed is on at Minimum, while no level at all
  includes the category lists (gambling, adult, social media, fake news) or the three
  that break working software: bad hosters, dynamic DNS, and the DoH/VPN/proxy bypass
  list.
- **`dnsBlock.answer`** chooses what a blocked name is answered with: `nxdomain`
  (the default), `sinkhole` (`0.0.0.0` and `::`) or `refused`.
- **Allowlist, manual blocklist, pause and per-list refresh.**
  `app-tail dns block allow add NAME` beats every list; `deny add` blocks a name with
  no list at all; `pause 15m` stops blocking for as long as you asked and is never
  written to disk; lists are re-downloaded on `dnsBlock.refreshHours`.
- **Lists keep blocking from disk when they cannot be downloaded.**
  `<stateDir>/blocklists/` caches each list and records what it contributed; downloads
  are conditional, dialled at a pre-resolved address with the system proxy bypassed so
  fetching a list through app-tail's own resolver cannot deadlock or self-block.
- **`app-tail dns block`** covers all of it — status, `on`/`off`, `list`, `add`, `rm`,
  `enable`/`disable`, `refresh`, `pause`/`resume`, `allow`/`deny` and
  `check NAME`, which names the list that stops a name or says why nothing does — with
  the same surface on the dashboard's DNS page and under `/api/dns/block`.
- **Starting app-tail again takes over from the copy already running.** One agent per
  config document, held as an operating-system lock on the `agent.lock` file beside it
  (`<stateDir>/agent.lock` unless `--config` moves it), so the
  kernel drops it however a run ends and nothing stale is left to clear. A second start
  asks the first to shut down — a terminate signal, or `POST /api/quit` where a signal
  cannot cross, which is Windows and an agent another account started — waits for it to
  finish putting this machine's resolver, proxy settings and routes back, and only then
  starts. One that will not go within fifteen seconds is ended, and what it left behind
  is repaired before the new agent starts. Two runs pointed at different config files
  are still two agents and leave each other alone.

### Changed

- **app-tail is released under the MIT licence.** `LICENSE` carries the MIT text and every
  Go, TypeScript and TSX source file carries an `SPDX-License-Identifier: MIT` header. The
  notices for what app-tail ships alongside its own code stay where they were, in
  `internal/licenses/THIRD_PARTY_LICENSES.txt`.
- **The README is an introduction and the reference moved to `docs/`.** The README now says
  what app-tail is, what the three shapes are — forwards, proxy, one network interface — and
  how to get to a working connection, in a page somebody can read before deciding to install
  it. Everything it used to carry is in `docs/`: `modes.md`, `connections.md`, `dns.md`,
  `routing.md`, `cli.md`, `api.md`, `configuration.md`, `install.md`, `deployment.md`,
  `releasing.md`, `troubleshooting.md` and `security.md`. The command block that is checked
  against `app-tail --help` moved to `docs/cli.md`, and `verify.sh` and CI check it there.
- **`docs/api.md` documents every HTTP route** rather than the twenty-one the README listed.
- **Contributing, conduct and issue templates.** `CONTRIBUTING.md` covers building from
  source, the script quartet and the manual checks that need a real tailnet;
  `CODE_OF_CONDUCT.md` is Contributor Covenant 2.1; the bug template asks for the operating
  system, the run mode and `app-tail health --json`.
- **Windows is gated the way macOS is.** CI lints `*_windows.go` at `GOOS=windows`, records
  coverage on the Windows leg, cross-builds the tray-enabled `.exe` that `release.sh` ships,
  and smoke-tests a Windows binary end to end. The packages that only run on Windows —
  `sysdns`, `autostart`, `elevate`, `relaunch`, `hostnet`, `forward` — have tests there now.

### Fixed

- **A Mac that crashed with System DNS on no longer stays offline until you open
  app-tail.** The helper made one attempt to put the machine's resolver back at boot,
  and that attempt could miss: the network was not up yet, or a network service had
  dropped out of the restore record. Nothing tried again, so every name lookup went to
  an app-tail that was not running. The helper now checks every 30 seconds while no
  app-tail is serving the machine, and also hands back any service still pointed only at
  app-tail's own addresses, recorded or not. `app-tail dns restore` and
  `tun uninstall-helper` do the same sweep, and a service renamed while the override stood
  is now put back under its new name. Every repair stands back for a running app-tail,
  which holds a lock beside the restore record while its override is up.
- **Windows gets the same protection.** Switching System DNS on registers a scheduled
  task, `\app-tail DNS repair`, that runs `app-tail dns restore` as SYSTEM at boot, two
  minutes after boot and at every logon, so a crash or power cut no longer leaves the
  machine resolving nothing until app-tail is started again. The task is registered before the machine is pointed at app-tail, and
  System DNS is refused when it cannot be (app-tail running from a folder other accounts
  can write, which `app-tail install` fixes).
- **A node that had to start inside app-tail now moves onto the network interface by
  itself.** The mode was chosen when the node was built and never looked at again, so
  starting while the official Tailscale client was connected kept the tailnet inside
  app-tail for the life of the process — quitting the other client changed nothing until
  the node was restarted by hand. The machine is now read again on a slowing schedule
  while a node is in that state, and the node is rebuilt onto the interface as soon as it
  can carry one. A start that failed on a machine that looked able still waits for you:
  re-reading the machine says nothing about it.
- **An idle tailnet device is no longer reported as unreachable.** Tailscale configures a
  peer in its WireGuard engine on the first packet sent to it, so a device nobody has
  dialled yet is normally absent from it. app-tail read that as no path and told people to
  restart the node, which reported most of a quiet tailnet as broken. Reachability now
  follows what the socket layer tracks, which is every device the tailnet lists.
- **A dashboard port that was busy for a moment no longer becomes the address you are
  stuck on.** The agent recorded where it bound over `uiListenAddr`, so starting while
  the previous instance still held the port replaced the configured address for good,
  and the port drifted again on every recurrence. Where it is listening is now recorded
  in `<stateDir>/dashboard-address`, which the CLI and tray read first; the setting
  stays what you asked for and is tried again on the next start.

### Security

- **The dashboard API needs a token.** Every `/api` route asks for the token in
  `<stateDir>/api-token`, readable only by your account. The tray and `app-tail
  dashboard` open the dashboard with a one-time link that expires in two minutes and is
  exchanged for a session that ends when the agent stops. On macOS and Linux that link
  only works for a browser running as your account. **Breaking:** scripts that called the
  API without a token get `401`; [docs/api.md](docs/api.md#calling-the-api-from-a-script)
  has the fix.
- **The CLI checks the agent before trusting it.** It asks the listener to prove it holds
  the token before sending it, so a program squatting on the dashboard port, or a stale
  address file, never receives it.
- **The root helper checks which program is calling, not just which account.** On macOS
  the caller's code-signature hash must match the helper's, and both are signed with the
  hardened runtime. On Linux the helper compares the program file and refuses a traced
  caller. The helper now lives in `/Library/PrivilegedHelperTools` on macOS.
- **Changes that could take over this machine's traffic need an administrator's
  approval.** Full tunnels, public routes, the machine's own resolver, domains outside
  `ts.net`, each OpenVPN server and traffic interception are refused until approved in a
  root-owned `grants.json`. The dashboard and tray show what is waiting with an
  **Approve** button; `app-tail tun grant` does the same from a shell.
- **Root never runs a program another account could have changed.** Before starting
  `openvpn`, the helper checks the program, every folder above it and every library it
  loads, and refuses anything a non-root account can write. OpenVPN's management socket
  sits in a root-owned folder and only your account may connect to it.
- **Credentials moved out of `config.json`** into `secrets.json` (`0600`, and encrypted
  with DPAPI on Windows). Older configs move theirs on the first save, and the backups
  app-tail takes have credentials removed.
- **A credential only goes to the server it was entered for.** Pointing a connection at
  another control server drops its auth key and OAuth secret unless you enter them again.
  An OAuth secret file must be a small regular file holding something shaped like a
  credential, so a path to some other file is never sent.
- **Windows installs where only administrators can change it.** `app-tail install` copies
  app-tail to Program Files. Elevating from a folder your account can write is refused
  unless that run carries `--allow-unprotected-elevation`. `wintun.dll` is loaded only if
  its SHA-256 matches the hash built into app-tail.
- **Forwards cannot point at app-tail's own listeners**, and a forward that listens on
  anything other than loopback needs `exposeToNetwork`.
- **Feed downloads refuse a redirect from HTTPS to HTTP.**
- **No log upload.** app-tail turns off Tailscale's log upload before any node starts,
  removes the log buffers older builds left behind, and keeps login URLs out of its logs.
- **The traffic-interception root is limited** to server certificates, to the names you
  chose (X.509 name constraints), and to one year. `app-tail ips remove-root` takes an old
  one out.

## 0.1.0

The first release. One binary is the agent, the embedded dashboard and the
CLI; it joins your tailnet as its own userspace device and forwards only the
TCP/UDP ports you configure.

### Added

- **Forwarding both directions.** `to_local` maps a tailnet service onto a local
  port; `to_tailnet` publishes a local service to the tailnet. TCP, UDP or both.
- **Dashboard** on loopback, compiled into the binary, with live forward state,
  peer discovery, service presets and a settings drawer generated from the same
  Go registry the CLI reads — so the two cannot drift.
- **19 CLI commands** covering everything the dashboard does, plus
  `settings menu` for an interactive terminal editor.
- **Fleet provisioning.** `bootstrap-policy` prepares the tailnet policy once;
  `provision --profile` applies shared settings and forwards to each node. Both
  are idempotent.
- **`app-tail health`** and `GET /healthz`: 503 unless the node is Running *and*
  every enabled forward is listening. This is what the container healthcheck asks.
- **`app-tail licenses`** prints the third-party notices embedded in the binary.
- **Start at login** on macOS (launchd), Linux (systemd user unit) and Windows
  (`HKCU\...\Run`), each writing a small file you can read and delete by hand.
- **Docker image** and Compose file: static, tray-less, non-root, host-networked.
- **Signed, checksummed releases** for macOS (universal `.app` with the menu-bar
  tray), Windows (console and GUI `.exe`) and Linux (amd64, arm64). Binaries are
  reproducible: two builds of one commit compare equal under `cmp`.

### Security

- **DNS-rebinding guard.** Every request must carry a loopback `Host`. Without
  it, a hostile page could rebind its own name to 127.0.0.1 and read
  `GET /api/status`, which carries the pending Tailscale login URL — a bearer
  capability to enroll a device into your tailnet.
- **CSRF guard.** State-changing requests must carry an `Origin` matching the
  host they were served from. The check is deliberately not a loopback-name
  allowlist: a resolver that forwards `*.localhost` upstream would let a genuinely
  remote page present a trusted origin.
- **Credential exfiltration guard.** `bootstrap-policy` refuses to send its
  `policy_file`-scoped OAuth secret to a non-Tailscale host without an explicit
  `--allow-foreign-api-url`, and never in cleartext off loopback. The rule is
  enforced at the point the secret leaves the process, and again on every redirect
  hop — Go replays request bodies on 307/308, so a redirect would otherwise resend
  the secret verbatim.
- **Response hardening.** CSP, `nosniff`, `X-Frame-Options: DENY` and
  `Referrer-Policy: no-referrer` on every response, including refusals.
- **Secrets are write-only across the API** and never accepted as a literal
  command-line argument, where every process on the machine could read them.

### Fixed

- A data race between `POST /api/restart` and the dashboard's status poll, where
  the tailnet node was published before `Start` finished writing its fields.
- `POST /api/forwards` returned 201 with `state: "stopped"` before the listener
  existed, so a new forward looked dead for up to three seconds.
- A failed node restart left the agent stuck: the reconcile never ran, no watcher
  was started, and only a second `POST /api/restart` recovered it.
- The HTTP server never closed its listener on shutdown, so a restart could not
  rebind the port.
- `Suggest` for a `both` forward gave up on the first TCP port that was already
  bound on UDP instead of trying another.

### Known limits

- The menu-bar tray ships on macOS only. Windows and Linux builds are
  dashboard-only; the tray needs a per-OS C toolchain to cross-compile.
- Releases are ad-hoc signed, not notarized, so macOS quarantines the download.
  The README has the one-line `xattr` workaround.
