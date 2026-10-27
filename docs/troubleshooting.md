# Troubleshooting

Health checks, where the logs go, and the failures worth naming.

## Health and monitoring

`GET /healthz` answers 200 only when the tailnet node is Running **and** every
enabled forward is listening. Anything else is 503 with a `reason`. `app-tail health`
is the same check from a shell, exiting non-zero when unhealthy:

```
$ app-tail health
app-tail: unhealthy: tailnet node is not running (NeedsLogin)
$ echo $?
1
```

`--json` prints the body and still exits non-zero, so it is usable both by a person
and by a script.

This is what the container healthcheck runs. It replaced `app-tail status`, which
exits 0 as soon as the loopback API answers: green while the node sat in
`NeedsLogin` and nothing was being forwarded. `health` discovers the dashboard
address from the state directory rather than assuming `8377`, which matters under host
networking, where a hardcoded probe could answer from a different instance.

## Logs

app-tail writes to **stderr**: JSON when headless, human-readable text otherwise. A
log file is written only where there is no stderr to write to, which is the Windows
GUI build.

| How it was started | Where the output goes |
|---|---|
| A terminal | that terminal |
| macOS login item | the unified log; the launchd plist sets no `StandardOutPath`. Read it with `log show --predicate 'process == "app-tail"' --last 1h` |
| Linux login item | the journal: `journalctl --user -u app-tail -f` |
| Docker | `docker logs -f app-tail` |
| The Windows GUI `.exe` | `app-tail.log` in the state directory, capped at 4 MB with one previous generation kept beside it as `app-tail.log.1` |

## Troubleshooting

**The dashboard shows it is signed out, or `curl` gets 401.** Every `/api/` call needs
the agent's API token or a dashboard session. A session ends after 30 days, when the agent
stops, and when someone runs `app-tail auth rotate`. A refused call answers 401, and its
error says to open the dashboard from the app-tail menu or run `app-tail dashboard`. Open
the dashboard from the tray menu or with `app-tail dashboard`, which signs the browser in
with a one-time link. A link that was already used, or is more than two minutes old, says
`this sign-in link has expired or was already used`; ask for a new one. For `curl` and
scripts, send the token from `api-token` in the state directory as a bearer token; see
[Authentication](api.md#authentication). On a remote host, use
[the SSH steps](deployment.md#reaching-the-dashboard-from-another-machine).

**The dashboard returns 403.** Either you reached it by a name the Host guard does not
recognise, or (on macOS and Linux) a sign-in link that `app-tail dashboard` or the tray
opened was redeemed by a browser running as a different account. For the first, use `127.0.0.1`, `localhost` or a
`*.localhost` name, and forward the port over SSH rather than through `tailscale serve`. For
the second, use `app-tail dashboard --print` and open the printed link yourself: a printed
link works from any account.

**A command says `something other than your app-tail agent is listening on ...`.** Before
it sends the token, the CLI asks whatever is on the recorded dashboard port to prove it
holds the same token. This answer means it could not, so the CLI sent nothing. Usually
the agent stopped without cleaning up and another program took its port. Start app-tail
again and the record is rewritten. If the agent is running, check that the CLI reads the
same state directory as the agent (see the `app-tail status` entry below).

**A command says `read the API token: ... permission denied`.** The token file is readable
only by the account the agent runs as. Run the CLI as that account. In Docker, use
`docker exec app-tail app-tail ...`, which runs as the container's own user.

**`app-tail status` says no agent is running.** The CLI finds the agent by reading the
address it recorded in `dashboard-address`, falling back to the configured one. Point `--state-dir` or `APPTAIL_STATE_DIR`
at the same directory the agent uses. A login item and a shell may not share one.

**A forward shows an error with a connection refused or timeout.** The tailnet node
is up but the far end is not reachable. Check your ACLs first: a denied forward fails
at connect time, not at creation, and the reason appears on that forward.

**A setting saved but nothing changed.** Identity settings need
`app-tail restart`; see [Applying settings that need a restart](configuration.md#applying-settings-that-need-a-restart).
Changing the dashboard address needs a full process restart, and the dashboard says so.

**Starting app-tail closed the copy that was already running.** That is deliberate: one
agent per config document. The new run asks the old one to shut down, waits for it to put
this machine's resolver, proxy settings and routes back, and only then starts. The log
names the process it stopped. To run two at once, give the second one its own state:
`app-tail run --state-dir ~/.config/app-tail-second`. A start that reports it cannot take
the claim found an agent that would neither stop nor be ended; the process it names is
still holding the machine.

**Nothing on this machine resolves names, and restarting app-tail does not help.** A run
that ended without putting the machine back left it pointed at app-tail's own resolver
address, which nothing is listening on any more. This should fix itself: on macOS the
helper checks every 30 seconds and puts back any service left pointed at app-tail, and on
Windows the `\app-tail DNS repair` task does it at boot and at every logon. If it has not (no helper
installed, or the task missing from Task Scheduler), start app-tail and accept the
administrator prompt: it repairs this at startup, and asks for the rights because it
cannot do it without them. Declining leaves the machine where it is, and app-tail says so
with the command that fixes it by hand: `app-tail dns restore` from a Command Prompt or
PowerShell started as administrator, or `sudo app-tail dns restore` on macOS and Linux.
If that reports a network service it could not reach, bring the adapter back (plug the
dock in, switch the radio on, re-enable it in Network Connections) and run it again.

**A feature says `this change needs an administrator's approval`.** Some changes to this
machine's networking are refused until an administrator approves them: carrying all
internet traffic, routes to public addresses or over your own LAN, making app-tail the
machine's resolver, answering for domains outside `ts.net`, each OpenVPN server, and
traffic interception. The message names each change and ends with the command that
approves it, for example `` An administrator approves it with `app-tail tun grant --full-tunnel` ``.
The dashboard and the tray menu (**Approve network changes…**) offer the same with one
password prompt on macOS once the helper is installed. Elsewhere, run the command from an
administrator's shell: `sudo app-tail tun grant ...` on macOS and Linux, or PowerShell
started as administrator on Windows. `app-tail tun grant --show` lists what is already
approved. See [Approving network changes](security.md#approving-network-changes).

**An OpenVPN connection says `the openvpn program is not installed on this machine`.**
Either there is no `openvpn` in the places app-tail looks, or the one there could be
changed by a normal account, and app-tail will not run that as root. The message names each
copy it refused and why, for example that a folder on the way to it `belongs to <you>
rather than to root`. Homebrew's openvpn is refused for this reason on every Mac. The fix,
and the list of places it looks, is under [OpenVPN](install.md#openvpn).

**Windows refuses with `app-tail is not installed where only administrators can change
it`.** The network-interface mode and the machine-wide resolver need administrator rights,
and app-tail will not ask for them from a folder you can write. Run
`app-tail-<version>-windows-amd64.exe install` from the unpacked folder and start the
installed copy; see [Install for all users in Program Files](install.md#install-for-all-users-in-program-files).

**macOS refuses to open the app.** It is not notarized. Run
`xattr -d com.apple.quarantine /Applications/App-Tail.app` once.

**The Windows GUI build prints nothing.** That is what `-H=windowsgui` does: the
process has no console to write to. The agent's own log is written to `app-tail.log` in
the state directory (`%APPDATA%\app-tail` by default) instead, so a start that fails is
readable there. Use the console `.exe` for any command whose output you want to read.

## Checking the machine with tun doctor

`app-tail tun doctor` (or plain `app-tail tun`) reads this machine and reports what app-tail
has installed outside its own folder. It needs no running agent and changes nothing. It
lists:

- whether this platform has a network-interface mode, and whether this process has
  administrator rights;
- the privileged helper on macOS: `installed and answering`, `installed, but not
  answering`, or not installed, with the command that installs it;
- anything **Missing** (on Windows, a missing or mismatched `wintun.dll`) or in
  **Conflict** (another tailnet client on this machine, such as the official Tailscale
  app);
- anything a previous run left behind, with the commands that remove it by hand;
- a resolver still pointed at app-tail after a run that did not clean up, with the
  `app-tail dns restore` command that puts it back.

On a machine with nothing to report it ends with `This machine is clean: app-tail has
nothing installed on it outside its own folder.` `--json` prints the same report as JSON,
which is the form to attach to a bug report once you have removed anything private.

## Checks that need a real tailnet

The automated suite runs without any network, using fakes at the tailnet boundary,
so these need a person and two real devices:

- Enrollment by all three auth paths: interactive login, `TS_AUTHKEY`, and an OAuth
  client secret with self-tagging.
- A `to_local` forward to SSH on another device, and a `to_tailnet` forward serving
  HTTP to one.
- UDP in both directions, DNS being the easy case.
- A forward to something your ACLs deny, confirming it surfaces as an error on that
  forward with a readable reason rather than failing silently.
- The macOS menu bar and the Windows notification area: status, the forwards
  toggle, the settings checkboxes, and quit.
- Start-at-login surviving a real reboot.
- Windows, with the machine-wide resolver on: `ipconfig /all` shows `127.0.0.153`, then
  `shutdown /r /t 0`. At the next boot, before starting app-tail, `ipconfig /all` must show
  the network's own resolvers and `%ProgramData%\app-tail\systemdns-restore.json` must be
  gone. Then reinstate the override, end app-tail with Task Manager so no teardown runs,
  and start it unelevated from Explorer: it must raise the UAC prompt, and accepting must
  make names resolve again.
- macOS with no helper installed: `sudo app-tail run`, turn the machine-wide resolver on,
  `kill -9` it, then `sudo app-tail run` again. It must repair on start. With the helper
  installed and an agent connected, `sudo launchctl bootout
  system/com.github.sellitus.app-tail.helper` must return in well under launchd's twenty
  seconds, with `networksetup -getdnsservers Wi-Fi` back to the network's own resolvers.
- Login by QR code from a phone.
