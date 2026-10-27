# Configuration

## Applying settings that need a restart

Most settings take effect the moment you save them. A few (the ones that define the
tailnet node's identity, such as the hostname, tags, control server or credentials)
only apply when the node is rebuilt. Rather than restarting the whole process (which
would drop the tray and any login supervision), the agent rebuilds just the tailnet
node in place:

- In the dashboard, saving such a change shows a **Restart now** button. Clicking it
  reconnects the node; active forwards are interrupted briefly and resume once it is
  back.
- Headless or in a container, run `app-tail restart`.

The one exception is the dashboard address itself: the listener serving the request
cannot move itself, so changing it needs a full process restart. The dashboard says
so and offers no button in that case.

If that address is taken when the app starts (most often by the instance it is
replacing, which has not let go of the port yet), it runs on a port the system assigns
instead and says so in a banner. The setting is left as you wrote it and is asked for
again on the next start, so a port that was busy for a moment never becomes the address
you are stuck on.

The dashboard address (`uiListenAddr` in the config, `--ui-addr` on the command line,
`APPTAIL_UI_ADDR` in the environment) must be a loopback address such as `127.0.0.1:8377`
or `[::1]:8377`. Anything else is refused with `must bind a loopback address`, because the
dashboard can change forwards and show the pending login link. The default, `127.0.0.1:0`,
takes any free port, and the agent records the port it got in `dashboard-address` (below).
To reach it from another machine, see
[Reaching the dashboard from another machine](deployment.md#reaching-the-dashboard-from-another-machine).

## Where state lives

Everything is under one directory, the OS user-config directory plus `app-tail`:

| Platform | Path |
|---|---|
| macOS | `~/Library/Application Support/app-tail` |
| Linux | `~/.config/app-tail` |
| Windows | `%AppData%\app-tail` |

It holds `config.json` (settings and forwards, written `0600` through a temp-file
rename so a crash cannot truncate it), `secrets.json` (every credential, kept out of
`config.json`; see [Where credentials are stored](security.md#where-credentials-are-stored)),
`api-token` (the API token the CLI signs in to the agent with, readable only by your account;
`app-tail auth rotate` replaces it), `dashboard-address` (where the running agent is
listening, so the CLI and the tray never guess a port; it is written when the agent binds
and removed when it stops), `agent.lock` (the claim that keeps one agent per config
document: an empty-looking file whose contents matter only while a run holds a lock on it,
so it is left in place between runs), the tailnet node identity, and `blocklists/` (one
downloaded file per [blocklist](dns.md#blocking) plus the `index.json` recording what each
contributed). Deleting the directory resets the device completely; it will enroll as a new
one next time.

Everything app-tail keeps for itself is in that directory. It changes things outside it only
for a feature you turn on, and each of those can be undone:

- the login item from `app-tail install-autostart` (see [Start at login](deployment.md#start-at-login));
- what [the network-interface mode](modes.md#the-network-interface-mode) installs: the root
  helper on macOS, a network adapter and a scheduled task on Windows;
- the approvals an administrator gives with `app-tail tun grant`, in a file only an
  administrator can write (see [Approving network changes](security.md#approving-network-changes));
- this machine's resolver and proxy settings, while app-tail is set to manage them, plus a
  record of what they were so they can be put back;
- the traffic-interception root certificate, when you add it to the trust store;
- on Windows, the copy `app-tail install` puts in Program Files.

`app-tail tun doctor` reads back what is installed and what a previous run left behind.

Override with `--state-dir`, or `--config` to move just the config file.

Credentials (auth keys, OAuth client secrets, WireGuard and OpenVPN keys and passwords, the
proxy password) are write-only across the API: they are stored in `secrets.json`, never in
`config.json`, and never sent back to the dashboard, which shows only whether one is set.
`secrets.json` is readable only by your account, and on Windows its contents are also
encrypted to your Windows account.

Every setting, with its key, CLI flag, default and when a change takes effect, is listed in
the [settings reference](settings.md), which is generated from the same registry the agent
reads. Precedence for every setting is flag, then environment, then config file.

| Environment variable | Sets |
|---|---|
| `APPTAIL_CONFIG` | path to `config.json` |
| `APPTAIL_STATE_DIR` | state directory |
| `APPTAIL_UI_ADDR` | requested dashboard address |
| `APPTAIL_HOSTNAME` | tailnet device name |
| `APPTAIL_HOSTNAME_TEMPLATE` | template used when no hostname is set |
| `APPTAIL_TAGS` | tags the node advertises |
| `APPTAIL_CONTROL_URL` | control plane (Headscale and friends) |
| `APPTAIL_EPHEMERAL` | enroll as an ephemeral node |
| `APPTAIL_ADVERTISE_TAGS_ON_LOGIN` | self-tag on browser login |
| `APPTAIL_HEADLESS` | no tray, no browser |
| `APPTAIL_AUTH_KEY` | auth key |
| `APPTAIL_OAUTH_CLIENT_SECRET` | OAuth client secret |
| `APPTAIL_OAUTH_CLIENT_SECRET_FILE` | file holding the OAuth client secret |
| `TS_AUTHKEY` | auth key, Tailscale's own name for it |
| `TS_CLIENT_SECRET` | OAuth client secret, Tailscale's own name for it |

The two `TS_*` names are honored so an existing Tailscale deployment's environment
works unchanged. Tailscale's other spellings, `TS_AUTH_KEY` and `TS_CONTROL_URL`, are removed
from the environment at start and ignored, so a stray one can never enroll a connection
into the wrong tailnet: use `APPTAIL_AUTH_KEY` and `APPTAIL_CONTROL_URL` instead. Prefer the
`*_FILE` form for secrets.
