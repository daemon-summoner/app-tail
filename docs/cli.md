# The command line

## Commands

<!-- commands:begin -->
```
  app-tail [run] [flags]                                                start the agent and its dashboard
  app-tail status [--json]                                              show the tailnet connection state
  app-tail dashboard [--print] [--base URL]                             open the dashboard, already signed in
  app-tail login                                                        start an interactive login
  app-tail logout                                                       disconnect this device from the tailnet
  app-tail restart                                                      rebuild the tailnet node to apply settings
  app-tail list [--json]                                                list configured forwards
  app-tail add --target HOST:PORT                                       add a forward
  app-tail rm NAME-OR-ID                                                remove a forward
  app-tail forward get|update|enable|disable|toggle ID                  inspect or change one forward
  app-tail connection list|get|add|set|import|rm|enable|disable|retry   manage the private networks this machine is attached to
  app-tail route list|add|rm|move|check|clear                           send some destinations through a different connection
  app-tail peers [--json]                                               list tailnet devices this node can see
  app-tail exec -- COMMAND                                              run a command with the tailnet proxy set for it
  app-tail proxy status|system|connect|probe                            use or inspect the tailnet proxy
  app-tail automap [forget]                                             inspect the ports opened for every device
  app-tail lock [log|sign NODEKEY]                                      show why tailnet lock is holding this device back
  app-tail ips root|remove-root                                         show or remove the traffic-interception root certificate
  app-tail dns [use NAME|profile|block|setup|restore]                   show or switch how this machine and app-tail resolve names
  app-tail tun setup|doctor|install-helper|uninstall-helper|grant       set up or inspect the network-interface mode
  app-tail health [--json]                                              report whether the agent is ready to carry traffic
  app-tail log [--follow] [filters]                                     show what the agent has been doing
  app-tail settings get|list|set|menu                                   read or change agent settings
  app-tail config check|restore|reset                                   inspect or repair the configuration document
  app-tail auth rotate                                                  replace the API token and sign out every dashboard
  app-tail preset list|add|rm                                           manage service templates
  app-tail autostart status                                             show whether app-tail starts at login
  app-tail provision --profile FILE                                     apply a fleet profile to the local config
  app-tail install                                                      install app-tail for all users in Program Files (Windows)
  app-tail install-autostart                                            start app-tail when you log in
  app-tail bootstrap-policy                                             prepare a tailnet policy for a fleet
  app-tail version                                                      print the version
  app-tail licenses                                                     print the third-party license notices
```
<!-- commands:end -->

`./verify.sh` diffs this block against the binary's own `--help`, so it cannot go
stale: the table lives once, in `internal/cli/registry.go`.

`status`, `dashboard`, `login`, `logout`, `restart`, `list`, `add`, `rm`, `forward`,
`connection`, `route`, `peers`, `exec`, `proxy`, `automap`, `lock`, `ips`, `dns`, `health`,
`log`, `settings` and `preset` talk to a running agent over the same loopback API the
dashboard uses, and fail if none is running.
`exec` and `proxy` additionally need the proxy module switched on, and say so if it
is not. Two commands repair the machine with or without a running agent, because the state
they fix is the one a killed agent leaves behind: `app-tail proxy system off` puts this
machine's own proxy settings back, and `app-tail dns restore` (run as administrator) puts its
resolver back.
`tun`, `config`, `auth`, `version`, `licenses`, `provision`, `install`,
`install-autostart`, `autostart` and `bootstrap-policy` work offline. Any
command takes `--help` for its own flags. In a source checkout that has been built once,
`go run . <command> --help` prints them without starting an agent.

### Signing in

The loopback API answers only callers holding the agent's API token. The agent writes
it to `api-token` beside the config file, readable only by the account the agent runs
as, and the CLI reads it from there, so commands run from that account need nothing
extra. Scripts that call the API directly send the same token; see
[Authentication](api.md#authentication). Before sending the token, the CLI asks whatever is
listening on the recorded port to prove it holds the same token; anything that cannot is refused with
`something other than your app-tail agent is listening on ...`, and the token never
leaves the CLI.

A browser cannot read the token file, so the dashboard signs in with a one-time link
instead. The tray menu opens one. `app-tail dashboard` opens one too, or prints it with
`--print` for a machine with no browser. A link works once and expires after two
minutes; the dashboard then stays signed in for 30 days or until the agent stops. On
macOS and Linux an opened link only signs in a browser running as your account, because
other accounts on the machine can read the command line it was handed over on. A printed
link signs in from any account, so give it only to whoever should have the dashboard.
`--base URL` moves the link to another `scheme://host:port`, keeping its path and one-time
token. Use it for the Vite dev server
(`app-tail dashboard --print --base http://localhost:5173`) or for an SSH tunnel to a
remote agent: forward a local port to the remote dashboard, run
`app-tail dashboard --print --base http://127.0.0.1:<local port>` on the remote host, and
open the link on your own machine. The full steps are in
[Reaching the dashboard from another machine](deployment.md#reaching-the-dashboard-from-another-machine).

`app-tail auth rotate` writes a new token and signs out every dashboard at once. Use
it if a link or the token was shared by mistake. With no agent running it deletes the
token file, and the agent writes a new one the next time it starts.

`app-tail config check` reports whether the stored document loads and lists every
copy kept beside it; `config restore` puts one of those copies back, and `config
reset` starts from the defaults. Both keep the document they replace, so either is
undoable. A document this app cannot use never stops it from starting: it is moved
aside on load and the defaults take its place, and every surface says so.

`app-tail settings menu` is an interactive terminal editor over the same settings
registry the dashboard's drawer is generated from.

### The network-interface mode and approvals

`app-tail tun` covers what app-tail installs on the machine and what an administrator has
approved. None of it needs a running agent.

| Command | Does |
|---|---|
| `app-tail tun doctor` (or `app-tail tun`) | Reports whether this machine can run the network-interface mode, the state of the root helper, anything missing or in conflict, and anything a previous run left behind. Changes nothing. `--json` for a script or a bug report. |
| `app-tail tun setup` | On macOS, installs the root helper behind the system password prompt, and approves the network changes the current config asks for with the same password. |
| `sudo app-tail tun install-helper` | The same install for a script. `--grant` also approves what the config asks for; `--owner UID` names the account the helper takes commands from (by default, the one that ran `sudo`). |
| `sudo app-tail tun uninstall-helper` | Removes the helper and everything it installed. The contained mode keeps working. |
| `app-tail tun grant ...` | Approves network changes, run as administrator: `--full-tunnel`, `--route CIDR`, `--system-dns`, `--dns-domain NAME`, `--openvpn host:port=SHA256`, `--tls-interception`. `--show` prints what is approved and changes nothing. |

The helper install commands are for macOS. On Linux the helper runs in the foreground with
`sudo APPTAIL_HELPER_OWNER=$(id -u) app-tail tun helper` (the variable names the account
it takes commands from; without it the helper refuses everyone but root), and on Windows app-tail asks for administrator rights itself when
it needs them. Which changes need an approval, and where approvals are kept, is in
[Approving network changes](security.md#approving-network-changes).

### The traffic-interception root

`app-tail ips root` shows the root certificate traffic interception signs with: its
file, its SHA-256 fingerprint (the way a trust store lists it), when it expires, what it
can sign for, and whether this machine trusts it. It also prints any warning about the
root expiring within 30 days or needing to be replaced. `--json` prints the agent's
answer as it is.

`app-tail ips remove-root` takes the root out of this machine's trust store and deletes
its key and certificate. It runs the trust-store commands in your terminal, printing each
one first, so `sudo` (or, on Windows, an administrator prompt) asks you directly; the
agent never changes what the machine trusts. It refuses while interception is switched
on, because a new root would be generated straight away: run
`app-tail settings set ips.intercept off` first. If a trust-store command fails, the files
are kept so you can run it again. For a root that was never installed, or one you
removed by hand, `--files-only` deletes the files and leaves the trust store alone.
