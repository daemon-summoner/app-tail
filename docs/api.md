# HTTP API

Loopback only, JSON, and every route under `/api/` needs a token (see
[Authentication](#authentication)). Every request must carry a loopback `Host`; every
state-changing request must carry an `Origin` matching it. Both guards are what stop a
hostile web page from rebinding its own domain to `127.0.0.1` and reading your pending
login URL, so neither is relaxable. See [Security notes](security.md).

The dashboard is the only client this is designed for. It is stable in the sense that the
dashboard shipping in the same binary uses it, and no further: routes may change with the
UI they serve. The CLI talks to these same routes, so `app-tail <command> --json` is the
supported way to script app-tail.

Find the address the agent is actually on in `<stateDir>/dashboard-address` rather than
assuming a port. `app-tail settings get uiListenAddr` prints what was asked for, which is
not always what was bound.

## Authentication

Send `Authorization: Bearer <credential>` on every `/api/` request. A request without
a valid credential gets 401 with `WWW-Authenticate: Bearer realm="app-tail"`, and the
agent logs the refusal without the credential. `/healthz`, `/proxy.pac` and the
dashboard's own files need no credential.

There are two kinds of credential:

- The API token. The agent writes it to `api-token` beside the config file, mode 0600 and
  owned by the account the agent runs as. Scripts read it from there, from that account.
- A session. A browser cannot read the token file, so it trades a one-time launch token
  for a session. The tray menu and `app-tail dashboard` open `/?launch=<token>`. A launch
  token works once and expires after two minutes. A session lasts 30 days or until the
  agent stops, whichever comes first.

The tray and `app-tail dashboard` hand the link to the browser on its command line, which
on macOS and Linux every account on the machine can read. So a link minted for opening is
bound to the agent's account: on macOS and Linux it is only redeemed over a connection a
process of that account holds, and anything else gets 403 and leaves the link unspent for
the browser it was meant for. A link minted with `{"anyAccount": true}` skips that check;
`app-tail dashboard --print` asks for one, because a printed link is for a person who may
open it from another account, such as a Docker host or the far end of an SSH tunnel.

Rotating the token ends every session at once.

| Method | Path | Does |
|---|---|---|
| POST | `/api/auth/session` | `{"launch": "..."}` → `{"session": "..."}`. Needs no credential; an unknown, used or expired launch token gets 401, and a link bound to the agent's account redeemed from another account gets 403 |
| POST | `/api/auth/hello` | `{"nonce": "..."}` → `{"proof": "..."}`. Needs no credential. The nonce is 16 to 64 bytes of unpadded base64url. The proof is unpadded base64url HMAC-SHA256, under a key derived from the token, of the nonce, a newline and the address the connection arrived on. It lets a client confirm it reached the agent before sending the token |
| POST | `/api/auth/launch` | optional `{"anyAccount": true}` → `{"url": "http://<host>/?launch=..."}`, a fresh sign-in link for the host the caller dialed. Without `anyAccount` the link is bound to the agent's account |
| POST | `/api/auth/rotate` | write a new token and end every session; answers 204 |

### Calling the API from a script

The token and the address the agent actually bound both live in the state directory:
`~/Library/Application Support/app-tail` on macOS, `~/.config/app-tail` on Linux,
`%APPDATA%\app-tail` on Windows and `/data` in the Docker image.

```sh
STATE="$HOME/Library/Application Support/app-tail"
TOKEN="$(tr -d '[:space:]' < "$STATE/api-token")"
ADDR="$(tr -d '[:space:]' < "$STATE/dashboard-address")"

# Read
curl -s -H "Authorization: Bearer $TOKEN" "http://$ADDR/api/status"

# Write: a body must be declared as JSON
curl -s -X PUT "http://$ADDR/api/settings" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"proxy.enabled": true}'
```

Two things trip people up. A write whose body is sent as anything but
`application/json` gets 415, and curl's `-d` sends form encoding unless you set the
header, as above. And settings are patched by their flat key (`"proxy.enabled"`, not
`{"proxy": {"enabled": true}}`); [the settings reference](settings.md) lists every key.

If a script cannot be sure the address file is current, it can make the agent prove
itself before sending the token, the way the CLI does: POST a random nonce to
`/api/auth/hello` and check the HMAC in the answer. `app-tail auth rotate` replaces a
token that has leaked.

## Node and session

| Method | Path | Does |
|---|---|---|
| GET | `/api/status` | tailnet state, node name, addresses, pending login URL |
| POST | `/api/login` | start an interactive login |
| POST | `/api/login/url` | the pending login URL. A POST because the same-origin guard applies to state-changing methods only, so a page you did not open cannot read it |
| POST | `/api/logout` | disconnect this device |
| POST | `/api/restart` | rebuild the tailnet node in place |
| POST | `/api/restart-app` | restart the whole process. Answers 202 before anything begins, because the listener serving the request goes away with it |
| POST | `/api/quit` | stop the whole process, with no replacement started. How a second copy of app-tail asks the one already running to hand over; answers 202 for the same reason the restart does |
| GET | `/api/peers` | tailnet devices this node can see |
| GET | `/api/prefs` | the settings this app keeps on the node, beside what the node says they are. A save that stored fine and never reached the tailnet is otherwise invisible |

## Forwards

| Method | Path | Does |
|---|---|---|
| GET | `/api/forwards` | list forwards |
| POST | `/api/forwards` | create one; the 201 body reports the running state |
| GET | `/api/forwards/suggest-port` | a free local port for a target |
| GET | `/api/forwards/{id}` | one forward |
| PUT | `/api/forwards/{id}` | replace one |
| DELETE | `/api/forwards/{id}` | remove one |
| POST | `/api/forwards/{id}/toggle` | enable or disable one |

## Connections

| Method | Path | Does |
|---|---|---|
| GET | `/api/tunnels` | every configured connection and its live state |
| POST | `/api/tunnels` | add one |
| GET | `/api/tunnels/schema` | the connection field registry, per kind |
| GET | `/api/tunnels/{id}` | one connection |
| GET | `/api/tunnels/{id}/peers` | the devices that connection can see |
| PUT | `/api/tunnels/{id}` | patch its settings |
| POST | `/api/tunnels/{id}/import` | import a `wg-quick` or `.ovpn` configuration into it |
| POST | `/api/tunnels/{id}/retry` | reconnect one that failed |
| DELETE | `/api/tunnels/{id}` | remove one |

## Settings and presets

| Method | Path | Does |
|---|---|---|
| GET | `/api/settings` | current settings; secrets appear only as set or unset |
| PUT | `/api/settings` | patch settings |
| GET | `/api/settings/schema` | the field registry the dashboard renders from |
| GET | `/api/presets` | service templates |
| POST | `/api/presets` | add one |
| DELETE | `/api/presets/{id}` | remove one |

## Mode, interface and fabric

| Method | Path | Does |
|---|---|---|
| GET | `/api/tun` | what the interface mode needs and what this machine has, read fresh on every call |
| POST | `/api/tun/setup` | install the privileged helper, the dashboard's half of `app-tail tun setup` |
| POST | `/api/tun/approve` | ask an administrator to approve every network change that is waiting, then try each refused feature again. Takes no body; answers with what is still waiting |
| GET | `/api/fabric` | the fabric's addressing: which network is presented where, and every collision |

When the root helper refuses a change because nobody has approved it, `/api/status` carries an
`approvals` object: `needs`, one entry per waiting change (`kind`, `value`, `caSha256` for an
OpenVPN server, `reason` in plain words, and `features`, the parts of app-tail that asked for
it), and `command`, the `app-tail tun grant` line that approves them all from an administrator's
shell. The field is absent when nothing is waiting, and a feature you switch off drops what it
was waiting for. See [Approving network changes](security.md#approving-network-changes).

`POST /api/tun/approve` approves the agent's own list; nothing in the request can add to it.
With nothing waiting it raises no prompt and answers `{"needs":[],"command":""}`. On macOS with
the helper installed it shows the administrator password dialog; a dismissed dialog answers
409 and leaves the list as it was. On Linux, on Windows, and on macOS without the helper,
app-tail cannot raise the prompt itself, so it answers 501 with the command to run instead.

## Routing and egress

| Method | Path | Does |
|---|---|---|
| GET | `/api/routes` | the tailnet's subnet routes: what this device reaches and what it offers |
| POST | `/api/routes/check` | ask each device carrying a route whether it answers |
| GET | `/api/routing` | the per-destination rules, in order |
| PUT | `/api/routing/rules` | replace the rule list |
| POST | `/api/routing/check` | which way one destination goes |
| GET | `/api/egress` | where internet traffic leaves, and whether it is carried or held |
| GET | `/api/exitnode` | the exit node in use, which under rotation is not the configured one |
| POST | `/api/exitnode/suggest` | ask the tailnet for a device to use |

## Proxy

| Method | Path | Does |
|---|---|---|
| GET | `/api/proxy` | the proxy every install has |
| POST | `/api/proxy/probe` | check that it answers |
| GET | `/api/proxy/system` | whether this machine's own proxy settings point at app-tail |
| GET | `/api/proxies` | every proxy instance |
| POST | `/api/proxies` | add one |
| GET | `/api/proxies/schema` | the proxy field registry |
| GET | `/api/proxies/{id}` | one instance |
| PUT | `/api/proxies/{id}` | patch it |
| PUT | `/api/proxies/{id}/rules` | replace its scope rules |
| POST | `/api/proxies/{id}/test` | check that one answers |
| DELETE | `/api/proxies/{id}` | remove one |
| GET | `/proxy.pac` | the browser auto-config script. Deliberately not under `/api`: a browser fetches it by a URL somebody reads and types |

## DNS

| Method | Path | Does |
|---|---|---|
| GET | `/api/dns` | both halves: what your tailnet publishes and what this machine resolves with |
| POST | `/api/dns/setup` | install the privileged helper for the system-wide resolver |
| GET | `/api/dns/profiles` | the resolver profiles, shipped and your own |
| POST | `/api/dns/profiles` | add one |
| PUT | `/api/dns/profiles/{id}` | change one |
| DELETE | `/api/dns/profiles/{id}` | remove one |
| GET | `/api/dns/block` | blocking state, per list, with what each contributed |
| POST | `/api/dns/block/refresh` | download now |
| POST | `/api/dns/block/pause` | pause blocking for a duration |
| POST | `/api/dns/block/resume` | end a pause |
| POST | `/api/dns/block/preset` | switch the shipped lists to one rung of the curated ladder; answers with what is on now |
| GET | `/api/dns/block/check` | which list stops a name, or why nothing does |
| POST | `/api/dns/block/lists` | add a list of your own |
| PUT | `/api/dns/block/lists/{id}` | change one |
| DELETE | `/api/dns/block/lists/{id}` | remove one |

## Traffic inspection

| Method | Path | Does |
|---|---|---|
| GET | `/api/ips` | what the rules hold, per feed, with what each contributed, and the recent matches |
| POST | `/api/ips/refresh` | download every enabled feed now |
| POST | `/api/ips/pause` | pause inspection for a duration |
| POST | `/api/ips/resume` | end a pause |
| POST | `/api/ips/preset` | switch the shipped feeds to one rung of the curated ladder; answers with what is on now |
| GET | `/api/ips/check` | what the rules say about one destination, or why nothing does |
| POST | `/api/ips/intercept/remove-root` | delete the traffic-interception root's key and certificate; refused with 400 on `ips.intercept` while interception is on. Taking the root out of the trust store is `app-tail ips remove-root`'s job, run in your terminal |
| POST | `/api/ips/feeds` | add a feed of your own |
| PUT | `/api/ips/feeds/{id}` | change one |
| DELETE | `/api/ips/feeds/{id}` | remove one |

Traffic interception needs an administrator's approval before it runs. While it is switched on
and not approved, the `intercept` object in `/api/ips` keeps `on: true` and carries
`awaitingApproval`, the reason it is waiting. If the approvals file cannot be read, it carries
`approvalError` instead, and interception stays off until the file can be read.

## Tailnet lock

| Method | Path | Does |
|---|---|---|
| GET | `/api/lock` | whether lock is on, whether this device is signed, and which peers it holds back |
| GET | `/api/lock/log` | the lock's own log |
| POST | `/api/lock/sign` | sign another device, from one holding a trusted key |
| POST | `/api/lock/disable-local` | rebuild this device's copy of the lock from the control plane. This device alone; the tailnet's lock stays on |

## Traffic, telemetry and automatic ports

| Method | Path | Does |
|---|---|---|
| GET | `/api/traffic` | the sampled traffic window, all lanes |
| GET | `/api/traffic/{lane}` | one lane split by what that lane names. One route per lane so a dashboard pays only for the split it is drawing |
| GET | `/api/telemetry` | counters |
| GET | `/api/telemetry/events` | the event stream behind the activity view |
| GET | `/api/automap` | the ports opened for every device |
| POST | `/api/automap/forget` | forget a mapping |

## Machine integration

| Method | Path | Does |
|---|---|---|
| GET | `/api/autostart` | whether the login item is installed |
| POST | `/api/autostart` | install or remove it |
| POST | `/api/policy/preview` | what tag setup would change |
| POST | `/api/policy/apply` | apply it |

## Health

| Method | Path | Does |
|---|---|---|
| GET | `/healthz` | 200 only when the node is Running and every enabled forward is listening; otherwise 503 with a `reason` |

Everything else under `/` serves the embedded dashboard.
