# Security notes

[SECURITY.md](../SECURITY.md) has the threat model and how to report a vulnerability
privately. This page is the operational detail behind it.

## Blocking incoming connections and device posture

```
app-tail settings set security true
app-tail connection set office security.shieldsUp true
```

Shields and posture belong to one Tailscale connection rather than to the machine, so
`office` above is a connection's short name; `app-tail connection list` prints yours.

`security.shieldsUp` drops every connection other devices open to this one,
whatever your tailnet's ACLs allow; this device can still reach out. It is the
quickest way to make a machine tailnet-invisible without disconnecting it.

It also silences every forward that listens on the tailnet (the `to_tailnet`
direction). app-tail does not refuse that combination, because turning shields on
while such a forward exists may be exactly what you meant; instead the forwards
table marks each one it has silenced and says why. A forward that reports itself
running while refusing every connection is the thing to avoid.

`security.postureChecking` sends identifying details about this machine (serial
number, OS version, any device-management identifiers) to your tailnet, so admins
can write access rules against them. That information leaves the machine, so it is
off unless you turn it on, is never switched on by a preset, and sits in the
advanced tier with the plain description above rather than a one-word label.

## Traffic inspection

```
app-tail settings set ips true
app-tail settings set ips-mode prevent
```

Inspection covers what app-tail itself carries: the network interface in fabric mode, the
proxy and the port forwards, and connections other devices on the tailnet route through this
one. In tun mode the machine's own networking carries the tailnet's traffic, so nothing on
that path is inspected. `ips-mode` is `detect` until you change it, and `detect` records a
match without refusing anything.

### Levels

The feeds of known-bad addresses come as six levels, lowest first: `minimum`, `low`, `medium`,
`high`, `pro` and `ultimate`. `high` is the one to pick without reading the rest. A level
switches on exactly the shipped feeds it names and leaves any feed you added alone, and the
Traffic inspection card offers them as one choice. Over the API it is one call (the
[API reference](api.md#calling-the-api-from-a-script) shows where `$TOKEN` and `$ADDR` come
from):

```
curl -X POST "http://$ADDR/api/ips/preset" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"preset":"high"}'
```

The ordering is by how long an entry stays true rather than by how much each feed holds: the
low rungs carry networks criminals control outright, which nobody else is given next month,
and the high rungs carry addresses that attacked something recently, which age out and so
refuse traffic somebody wanted. The Tor exit list is on no level. Nothing on it is malicious,
and switching it on stops Tor working from this machine, so it stays a switch of its own.

### Opening encrypted connections

The last rung reads inside TLS, and it is the only part of app-tail that changes what the
program at the far end sees. It stays off until you set both the agreement and a mode:

```
app-tail settings set ips-intercept-agreed true
app-tail settings set ips-intercept only
app-tail settings set ips-intercept-only internal.example,10.20.0.0/24
```

`ips-intercept except` opens everything instead, leaving alone the destinations in
`ips-intercept-except`; left empty, the list app-tail ships applies, which covers the vendors
known to pin their own certificates (Apple, Microsoft, Google, Mozilla, Signal, Dropbox,
Docker, the certificate authorities and Tailscale itself). Add to it rather than emptying it.

`ips-intercept-agreed` is separate on purpose: a mode on its own opens nothing, so a restored
settings file or an upgrade cannot arrive with this running.

The first time it runs, app-tail generates a root certificate under the state directory,
`tls/ca.crt` and `tls/ca.key`, the key readable only by the account app-tail runs as. The key
is generated on this machine and never sent anywhere. Nothing is opened successfully until
you install the certificate yourself; the dashboard's inspection card prints the exact
command for this OS, and the command to remove it again. app-tail deliberately cannot install
it for you: a root in the trust store outlives app-tail and is a change to the whole machine.

The root is limited to what it was made for, and every program that trusts it enforces
that limit whoever holds the key. With `ips-intercept only` it can sign for the names and
networks listed and nothing else (X.509 name constraints, marked critical). With
`ips-intercept except` it can sign for anything except the destinations left alone. It can
sign server certificates and nothing else: no code signing, no mail, no client identities,
and no other certificate authority below it. It lasts one year, and the certificates it
mints last 30 days.

Change the list so it reaches past what the root was made for, and app-tail keeps the root
(it is the one you installed) and carries the new destinations untouched. The card and
`app-tail ips root` say a new root is needed. The same happens for a root made before roots
were limited, which can sign for any site. To replace a root, switch interception off, run
`app-tail ips remove-root`, switch it back on, and install the new root it generates.

From 30 days before the root expires, the card and `app-tail ips root` warn you, and say so
again once it has. app-tail never replaces an installed root on its own.

The card shows the root's SHA-256 fingerprint, the one your trust store lists it by. Anyone
who holds `tls/ca.key` can impersonate the sites the root covers to this machine, so keep it
private and remove the root when you stop using interception.

While this is on the inspection card reads as degraded, whatever else is healthy, and every
connection app-tail opens is readable in this process. Programs that pin their own
certificates fail rather than being inspected, and a connection whose real server does not
verify is stopped rather than carried unread. Mutual TLS cannot be opened at all.

If the pair under `tls/` is damaged or half-present, app-tail refuses to run interception and
says so, rather than generating a replacement. A second root would leave the one you
installed in the trust store, unaccounted for, while a certificate you have never seen starts
signing. With interception switched off, `app-tail ips remove-root` takes the old
certificate out of the trust store and deletes both files, which starts over.

## Approving network changes

The root helper makes the changes to this machine's networking that app-tail cannot make
itself. It makes the safe ones for anybody, and refuses the rest until an administrator has
approved them, so an account that can run app-tail cannot use the helper to take over the
machine's traffic.

These need no approval:

- Routes inside private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), the CGNAT
  range the tailnet uses (`100.64.0.0/10`), `198.18.0.0/15` (the pool the fabric moves
  networks into) and IPv6 unique-local addresses (`fc00::/7`), as long as the route does not
  overlap a network this machine is already on. A route over your own LAN would take the LAN
  away from the machine.
- Resolvers on loopback or inside the tailnet, answering for names under `ts.net`.

These need an administrator's approval:

- Carrying all internet traffic (a full tunnel, including the two-halves form OpenVPN uses).
- Routes to public addresses, and private routes that overlap a network this machine is on.
- Making app-tail the machine's own resolver (system DNS), a resolver outside the tailnet, or
  a resolver that answers every lookup.
- Answering for any domain outside `ts.net`.
- Each OpenVPN server, approved together with the certificate authority it is trusted with. A
  server approved with one certificate authority still needs approval for another.
- Traffic interception.

An OpenVPN server also hands this machine an address, and that address puts its whole network
on the new interface, much like a route. The helper holds it to the same rules: once the
connection is up, it reads the addresses the interface ended up with, and stops the
connection when one of them needs an approval that is not there. Between the server's answer
and that check, which is the time it takes OpenVPN to finish starting, traffic for the
server's network can already go through the tunnel.

When something is refused, the dashboard lists each waiting change in plain words with an
**Approve…** button, and the tray adds **Approve network changes…** for as long as something
is waiting. On macOS with the helper installed, approving shows the administrator password
dialog once for the whole list, and app-tail tries each refused feature again right after.
On Linux and Windows, and on macOS before the helper is installed, app-tail cannot raise that
prompt, so it shows the `app-tail tun grant ...` command to run from an administrator's shell
(`sudo` on macOS and Linux, PowerShell started as administrator on Windows).
`app-tail tun setup` approves everything the current config asks for while it installs
the helper, with the same password; `--config PATH` points it at a config other than the
default.

Approvals live in one file that only an administrator can write:

| System | File |
|---|---|
| macOS | `/Library/Application Support/app-tail/grants.json` |
| Linux and other Unix | `/etc/app-tail/grants.json` |
| Windows | `ProgramData\app-tail\grants.json` |

On macOS and Linux the file and every folder above it must belong to root and be writable by
nobody else; on Windows they must belong to the administrators. If the file is missing,
nothing is approved. If it is there but fails those checks or does not parse, the helper and
app-tail refuse everything that needs an approval, with an error naming the file and what is
wrong with it. The helper's refusal shows up in that feature's own error; for traffic
interception it is on the inspection card.

`app-tail tun grant --show` prints what is approved and changes nothing. There is no
command to take an approval back. To revoke one, edit `grants.json` as an administrator
and remove the entry. The helper reads the file on every request, so the next
change that needs the removed approval is refused.

## Security notes

`SECURITY.md` has the threat model and how to report something. In short:

The dashboard API binds to loopback only and answers only callers holding the API
token in `api-token`, which only your account can read; the dashboard gets a session
from a one-time link the tray or `app-tail dashboard` opens. That link travels on a
command line other accounts can read, so on macOS and Linux it only signs in a browser
running as your account, and a session ends when the agent stops, so a session copied
out of a browser is dead after the next restart. The config refuses any non-loopback
dashboard address on every path, including a hand-edited `config.json`; there is no
flag that will let you bind it to `0.0.0.0`. For remote access, forward the port over
SSH and sign in with `app-tail dashboard --print`; [Deployment](deployment.md) walks
through it.

The tailnet proxy, when you turn it on, is loopback-only for the same reason and
carries the same caveat: a `127.0.0.1` bind restricts by host, not by user, so every
local process can use it. There is no portable way to check the peer credentials of a
loopback TCP connection, so this is a property of the feature rather than something a
later release tightens. `proxy.requireToken` is the answer if you need one.

## Where credentials are stored

The credentials you enter in the dashboard or the CLI live in `secrets.json`, beside
`config.json` in the state directory (`/data` in the Docker image). They are a tailnet's auth
key and OAuth client secret, a WireGuard private key and pre-shared key, an OpenVPN private
key, its passphrase, its password and its tls-crypt or tls-auth key, and a proxy's password.
`config.json` holds none of them, so you can read it, diff it, back it up or attach it to a
bug report without handing over a key. An OAuth secret file you point app-tail at stays where
you put it; only its path is in `config.json`.

`secrets.json` is written `0600` through a temp-file rename, so only your account can read it
and a crash cannot truncate it. On Windows, where an administrator can take over any file's
access list, the contents are also encrypted with DPAPI to your Windows account: another
account, or a copy of the file on another machine, cannot decrypt it. macOS and Linux rely on
the file permissions alone; the macOS Keychain is not used.

Each credential is filed under the id of the connection or proxy it belongs to, so renaming
or reordering connections never mixes them up. Deleting a connection deletes its credentials
from the file.

A tailnet connection's auth key and OAuth secret are also filed with the control server they
were entered for, and app-tail only gives them back to a connection that still names that
server. Pointing a connection at another server clears them, unless you enter them again in
the same change. If `config.json` and `secrets.json` ever come from different moments, after
a crash between the two writes of a save or after restoring an older `config.json`, a key
saved for one server is never handed to another; that connection asks for its credential
again instead.

If `secrets.json` is there but cannot be read or decrypted, app-tail refuses to start and
names the file, rather than starting without your credentials. `app-tail config check`
reports the same error. Restore the file from a backup, or move it aside and enter the
credentials again.

Copies of `config.json` that app-tail keeps follow the same rule. The copy taken before a
document is upgraded (`config.json.v<N>.bak`) has its credentials removed, and restoring it
keeps the credentials in `secrets.json`. When `app-tail config reset`, or a document this
build cannot use, sets `config.json` aside, `secrets.json` is set aside with it under the same
suffix (`secrets.json.replaced-…`, `secrets.json.unusable-…`), so the defaults start with no
credentials and `app-tail config restore` of that copy brings them back.

A `config.json` written by an older build that kept credentials inline still loads. Its
first save moves them into `secrets.json`.

## Passing secrets to app-tail

Pass secrets by environment variable or a `*_FILE` setting, never on the command
line: an argument is visible to every process on the machine. `bootstrap-policy`
takes `--client-secret-file` for the same reason, and there is deliberately no flag
that accepts a literal secret.

`--allow-foreign-api-url` exists only to point `bootstrap-policy` at a control plane
you run yourself. It relaxes the host rule and nothing else: cleartext off loopback
stays refused.
