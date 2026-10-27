# Connections

A connection is one attachment to one private network. app-tail holds several at once,
and every other feature (forwards, the proxy, DNS, routing, fabric) is written against
the set of them rather than against one.

Three kinds ship:

| Kind | How it connects | What it costs |
|---|---|---|
| **Tailscale** | a userspace WireGuard node ([`tsnet`](https://tailscale.com/kb/1244/tsnet)) enrolled as its own device | nothing on the machine changes |
| **WireGuard** | a userspace device against one server, inside this process | nothing on the machine changes |
| **OpenVPN** | the `openvpn` program installed on this machine, run as root by the privileged helper | a real network interface appears, each server needs an administrator's approval; macOS and Linux only |

## Adding one

```
app-tail connection list
app-tail connection add --type wireguard --name "Office" --from-file office.conf
app-tail connection add --type openvpn  --name "Lab"    --from-file lab.ovpn
app-tail connection get office            # every setting this connection takes
app-tail connection set office wg.mtu 1380
app-tail connection enable office         # and disable, retry, rm
```

`--from-file` imports a configuration the server issued (a `wg-quick` `.conf` or an
`.ovpn` profile) into the connection once it exists. `app-tail connection import NAME
FILE` does the same to a connection you already have, which is how you take a re-issued
profile without rebuilding anything around it.

A connection's short name comes from `--name` (`"Office"` becomes `office`); `--slug`
picks it yourself. Every command takes the name, the short name or the connection's ID
(the `tn_` code `app-tail connection list` prints). The tailnet app-tail starts with is
called `tailnet`.

**Secrets never go on a command line.** `connection set` refuses a secret field passed as
an argument, because an argument is readable by every process on the machine and lands in
your shell history. Use `--value-file FILE` or `--value-stdin`.

### OpenVPN

For OpenVPN, nothing about the connection is a file app-tail hands over. The stored
settings cross the privilege boundary as typed values, the helper renders the
configuration itself from a fixed template (no scripts, no plugins), and an account the
server asks for is answered over the management socket, so it is never written anywhere
at all.

The server does not get to decide what this machine does with its traffic. Routes and
DNS servers the server pushes are ignored. The networks the connection carries are the
ones in `ovpn.routes` ("Networks this connection carries"), and the connection shows the
routes the server offered so you can copy the ones you want. Its resolvers are
`ovpn.dns`.

**Each server needs an administrator's approval**, together with the certificate
authority it is trusted with, because the helper runs `openvpn` as root on your behalf.
Until then the connection does not start, and the dashboard lists it with an
**Approve…** button. [Approving network changes](security.md#approving-network-changes)
covers how that works. From an administrator's shell the command is `app-tail tun grant
--openvpn HOST:PORT=SHA256`, where the hash is the SHA-256 of the CA certificate; where
the dashboard cannot ask for the password itself, it prints the exact line for your
connection.

**app-tail only runs an `openvpn` that root controls.** Since it runs as root, the program,
every folder on the way to it and every library it loads must belong to root and be
writable by nobody else. Otherwise anything running as you could replace it and get root.
The places it looks:

- **macOS:** `/Library/PrivilegedHelperTools/app-tail/openvpn` first, then
  `/opt/homebrew`, `/usr/local`, `/usr/sbin` and `/usr/bin`. A Homebrew install is
  refused, because Homebrew's folders and libraries belong to your account. Copy a
  statically linked build (Tunnelblick's works) into the first spot:

  ```
  sudo mkdir -p /Library/PrivilegedHelperTools/app-tail
  sudo install -o root -g wheel -m 755 /path/to/openvpn /Library/PrivilegedHelperTools/app-tail/openvpn
  ```

- **Linux:** `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`, `/usr/local/sbin` and
  `/usr/local/bin`. Your distribution's `openvpn` package passes as installed.

When the check fails, the connection's error names the exact file or folder that is
wrong. OpenVPN is not available on Windows.

## Names: every connection answers for a suffix of its own

Each connection has a short name, and every host on it is reachable as
`<host>.<shortname>.<zone>`. The zone defaults to `internal`, the top-level domain
reserved for private use, which will never be delegated to anybody.

```
app-tail settings set dns-zone corp.example.com   # move the zone
```

This is what makes two networks that use the same addresses usable at the same time. If
`office` and `lab` both carry `10.0.0.5`, then `db.office.internal` and `db.lab.internal`
are two different machines and both work at once. A name carrying a connection's suffix
is answered by that connection or not at all, never by another one that happens to hold
the same address. See [DNS](dns.md#names-on-your-connections) for the whole of it.

The suffix comes from the short name rather than being stored beside it, so renaming a
connection renames its names too and a stale suffix cannot be left pointing at a
different network.

## What reaches a connection

A connection does not put the machine on its network. What reaches it depends on the
[run mode](modes.md):

- **Standalone and Proxy:** app-tail's own forwards and its proxy reach it, and nothing
  else on this machine does, because nothing else has a route there.
- **Network interface:** the tailnet is on a real interface; other connections are still
  reached through the forwards and the proxy.
- **Fabric:** every connection is on the interface, so every program on the machine
  reaches all of them by address.

An OpenVPN connection is the exception on macOS and Linux: `openvpn` creates its own
interface, so the networks in its `ovpn.routes` are on the machine whatever mode app-tail
is in. The machine's routing table has one winner per address range, which is why two
OpenVPN connections carrying the same range cannot both be reached at their real
addresses. That is what fabric exists for.

WireGuard is one server per connection. The configuration format allows several peers
because it also describes meshes; a client dialling one gateway is what this connects,
and two gateways are two connections with their own names and their own place in the
addressing report.

## Sending internet traffic through them

Which connection carries the traffic your networks do not, and how to chain several,
one inside the next, is [Routing](routing.md#where-internet-traffic-leaves).

## Tailnet lock

If your tailnet has tailnet lock switched on, a device only reaches its peers once
somebody holding a trusted key has signed it. app-tail joins as a brand-new device, so a
fresh install starts out unsigned. What that looks like without an explanation is
the worst kind of bug report: the node connects, reports `Running`, and reaches nothing
at all.

So this one has no setting. The dashboard's tailnet lock card appears whenever your
tailnet has lock on, and `app-tail lock` says the same thing in a terminal:

```
app-tail lock
app-tail lock log
```

An unsigned device is told exactly what to do about it: the card and the command both
print the `tailscale lock sign` line built from this device's own keys, to run on any
device that already holds a trusted key. Nothing has to be typed back in; this device
reconnects on its own once the signature lands.

The card also lists the devices lock is holding *back*: peers your tailnet shows this
device that it cannot talk to, because they are unsigned themselves. That is the other
unexplainable screen: everything looks connected and half the tailnet is unreachable,
however your access rules read.

From a device that holds a trusted key, `app-tail lock sign NODEKEY [TLPUBKEY]` signs
another device, and the dashboard offers the same thing as a form. Setting up lock for a
tailnet, and the recovery ceremonies that go with it, are deliberately not here. They
belong in the admin console, where the disablement secrets they depend on are handled
properly.

## Tags, ACLs and groups

app-tail is a device on your tailnet, so your policy file governs what it can reach and
who can reach it. It grants no access of its own. A forward to a service your ACLs deny
does not fail at creation; it fails when it tries to connect, and the dashboard shows
that forward in an error state with the reason.

The clean way to write rules for a set of app-tail devices is to give them all the same
**tag** (`tag:app-tail` by default) and target that tag in your policy. A tag is
Tailscale's grouping mechanism: `tagOwners` says who may apply it, and grants can name it
as a source or destination instead of listing devices one by one.

The dashboard's **Tag setup** button (on the connection card) helps you get there three
ways:

- Click-by-click instructions for the admin console's visual editor, for the common case
  of creating one tag by hand.
- A copy-paste HuJSON snippet with the `tagOwners` entry and an example grant for your
  configured tags. This is always available, including on Headscale.
- One-click apply: give it an OAuth client with the `policy_file` scope and it writes the
  same `tagOwners` entry to your tailnet directly, previewing the change first and making
  no write when the policy already covers it.

A device only lands in the group if it actually advertises the tag. Enrolling with an
OAuth client secret or a tagged auth key does this automatically. For a device you sign
in through the browser, turn on **Advertise tags on browser login** first. Your login
user must own the tag in `tagOwners`. Tagging also transfers the device to the tag's
ownership and turns off key expiry.
