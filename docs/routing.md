# Routing

Which network a destination goes through, and where the rest of your traffic leaves.

**Two scopes, and the commands differ.** A module's master switch belongs to this
machine (`app-tail settings set routes true`). What it then does belongs to one
connection (`app-tail connection set tailnet routes.accept true`), because subnet routes
and exit nodes are properties of the network you are attached to, and this app is
attached to several. Subnet routes and exit nodes are Tailscale features, so they are set
on a Tailscale connection. `tailnet` in the examples below is the short name of the one
app-tail starts with; `app-tail connection list` prints yours, and
`app-tail connection get NAME` lists every setting that connection takes.

## Subnet routes

A subnet router puts a whole private network on your tailnet (a home LAN, an office
range, a VPC) so its addresses are reachable from every device. app-tail does both
directions of that, and neither is the same as the official client's.

```
app-tail settings set routes true
app-tail connection set tailnet routes.accept true
```

`routes.accept` makes the networks your peers advertise reachable **through
app-tail's proxy and its forwards**, and nowhere else. Nothing on this machine is
reconfigured, so a browser or a `curl` that is not pointed at the proxy still
resolves and routes those addresses the way it always did:

```
app-tail exec -- curl http://192.168.1.10/
```

The [network-interface mode](modes.md#the-network-interface-mode) is the exception. There
the accepted routes go on the interface, so every program on the machine reaches those
networks. A route to public addresses, or one that overlaps a network this machine is
already on, then needs an administrator's approval first
([Approving network changes](security.md#approving-network-changes)).

The dashboard's subnet routes card lists what this device reaches, and its check
button asks each device carrying a route whether it answers. A route that is in the
netmap and answers from nowhere is otherwise indistinguishable from a working one.

### Offering a network to your tailnet

```
app-tail connection set tailnet routes.advertise 192.168.7.0/24
app-tail connection set tailnet routes.serve true
```

`routes.advertise` puts the network in the admin console for approval. Advertising is
only a request: until an admin approves it your tailnet sends this device no traffic
for it at all, which is by far the most common reason a route appears to do nothing.
The card shows what this device offers and what the tailnet approved as two separate
lists for exactly that reason.

`routes.serve` then answers the connections that arrive. Without a network
interface, app-tail is a **userspace subnet router, TCP only**, and the limits are the
shape of the feature rather than bugs in it:

> **TCP works. UDP does not, at all.** DNS, QUIC and HTTP/3, WireGuard, VoIP, NFS
> and game traffic all fail across a route this device carries, and there is no
> setting that changes it.
>
> **ICMP is echo only.** A ping across the route is answered by this machine, not by
> the host you named, so it proves the route and not the host.
>
> **The source address is this machine's.** Connections leave from this device's own
> address on that network, so a host that logs or filters by client address sees this
> device rather than the tailnet peer that called it.

In the network-interface mode the node's own network stack carries the networks this
device advertises, as the official client does: inside app-tail on macOS and Windows,
and by the kernel on Linux. That path is not limited to TCP.

`routes.serve` is off by default and separate from `routes.advertise` on purpose: a
route can be advertised and approved (a useful thing to exercise on its own) while every
connection to it is refused, rather than half-working.

Only approved networks are carried, and that is read from the tailnet rather than
from what this device asked for. Loopback, link-local and multicast addresses are
refused even inside an approved range, so an over-broad approval in the admin console
cannot turn a route into a way to reach services bound to this machine's loopback.

`lc.CheckIPForwarding` and the official client's `no-snat`, `netfilter-mode` and
`netfilter-kind` settings have no equivalent here and are not needed for the userspace
router: nothing is forwarded by the kernel, so `net.ipv4.ip_forward` and the host
firewall are not part of that path.

## Exit nodes

An exit node sends traffic out through another device on your tailnet instead of
through this machine's own network. Off by default, like everything else:

```
app-tail settings set exit-node true
app-tail connection set tailnet exitNode.nodeId nABCdef11CNTRL
```

The dashboard's exit node card lists the devices your tailnet offers and fills in
the same setting; `exitNode.auto` hands the choice to Tailscale instead, which on
most tailnets means its own Mullvad nodes rather than one you run yourself.

What "traffic" means here is narrower than in the official client, and the
difference is the whole point of this app:

> Only what already goes through app-tail (the proxy and the forwards) leaves
> through the exit node. Every other program on this machine is unaffected,
> because app-tail installs no VPN interface and changes no routes.

That holds in the standalone and proxy modes. In the
[network-interface mode](modes.md#the-network-interface-mode) the exit node's default
route goes on the interface and carries the whole machine's internet traffic, like the
official client. Because that takes over all of the machine's traffic, an administrator
has to approve it once (`sudo app-tail tun grant --full-tunnel`, or the dashboard's
**Approve…** button; see
[Approving network changes](security.md#approving-network-changes)).

`exitNode.allowLanAccess` keeps the printers and NAS on this machine's own network
reachable while the exit node carries the rest. Leaving it off is the stricter
choice.

The property worth relying on is what happens when the chosen device stops
working: the tailnet blackholes the traffic, so a dial through the proxy times out
and is refused. **It is never quietly sent direct.** `exitNode.onFailure` decides
what happens next: `hold` (the default: traffic stops until the device is back,
which is what you want if the exit node is there to keep this machine's address
out of it), `next` (move to another device the tailnet offers), or `off` (stop
using an exit node, giving up what it was for).

### Rotating between exit nodes

`exitNode.rotate.enabled` changes exit node on a schedule, so no single one sees
all of this device's traffic. `exitNode.rotate.strategy` is `round_robin` (each in
turn), `random` (never the one in use) or `latency` (whichever answers fastest,
measured over the tailnet itself rather than with ICMP, so it works against
devices that drop pings).

Every switch drops the connections going through the old device. There is no
graceful drain at any layer: downloads stop, SSH sessions end, and the far end
sees a new address, so anything tied to the previous one has to sign in again.
Three settings bound the damage rather than remove it:
`exitNode.rotate.intervalSec` (900 by default, floored at 60, because rotating
faster is an outage this device inflicts on itself),
`exitNode.rotate.pauseOnActive` (hold a switch back while connections are still
open) and `exitNode.rotate.maxDeferrals` (how many holds before one happens
anyway, so a machine that is never idle still rotates).

While rotation is on, `exitNode.nodeId` is the device to fall back to rather than
the one in use. The device actually in use is runtime state: `GET /api/exitnode`
and the tray's exit node line report it, and it is deliberately not written back
to `config.json` every fifteen minutes.

### Offering this device as an exit node

`routes.advertiseExitNode` offers this device to your tailnet for an admin to
approve. Without a network interface it is honest about what it is not: app-tail
routes in userspace and cannot carry the UDP other devices would send through it, so
DNS, video calls and QUIC all fail. There it is useful for exercising the approval
flow, not for being an exit node. In the network-interface mode the node's own stack
carries it, as with subnet routes above. Advertising and using one at the same time is refused, in the backend's
own words, at every write path.

## Where internet traffic leaves

Everything your connections do not carry (the open internet) leaves one of three
ways, set by `egress.mode`:

```
app-tail settings set egress direct                       # out of this machine, as it always has
app-tail settings set egress tunnel                       # through one connection
app-tail settings set egress-connection tn_4f1c2a
app-tail settings set egress multi                        # through several at once
app-tail settings set egress-connections tn_4f1c2a,tn_9b03de
app-tail settings set egress-shape spread                 # or cascade
```

The `tn_` values are connection IDs; `app-tail connection list` prints them in its `ID`
column. On the dashboard this is the **Internet traffic** card on the **Internet** page.

A connection can only carry internet traffic if it can reach the internet: a Tailscale
connection needs an exit node chosen, and a WireGuard connection needs the default route
(`0.0.0.0/0`) in its allowed addresses. With a network interface, sending the machine's
internet traffic through a connection needs the same administrator approval as an exit
node above.

With `multi` and `spread`, leaving the list empty uses every connection that is running.
`cascade` needs the list, because the order is the point.

`spread` gives each destination one of the connections and keeps it there, so a page
and everything it loads leave the same way while different sites leave different
ways. `cascade` reads the same list as an order instead: the traffic goes through
every connection in turn, so the first sees who you are but not where you went and
the last sees where you went but not who you are. Every extra hop costs its own
round trip, and the card says so.

### Holding the traffic rather than letting it out

`egress.killSwitch` is the promise that nothing leaks while the connection carrying
your internet traffic cannot:

```
app-tail settings set kill-switch true
```

With it off, a connection that is down, switched off or carrying nothing leaves the
traffic going out over whatever network this machine is on, with the setting still
reading "through one of your connections". With it on, that traffic stops here
instead: the network interface keeps claiming the default route and refuses every
flow, and the proxy refuses to dial. Nothing falls back.

It is read only while one connection carries the traffic. Several connections hold
it whether or not the switch is on, and sending traffic out of this machine directly
is the setting that says this machine's own network is where it goes.

Two things it deliberately does not take back, both named on the card rather than
left to be discovered:

- Outside the network-interface mode, app-tail only holds the traffic that goes
  through app-tail: its proxy, and whatever is pointed at it. Everything else on
  this machine leaves over its own network as before.
- A per-destination rule that sends its destinations out over this machine's own
  network still does. A rule is an exception written on purpose, so holding
  everything else does not withdraw it.

The dashboard's **Internet traffic** card says which of the two states is live:
`carrying` while the connection is carrying it, and `held` rather than
`not carrying` when the switch is what stopped it.

## Per-destination routing rules

Where internet traffic leaves is one setting for everything your connections do not
carry. Routing rules are the exceptions to it: send everything under a company's
domain through one connection, keep a bank on this machine's own network, refuse a
range outright. A destination no rule names still leaves the way the setting says,
so an empty list changes nothing.

```
app-tail route add --host '**.corp.example' --via office
app-tail route add --host bank.example --direct
app-tail route add --range 192.0.2.0/24 --block
app-tail route                       # the list, numbered, with what each rule does
app-tail route check db.corp.example # which way one destination goes
app-tail route move 3 1              # order is the meaning: first match decides
```

`--via` takes a connection's name or ID. `**.corp.example` matches any name one or more
labels under `corp.example`, but not `corp.example` itself. `route move` takes a rule's
position or its ID (the `ar_` code in the list) and the position to move it to;
`route rm` and `route clear` remove one rule or all of them.

The dashboard holds the same list on the **Internet** page, in the **Per-destination
rules** card directly below the internet traffic card the rules make exceptions to,
with the same destination check beside it.

The first matching rule decides, so a narrow exception belongs above the broad rule
it is an exception to. A rule sending traffic through a connection that is not
running refuses those destinations rather than quietly sending them out another
way.

Two things follow from what each surface can see, and both are stated on the card
and under the CLI's table rather than discovered:

- A rule about a **host name** applies to traffic app-tail resolves for: through
  the proxy, or through its own resolver. A packet reaching the network interface
  carries an address and no name, so only a rule naming a range decides it.
- A rule naming a **range** moves the traffic, not the name lookup that found it:
  the query still goes to whichever resolver carries everything else. A `block`
  rule is the exception: nothing is dialled and no name is looked up, so neither
  the traffic nor the query leaves.

On the network interface the addressing is a routing table rather than a
first-match list, so a range an earlier rule already covers gets no entry of its
own. Those rules are named as shadowed instead of silently doing nothing.
