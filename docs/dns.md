# DNS

## DNS

There are two independent switches here, and they answer different questions.
`dns.*` decides what **app-tail** resolves with and changes nothing about the machine.
`systemDns.*` decides what **this machine** resolves with, and is one of the two
features that do change it ([it has its own section](#the-system-wide-resolver)).
Neither needs the other: the system-wide resolver works with every Tailscale feature
switched off, and on a machine that has never signed in to a tailnet.

### Your tailnet's DNS

Off by default, like the rest:

```
app-tail settings set dns true
app-tail connection set tailnet dns.useTailnet true
```

The first switch is this machine's; the second belongs to one Tailscale connection.
`tailnet` is the short name of the tailnet app-tail starts with, and
`app-tail connection list` prints the rest.

Read the scope of that second setting carefully, because it is narrower than the
same switch in the official client:

> **`dns.useTailnet` means exactly one thing: the resolver inside app-tail is
> configured with your tailnet's DNS. It changes nothing about how any other
> program on this machine resolves names.**

No `resolv.conf` is rewritten, no `scutil` entry is added and no NRPT rule is
installed by this switch. Names your tailnet serves resolve for connections that go
through app-tail's proxy and its forwards, and nowhere else. A browser pointed at the
proxy will resolve `foo.corp`; the same browser with no proxy configured will not, and
that is working as intended.

The [network-interface mode](modes.md#the-network-interface-mode) is where this switch
does reach the machine: with it on, the helper sends your tailnet's own names to the
tailnet's resolver for every program, the way the official client does.

`app-tail dns` and the dashboard's DNS band print both halves side by side (what
your tailnet publishes, and what this machine actually resolves with) because the
gap between them is the answer to nearly every question this feature raises. They
also report when an exit node is answering your lookups, which is a property you
cannot otherwise confirm from this machine and one of the main reasons to choose
one.

Split-DNS domains (a suffix your admin points at a private nameserver) are the
case worth knowing about. Through the proxy they also need that proxy's **Resolve names
with** set to **The tailnet's DNS** (`resolveVia: tailnet`, on the Proxies page), since
by default a proxy only reads tailnet device names out of the tailnet's device list and
hands every other name to this machine's resolver. In the network-interface mode the
helper only sends a split-DNS domain to the tailnet for the whole machine once an
administrator has approved that domain, because it is outside `ts.net`
([Approving network changes](security.md#approving-network-changes)).

### Names on your connections

Every connection answers for a name suffix of its own, made of its short name and the
zone all of them hang under: a host called `db` on the connection whose short name is
`office` is `db.office.internal`. The zone defaults to `internal`, the top-level domain
reserved for private use, which will never be delegated to anybody, and moves with one
setting:

```
app-tail settings set dns-zone corp.example.com
```

This is what makes two networks that use the same addresses usable at the same time. If
`office` and `lab` both carry `10.0.0.5`, then `db.office.internal` and `db.lab.internal`
are two different machines and both work at once, with nothing to switch over between
them. A name carrying a connection's suffix is answered by that connection or not at
all, never by another one that happens to hold the same address.

The suffix is derived from the short name rather than stored beside it, so renaming a
connection renames its names too and a stale suffix cannot be left pointing at a
different network. Short names are unique, so two connections can never claim one
suffix.

These names reach your networks through app-tail (its proxies, its forwards and its
auto-config file) the same way tailnet names do. What [the system-wide
resolver](#the-system-wide-resolver) does with them depends on the run mode:

- **In [fabric](modes.md#fabric-every-network-at-once)** every program on the machine can
  reach every connection, so it answers with the address this machine reaches the host
  at. When fabric moved a colliding network into `198.18.0.0/15`, that is the moved
  address.
- **In every other mode** it answers "no such name", with the connection named in the
  reason: nothing outside app-tail can route those networks, so an address for one would
  be an address this machine cannot reach.

The dashboard's DNS page lists which connection answers for which names.

### Blocking

app-tail can refuse names itself, against lists you choose, with nothing sent anywhere
to decide it. Off by default:

```
app-tail dns block on                    # blocking on, both halves below on
app-tail dns block                       # what is on, what each list contributed
app-tail dns block check doubleclick.net # which list stops a name, or why nothing does
```

The dashboard's blocking card asks that last question too, in a box beside the counters:
type the name a page needed and it says which list holds it, or why nothing does.

**Two switches again, and they reach different things.** `dnsBlock.own` filters what
**app-tail** resolves: everything its proxy dials by name. `dnsBlock.system` filters what
**this machine** resolves, and only reaches anything while [the system-wide
resolver](dns.md#the-system-wide-resolver) is on. Both read one catalog and one compiled
matcher, so the two halves can never disagree about what a list says. Two things are
outside both, by construction: a **forward** hands its target straight to a dialer and
never passes a resolver, and a packet arriving on the network interface carries an
address and no name.

`dnsBlock.answer` decides what a blocked name is answered with. `nxdomain` is the
default: "no such name" is what every program already handles, and a browser shows its
own "site cannot be reached" rather than a page that failed to load. `sinkhole` answers
`0.0.0.0` and `::`, which is faster to spot in a packet capture and is what some
software expects; `refused` says the resolver declined, which is the honest answer and
the one most likely to make a client retry elsewhere.

**The shipped catalog** is forty-five lists from sixteen publishers, each switchable on
its own, none editable, grouped by who publishes them on the card and in
`app-tail dns block list`. A group opens on the card when something inside it is on, so
the catalog reads as sixteen names rather than forty-five rows, and **Show only what's
on** collapses it further to just the lists that are switched on, every group open:

- **Hagezi:** the five tiers and the threat feed, plus gambling, fake shops, DoH and
  proxy bypass, bad hosters, dynamic DNS, and the native-telemetry lists for Apple,
  Windows and Office, Amazon, Samsung, Xiaomi, Huawei, Oppo and Realme, and TikTok.
- **StevenBlack:** the unified hosts file and its fake news, gambling, adult and social
  variants.
- **OISD:** Small, Big and Adult. **1Hosts:** Lite and Xtra.
- **AdGuard:** the DNS filter. **malware-filter:** URLhaus, phishing and botnet
  command-and-control. **Phishing Army**, and **abuse.ch**'s own URLhaus hosts export.
- **Peter Lowe**, **Dan Pollock**, **AdAway**, **NextDNS**'s CNAME-cloaking list,
  **Dandelion Sprout**'s anti-malware list, **NoTrack** and **hBlock**.
- **EasyList:** EasyList, EasyPrivacy and Fanboy's Annoyance list.

**Six levels, if you would rather not read forty-five descriptions.** Each one names a
set of the shipped lists; switching to a level turns on exactly those and leaves the
lists you added alone. The card offers them as one choice, and so does the CLI:

```
app-tail dns block level          # the ladder, with the one in force marked
app-tail dns block level high     # switch to it
```

`high` is the one marked as the pick if you would rather not compare them.

| Level | Lists | What it adds to the one below |
| --- | --- | --- |
| Minimum | 5 | The light ad and tracking tier, and every malware, phishing, botnet and CNAME-cloaking feed. |
| Low | 8 | Wider advertising and tracking, phone-app ad servers, two more threat feeds. |
| Medium | 12 | The everyday tier, with two more curated sources beside it. |
| High | 20 | The big curated sets, the long-standing hosts files, the EasyList family, and fake shops and scam sites. |
| Pro | 22 | Native device and app telemetry, Hagezi's threat-intelligence feed, and a very wide merged hosts file. |
| Ultimate | 22 | The widest tier of every source that has one, in place of the middle tier below. |

Two rules decided every entry. A list whose worst case is a blocked advertiser, tracker
or malicious host goes in early: nothing stops working because a malware feed refused a
name, which is why those are all on at Minimum. A list whose worst case is a site not
loading arrives late, or never: **no level includes the category lists** (gambling,
adult, social media, fake news) or the three that break working software: bad hosters,
dynamic DNS, and the DoH/VPN/proxy bypass list, which blocks the endpoints other VPN and
proxy software needs. Those stay one switch away in the catalog, where a deliberate
choice belongs. Breadth comes from independent publishers rather than one publisher's
widest file, because two lists built from different sources catch different things.

Switching lists on and off by hand is still there; do it and the card says the set is
not one of the levels rather than claiming one.

`hagezi-pro` is the one that is on when you turn blocking on. Add your own with
`app-tail dns block add --name X --url Y` (they share a group of their own). A list is
read as a hosts file or as an Adblock-syntax filter list, detected from the body unless
you pass `--format hosts` or `--format abp`; `app-tail dns block rm` removes one you
added.

**EasyList is a browser filter list, and mostly does not survive here.** Its rules name
URL paths and page elements, which no resolver can act on; only its `||domain^` subset
translates. The parser counts what it dropped and every list's row shows
`N names, M skipped`, so a list contributing almost nothing is visible rather than
assumed. AdGuard's *DNS* filter is written for resolvers and does not have this problem,
which is why that is the AdGuard entry that ships.

Four controls sit on top of the lists:

```
app-tail dns block allow add news.example  # never blocked, beats every list
app-tail dns block deny  add tracker.example
app-tail dns block pause 15m               # and `resume`; never survives a restart
app-tail dns block disable easylist        # per list, and `refresh` to download now
```

A pause is deliberately not written to disk: a blocker that comes back paused after a
restart is the failure this feature must not have.

**Where the lists live and what happens when they cannot be downloaded.**
`<stateDir>/blocklists/` holds one file per list plus an `index.json` of what each
contributed, written `0600` through the same temp-file rename as everything else.
Downloads are conditional, so an unchanged list costs one `304`. A list that fails to
download keeps blocking from the copy on disk and the card names the failure, which is
what makes this work through a network outage, an exit node that is down, or the egress
kill switch. The download is dialled at a pre-resolved address with the system proxy
bypassed, because resolving `raw.githubusercontent.com` through app-tail while app-tail
is this machine's resolver is a deadlock, and the name may itself be on a list.

One interaction worth knowing: `systemDns.retryOnNxdomain` sends a blocked name to this
network's resolvers as well, which unblocks it. It is off by default, and the card says
so when it is on.

## The system-wide resolver

The other half of DNS, and the second of the two features that change this machine.
It points every program here at a resolver you choose (a filtering one like NextDNS,
a public one like Cloudflare, your tailnet's own, your DNS-over-TLS endpoint) and lets you
switch between them in one click when the one you are on breaks a site. It works with no
tailnet at all: signed out, every Tailscale module off, userspace mode or the
network-interface mode alike.

```
app-tail dns                       # both halves, and which resolver is in force
app-tail dns use cloudflare        # switch, asking for a password the first time
app-tail dns profile add --name NextDNS --servers https://dns.nextdns.io/abc123
app-tail dns use system            # System default: puts this machine back
```

`system` is also where it starts: until you pick something else, this machine resolves
the way it always did.

**Setting it up.** Changing the machine's resolver needs the same root helper as the
network-interface mode ([macOS and Linux](modes.md#macos-and-linux-a-small-root-helper)),
or elevation on Windows. On macOS the first `dns use` asks for your password and installs
the helper; `app-tail dns setup` does that step on its own. On macOS and Linux, pointing
the machine at app-tail is also a change an administrator has to approve, because whoever
answers DNS can steer every program here. On macOS that approval rides on the same
password prompt; on Linux, `sudo app-tail tun grant --system-dns` does it
([Approving network changes](security.md#approving-network-changes)). When something is
still missing, `app-tail dns use` says what and names the command.

A profile is a name and up to four servers, tried **in order and never raced**: a
resolver that filters a domain has to be the one that answers, or it filters nothing.
Each server is a plain address (`1.1.1.1`, `1.1.1.1:53`), DNS over TLS
(`tls://one.one.one.one`) or DNS over HTTPS (`https://dns.example/dns-query`).
`system`, `tailnet`, `quad9`, `quad9-unfiltered`, `cloudflare` and `google` ship with the
binary and cannot be edited or deleted. They are the way back when a profile you added
is what broke resolution. `tailnet` resolves through whatever nameservers your tailnet
publishes, read from the node each time it is applied, so changing them in the Tailscale
admin console changes them here with nothing to edit. The two Quad9 entries are the same
resolver at different addresses: `quad9` (`9.9.9.9`) refuses names on Quad9's malware feed
and validates DNSSEC, `quad9-unfiltered` (`9.9.9.10`) does neither. Switching between them
is how you tell "this site is down" from "my resolver blocked it".

**A resolver named by a hostname needs one lookup first, and it matters who does it.**
`tls://dns.nextdns.io` and `https://dns.example/dns-query` have to become an address
before app-tail can reach them, and that one query cannot go to the resolver being
looked up. It is the last part of the chain this network still gets to answer: send it
to the network's own resolver and the network decides which address answers for that
name. It cannot make your resolver *wrong* (the certificate is verified against the
hostname you wrote, so a substituted address fails the handshake), but it can make it
unreachable, on a network that answers port 53 itself, before the first real query. So
it goes to `systemDns.bootstrapProfile` instead: any profile in the catalog, `quad9` by
default, using only the entries in it that carry a literal address. The name is pinned
to what came back and stays pinned until the profile changes. If that
profile cannot be reached at all (a captive portal answers only its own resolver),
this network's resolvers do it and the card, `app-tail dns` and the tray say so.
`systemDns.bootstrapProfile: system` chooses that on purpose. A profile of literal
addresses only, which every shipped one is, never needs any of this.

**Why the shipped public resolvers are HTTPS and not bare IPs.** Plenty of routers and
ISPs redirect outbound port 53 to their own resolver. On such a network a profile of
plain addresses resolves through the network you switched away from: every answer looks
normal and none of them came from the server you picked. The shipped Quad9, Cloudflare
and Google profiles are therefore `https://9.9.9.9/dns-query`,
`https://1.1.1.1/dns-query` and
`https://8.8.8.8/dns-query`: encrypted, verified against the resolver's certificate,
and reaching the server you chose or failing loudly. A profile of your own may use
plain addresses; when one is in force app-tail checks whether this network answers DNS
addressed elsewhere, and says so on the card and in `app-tail dns` when it does.

**What goes where.** app-tail listens on `127.0.0.153:53` (`systemDns.listenAddr`) and
this machine is pointed there; if something else already holds that address, it moves to
another loopback address by itself. macOS assigns `127.0.0.1` and nothing else of
`127/8`, so that address is added to `lo0` as an alias while the override is on and taken
off again with it, recorded in the same root-owned file and restored on the same
occasions below. Names that belong to the network you are on go to that network's own
resolvers:
single labels, anything under `.local` or `localhost`, reverse lookups for private
addresses, the search domains this network published, and any suffix you list in
`systemDns.localSuffixes`. Everything else goes to your chosen profile, and **its
answer is final**, including "no such name", which is how a filtering resolver
filters. `systemDns.retryOnNxdomain` turns that off and is off by default, because
turning it on is how a blocklist stops blocking.

**What it changes, by path.** Only these, only while it is on:

| Platform | What is written | Where the network's own resolvers are read from |
|---|---|---|
| macOS | `Setup:/Network/Service/<id>/DNS` on each active service, via `networksetup -setdnsservers`, plus `127.0.0.153` added to `lo0` as an alias so there is somewhere to listen | `State:/Network/Service/<id>/DNS`, which DHCP writes and this never touches |
| Windows | `NameServer` under each adapter's `Tcpip\Parameters\Interfaces\{GUID}`, via `netsh` | `DhcpNameServer` in the same key, which the override does not replace |
| Linux (systemd-resolved) | the per-link resolver, via `resolvectl dns <link>`, run-time only and gone at reboot | `org.freedesktop.resolve1.Link` |
| Linux (anything else) | nothing: refused, loudly | not read |

Linux outside systemd-resolved is refused rather than guessed at, for the reason the
network-interface mode gives: the only way to override a `resolv.conf` written by
NetworkManager, `dhclient` or a hand-rolled script is to rewrite the file, and
guessing which one wrote it is how a working `resolv.conf` becomes a broken one.

On Windows the rights come from elevation rather than from a helper, so switching this
on restarts app-tail once, with a UAC prompt. The switch says so before you use it. As
with the network-interface mode, app-tail only elevates from a folder only
administrators can change, which `app-tail install` sets up
([details](modes.md#windows-one-prompt-and-the-app-runs-elevated)).

**It undoes itself, and here is exactly how far that goes.** What was replaced is
written to a root-owned record (`/var/db/app-tail/systemdns-restore.json` on macOS,
`/var/lib/app-tail/systemdns-restore.json` on Linux, `%ProgramData%\app-tail\` on
Windows) *before* the change, and put back on each of these occasions:

| Scenario | What puts the machine back |
|---|---|
| You switch it off, or choose System default | the agent, immediately |
| app-tail exits, crashes, or is `kill -9`'d | macOS and Linux: the helper, when the connection drops. Windows: the next start, which asks for administrator rights to do it |
| Windows shuts down, restarts, or you log off | the agent, before the session ends: Windows tells it the session is going, and the shutdown screen names app-tail while it works |
| The whole machine loses power or crashes mid-session | macOS: the helper at boot, before anyone logs in (`RunAtLoad`, so this happens with no agent running), and again every 30 seconds while no app-tail is serving the machine. Windows: the `\app-tail DNS repair` scheduled task, as SYSTEM, at boot, two minutes after boot, and at every logon. Linux: a reboot clears the override |
| `sudo app-tail tun uninstall-helper` | the helper restores before it removes anything, since afterwards nothing would |

On macOS the boot-time repair is the helper's LaunchDaemon, so it needs the helper
installed. A single attempt at boot can miss (the network may not be up yet, or a service
may not be in the record), so the helper keeps checking every 30 seconds while no agent
holds the resolver: any service still pointed only at app-tail's own addresses
(`127.0.0.153` to `127.0.0.155`) is handed back to its network. A machine is never left
resolving nothing for longer than that.

Every repair, on every platform, first takes a lock beside the record
(`systemdns-serving.lock`), and the app-tail that pointed the machine at itself holds that
lock for as long as its override stands. So a repair never takes back the override of an
app-tail that is running, including one started with `sudo` that never talks to the
helper, and an app-tail switching System DNS on waits for a repair in progress to finish.
The operating system drops the lock when its holder ends, however it ends.

Windows has no helper, so the first time System DNS is switched on in a run, app-tail
registers a scheduled task, `\app-tail DNS repair`, that runs `app-tail dns restore` as
SYSTEM at boot, again two minutes later (Windows lists an adapter only once it has an
address, so the first run can miss one the record lost), and at every logon (a Fast Startup
power-on is not a boot). It is registered *before* the machine is pointed at app-tail;
if it cannot be (app-tail running from a folder other accounts can write, or without
administrator rights), System DNS stays off and says why, because an override with no
repair is exactly the failure this table exists to prevent. The task stays registered
afterwards and does nothing when nothing is recorded. `app-tail install` puts the program
under Program Files, which the task needs.

Linux has the same helper with no install step (there is no one service manager to write a
unit for, so [it is started by hand](modes.md#macos-and-linux-a-small-root-helper)). Its
override is run-time only, so a reboot clears it regardless; the macOS and Windows ones are
written into the machine's own configuration and survive one.

The one case it does **not** survive on its own is the helper being deleted by hand while
the override is in force, on macOS or Linux, without going through `uninstall-helper`:
nothing is then left with the rights to restore, and the machine keeps resolving
through a socket that no longer answers. `sudo app-tail dns restore` fixes that
(`app-tail dns restore` from an administrator prompt on Windows), and `app-tail tun doctor`
reports the redirected resolver as a leftover with the exact command to undo it.

A restore that could not reach one of the machine's network services (a disabled adapter,
an unplugged dock, a radio switched off) puts back everything else and says which one it
left alone, keeping that service's record so the next run finishes the job. It does not
report success for a service it never touched.
