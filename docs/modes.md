# How app-tail runs on this machine

app-tail has four run modes, from touching nothing to putting the whole machine on
every network at once.

| Mode | What reaches your networks | Needs administrator rights |
|---|---|---|
| **Standalone** | your forwards, one local port each | no |
| **Proxy** | any program pointed at `127.0.0.1:1080`, plus the forwards | no |
| **Network interface** | every program on this machine, for the tailnet only | once |
| **Fabric** | every program on this machine, for every connected network | once |

Forwards are not a mode. They are always on, in every mode, and they are the least
obtrusive thing app-tail does: one local port bridged to one remote service.

Under the hood a mode is two switches: one for the proxy (`proxy.enabled`) and one for the
network interface (`interface.enabled`, with `interface.mode` saying which kind). The proxy
can run beside an interface, so the four rows above are what the switches add up to, not
four separate programs.

The dashboard's **How this machine reaches them** page, under Connections, offers the
four as one choice and writes the switches each one stands for, plus an **Also running**
panel for the modules that are on beside the mode's own. Picking a mode there sets
exactly these:

| You pick | Proxy | Interface |
|---|---|---|
| Standalone | off | off |
| Proxy | on | off |
| Network interface | left as it was | on, `tun` |
| Fabric | left as it was | on, `fabric` |

So picking Proxy does switch an interface off, and picking an interface mode keeps the
proxy if you had it. From a terminal you set the switches directly:

```
app-tail settings set --proxy=true                              # the proxy
app-tail settings set --interface=true --interface-mode=tun     # network interface
app-tail settings set --interface=true --interface-mode=fabric  # fabric
app-tail settings get mode.primary                              # which of the four that adds up to
```

`mode.primary` is read from those switches rather than stored beside them, so choosing a
mode and flipping the switches it stands for can never disagree. When more than one is
on, it reports the one that does the most: fabric, then network interface, then proxy.

Every interface setting is in the [settings reference](settings.md), including
`interface.name` (what the adapter is called) and `interface.virtualPool` (the range fabric
moves colliding networks into).

## Fabric: every network at once

Fabric is the only mode that reaches two networks carrying the same addresses. It puts
one interface on the machine, ends every flow arriving on it, and opens it again inside
the network the address belonged to. When two connections carry overlapping ranges,
app-tail presents the second one from `198.18.0.0/15` (reserved for benchmarking, so
nothing else routes it) and translates back on the way out. That re-addressing is
automatic and is the one conflict app-tail resolves for you rather than reports. The
system-wide resolver, when it is on, answers a connection's names with the moved address,
so names keep working (see [DNS](dns.md#names-on-your-connections)).

What it costs, stated here rather than found later:

- **Only TCP and UDP cross.** ICMP, ESP, GRE and SCTP do not. A ping to an address on
  one of these networks goes unanswered, and a traceroute shows one hop.
- **Every byte passes through app-tail**, so a single transfer is slower than one over a
  connection this machine holds itself.
- **The interface carries packets no larger than the smallest connected network's**,
  because a datagram cannot be split the way a byte stream can.
- Two IPv6 networks that collide have nowhere to move to: the pool is IPv4 only, and the
  collision is reported rather than resolved.

```
app-tail settings set --interface=true --interface-mode=fabric
```

## The network-interface mode

The proxy above reaches the tailnet without touching the machine. The other way is to
give the machine a real network interface, so `curl`, `ssh`, your browser and every
other program reach `100.x` addresses and MagicDNS names with nothing configured. This is
what the official Tailscale client does.

This and [the system-wide resolver](dns.md#the-system-wide-resolver) are the two parts of
app-tail that change the machine, and they share one privileged helper, whose install is
what asks the operating system for administrator rights. Turning the mode on takes both
switches, because the mode is refused while `interface.enabled`, the switch that offers
it, is off:

```
app-tail settings set --interface=true --interface-mode=tun
```

The mode takes effect when the node next starts. Forwards and the proxy keep working
unchanged. What changes is reach: subnet routes you accept and an exit node you pick now
apply to the whole machine rather than only to what app-tail carries. An exit node then
carries all of this machine's internet traffic, which is a change an administrator has to
approve first (see [Approvals](#approvals) below). Switching back to
`--interface-mode=userspace` removes the interface and everything with it.

Creating a network interface needs rights the app does not have and does not want, and
the two platforms hand them over differently enough that each is described on its own
below. `app-tail tun doctor` reports which one this machine is, what is installed and
what a previous run left behind, on either.

**One thing has to be true on both: the official Tailscale client cannot be running.**
Two clients cannot share the adapter, the routes or the address range, and on macOS they
also delete each other's `/etc/resolver` files. The mode refuses to start while one is
there and says which one it found.

### macOS and Linux: a small root helper

The agent stays your own process (your config directory, your tray, your login item),
and a separate helper holds the rights.

On macOS you do not have to install it yourself: turning the mode on asks for your
password once and sets the machine up, and `app-tail tun setup` does the same thing from
a terminal. Both run the installer below through macOS's own authorization prompt, so
there is no separate step and nothing to run as root by hand:

```
app-tail tun setup
```

The prompt appears only when you ask for the mode: never at login, and never again once
the helper is there. It names the binary and the start of its SHA-256 fingerprint, and
what runs as root is a private copy checked against that fingerprint, so a binary swapped
after you read the prompt is never the one installed. If your current config already needs
changes an administrator must approve, the prompt lists them and the same password
approves them too.

Declining leaves app-tail working in the contained mode and says so, and
`app-tail run --no-elevate` refuses the prompt up front for a machine that should never
see one. A node that had to start that way is not stuck there: while the mode is on and
the node is not on the interface, app-tail reads the machine again on a slowing schedule,
from one minute up to fifteen, and rebuilds the node onto the interface as soon as the
machine can carry one. So installing the helper, or quitting an official Tailscale client
that was holding the tailnet, is the whole of what you have to do.

To install it yourself instead, which is what a scripted deployment wants:

```
sudo app-tail tun install-helper
sudo app-tail tun install-helper --grant   # also approve what the current config needs
```

Run under `sudo`, the helper serves the account that ran `sudo`. `--owner UID` names a
different account.

**Everything it puts on the machine, in full.** In the default mode this list is
empty, and `app-tail tun doctor` says so in as many words.

| Path | What it is | When |
|---|---|---|
| `/Library/LaunchDaemons/com.github.sellitus.app-tail.helper.plist` | tells launchd to run the helper as root | from `install-helper` until `uninstall-helper` |
| `/Library/PrivilegedHelperTools/app-tail/app-tail-helper` | a copy of this binary, owned by root, in a folder only root can change | the same |
| `/var/run/app-tail/helper.sock` | where the helper listens, `0600` and owned by the account it serves, in a folder only root can enter | while the helper runs |
| `/etc/resolver/<your-tailnet>.ts.net` | sends your tailnet's own names to the tailnet's resolver | while the node is up and uses the tailnet's DNS (`dns.useTailnet`) |
| `/var/db/app-tail/systemdns-restore.json` | what each network service resolved with before [the system-wide resolver](dns.md#the-system-wide-resolver) changed it | while that feature is on, and until the restore it exists for has run |
| `/Library/Application Support/app-tail/grants.json` | the network changes an administrator approved | from the first approval until you delete it |

The interface itself (`utun<N>`) and its routes are not files and go away with it.

The same helper serves both features, so a machine that wants only the system-wide
resolver installs exactly this and no interface is ever created. `app-tail dns setup` is
the same install under that feature's wording.

That one resolver file is what makes `laptop.your-tailnet.ts.net` resolve in a browser,
in `ssh`, and everywhere else on the machine. A split-DNS domain your admin console
points at a private nameserver, such as `corp.example.com`, also needs the connection to
use the tailnet's DNS, and because it is outside `ts.net` an administrator has to approve
it before the helper will write it. Without that, it still resolves through app-tail's own
proxy when that proxy's **Resolve names with** is set to **The tailnet's DNS**.

The binary is *copied* rather than run where it sits, and that is deliberate: launchd
runs whatever is at the path its configuration names, and an app in a downloads folder
is writable by the user. Pointing root at one hands root to anyone who can write
there. The install also checks that every folder above the copy belongs to root and that
nobody else can write to it, and removes the copy older builds put in
`/usr/local/libexec/app-tail`.

**Who the helper listens to.** The helper takes commands only from the account recorded
when it was installed (and from root), checked against the kernel's own view of the
connecting process rather than anything that process claims. On top of that it checks
that the caller is app-tail itself and not some other program running as you:

- On macOS it compares the code signature hash the kernel recorded when the connecting
  process started with its own. A process that swaps its program after connecting is
  refused.
- On Linux it compares the program file the connecting process is running with its own,
  and refuses a process being traced by a debugger. This is weaker: a program that
  connects first and then starts app-tail is not caught. What it can get is only what the
  helper would do for app-tail anyway: the safe changes, and the ones you approved.
- Anywhere neither works, such as a helper binary with no code signature on macOS, the
  helper takes commands from root alone.

`app-tail tun doctor` shows which of these the installed helper uses on its
**Helper accepts** line.

#### Approvals

The helper makes the safe changes for anybody it accepts: routes inside private ranges
that do not cover your LAN, and the tailnet's own names. Anything that could take over
the machine's traffic needs an administrator to approve it first: carrying all internet
traffic (an exit node), routes to public addresses, making app-tail the machine's
resolver, names outside `ts.net`, each OpenVPN server, and traffic interception.
[Approving network changes](security.md#approving-network-changes) lists every rule, where
approvals are kept, and how to take one back.

When something is waiting, the dashboard lists it with an **Approve…** button and the tray
adds **Approve network changes…**. From a terminal, `app-tail tun grant --show` prints what
is approved, and the same command with flags approves more:

```
sudo app-tail tun grant --full-tunnel
sudo app-tail tun grant --route 203.0.113.0/24 --dns-domain corp.example.com
```

**It undoes itself.** The helper holds the agent's connection, and when that drops,
including when the agent is killed outright, it immediately removes the routes and
resolver files and closes the interface. There is nothing the agent has to remember to
do, and nothing left over from a crash.

```
app-tail tun doctor
```

reports whether the helper is installed and answering, and anything a previous run left
behind, with the exact commands to remove it by hand for the case where app-tail is not
the thing that will be doing the cleaning. `sudo app-tail tun uninstall-helper` puts any
system DNS settings back first, then takes the whole thing back off.

On macOS, `tailnet.repairRoutes` (on by default) watches for one quiet fault: the machine
still holds its tailnet address but has lost the route to the tailnet's range, so every
program sends tailnet traffic out the wrong way and times out. It puts that one route back
and touches nothing else.

On Linux the helper exists but is started by hand, since there is no one service manager
to write a unit for. It has to be told which account it serves, and `sudo` drops
environment variables by default, so pass it on the command line:

```
sudo APPTAIL_HELPER_OWNER=$(id -u) app-tail tun helper
```

Without `APPTAIL_HELPER_OWNER` the helper starts but refuses every caller except root.

### Windows: one prompt, and the app runs elevated

There is no helper here. A wintun adapter's handle cannot be passed to another process,
so whatever creates the adapter has to be what drives it, which means app-tail itself.
It asks Windows to restart it with administrator rights, once, at the moment it starts
with the mode turned on. The restarted copy keeps the same account and the same
`%APPDATA%`, so nothing moves and nothing is duplicated.

The prompt appears once per start and never in a loop: the restarted copy carries
`--no-elevate` and will not ask again, so a machine whose policy strips the rights
anyway falls back to the contained mode with a reason instead of prompting forever.
`app-tail run --no-elevate` refuses the prompt up front.

**app-tail only elevates from a folder only administrators can change.** Whatever sits at
that path when you answer the prompt gets administrator rights, and a folder your own
account can write is one any program you run could swap a file into. Install it once
with:

```
app-tail install
```

which copies it to `C:\Program Files\app-tail\`. Run from anywhere else, app-tail refuses
to elevate and says so. `app-tail run --allow-unprotected-elevation` accepts that risk for
one run, with a warning.

**`wintun.dll` has to be beside `app-tail.exe`.** It is the driver front end the
interface mode loads at run time, it is not part of app-tail, and its loader searches
only the folder holding the executable and `System32`, so a copy on `PATH` does not count.
app-tail checks its SHA-256 against the copy each release ships and refuses any other.
The Windows release archives already carry it, along with `WINTUN-LICENSE.txt`; a build
from source does not, and `app-tail tun doctor` says so with a link rather than letting
the start fail later. `app-tail licenses` prints its terms with everything else.

**Everything it puts on the machine, in full.**

| What | Where | When |
|---|---|---|
| the `app-tail` network adapter and its routes | not a file; visible in `netsh interface show interface` | while the node is up |
| the login item, as a scheduled task instead of a registry value | Task Scheduler, `\app-tail` | while start-at-login is on *and* the mode is on |
| the DNS repair, which runs `app-tail dns restore` as SYSTEM at boot and at logon | Task Scheduler, `\app-tail DNS repair` | from the first time System DNS is switched on; it stays, and does nothing when nothing is recorded. `schtasks /Delete /TN "\app-tail DNS repair" /F` removes it |

The login item changes shape because of the same rights. In the default mode it is an
`HKCU\...\Run` value, which needs nothing from anybody. That value cannot start an
elevated process, so leaving it in place would put a consent prompt on screen at every
single login, the thing this app exists not to do. In the interface mode it is replaced
by a scheduled task registered to run with highest privileges, which starts silently.
Switching modes swaps them back automatically at the next start; `app-tail
install-autostart` and `app-tail autostart status` do it and report it by hand.

Registering that task itself needs administrator rights once. If app-tail is running
unelevated when the mode is turned on, it says so and names the fix rather than failing
quietly.

The adapter outlives the process, unlike a `utun` on macOS: it is created by a driver
and stays until something removes it. Starting again adopts it, and `app-tail tun
doctor` reports one that nothing is driving, with the command that disables it.
