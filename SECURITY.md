# Security

app-tail sits between your machine and the networks it joins, and parts of it run with
administrator rights. That makes it a target, so this page says plainly what it defends
against, what it deliberately does not, and where its limits are.
[docs/security.md](docs/security.md) is the operational detail: approvals, traffic
inspection, and where credentials are stored.

## Reporting a vulnerability

Report privately through this repository's **Security → Advisories → Report a
vulnerability** form on GitHub. That keeps the report out of public issues until
there is a fix. Please do not open a public issue for anything exploitable.

Include what you did, what happened, and what you expected. A proof of concept
against a local agent is more useful than a description; app-tail is a loopback
service, so almost everything is reproducible on one machine.

## Who app-tail defends against

| Who | What they can do | Where app-tail stands |
|---|---|---|
| A web page in your browser | Nothing. It cannot call the dashboard API: every call needs the API token, the `Host` must be loopback, a request marked cross-site is refused, and writes need a JSON content type a page cannot send cross-origin without permission. | Defended |
| Another device on your tailnet or LAN | Reach the forwards you opened, and nothing else. The dashboard binds loopback only and no setting moves it. | Defended |
| Another account on this machine | Nothing of yours. It cannot read the API token or your credentials, cannot redeem a sign-in link meant for you (macOS and Linux), and the root helper refuses it. The one exception is the tailnet proxy, which is open to every local process while you have it on; see below. | Defended |
| A program running as you | What you can do in the dashboard, because it can read your files. It cannot make the root helper change the machine's networking beyond the narrow set that is always safe and the changes an administrator approved, and it cannot get root to run a program of its choosing. | Bounded |
| Malware with root or administrator rights | Anything. No program can defend a machine from its own administrator. | Out of scope |

The fourth row is where most desktop VPN tools stop at "same user means trusted." app-tail
does not. The root helper checks which program is calling it, not just which account, and
holds every change that could take over the machine's traffic to a list only an
administrator can write.

## Approving network changes

The helper makes some changes for anybody, because they cannot hurt the machine: routes
inside private ranges that do not cover a network you are on, and resolvers on loopback or
inside the tailnet for names under `ts.net`. Everything else waits for an administrator:

- carrying all internet traffic (a full tunnel),
- routes to public addresses, or over a network this machine is already on,
- making app-tail the machine's own resolver, or answering for any domain outside `ts.net`,
- each OpenVPN server, together with the certificate authority it is trusted with,
- traffic interception.

Approvals live in `grants.json`, a file only an administrator can write, and the helper
rereads it on every request. The dashboard and the tray say exactly what is waiting and
show the system's administrator prompt; `app-tail tun grant --show` prints what is
approved. [Approving network changes](docs/security.md#approving-network-changes) has the
full rules, the file locations and how to revoke one.

## Known limits

These are real, they are narrow, and each one is here so nobody has to discover it.

- **The tailnet proxy is open to every local process.** A `127.0.0.1` bind restricts by
  host, not by user, and there is no portable way to check who is on the other end of a
  loopback TCP connection. It is off by default, and `proxy.requireToken` adds a password
  when you need one.
- **A program running as you can use what you can.** It can read the API token and your
  `secrets.json`, the same as it can read your SSH keys. What it cannot do is escalate:
  see the table above.
- **OpenVPN's management socket has no password.** openvpn lets the account named with
  `--management-client-user` connect to it, and that account is yours. A program running
  as you that connects first, during the moments openvpn waits to be told to go on, can
  drive that one connection.
- **An OpenVPN server's address is checked once the connection is up, not before.**
  OpenVPN applies the address a server hands out while it starts, so the helper can only
  read it back afterwards. A server handing out a range that needs an approval you did not
  give has its connection stopped; until then, for the moments openvpn takes to finish
  starting, traffic for that range can go through the tunnel.
- **The macOS library check is narrower than dyld in one place.** When the helper vets
  `openvpn` and the libraries it loads, it does not search a loading image's inherited
  search paths for an optional (`weak`) `@rpath` library. A required library that is
  missing is still refused.
- **A traffic-interception root made by an earlier build lacks the newest exclusions.**
  app-tail never replaces a root you installed. Switch interception off, run
  `app-tail ips remove-root`, switch it back on, and install the root it generates.
- **On Linux, a debugger attached before the helper's checks can go unnoticed.** The
  helper compares the calling program's file and refuses a traced caller, but a program
  that starts app-tail under a debugger and changes it before letting go is not caught.
  What it can get is still limited to the always-safe changes and the ones you approved.
  `app-tail tun doctor` says which check this machine has.
- **Release binaries are not signed with an Apple Developer ID.** macOS builds are
  ad-hoc signed with the hardened runtime, which is what the helper's caller check relies
  on, but Gatekeeper may stop a downloaded copy until you allow it. Check downloads
  against `SHA256SUMS.txt` from the release.
- **Credentials are protected by file permissions on macOS and Linux.** `secrets.json`
  is readable only by your account. Windows also encrypts it with DPAPI to your Windows
  account. The macOS Keychain is not used yet.

## What is in scope

app-tail's job is to carry exactly the traffic you ask for and nothing else. The
things that would break that promise:

- Any dashboard API call succeeding without the API token, a sign-in link working twice
  or after two minutes, or a session outliving the agent that issued it.
- The CLI sending its API token to a listener that has not first proven it is this
  account's agent.
- Reaching the dashboard API from anywhere other than the machine it runs on.
- Reading an auth key, an OAuth client secret, or a pending login URL back out of
  any API response, log line, or error message.
- Sending a credential anywhere other than the control server it was entered for,
  including after the connection is pointed at another server.
- Traffic crossing a forward that was never configured, or reaching a host other
  than the forward's target.
- A forward that targets one of app-tail's own listeners: the dashboard, a proxy, or
  the resolver.
- Anything that makes the agent bind a non-loopback address for its dashboard.
- The tailnet proxy carrying a destination outside its configured scope, or
  falling back to a direct connection instead of refusing one. Failing closed is
  the point of the scope setting; a leak past it is a real bug.
- The tailnet proxy binding, or being reachable, while `proxy.enabled` is off.
- Automatic ports opening a local port for a device the tailnet does not report,
  or opening any port while `automap.enabled` is off.
- Traffic leaving through this machine's own network while an exit node is
  selected. When the selected device is unusable the connection must fail, not
  succeed by another path. That is the guarantee the setting is chosen for.
- The exit-node module choosing a device, measuring one, or writing an exit node
  preference while `exitNode.enabled` is off.
- A connection arriving over the tailnet for an advertised network reaching an
  address outside the ones the tailnet approved, including this machine's own
  loopback, a link-local address, or the tailnet's own range. The approved set is
  read from the tailnet, never from what this device asked to carry.
- Carrying any connection for an advertised network while `routes.serve` is off.
- This machine's own proxy configuration being written while `proxy.system` is
  off, or a value app-tail replaced not being put back when it is turned off.
- A connection arriving over the tailnet being answered while
  `security.shieldsUp` is on.
- Anything about this machine being reported to your tailnet while
  `security.postureChecking` is off.
- app-tail writing this machine's DNS configuration (`resolv.conf`, a `scutil`
  entry, an `/etc/resolver` file or an NRPT rule) while `interface.enabled` and
  `systemDns.enabled` are both off. `dns.useTailnet` configures the resolver inside
  this process only. Two features write them by definition, the network-interface
  mode and the system-wide resolver below, and each is a separate opt-in that is off
  until you turn it on; writing them with both off is a real bug.
- The system-wide resolver pointing this machine at anything other than a
  loopback address, or the privileged helper accepting a request to. The address
  is validated as loopback in the helper, on the helper's side of the socket,
  because that bound is what makes an unprivileged process asking a root one to
  rewrite the machine's DNS acceptable at all.
- A resolver override outliving the thing that asked for it. It is put back when
  the setting is turned off, when the connection to the helper drops, when the
  helper next starts (including at boot, before any login), every 30 seconds while
  no agent holds the helper's resolver session, at boot on Windows by a SYSTEM
  scheduled task registered before the override goes up, and when the helper is
  uninstalled. A machine left resolving through an app-tail that is not running
  is the highest-severity defect this feature can have.
- The network-interface mode creating an interface, a route or a resolver file
  before `interface.enabled` is on with `interface.mode` set to `tun` or `fabric`.
  Storing the mode is a request, not the change: nothing outside app-tail's own
  directory is touched until the privileged helper is installed, and installing it
  asks the operating system for administrator credentials.
- The privileged helper acting on a request from any account other than the one
  recorded when it was installed, from a program other than app-tail's own, or from
  a caller whose identity it took from anything other than the kernel.
- The helper making a change that needs an approval when `grants.json` does not
  hold one, or honoring a `grants.json` that it, or any folder above it, lets a
  non-administrator write.
- Root running an `openvpn` program, or a library one loads, that sits in a folder
  a non-root account can write, at any point between the check and the start.
- The helper's binary, its directory, its launch configuration or its socket being
  writable by a non-root account, at any point including mid-install. A root
  daemon that runs a user-writable file is a way to become root.
- The helper accepting an operation outside the closed list in
  `internal/hostnet/protocol.go`, or acting on a path, name or command string
  supplied by the caller beyond the one checked path described below.
- Routes, resolver files or an interface outliving the agent that asked for them.
  The helper undoes everything when the connection drops, including when the agent
  is killed; on Windows, where there is no helper, the agent undoes it before the
  session ends and the next start repairs whatever a kill left behind. Anything
  left behind after that is a defect, and it is what `app-tail tun doctor` is for.
- app-tail asking Windows for administrator rights while the stored settings ask
  for neither the network-interface mode nor the system-wide resolver, and no
  previous run left this machine's resolver pointed at app-tail. Those three are
  the whole of it: each names a privileged change this machine's own stored state
  already asks for, and the third is the repair for the second. Asking more than
  once for one start is equally a defect. The restarted process carries
  `--no-elevate` and never asks again; a prompt loop is a defect, and so is a
  prompt for a machine that wants none of the three.
- The elevated Windows process being started from a path, a working directory or a
  command line that any other account could have influenced. It relaunches its own
  resolved executable, quotes every argument through the platform's own parser, and
  passes no caller-supplied string beyond the flags it was itself started with.
- app-tail elevating itself from a folder its own account can write. Anything running
  as you could replace the program or the `wintun.dll` beside it before the prompt is
  answered, so it refuses unless that one run carries `--allow-unprotected-elevation`.
  `app-tail install` puts it under Program Files, where only administrators can change
  it.
- The scheduled task that starts the interface mode at login running as any account
  other than the one that installed it, or its definition being writable by another
  account before the Task Scheduler reads it.
- The boot-time DNS repair task running a program another account could replace. It
  runs as SYSTEM with no prompt, so it is only registered for an `app-tail.exe` whose
  folders only administrators can change, and its definition is written to a folder
  only administrators can write before the Task Scheduler reads it.
- The interface mode loading any `wintun.dll` other than the one pinned by SHA-256,
  or loading it from anywhere other than the folder holding `app-tail.exe` or the
  system directory. The file is held open against writes from before it is hashed
  until after it is loaded, by full path, so the bytes checked are the bytes loaded.
- Any tailnet lock operation that changes state for the tailnet rather than for
  this device. app-tail signs a device and forgets this device's own copy of the
  lock state; it cannot enable lock, disable it for the tailnet, or run a
  recovery ceremony.

## What is not a vulnerability

These are deliberate, and each one is enforced somewhere in the code:

- **Your own account can use the dashboard API.** It binds loopback only, with no
  flag that binds it anywhere else, and every call needs the API token in
  `api-token`, readable only by the account the agent runs as. Other accounts on
  the machine cannot read it; code already running as your user can, and no
  desktop app can keep its own user out of its own files. The one-time sign-in link
  the tray opens is visible to other accounts on the browser's command line, so on
  macOS and Linux the agent only redeems it over a connection your account's own
  process holds (`internal/peeraccount`). Sessions end when the agent stops.
- **A forward may bind `0.0.0.0`.** That is an explicit per-forward choice
  (`exposeToNetwork`, "Let other machines on your network use this forward") for
  serving other devices on your LAN. It is not the dashboard address.
- **Localhost pages can load the dashboard page.** They cannot call its API
  without a token. On top of that, every request must carry a loopback `Host`,
  which stops DNS rebinding; a request whose `Origin` names another site, or that
  the browser marks cross-site, is refused; and every write must be
  `Content-Type: application/json`.
- **`app-tail bootstrap-policy --api-url` accepts a foreign host** only with an
  explicit `--allow-foreign-api-url`, and never over cleartext off-loopback. The
  OAuth credential it carries has `policy_file` scope over your whole tailnet.
- **The tailnet proxy is open to every local process.** While it is on, any
  process on this machine, running as any local user, can reach every device your
  tailnet ACLs allow this node to reach. Binding to `127.0.0.1` restricts by host,
  not by user, and there is no portable peer-credential check for a loopback TCP
  connection: `SO_PEERCRED` and its equivalents are unix-socket only. This is why
  the module is off by default, why the grant is stated on the setting itself and
  in the dashboard rather than buried here, and why the default scope refuses
  anything the tailnet does not route. `proxy.requireToken` adds a password for
  the cases that need one; it necessarily disables the browser auto-config path,
  since a PAC file has nowhere to carry a credential.
- **`proxy.resolveVia` decides which resolver sees the names being dialed.** On
  the default, `netmap`, only tailnet device names are resolved inside the proxy
  and every other name goes to this machine's resolver, exactly as it would
  without app-tail. Set to `tailnet`, each name is asked of the tailnet's own
  resolver first, so the names your programs dial through the proxy are seen by
  whatever nameservers your tailnet is configured with rather than by this
  machine's. That is the point of the setting, since it is the only way a split-DNS
  domain resolves correctly, and it is off by default because it changes who
  learns what you are connecting to. A resolver that fails is reported and the
  connection refused; it never falls back to the other resolver, which would
  resolve a private name against a public one without anyone noticing.
- **An exit node hides this machine's address from the destination, and from
  nobody else.** Your tailnet's control plane knows which device you selected,
  the exit node itself sees every connection it carries, and the tailnet's
  logging records the same flows it always did. Rotating changes how much any one
  exit node sees; it is not anonymity, and `exitNode.rotate.strategy: random`
  draws from the devices your own tailnet offers, which is a small and named set.
- **Rotation drops the connections going through the old device.** There is no
  graceful drain at any layer of Tailscale, so this is a consequence of the
  feature rather than a defect in it. It is stated on the setting, in the
  dashboard and in `docs/routing.md`, and bounded by `pauseOnActive` and
  `maxDeferrals` rather than hidden.
- **A carried subnet route carries TCP and nothing else.** app-tail routes in
  userspace, so `routes.serve` answers TCP flows and there is no equivalent hook
  for UDP at all: DNS, QUIC, WireGuard, VoIP and NFS fail across a route this
  device carries, and no setting changes that. A peer that reaches a host this way
  is talking to it from *this* machine's address on that network, because the
  connection is dialed from this machine's own stack, so a host that filters or
  logs by client address sees this device rather than the peer. Both are stated on
  the setting, on the dashboard card and in `docs/routing.md`, because a route that
  silently drops half a protocol is worse than one that is documented as carrying
  half of it. ICMP across the route is answered by this machine rather than by the
  host named, so a successful ping proves the route and not the host.
- **`routes.advertiseExitNode` advertises a device that cannot carry UDP.**
  app-tail routes in userspace, so a peer that selects this device as its exit
  node loses DNS, QUIC and every other UDP protocol. The setting is labeled as an
  approval-flow exercise rather than a working exit node, sits behind the routing
  module, and is off by default. Advertising while using an exit node is refused
  at every write path, in the backend's own words.
- **`proxy.system` changes a setting outside app-tail's own state.** It is one of
  three things app-tail writes outside its state directory at all (the
  network-interface mode and the system-wide resolver below are the other two, and
  all three are off by default), so it is narrow and reversible by construction:
  Windows only, `HKCU` only (this user account, no elevation, no machine-wide key),
  and only ever the `AutoConfigURL` value pointing at the auto-config script this
  agent serves on loopback. What was there before is written to
  `sysproxy-restore.json` in the state directory *before* the change, and put back
  when the setting is turned off, when the app exits, or on the next start after a
  kill. A value something else has changed since is left alone rather than
  overwritten with the older one. Turning it on extends the local-process grant
  above to every program that reads the Windows proxy setting, which is the point
  of the feature and the reason it is off by default and separate from
  `proxy.enabled`. On macOS and Linux app-tail does not write it at all; it prints
  the command instead. `app-tail proxy system off` restores it with or without a
  running agent.
- **`dns.useTailnet` does not change how this machine resolves names.** In the
  default mode it configures the resolver inside app-tail's own process and
  nothing else: no `resolv.conf`, no `scutil` entry, no `/etc/resolver` file, no
  NRPT rule. (Two other features do configure the machine's resolver, the
  network-interface mode and `systemDns.enabled`, and each is a separate opt-in
  with a switch of its own. Turning either of them on never turns this one on, and
  turning this one on never turns either of them on.) Names your tailnet serves
  resolve for connections that go through app-tail's proxy and its forwards, and
  for no other program on this machine. This is stated on the setting, on the
  dashboard card, in `app-tail dns` and in `docs/dns.md`, because a DNS switch that
  quietly meant less than it appeared to would be the one place this app oversold
  what it does. Which nameservers see the names being dialed is
  `proxy.resolveVia`, covered above.
- **`systemDns.enabled` does change how this machine resolves names, which is
  what it is for.** It is the one feature here whose whole purpose is to affect
  every program on the machine, so the design is about bounding and reversing it
  rather than about narrowing it. What it writes is enumerated by platform in
  `docs/dns.md`: on macOS the `Setup:` DNS servers of each active network service
  via `networksetup`, on Windows the `NameServer` value of each active interface
  via `netsh`, on Linux the runtime `resolvectl dns` of each managed link. On a
  Linux without systemd-resolved it refuses rather than guessing at the shape of a
  working `resolv.conf`. Every value it replaces is written to a root-owned
  `systemdns-restore.json` *before* the change, and a value something else has
  altered since is left alone rather than overwritten with the older one. The
  address it points the machine at is always a loopback one this process is
  already listening on (the helper validates that itself and refuses anything
  else), and the ordering is bind first, override second, never the reverse. On
  macOS that listening address has to be added to `lo0` first, because macOS
  assigns `127.0.0.1` alone and refuses the rest of `127/8`; the helper adds only
  a loopback address, records it in the same root-owned file before it adds it,
  and takes it off again after the resolver setting has been put back. That order
  matters, because a machine still pointed at an address whose alias has gone
  resolves nothing at all.
  Queries for names that belong to the network you are on (single labels, the
  network's own search domains, `.local`, private reverse lookups, captive-portal
  detection names) go to the resolver you had; everything else goes to the chosen
  profile, and that profile's answer is final, `NXDOMAIN` included, because a
  filtering resolver blocks a name *by* saying it does not exist and a silent
  retry elsewhere would defeat it. `systemDns.retryOnNxdomain` can turn that off
  and says so in those words; it is off by default. Total upstream failure is
  `SERVFAIL` rather than a quiet fall-back to the network, so a blocklist that
  stops working is visible instead of silent. The override is undone when the
  setting goes off, when the helper's connection drops, when an installed helper
  next starts (launchd's `RunAtLoad` means that is at boot, before any login, on
  macOS) and every 30 seconds after that while no agent holds the resolver, before
  `tun uninstall-helper` removes anything, and, on Windows, before the session ends
  when the machine is shutting down or logging off, and at boot, two minutes after
  boot and at every logon by the `\app-tail DNS repair` task, which runs
  `app-tail dns restore` as SYSTEM. Every repair stands back while the app-tail that
  made the change holds the serving lock beside the record, which only root or SYSTEM
  can open, so no other account can hold it to keep a repair away. The
  task is registered before the machine is pointed at app-tail and only for a
  program under a folder no other account can write; if it cannot be registered,
  System DNS is refused. On Linux the override does not survive a reboot.
  `app-tail tun doctor` reports a machine still resolving through app-tail as
  unclean and prints `sudo app-tail dns restore` (`app-tail dns restore` from an
  administrator prompt on Windows).
- **Tailnet lock state is read, and this device's own copy is the only one it can
  discard.** The card and `app-tail lock` report why a device is cut off and
  print the `tailscale lock sign` line that fixes it; signing another device
  requires this one to already hold a key your tailnet trusts, and the tailnet
  decides that, not app-tail. Forgetting this device's copy of the lock state
  takes a typed confirmation and affects this device alone: your tailnet's lock
  stays on and no other device changes. Enabling lock for a tailnet, disabling it
  for a tailnet, and the recovery ceremonies are deliberately absent. They depend
  on disablement secrets kept offline, and a port-forwarding utility is the wrong
  place to handle them.
- **`security.postureChecking` sends identifying details about this machine to
  your tailnet.** Serial number, operating system version and any
  device-management identifiers leave the machine so that admins can write access
  rules against them. That is the feature, not a leak, which is why it is off by
  default, never switched on by a preset, and described in those words on the
  setting rather than as a one-word label.
- **The network-interface mode and the system-wide resolver run a helper as root,
  on purpose.** They are the features that cannot be done without administrator
  rights: creating an interface, installing routes, writing resolver files and
  binding port 53 are privileged operations, and no amount of design removes that.
  What the design does control is how much runs with those rights and for how
  long. The agent (the tray, the dashboard, the proxy, the DNS forwarder that
  parses queries off the wire, everything that parses anything) stays your own
  unprivileged process; the helper binds the socket and hands the descriptor back
  rather than reading from it. The helper is a separate program whose entire
  vocabulary is a closed list of named operations. Nothing the caller sends ever
  names a program or becomes a command: the one pair of operations that starts
  anything runs a root-owned `openvpn` found at a fixed list of paths, after
  checking that it, every folder above it and every library it loads can be changed
  by root alone, against a configuration the helper renders itself from a template,
  so the server, keys and algorithm names that cross are values in that template
  and never directives. One operation does take a path from the caller, the socket
  the connection it starts is supervised through, and it is checked before it is
  used: absolute, no line breaks or nulls, short enough to fit a socket address, its
  parent directory owned by the account this helper serves and writable by nobody
  else, and the path itself read with `lstat` rather than followed, then required to
  be a socket that same account owns. That is the property that makes it a path the
  caller could have connected to on its own rather than this side reaching somewhere
  on its behalf, and the `lstat` is what stops a symbolic link being swapped in after
  the directory was checked. It takes commands only from the account recorded in its
  launch configuration, checked against the kernel's view of the connecting process
  rather than against anything that process says.
  On top of the account, the caller has to be running app-tail's own program: on
  macOS its code-signature hash must match the helper's, and the helper refuses to
  start unless it is signed with the hardened runtime and without debugging allowed,
  so no other program can load code into app-tail and keep that hash. On Linux the
  helper compares the program file, refuses a traced caller, and refuses to start
  from a dynamically linked build, which `LD_PRELOAD` could inject code into. The
  Linux debugger case is under [Known limits](#known-limits). Its socket is `0600` in
  a root-owned directory, and both the directory and the binary are re-secured on
  every install rather than trusted to already be right. The binary is copied to a
  root-owned path (`/Library/PrivilegedHelperTools` on macOS) instead of being run
  where it sits, because launchd runs whatever is at the path it is given and an app
  in a downloads folder is writable by its user. Both features are off, the helper
  is not installed until you run `sudo app-tail tun install-helper` (or
  `sudo app-tail dns setup`, which is the same install under the wording of the
  feature that asked for it, or `./build_install.sh`, which installs it because a
  build from source is a new binary for the helper to be a copy of), and
  `sudo app-tail tun uninstall-helper` removes all of it. Everything it installs is
  listed by path in `docs/modes.md` and read back by `app-tail tun doctor`.
- **On Windows the whole agent runs elevated, because nothing smaller can.** There
  is no helper there: a wintun adapter's handle is not exposed in a form another
  process could take over, so a helper would have to host the entire engine, which
  is the opposite of the split macOS gets. app-tail asks Windows to restart it with
  administrator rights instead: once, before it has bound a port or opened a state
  directory, only from a folder only administrators can change, and only when the
  stored settings already select the interface mode or the system-wide resolver, or
  a previous run left this machine's resolver pointed at app-tail and it has to be
  put back. The restarted copy keeps the same account and the same `%APPDATA%`, so
  nothing moves and there is nothing for two processes to fight over. It carries
  `--no-elevate` and cannot ask again, which is what bounds a machine whose policy
  grants the prompt but not the rights to one prompt and a fallback with a reason
  rather than a loop. Declining leaves app-tail in the contained mode, which is a
  working app. A `requireAdministrator` manifest was rejected deliberately: it would
  prompt at every launch, in every mode, for both executables.
- **The Windows login item becomes a scheduled task for the two features that need
  administrator rights, and only for those.** A registry Run value cannot start an
  elevated process, so keeping one while the interface mode or the system-wide
  resolver is on would put a consent prompt on screen at every login, which is the
  thing the one-time prompt exists to avoid. The task runs as the account that
  installed it, from an interactive token, and its definition is written to a file
  only that account can read before the Task Scheduler is pointed at it. Registering
  it needs administrator rights once; app-tail says so rather than failing quietly. A
  machine with both features off keeps the registry value, which needs nothing
  from anybody.
- **`wintun.dll` is a third-party binary loaded at run time by a privileged
  process.** It is not part of app-tail and is not linked into it: it ships beside
  `app-tail.exe`, unmodified and with its own notice, which is what its terms
  permit. It is loaded only in the interface mode, only from the folder holding the
  executable or from the system directory (never from `PATH`, never from the
  working directory), and only when its SHA-256 matches the hash built into
  app-tail. A machine without a matching copy is refused before anything is torn
  down rather than being allowed to fall back to some other copy. The release
  checks the same pin and the DLL's notice byte for byte against the archive it
  came from.
- **The mode refuses to start beside the official Tailscale client.** On macOS both
  delete each other's `/etc/resolver` files and both want the same address range, so
  the outcome is not a degraded pair of clients but two that break each other. On
  Windows they cannot share the adapter or the routes either, and app-tail registers
  its adapter under its own type and its own identifier so neither install ever reads
  the other's as its own left behind. The refusal happens before the running node is
  torn down, so a machine in that state keeps the tailnet it already had.
- **`security.shieldsUp` silences forwards rather than refusing to be turned
  on.** Every forward in the `to_tailnet` direction stops answering while shields
  are up, whatever your tailnet's ACLs allow. app-tail does not reject the
  combination, because turning shields on with such a forward configured may be
  exactly what was meant; instead each silenced forward is marked in the forwards
  table with the reason. Failing closed is the safe direction here. The risk worth
  guarding against is a forward that reports itself running while carrying
  nothing.

## Handling credentials

- Secrets are **write-only across the API**. The dashboard is told whether one is
  set, never what it is.
- Credentials live in `secrets.json`, apart from `config.json`, so the config can be
  read, diffed and attached to a bug report without handing over a key.
  [Where credentials are stored](docs/security.md#where-credentials-are-stored) has
  the details.
- A tailnet credential is filed with the control server it was entered for, and
  pointing a connection at another server drops it unless you enter it again.
- There is no `--auth-key` or `--oauth-client-secret` flag that takes a literal
  value on a fleet path. Arguments are visible to every process on the machine;
  use the `*_FILE` forms or the environment.
- The strongest credential app-tail touches is the `policy_file`-scoped OAuth
  client used by `bootstrap-policy`. It is for a one-time setup run from a
  trusted machine. **Never ship it to a fleet**: nodes need only the far weaker
  `auth_keys` scope.
- `config.json`, `secrets.json`, `api-token` and the node identity are written
  `0600` through a temp-file rename, so a crash cannot leave a truncated or
  world-readable file.
- app-tail does not upload logs to Tailscale, and login URLs are kept out of its
  own logs.

## Supported versions

The most recent tagged release receives security fixes. There are no backport
branches; upgrading is the fix. A security fix is called out in
[CHANGELOG.md](CHANGELOG.md) under the release that carries it.

## Dependencies

`./verify.sh` and every CI run gate on `govulncheck` against the full module
graph and on `gitleaks` over both the working tree and the git history. A known
vulnerability in a reachable dependency fails the build rather than warning.

`wintun.dll` is outside that graph. It is a binary the Windows archive carries
rather than a module the build links, so it is pinned by SHA-256 in app-tail itself
and in `release.sh`, and a mismatch fails the release. Updating it is a deliberate
change to that hash and to the notice beside it.
