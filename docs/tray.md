# The tray menu

The tray icon is the quick way to see whether app-tail is healthy and to flip the
switches you reach for most. Everything in it is also in the dashboard, which has
the full detail; the tray is for the five-second change.

## When there is a tray

| Platform | Tray |
|---|---|
| macOS | A menu-bar icon in every desktop session. A run started over SSH has no desktop to draw in, so it runs headless. |
| Windows | A notification-area icon. app-tail runs as a per-user login item, so it is always inside your desktop session. |
| Linux | Builds made from source show one when an X or Wayland session is running. The release binaries are built without it, because the servers and containers they target have no desktop. |

`app-tail --headless`, or turning off **Show tray icon** (`showTray`), runs without one
on any platform. The startup log says which of those applied.

## The icon

The dot on the icon answers one question: is app-tail doing its job right now?

| Dot | Meaning |
|---|---|
| Grey | Starting up. Nothing to do yet. |
| Cyan | Connected, and every forward you turned on is listening. |
| Purple | Disconnected, a forward you turned on is down, or the last action failed. Hover the icon to read why. |

The menu repaints every two seconds, so it follows changes you make in the dashboard
or the CLI without being reopened.

## The menu, top to bottom

### Status

The first rows are read-only:

- **Connection state**: "Connected as *name*", "Needs login", "Connecting..." or
  "Starting...".
- **Forwards**: "3 forwards running", "2 of 3 forwards running", "3 forwards, all
  disabled" or "No forwards yet".
- **Exit node**: which device your other traffic leaves through, shown only while one
  is in use.
- **Approve network changes...**: appears only when app-tail is waiting on an
  administrator to approve something, such as a full-tunnel route or a new system
  resolver. Clicking it shows the exact change in your system's administrator prompt. See
  [Security](security.md) for what needs approval and why.

### Network Devices

Every device on your tailnet, up to 24. Each one opens to its tailnet address and its
DNS name; clicking either copies it.

### The everyday switches

These five sections sit together at the top because they are what people open the
menu to change.

| Section | What is in it |
|---|---|
| **Connections** | One checkbox per connection (Tailscale, WireGuard, OpenVPN), up to 12, plus **Connections...** to add or edit one in the dashboard. Unticking a connection disconnects it and keeps its settings. |
| **Internet** | Where traffic that no connection claims leaves through: straight out of this machine, or through one of your connections. A row on top says where it goes right now. |
| **System DNS** | **Use a chosen resolver for this machine** (`systemDns.enabled`), then the resolver profiles to pick from, and **Resolver profiles...** to manage them. While it is on, every program on this machine resolves names through app-tail. |
| **DNS Blocker** | **Block names on a list** (`dnsBlock.enabled`) is the switch for the whole feature. Under it, **Block what app-tail looks up** and **Block what this machine looks up** say where blocking applies. |
| **Traffic Inspection** | **Inspect the traffic app-tail carries** (`ips.enabled`) is the switch. **When a connection matches** picks between *Record it and carry it* and *Refuse it*. The rest choose what is examined: names, destinations, unusual patterns and the start of each connection. |

### More sections

| Section | What is in it |
|---|---|
| **Port Forwards** | **Enable all forwards** or **Disable all forwards**, depending on which would change something, and **Open a port for every device** (`automap.enabled`). |
| **Network Interface** | **Turn on the network interface**, a row saying what stands in the way when it cannot, and **Offer the network-interface mode** (`interface.enabled`). |
| **Exit Node** | **Use an exit node** (`exitNode.enabled`), **Let Tailscale choose**, **Keep reaching this machine's own network**, and up to 12 devices to pick from. |
| **DNS** | **Use tailnet DNS** (`dns.enabled`) and **Resolve names with your tailnet's DNS**. This is the resolver app-tail itself uses; **System DNS** above is the one the whole machine uses. |
| **Advanced** | Capabilities most installs never turn on: **Proxy** (the loopback proxy, its instances, and on Windows **Point this machine's proxy settings at it**), **Subnet Routes** and **Security** (**Refuse incoming tailnet connections**). |
| **Settings** | **Show tray icon**, **Open the dashboard on first run**, **Start at login**, and **All settings...**, which opens the full settings form. |

### Session

**Log In** or **Log Out**, **Open Dashboard** and **Quit App-Tail**. Open Dashboard
hands the browser a one-time sign-in link, so you land signed in without ever seeing
the API token.

## What the menu leaves out

A setting this machine cannot use right now is hidden rather than shown greyed out
with no explanation. For example, the **Point this machine's proxy settings at it**
row exists only on Windows. The dashboard shows every setting, with the reason one is
unavailable.

A failed click does not pop up a dialog. The icon's dot turns purple and the tooltip
says what went wrong.

## Where each row comes from

Every checkbox in the menu is a setting from the registry that also drives the
dashboard and `app-tail settings`, marked for the tray. A tray row and the matching
dashboard switch are the same setting, so they cannot disagree. The
[settings reference](settings.md) lists each one with its key and default.
