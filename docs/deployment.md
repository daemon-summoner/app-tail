# Deployment

Running app-tail somewhere other than one desktop: at login, on a fleet, in a container,
and reaching its dashboard from another machine.

## Start at login

`app-tail install-autostart` writes a small, readable file you can inspect and
delete by hand, and `--remove` takes it back out:

| Platform | What it writes |
|---|---|
| macOS | `~/Library/LaunchAgents/com.sellitus.app-tail.plist` |
| Linux | `~/.config/systemd/user/app-tail.service` plus its `default.target.wants` symlink |
| Windows | the `app-tail` value under `HKCU\...\CurrentVersion\Run` |

It warns if the binary is somewhere temporary, like a build directory, since a
login item pointing at a path that will not exist next week is worse than none.

`app-tail autostart status` reports whether the login item is currently installed.

On Windows the [network-interface mode](modes.md#the-network-interface-mode) replaces that
registry value with a scheduled task, because a registry value cannot start an elevated
process and leaving it in place would mean a consent prompt at every login. Switching
modes swaps them back at the next start, and `autostart status` says when the installed
one no longer matches the mode.

## Reaching the dashboard from another machine

The dashboard binds loopback only (`127.0.0.1` or `[::1]`, addresses nothing off the machine
can reach), and there is no setting that will change that. `uiListenAddr` (the
`--ui-addr` flag, or `APPTAIL_UI_ADDR`) picks the address and port, and refuses anything
else with `must bind a loopback address`. Its default, `127.0.0.1:0`, takes any free port.
So remote access means forwarding a local port to it over SSH, then signing in with a
one-time link:

```
ssh the-host cat ~/.config/app-tail/dashboard-address   # where it bound, e.g. 127.0.0.1:41733
ssh -N -L 8377:127.0.0.1:41733 the-host                 # leave this running
```

That path is the Linux state directory; see [Where state lives](configuration.md#where-state-lives)
for the others. In a second terminal, ask the remote agent for a sign-in link that points at
your end of the tunnel:

```
ssh the-host app-tail dashboard --print --base http://127.0.0.1:8377
```

`--print` writes the link instead of opening a browser on the remote host, and `--base`
swaps the link's `scheme://host:port` for the one you give, keeping its path and one-time
token. Open the printed link in your own browser. It works once, within two minutes, and the
dashboard then stays signed in for 30 days or until the agent stops. A printed link signs in
from any account, so treat it like a password until it is used. `app-tail auth rotate` on
the host signs every dashboard out.

Set `uiListenAddr` to a fixed port on a host you forward to often, so the tunnel command
never changes. Scripts that call the API over the same tunnel send the token instead; see
[Authentication](api.md#authentication).

**`tailscale serve` does not work for this.** It forwards the original `Host`
header verbatim, so the request arrives claiming your tailnet name and the agent
refuses it with 403. That guard is what stops a hostile web page from rebinding its
own domain to 127.0.0.1 and reading your pending login URL, so it is not something
to relax.

For the same reason, reach the dashboard by a name the guard recognises:
`127.0.0.1`, `[::1]`, `localhost`, or any `*.localhost` label. Abbreviated loopback
literals (`127.1`, `2130706433`, `0177.0.0.1`) are refused, because accepting them
would mean resolving the Host header, and a resolver is exactly what an attacker
controls here.

## Fleet provisioning

To bring up many nodes with no clicking, do the [tag setup](connections.md#tags-acls-and-groups)
once and then hand each
node a credential and a shared profile:

1. **Prepare the tag.** Run the dashboard's one-click setup or
   `app-tail bootstrap-policy`, or paste the snippet, so `tag:app-tail` exists in your
   policy with an owner.
2. **Mint a credential** in the Tailscale admin console scoped to that tag (an OAuth
   client with the `auth_keys` scope, or a tagged auth key) and drop it on each node as a
   file. Never pass it on the command line.
3. **Write a profile** describing the shared settings and forwards. See
   [`examples/fleet-profile.json`](../examples/fleet-profile.json); it may carry comments
   and trailing commas (HuJSON). Point `oauthClientSecretFile` at the file from step 2.
4. **Apply and start** on each node:

   ```
   app-tail provision --profile fleet-profile.json
   app-tail            # authenticates from the credential, comes up running the forwards
   ```

`bootstrap-policy` and `provision` are both idempotent, so re-running either (in an
image build, a config-management pass, or by hand) changes nothing when already
applied.

`bootstrap-policy` needs the far stronger `policy_file` scope. Run it once from a
trusted machine and never ship that credential to the fleet. It refuses to send the
secret anywhere but a `tailscale.com` host unless you pass `--allow-foreign-api-url`,
and it refuses cleartext off loopback outright.

## Docker

The repo ships a multi-stage `Dockerfile` that builds the dashboard and a static,
tray-less binary into a minimal Alpine image, plus a `docker-compose.yml`. Base
images are pinned by digest.

Write the credential first. The directory is gitignored and excluded from the
build context:

```
mkdir -p secrets && printf '%s' 'tskey-client-...' > secrets/app-tail-oauth
chmod 600 secrets/app-tail-oauth

docker compose up -d --build
docker exec app-tail app-tail status --json
docker exec app-tail app-tail login          # prints an auth URL if one is needed
```

Compose mounts that file as a secret at `/run/secrets/app-tail-oauth` and points
`APPTAIL_OAUTH_CLIENT_SECRET_FILE` at it. If the file is missing, Compose refuses to
create the container and names the path, rather than starting a node that fails at
auth time.

The container runs as uid 10001 with `cap_drop: ALL` and `no-new-privileges`. It
needs no capability: the tailnet runs inside the process (Tailscale's tsnet library), so
there is no network device and no routing change, and it binds ports above 1024. A forward on a privileged port is what this
rules out: use a high port and redirect on the host instead.

The compose file uses `network_mode: host` (Linux) on purpose. The dashboard API binds
loopback only, so it must reach the host's own loopback and nowhere else; it is
deliberately **not** published with `ports:`. Every API call needs the token the agent
writes to `/data/api-token`, and the loopback-only bind keeps even token guessing off the
network. To open the dashboard from the Docker host, ask the container for a sign-in link
and open it in a browser on the host:

```
docker exec app-tail app-tail dashboard --print
```

The image pins the dashboard to `127.0.0.1:8377`, so with host networking the link works on
the host as printed. The `/data` volume keeps
the device identity across container replacements. It also holds `config.json` and
`secrets.json`, the credentials you enter in the dashboard, `0600` and owned by uid 10001.
`config.json` carries none of those credentials, so it can be copied out of the volume for a
bug report. `secrets.json` cannot: back the volume up as you would a password store. On Docker Desktop for macOS or
Windows there is no host loopback to share, so run app-tail natively there and use
containers for Linux hosts.
