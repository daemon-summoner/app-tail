#!/usr/bin/env bash
# Execution-truth smoke test: boot the real binary with no credentials in a throwaway
# state dir, prove its API refuses callers without its token, reports NeedsLogin, fails
# /healthz, and exits 0 on SIGINT.
# Usage: scripts/smoke.sh   (expects the binary to be built already)

# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

[ -x "$BIN_PATH" ] || fail "binary not built: $BIN_PATH"

# Windows has no POSIX signal delivery to a native process, so the shutdown assertions
# below are the one part of this script that cannot run there. Everything before them is
# identical on all three platforms.
WINDOWS=0
[ "$(go env GOOS 2>/dev/null || true)" = "windows" ] && WINDOWS=1

SMOKE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/app-tail-smoke.XXXXXX")"
AGENT_PID=""

cleanup() {
	if [ -n "$AGENT_PID" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
		kill -KILL "$AGENT_PID" 2>/dev/null || true
	fi
	rm -rf "$SMOKE_DIR"
}
trap cleanup EXIT

step "Smoke: booting headless agent (state dir: $SMOKE_DIR)"
# Deliberately clear inherited credentials so this exercises the interactive/NeedsLogin path.
env -u TS_AUTHKEY -u TS_CLIENT_SECRET -u APPTAIL_OAUTH_CLIENT_SECRET \
	"$BIN_PATH" --headless --state-dir "$SMOKE_DIR" --ui-addr 127.0.0.1:0 \
	>"$SMOKE_DIR/agent.log" 2>&1 &
AGENT_PID=$!

# The agent records the port it actually bound, which is how every other client finds
# it; poll for that record.
UI_ADDR=""
for _ in $(seq 1 100); do
	if [ -f "$SMOKE_DIR/dashboard-address" ]; then
		UI_ADDR=$(tr -d '[:space:]' <"$SMOKE_DIR/dashboard-address")
		case "$UI_ADDR" in
		*:0 | "") UI_ADDR="" ;;
		*) break ;;
		esac
	fi
	kill -0 "$AGENT_PID" 2>/dev/null || {
		cat "$SMOKE_DIR/agent.log"
		fail "agent exited during startup"
	}
	sleep 0.3
done
[ -n "$UI_ADDR" ] || {
	cat "$SMOKE_DIR/agent.log"
	fail "agent never recorded a bound dashboard address"
}
info "API listening on $UI_ADDR"

# The API answers only callers holding the token the agent wrote beside the address
# record. It is in place before the address is, so it is readable by now.
[ -f "$SMOKE_DIR/api-token" ] || fail "the agent recorded its address but wrote no api-token beside it"
API_TOKEN=$(tr -d '[:space:]' <"$SMOKE_DIR/api-token")
AUTH=(-H "Authorization: Bearer $API_TOKEN")

step "Smoke: the API refuses a caller without the token"
NOAUTH_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$UI_ADDR/api/status" || true)
[ "$NOAUTH_CODE" = "401" ] || fail "/api/status without a token returned $NOAUTH_CODE, want 401"
WRONG_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
	-H "Authorization: Bearer atk1_not-the-token" "http://$UI_ADDR/api/status" || true)
[ "$WRONG_CODE" = "401" ] || fail "/api/status with a wrong token returned $WRONG_CODE, want 401"
info "/api/status refuses a missing or wrong token (401)"

# /api/status must reach a real backend state without any tailnet credential.
STATE=""
for _ in $(seq 1 100); do
	BODY=$(curl -fsS --max-time 3 "${AUTH[@]}" "http://$UI_ADDR/api/status" 2>/dev/null || true)
	STATE=$(printf '%s' "$BODY" | sed -n 's/.*"backendState"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
	case "$STATE" in
	NeedsLogin | Starting | Running) break ;;
	esac
	sleep 0.3
done
case "$STATE" in
NeedsLogin | Starting) info "backendState=$STATE (expected without credentials)" ;;
Running) fail "backendState=Running with no credential -- state dir was not clean" ;;
*)
	cat "$SMOKE_DIR/agent.log"
	fail "no usable backendState from /api/status (got '${STATE:-none}')"
	;;
esac

# Readiness must be false while the node is not Running.
HEALTH_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$UI_ADDR/healthz" || true)
[ "$HEALTH_CODE" = "503" ] || fail "/healthz returned $HEALTH_CODE, want 503 while not connected"
info "/healthz correctly reports 503"

# The dashboard must be served from the embedded FS.
SPA_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$UI_ADDR/" || true)
[ "$SPA_CODE" = "200" ] || fail "dashboard root returned $SPA_CODE, want 200"
info "dashboard served from embedded FS"

# "Installs minimally" is a promise about a fresh state dir, and this is where it is
# mechanically enforced. The proxy is the module with real consequences if it drifted
# on by default: while it listens, every process on the machine, as any local user, can
# reach whatever this node's ACLs allow. Off has to mean no listener, not a listener
# that refuses.
step "Smoke: optional modules stay off on a fresh state dir"
PROXY_JSON=$(curl -fsS --max-time 3 "${AUTH[@]}" "http://$UI_ADDR/api/proxy" || true)
[ -n "$PROXY_JSON" ] || fail "/api/proxy did not answer"
case "$PROXY_JSON" in
*'"enabled":false'*) ;;
*) fail "the proxy module is on with no one having turned it on: $PROXY_JSON" ;;
esac
case "$PROXY_JSON" in
*'"listening"'*) fail "the proxy reports a bound address while switched off: $PROXY_JSON" ;;
esac

# Automatic ports opens a local port per device, so it drifting on would bind a listener
# for every peer the tailnet reports and take those ports away from everything else.
AUTOMAP_JSON=$(curl -fsS --max-time 3 "${AUTH[@]}" "http://$UI_ADDR/api/automap" || true)
[ -n "$AUTOMAP_JSON" ] || fail "/api/automap did not answer"
case "$AUTOMAP_JSON" in
*'"enabled":false'*) ;;
*) fail "automatic ports are on with no one having turned them on: $AUTOMAP_JSON" ;;
esac
case "$AUTOMAP_JSON" in
*'"mapped":0'*) ;;
*) fail "automatic ports report open ports while switched off: $AUTOMAP_JSON" ;;
esac

# An exit node redirects where this device's traffic leaves from, so it drifting on
# would silently route through whichever device the tailnet happened to offer. Off has
# to mean no device is chosen and none is reported carrying traffic.
EXITNODE_JSON=$(curl -fsS --max-time 3 "${AUTH[@]}" "http://$UI_ADDR/api/exitnode" || true)
[ -n "$EXITNODE_JSON" ] || fail "/api/exitnode did not answer"
case "$EXITNODE_JSON" in
*'"enabled":false'*) ;;
*) fail "the exit node module is on with no one having turned it on: $EXITNODE_JSON" ;;
esac
case "$EXITNODE_JSON" in
*'"current"'* | *'"liveId"'*) fail "an exit node is selected while the module is off: $EXITNODE_JSON" ;;
esac

# The one setting that writes something outside the state directory. Off has to mean the
# machine's own configuration was never touched, and the record file is what proves it:
# it exists only when something was replaced.
SYSPROXY_JSON=$(curl -fsS --max-time 3 "${AUTH[@]}" "http://$UI_ADDR/api/proxy/system" || true)
[ -n "$SYSPROXY_JSON" ] || fail "/api/proxy/system did not answer"
case "$SYSPROXY_JSON" in
*'"enabled":false'*) ;;
*) fail "this machine's proxy settings are managed with no one having asked: $SYSPROXY_JSON" ;;
esac
case "$SYSPROXY_JSON" in
*'"applied":false'*) ;;
*) fail "this machine's proxy settings were changed while the setting is off: $SYSPROXY_JSON" ;;
esac
[ ! -e "$SMOKE_DIR/sysproxy-restore.json" ] ||
	fail "a restore record was written with nothing ever applied"

# Blocking downloads lists off the internet and refuses names once it has them. Off has
# to mean nothing was downloaded and nothing is being refused, which the empty cache
# directory is the evidence for: a module that fetched anything left files behind.
DNSBLOCK_JSON=$(curl -fsS --max-time 3 "${AUTH[@]}" "http://$UI_ADDR/api/dns/block" || true)
[ -n "$DNSBLOCK_JSON" ] || fail "/api/dns/block did not answer"
case "$DNSBLOCK_JSON" in
*'"enabled":false'*) ;;
*) fail "DNS blocking is on with no one having turned it on: $DNSBLOCK_JSON" ;;
esac
case "$DNSBLOCK_JSON" in
*'"rules":0'*) ;;
*) fail "DNS blocking holds names while switched off: $DNSBLOCK_JSON" ;;
esac
[ ! -e "$SMOKE_DIR/blocklists" ] ||
	fail "blocklists were downloaded with the module switched off"

info "every optional module reports off, and nothing outside the state dir was changed"

# ...and not merely reported off. Counting the agent's own listening sockets by pid is
# what distinguishes "this agent bound nothing else" from "no other program on this
# developer's machine happens to use that port".
if command -v lsof >/dev/null 2>&1; then
	LISTENERS=$(lsof -nP -a -p "$AGENT_PID" -iTCP -sTCP:LISTEN 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
	[ "$LISTENERS" = "1" ] ||
		fail "the agent holds $LISTENERS listening sockets with every module off, want only the dashboard"
	info "one listening socket (the dashboard), no module bound a port"
else
	info "SOCKET-COUNT: N/A -- lsof is not installed"
fi

# The ACL bootstrap endpoint must validate before doing anything: an empty request
# carries no credential, so it has to be rejected, not acted on.
step "Smoke: policy preview rejects an empty request"
POLICY_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
	-X POST -H 'Content-Type: application/json' -d '{}' \
	"${AUTH[@]}" "http://$UI_ADDR/api/policy/preview" || true)
[ "$POLICY_CODE" = "400" ] || fail "/api/policy/preview on an empty body returned $POLICY_CODE, want 400"
info "policy preview validates its input (400)"

# The headline of workstream C: rebuild the tailnet node in place. Unit tests cover
# this against a stand-in node, so here prove the real tsnet node survives a
# close-then-start cycle in the same process and the API keeps serving afterward.
step "Smoke: in-process node restart"
RESTART_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
	-X POST "${AUTH[@]}" "http://$UI_ADDR/api/restart" || true)
[ "$RESTART_CODE" = "200" ] || {
	cat "$SMOKE_DIR/agent.log"
	fail "/api/restart returned $RESTART_CODE, want 200"
}
# The management API must still answer, on a node that reached a usable state again.
STATE_AFTER=""
for _ in $(seq 1 100); do
	BODY=$(curl -fsS --max-time 3 "${AUTH[@]}" "http://$UI_ADDR/api/status" 2>/dev/null || true)
	STATE_AFTER=$(printf '%s' "$BODY" | sed -n 's/.*"backendState"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
	case "$STATE_AFTER" in
	NeedsLogin | Starting | Running) break ;;
	esac
	sleep 0.3
done
case "$STATE_AFTER" in
NeedsLogin | Starting) info "node rebuilt, API still serving (backendState=$STATE_AFTER)" ;;
*)
	cat "$SMOKE_DIR/agent.log"
	fail "after restart /api/status gave '${STATE_AFTER:-none}', want the node serving again"
	;;
esac

if [ "$WINDOWS" = "1" ]; then
	# Ctrl+C on Windows is a console control event, not a signal a shell can deliver to
	# a process it did not share a console with, so there is no way from here to ask the
	# agent to shut down the way a user would. Killing it instead proves nothing about
	# the shutdown path, so this states what went unexercised rather than asserting
	# against a hard kill.
	step "Smoke: shutdown"
	na "SHUTDOWN: graceful shutdown not exercised -- Windows has no signal path from a shell"
	kill -KILL "$AGENT_PID" 2>/dev/null || true
	AGENT_PID=""
	step "Smoke: PARTIAL -- everything but shutdown"
	exit 0
fi

step "Smoke: SIGINT shutdown"
kill -INT "$AGENT_PID"
EXIT_CODE=""
for _ in $(seq 1 100); do
	if ! kill -0 "$AGENT_PID" 2>/dev/null; then
		wait "$AGENT_PID" && EXIT_CODE=0 || EXIT_CODE=$?
		break
	fi
	sleep 0.1
done
AGENT_PID=""
[ -n "$EXIT_CODE" ] || fail "agent did not exit within 10s of SIGINT"
[ "$EXIT_CODE" = "0" ] || {
	cat "$SMOKE_DIR/agent.log"
	fail "agent exited $EXIT_CODE on SIGINT, want 0"
}

# The record of where it was listening has to go with it: one left behind sends the next
# `app-tail status` at whatever takes that port.
[ ! -e "$SMOKE_DIR/dashboard-address" ] ||
	fail "the dashboard address record survived shutdown: $(cat "$SMOKE_DIR/dashboard-address")"
info "the dashboard address record was removed on shutdown"

step "Smoke: PASS"
