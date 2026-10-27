#!/usr/bin/env bash
# Record what this machine actually gets through the app: transfer rate and per-flow
# latency, direct and through each path the running agent offers, plus the public address
# traffic leaves from -- the reference every later leak check is judged against.
# Usage: scripts/throughput.sh [--out FILE] [--bytes N] [--samples N] [--api HOST:PORT]

# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

BYTES=${APPTAIL_PROBE_BYTES:-25000000}
SAMPLES=3
API_ADDR=${APPTAIL_API:-}
OUT_FILE=""

while [ $# -gt 0 ]; do
	case "$1" in
	--out)
		OUT_FILE="${2:-}"
		shift 2
		;;
	--bytes)
		BYTES="${2:-}"
		shift 2
		;;
	--samples)
		SAMPLES="${2:-}"
		shift 2
		;;
	--api)
		API_ADDR="${2:-}"
		shift 2
		;;
	*) fail "unknown argument: $1 (usage: $0 [--out FILE] [--bytes N] [--samples N] [--api HOST:PORT])" ;;
	esac
done

command -v curl >/dev/null 2>&1 || fail "curl is required and is not installed"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [ -z "$OUT_FILE" ]; then
	mkdir -p "$REPO_ROOT/.bench"
	OUT_FILE="$REPO_ROOT/.bench/throughput-$STAMP.json"
fi

# The transfer source. It answers with exactly the number of bytes asked for, which is
# what makes two runs comparable; override it for a machine that cannot reach it.
DOWNLOAD_URL=${APPTAIL_PROBE_URL:-"https://speed.cloudflare.com/__down?bytes=$BYTES"}
# Several, because one being down must not be reported as "no address".
IP_SERVICES=${APPTAIL_PROBE_IP_URLS:-"https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com"}

# median prints the middle value of the numbers on stdin, which is what a transfer rate
# wants: one sample landing on a congested moment must not move the recorded figure.
median() {
	sort -g | awk '{v[NR]=$1} END {
		if (NR == 0) { print "0"; exit }
		if (NR % 2) { printf "%.3f", v[(NR+1)/2] }
		else { printf "%.3f", (v[NR/2] + v[NR/2+1]) / 2 }
	}'
}

# transfer runs the download SAMPLES times through the given curl arguments and prints
# "megabytes-per-second connect-seconds first-byte-seconds", or nothing at all when every
# attempt failed. Rates are the median; a failure is never averaged into a number.
transfer() {
	local rates="" connects="" firsts="" line ok=0
	for _ in $(seq 1 "$SAMPLES"); do
		line=$(curl -sS --max-time 120 -o /dev/null \
			-w '%{speed_download} %{time_connect} %{time_starttransfer}\n' \
			"$@" "$DOWNLOAD_URL" 2>/dev/null) || continue
		[ -n "$line" ] || continue
		ok=$((ok + 1))
		rates="$rates${line%% *}"$'\n'
		connects="$connects$(printf '%s' "$line" | awk '{print $2}')"$'\n'
		firsts="$firsts$(printf '%s' "$line" | awk '{print $3}')"$'\n'
	done
	[ "$ok" -gt 0 ] || return 1
	printf '%s %s %s' \
		"$(printf '%s' "$rates" | grep -v '^$' | median | awk '{printf "%.2f", $1 / 1000000}')" \
		"$(printf '%s' "$connects" | grep -v '^$' | median)" \
		"$(printf '%s' "$firsts" | grep -v '^$' | median)"
}

# publicAddress prints the address this machine is seen at, from the first service that
# answers.
publicAddress() {
	local url answer
	for url in $IP_SERVICES; do
		answer=$(curl -sS --max-time 10 "$url" 2>/dev/null | tr -d '[:space:]') || continue
		case "$answer" in
		*[0-9a-fA-F]*[.:]*) printf '%s' "$answer" && return 0 ;;
		esac
	done
	return 1
}

# ---------------------------------------------------------------------------
# The agent, if one is running. Everything about it is optional: the direct lane
# below is the point of the probe and must run on a machine with no agent at all.
# ---------------------------------------------------------------------------
step "Probe: locating the agent"
CONFIG_FILE="${APPTAIL_CONFIG:-$HOME/Library/Application Support/app-tail/config.json}"
[ -f "$CONFIG_FILE" ] || CONFIG_FILE="$HOME/.config/app-tail/config.json"
if [ -z "$API_ADDR" ] && [ -f "$CONFIG_FILE" ]; then
	API_ADDR=$(sed -n 's/.*"uiListenAddr"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
		"$CONFIG_FILE" | head -1)
fi
# The API answers only callers holding the token the agent keeps beside its config and
# dashboard-address record. Without it every call below is refused, and the agent reads
# as not answering.
TOKEN_FILE="$(dirname "$CONFIG_FILE")/api-token"
API_TOKEN=""
[ -r "$TOKEN_FILE" ] && API_TOKEN=$(tr -d '[:space:]' <"$TOKEN_FILE")
AUTH=(-H "Authorization: Bearer $API_TOKEN")

AGENT_UP=false
INTERFACE_MODE="unknown"
FABRIC_INTERFACE=""
FABRIC_RUNNING=false
EGRESS_MODE="unknown"
EGRESS_TUNNEL=""
PROXY_ADDR=""
if [ -n "$API_ADDR" ] && curl -fsS --max-time 3 "${AUTH[@]}" "http://$API_ADDR/api/status" >/dev/null 2>&1; then
	AGENT_UP=true
	# What the user asked for, not what is momentarily in force: a run recorded while the
	# interface was still coming up would be labelled as a mode it was never in.
	TUN_JSON=$(curl -fsS --max-time 5 "${AUTH[@]}" "http://$API_ADDR/api/tun" 2>/dev/null || true)
	INTERFACE_MODE=$(printf '%s' "$TUN_JSON" |
		sed -n 's/.*"configured"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
	FABRIC_JSON=$(curl -fsS --max-time 5 "${AUTH[@]}" "http://$API_ADDR/api/fabric" 2>/dev/null || true)
	FABRIC_INTERFACE=$(printf '%s' "$FABRIC_JSON" |
		sed -n 's/.*"interface"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
	case "$FABRIC_JSON" in
	*'"running":true'*) FABRIC_RUNNING=true ;;
	esac
	EGRESS_JSON=$(curl -fsS --max-time 5 "${AUTH[@]}" "http://$API_ADDR/api/egress" 2>/dev/null || true)
	EGRESS_MODE=$(printf '%s' "$EGRESS_JSON" |
		sed -n 's/.*"mode"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
	EGRESS_TUNNEL=$(printf '%s' "$EGRESS_JSON" |
		sed -n 's/.*"tunnelId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
	PROXY_JSON=$(curl -fsS --max-time 5 "${AUTH[@]}" "http://$API_ADDR/api/proxy" 2>/dev/null || true)
	case "$PROXY_JSON" in
	*'"enabled":true'*)
		PROXY_ADDR=$(printf '%s' "$PROXY_JSON" |
			sed -n 's/.*"listening"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
		;;
	esac
	info "agent on $API_ADDR -- interface mode ${INTERFACE_MODE:-unknown}, egress ${EGRESS_MODE:-unknown}"
	if [ "$FABRIC_RUNNING" = true ]; then
		info "the fabric is carrying traffic on ${FABRIC_INTERFACE:-an interface it did not name}"
	else
		info "the fabric is not carrying traffic, so the rates below are not through it"
	fi
else
	if [ -z "$API_TOKEN" ]; then
		na "no API token readable at $TOKEN_FILE -- the app lanes below are skipped"
	else
		na "no agent answering${API_ADDR:+ on $API_ADDR} -- the app lanes below are skipped"
	fi
fi

# ---------------------------------------------------------------------------
# The address traffic is seen leaving from. Recorded whatever the mode is, and
# labelled with it: an address recorded while a VPN carries the internet is that
# VPN's, and using it later as the bare-ISP reference would pass a real leak.
# ---------------------------------------------------------------------------
step "Probe: public address"
PUBLIC_IP=$(publicAddress || true)
if [ -n "$PUBLIC_IP" ]; then
	info "seen at $PUBLIC_IP"
else
	na "no address service answered -- there is no reference to compare a leak against"
fi
ISP_REFERENCE=false
case "$EGRESS_MODE" in
"" | unknown | direct | this-machine | local)
	ISP_REFERENCE=true
	[ -n "$PUBLIC_IP" ] && info "nothing carries the internet, so this is the bare-ISP reference"
	;;
*)
	printf '    \033[33mNOTE -- egress mode is %s, so %s is that path'"'"'s address, not the ISP'"'"'s.\033[0m\n' \
		"$EGRESS_MODE" "${PUBLIC_IP:-the address above}"
	printf '    \033[33mRe-run with the internet carried by this machine to record the reference.\033[0m\n'
	;;
esac

# ---------------------------------------------------------------------------
# The transfers.
# ---------------------------------------------------------------------------
step "Probe: transfer, as the machine is configured now ($(printf '%s' "$BYTES") bytes x $SAMPLES)"
DIRECT=$(transfer || true)
if [ -n "$DIRECT" ]; then
	info "$(printf '%s' "$DIRECT" | awk '{printf "%s MB/s, connect %ss, first byte %ss", $1, $2, $3}')"
else
	na "the transfer failed every attempt -- no rate recorded"
fi

PROXIED=""
step "Probe: transfer through the app's proxy"
if [ -z "$PROXY_ADDR" ]; then
	na "the proxy is not listening -- nothing to measure through it"
elif [ -n "${APPTAIL_PROXY_URL:-}" ]; then
	# The credential stays in the environment and is never printed or written out.
	PROXIED=$(transfer --proxy "$APPTAIL_PROXY_URL" || true)
	[ -n "$PROXIED" ] ||
		na "the proxy refused or dropped every attempt -- check APPTAIL_PROXY_URL"
else
	PROXIED=$(transfer --proxy "socks5h://$PROXY_ADDR" || true)
	if [ -z "$PROXIED" ]; then
		na "the proxy at $PROXY_ADDR did not carry the transfer; if it requires a credential, set APPTAIL_PROXY_URL"
	fi
fi
if [ -n "$PROXIED" ]; then
	info "$(printf '%s' "$PROXIED" | awk '{printf "%s MB/s, connect %ss, first byte %ss", $1, $2, $3}')"
	if [ -n "$DIRECT" ]; then
		info "$(awk -v a="${DIRECT%% *}" -v b="${PROXIED%% *}" \
			'BEGIN {if (a > 0) printf "the app'"'"'s byte path keeps %.0f%% of the direct rate", 100 * b / a}')"
	fi
fi

# ---------------------------------------------------------------------------
# The record. One flat document per run, so two runs diff directly.
# ---------------------------------------------------------------------------
{
	printf '{\n'
	printf '  "recordedAt": "%s",\n' "$STAMP"
	printf '  "bytes": %s,\n' "$BYTES"
	printf '  "samples": %s,\n' "$SAMPLES"
	printf '  "agentRunning": %s,\n' "$AGENT_UP"
	printf '  "interfaceMode": "%s",\n' "${INTERFACE_MODE:-unknown}"
	printf '  "fabricRunning": %s,\n' "$FABRIC_RUNNING"
	printf '  "fabricInterface": "%s",\n' "$FABRIC_INTERFACE"
	printf '  "egressMode": "%s",\n' "${EGRESS_MODE:-unknown}"
	printf '  "egressTunnel": "%s",\n' "$EGRESS_TUNNEL"
	printf '  "publicAddress": "%s",\n' "$PUBLIC_IP"
	printf '  "publicAddressIsISP": %s,\n' "$ISP_REFERENCE"
	if [ -n "$DIRECT" ]; then
		printf '%s' "$DIRECT" | awk '{printf "  \"directMBps\": %s,\n  \"directConnectSeconds\": %s,\n  \"directFirstByteSeconds\": %s,\n", $1, $2, $3}'
	else
		printf '  "directMBps": null,\n  "directConnectSeconds": null,\n  "directFirstByteSeconds": null,\n'
	fi
	if [ -n "$PROXIED" ]; then
		printf '%s' "$PROXIED" | awk '{printf "  \"proxyMBps\": %s,\n  \"proxyConnectSeconds\": %s,\n  \"proxyFirstByteSeconds\": %s\n", $1, $2, $3}'
	else
		printf '  "proxyMBps": null,\n  "proxyConnectSeconds": null,\n  "proxyFirstByteSeconds": null\n'
	fi
	printf '}\n'
} >"$OUT_FILE"

step "Probe: recorded to $OUT_FILE"
