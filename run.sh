#!/usr/bin/env bash
# Build if stale and run the agent on a fixed dev UI port (the SPA dev server proxies here).
# Usage: ./run.sh

# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/scripts/lib.sh"

build_ui_if_stale || na "UI not built; dashboard will not be served"
build_binary

step "Starting agent on http://$DEV_UI_ADDR"
# The dashboard signs in with a one-time link, and the Vite dev server (cd ui && npm run
# dev) needs one minted for its own port.
info "for the Vite dev server, run this once the agent is up:"
info "  $BIN_PATH dashboard --print --base http://localhost:5173"
exec "$BIN_PATH" --ui-addr "$DEV_UI_ADDR" "$@"
