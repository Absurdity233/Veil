#!/bin/sh
# Liveness and readiness probe for the relay.
#
# The image is distroless, so there is no shell, no curl and no wget inside the
# container: a healthcheck has to be a binary call. That is why this script
# runs on the *host* (or in an orchestrator's sidecar) and probes the exposed
# port from outside.
#
#   ./scripts/healthcheck.sh [host] [port]
#
# Exits 0 when the relay answers /health with 200, 1 otherwise.

set -eu

HOST="${1:-127.0.0.1}"
PORT="${2:-8080}"

URL="http://${HOST}:${PORT}/health"

if command -v curl >/dev/null 2>&1; then
    # --noproxy: a relay on the loopback must not be reached through whatever
    # proxy the host happens to have configured. curl on Windows reads the
    # system proxy, which turns a perfectly healthy local relay into a timeout.
    code=$(curl -fsS --noproxy '*' -o /dev/null -w '%{http_code}' \
        --max-time 5 "$URL" || true)
elif command -v wget >/dev/null 2>&1; then
    if wget -q -T 5 -O /dev/null "$URL"; then code=200; else code=000; fi
else
    echo "healthcheck: neither curl nor wget is available" >&2
    exit 1
fi

if [ "$code" = "200" ]; then
    exit 0
fi

echo "healthcheck: $URL returned $code" >&2
exit 1