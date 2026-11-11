#!/usr/bin/env sh
# Brings the stack up and proves it works.
#
# Run from the deploy/ directory on the server. Nothing here assumes a domain is
# already resolvable: the checks below report what is wrong rather than failing
# with a TLS error three layers down.

set -eu

cd "$(dirname "$0")"

if [ ! -f .env ]; then
	echo "no .env: copy .env.example and set VEIL_DOMAIN" >&2
	exit 1
fi

# shellcheck disable=SC1091
. ./.env

if [ -z "${VEIL_DOMAIN:-}" ] || [ "$VEIL_DOMAIN" = "veil.example.com" ]; then
	echo "VEIL_DOMAIN is unset or still the placeholder" >&2
	exit 1
fi

echo "domain: $VEIL_DOMAIN"
echo

# ---- Preflight --------------------------------------------------------
#
# Both of these are the failures that look like application bugs and are not.

echo "==> checking port 443"
# 80 is deliberately not checked: this deployment binds 443 only, because an
# IP-only host cannot pass an ACME HTTP challenge and something else may already
# be using 80.
#
# 443 is checked only when the stack is not already running. Re-running this
# script is the normal way to update a deployment, and the port is then held by
# our own Caddy - reporting that as a conflict would make the script refuse to
# do the thing it exists for.
already_running=$(docker compose ps --status running --services 2>/dev/null | grep -cx caddy || true)
if [ "$already_running" -eq 0 ] && command -v ss >/dev/null 2>&1; then
	if ss -ltn "sport = :443" 2>/dev/null | grep -q LISTEN; then
		echo "    port 443 is already in use by something other than this stack" >&2
		echo "    stop it; Caddy needs 443" >&2
		exit 1
	fi
fi
echo "    free, or already held by this stack"

# ---- Build and start --------------------------------------------------

echo
echo "==> building"
docker compose build

echo
echo "==> starting"
docker compose up -d

echo
echo "==> waiting for the relay to report healthy"
tries=0
until docker compose ps relay --format '{{.Health}}' 2>/dev/null | grep -q healthy; do
	tries=$((tries + 1))
	if [ "$tries" -gt 60 ]; then
		echo "    the relay did not become healthy in 60s" >&2
		docker compose logs --tail=40 relay >&2
		exit 1
	fi
	sleep 1
done
echo "    healthy"

# ---- Verify ----------------------------------------------------------
#
# The certificate here is self-signed, so curl has to be told not to validate it.
# That is not skipping a check: the check that matters is that TLS terminates and
# the relay answers, not that a public CA signed the certificate for an IP
# address, which no CA will do.

echo
echo "==> waiting for TLS"
tries=0
until curl -fsSk --max-time 5 "https://$VEIL_DOMAIN/health" >/dev/null 2>&1; do
	tries=$((tries + 1))
	if [ "$tries" -gt 40 ]; then
		echo "    https://$VEIL_DOMAIN/health did not answer in 40s" >&2
		docker compose logs --tail=40 caddy >&2
		exit 1
	fi
	sleep 2
done

echo "    https is up"
echo
curl -fsSk "https://$VEIL_DOMAIN/health" && echo

echo
echo "==> checking the websocket origin allow-list"
# A websocket upgrade with a foreign Origin must be refused. This is the one
# deployment rule that is invisible until a browser fails to connect, and it is
# checked before the handshake can proceed: the relay answers 403 during the HTTP
# upgrade, so a bare upgrade request with no HELLO is enough.
if curl -fsSk --max-time 5 \
	-H "Upgrade: websocket" -H "Connection: Upgrade" \
	-H "Sec-WebSocket-Version: 13" \
	-H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
	-H "Origin: https://evil.example" \
	"https://$VEIL_DOMAIN/ws" -o /dev/null -w '%{http_code}' 2>/dev/null | grep -q 403; then
	echo "    a foreign origin is refused"
else
	echo "    warning: a foreign origin was not refused with 403" >&2
	echo "    check VEIL_ALLOWED_ORIGINS reached the container:" >&2
	echo "    docker compose exec relay printenv VEIL_ALLOWED_ORIGINS" >&2
fi

echo
echo "==> checking the socket accepts a real handshake"
# A 101 here would mean the upgrade succeeded and HELLO was never sent, which is
# what a curl probe without a HELLO produces. What is being checked is that the
# upgrade reaches the relay: 400 means the relay read it and wanted a proper
# HELLO (it got an empty websocket frame), 403 would mean a blocked origin, and
# a TLS error would mean Caddy is not terminating.
code=$(curl -sk --max-time 5 \
	-H "Upgrade: websocket" -H "Connection: Upgrade" \
	-H "Sec-WebSocket-Version: 13" \
	-H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
	-H "Origin: https://$VEIL_DOMAIN" \
	"https://$VEIL_DOMAIN/ws" -o /dev/null -w '%{http_code}' 2>/dev/null || true)
case "$code" in
	101|400) echo "    the upgrade reaches the relay" ;;
	403) echo "    the origin allow-list rejected the deployment's own origin" >&2
	     echo "    check that VEIL_ALLOWED_ORIGINS matches https://$VEIL_DOMAIN" >&2 ;;
	000) echo "    TLS did not complete; check the caddy logs" >&2 ;;
	*) echo "    unexpected status $code" >&2 ;;
esac

echo
echo "done. the web client is at https://$VEIL_DOMAIN"
echo
echo "the certificate is self-signed (no public CA issues one for an IP)."
echo "The browser will warn once; the client works after it is accepted, because"
echo "the origin is still a secure context and crypto.subtle requires no more."
echo "On this host the CA is at /data/caddy/pki/authorities/local/root.crt in the"
echo "caddy container; importing it removes the warning."
