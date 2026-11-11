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

echo "==> resolving $VEIL_DOMAIN"
if ! getent hosts "$VEIL_DOMAIN" >/dev/null 2>&1; then
	echo "    $VEIL_DOMAIN does not resolve." >&2
	echo "    Caddy cannot obtain a certificate for a name with no A record." >&2
	echo "    Point DNS at this host, or use the local CA (see Caddyfile)." >&2
	exit 1
fi
resolved=$(getent hosts "$VEIL_DOMAIN" | awk '{print $1}' | head -n1)
echo "    $resolved"

echo "==> checking that the name resolves to this host"
public_ip=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)
if [ -n "$public_ip" ] && [ "$resolved" != "$public_ip" ]; then
	echo "    warning: $VEIL_DOMAIN -> $resolved, but this host is $public_ip" >&2
	echo "    a certificate will still be issued only if the record is correct" >&2
fi

echo "==> checking ports 80 and 443"
if command -v ss >/dev/null 2>&1; then
	for port in 80 443; do
		if ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN; then
			echo "    port $port is already in use" >&2
			echo "    stop whatever holds it; Caddy needs both for ACME" >&2
			exit 1
		fi
	done
fi
echo "    free"

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
# Issuance can take a few seconds on a first run, so this retries rather than
# declaring failure on the first attempt.

echo
echo "==> waiting for the certificate"
tries=0
until curl -fsS --max-time 5 "https://$VEIL_DOMAIN/health" >/dev/null 2>&1; do
	tries=$((tries + 1))
	if [ "$tries" -gt 40 ]; then
		echo "    https://$VEIL_DOMAIN/health did not answer in 40s" >&2
		echo "    the usual cause is DNS pointing somewhere else, or 80/443 blocked" >&2
		docker compose logs --tail=40 caddy >&2
		exit 1
	fi
	sleep 2
done

echo "    https is up"
echo
curl -fsS "https://$VEIL_DOMAIN/health" && echo

echo
echo "==> checking the websocket origin allow-list"
# A request with no Origin is what a native client sends, and must be accepted.
# A request with a foreign Origin must not be.
if curl -fsS --max-time 5 \
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
echo "done. the web client is at https://$VEIL_DOMAIN"
