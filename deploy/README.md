# Deploying

The relay and the web client, in Docker, behind TLS.

Nothing here is optional decoration: a browser refuses to expose `crypto.subtle`
on a non-secure origin, so the web client will not generate keys over plain
`http://` or `ws://`. It does not degrade — it declines to start. TLS is the
first requirement, not a hardening step.

## What gets deployed

```
internet ──443──▶ caddy ──┬── /        the web client, static
                          ├── /ws      the relay's websocket
                          └── /health  readiness, for a monitor
                             │
                             ▼
                          relay ──▶ /data/veil.db   (ciphertext only)
```

Three facts about the relay worth knowing before you deploy it:

- It holds **no keys**. It routes opaque ciphertext and stores device lists and
  prekey bundles. A compromise of the host does not let anyone read messages.
- It **cannot forge a device or a prekey**. Both are signed by keys it never
  sees.
- Its database is **ciphertext and metadata**. It knows who talks to whom, when,
  and how many devices each participant has. That is stated in the
  [threat model](threat-model.md) rather than glossed over.

## Requirements

- A host with a public IPv4 address.
- **A DNS name.** Caddy needs one to obtain a certificate; an IP address alone
  cannot have one. Point an A record at the host.
- Ports 80 and 443 reachable. ACME uses 80 for the HTTP challenge.

## Deploy

```bash
# on the server
git clone https://github.com/Absurdity233/Veil.git
cd Veil/deploy

cp .env.example .env
$EDITOR .env          # set VEIL_DOMAIN

./up.sh
```

`up.sh` does the preflight that catches the failures which otherwise look like
application bugs:

1. the name resolves, and to this host
2. ports 80/443 are free
3. builds, starts, waits for the relay's own healthcheck
4. waits for the certificate, then fetches `/health` over https
5. checks that a **foreign Origin is refused** — the one websocket rule that is
   invisible until a browser fails to connect

If it finishes, the deployment works. If it stops, it names which of those five
is wrong.

## Without a DNS name yet

Two options, both honest about the trade:

**Use Caddy's local CA.** Uncomment the `local_certs` global option in
`Caddyfile`, set `VEIL_DOMAIN=HOST_ADDRESS`, and start. The origin becomes
`https://HOST_ADDRESS`, which *is* a secure context, so the web client works
after the browser's certificate warning is accepted. Fine for testing and for a
deployment with no public name.

**Use a name you control.** If you own any domain, a subdomain A record is
enough and gives a real certificate with no warnings.

What does not work is plain `http://HOST_ADDRESS:8080`. The page will load and
the client will refuse to create keys, because `crypto.subtle` is undefined on an
insecure origin. That is the client doing its job.

### For HOST_ADDRESS specifically

Because `VEIL_DOMAIN` also feeds the relay's origin allow-list, the two modes need
matching values:

| mode | `VEIL_DOMAIN` | `Caddyfile` | relay origin |
|---|---|---|---|
| local CA | `HOST_ADDRESS` | uncomment `local_certs` | `https://HOST_ADDRESS` |
| real certificate | `chat.example.com` | unchanged | `https://chat.example.com` |

The compose file derives the allow-list from `VEIL_DOMAIN`, so there is one value
to get right rather than two that can disagree.

## Operating it

```bash
docker compose ps
docker compose logs -f relay
docker compose logs -f caddy      # certificate issuance lives here

# relay statistics, without exposing anything
docker compose port caddy 443     # should be 0.0.0.0:443
```

### Backup

One file: the SQLite database in the `veil-data` volume. It contains ciphertext,
device credentials and prekey bundles — no plaintext and no private keys.

```bash
docker compose exec relay cat /data/veil.db > "veil-$(date +%F).db"
```

A restored database brings back undelivered messages and device lists. It does
not bring back an identity: those live on devices, and the relay never had them.

### Updating

```bash
git pull
cd deploy && docker compose up -d --build
```

The relay's schema migrations run on startup and are additive, so an existing
database keeps working. Downgrading is not supported — the schema moves forward.

## Hardening already in place

| | |
|---|---|
| relay image | distroless, non-root, read-only root filesystem |
| relay exposure | no published ports; reachable only from Caddy |
| caddy | non-root, no new privileges |
| websocket origins | explicit allow-list; empty means native clients only |
| HSTS | one year, including subdomains |
| content policy | `script-src 'self' 'wasm-unsafe-eval'`, no third-party anything |
| framing | `X-Frame-Options: DENY` and `frame-ancestors 'none'` |

## What this deployment does not do

- **No push notifications.** A message waits in the relay's outbox until the
  client reconnects. A mobile client closed for a day sees a backlog, not a
  notification.
- **No multi-node.** One relay, one SQLite file. Scaling out needs a shared
  store and a presence model, neither of which exists.
- **No account recovery.** The identity lives on the device. Lose the device,
  lose the account; that is a property of the protocol, not of this deployment.
