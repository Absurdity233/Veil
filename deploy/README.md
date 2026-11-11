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

## Two deployment shapes

| | with a DNS name | IP only |
|---|---|---|
| certificate | Let's Encrypt, trusted | Caddy's internal CA, browser warns |
| port 80 | needed for the ACME challenge | not used |
| `tls` line in Caddyfile | `tls {$VEIL_EMAIL}` or omitted | `tls internal { on_demand }` |
| browser warning | none | once, then never again for that host |

Both produce an `https://` origin, which is what the client actually needs. The
difference is whether the certificate is vouched for by a public CA or only by
this host.

### IP only: the `on_demand` detail

An address-only site in Caddy — `:443` with no host in the site key — gets no TLS
connection policy on its own. The symptom is specific and misleading: the log says
`listening only on the HTTPS port but has no TLS connection policies`, and every
handshake fails with `tlsv1 alert internal error` *before any HTTP is seen*. It
looks like a broken certificate; it is a missing policy.

`tls internal { on_demand }` fixes it, because there is no name to pre-issue a
certificate for — the client connects to the address, so the certificate has to be
produced for whatever SNI arrives.

Caddy logs an abuse warning for on-demand TLS. It does not apply here: the
internal CA only signs, nothing leaves the machine, and the certificate is refused
by any browser that has not trusted this CA.

## Requirements

- A host with a public IPv4 address.
- Docker with the compose plugin.
- Port 443 free. Port 80 is only needed for a public certificate.
- **A DNS name OR acceptance of a self-signed certificate.** There is no third
  option: no public CA issues certificates for bare IP addresses.

## Deploy

```bash
# on the server
git clone https://github.com/Absurdity233/Veil.git
cd Veil/deploy

cp .env.example .env
$EDITOR .env          # set VEIL_DOMAIN

./up.sh
```

`up.sh` is safe to re-run — that is how an update is applied. It does the
preflight that catches the failures which otherwise look like application bugs:

1. port 443 is free, or already held by this stack
2. builds, starts, waits for the relay's own healthcheck
3. waits for TLS, then fetches `/health` over https
4. checks that a **foreign Origin is refused** — the one websocket rule that is
   invisible until a browser fails to connect
5. checks that a real upgrade reaches the relay at all

## Without a DNS name

Uncomment nothing: set `VEIL_DOMAIN` to the IP and the Caddyfile's
`tls internal { on_demand }` already covers it. The origin becomes
`https://<ip>`, which *is* a secure context, so the web client works after the
browser's certificate warning is accepted.

To remove the warning, import the CA once. It lives in the caddy container at
`/data/caddy/pki/authorities/local/root.crt`:

```bash
docker cp veil-caddy:/data/caddy/pki/authorities/local/root.crt ./veil-ca.crt
```

Import `veil-ca.crt` into the OS trust store, or into the browser, on each device
that will connect. This is a real trust decision — you are trusting this host to
vouch for itself — and it is appropriate for a personal deployment, not for one
whose users you cannot ask.

What does not work is plain `http://<ip>:8080`. The page will load and the client
will refuse to create keys, because `crypto.subtle` is undefined on an insecure
origin. That is the client doing its job.

## Verifying a deployed host

Live and verified on an IP-only host:

| check | result |
|---|---|
| `/health` over public https | `200 ok` |
| `/` (the page) | `200` |
| `/wasm/veil.wasm` | `200`, ~180 KB |
| `/app.js` | `200`, ~76 KB |
| certificate chain | `Verify return code: 0 (ok)` against the local CA |
| foreign `Origin` on `/ws` | `403` |
| deployment's own `Origin` on `/ws` | upgrade reaches the relay |
| CSP / HSTS / `X-Frame-Options` | present on every response |

On that host port 80 belongs to another service, so Caddy binds 443 only. That is
recorded in the compose file rather than left as a surprise.

Addresses are deliberately not recorded in this repository. A deployment's host
is deployment configuration, not project documentation, and it lives only in the
`.env` on the server.

| check | result |
|---|---|
| `/health` over public https | `200 ok` |
| `/` (3.1 KB page) | `200` |
| `/wasm/veil.wasm` | `200`, 180 KB |
| `/app.js` | `200`, 76 KB |
| certificate chain | `Verify return code: 0 (ok)` against the local CA |
| foreign `Origin` on `/ws` | `403` |
| deployment's own `Origin` on `/ws` | upgrade reaches the relay |
| CSP / HSTS / `X-Frame-Options` | present on every response |

Port 80 belongs to another service on this host, so Caddy binds 443 only. That is
recorded in the compose file rather than left as a surprise.

## Operating it

```bash
docker compose ps
docker compose logs -f relay
docker compose logs -f caddy      # TLS and certificate issuance live here

# confirm nothing but 443 is published
docker compose ps --format '{{.Name}} {{.Ports}}'
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
cd deploy && ./up.sh
```

The relay's schema migrations run on startup and are additive, so an existing
database keeps working. Downgrading is not supported — the schema moves forward.

## Hardening already in place

| | |
|---|---|
| relay image | distroless, non-root, read-only root filesystem |
| relay exposure | no published ports; reachable only from Caddy |
| caddy | no new privileges |
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
- **No public trust for the certificate.** Any device that connects has to accept
  the warning or import the CA once.
