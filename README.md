# Veil

An end-to-end encrypted chat system: an Android client that runs the Signal
protocol on-device, and a relay written in Go that forwards ciphertext it
cannot read.

```
   Android device A                    Android device B
 ┌──────────────────┐                ┌──────────────────┐
 │ Compose UI       │                │ Compose UI       │
 │ ChatController   │                │ ChatController   │
 │ VeilEngine (JNI) │                │ VeilEngine (JNI) │
 │   X3DH           │                │   X3DH           │
 │   Double Ratchet │                │   Double Ratchet │
 └────────┬─────────┘                └────────┬─────────┘
          │        WebSocket, opaque bytes     │
          └───────────────┬───────────────────┘
                          ▼
              ┌───────────────────────┐
              │   Go relay (this repo)│
              │  routes + offline box │
              │  no keys, no plaintext│
              └───────────┬───────────┘
                          ▼
                    SQLite file
```

## What is encrypted, and by whom

| Layer | Protects against | Relay sees |
|---|---|---|
| TLS | network observers | nothing (terminates TLS) |
| X3DH + Double Ratchet | the relay itself, database theft, future compromise | ciphertext only |

The relay is a switchboard. It knows *who* sent *how many bytes* to *whom*. It
cannot recover a single character of message content, and there is no code
path in it that tries.

## Layout

```
app/                 Android client (Kotlin + Compose)
core-native/         Protocol engine (C++17), JNI binding, host tests
server/              Relay (Go), Docker image
build/relay/         Compiled relay binary (gitignored)
```

### core-native

```
src/main/cpp/veil/
  common.h        fixed-width types, endian helpers, constant-time compare
  crypto.{h,cpp}  thin wrappers over the vendored Monocypher primitives
  random.{h,cpp}  platform CSPRNG (BCrypt / /dev/urandom)
  keys.{h,cpp}    identity, signed prekey, one-time prekeys, bundle codec
  ratchet.{h,cpp} X3DH handshake and the Double Ratchet
  engine.{h,cpp}  session registry, wire framing, safety number
src/main/cpp/jni/veil_jni.cpp   the entire native surface
third_party/monocypher/         vendored crypto primitives
host/tests/test_core.cpp        host-side test suite
```

Monocypher supplies the primitives (X25519, XChaCha20-Poly1305, Ed25519,
HKDF-SHA512, BLAKE2b). Everything above the primitive line — the handshake,
the ratchet, the wire format — is implemented here.

### server

```
main.go       process setup, signal handling
hub.go        connection registry, fan-out, websocket lifecycle
store.go      SQLite: accounts, prekeys, outbox
protocol.go   envelope and field codec
prekeys.go    one-time prekey consumption
```

## Protocol

### Envelope

```
[1] version | [1] type | [4] payload length (big endian) | payload
```

Payload fields are length-prefixed except where a fixed width is part of the
format. A frame whose length does not match its header is rejected before any
field is read.

### Message types

| Type | Direction | Purpose |
|---|---|---|
| `HELLO` | client → relay | claim a user id, naming an identity key |
| `AUTH_CHALLENGE` | relay → client | 32-byte nonce the client must sign |
| `AUTH_RESPONSE` | client → relay | Ed25519 signature over the nonce |
| `HELLO_OK` | relay → client | id bound; the connection is usable |
| `PUBLISH_PREKEYS` | client → relay | store signed + one-time prekeys |
| `GET_BUNDLE` | client → relay | fetch a peer's prekey bundle |
| `BUNDLE` | relay → client | identity, signed prekey, one one-time prekey |
| `SEND` | client → relay | opaque body for a recipient |
| `DELIVER` | relay → client | `[8] outbox id \| [sender] \| [body]` |
| `MORE_PENDING` | relay → client | the last page was full; ACK to pull the next |
| `ACK` | client → relay | `[8]` seq: drop entries up to it, and pull the next page |
| `ERROR` | relay → client | human-readable rejection |

A live delivery carries outbox id `0`; a replayed one carries the real id so
the client can acknowledge it.

The id is **8 bytes** and is a *per-recipient* sequence number. It used to be
the SQLite rowid truncated to 4 bytes: that counter is global, so it was sparse
per recipient (a client had to acknowledge ids it never received), it wrapped
at 2^32, and after the wrap an acknowledgement could delete a different
recipient's entry. A dense per-recipient counter scoped to the recipient has
neither problem.

Registration is a challenge-response, not a claim. `HELLO` gets a nonce back,
and the user id is only bound once the client proves it holds the identity
signing key by signing that nonce. Without it an unused id would be
first-come-first-served, and anyone could take it and publish prekeys of their
own under it.

Replay is paged. A connection that has a backlog receives up to 200 entries,
then `MORE_PENDING`; each `ACK` acknowledges what was consumed and pulls the
following page, so nothing is stranded behind the first page.

Delivery is **at-least-once**: a message can arrive live and then again as a
replay out of the outbox. The ratchet refuses the second copy, and the client
is told *why* — `DUPLICATE` is acknowledged silently, while a frame that fails
on a counter never seen before is surfaced as an authentication failure. Before
that distinction existed, every duplicated delivery looked like an attack.

Sends are paced per connection (a token bucket, 30 burst / 1 per 10s). The
outbox is not free storage: it expires after 7 days, is capped at 2000 entries
per recipient, and the oldest entries go first when the cap is reached.

### Endpoints

| Path | Purpose |
|---|---|
| `/ws` | the relay itself |
| `/healthz` | liveness only; touches nothing, so a slow disk cannot cause a restart |
| `/readyz` | readiness; reports queue depth, live connections, and fails 503 when the store cannot be written |
| `/health` | alias of `/readyz`, for the container probe and older deployments |

### Ratchet frame

```
[1]   flags            bit 0 = carries a prekey header
[200] prekey header    only when the flag is set
[40]  ratchet header   dh public | previous chain length | message number
[n]   ciphertext || 16-byte MAC
```

The prekey header is

```
[32] sender identity DH key
[32] sender identity signing key
[64] binding signature   (signing key over the DH key)
[32] sender ephemeral key
[32] recipient identity DH key
[4]  signed prekey id | [4] one-time prekey id
```

It travels with **every** frame until the peer answers. A first frame can be
lost — the socket drops, the outbox entry is discarded, the peer restarts — and
if the header went with it the handshake could never be retried.

The ratchet header is authenticated as associated data, so it cannot be
rewritten in flight.

## Cryptography

**Identity binding** — the identity is two keys, a Curve25519 key for X3DH and
an Ed25519 key that signs prekeys. They are tied together explicitly: the
signing key signs the DH public key, and every bundle and prekey header carries
that signature. A prekey signature covers
`"Veil/signed-prekey/v1" || identity_dh_pub || signed_pub`, so a relay cannot
pair a victim's DH key with its own signing key and then vouch for a prekey of
its choosing.

**X3DH** — the sender verifies the signed prekey against the peer's identity
key, then runs four Diffie-Hellman operations and derives a shared secret with
HKDF-SHA512 over `0xFF*32 || DH1 || DH2 || DH3 || DH4`. Inbound refuses a
header that names a signed prekey id the device does not hold; the previous
signed prekey stays usable until the next rotation, so a bundle fetched just
before a rotation still works.

**Double Ratchet** — a symmetric ratchet advances per message
(`HMAC-SHA512(chain, 0x02)` for the next chain key, `0x01` for the message
key), and a DH ratchet advances whenever the peer publishes a new ratchet key.
Message keys are discarded after use, which is what gives forward secrecy.

**Skipped keys** — message keys are cached so out-of-order delivery still
decrypts, under two bounds: 1000 per chain, and 2000 across the whole session.
The per-chain cap alone bounded nothing, because a peer opens a new chain every
time it publishes a ratchet key — the memory a remote party could pin grew with
the number of ratchet steps it felt like taking. The global cap is what holds,
and it evicts the oldest chain first.

**Safety number** — BLAKE2b-256 over **both halves of both identities**, in
sorted order by DH key, rendered as five groups of five digits. Hashing only
the DH keys would leave the signing key — the one that actually authenticates
prekeys — outside what the user verifies. Comparing the digits out of band
rules out a middlebox.

**Identity pinning** — once a peer label has been bound to an identity, every
later bundle for that label must present the same identity. A different one is
reported as `IDENTITY_CHANGED` and nothing is sent; the pin survives a restart
and is *not* cleared by dropping the session, because otherwise a re-handshake
could silently swap the peer.

**Prekey lifecycle** — the signed prekey id comes from a counter carried in the
persisted prekey state, so it only moves forward. It used to be the constant
`1`, regenerated with fresh keys on every launch: same id, different key, which
is indistinguishable from a stale bundle on the wire. Two generations are kept
(current and retired), and every one-time prekey carries a *consumed* flag that
is persisted — the relay pops an entry when it hands it out, but without a local
record the private half stayed usable, and a replayed first frame could run
X3DH against it a second time. A fresh batch is generated when the unspent
supply drops below half.

**Forward secrecy of state** — ratchet state, identity pins and prekey state
are stored through AES-GCM keys held by the Android Keystore. Prekey state is
in that set because whoever holds it can read the first message of any session
that used it. None of it touches disk in the clear.

**Session state is asked for, not cached** — the engine reports
`NoPeer / PinnedOnly / Ready`. The UI used to infer "a session exists" from a
cached safety number, which outlived a restart in which the session did not, so
the screen could claim a session was live while every frame was being dropped.

## Building

### Relay

```bash
cd server
go build -o ../build/relay/veil-relay .
```

Or with Docker:

```bash
cd server
docker compose up --build
```

The image is distroless and runs as a non-root user with a read-only root
filesystem; the SQLite file lives on a named volume. Because that image has no
shell and no HTTP client, the container healthcheck is the relay binary probing
itself (`veil-relay -healthcheck`), which checks `/health` rather than merely
that the port is bound — a bound port says nothing about whether the store is
usable.

From outside the container, `scripts/healthcheck.sh [host] [port]` does the same
probe with `curl`, falling back to `wget`.

The relay speaks plain `ws://` and expects TLS to be terminated in front of it,
or serves TLS itself when `VEIL_TLS_CERT` and `VEIL_TLS_KEY` are both set. It
says which mode it is in at startup, because "TLS is somebody else's job" is the
assumption that quietly does not hold.

Browser clients are only accepted from origins named in `VEIL_ALLOWED_ORIGINS`
(a comma-separated list); native clients send no `Origin` header and are always
accepted. Leaving the list empty is therefore the correct setting for an
Android-only deployment.

On `SIGTERM` the relay stops accepting handshakes, closes every live socket
with a `1001 going away` status, and waits up to 5 seconds for the handlers to
unwind. `http.Server.Shutdown` does not touch hijacked websockets, so without
this step clients learned about a deploy only when their next write failed.

### Android

```bash
./gradlew :app:assembleDebug
```

Requires the Android SDK with NDK `28.2.13676358` and CMake `3.22.1`. The
build produces `arm64-v8a` and `x86_64` only.

Point the client at the relay with the URL field on the home screen. The
default, `ws://10.0.2.2:8080/ws`, reaches the host loopback from an emulator.

The UI is localised (English and Simplified Chinese) and every interactive
element and message bubble carries a content description; the link state is
spelled out as a word as well as a colour. `FLAG_SECURE` is set in
`MainActivity`, so plaintext stays out of screenshots, screen recordings and the
recents thumbnail.

## Tests

Four suites, none of which needs a device.

```bash
# Protocol engine, on the build machine
#   Windows:  core-native\host\run_host_tests.bat
#   Linux/macOS:
cmake -S core-native/host -B build/host-cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build/host-cmake && ctest --test-dir build/host-cmake --output-on-failure

# Relay
cd server && go test -race ./...

# Client wire code against a real relay process
#   (builds nothing itself: it starts the binary at build/relay/veil-relay,
#    and skips if that file is absent)
cd server && go build -o ../build/relay/veil-relay . && cd ..
./gradlew :app:testDebugUnitTest

# Fuzzers
./build-fuzz-parsers -max_total_time=60          # C++, libFuzzer
cd server && go test -fuzz=FuzzEnvelope -fuzztime=60s
```

The host suite covers agreement, round-trip, out-of-order delivery, replay
rejection, tamper detection, forward secrecy, the skipped-key budget (per chain
*and* globally), session persistence, the identity binding and prekey signature,
rejection of a spliced signing key, the retired-prekey path, the prekey header
surviving a lost first frame, identity pinning surviving a restart, prekey state
surviving a restart, one-time prekeys being spent exactly once, the difference
between a duplicated delivery and a tampered one, the engine's session-state
enum, and the exact byte layouts the relay and client share.

The relay suite covers the challenge handshake, forged proofs, the origin
allow-list, prekey hand-out, live and offline delivery, paging a backlog larger
than one page, acknowledgement scoping, the per-recipient sequence being dense,
the expiry and per-recipient trim sweep, the send-rate limiter, readiness
reporting, and a clean shutdown that clients can observe.

The fuzz targets cover every parser that reads attacker bytes: the envelope and
field codec, the prekey set, and the three C++ deserialisers (wire frame,
prekey header, bundle, session state, prekey state).

CI (`.github/workflows/ci.yml`) runs the host suite, the same suite under
ASan+UBSan, a short libFuzzer pass, `go vet` and `go test -race`, a Go fuzz
pass, the client/relay interop test against a relay it builds itself, the APK
build, Android Lint, and the vendored-dependency hash check.

## Dependency pinning

`core-native/src/main/cpp/third_party/DEPENDENCIES.md` records the Monocypher
sources by SHA-256; `verify.sh` next to it checks them and runs in CI. Upstream
stamps `__git__` into the header rather than a release number, so a version
string alone is not a pin — the content hash is.

## Deliberate limits

- **One-to-one only.** Group messaging needs Sender Keys or per-member
  fan-out; neither is implemented.
- **Messages are in memory.** The session, the identity pin and the prekey
  state are persisted (encrypted, see above), but conversation history is not:
  a restart keeps the ability to talk, and loses the transcript.
- **Metadata is visible to the relay.** Who talks to whom, when, and how much
  — the protocol hides content, not traffic shape.
- **No account recovery.** The identity lives in the Android Keystore; losing
  the device means losing the identity. A keystore reset is reported rather
  than papered over as a first run.
- **No push notifications.** A message waits in the outbox until the client
  reconnects. FCM would carry an encrypted payload, and saying so plainly is
  cheaper than implying delivery is instant.

## Licence

Veil is licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).

Monocypher is vendored under its own licence (see
`core-native/src/main/cpp/third_party/monocypher/LICENCE.md`) and is the only
third-party code compiled into the client.
