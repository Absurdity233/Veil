# Architecture

Veil is three pieces that fit together and can be read independently.

```
┌──────────────────────────┐              ┌──────────────────────────┐
│ Android device A         │              │ Android device B         │
│                          │              │                          │
│  Compose UI              │              │  Compose UI              │
│  ChatController          │              │  ChatController          │
│  ─────────────────────   │              │  ─────────────────────   │
│  VeilEngine (JNI)        │              │  VeilEngine (JNI)        │
│    X3DH                  │              │    X3DH                  │
│    Double Ratchet        │              │    Double Ratchet        │
└────────────┬─────────────┘              └────────────┬─────────────┘
             │        WebSocket, opaque bytes          │
             └──────────────────┬──────────────────────┘
                                ▼
                    ┌───────────────────────┐
                    │  Go relay             │
                    │  routing + outbox     │
                    │  no keys, no plaintext│
                    └───────────┬───────────┘
                                ▼
                          SQLite file
```

## Where each responsibility lives

| Layer | Owns | Never sees |
|---|---|---|
| `app/` (Kotlin + Compose) | UI, relay connection, send state, encrypted at-rest storage | private keys |
| `core-native/` (C++17) | identity, prekeys, X3DH, Double Ratchet, wire framing | network, disk |
| `server/` (Go) | routing, offline queue, registration proof | any key, any plaintext |

The split is deliberate. The crypto engine has no I/O at all, so it can be run
on a build machine with no Android SDK in the way, and the relay has no
cryptographic code, so "the relay cannot read your messages" is a property you
can check by reading one package.

## core-native

```
src/main/cpp/veil/
  common.h          fixed-width types, endian helpers, constant-time compare
  crypto.{h,cpp}    thin wrappers over the vendored Monocypher primitives
  random.{h,cpp}    platform CSPRNG (BCrypt / getrandom / /dev/urandom)
  keys.{h,cpp}      identity, signed prekey, one-time prekeys, bundle codec
  ratchet.{h,cpp}   X3DH handshake and the Double Ratchet
  engine.{h,cpp}    session registry, wire framing, safety number, pinning
src/main/cpp/jni/veil_jni.cpp    the entire native surface
third_party/monocypher/          vendored primitives, pinned by hash
host/tests/test_core.cpp         host-side suite
host/fuzz/fuzz_parsers.cpp       libFuzzer targets for the parsers
```

Monocypher supplies the primitives — X25519, XChaCha20-Poly1305, Ed25519,
HKDF-SHA512, BLAKE2b. Everything above the primitive line is in this
repository: the handshake, the ratchet, the wire format, the prekey lifecycle.

The prekey lifecycle lives here rather than in the client because it is
cryptographic state, not UI state. Three things about it are easy to get wrong
and are therefore explicit:

- **The signed prekey id is a persisted monotonic counter.** It used to be the
  constant `1`, regenerated with fresh keys on every launch. Same id with
  different keys is indistinguishable from a stale bundle on the wire, and it
  let the relay overwrite the row under the same name.
- **Two generations are kept.** A peer may have downloaded the previous bundle
  just before a rotation and only send its first message afterwards; without the
  retired private half that handshake could never complete.
- **Every one-time prekey carries a consumed flag.** The relay pops its copy
  when it hands one out, but the private half lives here, and without a local
  record a replayed first frame could run X3DH against it twice.

All of it is exported for encrypted storage and restored before any frame is
decrypted.

The JNI surface is deliberately narrow. Nineteen entry points, each of which
validates its arguments, calls the engine, and converts back. No protocol logic
lives there, and no exception crosses the boundary.

## app

```
ChatController.kt   glue between UI, relay and engine; owns the send queue
crypto/             IdentityVault, SessionVault — Keystore-backed AES-GCM
net/                RelayClient (websocket), Wire (framing, field codec)
data/               in-memory store, models
ui/                 Compose screens
```

Every call into the engine runs on a single-threaded dispatcher. The engine
keeps per-peer ratchet state with no internal locking, so one thread is cheaper
than a mutex and removes the ordering question entirely.

## server

```
main.go       process setup, TLS mode, signal handling, outbox sweep
hub.go        connection registry, fan-out, challenge handshake, rate limiting
store.go      SQLite: accounts, prekeys, outbox, per-recipient sequence
protocol.go   envelope and field codec
prekeys.go    one-time prekey hand-out
errors.go     the rejection vocabulary
```

The relay is a switchboard with a bounded memory. It knows *who* sent *how many
bytes* to *whom*; it has no code path that could recover message content.

## Data flow for one message

1. Alice's UI calls `sendMessage`. The controller encrypts on the crypto thread,
   which advances her sending chain and returns a frame of opaque bytes.
2. The frame is written to the socket. If the socket cannot take it, the exact
   bytes are queued and replayed on reconnect — re-encrypting would advance the
   chain a second time and leave Bob with a hole he can never fill.
3. The relay looks at the recipient field, not the body, and either pushes the
   frame to Bob's live socket or appends it to his outbox under the next
   per-recipient sequence number.
4. Bob decrypts. The ratchet either accepts the frame, or reports that it is a
   duplicate (routine, at-least-once delivery) or that it failed to
   authenticate on an unseen counter (not routine).
5. If the frame came out of the outbox, Bob acknowledges the sequence number,
   which also pulls the next page of his backlog.
