# Architecture

Veil is one protocol engine and three clients, plus a relay that fits between
them.

```
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Android         │  │ Desktop (JVM)   │  │ Browser         │
│ Kotlin + Compose│  │ Kotlin + Swing  │  │ TypeScript      │
│        │        │  │        │        │  │        │        │
│        ▼        │  │        ▼        │  │        ▼        │
│   JNI binding   │  │  JNA → C ABI    │  │  wasm → C ABI   │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         └─────────────┬──────┴────────────────────┘
                       ▼
            ┌─────────────────────┐
            │  veil-core (C++17)  │
            │  X3DH, Ratchet,     │
            │  prekeys, framing   │
            └──────────┬──────────┘
                       │  WebSocket, opaque bytes
                       ▼
            ┌─────────────────────┐
            │  Go relay           │
            │  routes + outbox    │
            └──────────┬──────────┘
                       ▼
                 SQLite file
```

## The C ABI is the seam

`core-native/src/main/cpp/veil/veil_c.h` is what makes three clients affordable.
It is a small, deliberately boring interface: no C++ types cross it, buffers are
caller-owned, and every fallible call returns a status rather than throwing.

Two rules govern it, and breaking either would defeat the purpose:

1. **No C++ type crosses the boundary.** No `std::string`, no `std::vector`, no
   references, no exceptions. A caller must be able to use it from a language
   that has none of those — which is the whole point of binding it from JNA and
   from WebAssembly.
2. **Buffers are caller-owned.** A producing call writes into memory the caller
   provided, or reports the size it needs. Nothing is allocated on one side and
   freed on the other.

The engine's `decrypt` is the one place where a status is more than success or
failure: it distinguishes `DUPLICATE` from `AUTH_FAILED`, because the relay is
at-least-once and a replay is routine while a failed MAC is not.

## Where each responsibility lives

| Layer | Owns | Never sees |
|---|---|---|
| `core-native/` (C++17) | identity, prekeys, X3DH, Double Ratchet, wire framing, the C ABI | network, disk |
| `app/` (Kotlin, Android) | UI, relay connection, Keystore-backed storage | private keys |
| `desktop/` (Kotlin, JVM) | UI, relay connection, file-backed storage | private keys |
| `web/` (TypeScript) | DOM, relay connection, IndexedDB-backed storage | private keys |
| `server/` (Go) | routing, offline queue, registration proof | any key, any plaintext |

The crypto engine has no I/O at all, so it can be run on a build machine with no
Android SDK in the way, compiled to wasm without a change, and exercised by a
native test suite. The relay has no cryptographic code, so "the relay cannot read
your messages" is a property you can check by reading one package.

## core-native

```
src/main/cpp/veil/
  common.h          fixed-width types, endian helpers, constant-time compare
  crypto.{h,cpp}    thin wrappers over the vendored Monocypher primitives
  random.{h,cpp}    platform CSPRNG, plus a pluggable host source for wasm
  keys.{h,cpp}      identity, signed prekey, one-time prekeys, bundle codec
  ratchet.{h,cpp}   X3DH handshake and the Double Ratchet
  engine.{h,cpp}    session registry, wire framing, safety number, pinning
  veil_c.{h,cpp}    the C ABI every non-Android client goes through
src/main/cpp/jni/veil_jni.cpp    the JNI surface (Android)
src/main/cpp/wasm/rng_bridge.cpp entropy bridge for WebAssembly
third_party/monocypher/          vendored primitives, pinned by hash
host/tests/                      host suite + C ABI suite
host/fuzz/fuzz_parsers.cpp       libFuzzer targets for the parsers
```

Monocypher supplies the primitives — X25519, XChaCha20-Poly1305, Ed25519,
HKDF-SHA512, BLAKE2b. Everything above the primitive line is in this repository:
the handshake, the ratchet, the wire format, the prekey lifecycle.

The prekey lifecycle lives here rather than in a client because it is
cryptographic state, not UI state. Three things about it are easy to get wrong
and are therefore explicit:

- **The signed prekey id is a persisted monotonic counter.** It used to be the
  constant `1`, regenerated with fresh keys on every launch. Same id with
  different keys is indistinguishable from a stale bundle on the wire, and it
  let the relay overwrite the row under the same name.
- **Two generations are kept.** A peer may have downloaded the previous bundle
  just before a rotation and only send its first message afterwards; without the
  retired private half that handshake could never complete. One-time prekeys
  live and die with their generation for the same reason.
- **Every one-time prekey carries a consumed flag.** The relay pops its copy
  when it hands one out, but the private half lives here, and without a local
  record a replayed first frame could run X3DH against it twice.

All of it is exported for encrypted storage and restored before any frame is
decrypted.

### Entropy, and why wasm needs help

A wasm module has no syscall, no `/dev/urandom` and no `BCrypt`. The engine
therefore exposes a single hook — `veil_set_random_source` — and the browser
installs `crypto.getRandomValues` through it before creating any engine. If the
browser refuses (an insecure origin disables it), key generation fails rather
than proceeding with predictable bytes.

## The clients

Each has the same three pieces, differing only in what the platform provides:

```
Controller    transport + storage + state, no cryptography
Relay client  the websocket, the envelope, the challenge-response
Vault         where keys sit at rest
```

The Vault is where the three genuinely differ, and the web client's is the one
worth reading: a browser has no hardware-backed key store a page can reach, so
it encrypts the identity with a non-extractable AES-GCM `CryptoKey` held in
IndexedDB. That protects a stolen database copy; it does not protect against
script injection on the page. Both facts are in
[the threat model](threat-model.md), not quietly assumed away.

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

1. A client's UI calls `send`. The controller encrypts on its crypto thread,
   which advances the sending chain and returns a frame of opaque bytes.
2. The frame is written to the socket. If the socket cannot take it, the exact
   bytes are queued and replayed on reconnect — re-encrypting would advance the
   chain a second time and leave the peer with a hole it can never fill.
3. The relay looks at the recipient field, not the body, and either pushes the
   frame to the peer's live socket or appends it to their outbox under the next
   per-recipient sequence number.
4. The peer decrypts. The ratchet either accepts the frame, or reports that it is
   a duplicate (routine, at-least-once delivery) or that it failed to
   authenticate on an unseen counter (not routine).
5. If the frame came out of the outbox, the peer acknowledges the sequence number,
   which also pulls the next page of their backlog.
