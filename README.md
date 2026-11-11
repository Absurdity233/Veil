<div align="center">

# Veil

**End-to-end encrypted chat, with a relay that cannot read a single character.**

One Signal-protocol engine written from the primitives up in C++17, and three
clients that all call it: Android (Kotlin + Compose, via JNI), desktop (JVM,
via JNA) and browser (TypeScript, via WebAssembly). The Go relay routes
ciphertext it holds no key for.

[Architecture](docs/architecture.md) ·
[Protocol](docs/protocol.md) ·
[Threat model](docs/threat-model.md) ·
[Multi-device](docs/multi-device.md) ·
[Groups](docs/group.md) ·
[Building](docs/building.md) ·
[Deploying](deploy/README.md)

[![ci](https://github.com/Absurdity233/Veil/actions/workflows/ci.yml/badge.svg)](https://github.com/Absurdity233/Veil/actions/workflows/ci.yml)
![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)

</div>

---

## Three clients, one engine

The interesting claim this repository makes is that the protocol lives in
exactly one place. The same C++ compiles to an Android `.so`, a desktop shared
library and a 121 KB `.wasm`; each client is a transport, a key store and a
window.

| | Android | Desktop | Web |
|---|---|---|---|
| Language | Kotlin + Compose | Kotlin + Swing | TypeScript |
| Engine binding | JNI | JNA over a C ABI | WebAssembly |
| Keys at rest | Android Keystore | owner-only files | non-extractable `CryptoKey` |
| Tests | 3 interop | 6 interop | 4 e2e + 19 unit |

The C ABI (`core-native/src/main/cpp/veil/veil_c.h`) is the seam. It exists so a
new platform does not need to reimplement the protocol and does not need to link
C++ — which is exactly why the desktop client is 600 lines of Kotlin instead of a
second crypto implementation.

## What this is

Most "encrypted chat" projects encrypt in the client and decrypt in the server,
which makes the server the only thing standing between a message and its reader.
Veil does the opposite: the server is a switchboard, and the cryptography lives
where the keys live.

```
   Alice's phone            Alice's browser             Bob's phone
 ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
 │  Compose UI      │    │  DOM             │    │  Compose UI      │
 │  ──────────────  │    │  ──────────────  │    │  ──────────────  │
 │  VeilEngine      │    │  VeilEngine      │    │  VeilEngine      │
 │   (JNI)          │    │  (.wasm)         │    │  (JNI)           │
 │  X3DH            │    │  X3DH            │    │  X3DH            │
 │  Double Ratchet  │    │  Double Ratchet  │    │  Double Ratchet  │
 └────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘
          │      WebSocket, opaque bytes  │               │
          └───────────────┬───────────────┴───────────────┘
                          ▼
              ┌───────────────────────┐
              │  Go relay             │
              │  routes + outbox      │
              │  no keys, no plaintext│
              └───────────┬───────────┘
                          ▼
                    SQLite file
```

The relay knows *who* sent *how many bytes* to *whom*. It cannot recover message
content, and there is no code path in it that tries — the whole Go package is
about 1,550 lines and contains no cryptographic operation beyond verifying a
registration signature.

## The parts that are easy to get wrong

An end-to-end encrypted messenger is mostly a list of subtle ways to fail
silently. These are the ones this implementation takes a position on; each links
to the reasoning.

| Problem | What Veil does |
|---|---|
| A prekey bundle is the peer's whole identity, not just a DH key | The signing key signs the DH key, and every bundle carries that binding — [why](docs/threat-model.md#a-relay-substitutes-a-prekey-bundle) |
| The safety number is what the user actually checks | It hashes **both halves** of both identities, so the key that authenticates prekeys is inside what you compare |
| A hostile relay can hand back a different identity mid-conversation | Labels are pinned; a change is `IDENTITY_CHANGED` and nothing is sent — [why](docs/threat-model.md#a-relay-swaps-the-peers-identity-mid-conversation) |
| The first frame can be lost, and with it the handshake | The prekey header rides every frame until the peer answers — [why](docs/protocol.md#ratchet-frame) |
| Replay protection must not drag the ratchet backwards | Frames from a retired chain are refused, and the session keeps working — [why](docs/protocol.md#delivery-is-at-least-once) |
| Re-registering prekeys under a reused id is indistinguishable from a stale bundle | The signed prekey id is a persisted monotonic counter — [why](docs/architecture.md#core-native) |
| A one-time prekey that is only popped at the relay can still be used twice | Every one-time key carries a persisted *consumed* flag — [why](docs/protocol.md#one-time-prekeys-are-spent-locally-not-only-at-the-relay) |
| Duplicated delivery is normal on an at-least-once relay | `DUPLICATE` is acknowledged silently; only a real authentication failure is surfaced |
| A dropped socket must not silently lose a message | The exact encrypted bytes are queued and replayed — re-encrypting would advance the chain twice — [why](docs/architecture.md#data-flow-for-one-message) |
| Ratchet state on disk is as sensitive as the identity | Sessions, pins and prekey state are AES-GCM sealed — Keystore on Android, files on desktop, a non-extractable `CryptoKey` in the browser |

## By the numbers

| | |
|---|---|
| Protocol engine | C++17, no I/O, and no allocation between handshake and message |
| Primitive layer | vendored Monocypher — X25519, XChaCha20-Poly1305, Ed25519, HKDF-SHA512, BLAKE2b |
| Relay | Go, single static binary, distroless image, non-root, read-only root |
| Clients | Android (JNI), desktop (JNA), browser (121 KB wasm) |
| Tests | 226 host + 62 C ABI assertions, 29 relay tests, 13 interop, 24 web, 8 fuzz targets |
| Wire overhead | 257 bytes on the first frame (prekey header), 57 bytes thereafter |

## Quick start

```bash
# relay
cd server && go build -o ../build/relay/veil-relay . && ./../build/relay/veil-relay

# android
./gradlew :app:assembleDebug

# desktop — needs the C ABI library first
cmake -S desktop -B build/abi -DCMAKE_BUILD_TYPE=Release && cmake --build build/abi
./gradlew :desktop:run

# web
cd web && npm ci && npm run build && npm run serve   # http://127.0.0.1:5173
```

The Android client's default relay URL is `ws://10.0.2.2:8080/ws`, which is the
host loopback as seen from an emulator. The desktop and web clients default to
`ws://127.0.0.1:8080/ws`.

A browser page served from anywhere other than the relay's own origin has to be
listed in `VEIL_ALLOWED_ORIGINS`, or the handshake is refused with a 403:

```bash
VEIL_ALLOWED_ORIGINS=http://127.0.0.1:5173 ./build/relay/veil-relay
```

Full instructions, including TLS, origins and the container healthcheck, are in
[Building and running](docs/building.md).

## Design notes worth reading

- **[Architecture](docs/architecture.md)** — what lives where, why the crypto
  engine has no I/O, and what the C ABI exists for.
- **[Protocol](docs/protocol.md)** — every frame, field and state transition the
  clients and relay agree on.
- **[Threat model](docs/threat-model.md)** — what is defended, what leaks, and
  what is simply not implemented.

The threat model is the honest one. It lists the four things this design
deliberately does not hide — who talks to whom, when, how many bytes, and that
two ids exist — because sealed sender, cover traffic and mixnets are the
techniques that address them and none of them are here.

## Status

Working, tested, and honest about its limits. Sessions persist, so a restart
keeps the ability to talk; conversation history does not, so a restart loses the
transcript.

**At the protocol layer:** one-to-one messaging, multi-device accounts (identity
plus a list of account-signed device credentials, per-device sessions, fan-out
sending), and group messaging with Sender Keys (one frame per message regardless
of group size, epoch-based re-keying when membership changes, persisted across
restarts). The relay addresses frames per device and stores device lists.

**Surfaced in all three clients:** device identity claimed on connect and
persisted, fan-out sending (one frame per device of a peer), group
create/send/receive, and group state in each client's encrypted store. Android
and desktop reach it through JNI and JNA respectively; the web client through
wasm.

**Not implemented at all:** push notifications, account recovery, a device
linking UI, and group invitations over the wire (chains and member lists travel
through export/adopt pairs, so a caller has to hand them over).

The designs, and the honest account of what is missing from each, are in
[Multi-device](docs/multi-device.md) and [Groups](docs/group.md).
To run it, see [Deploying](deploy/README.md) — Docker, Caddy, TLS.

## Licence

[Apache-2.0](LICENSE). Monocypher is vendored under its own licence (BSD-2-Clause
or CC0) and is pinned by SHA-256 — see
[DEPENDENCIES](core-native/src/main/cpp/third_party/DEPENDENCIES.md).
