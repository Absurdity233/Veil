<div align="center">

# Veil

**End-to-end encrypted chat, with a relay that cannot read a single character.**

A Signal-protocol engine written from the primitives up in C++17, an Android
client in Kotlin and Compose, and a Go relay that routes ciphertext it has no
key for.

[Architecture](docs/architecture.md) ·
[Protocol](docs/protocol.md) ·
[Threat model](docs/threat-model.md) ·
[Building](docs/building.md)

[![ci](https://github.com/Absurdity233/Veil/actions/workflows/ci.yml/badge.svg)](https://github.com/Absurdity233/Veil/actions/workflows/ci.yml)
![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)

</div>

---

## What this is

Most "encrypted chat" projects encrypt in the client and decrypt in the server,
which makes the server the only thing standing between a message and its reader.
Veil does the opposite: the server is a switchboard, and the cryptography lives
where the keys live.

```
   Alice's phone                                  Bob's phone
 ┌──────────────────────┐                     ┌──────────────────────┐
 │  Compose UI          │                     │  Compose UI          │
 │  ChatController      │                     │  ChatController      │
 │  ──────────────────  │                     │  ──────────────────  │
 │  X3DH                │                     │  X3DH                │
 │  Double Ratchet      │                     │  Double Ratchet      │
 └──────────┬───────────┘                     └──────────┬───────────┘
            │          WebSocket, opaque bytes           │
            └────────────────────┬───────────────────────┘
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
| Ratchet state on disk is as sensitive as the identity | Sessions, pins and prekey state go through Keystore-backed AES-GCM |

## By the numbers

| | |
|---|---|
| Protocol engine | C++17, no I/O, and no allocation between handshake and message |
| Primitive layer | vendored Monocypher — X25519, XChaCha20-Poly1305, Ed25519, HKDF-SHA512, BLAKE2b |
| Relay | Go, single static binary, distroless image, non-root, read-only root |
| Tests | 226 host assertions, 29 relay tests, 3 end-to-end interop tests, 8 fuzz targets |
| Wire overhead | 257 bytes on the first frame (prekey header), 57 bytes thereafter |

## Quick start

```bash
# relay
cd server && go build -o ../build/relay/veil-relay . && ./../build/relay/veil-relay

# client
./gradlew :app:assembleDebug
```

The client's default relay URL is `ws://10.0.2.2:8080/ws`, which is the host
loopback as seen from an emulator. On a real device, point it at the relay's LAN
or public address.

Full instructions, including TLS, origins and the container healthcheck, are in
[Building and running](docs/building.md).

## Design notes worth reading

- **[Architecture](docs/architecture.md)** — what lives where, and why the crypto
  engine has no I/O.
- **[Protocol](docs/protocol.md)** — every frame, field and state transition the
  client and relay agree on.
- **[Threat model](docs/threat-model.md)** — what is defended, what leaks, and
  what is simply not implemented.

The threat model is the honest one. It lists the four things this design
deliberately does not hide — who talks to whom, when, how many bytes, and that
two ids exist — because sealed sender, cover traffic and mixnets are the
techniques that address them and none of them are here.

## Status

Working, tested, and honest about its limits: one-to-one only, no group
messaging, no multi-device, no push notifications, no account recovery. The
[session layer](docs/architecture.md) persists, so a restart keeps the ability to
talk; conversation history does not, so a restart loses the transcript.

Contributions are welcome, particularly failing tests.

## Licence

[Apache-2.0](LICENSE). Monocypher is vendored under its own licence (BSD-2-Clause
or CC0) and is pinned by SHA-256 — see
[DEPENDENCIES](core-native/src/main/cpp/third_party/DEPENDENCIES.md).
