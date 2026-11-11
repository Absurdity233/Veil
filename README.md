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
| `HELLO` | client → relay | bind a user id to an identity key |
| `HELLO_OK` | relay → client | accepted |
| `PUBLISH_PREKEYS` | client → relay | store signed + one-time prekeys |
| `GET_BUNDLE` | client → relay | fetch a peer's prekey bundle |
| `BUNDLE` | relay → client | identity, signed prekey, one one-time prekey |
| `SEND` | client → relay | opaque body for a recipient |
| `DELIVER` | relay → client | `[4] outbox id | [sender] | [body]` |
| `ACK` | client → relay | drop outbox entries up to an id |
| `ERROR` | relay → client | human-readable rejection |

A live delivery carries outbox id `0`; a replayed one carries the real id so
the client can acknowledge it.

### Ratchet frame

```
[1]  flags            bit 0 = carries a prekey header
[104] prekey header   only when the flag is set
[40]  ratchet header  dh public | previous chain length | message number
[n]   ciphertext || 16-byte MAC
```

The ratchet header is authenticated as associated data, so it cannot be
rewritten in flight.

## Cryptography

**X3DH** — the sender verifies the signed prekey against the peer's identity
key, then runs four Diffie-Hellman operations and derives a shared secret with
HKDF-SHA512 over `0xFF*32 || DH1 || DH2 || DH3 || DH4`.

**Double Ratchet** — a symmetric ratchet advances per message
(`HMAC-SHA512(chain, 0x02)` for the next chain key, `0x01` for the message
key), and a DH ratchet advances whenever the peer publishes a new ratchet key.
Message keys are discarded after use, which is what gives forward secrecy.

**Skipped keys** — up to 1000 message keys are cached per peer so out-of-order
delivery still decrypts. The bound exists so a peer cannot pin arbitrary
memory by claiming a huge gap.

**Safety number** — BLAKE2b-256 over both identity public keys in sorted
order, rendered as five groups of five digits. Both sides compute the same
string; comparing it out of band rules out a middlebox.

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
filesystem; the SQLite file lives on a named volume.

### Android

```bash
./gradlew :app:assembleDebug
```

Requires the Android SDK with NDK `28.2.13676358` and CMake `3.22.1`. The
build produces `arm64-v8a` and `x86_64` only.

Point the client at the relay with the URL field on the home screen. The
default, `ws://10.0.2.2:8080/ws`, reaches the host loopback from an emulator.

## Tests

```bash
# Protocol engine, on the build machine
build/host/build.bat && ./build/host/test_core.exe

# Relay
cd server && go test ./...

# Client wire code against a real relay process
./gradlew :app:testDebugUnitTest
```

The host suite covers agreement, round-trip, out-of-order delivery, replay
rejection, tamper detection, forward secrecy, the skipped-key bound, session
persistence, and the exact byte layouts the relay and client share.

## Deliberate limits

- **One-to-one only.** Group messaging needs Sender Keys or per-member
  fan-out; neither is implemented.
- **In-memory client state.** Messages, sessions and prekeys live for the
  process lifetime. A restart re-runs the handshake. Persisting sessions means
  encrypting `Session::serialize()` output at rest and restoring it on launch.
- **Metadata is visible to the relay.** Who talks to whom, when, and how much
  — the protocol hides content, not traffic shape.
- **No account recovery.** The identity lives in the Android Keystore; losing
  the device means losing the identity.

## Licence

Monocypher is vendored under its own licence (see
`core-native/src/main/cpp/third_party/monocypher/LICENCE.md`).
