# Building and running

## Requirements

| Piece | Needs |
|---|---|
| relay | Go 1.24+ |
| protocol engine, host tests | any C++17 compiler; CMake 3.22+ for the portable path, Visual Studio on Windows |
| Android client | Android SDK, NDK `28.2.13676358`, CMake `3.22.1`, JDK 21 |

Nothing needs a phone. The protocol suite runs on a workstation, and the client
wire code is exercised against a real relay process in a JVM test.

## Relay

```bash
cd server
go build -o ../build/relay/veil-relay .
./build/relay/veil-relay -addr :8080 -db ./veil.db
```

Or with Docker:

```bash
cd server
docker compose up --build
```

The image is distroless, runs as a non-root user, and has a read-only root
filesystem; the SQLite file lives on a named volume. Because that image has no
shell and no HTTP client, the container healthcheck is the relay probing itself
(`veil-relay -healthcheck`), and it checks `/health` rather than merely that the
port is bound — a bound port says nothing about whether the store is usable.

From outside the container, `scripts/healthcheck.sh [host] [port]` does the same
probe with `curl`, falling back to `wget`.

### Configuration

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `-addr` | `VEIL_ADDR` | `:8080` | listen address |
| `-db` | `VEIL_DB` | `veil.db` | SQLite path |
| `-allowed-origins` | `VEIL_ALLOWED_ORIGINS` | *(empty)* | comma-separated browser origins |
| — | `VEIL_TLS_CERT` | — | certificate; must be paired with the key |
| — | `VEIL_TLS_KEY` | — | private key |
| `-healthcheck` | `VEIL_HEALTH_URL` | `http://127.0.0.1:8080/health` | probe mode: check and exit |

### TLS

The relay serves TLS itself when both `VEIL_TLS_CERT` and `VEIL_TLS_KEY` are
set. With neither set it serves plain `ws://` and says so at startup, loudly —
"TLS is somebody else's job" is the assumption that quietly fails, so it is
worth hearing every time the process starts.

### Origins

Browser clients are only accepted from origins in `VEIL_ALLOWED_ORIGINS`.
Native clients send no `Origin` header and are accepted; a browser cannot forge
its absence. Leaving the list empty is therefore correct for an Android-only
deployment, and wrong for one that serves a web build.

### Shutdown

On `SIGTERM` the relay stops accepting handshakes, closes every live socket with
a `1001 going away` status, waits up to five seconds for the handlers to unwind,
runs a final outbox sweep, and exits.

`http.Server.Shutdown` does not touch hijacked websockets. Without the explicit
close, clients learned about a deploy only when their next write failed.

## Android

```bash
./gradlew :app:assembleDebug
```

The build produces `arm64-v8a` and `x86_64` only. Point the client at the relay
with the URL field on the home screen; the default `ws://10.0.2.2:8080/ws`
reaches the host loopback from an emulator.

The UI is localised (English and Simplified Chinese), every interactive element
and message bubble carries a content description, and the link state is a word
as well as a colour. `FLAG_SECURE` is set on the window, so plaintext stays out
of screenshots, screen recordings and the recents thumbnail.

## Tests

Four suites, none of which needs a device.

```bash
# Protocol engine
#   Windows:
core-native\host\run_host_tests.bat
#   Linux / macOS:
cmake -S core-native/host -B build/host -DCMAKE_BUILD_TYPE=Release
cmake --build build/host --parallel
ctest --test-dir build/host --output-on-failure

# Relay
cd server && go test -race ./...

# Client wire code against a real relay process
#   (starts the binary at build/relay/veil-relay and skips if it is absent)
cd server && go build -o ../build/relay/veil-relay . && cd ..
./gradlew :app:testDebugUnitTest

# Fuzzers
clang++ -g -O1 -std=c++17 -fsanitize=fuzzer,address \
  -Icore-native/src/main/cpp \
  -Icore-native/src/main/cpp/third_party/monocypher \
  core-native/host/fuzz/fuzz_parsers.cpp \
  core-native/src/main/cpp/veil/*.cpp \
  core-native/src/main/cpp/third_party/monocypher/monocypher*.c \
  -o build-fuzz-parsers
./build-fuzz-parsers -max_total_time=60

cd server && go test -fuzz=FuzzEnvelope -fuzztime=60s
```

### What each suite covers

**Host (C++).** Agreement, round-trip, out-of-order delivery, replay rejection,
tamper detection, forward secrecy, the skipped-key budget per chain *and*
globally, session persistence, the identity binding and prekey signature,
rejection of a spliced signing key, the retired-prekey path, the prekey header
surviving a lost first frame, identity pinning surviving a restart, prekey state
surviving a restart, one-time prekeys spent exactly once, the difference between
a duplicated delivery and a tampered one, the engine's session-state enum, and
the exact byte layouts the relay and client share.

**Relay (Go).** The challenge handshake, forged proofs, the origin allow-list,
prekey hand-out, live and offline delivery, paging a backlog larger than one
page, acknowledgement scoping, the per-recipient sequence being dense, the expiry
and trim sweep, the send-rate limiter, readiness reporting, and a clean shutdown
that clients can observe.

**Interop (JVM).** The real client wire code against a real relay process,
including a real Ed25519 proof of identity — the relay verifies it for real, so
it cannot be stubbed.

**Fuzzers.** Every parser that reads attacker bytes: the envelope and field
codec, the prekey set, and the C++ deserialisers for wire frames, prekey
headers, bundles, session state and prekey state.

## CI

`.github/workflows/ci.yml` runs six jobs: the host suite, the same suite under
ASan+UBSan, a short libFuzzer pass, `go vet` plus `go test -race` plus a Go fuzz
pass, the client/relay interop test against a relay it builds itself, and the APK
build with Android Lint. Every job also checks the vendored-dependency hashes.

## Dependency pinning

`core-native/src/main/cpp/third_party/DEPENDENCIES.md` records the Monocypher
sources by SHA-256; `verify.sh` next to it checks them and runs in CI. Upstream
stamps `__git__` into the header rather than a release number, so a version
string pins nothing — the content hash is the pin.

## Troubleshooting

**The interop test is skipped.** It needs `build/relay/veil-relay` to exist. Build
it first; the test starts the process itself rather than mocking the protocol.

**`local.properties` is missing.** Gradle needs `sdk.dir` pointing at an Android
SDK. It is gitignored on purpose — it is machine-specific.

**The relay says it is serving plain `ws://`.** That is correct when a TLS
terminator sits in front of it, and a warning worth reading when one does not.
