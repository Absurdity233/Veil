# Vendored dependencies

## Monocypher

| Field | Value |
|---|---|
| Upstream | https://github.com/LoupVaillant/Monocypher |
| Version | 4.0.2 (header still says `__git__`; pinned by hash below) |
| Licence | BSD-2-Clause OR CC0-1.0 — see `monocypher/LICENCE.md` |
| Location | `core-native/src/main/cpp/third_party/monocypher/` |
| Used by | `veil::crypto` — X25519, XChaCha20-Poly1305, Ed25519, HKDF-SHA512, BLAKE2b |

The header of `monocypher.h` reads `// Monocypher version __git__`, which is
what upstream ships: it does not stamp a release number into the source. A
version string that only ever says "some commit" is not a pin, so the pin is
the content hash. `verify.sh` next to this file checks them.

```
02174117935699d418443c75a558a287deb06ef8cf7c1adced61d9047d2f323d  monocypher.c
fcaf6ed771358bb4f40fba016f6518ae86ec02b1b877d2cc35ad92d3a26fd7b3  monocypher.h
97d581639dfa72be08a6d57deb7d79b736be001cb416819cab196d22559d242b  monocypher-ed25519.c
3a3035181f991a158d0e1c7567258f0bae8ba0f1f23c5512b4a1db1b3c9730ce  monocypher-ed25519.h
a5781770269d2516e52ba4863f790c10a16da4089a1e81823aee19ff1e9026b0  LICENCE.md
```

### Why a hash and not a tag

This is the only third-party code compiled into the client, and it is the code
that turns bytes into keys. Two properties matter:

1. **Reproducibility.** Two builds of the same commit must link the same
   primitives. A tag can be moved; a hash cannot.
2. **Reviewability.** An upgrade is a visible diff to these files plus a diff
   to this file. There is no transitive tree to audit.

### Upgrading

1. Replace the files from the new upstream release.
2. `cd third_party && ./verify.sh --update` to record the new hashes.
3. Run the host suite: `core-native/host/run_host_tests.bat`, or the CMake
   target on Linux/macOS.
4. Run the fuzzers with the new primitives in place:
   `core-native/host/fuzz/fuzz_parsers.cpp` under libFuzzer.
5. Note the reason for the bump in the commit message.

## Go modules

Pinned by `server/go.sum`; the module graph is small and entirely indirect
except for `gorilla/websocket` and `modernc.org/sqlite`. `go mod verify` is
part of CI.

## Android dependencies

Pinned by the Gradle dependency lock and the Compose BOM in
`app/build.gradle.kts`.
