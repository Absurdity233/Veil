// Veil - libFuzzer targets for the parsers that eat attacker bytes.
//
// Every function here takes a byte string from the network, or from a file the
// network told it to read. They are the only place where a remote party
// controls the shape of the input, so they are the place where a fuzzer earns
// its keep: a length-prefix bug here is a memory-safety bug, not a 400.
//
// Build and run:
//   clang++ -g -O1 -fsanitize=fuzzer,address -std=c++17 \
//     -Icore-native/src/main/cpp \
//     -Icore-native/src/main/cpp/third_party/monocypher \
//     core-native/host/fuzz/fuzz_parsers.cpp \
//     core-native/src/main/cpp/veil/*.cpp \
//     core-native/src/main/cpp/third_party/monocypher/monocypher*.c \
//     -o build/fuzz_parsers
//   ./build/fuzz_parsers -max_len=4096
#include <cstdint>
#include <cstddef>
#include <cstring>

#include "veil/engine.h"
#include "veil/keys.h"
#include "veil/ratchet.h"

namespace {

// A fixed identity so the targets exercise the real code paths rather than
// bailing out at "no identity" every time. Not const: decryption advances the
// ratchet, which is the state the fuzzer is meant to drive.
struct Fixture {
    veil::Engine engine;
    veil::Identity identity;
    veil::PreKeys prekeys;

    Fixture() {
        engine.createIdentity();
        identity.generate();
        prekeys.rotate(identity, 4);
    }
};

Fixture& fixture() {
    static Fixture f;
    return f;
}

void fuzzWireFrame(const uint8_t* data, size_t size) {
    // WireMessage::decode is the first thing a delivered frame touches. It has
    // to reject anything that does not match its own length field before
    // reading a single field.
    bool has_prekey = false;
    veil::PreKeyHeader prekey;
    veil::RatchetMessage msg;
    if (veil::WireMessage::decode(data, size, has_prekey, prekey, msg)) {
        // Whatever survived the framing is now fed to the ratchet, which is
        // the deeper parser: counters, ratchet keys, skipped-key budgets.
        veil::Bytes out;
        (void)fixture().engine.decrypt("peer", data, size, out);
    }
}

void fuzzPreKeyHeader(const uint8_t* data, size_t size) {
    veil::PreKeyHeader h;
    if (!veil::PreKeyHeader::read(h, data, size)) return;

    // A well-formed header goes into the handshake. This is where a bad
    // one-time-prekey id or a mismatched identity gets refused.
    veil::Session s;
    (void)s.establishInbound(fixture().identity, fixture().prekeys, h);
}

void fuzzBundle(const uint8_t* data, size_t size) {
    veil::PreKeyBundle b;
    if (!veil::PreKeyBundle::deserialize(b, data, size)) return;

    veil::Session s;
    (void)s.establishOutbound(fixture().identity, b);
}

void fuzzSessionState(const uint8_t* data, size_t size) {
    // Ratchet state comes back from the encrypted store, which means it was
    // written by this process - but a corrupted keystore blob or a downgrade
    // attempt is exactly what a parser has to survive.
    veil::Session s;
    (void)s.deserialize(data, size);
}

void fuzzPreKeyState(const uint8_t* data, size_t size) {
    veil::PreKeys p;
    (void)p.deserialize(data, size);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0) return 0;

    // The first byte picks the target, so one binary covers all five parsers
    // and the corpus stays shared.
    const uint8_t selector = data[0] % 5;
    const uint8_t* body = data + 1;
    const size_t body_size = size - 1;

    switch (selector) {
        case 0: fuzzWireFrame(body, body_size); break;
        case 1: fuzzPreKeyHeader(body, body_size); break;
        case 2: fuzzBundle(body, body_size); break;
        case 3: fuzzSessionState(body, body_size); break;
        default: fuzzPreKeyState(body, body_size); break;
    }
    return 0;
}