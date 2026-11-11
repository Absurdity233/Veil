// Veil - shared types and small helpers.
#ifndef VEIL_COMMON_H
#define VEIL_COMMON_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace veil {

using Bytes = std::vector<uint8_t>;

constexpr size_t kKeySize   = 32;
constexpr size_t kMacSize   = 16;
constexpr size_t kNonceSize = 24;
constexpr size_t kSigSize   = 64;

// A full identity is two public keys, not one: the Curve25519 key that X3DH
// uses, followed by the Ed25519 key that signs prekeys. Treating them as one
// 64-byte value everywhere is deliberate - a binding signature alone is not
// enough, because the safety number has to cover the key that actually
// authenticates the peer, and that is the signing key.
constexpr size_t kIdentitySize = kKeySize + 32;

static_assert(kIdentitySize == 64, "identity blob layout is documented as 64 bytes");

// Ed25519 signature over the identity's Curve25519 public key. Proves the two
// halves of an identity belong to the same holder; without it a relay could
// splice its own signing key onto a victim's DH key.
constexpr size_t kBindingSize = kSigSize;

// A message header carries everything the receiver needs to advance its
// ratchet state before it can derive the message key.
constexpr size_t kHeaderSize = 32 + 4 + 4;  // dh public || pn || n

// Upper bound on cached message keys. Without a cap, a peer could pin an
// arbitrary amount of memory by claiming to have skipped a huge run of
// messages.
constexpr size_t kMaxSkippedKeys = 1000;

inline void wipe(void* p, size_t n) {
    if (p != nullptr && n != 0) {
        volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
        while (n--) *v++ = 0;
    }
}

inline void wipe(Bytes& b) {
    wipe(b.data(), b.size());
    b.clear();
}

inline void put_u32(uint8_t* out, uint32_t v) {
    out[0] = static_cast<uint8_t>(v);
    out[1] = static_cast<uint8_t>(v >> 8);
    out[2] = static_cast<uint8_t>(v >> 16);
    out[3] = static_cast<uint8_t>(v >> 24);
}

inline uint32_t get_u32(const uint8_t* in) {
    return static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) |
           (static_cast<uint32_t>(in[2]) << 16) | (static_cast<uint32_t>(in[3]) << 24);
}

inline void put_u64(uint8_t* out, uint64_t v) {
    put_u32(out, static_cast<uint32_t>(v));
    put_u32(out + 4, static_cast<uint32_t>(v >> 32));
}

inline uint64_t get_u64(const uint8_t* in) {
    return static_cast<uint64_t>(get_u32(in)) |
           (static_cast<uint64_t>(get_u32(in + 4)) << 32);
}

inline bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

}  // namespace veil

#endif  // VEIL_COMMON_H
