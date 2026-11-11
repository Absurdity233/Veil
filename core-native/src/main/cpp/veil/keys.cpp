#include "veil/keys.h"

#include <cstring>

#include "veil/crypto.h"
#include "veil/random.h"

namespace veil {
namespace {

// Domain-separation strings. Every derivation in Veil is prefixed with one of
// these so a key produced for one purpose can never be reinterpreted as a key
// for another.
constexpr char kDomainIdentityDh[]   = "Veil/identity/dh";
constexpr char kDomainIdentitySign[] = "Veil/identity/sign";

}  // namespace

bool Identity::generate() {
    uint8_t seed[32];
    if (!secure_random(seed, sizeof(seed))) return false;

    // Derive the two key pairs from one seed so export/import only has to
    // carry 32 bytes.
    crypto::hkdf(dh_priv, kKeySize,
                 seed, sizeof(seed),
                 reinterpret_cast<const uint8_t*>(kDomainIdentityDh),
                 sizeof(kDomainIdentityDh) - 1,
                 nullptr, 0);
    crypto::x25519_keypair(dh_pub, dh_priv);

    uint8_t sign_seed[32];
    crypto::hkdf(sign_seed, sizeof(sign_seed),
                 seed, sizeof(seed),
                 reinterpret_cast<const uint8_t*>(kDomainIdentitySign),
                 sizeof(kDomainIdentitySign) - 1,
                 nullptr, 0);
    crypto::ed25519_keypair(sign_pub, sign_priv, sign_seed);

    veil::wipe(seed, sizeof(seed));
    veil::wipe(sign_seed, sizeof(sign_seed));
    return true;
}

bool Identity::fromSecrets(Identity& out,
                           const uint8_t dh_priv_in[kKeySize],
                           const uint8_t sign_priv_in[64]) {
    if (dh_priv_in == nullptr || sign_priv_in == nullptr) return false;

    std::memcpy(out.dh_priv, dh_priv_in, kKeySize);
    crypto::x25519_keypair(out.dh_pub, out.dh_priv);

    std::memcpy(out.sign_priv, sign_priv_in, 64);
    // Monocypher stores the public half in the tail of the secret key.
    std::memcpy(out.sign_pub, sign_priv_in + 32, 32);
    return true;
}

void Identity::wipeSecrets() {
    veil::wipe(dh_priv, sizeof(dh_priv));
    veil::wipe(sign_priv, sizeof(sign_priv));
}

bool PreKeys::generate(const Identity& identity, uint32_t signed_id,
                       uint32_t one_time_count) {
    signed_prekey_id = signed_id;

    if (!crypto::x25519_generate(signed_pub, signed_priv)) return false;

    crypto::ed25519_sign(signed_signature, identity.sign_priv,
                         signed_pub, kKeySize);

    one_time.clear();
    one_time.reserve(one_time_count);
    for (uint32_t i = 0; i < one_time_count; ++i) {
        OneTime ot;
        ot.id = signed_id * 1000u + i;
        if (!crypto::x25519_generate(ot.pub, ot.priv)) return false;
        one_time.push_back(ot);
    }
    return true;
}

void PreKeys::wipeSecrets() {
    veil::wipe(signed_priv, sizeof(signed_priv));
    for (auto& ot : one_time) veil::wipe(ot.priv, sizeof(ot.priv));
    one_time.clear();
}

// ---- Bundle serialisation ----------------------------------------------
//
// Layout:
//   [32] identity dh public
//   [32] identity signing public
//   [4]  signed prekey id
//   [32] signed prekey public
//   [64] signature
//   [1]  has one-time (0/1)
//   [4]  one-time id        (present only when has_one_time == 1)
//   [32] one-time public    (present only when has_one_time == 1)
Bytes PreKeyBundle::serialize() const {
    Bytes out;
    out.reserve(32 + 32 + 4 + 32 + 64 + 1 + 4 + 32);
    out.insert(out.end(), identity_dh_pub, identity_dh_pub + 32);
    out.insert(out.end(), identity_sign_pub, identity_sign_pub + 32);
    uint8_t id[4];
    put_u32(id, signed_prekey_id);
    out.insert(out.end(), id, id + 4);
    out.insert(out.end(), signed_pub, signed_pub + 32);
    out.insert(out.end(), signed_signature, signed_signature + 64);
    out.push_back(has_one_time ? 1 : 0);
    if (has_one_time) {
        put_u32(id, one_time_id);
        out.insert(out.end(), id, id + 4);
        out.insert(out.end(), one_time_pub, one_time_pub + 32);
    }
    return out;
}

bool PreKeyBundle::deserialize(PreKeyBundle& out, const uint8_t* data, size_t size) {
    if (data == nullptr) return false;

    const size_t kFixed = 32 + 32 + 4 + 32 + 64 + 1;
    if (size < kFixed) return false;

    size_t off = 0;
    std::memcpy(out.identity_dh_pub, data + off, 32); off += 32;
    std::memcpy(out.identity_sign_pub, data + off, 32); off += 32;
    out.signed_prekey_id = get_u32(data + off); off += 4;
    std::memcpy(out.signed_pub, data + off, 32); off += 32;
    std::memcpy(out.signed_signature, data + off, 64); off += 64;
    out.has_one_time = data[off] != 0; off += 1;

    out.one_time_id = 0;
    std::memset(out.one_time_pub, 0, sizeof(out.one_time_pub));
    if (out.has_one_time) {
        if (size < off + 4 + 32) return false;
        out.one_time_id = get_u32(data + off); off += 4;
        std::memcpy(out.one_time_pub, data + off, 32);
    }
    return true;
}

PreKeyBundle publishBundle(const Identity& identity, const PreKeys& prekeys,
                           const PreKeys::OneTime* one_time) {
    PreKeyBundle b;
    std::memcpy(b.identity_dh_pub, identity.dh_pub, 32);
    std::memcpy(b.identity_sign_pub, identity.sign_pub, 32);
    b.signed_prekey_id = prekeys.signed_prekey_id;
    std::memcpy(b.signed_pub, prekeys.signed_pub, 32);
    std::memcpy(b.signed_signature, prekeys.signed_signature, 64);
    if (one_time != nullptr) {
        b.has_one_time = true;
        b.one_time_id = one_time->id;
        std::memcpy(b.one_time_pub, one_time->pub, 32);
    }
    return b;
}

}  // namespace veil
