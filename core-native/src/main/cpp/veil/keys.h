// Veil - long-term identity and prekey material.
#ifndef VEIL_KEYS_H
#define VEIL_KEYS_H

#include <cstdint>
#include <string>
#include <vector>

#include "veil/common.h"

namespace veil {

// Two independent long-term keys. Keeping them separate is simpler to reason
// about than deriving one from the other, and costs 32 extra bytes:
//
//   identity_dh   Curve25519, used for X3DH
//   identity_sign Ed25519,    used to sign prekeys
//
// The two halves are tied together by a binding signature: identity_sign signs
// identity_dh. Every bundle a peer downloads carries that signature, so a relay
// cannot splice its own signing key onto somebody else's DH key and then sign
// prekeys of its own choosing while the safety number stays unchanged.
struct Identity {
    uint8_t dh_pub[kKeySize]{};
    uint8_t dh_priv[kKeySize]{};
    uint8_t sign_pub[32]{};
    uint8_t sign_priv[64]{};

    // Generates a fresh identity from the platform CSPRNG.
    bool generate();

    // Restores from previously exported secrets.
    static bool fromSecrets(Identity& out,
                            const uint8_t dh_priv[kKeySize],
                            const uint8_t sign_priv[64]);

    // Ed25519 signature over dh_pub, made with sign_priv. This is the value
    // that proves the two halves belong to one holder.
    void bindingSignature(uint8_t sig[kBindingSize]) const;

    // Verifies a binding signature against the public halves only.
    static bool verifyBinding(const uint8_t dh_pub[kKeySize],
                              const uint8_t sign_pub[32],
                              const uint8_t sig[kBindingSize]);

    // Wipes the private halves. The public halves are left intact.
    void wipeSecrets();
};

// One signed prekey plus a batch of one-time prekeys.
//
// `signed_prekey` is medium-lived and rotated periodically; the one-time
// prekeys are consumed by the server as peers fetch them.
struct PreKeys {
    uint32_t signed_prekey_id = 0;
    uint8_t  signed_pub[kKeySize]{};
    uint8_t  signed_priv[kKeySize]{};
    uint8_t  signed_signature[kSigSize]{};

    // The signed prekey that was live before the current one. A peer may have
    // downloaded the old bundle just before a rotation and send its first
    // message afterwards; without this the handshake would fail and the user
    // would have no way to tell why.
    uint32_t retired_signed_id = 0;
    bool     has_retired_signed = false;
    uint8_t  retired_signed_pub[kKeySize]{};
    uint8_t  retired_signed_priv[kKeySize]{};
    uint8_t  retired_signed_signature[kSigSize]{};

    struct OneTime {
        uint32_t id = 0;
        uint8_t  pub[kKeySize]{};
        uint8_t  priv[kKeySize]{};
    };
    std::vector<OneTime> one_time;

    // Signs the signed prekey with `identity`. The signature covers the
    // identity's DH public key too - see verifySignedPreKey().
    bool generate(const Identity& identity, uint32_t signed_id, uint32_t one_time_count);

    // Returns the private half that a prekey header was addressed to, or
    // nullptr when the id matches neither the current nor the retired prekey.
    const uint8_t* signedPrivFor(uint32_t signed_id) const;

    void wipeSecrets();
};

// What a peer downloads from the server in order to start a session.
struct PreKeyBundle {
    uint8_t  identity_dh_pub[kKeySize]{};
    uint8_t  identity_sign_pub[32]{};
    uint32_t signed_prekey_id = 0;
    uint8_t  signed_pub[kKeySize]{};
    uint8_t  signed_signature[kSigSize]{};
    bool     has_one_time = false;
    uint32_t one_time_id = 0;
    uint8_t  one_time_pub[kKeySize]{};

    Bytes serialize() const;
    static bool deserialize(PreKeyBundle& out, const uint8_t* data, size_t size);
};

// The public half of a published prekey set.
PreKeyBundle publishBundle(const Identity& identity, const PreKeys& prekeys,
                           const PreKeys::OneTime* one_time);

// ---- Prekey signature binding -----------------------------------------
//
// A signed prekey signature does not merely cover the prekey: it covers
//      "Veil/signed-prekey/v1" || identity_dh_pub || signed_pub
//
// The extra 32 bytes are the point. Without them the signature says "whoever
// holds this signing key endorses this prekey", and nothing ties that signing
// key to the Curve25519 key X3DH actually runs against. A relay could then
// publish a bundle that pairs a victim's DH key with its own signing key, sign
// its own prekey, and the client would happily build a session - the safety
// number would not move, because the DH key did not. Including identity_dh_pub
// in the signed message closes that gap on the wire we already have, with no
// new field for the relay to carry.
constexpr char kSignedPreKeyDomain[] = "Veil/signed-prekey/v1";

// Writes the exact byte string a prekey signature covers. Returns the length.
size_t signedPreKeyMessage(uint8_t* out, size_t capacity,
                           const uint8_t identity_dh_pub[kKeySize],
                           const uint8_t signed_pub[kKeySize]);

// Verifies a bundle's prekey signature, including the DH-key binding.
bool verifySignedPreKey(const uint8_t identity_dh_pub[kKeySize],
                        const uint8_t identity_sign_pub[32],
                        const uint8_t signed_pub[kKeySize],
                        const uint8_t signature[kSigSize]);

}  // namespace veil

#endif  // VEIL_KEYS_H
