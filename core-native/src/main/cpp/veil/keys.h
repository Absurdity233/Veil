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

    struct OneTime {
        uint32_t id = 0;
        uint8_t  pub[kKeySize]{};
        uint8_t  priv[kKeySize]{};
    };
    std::vector<OneTime> one_time;

    // Signs the signed prekey with `identity`.
    bool generate(const Identity& identity, uint32_t signed_id, uint32_t one_time_count);

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

}  // namespace veil

#endif  // VEIL_KEYS_H
