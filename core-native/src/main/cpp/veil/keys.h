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
// One signed prekey generation plus the one-time prekeys that went with it.
//
// Two generations are kept. A peer may have downloaded the previous bundle
// just before a rotation and only send its first message afterwards, and
// without the retired private half that handshake could never complete.
struct SignedPreKey {
    uint32_t id = 0;
    uint8_t  pub[kKeySize]{};
    uint8_t  priv[kKeySize]{};
    uint8_t  signature[kSigSize]{};
};

// A one-time prekey, plus whether it has already been handed to somebody.
//
// The consumed flag matters locally, not just at the relay: the relay pops an
// entry when it hands it out, but the *private* half stays here forever unless
// something marks it. Reusing a one-time prekey across two sessions is exactly
// the weakness the "one-time" in the name is meant to exclude.
struct OneTimePreKey {
    uint32_t id = 0;
    uint8_t  pub[kKeySize]{};
    uint8_t  priv[kKeySize]{};
    bool     consumed = false;
};

struct PreKeys {
    // Current and previous generation. Both stay decryptable.
    SignedPreKey current;
    SignedPreKey retired;
    bool         has_retired = false;

    // Every one-time prekey this device ever generated. Bounded, because it
    // is persisted: `kTombstoneKeep` of them are kept per generation so a
    // late first message can still name one, and the rest are dropped.
    std::vector<OneTimePreKey> one_time;

    // The signed prekey *id* counter is monotonic across restarts.
    //
    // It used to be the constant 1, regenerated with fresh keys on every
    // launch. Same id, different key: a peer holding a bundle fetched before
    // the restart could not tell a stale bundle from a current one, and the
    // relay overwrote the row with the new keys under the same name.
    uint32_t next_signed_id = 1;

    uint32_t signed_prekey_id() const { return current.id; }

    // Signs a fresh signed prekey with `identity`, retires the previous one,
    // and generates a fresh batch of one-time prekeys.
    //
    // The signature covers the identity's DH public key as well as the prekey
    // itself - see verifySignedPreKey().
    bool rotate(const Identity& identity, uint32_t one_time_count);

    // Returns the private half that a prekey header was addressed to, or
    // nullptr when the id matches neither the current nor the retired prekey.
    const uint8_t* signedPrivFor(uint32_t signed_id) const;

    // Looks up an unconsumed one-time prekey by id and marks it consumed.
    // Returns nullptr when the id is unknown or already spent.
    const OneTimePreKey* consumeOneTime(uint32_t id);

    // True when fewer than `low_water` one-time prekeys remain unspent, which
    // is the signal to publish a fresh batch.
    bool needsRefill(size_t low_water) const;

    // Drops spent one-time prekeys beyond the tombstone budget.
    void pruneOneTime();

    // ---- Persistence ----------------------------------------------------
    //
    // Prekey state is as sensitive as the sessions: whoever holds the signed
    // prekey's private half can read the first message of any session that
    // used it. It is therefore exported for encrypted storage, never as plain
    // bytes on disk.
    Bytes serialize() const;
    bool deserialize(const uint8_t* data, size_t size);

    void wipeSecrets();
};

// How many one-time prekeys are generated per rotation.
constexpr uint32_t kOneTimeBatch = 20;

// How many spent one-time prekeys are kept so a late handshake can still name
// one, and so a duplicate cannot silently reuse it.
constexpr size_t kTombstoneKeep = 64;

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
                           const OneTimePreKey* one_time);

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
