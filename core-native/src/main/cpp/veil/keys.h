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

// ---- Device credentials -----------------------------------------------
//
// One account, many devices. The account identity signs an endorsement of each
// device's key pair, and that endorsement is the only thing that makes a device
// able to speak for the account.
//
// This is deliberately a certificate and not a shared secret. Copying the
// identity to every device would multiply the places a private key can leak and
// make revoking one device require rotating the identity - which changes the
// safety number for every peer, which is exactly the event the verification
// story exists to make visible. A per-device key pair means compromising one
// device does not compromise the account.
//
// See docs/multi-device.md for the full argument, including what revocation
// does not do.

constexpr size_t kDeviceIdSize = 32;

// The signed bytes, in order. Fixed width, so there is exactly one encoding and
// no parser to disagree with.
//
//   "Veil/device-credential/v1" || user_id_len(2) || user_id
//   || device_id(32) || device_dh_pub(32) || device_sign_pub(32) || issued_at(8)
//
// The user id is length-prefixed rather than NUL-terminated because a credential
// for "bo" and one for "bob\0" must not collide, and because the relay stores
// user ids as arbitrary byte strings.
constexpr char kDeviceCredentialDomain[] = "Veil/device-credential/v1";

struct DeviceCredential {
    std::string user_id;
    uint8_t  device_id[kDeviceIdSize]{};
    uint8_t  device_dh_pub[kKeySize]{};
    uint8_t  device_sign_pub[32]{};
    uint64_t issued_at = 0;  // seconds since the epoch; display only

    // The device's signing key endorses its own DH key. Without this, a relay
    // could pair this device's DH key with its own signing key and sign prekeys
    // of its choosing - the same attack the account-level binding closes, one
    // level down.
    uint8_t  device_binding[kBindingSize]{};

    // The account identity's endorsement of the whole record above.
    uint8_t  account_signature[kSigSize]{};

    // Builds the credential a device publishes about itself, including the
    // self-binding. Does not fill account_signature.
    static bool create(DeviceCredential& out,
                       const std::string& user_id,
                       const uint8_t device_id[kDeviceIdSize],
                       const uint8_t device_dh_pub[kKeySize],
                       const uint8_t device_dh_priv[kKeySize],
                       const uint8_t device_sign_pub[32],
                       const uint8_t device_sign_priv[64],
                       uint64_t issued_at);

    // Signs a fully populated credential with the account identity.
    bool signBy(const Identity& account_identity);

    // Checks the device's self-binding and the account's endorsement.
    //
    // Both halves matter and neither is sufficient: the binding stops a relay
    // splicing keys, the account signature stops a relay adding a device.
    bool verify(const uint8_t account_dh_pub[kKeySize],
                const uint8_t account_sign_pub[32]) const;

    // Just the device's own binding, for the case where the account signature
    // has been verified separately (the relay does this: it checks the account
    // signature once when the list is published).
    bool verifyDeviceBinding() const;

    // The exact bytes an account signature covers.
    size_t signedMessage(uint8_t* out, size_t capacity) const;

    // Wire form, fixed width except for the user id:
    //   [2] user id length | user id | [32] device id | [32] dh | [32] sign
    //   | [8] issued_at | [64] device binding | [64] account signature
    Bytes serialize() const;
    static bool deserialize(DeviceCredential& out, const uint8_t* data, size_t size);

    // A short human-comparable fingerprint of the device's two public keys, so
    // a linking flow can show *what* is being approved rather than just asking
    // "allow?". Eight groups of four hex digits would be unreadable; this is
    // four groups from a BLAKE2b digest.
    std::string fingerprint() const;
};

// The signed-message encoding, exposed so a test can pin the exact bytes.
size_t deviceCredentialMessage(uint8_t* out, size_t capacity,
                               const std::string& user_id,
                               const uint8_t device_id[kDeviceIdSize],
                               const uint8_t device_dh_pub[kKeySize],
                               const uint8_t device_sign_pub[32],
                               uint64_t issued_at);

// The largest encoding the function above can produce, for buffer sizing.
constexpr size_t kDeviceCredentialMessageMax =
    sizeof(kDeviceCredentialDomain) - 1 + 2 + 128 + kDeviceIdSize +
    kKeySize + 32 + 8;

// Generates a device id from the platform CSPRNG.
bool generateDeviceId(uint8_t out[kDeviceIdSize]);

}  // namespace veil

#endif  // VEIL_KEYS_H
