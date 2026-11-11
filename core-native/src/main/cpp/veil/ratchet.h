// Veil - Double Ratchet session.
//
// One Session object represents the cryptographic state shared with exactly
// one peer. It is not thread safe; the engine serialises access.
#ifndef VEIL_RATCHET_H
#define VEIL_RATCHET_H

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "veil/common.h"
#include "veil/keys.h"

namespace veil {

// The handshake parameters that must travel with the first message(s) so the
// recipient can run its side of X3DH. Once the peer has replied, the session
// drops this and sends plain ratchet messages.
//
// It carries the sender's *whole* identity, not just the DH half, for two
// reasons. The binding signature lets the recipient check that the DH key it
// will run X3DH against and the signing key it will trust for future prekeys
// belong to the same holder. And without the signing half the recipient could
// never compute a safety number the sender would agree with, because the
// sender's own safety number covers both halves of its identity.
struct PreKeyHeader {
    uint8_t  sender_identity_dh[kKeySize]{};
    uint8_t  sender_identity_sign[32]{};
    uint8_t  sender_binding[kBindingSize]{};   // sign key over sender_identity_dh
    uint8_t  sender_ephemeral[kKeySize]{};
    uint8_t  recipient_identity_dh[kKeySize]{};
    uint32_t signed_prekey_id = 0;
    uint32_t one_time_prekey_id = 0;  // 0 == no one-time prekey was used

    static constexpr size_t kSize = 32 + 32 + 64 + 32 + 32 + 4 + 4;

    void write(uint8_t* out) const;
    static bool read(PreKeyHeader& out, const uint8_t* in, size_t size);
};

// Header attached to every ratchet message.
struct RatchetHeader {
    uint8_t  dh_pub[kKeySize]{};
    uint32_t previous_chain_length = 0;
    uint32_t message_number = 0;

    static constexpr size_t kSize = kHeaderSize;

    void write(uint8_t* out) const;
    static bool read(RatchetHeader& out, const uint8_t* in, size_t size);
};

// A decrypted or to-be-encrypted ratchet message.
struct RatchetMessage {
    RatchetHeader header;
    Bytes ciphertext;  // includes the 16-byte MAC appended at the end
};

class Session {
public:
    // ---- Construction ---------------------------------------------------

    // Runs the sender half of X3DH against a downloaded prekey bundle and
    // performs the first DH ratchet step.
    bool establishOutbound(const Identity& identity, const PreKeyBundle& bundle);

    // Runs the receiver half of X3DH from an inbound prekey header.
    //
    // Takes `prekeys` by reference because a successful handshake *spends* the
    // one-time prekey it named. A const reference would either hide that
    // mutation or force it to happen somewhere the caller cannot see, and a
    // spent key that is not recorded anywhere is a key that can be used twice.
    bool establishInbound(const Identity& identity,
                          PreKeys& prekeys,
                          const PreKeyHeader& header);

    // ---- Messaging ------------------------------------------------------

    // Encrypts `plain`. `extra_aad` is authenticated but not encrypted; the
    // engine passes the prekey header here so an attacker cannot swap it.
    bool encrypt(const uint8_t* plain, size_t plain_size,
                 const uint8_t* extra_aad, size_t extra_aad_size,
                 RatchetMessage& out);

    // Decrypts `message`. Fails (returns false) on any authentication error,
    // replay, or unsupported skip. `out` is only written on success.
    bool decrypt(const RatchetMessage& message,
                 const uint8_t* extra_aad, size_t extra_aad_size,
                 Bytes& out);

    // As above, but says whether the frame was refused because it had already
    // been accepted.
    //
    // That distinction is not cosmetic. The relay delivers at-least-once - one
    // live push plus a replay of the same outbox entry - so a duplicated frame
    // is a normal event, while a frame that fails to authenticate on a counter
    // we have *not* consumed is a tamper attempt. Collapsing both into one
    // error meant every duplicate looked like an attack.
    enum DecryptResult : int32_t {
        DecryptOk = 0,
        // Already consumed: either the counter is behind the chain, or the
        // frame belongs to a chain we have ratcheted away from.
        DecryptDuplicate = 1,
        // Would not authenticate on a counter we have not seen.
        DecryptAuthFailed = 2,
        // The counter is so far ahead that honouring it would blow the
        // skipped-key budget.
        DecryptTooFarAhead = 3,
    };
    DecryptResult decryptDetailed(const RatchetMessage& message,
                                  const uint8_t* extra_aad, size_t extra_aad_size,
                                  Bytes& out);

    // ---- Handshake state ------------------------------------------------

    bool hasPendingPreKeyHeader() const { return has_pending_prekey_; }
    const PreKeyHeader& pendingPreKeyHeader() const { return pending_prekey_; }
    void clearPendingPreKeyHeader() { has_pending_prekey_ = false; }

    // ---- Introspection -------------------------------------------------
    //
    // The skipped-key budget is a memory bound, so it has to be observable to
    // be tested: without a count there is no way to assert that repeated
    // ratchet steps cannot grow the table past the cap.
    size_t skippedKeyCount() const { return skipped_total_; }
    size_t skippedChainCount() const { return skipped_.size(); }

    // ---- Persistence ----------------------------------------------------

    // Serialises the full ratchet state, including chain keys. The result is
    // itself sensitive and must be encrypted before it touches disk.
    Bytes serialize() const;
    bool deserialize(const uint8_t* data, size_t size);

    void wipe();

private:
    // Advances the sending chain and returns the message key for this message.
    bool nextSendingKey(std::array<uint8_t, 32>& message_key);

    // Performs a DH ratchet step on receiving a new peer public key.
    // `remote_previous_chain_length` is the count the peer reports for the
    // chain it just finished, which is how far our old receiving chain has to
    // be drained before it is replaced.
    bool dhRatchet(const uint8_t remote_pub[kKeySize],
                   uint32_t remote_previous_chain_length);

    // Caches a message key for a message we have not seen yet, so that
    // out-of-order delivery still decrypts.
    bool skipMessageKeys(uint32_t until);

    static void kdfRootKey(const uint8_t root_key[32],
                           const uint8_t dh_out[32],
                           uint8_t new_root_key[32],
                           uint8_t chain_key[32]);

    static void kdfChainKey(const uint8_t chain_key[32],
                            uint8_t next_chain_key[32],
                            uint8_t message_key[32]);

    static void deriveMessageKeyMaterial(const uint8_t message_key[32],
                                         uint8_t enc_key[32],
                                         uint8_t nonce[kNonceSize]);

    // ---- DH ratchet ----
    uint8_t dh_self_pub_[kKeySize]{};
    uint8_t dh_self_priv_[kKeySize]{};
    uint8_t dh_remote_pub_[kKeySize]{};

    // The ratchet key we most recently moved past. A frame carrying it is
    // either a skipped message (handled from the cache) or a replay, and
    // must never be allowed to drag the ratchet backwards.
    uint8_t dh_prev_remote_pub_[kKeySize]{};
    bool has_prev_remote_ = false;

    // ---- Symmetric ratchets ----
    std::array<uint8_t, 32> root_key_{};
    std::array<uint8_t, 32> chain_send_{};
    std::array<uint8_t, 32> chain_recv_{};
    uint32_t n_send_ = 0;
    uint32_t n_recv_ = 0;
    uint32_t pn_ = 0;

    // Skipped message keys, indexed by the peer's ratchet public key and then
// by message number.
    //
    // Ordered by peer key so the oldest chain can be evicted first when the
    // global budget is exceeded: a chain the peer ratcheted away from long ago
    // is the least likely to still be needed.
    std::map<std::array<uint8_t, 32>, std::map<uint32_t, std::array<uint8_t, 32>>>
        skipped_;
    size_t skipped_total_ = 0;

    // Drops the oldest chain buckets until the total is back inside the
    // budget. Returns how many keys were discarded.
    size_t evictSkippedOverBudget();

    bool has_pending_prekey_ = false;
    PreKeyHeader pending_prekey_;
};

}  // namespace veil

#endif  // VEIL_RATCHET_H
