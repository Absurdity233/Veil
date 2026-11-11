#include "veil/ratchet.h"

#include <cstring>

#include "veil/crypto.h"
#include "veil/random.h"

namespace veil {
namespace {

// Every derivation carries a distinct domain string so that a value produced
// for one purpose can never be mistaken for another.
constexpr char kDomainX3dh[]     = "Veil/x3dh/v1";
constexpr char kDomainRootKey[]  = "Veil/ratchet/root/v1";
constexpr char kDomainMessage[]  = "Veil/message/v1";

// X3DH prepends 32 bytes of 0xFF to the DH outputs. The constant makes the
// input to HKDF distinguishable from any other concatenation of DH results.
constexpr uint8_t kX3dhPrefix[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

constexpr uint8_t kRatchetInfoChain = 0x02;
constexpr uint8_t kRatchetInfoMessage = 0x01;

constexpr uint32_t kStateVersion = 1;

}  // namespace

// ---- Header helpers ----------------------------------------------------

void PreKeyHeader::write(uint8_t* out) const {
    std::memcpy(out, sender_identity_dh, 32);
    std::memcpy(out + 32, sender_identity_sign, 32);
    std::memcpy(out + 64, sender_binding, 64);
    std::memcpy(out + 128, sender_ephemeral, 32);
    std::memcpy(out + 160, recipient_identity_dh, 32);
    put_u32(out + 192, signed_prekey_id);
    put_u32(out + 196, one_time_prekey_id);
}

bool PreKeyHeader::read(PreKeyHeader& out, const uint8_t* in, size_t size) {
    if (in == nullptr || size < kSize) return false;
    std::memcpy(out.sender_identity_dh, in, 32);
    std::memcpy(out.sender_identity_sign, in + 32, 32);
    std::memcpy(out.sender_binding, in + 64, 64);
    std::memcpy(out.sender_ephemeral, in + 128, 32);
    std::memcpy(out.recipient_identity_dh, in + 160, 32);
    out.signed_prekey_id = get_u32(in + 192);
    out.one_time_prekey_id = get_u32(in + 196);
    return true;
}

void RatchetHeader::write(uint8_t* out) const {
    std::memcpy(out, dh_pub, 32);
    put_u32(out + 32, previous_chain_length);
    put_u32(out + 36, message_number);
}

bool RatchetHeader::read(RatchetHeader& out, const uint8_t* in, size_t size) {
    if (in == nullptr || size < kSize) return false;
    std::memcpy(out.dh_pub, in, 32);
    out.previous_chain_length = get_u32(in + 32);
    out.message_number = get_u32(in + 36);
    return true;
}

// ---- KDFs --------------------------------------------------------------

void Session::kdfRootKey(const uint8_t root_key[32],
                         const uint8_t dh_out[32],
                         uint8_t new_root_key[32],
                         uint8_t chain_key[32]) {
    uint8_t out[64];
    crypto::hkdf(out, sizeof(out),
                 dh_out, 32,
                 root_key, 32,
                 reinterpret_cast<const uint8_t*>(kDomainRootKey),
                 sizeof(kDomainRootKey) - 1);
    std::memcpy(new_root_key, out, 32);
    std::memcpy(chain_key, out + 32, 32);
    veil::wipe(out, sizeof(out));
}

void Session::kdfChainKey(const uint8_t chain_key[32],
                          uint8_t next_chain_key[32],
                          uint8_t message_key[32]) {
    const uint8_t chain_const = kRatchetInfoChain;
    const uint8_t msg_const = kRatchetInfoMessage;
    crypto::hmac_sha512_32(next_chain_key, chain_key, &chain_const, 1);
    crypto::hmac_sha512_32(message_key, chain_key, &msg_const, 1);
}

void Session::deriveMessageKeyMaterial(const uint8_t message_key[32],
                                       uint8_t enc_key[32],
                                       uint8_t nonce[kNonceSize]) {
    uint8_t out[32 + kNonceSize];
    crypto::hkdf(out, sizeof(out),
                 message_key, 32,
                 nullptr, 0,
                 reinterpret_cast<const uint8_t*>(kDomainMessage),
                 sizeof(kDomainMessage) - 1);
    std::memcpy(enc_key, out, 32);
    std::memcpy(nonce, out + 32, kNonceSize);
    veil::wipe(out, sizeof(out));
}

// ---- X3DH --------------------------------------------------------------

bool Session::establishOutbound(const Identity& identity, const PreKeyBundle& bundle) {
    // 1. Verify that the signed prekey really was signed by the peer's
    //    identity key. The signed message covers the identity's DH public key
    //    as well, so these bytes also prove that the signing key and the key
    //    X3DH runs against belong to the same holder. Without that a server
    //    could pair a victim's DH key with its own signing key and sit in the
    //    middle while the safety number stayed put.
    if (!verifySignedPreKey(bundle.identity_dh_pub, bundle.identity_sign_pub,
                            bundle.signed_pub, bundle.signed_signature)) {
        return false;
    }

    // 2. Generate the ephemeral key for this session.
    uint8_t ek_pub[kKeySize];
    uint8_t ek_priv[kKeySize];
    if (!crypto::x25519_generate(ek_pub, ek_priv)) return false;

    // 3. Four Diffie-Hellman operations.
    uint8_t dh1[kKeySize], dh2[kKeySize], dh3[kKeySize], dh4[kKeySize];
    bool ok = crypto::x25519(dh1, identity.dh_priv, bundle.signed_pub) &&
              crypto::x25519(dh2, ek_priv, bundle.identity_dh_pub) &&
              crypto::x25519(dh3, ek_priv, bundle.signed_pub);
    if (ok && bundle.has_one_time) {
        ok = crypto::x25519(dh4, ek_priv, bundle.one_time_pub);
    }
    if (!ok) {
        veil::wipe(dh1, sizeof(dh1));
        veil::wipe(dh2, sizeof(dh2));
        veil::wipe(dh3, sizeof(dh3));
        veil::wipe(ek_priv, sizeof(ek_priv));
        return false;
    }

    // 4. SK = HKDF(F || DH1 || DH2 || DH3 || DH4)
    uint8_t ikm[32 + kKeySize * 4];
    size_t ikm_len = 32;
    std::memcpy(ikm, kX3dhPrefix, 32);
    std::memcpy(ikm + ikm_len, dh1, kKeySize); ikm_len += kKeySize;
    std::memcpy(ikm + ikm_len, dh2, kKeySize); ikm_len += kKeySize;
    std::memcpy(ikm + ikm_len, dh3, kKeySize); ikm_len += kKeySize;
    if (bundle.has_one_time) {
        std::memcpy(ikm + ikm_len, dh4, kKeySize); ikm_len += kKeySize;
    }

    uint8_t sk[32];
    crypto::hkdf(sk, sizeof(sk), ikm, ikm_len, nullptr, 0,
                 reinterpret_cast<const uint8_t*>(kDomainX3dh),
                 sizeof(kDomainX3dh) - 1);

    veil::wipe(ikm, sizeof(ikm));
    veil::wipe(dh1, sizeof(dh1));
    veil::wipe(dh2, sizeof(dh2));
    veil::wipe(dh3, sizeof(dh3));
    veil::wipe(dh4, sizeof(dh4));

    // 5. Remember the handshake parameters for the first message.
    pending_prekey_.signed_prekey_id = bundle.signed_prekey_id;
    pending_prekey_.one_time_prekey_id = bundle.has_one_time ? bundle.one_time_id : 0;
    std::memcpy(pending_prekey_.sender_identity_dh, identity.dh_pub, 32);
    std::memcpy(pending_prekey_.sender_identity_sign, identity.sign_pub, 32);
    identity.bindingSignature(pending_prekey_.sender_binding);
    std::memcpy(pending_prekey_.sender_ephemeral, ek_pub, 32);
    std::memcpy(pending_prekey_.recipient_identity_dh, bundle.identity_dh_pub, 32);
    has_pending_prekey_ = true;

    // 6. Initialise the ratchet. The sender takes a fresh DH key pair and
    //    treats the peer's signed prekey as the first remote ratchet key.
    if (!crypto::x25519_generate(dh_self_pub_, dh_self_priv_)) {
        veil::wipe(sk, sizeof(sk));
        veil::wipe(ek_priv, sizeof(ek_priv));
        return false;
    }
    std::memcpy(dh_remote_pub_, bundle.signed_pub, kKeySize);

    uint8_t dh_out[32];
    if (!crypto::x25519(dh_out, dh_self_priv_, dh_remote_pub_)) {
        veil::wipe(sk, sizeof(sk));
        veil::wipe(ek_priv, sizeof(ek_priv));
        return false;
    }

    uint8_t new_root[32];
    uint8_t chain[32];
    kdfRootKey(sk, dh_out, new_root, chain);

    std::memcpy(root_key_.data(), new_root, 32);
    std::memcpy(chain_send_.data(), chain, 32);
    std::memset(chain_recv_.data(), 0, 32);
    n_send_ = 0;
    n_recv_ = 0;
    pn_ = 0;

    veil::wipe(sk, sizeof(sk));
    veil::wipe(ek_priv, sizeof(ek_priv));
    veil::wipe(dh_out, sizeof(dh_out));
    veil::wipe(new_root, sizeof(new_root));
    veil::wipe(chain, sizeof(chain));
    return true;
}

bool Session::establishInbound(const Identity& identity,
                               PreKeys& prekeys,
                               const PreKeyHeader& header) {
    // The header must be addressed to this identity.
    if (!constant_time_equal(header.recipient_identity_dh, identity.dh_pub, 32)) {
        return false;
    }

    // The sender's two identity halves have to belong together before either
    // one is used. Without this check a relay could take a victim's DH key,
    // bolt on its own signing key, and present a bundle whose prekey signature
    // verifies - the safety number would not move because the DH half is the
    // victim's.
    if (!Identity::verifyBinding(header.sender_identity_dh,
                                 header.sender_identity_sign,
                                 header.sender_binding)) {
        return false;
    }

    // The header names the signed prekey the sender used. A frame that names
    // a key we do not hold cannot complete X3DH, and silently falling back to
    // the current key would derive a different secret than the sender did,
    // producing a session that fails on the first message with no explanation.
    // The retired prekey is checked too, so a bundle fetched just before a
    // rotation still works.
    const uint8_t* signed_priv = prekeys.signedPrivFor(header.signed_prekey_id);
    if (signed_priv == nullptr) return false;

    // Locate and spend the one-time prekey the sender used, if any.
    //
    // `consumeOneTime` refuses an id that has already been spent. Without that
    // a replayed first frame would re-run X3DH against the same one-time key,
    // which is the one thing a one-time key must never allow.
    const OneTimePreKey* ot = nullptr;
    if (header.one_time_prekey_id != 0) {
        ot = prekeys.consumeOneTime(header.one_time_prekey_id);
        if (ot == nullptr) return false;
    }

    uint8_t dh1[kKeySize], dh2[kKeySize], dh3[kKeySize], dh4[kKeySize];
    bool ok = crypto::x25519(dh1, signed_priv, header.sender_identity_dh) &&
              crypto::x25519(dh2, identity.dh_priv, header.sender_ephemeral) &&
              crypto::x25519(dh3, signed_priv, header.sender_ephemeral);
    if (ok && ot != nullptr) {
        ok = crypto::x25519(dh4, ot->priv, header.sender_ephemeral);
    }
    if (!ok) {
        veil::wipe(dh1, sizeof(dh1));
        veil::wipe(dh2, sizeof(dh2));
        veil::wipe(dh3, sizeof(dh3));
        return false;
    }

    uint8_t ikm[32 + kKeySize * 4];
    size_t ikm_len = 32;
    std::memcpy(ikm, kX3dhPrefix, 32);
    std::memcpy(ikm + ikm_len, dh1, kKeySize); ikm_len += kKeySize;
    std::memcpy(ikm + ikm_len, dh2, kKeySize); ikm_len += kKeySize;
    std::memcpy(ikm + ikm_len, dh3, kKeySize); ikm_len += kKeySize;
    if (ot != nullptr) {
        std::memcpy(ikm + ikm_len, dh4, kKeySize); ikm_len += kKeySize;
    }

    uint8_t sk[32];
    crypto::hkdf(sk, sizeof(sk), ikm, ikm_len, nullptr, 0,
                 reinterpret_cast<const uint8_t*>(kDomainX3dh),
                 sizeof(kDomainX3dh) - 1);

    veil::wipe(ikm, sizeof(ikm));
    veil::wipe(dh1, sizeof(dh1));
    veil::wipe(dh2, sizeof(dh2));
    veil::wipe(dh3, sizeof(dh3));
    veil::wipe(dh4, sizeof(dh4));

    // Receiver starts with the root key only. Its first DH ratchet happens
    // when the sender's first message arrives.
    std::memcpy(root_key_.data(), sk, 32);
    std::memset(chain_send_.data(), 0, 32);
    std::memset(chain_recv_.data(), 0, 32);
    std::memcpy(dh_self_priv_, signed_priv, kKeySize);
    crypto::x25519_keypair(dh_self_pub_, dh_self_priv_);
    std::memset(dh_remote_pub_, 0, kKeySize);
    n_send_ = 0;
    n_recv_ = 0;
    pn_ = 0;
    skipped_.clear();
    skipped_total_ = 0;
    has_pending_prekey_ = false;
    has_prev_remote_ = false;
    std::memset(dh_prev_remote_pub_, 0, kKeySize);

    veil::wipe(sk, sizeof(sk));
    return true;
}

// ---- Ratchet steps -----------------------------------------------------

bool Session::dhRatchet(const uint8_t remote_pub[kKeySize],
                        uint32_t remote_previous_chain_length) {
    // Drain whatever is still outstanding on the old receiving chain, up to
    // the length the peer reports for it. A zeroed chain key means we have
    // not received anything on it yet.
    uint8_t acc = 0;
    for (uint8_t b : chain_recv_) acc |= b;
    if (acc != 0) {
        if (!skipMessageKeys(remote_previous_chain_length)) return false;
    }

    // Remember the key we are leaving behind so a late frame from that chain
    // is rejected instead of triggering a backwards ratchet. A zeroed remote
    // key means no chain existed yet (the responder's first ratchet), so
    // there is nothing to remember.
    uint8_t remote_acc = 0;
    for (size_t i = 0; i < kKeySize; ++i) remote_acc |= dh_remote_pub_[i];
    if (remote_acc != 0) {
        std::memcpy(dh_prev_remote_pub_, dh_remote_pub_, kKeySize);
        has_prev_remote_ = true;
    }

    pn_ = n_send_;
    n_send_ = 0;
    n_recv_ = 0;
    std::memcpy(dh_remote_pub_, remote_pub, kKeySize);

    uint8_t dh_out[32];
    if (!crypto::x25519(dh_out, dh_self_priv_, dh_remote_pub_)) return false;

    uint8_t new_root[32], new_chain[32];
    kdfRootKey(root_key_.data(), dh_out, new_root, new_chain);
    std::memcpy(root_key_.data(), new_root, 32);
    std::memcpy(chain_recv_.data(), new_chain, 32);

    // Immediately take our own new DH key pair and advance the sending chain.
    if (!crypto::x25519_generate(dh_self_pub_, dh_self_priv_)) {
        veil::wipe(dh_out, sizeof(dh_out));
        return false;
    }
    if (!crypto::x25519(dh_out, dh_self_priv_, dh_remote_pub_)) {
        veil::wipe(dh_out, sizeof(dh_out));
        return false;
    }
    kdfRootKey(root_key_.data(), dh_out, new_root, new_chain);
    std::memcpy(root_key_.data(), new_root, 32);
    std::memcpy(chain_send_.data(), new_chain, 32);

    veil::wipe(dh_out, sizeof(dh_out));
    veil::wipe(new_root, sizeof(new_root));
    veil::wipe(new_chain, sizeof(new_chain));
    return true;
}

size_t Session::evictSkippedOverBudget() {
    size_t dropped = 0;
    while (skipped_total_ > kMaxSkippedKeysTotal && !skipped_.empty()) {
        auto oldest = skipped_.begin();
        for (auto& [idx, mk] : oldest->second) {
            veil::wipe(mk.data(), mk.size());
            ++dropped;
        }
        skipped_total_ -= oldest->second.size();
        skipped_.erase(oldest);
    }
    return dropped;
}

bool Session::skipMessageKeys(uint32_t until) {
    if (until < n_recv_) return true;  // already past it
    if (until - n_recv_ > kMaxSkippedKeys) return false;

    // Refuse before doing any work if this run could not fit even after
    // evicting every other chain: the sender is asking for something no
    // session could honour, so the frame is not a legitimate late arrival.
    if (skipped_total_ + (until - n_recv_) > kMaxSkippedKeysTotal + kMaxSkippedKeys) {
        return false;
    }

    std::array<uint8_t, 32> peer_key;
    std::memcpy(peer_key.data(), dh_remote_pub_, 32);

    auto& bucket = skipped_[peer_key];
    while (n_recv_ < until) {
        uint8_t next_chain[32];
        uint8_t message_key[32];
        kdfChainKey(chain_recv_.data(), next_chain, message_key);

        std::array<uint8_t, 32> mk;
        std::memcpy(mk.data(), message_key, 32);

        // Idempotent: a replayed header must not be able to inflate the count.
        if (bucket.emplace(n_recv_, mk).second) ++skipped_total_;

        std::memcpy(chain_recv_.data(), next_chain, 32);
        ++n_recv_;
        veil::wipe(next_chain, sizeof(next_chain));
        veil::wipe(message_key, sizeof(message_key));
    }

    // The per-chain cap still applies, but the global one now decides what has
    // to go when several chains are open at once.
    while (bucket.size() > kMaxSkippedKeys) {
        auto victim = bucket.begin();
        veil::wipe(victim->second.data(), victim->second.size());
        bucket.erase(victim);
        --skipped_total_;
    }

    evictSkippedOverBudget();
    return true;
}

bool Session::nextSendingKey(std::array<uint8_t, 32>& message_key) {
    uint8_t next_chain[32];
    uint8_t mk[32];
    kdfChainKey(chain_send_.data(), next_chain, mk);
    std::memcpy(chain_send_.data(), next_chain, 32);
    std::memcpy(message_key.data(), mk, 32);
    veil::wipe(next_chain, sizeof(next_chain));
    veil::wipe(mk, sizeof(mk));
    ++n_send_;
    return true;
}

// ---- Encrypt / decrypt -------------------------------------------------

bool Session::encrypt(const uint8_t* plain, size_t plain_size,
                      const uint8_t* extra_aad, size_t extra_aad_size,
                      RatchetMessage& out) {
    if (plain == nullptr && plain_size != 0) return false;

    // The sending chain only exists once a DH ratchet has happened. For the
    // initiator that is at establishment; for the responder it is on its
    // first send, which is triggered by the peer's first message.
    uint8_t acc = 0;
    for (uint8_t b : chain_send_) acc |= b;
    if (acc == 0) return false;

    std::array<uint8_t, 32> message_key;
    if (!nextSendingKey(message_key)) return false;

    uint8_t enc_key[32];
    uint8_t nonce[kNonceSize];
    deriveMessageKeyMaterial(message_key.data(), enc_key, nonce);

    out.header.message_number = n_send_ - 1;
    out.header.previous_chain_length = pn_;
    std::memcpy(out.header.dh_pub, dh_self_pub_, 32);

    // AAD binds the header (including the DH public key and counters) to the
    // ciphertext, so an attacker cannot rewrite routing data without the
    // recipient noticing.
    uint8_t header_bytes[RatchetHeader::kSize];
    out.header.write(header_bytes);

    Bytes aad;
    aad.reserve(sizeof(header_bytes) + extra_aad_size);
    aad.insert(aad.end(), header_bytes, header_bytes + sizeof(header_bytes));
    if (extra_aad_size > 0) aad.insert(aad.end(), extra_aad, extra_aad + extra_aad_size);

    out.ciphertext.assign(plain_size + kMacSize, 0);
    crypto::aead_encrypt(out.ciphertext.data(), out.ciphertext.data() + plain_size,
                         enc_key, nonce, aad.data(), aad.size(), plain, plain_size);

    veil::wipe(message_key.data(), message_key.size());
    veil::wipe(enc_key, sizeof(enc_key));
    veil::wipe(nonce, sizeof(nonce));
    return true;
}

bool Session::decrypt(const RatchetMessage& message,
                      const uint8_t* extra_aad, size_t extra_aad_size,
                      Bytes& out) {
    return decryptDetailed(message, extra_aad, extra_aad_size, out) == DecryptOk;
}

Session::DecryptResult Session::decryptDetailed(const RatchetMessage& message,
                                                const uint8_t* extra_aad, size_t extra_aad_size,
                                                Bytes& out) {
    // A frame too short to even carry a MAC is malformed, not a duplicate:
    // saying otherwise would let a truncated delivery be swallowed silently.
    if (message.ciphertext.size() < kMacSize) return DecryptAuthFailed;

    const size_t text_size = message.ciphertext.size() - kMacSize;

    uint8_t header_bytes[RatchetHeader::kSize];
    message.header.write(header_bytes);

    Bytes aad;
    aad.reserve(sizeof(header_bytes) + extra_aad_size);
    aad.insert(aad.end(), header_bytes, header_bytes + sizeof(header_bytes));
    if (extra_aad_size > 0) aad.insert(aad.end(), extra_aad, extra_aad + extra_aad_size);

    std::array<uint8_t, 32> message_key;
    bool have_key = false;

    // 1. A previously skipped message?
    std::array<uint8_t, 32> peer_key;
    std::memcpy(peer_key.data(), message.header.dh_pub, 32);
    auto bucket_it = skipped_.find(peer_key);
    if (bucket_it != skipped_.end()) {
        auto mk_it = bucket_it->second.find(message.header.message_number);
        if (mk_it != bucket_it->second.end()) {
            message_key = mk_it->second;
            veil::wipe(mk_it->second.data(), mk_it->second.size());
            bucket_it->second.erase(mk_it);
            --skipped_total_;
            if (bucket_it->second.empty()) skipped_.erase(bucket_it);
            have_key = true;
        }
    }

    // 2. Otherwise this must be a new ratchet key.
    if (!have_key) {
        // A frame from a chain we have already left cannot be decrypted any
        // more, and treating it as a new ratchet key would drag the session
        // backwards. That is a duplicate, not an attack.
        if (has_prev_remote_ &&
            constant_time_equal(message.header.dh_pub, dh_prev_remote_pub_, kKeySize)) {
            return DecryptDuplicate;
        }

        if (!constant_time_equal(message.header.dh_pub, dh_remote_pub_, kKeySize)) {
            if (!dhRatchet(message.header.dh_pub,
                           message.header.previous_chain_length)) {
                return DecryptTooFarAhead;
            }
        }

        if (message.header.message_number < n_recv_) {
            // The counter has already been consumed and the key is gone, so
            // this frame cannot be authenticated either way. It is a
            // duplicate: the only way to produce it is to resend something
            // that was accepted once, because a fresh forgery would have had
            // to guess a counter we already advanced past.
            return DecryptDuplicate;
        }

        if (!skipMessageKeys(message.header.message_number)) return DecryptTooFarAhead;

        uint8_t next_chain[32];
        kdfChainKey(chain_recv_.data(), next_chain, message_key.data());
        std::memcpy(chain_recv_.data(), next_chain, 32);
        ++n_recv_;
        veil::wipe(next_chain, sizeof(next_chain));
    }

    uint8_t enc_key[32];
    uint8_t nonce[kNonceSize];
    deriveMessageKeyMaterial(message_key.data(), enc_key, nonce);

    Bytes plain(text_size);
    bool ok = crypto::aead_decrypt(plain.data(),
                                   message.ciphertext.data() + text_size,
                                   enc_key, nonce,
                                   aad.data(), aad.size(),
                                   message.ciphertext.data(), text_size);

    veil::wipe(message_key.data(), message_key.size());
    veil::wipe(enc_key, sizeof(enc_key));
    veil::wipe(nonce, sizeof(nonce));

    if (!ok) return DecryptAuthFailed;
    out = std::move(plain);
    return DecryptOk;
}

// ---- Persistence -------------------------------------------------------

Bytes Session::serialize() const {
    Bytes out;
    out.reserve(1 + 4 + 32 * 3 + 32 * 3 + 12 + 4 + skipped_total_ * 36);

    out.push_back(static_cast<uint8_t>(kStateVersion));
    out.insert(out.end(), dh_self_pub_, dh_self_pub_ + 32);
    out.insert(out.end(), dh_self_priv_, dh_self_priv_ + 32);
    out.insert(out.end(), dh_remote_pub_, dh_remote_pub_ + 32);
    out.insert(out.end(), dh_prev_remote_pub_, dh_prev_remote_pub_ + 32);
    out.push_back(has_prev_remote_ ? 1 : 0);
    out.insert(out.end(), root_key_.begin(), root_key_.end());
    out.insert(out.end(), chain_send_.begin(), chain_send_.end());
    out.insert(out.end(), chain_recv_.begin(), chain_recv_.end());

    uint8_t num[12];
    put_u32(num, n_send_);
    put_u32(num + 4, n_recv_);
    put_u32(num + 8, pn_);
    out.insert(out.end(), num, num + 12);

    put_u32(num, static_cast<uint32_t>(skipped_.size()));
    out.insert(out.end(), num, num + 4);

    for (const auto& [peer_key, keys] : skipped_) {
        out.insert(out.end(), peer_key.begin(), peer_key.end());
        put_u32(num, static_cast<uint32_t>(keys.size()));
        out.insert(out.end(), num, num + 4);
        for (const auto& [idx, mk] : keys) {
            put_u32(num, idx);
            out.insert(out.end(), num, num + 4);
            out.insert(out.end(), mk.begin(), mk.end());
        }
    }
    return out;
}

bool Session::deserialize(const uint8_t* data, size_t size) {
    if (data == nullptr) return false;

    size_t off = 0;
    if (size < 1 + 32 * 4 + 1 + 32 * 3 + 12 + 4) return false;
    if (data[off++] != kStateVersion) return false;

    std::memcpy(dh_self_pub_, data + off, 32); off += 32;
    std::memcpy(dh_self_priv_, data + off, 32); off += 32;
    std::memcpy(dh_remote_pub_, data + off, 32); off += 32;
    std::memcpy(dh_prev_remote_pub_, data + off, 32); off += 32;
    has_prev_remote_ = data[off++] != 0;
    std::memcpy(root_key_.data(), data + off, 32); off += 32;
    std::memcpy(chain_send_.data(), data + off, 32); off += 32;
    std::memcpy(chain_recv_.data(), data + off, 32); off += 32;

    n_send_ = get_u32(data + off); off += 4;
    n_recv_ = get_u32(data + off); off += 4;
    pn_ = get_u32(data + off); off += 4;

    uint32_t peer_count = get_u32(data + off); off += 4;
    if (peer_count > kMaxSkippedKeysTotal) return false;

    skipped_.clear();
    skipped_total_ = 0;
    for (uint32_t i = 0; i < peer_count; ++i) {
        if (size < off + 32 + 4) return false;
        std::array<uint8_t, 32> peer_key;
        std::memcpy(peer_key.data(), data + off, 32); off += 32;
        uint32_t count = get_u32(data + off); off += 4;
        if (count > kMaxSkippedKeys) return false;
        if (skipped_total_ + count > kMaxSkippedKeysTotal) return false;

        std::map<uint32_t, std::array<uint8_t, 32>> bucket;
        for (uint32_t j = 0; j < count; ++j) {
            if (size < off + 4 + 32) return false;
            uint32_t idx = get_u32(data + off); off += 4;
            std::array<uint8_t, 32> mk;
            std::memcpy(mk.data(), data + off, 32); off += 32;
            bucket[idx] = mk;
        }
        skipped_total_ += bucket.size();
        skipped_[peer_key] = std::move(bucket);
    }

    has_pending_prekey_ = false;
    return true;
}

void Session::wipe() {
    veil::wipe(dh_self_priv_, sizeof(dh_self_priv_));
    veil::wipe(dh_remote_pub_, sizeof(dh_remote_pub_));
    veil::wipe(dh_prev_remote_pub_, sizeof(dh_prev_remote_pub_));
    has_prev_remote_ = false;
    veil::wipe(root_key_.data(), root_key_.size());
    veil::wipe(chain_send_.data(), chain_send_.size());
    veil::wipe(chain_recv_.data(), chain_recv_.size());
    for (auto& [peer_key, keys] : skipped_) {
        for (auto& [idx, mk] : keys) veil::wipe(mk.data(), mk.size());
    }
    skipped_.clear();
    skipped_total_ = 0;
    n_send_ = n_recv_ = pn_ = 0;
}

}  // namespace veil
