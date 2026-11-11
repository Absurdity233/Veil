#include "veil/engine.h"

#include <cstdio>
#include <cstring>

#include "veil/crypto.h"

namespace veil {

// ---- Wire framing ------------------------------------------------------

Bytes WireMessage::encode(const Session& session, const RatchetMessage& msg) {
    const bool has_prekey = session.hasPendingPreKeyHeader();

    Bytes out;
    out.reserve(1 + (has_prekey ? PreKeyHeader::kSize : 0) +
                RatchetHeader::kSize + msg.ciphertext.size());

    out.push_back(has_prekey ? kFlagPreKey : 0);
    if (has_prekey) {
        uint8_t buf[PreKeyHeader::kSize];
        session.pendingPreKeyHeader().write(buf);
        out.insert(out.end(), buf, buf + sizeof(buf));
    }

    uint8_t hdr[RatchetHeader::kSize];
    msg.header.write(hdr);
    out.insert(out.end(), hdr, hdr + sizeof(hdr));
    out.insert(out.end(), msg.ciphertext.begin(), msg.ciphertext.end());
    return out;
}

bool WireMessage::decode(const uint8_t* data, size_t size,
                         bool& has_prekey, PreKeyHeader& prekey,
                         RatchetMessage& msg) {
    if (data == nullptr) return false;

    size_t off = 0;
    if (size < 1) return false;
    const uint8_t flags = data[off++];
    has_prekey = (flags & kFlagPreKey) != 0;

    if (has_prekey) {
        if (!PreKeyHeader::read(prekey, data + off, size - off)) return false;
        off += PreKeyHeader::kSize;
    }

    if (!RatchetHeader::read(msg.header, data + off, size - off)) return false;
    off += RatchetHeader::kSize;

    if (size <= off) return false;  // at least the MAC must be present
    msg.ciphertext.assign(data + off, data + size);
    return true;
}

// ---- Engine ------------------------------------------------------------

Engine::~Engine() {
    identity_.wipeSecrets();
    prekeys_.wipeSecrets();
    for (auto& entry : sessions_) entry.second.wipe();
    sessions_.clear();
}

bool Engine::createIdentity() { return identity_.generate(); }

bool Engine::restoreIdentity(const uint8_t* dh_priv, const uint8_t* sign_priv) {
    return Identity::fromSecrets(identity_, dh_priv, sign_priv);
}

Bytes Engine::exportIdentitySecrets() const {
    Bytes out;
    out.reserve(kKeySize + 64);
    out.insert(out.end(), identity_.dh_priv, identity_.dh_priv + kKeySize);
    out.insert(out.end(), identity_.sign_priv, identity_.sign_priv + 64);
    return out;
}

Bytes Engine::exportIdentityPublic() const {
    Bytes out;
    out.reserve(kKeySize + 32);
    out.insert(out.end(), identity_.dh_pub, identity_.dh_pub + kKeySize);
    out.insert(out.end(), identity_.sign_pub, identity_.sign_pub + 32);
    return out;
}

bool Engine::generatePreKeys(uint32_t signed_id, uint32_t one_time_count) {
    return prekeys_.generate(identity_, signed_id, one_time_count);
}

Bytes Engine::exportPreKeySet() const {
    Bytes out;
    out.reserve(4 + 32 + 64 + 4 + prekeys_.one_time.size() * 36);

    uint8_t buf[4];
    put_u32(buf, prekeys_.signed_prekey_id);
    out.insert(out.end(), buf, buf + 4);
    out.insert(out.end(), prekeys_.signed_pub, prekeys_.signed_pub + 32);
    out.insert(out.end(), prekeys_.signed_signature, prekeys_.signed_signature + 64);

    put_u32(buf, static_cast<uint32_t>(prekeys_.one_time.size()));
    out.insert(out.end(), buf, buf + 4);
    for (const auto& ot : prekeys_.one_time) {
        put_u32(buf, ot.id);
        out.insert(out.end(), buf, buf + 4);
        out.insert(out.end(), ot.pub, ot.pub + 32);
    }
    return out;
}

Bytes Engine::publishBundle(int one_time_index) const {
    if (one_time_index < 0) {
        return veil::publishBundle(identity_, prekeys_, nullptr).serialize();
    }
    if (static_cast<size_t>(one_time_index) >= prekeys_.one_time.size()) return {};
    return veil::publishBundle(identity_, prekeys_, &prekeys_.one_time[one_time_index])
        .serialize();
}

// ---- Sessions ----------------------------------------------------------

Session* Engine::findSession(const std::string& peer) {
    auto it = sessions_.find(peer);
    return it == sessions_.end() ? nullptr : &it->second;
}

const Session* Engine::findSession(const std::string& peer) const {
    auto it = sessions_.find(peer);
    return it == sessions_.end() ? nullptr : &it->second;
}

bool Engine::hasSession(const std::string& peer) const {
    return findSession(peer) != nullptr;
}

bool Engine::establishOutbound(const std::string& peer, const uint8_t* bundle, size_t size) {
    PreKeyBundle parsed;
    if (!PreKeyBundle::deserialize(parsed, bundle, size)) return false;

    Session session;
    if (!session.establishOutbound(identity_, parsed)) return false;

    std::memcpy(peer_identity_[peer].data(), parsed.identity_dh_pub, kKeySize);
    sessions_[peer] = std::move(session);
    return true;
}

bool Engine::establishInbound(const std::string& peer, const PreKeyHeader& header) {
    Session session;
    if (!session.establishInbound(identity_, prekeys_, header)) return false;

    std::memcpy(peer_identity_[peer].data(), header.sender_identity_dh, kKeySize);
    sessions_[peer] = std::move(session);
    return true;
}

bool Engine::importSession(const std::string& peer, const uint8_t* data, size_t size) {
    Session session;
    if (!session.deserialize(data, size)) return false;
    sessions_[peer] = std::move(session);
    return true;
}

Bytes Engine::exportSession(const std::string& peer) const {
    const Session* s = findSession(peer);
    if (s == nullptr) return {};
    return s->serialize();
}

void Engine::dropSession(const std::string& peer) {
    auto it = sessions_.find(peer);
    if (it == sessions_.end()) return;
    it->second.wipe();
    sessions_.erase(it);
    peer_identity_.erase(peer);
}

// ---- Messaging ---------------------------------------------------------

Bytes Engine::encrypt(const std::string& peer, const uint8_t* plain, size_t size) {
    Session* s = findSession(peer);
    if (s == nullptr) return {};

    Bytes prekey_aad;
    if (s->hasPendingPreKeyHeader()) {
        uint8_t buf[PreKeyHeader::kSize];
        s->pendingPreKeyHeader().write(buf);
        prekey_aad.assign(buf, buf + sizeof(buf));
    }

    RatchetMessage msg;
    if (!s->encrypt(plain, size, prekey_aad.data(), prekey_aad.size(), msg)) return {};

    Bytes frame = WireMessage::encode(*s, msg);
    if (s->hasPendingPreKeyHeader()) s->clearPendingPreKeyHeader();
    return frame;
}

bool Engine::decrypt(const std::string& peer, const uint8_t* frame, size_t size, Bytes& out) {
    bool has_prekey = false;
    PreKeyHeader prekey;
    RatchetMessage msg;
    if (!WireMessage::decode(frame, size, has_prekey, prekey, msg)) return false;

    Bytes prekey_aad;
    if (has_prekey) {
        uint8_t buf[PreKeyHeader::kSize];
        prekey.write(buf);
        prekey_aad.assign(buf, buf + sizeof(buf));
    }

    Session* s = findSession(peer);

    // A prekey header on a message means the sender has not heard from us
    // yet. With no session, this is the handshake. With a session, the header
    // is stale and must not re-run X3DH.
    if (s == nullptr) {
        if (!has_prekey) return false;

        // Once a peer label has been bound to an identity it must stay bound.
        // Otherwise an attacker could start a fresh handshake under a label
        // we already trust.
        auto known = peer_identity_.find(peer);
        if (known != peer_identity_.end() &&
            !constant_time_equal(known->second.data(),
                                 prekey.sender_identity_dh, kKeySize)) {
            return false;
        }

        if (!establishInbound(peer, prekey)) return false;
        s = findSession(peer);
        if (s == nullptr) return false;
    }

    return s->decrypt(msg, prekey_aad.data(), prekey_aad.size(), out);
}

// ---- Safety number -----------------------------------------------------

std::string Engine::safetyNumber(const std::string& peer) const {
    auto it = peer_identity_.find(peer);
    if (it == peer_identity_.end()) return {};

    const uint8_t* mine = identity_.dh_pub;
    const uint8_t* theirs = it->second.data();

    // Canonical ordering so both sides hash the same bytes.
    const bool mine_first = std::memcmp(mine, theirs, kKeySize) <= 0;
    uint8_t buf[kKeySize * 2];
    if (mine_first) {
        std::memcpy(buf, mine, kKeySize);
        std::memcpy(buf + kKeySize, theirs, kKeySize);
    } else {
        std::memcpy(buf, theirs, kKeySize);
        std::memcpy(buf + kKeySize, mine, kKeySize);
    }

    uint8_t digest[32];
    crypto::blake2b(digest, sizeof(digest), buf, sizeof(buf));

    std::string out;
    out.reserve(29);
    for (int i = 0; i < 5; ++i) {
        uint32_t v = get_u32(digest + i * 4) % 100000u;
        char group[8];
        std::snprintf(group, sizeof(group), "%05u", v);
        if (i != 0) out.push_back(' ');
        out.append(group, 5);
    }
    return out;
}

}  // namespace veil
