#include "veil/engine.h"

#include <cstdio>
#include <cstring>
#include <ctime>

#include "veil/crypto.h"

namespace veil {

namespace {

// A pinned identity always has a DH half. The signing half is zero-filled
// until a bundle or prekey header has supplied it, which lets the engine tell
// "pinned DH only" from "pinned both" without a second flag.
bool hasSignHalf(const std::array<uint8_t, kIdentitySize>& known) {
    uint8_t acc = 0;
    for (size_t i = kKeySize; i < kIdentitySize; ++i) acc |= known[i];
    return acc != 0;
}

}  // namespace

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
    out.reserve(kIdentitySize);
    out.insert(out.end(), identity_.dh_pub, identity_.dh_pub + kKeySize);
    out.insert(out.end(), identity_.sign_pub, identity_.sign_pub + 32);
    return out;
}

Bytes Engine::exportIdentityBinding() const {
    uint8_t sig[kBindingSize];
    identity_.bindingSignature(sig);
    Bytes out(sig, sig + sizeof(sig));
    veil::wipe(sig, sizeof(sig));
    return out;
}

bool Engine::verifyIdentityBinding(const uint8_t identity[kIdentitySize],
                                   const uint8_t binding[kBindingSize]) {
    if (identity == nullptr || binding == nullptr) return false;
    return Identity::verifyBinding(identity, identity + kKeySize, binding);
}

Bytes Engine::signChallenge(const uint8_t* data, size_t size) const {
    if (data == nullptr && size != 0) return {};
    uint8_t sig[kSigSize];
    crypto::ed25519_sign(sig, identity_.sign_priv, data, size);
    Bytes out(sig, sig + sizeof(sig));
    veil::wipe(sig, sizeof(sig));
    return out;
}

bool Engine::rotatePreKeys() {
    return prekeys_.rotate(identity_, kOneTimeBatch);
}

bool Engine::needsPreKeyRefill(size_t low_water) const {
    return prekeys_.needsRefill(low_water);
}

// The public prekey set as the relay should store it. Only unspent one-time
// keys are published: a key that has already been handed to somebody must not
// be offered again.
Bytes Engine::exportPreKeySet() const {
    size_t unused = 0;
    for (const auto& ot : prekeys_.one_time) {
        if (!ot.consumed) ++unused;
    }

    Bytes out;
    out.reserve(4 + 32 + 64 + 4 + unused * 36);

    uint8_t buf[4];
    put_u32(buf, prekeys_.current.id);
    out.insert(out.end(), buf, buf + 4);
    out.insert(out.end(), prekeys_.current.pub, prekeys_.current.pub + 32);
    out.insert(out.end(), prekeys_.current.signature, prekeys_.current.signature + 64);

    put_u32(buf, static_cast<uint32_t>(unused));
    out.insert(out.end(), buf, buf + 4);
    for (const auto& ot : prekeys_.one_time) {
        if (ot.consumed) continue;
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

    // Only an unspent key may be offered. Indexing into the raw vector would
    // happily hand out a key that some earlier session already used.
    size_t seen = 0;
    for (const auto& ot : prekeys_.one_time) {
        if (ot.consumed) continue;
        if (seen++ == static_cast<size_t>(one_time_index)) {
            return veil::publishBundle(identity_, prekeys_, &ot).serialize();
        }
    }
    return {};
}

// ---- Prekey state ------------------------------------------------------

Bytes Engine::exportPreKeyState() const {
    return prekeys_.serialize();
}

bool Engine::importPreKeyState(const uint8_t* data, size_t size) {
    PreKeys loaded;
    if (!loaded.deserialize(data, size)) return false;
    prekeys_.wipeSecrets();
    prekeys_ = std::move(loaded);
    return true;
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
    return establishOutboundStatus(peer, bundle, size) == Result::Ok;
}

Engine::Result Engine::establishOutboundStatus(const std::string& peer,
                                               const uint8_t* bundle, size_t size) {
    PreKeyBundle parsed;
    if (!PreKeyBundle::deserialize(parsed, bundle, size)) return Result::BadBundle;

    // A peer label is bound to one identity for the lifetime of the pinning.
    // Learning a different identity for a label we already know is not an
    // ordinary error: it is either a hostile relay or a genuinely reinstalled
    // peer, and either way the user has to be told rather than silently
    // downgraded onto a new session with a new safety number.
    auto known = peer_identity_.find(peer);
    if (known != peer_identity_.end()) {
        if (!constant_time_equal(known->second.data(), parsed.identity_dh_pub, kKeySize) ||
            !constant_time_equal(known->second.data() + kKeySize,
                                 parsed.identity_sign_pub, 32)) {
            return Result::IdentityChanged;
        }
    }

    Session session;
    if (!session.establishOutbound(identity_, parsed)) {
        // The only failure establishOutbound() reports at this point is the
        // prekey signature.
        return Result::BadSignature;
    }

    std::memcpy(peer_identity_[peer].data(), parsed.identity_dh_pub, kKeySize);
    std::memcpy(peer_identity_[peer].data() + kKeySize, parsed.identity_sign_pub, 32);
    sessions_[peer] = std::move(session);
    return Result::Ok;
}

Engine::Result Engine::establishInbound(const std::string& peer, const PreKeyHeader& header) {
    Session session;
    if (!session.establishInbound(identity_, prekeys_, header)) {
        return Result::BadSignature;
    }

    // Inbound learns the sender's whole identity from the header, including
    // the signing half, so both sides can compute the same safety number.
    auto known = peer_identity_.find(peer);
    if (known != peer_identity_.end()) {
        if (!constant_time_equal(known->second.data(), header.sender_identity_dh, kKeySize) ||
            (hasSignHalf(known->second) &&
             !constant_time_equal(known->second.data() + kKeySize,
                                  header.sender_identity_sign, 32))) {
            return Result::IdentityChanged;
        }
    }
    std::memcpy(peer_identity_[peer].data(), header.sender_identity_dh, kKeySize);
    std::memcpy(peer_identity_[peer].data() + kKeySize, header.sender_identity_sign, 32);
    sessions_[peer] = std::move(session);
    return Result::Ok;
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
    // The pinned identity is deliberately left in place: dropping a session
    // is not the same event as forgetting who the peer is, and clearing the
    // pin would let anyone re-bind the label afterwards.
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

    // The prekey header is deliberately *not* cleared here. The first frame
    // can be lost - the socket drops, the relay's outbox entry is acknowledged
    // away, or the peer process was restarted - and if the header went with it
    // the handshake could never be retried. It travels with every frame until
    // the peer answers, which is the signal that X3DH completed on both sides.
    return WireMessage::encode(*s, msg);
}

bool Engine::decrypt(const std::string& peer, const uint8_t* frame, size_t size, Bytes& out) {
    return decryptStatus(peer, frame, size, out) == Result::Ok;
}

Engine::Result Engine::decryptStatus(const std::string& peer, const uint8_t* frame,
                                     size_t size, Bytes& out) {
    bool has_prekey = false;
    PreKeyHeader prekey;
    RatchetMessage msg;
    if (!WireMessage::decode(frame, size, has_prekey, prekey, msg)) return Result::BadBundle;

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
        if (!has_prekey) return Result::NoSession;

        Result established = establishInbound(peer, prekey);
        if (established != Result::Ok) return established;
        s = findSession(peer);
        if (s == nullptr) return Result::NoSession;
    }

    Session::DecryptResult r =
        s->decryptDetailed(msg, prekey_aad.data(), prekey_aad.size(), out);
    if (r != Session::DecryptOk) {
        // A duplicated delivery is a normal event - the relay is
        // at-least-once, so one frame can arrive live and again from the
        // outbox - and must not be reported as tampering. A frame that fails
        // on a counter we have not consumed is the real failure.
        switch (r) {
            case Session::DecryptDuplicate:  return Result::Duplicate;
            case Session::DecryptTooFarAhead: return Result::BadSignature;
            case Session::DecryptAuthFailed:  return Result::AuthFailed;
            default:                          return Result::AuthFailed;
        }
    }

    // A frame that authenticated proves the peer holds this session. Once it
    // arrives *without* a prekey header, the peer has already completed X3DH
    // from its side, so those parameters no longer need to travel and sending
    // can drop to plain ratchet frames.
    //
    // Keeping them until that moment - rather than dropping them after the
    // first send - means a first frame lost to a dropped socket or a discarded
    // outbox entry is retried instead of orphaning the session forever.
    if (!has_prekey && s->hasPendingPreKeyHeader()) s->clearPendingPreKeyHeader();

    return Result::Ok;
}

Engine::SessionState Engine::sessionState(const std::string& peer) const {
    if (findSession(peer) != nullptr) return Ready;
    if (peer_identity_.find(peer) != peer_identity_.end()) return PinnedOnly;
    return NoPeer;
}

Bytes Engine::peerIdentity(const std::string& peer) const {
    auto it = peer_identity_.find(peer);
    if (it == peer_identity_.end()) return {};
    return Bytes(it->second.begin(), it->second.end());
}

// ---- Pinned identity registry -----------------------------------------

Bytes Engine::exportPeerRegistry() const {
    Bytes out;
    out.reserve(4 + peer_identity_.size() * (4 + 32 + kIdentitySize));

    uint8_t buf[4];
    put_u32(buf, static_cast<uint32_t>(peer_identity_.size()));
    out.insert(out.end(), buf, buf + 4);

    for (const auto& [peer, identity] : peer_identity_) {
        put_u32(buf, static_cast<uint32_t>(peer.size()));
        out.insert(out.end(), buf, buf + 4);
        out.insert(out.end(), peer.begin(), peer.end());
        out.insert(out.end(), identity.begin(), identity.end());
    }
    return out;
}

bool Engine::importPeerRegistry(const uint8_t* data, size_t size) {
    if (data == nullptr || size < 4) return false;

    size_t off = 0;
    const uint32_t count = get_u32(data + off);
    off += 4;

    // Every entry is at least 4 + 1 + 64 bytes, so a count that could not fit
    // in the remaining bytes is malformed rather than merely large.
    if (static_cast<size_t>(count) > (size - off) / (4 + kIdentitySize)) return false;

    std::map<std::string, std::array<uint8_t, kIdentitySize>> loaded;
    for (uint32_t i = 0; i < count; ++i) {
        if (size < off + 4) return false;
        const uint32_t id_len = get_u32(data + off);
        off += 4;
        if (id_len == 0 || id_len > 128) return false;
        if (size < off + id_len + kIdentitySize) return false;

        std::string peer(reinterpret_cast<const char*>(data + off), id_len);
        off += id_len;

        std::array<uint8_t, kIdentitySize> identity{};
        std::memcpy(identity.data(), data + off, kIdentitySize);
        off += kIdentitySize;
        loaded[peer] = identity;
    }

    peer_identity_ = std::move(loaded);
    return true;
}

// ---- Safety number -----------------------------------------------------

std::string Engine::safetyNumber(const std::string& peer) const {
    auto it = peer_identity_.find(peer);
    if (it == peer_identity_.end()) return {};

    // Both halves of each identity go in: the DH key that X3DH runs against
    // and the signing key that authenticates prekeys. Hashing only the DH half
    // would let a relay swap the signing key - and therefore sign prekeys of
    // its choosing - while the 25 digits the user compares stayed identical.
    //
    // Canonical ordering is on the DH half, which is unique per identity.
    const uint8_t* mine = identity_.dh_pub;
    const uint8_t* theirs = it->second.data();

    const bool mine_first = std::memcmp(mine, theirs, kKeySize) <= 0;
    uint8_t buf[kIdentitySize * 2];
    if (mine_first) {
        std::memcpy(buf, mine, kKeySize);
        std::memcpy(buf + kKeySize, identity_.sign_pub, 32);
        std::memcpy(buf + kIdentitySize, theirs, kIdentitySize);
    } else {
        std::memcpy(buf, theirs, kIdentitySize);
        std::memcpy(buf + kIdentitySize, mine, kKeySize);
        std::memcpy(buf + kIdentitySize + kKeySize, identity_.sign_pub, 32);
    }

    uint8_t digest[32];
    crypto::blake2b(digest, sizeof(digest), buf, sizeof(buf));
    veil::wipe(buf, sizeof(buf));

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

// ---- Multi-device ------------------------------------------------------
//
// The account layer over the per-device sessions below it. Nothing in the
// ratchet changed: a device session is an ordinary session whose label happens
// to be "<user>#<device>".

namespace {

std::string hex(const uint8_t* data, size_t size) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        out.push_back(kHex[data[i] >> 4]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

bool fromHex(const std::string& text, uint8_t* out, size_t size) {
    if (text.size() != size * 2) return false;
    for (size_t i = 0; i < size; ++i) {
        const char hi = text[i * 2];
        const char lo = text[i * 2 + 1];
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        const int h = nibble(hi);
        const int l = nibble(lo);
        if (h < 0 || l < 0) return false;
        out[i] = static_cast<uint8_t>((h << 4) | l);
    }
    return true;
}

}  // namespace

std::string Engine::deviceLabel(const std::string& user_id,
                                const std::string& device_id_hex) {
    // '#' cannot appear in a user id (the relay rejects it) and is not a hex
    // digit, so the label splits unambiguously.
    return user_id + "#" + device_id_hex;
}

std::string Engine::accountLabel(const std::string& user_id) const {
    // A peer with no published device list is addressed by its bare user id,
    // which is exactly the single-device behaviour that existed before. A relay
    // that has not been upgraded, and a peer that never linked a second device,
    // both keep working without a migration.
    return user_id;
}

bool Engine::initDevice(const std::string& user_id) {
    if (user_id.empty() || user_id.size() > 128) return false;
    // '#' is the label separator, so it cannot appear in a user id.
    if (user_id.find('#') != std::string::npos) return false;

    user_id_ = user_id;
    has_device_ = true;

    // The device gets its own key pair. On the first device of an account these
    // are the account keys, so the account is its own device and no linking
    // flow is needed to get started.
    //
    // A *linked* device calls adoptDeviceCredential instead and keeps the key
    // pair it generated for itself.
    if (!has_device_keys_) {
        if (!generateDeviceId(device_id_)) return false;

        if (!crypto::x25519_generate(device_dh_pub_, device_dh_priv_)) return false;

        uint8_t seed[32];
        crypto::blake2b(seed, sizeof(seed), device_id_, kDeviceIdSize);
        crypto::ed25519_keypair(device_sign_pub_, device_sign_priv_, seed);
        veil::wipe(seed, sizeof(seed));
        has_device_keys_ = true;
    }

    DeviceCredential cred;
    if (!DeviceCredential::create(cred, user_id_, device_id_,
                                  device_dh_pub_, device_dh_priv_,
                                  device_sign_pub_, device_sign_priv_,
                                  static_cast<uint64_t>(std::time(nullptr)))) {
        return false;
    }
    if (!cred.signBy(identity_)) return false;
    own_credential_ = cred;
    has_own_credential_ = true;
    return true;
}

Bytes Engine::ownDeviceId() const {
    if (!has_device_) return {};
    return Bytes(device_id_, device_id_ + kDeviceIdSize);
}

Bytes Engine::ownDeviceCredential() const {
    if (!has_own_credential_) return {};
    return own_credential_.serialize();
}

bool Engine::adoptDeviceCredential(const uint8_t* data, size_t size,
                                   const uint8_t account_dh_pub[kKeySize],
                                   const uint8_t account_sign_pub[32]) {
    DeviceCredential cred;
    if (!DeviceCredential::deserialize(cred, data, size)) return false;

    // The endorsement must be this account's, and the credential must describe
    // *this* device's keys: adopting somebody else's credential would be a
    // different kind of failure entirely.
    if (!cred.verify(account_dh_pub, account_sign_pub)) return false;
    if (!has_device_keys_) return false;
    if (!constant_time_equal(cred.device_dh_pub, device_dh_pub_, kKeySize)) return false;
    if (!constant_time_equal(cred.device_sign_pub, device_sign_pub_, 32)) return false;

    user_id_ = cred.user_id;
    std::memcpy(device_id_, cred.device_id, kDeviceIdSize);
    has_device_ = true;
    own_credential_ = cred;
    has_own_credential_ = true;
    return true;
}

Engine::Result Engine::adoptDeviceList(const std::string& user_id,
                                       uint32_t version,
                                       const uint8_t* data, size_t size,
                                       const uint8_t account_dh_pub[kKeySize],
                                       const uint8_t account_sign_pub[32]) {
    if (user_id.empty()) return Result::BadBundle;
    if (data == nullptr || size < 4) return Result::BadBundle;

    // Rolling back to a list that still contains a removed device is the one
    // attack a version guard stops cheaply.
    auto existing = peer_devices_.find(user_id);
    if (existing != peer_devices_.end() && version <= existing->second.version) {
        // Not an error: a relay echoing an older list is stale, and the caller
        // already has something at least as new.
        return Result::Ok;
    }

    size_t off = 0;
    const uint32_t count = get_u32(data + off);
    off += 4;

    // Validate everything before mutating anything: a list in which one entry
    // fails is refused whole, because a partially trusted list is worse than a
    // stale one.
    PeerDevices parsed;
    parsed.version = version;
    parsed.devices.reserve(count);

    for (uint32_t i = 0; i < count; ++i) {
        DeviceCredential cred;
        if (!DeviceCredential::deserialize(cred, data + off, size - off)) {
            return Result::BadBundle;
        }
        const Bytes entry = cred.serialize();
        off += entry.size();

        if (cred.user_id != user_id) return Result::BadSignature;
        if (!cred.verify(account_dh_pub, account_sign_pub)) return Result::BadSignature;

        parsed.devices.push_back(cred);
    }

    // The account identity this list belongs to is now known, so the safety
    // number can be computed before any session exists.
    std::memcpy(peer_identity_[user_id].data(), account_dh_pub, kKeySize);
    std::memcpy(peer_identity_[user_id].data() + kKeySize, account_sign_pub, 32);

    peer_devices_[user_id] = std::move(parsed);
    return Result::Ok;
}

std::vector<std::string> Engine::peerDevices(const std::string& user_id) const {
    std::vector<std::string> out;
    auto it = peer_devices_.find(user_id);
    if (it == peer_devices_.end()) return out;

    out.reserve(it->second.devices.size());
    for (const auto& cred : it->second.devices) {
        out.push_back(hex(cred.device_id, kDeviceIdSize));
    }
    return out;
}

uint32_t Engine::peerDeviceVersion(const std::string& user_id) const {
    auto it = peer_devices_.find(user_id);
    return it == peer_devices_.end() ? 0 : it->second.version;
}

size_t Engine::establishWithDevices(const std::string& user_id,
                                    const std::vector<DeviceBundle>& bundles,
                                    std::vector<std::string>& out_failed) {
    out_failed.clear();
    if (bundles.empty()) return 0;

    // A caller that has not adopted a device list is talking to a peer that has
    // not published one. Address it by its bare label, and every bundle is for
    // that single peer.
    const bool multi = peer_devices_.find(user_id) != peer_devices_.end();

    size_t established = 0;
    for (const auto& item : bundles) {
        const std::string label = multi ? deviceLabel(user_id, item.device_id) : user_id;

        if (findSession(label) == nullptr) {
            const Result r = establishOutboundStatus(label, item.bundle.data(),
                                                     item.bundle.size());
            if (r != Result::Ok) {
                out_failed.push_back(item.device_id);
                continue;
            }
        }
        ++established;
    }
    return established;
}

std::vector<Engine::DeviceFrame> Engine::encryptToAccount(const std::string& user_id,
                                                          const uint8_t* plain,
                                                          size_t size) {
    std::vector<DeviceFrame> out;

    auto list = peer_devices_.find(user_id);
    if (list == peer_devices_.end()) {
        // Single-device peer, or a peer whose list has not been fetched. One
        // frame, exactly as before.
        Bytes frame = encrypt(user_id, plain, size);
        if (!frame.empty()) out.push_back({std::string(), std::move(frame)});
        return out;
    }

    for (const auto& cred : list->second.devices) {
        const std::string device_hex = hex(cred.device_id, kDeviceIdSize);
        const std::string label = deviceLabel(user_id, device_hex);

        // A device with no session is skipped rather than treated as an error:
        // a peer's laptop may not have been online since the last handshake, and
        // failing the whole send would make one stale device block the account.
        if (findSession(label) == nullptr) continue;

        Bytes frame = encrypt(label, plain, size);
        if (!frame.empty()) out.push_back({device_hex, std::move(frame)});
    }
    return out;
}

}  // namespace veil
