#include "veil/engine.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>

#include "veil/crypto.h"
#include "veil/random.h"

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

bool fromHex(const std::string& text, uint8_t* out, size_t size) {    if (text.size() != size * 2) return false;
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

// Serialisation helpers for the persistence blobs. Local to this file because
// they are the only readers and writers of those layouts, and a shared helper
// would invite a second caller to depend on a format that is allowed to change.
namespace {

void put_u32_append(Bytes& out, uint32_t value) {
    uint8_t num[4];
    put_u32(num, value);
    out.insert(out.end(), num, num + 4);
}

void put_string(Bytes& out, const std::string& text) {
    put_u32_append(out, static_cast<uint32_t>(text.size()));
    out.insert(out.end(), text.begin(), text.end());
}

bool get_string(std::string& out, const uint8_t* data, size_t size, size_t& off) {
    if (size - off < 4) return false;
    const uint32_t len = get_u32(data + off);
    off += 4;
    // Subtraction rather than addition, so the comparison cannot overflow.
    if (static_cast<size_t>(len) > size - off) return false;
    out.assign(reinterpret_cast<const char*>(data + off), len);
    off += len;
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

    // The list is fresh as of now. recorded here rather than by the caller so
    // there is no way to adopt a list and forget to say when.
    peer_devices_[user_id].refreshed_at = now_ms_;
    peer_devices_[user_id].needs_refresh = false;
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

// ---- Device list freshness --------------------------------------------

void Engine::setClock(uint64_t now_ms) {
    now_ms_ = now_ms;
}

void Engine::noteSendFailed(const std::string& user_id) {
    auto it = peer_devices_.find(user_id);
    if (it == peer_devices_.end()) return;

    // Only an existing list is marked. A peer with no list is already handled by
    // RefreshUnknown, and creating an entry here would pretend a list was known.
    it->second.needs_refresh = true;
}

void Engine::noteDeviceListFetched(const std::string& user_id) {
    auto it = peer_devices_.find(user_id);
    if (it == peer_devices_.end()) return;

    it->second.needs_refresh = false;
    it->second.refreshed_at = now_ms_;
}

Engine::RefreshReason Engine::deviceListNeedsRefresh(const std::string& user_id,
                                                     uint64_t staleness_ms) const {
    auto it = peer_devices_.find(user_id);
    if (it == peer_devices_.end()) {
        // No list held. The caller may not need one - a single-device peer works
        // without - but "unknown" is the honest answer, and it is up to the client
        // whether to act on it.
        return RefreshUnknown;
    }

    // A send that could not reach a device outranks staleness: it is evidence,
    // where staleness is only a guess.
    if (it->second.needs_refresh) return RefreshSendFailed;

    if (now_ms_ == 0 || it->second.refreshed_at == 0) {
        // No clock has been supplied, so nothing can be called stale. Reporting
        // None here is deliberate: a client that never sets a clock gets "refresh
        // only when a send fails", which is a working policy rather than a wrong
        // one.
        return RefreshNone;
    }

    // Guards against a clock that went backwards (a wall clock adjusted by NTP),
    // which would otherwise report a huge staleness for a list fetched a second
    // ago.
    if (now_ms_ < it->second.refreshed_at) return RefreshNone;

    if (now_ms_ - it->second.refreshed_at >= staleness_ms) return RefreshStale;
    return RefreshNone;
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
        //
        // It is also recorded: a list that names a device this client cannot
        // reach is exactly the list worth re-fetching, because the most likely
        // reason is that the device was linked after the list was cached.
        if (findSession(label) == nullptr) {
            list->second.needs_refresh = true;
            continue;
        }

        Bytes frame = encrypt(label, plain, size);
        if (!frame.empty()) out.push_back({device_hex, std::move(frame)});
    }
    return out;
}

// ---- Groups ------------------------------------------------------------

bool Engine::createGroup(const std::string& group_id) {
    if (group_id.empty() || group_id.size() > 128) return false;
    if (groups_.find(group_id) != groups_.end()) return false;
    if (user_id_.empty()) return false;  // a group needs a founder

    GroupState state;
    state.membership.group_id = group_id;
    state.membership.founder = user_id_;
    state.membership.epoch = 1;
    state.membership.members = {user_id_};

    const Bytes payload = state.membership.signedPayload();
    crypto::ed25519_sign(state.membership.signature, identity_.sign_priv,
                         payload.data(), payload.size());

    groups_[group_id] = std::move(state);
    return true;
}

bool Engine::rotateGroupChain(const std::string& group_id, GroupState& state) {
    // A fresh chain key per epoch, derived from the identity secret and the
    // group/epoch pair so it is reproducible for this device and unforgeable for
    // anybody else.
    //
    // A removed member holds the previous chain key but not this derivation
    // input, which is what makes rotation actually cut them off.
    uint8_t seed[32];
    const std::string material = "Veil/group-epoch/v1|" + group_id + "|" +
                                 std::to_string(state.membership.epoch);
    crypto::hkdf(seed, sizeof(seed),
                 identity_.dh_priv, kKeySize,
                 reinterpret_cast<const uint8_t*>(material.data()), material.size(),
                 nullptr, 0);

    state.outgoing.epoch = state.membership.epoch;
    state.outgoing.iteration = 0;
    std::memcpy(state.outgoing.chain_key.data(), seed, 32);
    state.outgoing.skipped.clear();
    state.has_outgoing = true;

    veil::wipe(seed, sizeof(seed));
    return true;
}

uint32_t Engine::setGroupMembers(const std::string& group_id,
                                 const std::vector<std::string>& members) {
    auto it = groups_.find(group_id);
    if (it == groups_.end()) return 0;
    if (members.empty()) return 0;

    // Only the founder may change the list, because only the founder can produce
    // a signature the others will accept.
    if (it->second.membership.founder != user_id_) return 0;

    GroupState& state = it->second;
    state.membership.members = members;
    state.membership.epoch += 1;

    const Bytes payload = state.membership.signedPayload();
    crypto::ed25519_sign(state.membership.signature, identity_.sign_priv,
                         payload.data(), payload.size());

    // Every chain is discarded, including our own: the epoch moved, and a chain
    // from the old epoch is readable by whoever was just removed.
    state.has_outgoing = false;
    state.outgoing = GroupChain{};
    state.incoming.clear();

    rotateGroupChain(group_id, state);
    return state.membership.epoch;
}

uint32_t Engine::groupEpoch(const std::string& group_id) const {
    auto it = groups_.find(group_id);
    return it == groups_.end() ? 0 : it->second.membership.epoch;
}

std::vector<std::string> Engine::groupMembers(const std::string& group_id) const {
    auto it = groups_.find(group_id);
    return it == groups_.end() ? std::vector<std::string>{}
                               : it->second.membership.members;
}

bool Engine::isGroupMember(const std::string& group_id) const {
    auto it = groups_.find(group_id);
    if (it == groups_.end()) return false;
    const auto& members = it->second.membership.members;
    return std::find(members.begin(), members.end(), user_id_) != members.end();
}

Bytes Engine::exportMembership(const std::string& group_id) const {
    auto it = groups_.find(group_id);
    if (it == groups_.end()) return {};
    return it->second.membership.signedPayload();
}

Engine::Result Engine::adoptMembership(const uint8_t* data, size_t size,
                                       const uint8_t founder_sign_pub[32]) {
    if (data == nullptr || size < 8) return Result::BadBundle;

    // Parse the payload the founder signed.
    //
    // The layout mirrors GroupMembership::signedPayload(), and is parsed here
    // rather than in a free function because the result has to be checked
    // against state this engine holds.
    size_t off = 0;
    const char domain[] = "Veil/group-membership/v1";
    const size_t domain_len = sizeof(domain) - 1;
    if (size < domain_len + 8) return Result::BadBundle;
    if (std::memcmp(data, domain, domain_len) != 0) return Result::BadBundle;
    off += domain_len;

    auto readString = [&](std::string& out) -> bool {
        if (size - off < 2) return false;
        const size_t len = (static_cast<size_t>(data[off]) << 8) | data[off + 1];
        off += 2;
        if (size - off < len) return false;
        out.assign(reinterpret_cast<const char*>(data + off), len);
        off += len;
        return true;
    };

    GroupMembership parsed;
    if (!readString(parsed.group_id)) return Result::BadBundle;
    if (!readString(parsed.founder)) return Result::BadBundle;
    if (size - off < 4) return Result::BadBundle;
    parsed.epoch = get_u32(data + off); off += 4;
    if (parsed.epoch == 0) return Result::BadBundle;

    if (size - off < 4) return Result::BadBundle;
    const uint32_t count = get_u32(data + off); off += 4;
    if (count == 0 || count > 256) return Result::BadBundle;

    for (uint32_t i = 0; i < count; ++i) {
        std::string member;
        if (!readString(member)) return Result::BadBundle;
        parsed.members.push_back(member);
    }

    // The founder is the authority on who is in the group. A record claiming a
    // different founder than one already held is a different group wearing the
    // same name.
    auto existing = groups_.find(parsed.group_id);
    if (existing != groups_.end() && existing->second.has_founder_key) {
        if (!constant_time_equal(existing->second.founder_sign_pub.data(),
                                 founder_sign_pub, 32)) {
            return Result::IdentityChanged;
        }
        // Rolling back to an epoch that still contains a removed member is the
        // one attack a version guard stops cheaply.
        if (parsed.epoch <= existing->second.membership.epoch) {
            return Result::Ok;  // stale, not an error
        }
    }

    GroupState state;
    state.membership = parsed;
    state.has_founder_key = true;
    std::memcpy(state.founder_sign_pub.data(), founder_sign_pub, 32);
    groups_[parsed.group_id] = std::move(state);
    return Result::Ok;
}

Bytes Engine::exportSenderKey(const std::string& group_id, uint32_t epoch) const {
    auto it = groups_.find(group_id);
    if (it == groups_.end() || !it->second.has_outgoing) return {};
    if (epoch != 0 && epoch != it->second.membership.epoch) return {};

    const GroupChain& chain = it->second.outgoing;

    Bytes out;
    out.reserve(2 + user_id_.size() + 4 + 4 + 32 + kSigSize);

    out.push_back(static_cast<uint8_t>((user_id_.size() >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(user_id_.size() & 0xFF));
    out.insert(out.end(), user_id_.begin(), user_id_.end());

    uint8_t num[4];
    put_u32(num, chain.epoch);
    out.insert(out.end(), num, num + 4);
    put_u32(num, chain.iteration);
    out.insert(out.end(), num, num + 4);
    out.insert(out.end(), chain.chain_key.begin(), chain.chain_key.end());

    // Signed with this device's key, so a relay forwarding the chain cannot
    // substitute one of its own.
    const uint8_t* sign_key = has_device_keys_ ? device_sign_priv_ : identity_.sign_priv;
    uint8_t sig[kSigSize];
    crypto::ed25519_sign(sig, sign_key, out.data(), out.size());
    out.insert(out.end(), sig, sig + kSigSize);
    veil::wipe(sig, sizeof(sig));
    return out;
}

Engine::Result Engine::adoptSenderKey(const uint8_t* data, size_t size,
                                      const std::string& expected_sender,
                                      const uint8_t sender_sign_pub[32]) {
    if (data == nullptr || size < 2 + 8 + 32 + kSigSize) return Result::BadBundle;

    size_t off = 0;
    const size_t id_len = (static_cast<size_t>(data[off]) << 8) | data[off + 1];
    off += 2;
    if (id_len == 0 || size - off < id_len + 8 + 32 + kSigSize) return Result::BadBundle;

    const std::string sender(reinterpret_cast<const char*>(data + off), id_len);
    off += id_len;

    if (sender != expected_sender) return Result::IdentityChanged;

    const uint32_t epoch = get_u32(data + off); off += 4;
    const uint32_t iteration = get_u32(data + off); off += 4;

    std::array<uint8_t, 32> chain_key{};
    std::memcpy(chain_key.data(), data + off, 32); off += 32;

    // The signature covers everything before it.
    const size_t signed_len = off;
    if (!crypto::ed25519_verify(data + off, sender_sign_pub, data, signed_len)) {
        veil::wipe(chain_key.data(), chain_key.size());
        return Result::BadSignature;
    }

    // A chain for an epoch at or below one already held from this sender is a
    // re-publish of an older chain, which is what a rotated-out member would
    // try. Refuse it.
    for (auto& [group_id, state] : groups_) {
        auto incoming = state.incoming.find(sender);
        if (incoming == state.incoming.end()) continue;
        if (incoming->second.epoch >= epoch) return Result::Duplicate;
    }

    // Install into every group where this sender is a member. A sender key is
    // per membership, and the caller does not have to name the group because the
    // epoch and the member list already pin it down.
    bool installed = false;
    for (auto& [group_id, state] : groups_) {
        const auto& members = state.membership.members;
        if (std::find(members.begin(), members.end(), sender) == members.end()) continue;
        if (state.membership.epoch != epoch) continue;

        GroupChain chain;
        chain.epoch = epoch;
        chain.iteration = iteration;
        chain.chain_key = chain_key;
        state.incoming[sender] = chain;
        installed = true;
    }

    veil::wipe(chain_key.data(), chain_key.size());
    return installed ? Result::Ok : Result::NoSession;
}

bool Engine::encryptToGroup(const std::string& group_id,
                            const uint8_t* plain, size_t size,
                            GroupMessage& out) {
    auto it = groups_.find(group_id);
    if (it == groups_.end() || !it->second.has_outgoing) return false;
    if (!isGroupMember(group_id)) return false;

    GroupState& state = it->second;
    if (state.outgoing.epoch != state.membership.epoch) return false;

    // One key per message, advanced on the sending chain.
    std::array<uint8_t, 32> message_key{};
    std::array<uint8_t, 32> next_chain{};
    groupChainStep(state.outgoing.chain_key, next_chain, message_key);

    const uint32_t iteration = state.outgoing.iteration;
    state.outgoing.chain_key = next_chain;
    state.outgoing.iteration += 1;

    uint8_t enc_key[32];
    uint8_t nonce[kNonceSize];
    groupMessageMaterial(message_key, enc_key, nonce);

    const Bytes aad = groupAssociatedData(user_id_, state.membership.epoch, iteration);

    out.sender_id = user_id_;
    out.epoch = state.membership.epoch;
    out.iteration = iteration;
    out.ciphertext.assign(size + kMacSize, 0);

    crypto::aead_encrypt(out.ciphertext.data(), out.ciphertext.data() + size,
                         enc_key, nonce, aad.data(), aad.size(), plain, size);

    veil::wipe(message_key.data(), message_key.size());
    veil::wipe(enc_key, sizeof(enc_key));
    veil::wipe(nonce, sizeof(nonce));
    return true;
}

Engine::Result Engine::decryptFromGroup(const std::string& group_id,
                                        const GroupMessage& message,
                                        Bytes& out) {
    auto it = groups_.find(group_id);
    if (it == groups_.end()) return Result::NoSession;

    GroupState& state = it->second;

    if (message.epoch != state.membership.epoch) {
        // A message from an epoch we have moved past is unreadable by design:
        // the sender was rotated out, or we were.
        return Result::Duplicate;
    }

    auto chain_it = state.incoming.find(message.sender_id);
    if (chain_it == state.incoming.end()) return Result::NoSession;

    std::array<uint8_t, 32> message_key{};
    if (!chain_it->second.keyFor(message.iteration, message_key)) {
        return Result::Duplicate;
    }

    uint8_t enc_key[32];
    uint8_t nonce[kNonceSize];
    groupMessageMaterial(message_key, enc_key, nonce);

    const Bytes aad = groupAssociatedData(message.sender_id, message.epoch,
                                          message.iteration);

    const size_t text_size = message.ciphertext.size() - kMacSize;
    Bytes plain(text_size);

    const bool ok = crypto::aead_decrypt(plain.data(),
                                         message.ciphertext.data() + text_size,
                                         enc_key, nonce,
                                         aad.data(), aad.size(),
                                         message.ciphertext.data(), text_size);

    veil::wipe(message_key.data(), message_key.size());
    veil::wipe(enc_key, sizeof(enc_key));
    veil::wipe(nonce, sizeof(nonce));

    if (!ok) return Result::AuthFailed;
    out = std::move(plain);
    return Result::Ok;
}

// ---- Device linking ----------------------------------------------------
//
// The request carries public halves only. Its nonce is what makes a captured
// request useless later: an endorsement is for one request, and a replay of an
// old request would produce a credential the new device cannot use, because the
// keys in it are the ones the request named.

namespace {

constexpr char kLinkingDomain[] = "Veil/linking-request/v1";

}  // namespace

Bytes Engine::accountSignPublic() const {
    return Bytes(identity_.sign_pub, identity_.sign_pub + 32);
}

bool Engine::peerDeviceSignPublic(const std::string& peer, uint8_t out[32]) const {
    if (out == nullptr) return false;

    // Talking to yourself: the key is this device's own.
    if (has_device_keys_ && peer == user_id_) {
        std::memcpy(out, device_sign_pub_, 32);
        return true;
    }

    // A device-scoped label ("bob#<hex>") names a credential directly.
    const auto hash = peer.find('#');
    if (hash != std::string::npos) {
        const std::string account = peer.substr(0, hash);
        const std::string device_hex = peer.substr(hash + 1);

        auto devices = peer_devices_.find(account);
        if (devices == peer_devices_.end()) return false;

        for (const auto& cred : devices->second.devices) {
            if (hex(cred.device_id, kDeviceIdSize) != device_hex) continue;
            std::memcpy(out, cred.device_sign_pub, 32);
            return true;
        }
        return false;
    }

    // An account-scoped label: only unambiguous when that account has exactly one
    // device. With two, "which one invited me" is a real question and answering it
    // by picking the first would verify the invitation against the wrong key.
    auto devices = peer_devices_.find(peer);
    if (devices == peer_devices_.end() || devices->second.devices.size() != 1) {
        return false;
    }

    std::memcpy(out, devices->second.devices[0].device_sign_pub, 32);
    return true;
}

Bytes Engine::generateLinkingRequest() const {
    if (!has_device_keys_) return {};
    if (user_id_.empty()) return {};

    uint8_t nonce[32];
    if (!secure_random(nonce, sizeof(nonce))) return {};

    // The device's own endorsement of its DH key, which only it can produce.
    uint8_t binding[kBindingSize];
    crypto::ed25519_sign(binding, device_sign_priv_, device_dh_pub_, kKeySize);

    Bytes out;
    out.reserve(sizeof(kLinkingDomain) - 1 + 2 + user_id_.size() +
                kDeviceIdSize + kKeySize + 32 + kBindingSize + 32);

    out.insert(out.end(), kLinkingDomain, kLinkingDomain + sizeof(kLinkingDomain) - 1);

    out.push_back(static_cast<uint8_t>((user_id_.size() >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(user_id_.size() & 0xFF));
    out.insert(out.end(), user_id_.begin(), user_id_.end());

    out.insert(out.end(), device_id_, device_id_ + kDeviceIdSize);
    out.insert(out.end(), device_dh_pub_, device_dh_pub_ + kKeySize);
    out.insert(out.end(), device_sign_pub_, device_sign_pub_ + 32);
    out.insert(out.end(), binding, binding + kBindingSize);
    out.insert(out.end(), nonce, nonce + 32);

    veil::wipe(binding, sizeof(binding));
    return out;
}

std::string Engine::LinkingRequest::fingerprint() const {
    // The keys and the nonce, not the device id: the id is relay bookkeeping, and
    // including the nonce is what makes two requests from the same keys read
    // differently - so "approve this one" cannot be answered by approving the
    // previous one.
    static const char kDomain[] = "Veil/linking-fingerprint/v1";
    constexpr size_t kDomainLen = sizeof(kDomain) - 1;

    uint8_t buffer[kDomainLen + kKeySize + 32 + 32];
    std::memcpy(buffer, kDomain, kDomainLen);
    std::memcpy(buffer + kDomainLen, device_dh_pub, kKeySize);
    std::memcpy(buffer + kDomainLen + kKeySize, device_sign_pub, 32);
    std::memcpy(buffer + kDomainLen + kKeySize + 32, nonce, 32);

    uint8_t digest[32];
    crypto::blake2b(digest, sizeof(digest), buffer, sizeof(buffer));

    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(19);
    for (int group = 0; group < 4; ++group) {
        if (group != 0) out.push_back('-');
        for (int byte = 0; byte < 2; ++byte) {
            const uint8_t b = digest[group * 2 + byte];
            out.push_back(kHex[b >> 4]);
            out.push_back(kHex[b & 0x0F]);
        }
    }

    veil::wipe(buffer, sizeof(buffer));
    veil::wipe(digest, sizeof(digest));
    return out;
}

bool Engine::parseLinkingRequest(LinkingRequest& out, const uint8_t* data, size_t size) {
    if (data == nullptr) return false;

    const size_t domain_len = sizeof(kLinkingDomain) - 1;
    if (size < domain_len + 2) return false;
    if (std::memcmp(data, kLinkingDomain, domain_len) != 0) return false;

    size_t off = domain_len;

    const size_t id_len = (static_cast<size_t>(data[off]) << 8) | data[off + 1];
    off += 2;
    if (id_len == 0 || id_len > 128) return false;

    const size_t rest = kDeviceIdSize + kKeySize + 32 + kBindingSize + 32;
    if (size - off < id_len + rest) return false;

    out.user_id.assign(reinterpret_cast<const char*>(data + off), id_len);
    off += id_len;

    std::memcpy(out.device_id, data + off, kDeviceIdSize); off += kDeviceIdSize;
    std::memcpy(out.device_dh_pub, data + off, kKeySize); off += kKeySize;
    std::memcpy(out.device_sign_pub, data + off, 32); off += 32;
    std::memcpy(out.device_binding, data + off, kBindingSize); off += kBindingSize;
    std::memcpy(out.nonce, data + off, 32);

    // One trailing-byte check: a request with extra data is not this request.
    return off + 32 == size;
}

Bytes Engine::approveLinking(const LinkingRequest& request, uint64_t issued_at) const {
    if (request.user_id.empty() || request.user_id.size() > 128) return {};

    // The device's self-binding came with the request: only the requesting device
    // holds the private key that produces it, so this engine cannot derive it and
    // must not pretend to. Copying it forward is what lets the resulting
    // credential verify as a whole.
    DeviceCredential signed_cred;
    signed_cred.user_id = request.user_id;
    std::memcpy(signed_cred.device_id, request.device_id, kDeviceIdSize);
    std::memcpy(signed_cred.device_dh_pub, request.device_dh_pub, kKeySize);
    std::memcpy(signed_cred.device_sign_pub, request.device_sign_pub, 32);
    signed_cred.issued_at = issued_at;
    std::memcpy(signed_cred.device_binding, request.device_binding, kBindingSize);
    std::memset(signed_cred.account_signature, 0, kSigSize);

    if (!signed_cred.signBy(identity_)) return {};

    return signed_cred.serialize();
}

// ---- Group invitations -------------------------------------------------
//
// The payload, after the prefix:
//
//   [4] group id length | group id
//   [4] membership length | membership (the founder's signed record)
//   [4] chain length | chain (the founder's sender key for that epoch)
//
// Both inner blobs are exactly what exportMembership and exportSenderKey
// produce, so an invitation cannot drift from what those two formats are: it
// carries them, it does not re-encode them.

Bytes Engine::encodeInvite(const std::string& group_id) const {
    auto it = groups_.find(group_id);
    if (it == groups_.end()) return {};

    const Bytes membership = exportMembership(group_id);
    if (membership.empty()) return {};

    // The founder's own chain for the current epoch. Without it the invitee can
    // verify who is in the group but cannot read a single message, which makes
    // the invitation useless until a second round trip completes.
    const Bytes chain = exportSenderKey(group_id, it->second.membership.epoch);
    if (chain.empty()) return {};

    Bytes out;
    out.reserve(kInvitePrefixSize + 12 + group_id.size() + membership.size() + chain.size());

    out.insert(out.end(), kInvitePrefix, kInvitePrefix + kInvitePrefixSize);

    auto putBlob = [&out](const Bytes& blob) {
        uint8_t num[4];
        put_u32(num, static_cast<uint32_t>(blob.size()));
        out.insert(out.end(), num, num + 4);
        out.insert(out.end(), blob.begin(), blob.end());
    };

    Bytes id_bytes(group_id.begin(), group_id.end());
    putBlob(id_bytes);
    putBlob(membership);
    putBlob(chain);
    return out;
}

bool Engine::looksLikeInvite(const uint8_t* data, size_t size) {
    if (data == nullptr || size < kInvitePrefixSize) return false;
    return std::memcmp(data, kInvitePrefix, kInvitePrefixSize) == 0;
}

Engine::Result Engine::acceptInvite(const uint8_t* data, size_t size,
                                    const std::string& expected_founder,
                                    const uint8_t founder_sign_pub[32],
                                    std::string& out_group_id) {
    out_group_id.clear();
    if (data == nullptr || size < kInvitePrefixSize + 12) return Result::BadBundle;
    if (!looksLikeInvite(data, size)) return Result::BadBundle;

    size_t off = kInvitePrefixSize;

    auto readBlob = [&](Bytes& out) -> bool {
        if (size - off < 4) return false;
        const uint32_t len = get_u32(data + off);
        off += 4;
        if (static_cast<size_t>(len) > size - off) return false;
        out.assign(data + off, data + off + len);
        off += len;
        return true;
    };

    Bytes id_bytes, membership, chain;
    if (!readBlob(id_bytes)) return Result::BadBundle;
    if (!readBlob(membership)) return Result::BadBundle;
    if (!readBlob(chain)) return Result::BadBundle;

    if (id_bytes.empty() || id_bytes.size() > 128) return Result::BadBundle;
    const std::string group_id(id_bytes.begin(), id_bytes.end());

    // The member list first: it establishes the group and its epoch, which the
    // chain is then matched against.
    const Result adopted = adoptMembership(membership.data(), membership.size(),
                                           founder_sign_pub);
    if (adopted != Result::Ok) return adopted;

    // Then the founder's chain, verified with the same device key the founder's
    // credential carries.
    const Result chained = adoptSenderKey(chain.data(), chain.size(),
                                          expected_founder, founder_sign_pub);
    if (chained != Result::Ok && chained != Result::Duplicate) return chained;

    // Only now is the group usable. Reaching this point means the member list
    // verified, so "the founder said so" is established rather than assumed.
    if (groups_.find(group_id) == groups_.end()) return Result::NoSession;

    out_group_id = group_id;
    return Result::Ok;
}

// ---- Group persistence -------------------------------------------------

Bytes Engine::exportGroupState() const {
    Bytes out;
    put_u32_append(out, static_cast<uint32_t>(groups_.size()));

    for (const auto& [group_id, state] : groups_) {
        put_string(out, group_id);

        const auto& m = state.membership;
        put_u32_append(out, m.epoch);

        // Members are written sorted so two exports of the same group produce
        // identical bytes; a caller comparing blobs for equality then gets a
        // meaningful answer.
        std::vector<std::string> members = m.members;
        std::sort(members.begin(), members.end());
        members.erase(std::unique(members.begin(), members.end()), members.end());

        put_u32_append(out, static_cast<uint32_t>(members.size()));
        for (const auto& member : members) put_string(out, member);

        put_string(out, m.founder);

        out.push_back(state.has_founder_key ? 1 : 0);
        if (state.has_founder_key) {
            out.insert(out.end(), state.founder_sign_pub.begin(),
                       state.founder_sign_pub.end());
        }
        out.insert(out.end(), m.signature, m.signature + kSigSize);

        out.push_back(state.has_outgoing ? 1 : 0);
        if (state.has_outgoing) {
            put_u32_append(out, state.outgoing.epoch);
            put_u32_append(out, state.outgoing.iteration);
            out.insert(out.end(), state.outgoing.chain_key.begin(),
                       state.outgoing.chain_key.end());
        }

        put_u32_append(out, static_cast<uint32_t>(state.incoming.size()));
        for (const auto& [sender, chain] : state.incoming) {
            put_string(out, sender);
            put_u32_append(out, chain.epoch);
            put_u32_append(out, chain.iteration);
            out.insert(out.end(), chain.chain_key.begin(), chain.chain_key.end());

            // Skipped keys are part of the state: dropping them would silently
            // make every message that is currently in flight permanently
            // unreadable after a restart.
            put_u32_append(out, static_cast<uint32_t>(chain.skipped.size()));
            for (const auto& [index, key] : chain.skipped) {
                put_u32_append(out, index);
                out.insert(out.end(), key.begin(), key.end());
            }
        }
    }
    return out;
}

bool Engine::importGroupState(const uint8_t* data, size_t size) {
    if (data == nullptr || size < 4) return false;

    size_t off = 0;
    const uint32_t count = get_u32(data + off);
    off += 4;

    // A count that could not possibly fit is malformed rather than merely large.
    if (static_cast<size_t>(count) > (size - off) / 8) return false;

    std::map<std::string, GroupState> loaded;

    for (uint32_t i = 0; i < count; ++i) {
        std::string group_id;
        if (!get_string(group_id, data, size, off)) return false;
        if (group_id.empty() || loaded.count(group_id) != 0) return false;

        GroupState state;
        if (size - off < 4) return false;
        state.membership.epoch = get_u32(data + off);
        off += 4;
        if (state.membership.epoch == 0) return false;
        state.membership.group_id = group_id;

        if (size - off < 4) return false;
        const uint32_t member_count = get_u32(data + off);
        off += 4;
        if (member_count == 0 || static_cast<size_t>(member_count) > (size - off) / 6) {
            return false;
        }
        for (uint32_t j = 0; j < member_count; ++j) {
            std::string member;
            if (!get_string(member, data, size, off)) return false;
            state.membership.members.push_back(std::move(member));
        }

        if (!get_string(state.membership.founder, data, size, off)) return false;

        if (size - off < 1) return false;
        const uint8_t has_key = data[off++];
        if (has_key > 1) return false;
        if (has_key == 1) {
            if (size - off < 32) return false;
            std::memcpy(state.founder_sign_pub.data(), data + off, 32);
            off += 32;
            state.has_founder_key = true;
        }

        if (size - off < kSigSize) return false;
        std::memcpy(state.membership.signature, data + off, kSigSize);
        off += kSigSize;

        if (size - off < 1) return false;
        const uint8_t has_out = data[off++];
        if (has_out > 1) return false;
        if (has_out == 1) {
            if (size - off < 40) return false;
            state.outgoing.epoch = get_u32(data + off); off += 4;
            state.outgoing.iteration = get_u32(data + off); off += 4;
            std::memcpy(state.outgoing.chain_key.data(), data + off, 32);
            off += 32;
            state.has_outgoing = true;
        }

        if (size - off < 4) return false;
        const uint32_t incoming_count = get_u32(data + off);
        off += 4;
        if (static_cast<size_t>(incoming_count) > (size - off) / 44) return false;

        for (uint32_t j = 0; j < incoming_count; ++j) {
            std::string sender;
            if (!get_string(sender, data, size, off)) return false;

            if (size - off < 40) return false;
            GroupChain chain;
            chain.epoch = get_u32(data + off); off += 4;
            chain.iteration = get_u32(data + off); off += 4;
            std::memcpy(chain.chain_key.data(), data + off, 32);
            off += 32;

            if (size - off < 4) return false;
            const uint32_t skipped_count = get_u32(data + off);
            off += 4;
            if (static_cast<size_t>(skipped_count) > kMaxSkippedGroupKeys) return false;
            if (static_cast<size_t>(skipped_count) > (size - off) / 36) return false;

            for (uint32_t k = 0; k < skipped_count; ++k) {
                if (size - off < 36) return false;
                const uint32_t index = get_u32(data + off); off += 4;
                std::array<uint8_t, 32> key{};
                std::memcpy(key.data(), data + off, 32);
                off += 32;
                chain.skipped[index] = key;
            }

            state.incoming[sender] = std::move(chain);
        }

        loaded[group_id] = std::move(state);
    }

    // Everything parsed before anything is replaced, so a malformed blob leaves
    // the live groups untouched rather than half-loaded.
    for (auto& [id, state] : groups_) {
        for (auto& [sender, chain] : state.incoming) {
            veil::wipe(chain.chain_key.data(), chain.chain_key.size());
            for (auto& [index, key] : chain.skipped) {
                veil::wipe(key.data(), key.size());
            }
        }
        if (state.has_outgoing) {
            veil::wipe(state.outgoing.chain_key.data(), state.outgoing.chain_key.size());
        }
    }

    groups_ = std::move(loaded);
    return true;
}

}  // namespace veil
