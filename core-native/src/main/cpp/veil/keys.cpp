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

void Identity::bindingSignature(uint8_t sig[kBindingSize]) const {
    crypto::ed25519_sign(sig, sign_priv, dh_pub, kKeySize);
}

bool Identity::verifyBinding(const uint8_t dh_pub[kKeySize],
                             const uint8_t sign_pub[32],
                             const uint8_t sig[kBindingSize]) {
    return crypto::ed25519_verify(sig, sign_pub, dh_pub, kKeySize);
}

void Identity::wipeSecrets() {
    veil::wipe(dh_priv, sizeof(dh_priv));
    veil::wipe(sign_priv, sizeof(sign_priv));
}

// ---- Signed prekey message ---------------------------------------------

size_t signedPreKeyMessage(uint8_t* out, size_t capacity,
                           const uint8_t identity_dh_pub[kKeySize],
                           const uint8_t signed_pub[kKeySize]) {
    const size_t domain_len = sizeof(kSignedPreKeyDomain) - 1;
    const size_t total = domain_len + kKeySize * 2;
    if (out == nullptr || capacity < total) return 0;

    std::memcpy(out, kSignedPreKeyDomain, domain_len);
    std::memcpy(out + domain_len, identity_dh_pub, kKeySize);
    std::memcpy(out + domain_len + kKeySize, signed_pub, kKeySize);
    return total;
}

bool verifySignedPreKey(const uint8_t identity_dh_pub[kKeySize],
                        const uint8_t identity_sign_pub[32],
                        const uint8_t signed_pub[kKeySize],
                        const uint8_t signature[kSigSize]) {
    uint8_t message[sizeof(kSignedPreKeyDomain) - 1 + kKeySize * 2];
    const size_t len = signedPreKeyMessage(message, sizeof(message),
                                          identity_dh_pub, signed_pub);
    if (len == 0) return false;
    return crypto::ed25519_verify(signature, identity_sign_pub, message, len);
}

bool PreKeys::rotate(const Identity& identity, uint32_t one_time_count) {
    // Retire the current signed prekey before generating a new one. A peer
    // that fetched the old bundle and only now sends its first message still
    // has to be able to run X3DH against the key it was handed, so the
    // previous private half stays decryptable until the next rotation.
    if (current.id != 0) {
        retired = current;
        has_retired = true;
    }

    // The id only ever moves forward. Reusing "1" with fresh keys made a stale
    // bundle indistinguishable from a current one, and let the relay overwrite
    // the prekey row under the same name.
    current.id = next_signed_id++;

    if (!crypto::x25519_generate(current.pub, current.priv)) return false;

    // The signature covers the identity's DH public key as well as the prekey
    // itself, so a relay cannot pair a victim's DH key with its own signing
    // key and then vouch for a prekey of its choosing.
    uint8_t message[sizeof(kSignedPreKeyDomain) - 1 + kKeySize * 2];
    const size_t len = signedPreKeyMessage(message, sizeof(message),
                                          identity.dh_pub, current.pub);
    if (len == 0) return false;
    crypto::ed25519_sign(current.signature, identity.sign_priv, message, len);
    veil::wipe(message, sizeof(message));

    // One-time prekeys live and die with their generation.
    //
    // A rotation used to append a fresh batch on top of the previous one, so a
    // device that rotated on a schedule accumulated private keys it could never
    // use, and the published set grew with every rotation.
    //
    // But the *retired* generation has to be kept, for the same reason the
    // retired signed prekey is: a peer that fetched the previous bundle just
    // before the rotation names one of its one-time keys in its first message,
    // and establishInbound() refuses a header it cannot match. So exactly two
    // generations survive - current and retired - and everything older is
    // wiped.
    {
        std::vector<OneTimePreKey> kept;
        kept.reserve(kTombstoneKeep + one_time_count);

        for (auto& ot : one_time) {
            // The generation an id belongs to is its signed prekey id.
            const uint32_t generation = ot.id / 1000u;
            const bool live = generation == current.id ||
                              (has_retired && generation == retired.id);
            if (!live) {
                veil::wipe(ot.priv, sizeof(ot.priv));
                continue;
            }
            kept.push_back(ot);
        }
        one_time = std::move(kept);
    }

    for (uint32_t i = 0; i < one_time_count; ++i) {
        OneTimePreKey ot;
        ot.id = current.id * 1000u + i;
        if (!crypto::x25519_generate(ot.pub, ot.priv)) return false;
        one_time.push_back(ot);
    }

    pruneOneTime();
    return true;
}

void PreKeys::pruneOneTime() {
    // Keep every unspent key, plus enough spent tombstones that a handshake
    // arriving just before a rotation can still name one - and so a duplicate
    // cannot quietly reuse the private half.
    std::vector<OneTimePreKey> kept;
    kept.reserve(one_time.size());

    size_t tombstones = 0;
    for (const auto& ot : one_time) {
        if (ot.consumed) {
            if (tombstones >= kTombstoneKeep) {
                veil::wipe(const_cast<uint8_t*>(ot.priv), kKeySize);
                continue;
            }
            ++tombstones;
        }
        kept.push_back(ot);
    }
    one_time = std::move(kept);
}

const uint8_t* PreKeys::signedPrivFor(uint32_t signed_id) const {
    if (signed_id == 0) return nullptr;
    if (signed_id == current.id) return current.priv;
    if (has_retired && signed_id == retired.id) return retired.priv;
    return nullptr;
}

const OneTimePreKey* PreKeys::consumeOneTime(uint32_t id) {
    if (id == 0) return nullptr;
    for (auto& ot : one_time) {
        if (ot.id != id) continue;
        // Already spent: answering again would let two sessions share the
        // same one-time key, which is precisely what "one-time" excludes.
        if (ot.consumed) return nullptr;
        ot.consumed = true;
        return &ot;
    }
    return nullptr;
}

bool PreKeys::needsRefill(size_t low_water) const {
    size_t unused = 0;
    for (const auto& ot : one_time) {
        if (!ot.consumed) ++unused;
    }
    return unused < low_water;
}

void PreKeys::wipeSecrets() {
    veil::wipe(current.priv, sizeof(current.priv));
    veil::wipe(retired.priv, sizeof(retired.priv));
    has_retired = false;
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
                           const OneTimePreKey* one_time) {
    PreKeyBundle b;
    std::memcpy(b.identity_dh_pub, identity.dh_pub, 32);
    std::memcpy(b.identity_sign_pub, identity.sign_pub, 32);
    b.signed_prekey_id = prekeys.current.id;
    std::memcpy(b.signed_pub, prekeys.current.pub, 32);
    std::memcpy(b.signed_signature, prekeys.current.signature, 64);
    if (one_time != nullptr) {
        b.has_one_time = true;
        b.one_time_id = one_time->id;
        std::memcpy(b.one_time_pub, one_time->pub, 32);
    }
    return b;
}

// ---- Prekey state persistence ------------------------------------------
//
// Layout:
//   [1]  version
//   [4]  next signed id
//   [4]  current id | [32] pub | [32] priv | [64] signature
//   [1]  has retired
//   [4]  retired id | [32] pub | [32] priv | [64] signature   (when present)
//   [4]  one-time count
//   per one-time: [4] id | [32] pub | [32] priv | [1] consumed
//
// The result carries private keys: it is meant for the same encrypted store
// the ratchet state goes into, never for plain disk.
constexpr uint8_t kPreKeyStateVersion = 1;

namespace {

void putSignedPreKey(Bytes& out, const SignedPreKey& spk) {
    uint8_t buf[4];
    put_u32(buf, spk.id);
    out.insert(out.end(), buf, buf + 4);
    out.insert(out.end(), spk.pub, spk.pub + kKeySize);
    out.insert(out.end(), spk.priv, spk.priv + kKeySize);
    out.insert(out.end(), spk.signature, spk.signature + kSigSize);
}

bool readSignedPreKey(SignedPreKey& out, const uint8_t* data, size_t size, size_t& off) {
    if (size < off + 4 + kKeySize + kKeySize + kSigSize) return false;
    out.id = get_u32(data + off); off += 4;
    std::memcpy(out.pub, data + off, kKeySize); off += kKeySize;
    std::memcpy(out.priv, data + off, kKeySize); off += kKeySize;
    std::memcpy(out.signature, data + off, kSigSize); off += kSigSize;
    return true;
}

}  // namespace

Bytes PreKeys::serialize() const {
    Bytes out;
    out.reserve(1 + 4 + 4 + kKeySize * 2 + kSigSize + 1 + one_time.size() * (4 + 65));

    out.push_back(kPreKeyStateVersion);

    uint8_t buf[4];
    put_u32(buf, next_signed_id);
    out.insert(out.end(), buf, buf + 4);

    putSignedPreKey(out, current);

    out.push_back(has_retired ? 1 : 0);
    if (has_retired) putSignedPreKey(out, retired);

    put_u32(buf, static_cast<uint32_t>(one_time.size()));
    out.insert(out.end(), buf, buf + 4);
    for (const auto& ot : one_time) {
        put_u32(buf, ot.id);
        out.insert(out.end(), buf, buf + 4);
        out.insert(out.end(), ot.pub, ot.pub + kKeySize);
        out.insert(out.end(), ot.priv, ot.priv + kKeySize);
        out.push_back(ot.consumed ? 1 : 0);
    }
    return out;
}

bool PreKeys::deserialize(const uint8_t* data, size_t size) {
    if (data == nullptr || size < 1 + 4 + 4 + kKeySize * 2 + kSigSize + 1 + 4) return false;

    size_t off = 0;
    if (data[off++] != kPreKeyStateVersion) return false;

    next_signed_id = get_u32(data + off); off += 4;
    if (next_signed_id == 0) return false;

    if (!readSignedPreKey(current, data, size, off)) return false;
    if (current.id == 0 || current.id >= next_signed_id) return false;

    has_retired = data[off++] != 0;
    if (has_retired && !readSignedPreKey(retired, data, size, off)) return false;

    uint32_t count = get_u32(data + off); off += 4;
    // Each entry is a fixed size, so a count that cannot fit is malformed
    // rather than merely large.
    if (static_cast<size_t>(count) > (size - off) / (4 + kKeySize * 2 + 1)) return false;

    one_time.clear();
    one_time.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        if (size < off + 4) return false;
        OneTimePreKey ot;
        ot.id = get_u32(data + off); off += 4;
        if (size < off + kKeySize * 2 + 1) return false;
        std::memcpy(ot.pub, data + off, kKeySize); off += kKeySize;
        std::memcpy(ot.priv, data + off, kKeySize); off += kKeySize;
        ot.consumed = data[off++] != 0;
        one_time.push_back(ot);
    }
    return true;
}

// ---- Device credentials -----------------------------------------------

size_t deviceCredentialMessage(uint8_t* out, size_t capacity,
                               const std::string& user_id,
                               const uint8_t device_id[kDeviceIdSize],
                               const uint8_t device_dh_pub[kKeySize],
                               const uint8_t device_sign_pub[32],
                               uint64_t issued_at) {
    const size_t domain_len = sizeof(kDeviceCredentialDomain) - 1;

    // A user id longer than 128 bytes is not a real user id, and accepting one
    // here would let a caller build a credential whose encoding overflows the
    // documented buffer bound.
    if (user_id.size() > 128) return 0;

    const size_t total = domain_len + 2 + user_id.size() + kDeviceIdSize +
                         kKeySize + 32 + 8;
    if (out == nullptr || capacity < total) return 0;

    size_t off = 0;
    std::memcpy(out + off, kDeviceCredentialDomain, domain_len);
    off += domain_len;

    // Big endian, two bytes. The user id is compared as bytes, so the length
    // prefix is what keeps "bo" from colliding with "bob".
    out[off++] = static_cast<uint8_t>((user_id.size() >> 8) & 0xFF);
    out[off++] = static_cast<uint8_t>(user_id.size() & 0xFF);
    std::memcpy(out + off, user_id.data(), user_id.size());
    off += user_id.size();

    std::memcpy(out + off, device_id, kDeviceIdSize); off += kDeviceIdSize;
    std::memcpy(out + off, device_dh_pub, kKeySize); off += kKeySize;
    std::memcpy(out + off, device_sign_pub, 32); off += 32;
    put_u64(out + off, issued_at); off += 8;

    return off;
}

bool generateDeviceId(uint8_t out[kDeviceIdSize]) {
    return secure_random(out, kDeviceIdSize);
}

bool DeviceCredential::create(DeviceCredential& out,
                              const std::string& user_id,
                              const uint8_t device_id[kDeviceIdSize],
                              const uint8_t device_dh_pub[kKeySize],
                              const uint8_t device_dh_priv[kKeySize],
                              const uint8_t device_sign_pub[32],
                              const uint8_t device_sign_priv[64],
                              uint64_t issued_at) {
    if (user_id.empty() || user_id.size() > 128) return false;

    out.user_id = user_id;
    std::memcpy(out.device_id, device_id, kDeviceIdSize);
    std::memcpy(out.device_dh_pub, device_dh_pub, kKeySize);
    std::memcpy(out.device_sign_pub, device_sign_pub, 32);
    out.issued_at = issued_at;

    // The device signs its own DH key, exactly as the account identity does.
    crypto::ed25519_sign(out.device_binding, device_sign_priv, device_dh_pub, kKeySize);

    std::memset(out.account_signature, 0, kSigSize);
    return true;
}

size_t DeviceCredential::signedMessage(uint8_t* out, size_t capacity) const {
    return deviceCredentialMessage(out, capacity, user_id, device_id,
                                   device_dh_pub, device_sign_pub, issued_at);
}

bool DeviceCredential::signBy(const Identity& account_identity) {
    uint8_t message[kDeviceCredentialMessageMax];
    const size_t len = signedMessage(message, sizeof(message));
    if (len == 0) return false;

    crypto::ed25519_sign(account_signature, account_identity.sign_priv, message, len);
    veil::wipe(message, sizeof(message));
    return true;
}

bool DeviceCredential::verifyDeviceBinding() const {
    return crypto::ed25519_verify(device_binding, device_sign_pub,
                                  device_dh_pub, kKeySize);
}

bool DeviceCredential::verify(const uint8_t account_dh_pub[kKeySize],
                              const uint8_t account_sign_pub[32]) const {
    (void)account_dh_pub;  // not covered by the signature; see below

    if (!verifyDeviceBinding()) return false;

    uint8_t message[kDeviceCredentialMessageMax];
    const size_t len = signedMessage(message, sizeof(message));
    if (len == 0) return false;

    // The account *signing* key is what endorses a device. The account DH key
    // is deliberately not part of the signed bytes: it is bound to the signing
    // key by the identity binding that every bundle already carries, so
    // repeating it here would add a field without adding a guarantee.
    const bool ok = crypto::ed25519_verify(account_signature, account_sign_pub,
                                           message, len);
    veil::wipe(message, sizeof(message));
    return ok;
}

Bytes DeviceCredential::serialize() const {
    Bytes out;
    out.reserve(2 + user_id.size() + kDeviceIdSize + kKeySize + 32 + 8 + kBindingSize + kSigSize);

    out.push_back(static_cast<uint8_t>((user_id.size() >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(user_id.size() & 0xFF));
    out.insert(out.end(), user_id.begin(), user_id.end());
    out.insert(out.end(), device_id, device_id + kDeviceIdSize);
    out.insert(out.end(), device_dh_pub, device_dh_pub + kKeySize);
    out.insert(out.end(), device_sign_pub, device_sign_pub + 32);

    uint8_t num[8];
    put_u64(num, issued_at);
    out.insert(out.end(), num, num + 8);

    out.insert(out.end(), device_binding, device_binding + kBindingSize);
    out.insert(out.end(), account_signature, account_signature + kSigSize);
    return out;
}

bool DeviceCredential::deserialize(DeviceCredential& out, const uint8_t* data, size_t size) {
    if (data == nullptr || size < 2) return false;

    size_t off = 0;
    const size_t id_len = (static_cast<size_t>(data[off]) << 8) | data[off + 1];
    off += 2;

    if (id_len == 0 || id_len > 128) return false;

    const size_t fixed = kDeviceIdSize + kKeySize + 32 + 8 + kBindingSize + kSigSize;
    // The arithmetic must not overflow before the comparison, so the check is
    // done by subtraction rather than by addition.
    if (size - off < id_len + fixed) return false;

    out.user_id.assign(reinterpret_cast<const char*>(data + off), id_len);
    off += id_len;

    std::memcpy(out.device_id, data + off, kDeviceIdSize); off += kDeviceIdSize;
    std::memcpy(out.device_dh_pub, data + off, kKeySize); off += kKeySize;
    std::memcpy(out.device_sign_pub, data + off, 32); off += 32;

    out.issued_at = get_u64(data + off); off += 8;

    std::memcpy(out.device_binding, data + off, kBindingSize); off += kBindingSize;
    std::memcpy(out.account_signature, data + off, kSigSize);
    return true;
}

std::string DeviceCredential::fingerprint() const {
    // Both public halves, domain-separated so a fingerprint of a device cannot
    // be confused with one of an account identity.
    //
    // The buffer is sized from the domain string itself rather than from a
    // guessed constant: the first version of this used `uint8_t buf[16 + ...]`
    // and overflowed by ten bytes, which the compiler caught and a test would
    // not have.
    static const char kDomain[] = "Veil/device-fingerprint/v1";
    constexpr size_t kDomainLen = sizeof(kDomain) - 1;

    uint8_t buffer[kDomainLen + kKeySize + 32];
    std::memcpy(buffer, kDomain, kDomainLen);
    std::memcpy(buffer + kDomainLen, device_dh_pub, kKeySize);
    std::memcpy(buffer + kDomainLen + kKeySize, device_sign_pub, 32);

    uint8_t digest[32];
    crypto::blake2b(digest, sizeof(digest), buffer, sizeof(buffer));

    // Four groups of four hex characters. Long enough that guessing is not a
    // thing, short enough that a person can read it aloud on a call.
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

}  // namespace veil
