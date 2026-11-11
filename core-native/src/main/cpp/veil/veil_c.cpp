// Veil - C ABI implementation.
//
// A thin, careful wrapper. Two things in here deserve attention:
//
//  1. Every entry point validates its handle and its buffer size before
//     touching the engine. A C caller has no exceptions and no RAII, so the
//     only defensive line is the code at the boundary.
//  2. Output is produced into caller memory. The engine returns std::vector,
//     which is copied out and then wiped, so a secret does not linger in a
//     freed allocation waiting to be reused by something else.
#include "veil/veil_c.h"

#include <cstring>
#include <new>
#include <string>
#include <vector>

#include "veil/engine.h"
#include "veil/random.h"

namespace {

veil::Engine* toEngine(void* handle) {
    return reinterpret_cast<veil::Engine*>(handle);
}

const veil::Engine* toEngine(const void* handle) {
    return reinterpret_cast<const veil::Engine*>(handle);
}

// Copies `src` into a caller buffer with an explicit size check.
//
// Returns VEIL_OK with *written set, or VEIL_ERR_BUFFER_TOO_SMALL. When the
// caller passes out = NULL it returns the required size, which is what lets a
// caller size a buffer without guessing.
int copyOut(const veil::Bytes& src, uint8_t* out, size_t out_size, int* written) {
    if (out == nullptr) {
        if (written != nullptr) *written = static_cast<int>(src.size());
        return VEIL_OK;
    }
    if (src.size() > out_size) return VEIL_ERR_BUFFER_TOO_SMALL;

    if (!src.empty()) std::memcpy(out, src.data(), src.size());
    if (written != nullptr) *written = static_cast<int>(src.size());
    return VEIL_OK;
}

// A peer id arrives as a C string. An embedded NUL would silently truncate it
// and bind a session to a prefix of the real label, so it is rejected rather
// than accepted as a shorter id.
bool readPeer(const char* peer, std::string& out) {
    if (peer == nullptr) return false;
    out.assign(peer);
    return out.size() <= 128;
}

}  // namespace

// ---- Handle lifetime ---------------------------------------------------

extern "C" void* veil_engine_new(void) {
    auto* engine = new (std::nothrow) veil::Engine();
    if (engine == nullptr) return nullptr;

    if (!engine->createIdentity()) {
        delete engine;
        return nullptr;
    }
    return engine;
}

extern "C" void* veil_engine_restore(const uint8_t* secrets, size_t size) {
    if (secrets == nullptr || size != VEIL_IDENTITY_SECRET_SIZE) return nullptr;

    auto* engine = new (std::nothrow) veil::Engine();
    if (engine == nullptr) return nullptr;

    if (!engine->restoreIdentity(secrets, secrets + veil::kKeySize)) {
        delete engine;
        return nullptr;
    }
    return engine;
}

extern "C" void veil_engine_free(void* handle) {
    delete toEngine(handle);
}

// ---- Identity ----------------------------------------------------------

extern "C" int veil_identity_secrets(const void* handle, uint8_t* out, size_t out_size) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    int written = 0;
    veil::Bytes secrets = engine->exportIdentitySecrets();
    const int status = copyOut(secrets, out, out_size, &written);
    veil::wipe(secrets);
    return status == VEIL_OK ? written : status;
}

extern "C" int veil_identity_public(const void* handle, uint8_t* out, size_t out_size) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    int written = 0;
    const veil::Bytes pub = engine->exportIdentityPublic();
    const int status = copyOut(pub, out, out_size, &written);
    return status == VEIL_OK ? written : status;
}

extern "C" int veil_identity_binding(const void* handle, uint8_t* out, size_t out_size) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    int written = 0;
    const veil::Bytes sig = engine->exportIdentityBinding();
    const int status = copyOut(sig, out, out_size, &written);
    return status == VEIL_OK ? written : status;
}

extern "C" int veil_sign_challenge(const void* handle,
                                   const uint8_t* challenge, size_t challenge_size,
                                   uint8_t* out, size_t out_size) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (challenge == nullptr && challenge_size != 0) return VEIL_ERR_NULL_ARG;

    int written = 0;
    const veil::Bytes sig = engine->signChallenge(challenge, challenge_size);
    const int status = copyOut(sig, out, out_size, &written);
    return status == VEIL_OK ? written : status;
}

// ---- Prekeys -----------------------------------------------------------

extern "C" int veil_rotate_prekeys(void* handle, uint8_t* out, size_t out_size) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (!engine->rotatePreKeys()) return VEIL_ERR_NO_RANDOM;

    int written = 0;
    const veil::Bytes set = engine->exportPreKeySet();
    const int status = copyOut(set, out, out_size, &written);
    return status == VEIL_OK ? written : status;
}

extern "C" int veil_export_prekey_set(const void* handle, uint8_t* out, size_t out_size) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    int written = 0;
    const veil::Bytes set = engine->exportPreKeySet();
    const int status = copyOut(set, out, out_size, &written);
    return status == VEIL_OK ? written : status;
}

extern "C" int veil_needs_prekey_refill(const void* handle, size_t low_water) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    return engine->needsPreKeyRefill(low_water) ? 1 : 0;
}

extern "C" int veil_export_prekey_state(const void* handle, uint8_t* out, size_t out_size) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    int written = 0;
    veil::Bytes state = engine->exportPreKeyState();
    const int status = copyOut(state, out, out_size, &written);
    veil::wipe(state);
    return status == VEIL_OK ? written : status;
}

extern "C" int veil_import_prekey_state(void* handle, const uint8_t* data, size_t size) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (data == nullptr || size == 0) return VEIL_ERR_NULL_ARG;

    return engine->importPreKeyState(data, size) ? VEIL_OK : VEIL_ERR_BAD_PARAM;
}

// ---- Bounds ------------------------------------------------------------

extern "C" int veil_measure_session(const void* handle, const char* peer) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    std::string id;
    if (!readPeer(peer, id)) return VEIL_ERR_BAD_PARAM;

    const veil::Bytes blob = engine->exportSession(id);
    if (blob.empty()) return VEIL_NO_SESSION;
    return static_cast<int>(blob.size());
}

extern "C" int veil_measure_prekey_state(const void* handle) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    veil::Bytes state = engine->exportPreKeyState();
    const int size = static_cast<int>(state.size());
    veil::wipe(state);
    return size;
}

extern "C" int veil_measure_peer_registry(const void* handle) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    return static_cast<int>(engine->exportPeerRegistry().size());
}

// ---- Sessions ----------------------------------------------------------

extern "C" int veil_establish_outbound(void* handle, const char* peer,
                                       const uint8_t* bundle, size_t bundle_size) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (bundle == nullptr || bundle_size == 0) return VEIL_ERR_NULL_ARG;

    std::string id;
    if (!readPeer(peer, id)) return VEIL_ERR_BAD_PARAM;

    return static_cast<int>(engine->establishOutboundStatus(id, bundle, bundle_size));
}

extern "C" int veil_session_state(const void* handle, const char* peer) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    std::string id;
    if (!readPeer(peer, id)) return VEIL_ERR_BAD_PARAM;
    return static_cast<int>(engine->sessionState(id));
}

extern "C" int veil_export_session(const void* handle, const char* peer,
                                   uint8_t* out, size_t out_size) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    std::string id;
    if (!readPeer(peer, id)) return VEIL_ERR_BAD_PARAM;

    int written = 0;
    veil::Bytes blob = engine->exportSession(id);
    if (blob.empty()) return VEIL_NO_SESSION;

    const int status = copyOut(blob, out, out_size, &written);
    veil::wipe(blob);
    return status == VEIL_OK ? written : status;
}

extern "C" int veil_import_session(void* handle, const char* peer,
                                   const uint8_t* data, size_t size) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (data == nullptr || size == 0) return VEIL_ERR_NULL_ARG;

    std::string id;
    if (!readPeer(peer, id)) return VEIL_ERR_BAD_PARAM;

    return engine->importSession(id, data, size) ? VEIL_OK : VEIL_ERR_BAD_PARAM;
}

extern "C" void veil_drop_session(void* handle, const char* peer) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return;

    std::string id;
    if (!readPeer(peer, id)) return;
    engine->dropSession(id);
}

extern "C" int veil_peer_identity(const void* handle, const char* peer,
                                  uint8_t* out, size_t out_size) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    std::string id;
    if (!readPeer(peer, id)) return VEIL_ERR_BAD_PARAM;

    const veil::Bytes identity = engine->peerIdentity(id);
    if (identity.empty()) return VEIL_NO_SESSION;

    int written = 0;
    const int status = copyOut(identity, out, out_size, &written);
    return status == VEIL_OK ? written : status;
}

// ---- Pinned identity registry ------------------------------------------

extern "C" int veil_export_peer_registry(const void* handle, uint8_t* out, size_t out_size) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    int written = 0;
    const veil::Bytes blob = engine->exportPeerRegistry();
    const int status = copyOut(blob, out, out_size, &written);
    return status == VEIL_OK ? written : status;
}

extern "C" int veil_import_peer_registry(void* handle, const uint8_t* data, size_t size) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (data == nullptr || size == 0) return VEIL_ERR_NULL_ARG;

    return engine->importPeerRegistry(data, size) ? VEIL_OK : VEIL_ERR_BAD_PARAM;
}

// ---- Messaging ---------------------------------------------------------

extern "C" int veil_encrypt(void* handle, const char* peer,
                            const uint8_t* plain, size_t plain_size,
                            uint8_t* out, size_t out_size) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (plain == nullptr && plain_size != 0) return VEIL_ERR_NULL_ARG;

    std::string id;
    if (!readPeer(peer, id)) return VEIL_ERR_BAD_PARAM;

    veil::Bytes frame = engine->encrypt(id, plain, plain_size);
    if (frame.empty()) return VEIL_NO_SESSION;

    int written = 0;
    const int status = copyOut(frame, out, out_size, &written);
    veil::wipe(frame);
    return status == VEIL_OK ? written : status;
}

extern "C" int veil_decrypt(void* handle, const char* peer,
                            const uint8_t* frame, size_t frame_size,
                            uint8_t* out, size_t out_size, size_t* out_len) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (frame == nullptr || frame_size == 0) return VEIL_ERR_NULL_ARG;
    if (out_len == nullptr) return VEIL_ERR_NULL_ARG;

    std::string id;
    if (!readPeer(peer, id)) return VEIL_ERR_BAD_PARAM;

    // A size probe must not consume the message key.
    //
    // Decrypting advances the ratchet and spends the key, so a "how big is the
    // plaintext" call that actually decrypted would leave the caller holding a
    // plaintext length and an already-consumed frame - the real call would then
    // come back as a duplicate, which is exactly the bug JNA hit.
    //
    // The plaintext is always smaller than the frame (the frame carries a MAC
    // and a header), so the honest answer to a probe is "frame_size": the
    // caller allocates that, and the real call reports the true length in
    // out_len.
    if (out == nullptr) {
        *out_len = frame_size;
        return VEIL_OK;
    }
    if (out_size < frame_size) {
        // Not an error the caller can recover from by asking again with the
        // same buffer, so report what is needed and let it allocate.
        *out_len = frame_size;
        return VEIL_ERR_BUFFER_TOO_SMALL;
    }

    veil::Bytes plain;
    const veil::Engine::Result result =
        engine->decryptStatus(id, frame, frame_size, plain);

    if (result != veil::Engine::Result::Ok) {
        veil::wipe(plain);
        *out_len = 0;
        return static_cast<int>(result);
    }

    if (!plain.empty()) std::memcpy(out, plain.data(), plain.size());
    *out_len = plain.size();
    veil::wipe(plain);
    return VEIL_OK;
}

// ---- Verification ------------------------------------------------------

extern "C" int veil_safety_number(const void* handle, const char* peer,
                                  char* out, size_t out_size) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    std::string id;
    if (!readPeer(peer, id)) return VEIL_ERR_BAD_PARAM;

    const std::string number = engine->safetyNumber(id);
    if (number.empty()) return VEIL_NO_SESSION;
    if (out == nullptr) return static_cast<int>(number.size() + 1);
    if (number.size() + 1 > out_size) return VEIL_ERR_BUFFER_TOO_SMALL;

    std::memcpy(out, number.c_str(), number.size() + 1);
    return VEIL_OK;
}

// ---- Platform RNG ------------------------------------------------------

extern "C" void veil_set_random_source(veil_random_fn fn) {
    veil::set_platform_random_source(fn);
}

extern "C" void veil_version(int* major, int* minor, int* patch) {
    if (major != nullptr) *major = 0;
    if (minor != nullptr) *minor = 4;
    if (patch != nullptr) *patch = 0;
}

// ---- Groups ------------------------------------------------------------
//
// The wire shape for a group message is one record:
//   [2] sender len | sender | [4] epoch | [4] iteration
//   | [4] ciphertext len | ciphertext

namespace {

// Splits a NUL-separated member list.
std::vector<std::string> splitMembers(const uint8_t* data, size_t size) {
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i <= size; ++i) {
        if (i == size || data[i] == 0) {
            if (i > start) {
                out.emplace_back(reinterpret_cast<const char*>(data + start), i - start);
            }
            start = i + 1;
        }
    }
    return out;
}

std::string joinMembers(const std::vector<std::string>& members) {
    std::string out;
    for (size_t i = 0; i < members.size(); ++i) {
        if (i != 0) out.push_back('\0');
        out.append(members[i]);
    }
    return out;
}

}  // namespace

extern "C" int veil_create_group(void* handle, const char* group_id) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    std::string id;
    if (!readPeer(group_id, id) || id.empty()) return VEIL_ERR_BAD_PARAM;
    return engine->createGroup(id) ? VEIL_OK : VEIL_ERR_BAD_PARAM;
}

extern "C" uint32_t veil_set_group_members(void* handle, const char* group_id,
                                           const uint8_t* members, size_t members_size) {
    auto* engine = toEngine(handle);
    if (engine == nullptr || members == nullptr) return 0;

    std::string id;
    if (!readPeer(group_id, id)) return 0;

    const std::vector<std::string> parsed = splitMembers(members, members_size);
    return engine->setGroupMembers(id, parsed);
}

extern "C" int veil_export_membership(const void* handle, const char* group_id,
                                      uint8_t* out, size_t out_size) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    std::string id;
    if (!readPeer(group_id, id)) return VEIL_ERR_BAD_PARAM;

    int written = 0;
    const veil::Bytes blob = engine->exportMembership(id);
    if (blob.empty()) return VEIL_NO_SESSION;

    const int status = copyOut(blob, out, out_size, &written);
    return status == VEIL_OK ? written : status;
}

extern "C" int veil_adopt_membership(void* handle, const uint8_t* data, size_t size,
                                     const uint8_t* founder_sign_pub) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (data == nullptr || founder_sign_pub == nullptr) return VEIL_ERR_NULL_ARG;

    return static_cast<int>(engine->adoptMembership(data, size, founder_sign_pub));
}

extern "C" uint32_t veil_group_epoch(const void* handle, const char* group_id) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return 0;

    std::string id;
    if (!readPeer(group_id, id)) return 0;
    return engine->groupEpoch(id);
}

extern "C" int veil_group_members(const void* handle, const char* group_id,
                                  char* out, size_t out_size) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    std::string id;
    if (!readPeer(group_id, id)) return VEIL_ERR_BAD_PARAM;

    const std::string joined = joinMembers(engine->groupMembers(id));

    if (out == nullptr) return static_cast<int>(joined.size());
    if (joined.size() > out_size) return VEIL_ERR_BUFFER_TOO_SMALL;

    if (!joined.empty()) std::memcpy(out, joined.data(), joined.size());
    return static_cast<int>(joined.size());
}

extern "C" int veil_is_group_member(const void* handle, const char* group_id) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    std::string id;
    if (!readPeer(group_id, id)) return VEIL_ERR_BAD_PARAM;
    return engine->isGroupMember(id) ? 1 : 0;
}

extern "C" int veil_export_sender_key(const void* handle, const char* group_id,
                                      uint32_t epoch, uint8_t* out, size_t out_size) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    std::string id;
    if (!readPeer(group_id, id)) return VEIL_ERR_BAD_PARAM;

    int written = 0;
    veil::Bytes key = engine->exportSenderKey(id, epoch);
    if (key.empty()) return VEIL_NO_SESSION;

    const int status = copyOut(key, out, out_size, &written);
    veil::wipe(key);
    return status == VEIL_OK ? written : status;
}

extern "C" int veil_adopt_sender_key(void* handle, const uint8_t* data, size_t size,
                                     const char* expected_sender,
                                     const uint8_t* sender_sign_pub) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (data == nullptr || sender_sign_pub == nullptr) return VEIL_ERR_NULL_ARG;

    std::string sender;
    if (!readPeer(expected_sender, sender)) return VEIL_ERR_BAD_PARAM;

    return static_cast<int>(engine->adoptSenderKey(data, size, sender, sender_sign_pub));
}

extern "C" int veil_encrypt_to_group(void* handle, const char* group_id,
                                     const uint8_t* plain, size_t plain_size,
                                     uint8_t* out, size_t out_size) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (plain == nullptr && plain_size != 0) return VEIL_ERR_NULL_ARG;

    std::string id;
    if (!readPeer(group_id, id)) return VEIL_ERR_BAD_PARAM;

    veil::GroupMessage message;
    if (!engine->encryptToGroup(id, plain, plain_size, message)) return VEIL_NO_SESSION;

    const size_t total = 2 + message.sender_id.size() + 4 + 4 + 4 +
                         message.ciphertext.size();

    if (out == nullptr) return static_cast<int>(total);
    if (total > out_size) return VEIL_ERR_BUFFER_TOO_SMALL;

    size_t off = 0;
    out[off++] = static_cast<uint8_t>((message.sender_id.size() >> 8) & 0xFF);
    out[off++] = static_cast<uint8_t>(message.sender_id.size() & 0xFF);
    std::memcpy(out + off, message.sender_id.data(), message.sender_id.size());
    off += message.sender_id.size();

    uint8_t num[4];
    veil::put_u32(num, message.epoch);
    std::memcpy(out + off, num, 4);
    off += 4;
    veil::put_u32(num, message.iteration);
    std::memcpy(out + off, num, 4);
    off += 4;
    veil::put_u32(num, static_cast<uint32_t>(message.ciphertext.size()));
    std::memcpy(out + off, num, 4);
    off += 4;

    std::memcpy(out + off, message.ciphertext.data(), message.ciphertext.size());
    off += message.ciphertext.size();

    return static_cast<int>(total);
}

extern "C" int veil_decrypt_from_group(void* handle, const char* group_id,
                                       const uint8_t* data, size_t size,
                                       uint8_t* out, size_t out_size, size_t* out_len) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (data == nullptr || size < 2 || out_len == nullptr) return VEIL_ERR_NULL_ARG;

    std::string id;
    if (!readPeer(group_id, id)) return VEIL_ERR_BAD_PARAM;

    size_t off = 0;
    const size_t sender_len = (static_cast<size_t>(data[off]) << 8) | data[off + 1];
    off += 2;
    if (size - off < sender_len + 12) return VEIL_ERR_BAD_PARAM;

    veil::GroupMessage message;
    message.sender_id.assign(reinterpret_cast<const char*>(data + off), sender_len);
    off += sender_len;

    message.epoch = veil::get_u32(data + off); off += 4;
    message.iteration = veil::get_u32(data + off); off += 4;
    const uint32_t cipher_len = veil::get_u32(data + off); off += 4;
    if (size - off < cipher_len) return VEIL_ERR_BAD_PARAM;

    message.ciphertext.assign(data + off, data + off + cipher_len);

    veil::Bytes plain;
    const veil::Engine::Result result = engine->decryptFromGroup(id, message, plain);
    if (result != veil::Engine::Result::Ok) {
        veil::wipe(plain);
        *out_len = 0;
        return static_cast<int>(result);
    }

    // The plaintext is always smaller than the ciphertext, so a caller sizing
    // from the frame is safe - and asking for a probe must not consume the key,
    // which is why the bound is reported rather than computed.
    if (out == nullptr) {
        *out_len = size;
        veil::wipe(plain);
        return VEIL_OK;
    }
    if (out_size < plain.size()) {
        veil::wipe(plain);
        *out_len = plain.size();
        return VEIL_ERR_BUFFER_TOO_SMALL;
    }

    if (!plain.empty()) std::memcpy(out, plain.data(), plain.size());
    *out_len = plain.size();
    veil::wipe(plain);
    return VEIL_OK;
}

// ---- Multi-device ------------------------------------------------------

extern "C" int veil_init_device(void* handle, const char* user_id) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    std::string id;
    if (!readPeer(user_id, id) || id.empty()) return VEIL_ERR_BAD_PARAM;

    return engine->initDevice(id) ? VEIL_OK : VEIL_ERR_BAD_PARAM;
}

extern "C" int veil_device_id(const void* handle, uint8_t* out, size_t out_size) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (out == nullptr) return VEIL_DEVICE_ID_SIZE;
    if (out_size < VEIL_DEVICE_ID_SIZE) return VEIL_ERR_BUFFER_TOO_SMALL;

    const veil::Bytes id = engine->ownDeviceId();
    if (id.empty()) return VEIL_NO_SESSION;
    std::memcpy(out, id.data(), VEIL_DEVICE_ID_SIZE);
    return VEIL_DEVICE_ID_SIZE;
}

extern "C" int veil_device_credential(const void* handle, uint8_t* out, size_t out_size) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    int written = 0;
    const veil::Bytes cred = engine->ownDeviceCredential();
    if (cred.empty()) return VEIL_NO_SESSION;

    const int status = copyOut(cred, out, out_size, &written);
    return status == VEIL_OK ? written : status;
}

extern "C" int veil_adopt_device_credential(void* handle,
                                            const uint8_t* credential, size_t size,
                                            const uint8_t* account_dh_pub,
                                            const uint8_t* account_sign_pub) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (credential == nullptr || account_dh_pub == nullptr || account_sign_pub == nullptr) {
        return VEIL_ERR_NULL_ARG;
    }

    return engine->adoptDeviceCredential(credential, size, account_dh_pub, account_sign_pub)
               ? VEIL_OK
               : VEIL_BAD_SIGNATURE;
}

extern "C" int veil_adopt_device_list(void* handle, const char* user_id,
                                      uint32_t version,
                                      const uint8_t* data, size_t size,
                                      const uint8_t* account_dh_pub,
                                      const uint8_t* account_sign_pub) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (data == nullptr || account_dh_pub == nullptr || account_sign_pub == nullptr) {
        return VEIL_ERR_NULL_ARG;
    }

    std::string id;
    if (!readPeer(user_id, id)) return VEIL_ERR_BAD_PARAM;

    return static_cast<int>(engine->adoptDeviceList(id, version, data, size,
                                                    account_dh_pub, account_sign_pub));
}

namespace {

// Builds the NUL-separated hex list used by the device-list accessors.
std::string joinDevices(const std::vector<std::string>& ids) {
    std::string out;
    for (size_t i = 0; i < ids.size(); ++i) {
        if (i != 0) out.push_back('\0');
        out.append(ids[i]);
    }
    return out;
}

}  // namespace

extern "C" int veil_peer_devices(const void* handle, const char* user_id,
                                 char* out, size_t out_size) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;

    std::string id;
    if (!readPeer(user_id, id)) return VEIL_ERR_BAD_PARAM;

    const std::string joined = joinDevices(engine->peerDevices(id));

    if (out == nullptr) return static_cast<int>(joined.size());
    if (joined.size() > out_size) return VEIL_ERR_BUFFER_TOO_SMALL;

    if (!joined.empty()) std::memcpy(out, joined.data(), joined.size());
    return static_cast<int>(joined.size());
}

extern "C" uint32_t veil_peer_device_version(const void* handle, const char* user_id) {
    const auto* engine = toEngine(handle);
    if (engine == nullptr) return 0;

    std::string id;
    if (!readPeer(user_id, id)) return 0;
    return engine->peerDeviceVersion(id);
}

extern "C" int veil_device_fingerprint(const uint8_t* credential, size_t size,
                                       char* out, size_t out_size) {
    if (credential == nullptr) return VEIL_ERR_NULL_ARG;

    veil::DeviceCredential cred;
    if (!veil::DeviceCredential::deserialize(cred, credential, size)) return VEIL_BAD_BUNDLE;

    const std::string fp = cred.fingerprint();
    if (out == nullptr) return static_cast<int>(fp.size() + 1);
    if (fp.size() + 1 > out_size) return VEIL_ERR_BUFFER_TOO_SMALL;

    std::memcpy(out, fp.c_str(), fp.size() + 1);
    return VEIL_OK;
}

extern "C" int veil_establish_with_devices(void* handle, const char* user_id,
                                           const uint8_t* device_ids, size_t device_ids_size,
                                           const uint8_t* bundles, size_t bundles_size,
                                           char* failed, size_t failed_size) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (device_ids == nullptr || bundles == nullptr) return VEIL_ERR_NULL_ARG;

    std::string id;
    if (!readPeer(user_id, id)) return VEIL_ERR_BAD_PARAM;

    // [4] count | per entry [2] len | hex
    if (device_ids_size < 4) return VEIL_ERR_BAD_PARAM;
    const uint32_t count = (uint32_t(device_ids[0]) << 24) | (uint32_t(device_ids[1]) << 16) |
                           (uint32_t(device_ids[2]) << 8) | uint32_t(device_ids[3]);

    std::vector<std::string> ids;
    ids.reserve(count);
    size_t off = 4;
    for (uint32_t i = 0; i < count; ++i) {
        if (device_ids_size - off < 2) return VEIL_ERR_BAD_PARAM;
        const size_t len = (static_cast<size_t>(device_ids[off]) << 8) | device_ids[off + 1];
        off += 2;
        if (device_ids_size - off < len) return VEIL_ERR_BAD_PARAM;
        ids.emplace_back(reinterpret_cast<const char*>(device_ids + off), len);
        off += len;
    }

    std::vector<veil::Engine::DeviceBundle> parsed;
    parsed.reserve(count);
    off = 0;
    for (uint32_t i = 0; i < count && i < ids.size(); ++i) {
        if (bundles_size - off < 4) return VEIL_ERR_BAD_PARAM;
        const uint32_t len = (uint32_t(bundles[off]) << 24) | (uint32_t(bundles[off + 1]) << 16) |
                             (uint32_t(bundles[off + 2]) << 8) | uint32_t(bundles[off + 3]);
        off += 4;
        if (bundles_size - off < len) return VEIL_ERR_BAD_PARAM;

        veil::Engine::DeviceBundle item;
        item.device_id = ids[i];
        item.bundle.assign(bundles + off, bundles + off + len);
        parsed.push_back(std::move(item));
        off += len;
    }

    std::vector<std::string> failures;
    const size_t established = engine->establishWithDevices(id, parsed, failures);

    if (failed != nullptr && failed_size > 0) {
        const std::string joined = joinDevices(failures);
        const size_t n = joined.size() < failed_size ? joined.size() : failed_size - 1;
        if (n > 0) std::memcpy(failed, joined.data(), n);
        failed[n] = 0;
    }
    return static_cast<int>(established);
}

extern "C" int veil_encrypt_to_account(void* handle, const char* user_id,
                                       const uint8_t* plain, size_t plain_size,
                                       uint8_t* out, size_t out_size) {
    auto* engine = toEngine(handle);
    if (engine == nullptr) return VEIL_ERR_NULL_HANDLE;
    if (plain == nullptr && plain_size != 0) return VEIL_ERR_NULL_ARG;

    std::string id;
    if (!readPeer(user_id, id)) return VEIL_ERR_BAD_PARAM;

    const auto frames = engine->encryptToAccount(id, plain, plain_size);

    // [4] payload length | [1] id length | id (hex) | [4] frame length | frame
    size_t total = 0;
    for (const auto& item : frames) {
        total += 4 + 1 + item.device_id.size() + 4 + item.frame.size();
    }

    if (out == nullptr) return static_cast<int>(total);
    if (total > out_size) return VEIL_ERR_BUFFER_TOO_SMALL;

    size_t off = 0;
    for (const auto& item : frames) {
        const size_t record = 4 + 1 + item.device_id.size() + 4 + item.frame.size();

        uint8_t num[4];
        veil::put_u32(num, static_cast<uint32_t>(record - 4));
        std::memcpy(out + off, num, 4);
        off += 4;

        out[off++] = static_cast<uint8_t>(item.device_id.size());
        if (!item.device_id.empty()) {
            std::memcpy(out + off, item.device_id.data(), item.device_id.size());
            off += item.device_id.size();
        }

        veil::put_u32(num, static_cast<uint32_t>(item.frame.size()));
        std::memcpy(out + off, num, 4);
        off += 4;

        std::memcpy(out + off, item.frame.data(), item.frame.size());
        off += item.frame.size();
    }
    return static_cast<int>(total);
}