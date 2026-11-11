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

// ---- Version -----------------------------------------------------------

extern "C" void veil_version(int* major, int* minor, int* patch) {
    if (major != nullptr) *major = 0;
    if (minor != nullptr) *minor = 2;
    if (patch != nullptr) *patch = 0;
}