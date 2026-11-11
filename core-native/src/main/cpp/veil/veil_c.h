// Veil - C ABI.
//
// The C++ engine is the implementation; this is the boundary every other
// language talks to. It exists so that a new platform does not need to
// reimplement the protocol, and does not need to link C++: JNA on the desktop,
// the Emscripten build on the web, and the Kotlin/JNI path on Android all
// reach the same functions.
//
// Two rules govern this header:
//
//  1. No C++ type crosses it. No std::string, no std::vector, no references,
//     no exceptions. A caller must be able to use it from a language that has
//     none of those.
//  2. Buffers are caller-owned. Every function that produces bytes writes them
//     into a buffer the caller provides, or returns a pointer the caller must
//     release with veil_bytes_free. Nothing is malloc'd on one side of the
//     boundary and freed on the other.
//
// Errors are never exceptions. Every fallible call returns an int status; the
// negative values are shared and the positive ones mirror veil::Engine::Result.
#ifndef VEIL_C_H
#define VEIL_C_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(VEIL_C_BUILD_DLL)
#define VEIL_API __declspec(dllexport)
#elif defined(_WIN32)
#define VEIL_API __declspec(dllimport)
#elif defined(__EMSCRIPTEN__)
#define VEIL_API __attribute__((used))
#else
#define VEIL_API __attribute__((visibility("default")))
#endif

// ---- Status codes ------------------------------------------------------
//
// Shared negatives are transport-level failures every call can produce.
// Non-negative values are the engine's own vocabulary, so a caller can tell
// "the signature was wrong" from "the identity changed".

#define VEIL_OK                     0
#define VEIL_BAD_BUNDLE             1
#define VEIL_BAD_SIGNATURE          2
#define VEIL_IDENTITY_CHANGED       3
#define VEIL_NO_SESSION             4
#define VEIL_AUTH_FAILED            5
#define VEIL_DUPLICATE              6

#define VEIL_ERR_NULL_HANDLE       (-1)
#define VEIL_ERR_NULL_ARG          (-2)
#define VEIL_ERR_BUFFER_TOO_SMALL  (-3)
#define VEIL_ERR_OUT_OF_MEMORY     (-4)
#define VEIL_ERR_NO_RANDOM         (-5)
#define VEIL_ERR_BAD_PARAM         (-6)
#define VEIL_ERR_INTERNAL          (-7)

// ---- Sizes -------------------------------------------------------------
//
// Fixed sizes the caller needs to allocate. Kept in the header so a caller
// never has to probe for them.

#define VEIL_IDENTITY_SECRET_SIZE  96   // DH private || signing private
#define VEIL_IDENTITY_PUBLIC_SIZE  64   // DH public  || signing public
#define VEIL_IDENTITY_BINDING_SIZE 64   // Ed25519 signature over the DH key
#define VEIL_CHALLENGE_SIG_SIZE    64
#define VEIL_SAFETY_NUMBER_MAX     32   // includes the NUL terminator

// ---- Handle lifetime ---------------------------------------------------

// Creates an engine with a fresh identity. Returns NULL on failure.
VEIL_API void* veil_engine_new(void);

// Restores an engine from 96 identity secret bytes. Returns NULL on failure.
VEIL_API void* veil_engine_restore(const uint8_t* secrets, size_t size);

// Destroys an engine. Safe to pass NULL.
VEIL_API void veil_engine_free(void* handle);

// ---- Identity ----------------------------------------------------------

// Writes 96 bytes of identity secret into out (size >= 96).
VEIL_API int veil_identity_secrets(const void* handle, uint8_t* out, size_t out_size);

// Writes 64 bytes of public identity into out (size >= 64).
VEIL_API int veil_identity_public(const void* handle, uint8_t* out, size_t out_size);

// Writes the 64-byte binding signature (signing key over the DH key).
VEIL_API int veil_identity_binding(const void* handle, uint8_t* out, size_t out_size);

// Signs a relay challenge with the identity signing key. Writes 64 bytes.
VEIL_API int veil_sign_challenge(const void* handle,
                                 const uint8_t* challenge, size_t challenge_size,
                                 uint8_t* out, size_t out_size);

// ---- Prekeys -----------------------------------------------------------

// Rotates the signed prekey and generates a fresh batch of one-time keys.
// Writes the public prekey set, which the relay stores verbatim:
//   [4] signed id | [32] signed pub | [64] signature | [4] count
//   per one-time key: [4] id | [32] pub
//
// Returns the number of bytes written, or a negative error.
VEIL_API int veil_rotate_prekeys(void* handle, uint8_t* out, size_t out_size);

// Copies the current public prekey set without rotating anything.
VEIL_API int veil_export_prekey_set(const void* handle, uint8_t* out, size_t out_size);

// True when fewer than `low_water` one-time keys remain unspent.
VEIL_API int veil_needs_prekey_refill(const void* handle, size_t low_water);

// The prekey state blob, carrying the signed-id counter and the spent flags.
// Contains private keys: store it encrypted, never in plain text.
VEIL_API int veil_export_prekey_state(const void* handle, uint8_t* out, size_t out_size);
VEIL_API int veil_import_prekey_state(void* handle, const uint8_t* data, size_t size);

// ---- Bounds ------------------------------------------------------------
//
// The engine produces variable-length output, so a caller has two options:
// ask for the needed size, then allocate and call again. Every producing
// function follows the same contract: pass out = NULL to get the required
// size as a positive return value, or a buffer of at least that size to get
// VEIL_OK and the byte count written to out_len.
//
// veil_measure_* are the explicit "how big is it" calls, for callers that
// would rather not pass NULL.

VEIL_API int veil_measure_session(const void* handle, const char* peer);
VEIL_API int veil_measure_prekey_state(const void* handle);
VEIL_API int veil_measure_peer_registry(const void* handle);

// ---- Sessions ----------------------------------------------------------

// Starts a session from a peer's published bundle.
// Returns VEIL_OK, or one of VEIL_BAD_BUNDLE / VEIL_BAD_SIGNATURE /
// VEIL_IDENTITY_CHANGED.
VEIL_API int veil_establish_outbound(void* handle, const char* peer,
                                     const uint8_t* bundle, size_t bundle_size);

// 0 = unknown label, 1 = identity pinned without a session, 2 = session ready.
VEIL_API int veil_session_state(const void* handle, const char* peer);

// Writes the serialized session for `peer`. Contains chain keys: encrypt it.
VEIL_API int veil_export_session(const void* handle, const char* peer,
                                 uint8_t* out, size_t out_size);

// Restores a session exported by veil_export_session.
VEIL_API int veil_import_session(void* handle, const char* peer,
                                 const uint8_t* data, size_t size);

// Forgets the ratchet for `peer`. The identity pin is kept on purpose: a
// session reset must not let the label be rebound to somebody else.
VEIL_API void veil_drop_session(void* handle, const char* peer);

// The pinned identity for `peer` (64 bytes), or VEIL_NO_SESSION when unmapped.
VEIL_API int veil_peer_identity(const void* handle, const char* peer,
                                uint8_t* out, size_t out_size);

// ---- Pinned identity registry ------------------------------------------

VEIL_API int veil_export_peer_registry(const void* handle, uint8_t* out, size_t out_size);
VEIL_API int veil_import_peer_registry(void* handle, const uint8_t* data, size_t size);

// ---- Messaging ---------------------------------------------------------

// Encrypts `plain` for `peer` and writes the framed ciphertext.
// Returns the number of bytes written, or a negative error.
VEIL_API int veil_encrypt(void* handle, const char* peer,
                          const uint8_t* plain, size_t plain_size,
                          uint8_t* out, size_t out_size);

// Decrypts a frame. On VEIL_OK, *out_len holds the plaintext length.
// The plaintext is written into `out`; pass out = NULL to get the size.
//
// Returns VEIL_DUPLICATE for a frame already accepted once, which is a normal
// event on an at-least-once relay and must not be reported as tampering.
VEIL_API int veil_decrypt(void* handle, const char* peer,
                          const uint8_t* frame, size_t frame_size,
                          uint8_t* out, size_t out_size, size_t* out_len);

// ---- Verification ------------------------------------------------------

// Writes the safety number as a NUL-terminated ASCII string into out.
// Returns VEIL_NO_SESSION when the peer is unknown.
VEIL_API int veil_safety_number(const void* handle, const char* peer,
                                char* out, size_t out_size);

// ---- Platform RNG ------------------------------------------------------
//
// The Emscripten build cannot open /dev/urandom, so the host has to supply
// entropy. A web caller installs a callback before creating any engine; on
// every other platform these are no-ops that return VEIL_OK.

typedef int (*veil_random_fn)(uint8_t* buf, size_t len);

VEIL_API void veil_set_random_source(veil_random_fn fn);

// ---- Version -----------------------------------------------------------

// Three numbers, so a native build and a web build can refuse each other.
VEIL_API void veil_version(int* major, int* minor, int* patch);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // VEIL_C_H