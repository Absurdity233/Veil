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

// ---- Multi-device ------------------------------------------------------
//
// One account, many devices. See docs/multi-device.md for the design and what
// it costs.
//
// The shape of this section mirrors the engine: a device has an identity (its
// own key pair plus the account's endorsement), a peer has a device list, and
// sending is a fan-out. Sessions remain addressable by a composite label, so
// everything above this line keeps working unchanged.

#define VEIL_DEVICE_ID_SIZE   32
#define VEIL_DEVICE_CRED_MAX  512
#define VEIL_FINGERPRINT_SIZE 20   // 4 groups of 4 hex + 3 dashes + NUL

// Claims a user id for this engine and creates its device.
//
// The first device of an account is the account: it signs its own endorsement,
// so no linking flow is needed to get started, and a single-device account is
// just a list of one.
//
// Returns VEIL_OK, or VEIL_ERR_BAD_PARAM for an empty or over-long id.
VEIL_API int veil_init_device(void* handle, const char* user_id);

// Writes the 32-byte device id. VEIL_NO_SESSION when no device is initialised.
VEIL_API int veil_device_id(const void* handle, uint8_t* out, size_t out_size);

// Writes this device's credential, ready to publish. `out` may be NULL to get
// the size, following the same contract as the rest of this header.
VEIL_API int veil_device_credential(const void* handle, uint8_t* out, size_t out_size);

// Adopts a credential an existing device signed for this one.
//
// The endorsement is verified against the account keys passed in, so a relay
// cannot hand over a credential that was never issued. The credential must also
// describe *this* device's public keys.
VEIL_API int veil_adopt_device_credential(void* handle,
                                          const uint8_t* credential, size_t size,
                                          const uint8_t* account_dh_pub,
                                          const uint8_t* account_sign_pub);

// Records a peer's device list.
//
// `data` carries the entries only:
//   [4] count | per entry: a serialized DeviceCredential
// `version` travels beside it because it is the relay's bookkeeping, not the
// account's statement.
//
// A version at or below the one already held is ignored, so a relay cannot roll
// an account back to a list that still contains a device the user removed. A
// list in which any entry fails verification is refused whole.
VEIL_API int veil_adopt_device_list(void* handle, const char* user_id,
                                    uint32_t version,
                                    const uint8_t* data, size_t size,
                                    const uint8_t* account_dh_pub,
                                    const uint8_t* account_sign_pub);

// Fills `out` with the hex device ids known for a peer, NUL-separated.
//
// Hex rather than raw bytes so the result is a string a caller can log, compare
// and put in a JSON field without another encoding decision. Returns the number
// of bytes written, or a negative error; `out` may be NULL to get the size.
VEIL_API int veil_peer_devices(const void* handle, const char* user_id,
                               char* out, size_t out_size);

// The version of the list held for a peer, or 0 when none.
VEIL_API uint32_t veil_peer_device_version(const void* handle, const char* user_id);

// A device's short fingerprint: four groups of four hex characters.
//
// This is what a linking flow shows the user. It identifies the device's *keys*,
// not the id the relay assigned, because the id carries no security meaning.
VEIL_API int veil_device_fingerprint(const uint8_t* credential, size_t size,
                                     char* out, size_t out_size);

// Starts sessions with a list of a peer's devices.
//
// `device_ids` is [4] count | per entry [2] length | hex id, and `bundles`
// carries one bundle per device, length-prefixed in the same order. Devices that
// fail are reported in `failed` the same way, so a caller can say "3 of 4
// reachable" rather than a bare failure.
//
// Returns the number of sessions established (>= 0), or a negative error.
VEIL_API int veil_establish_with_devices(void* handle, const char* user_id,
                                         const uint8_t* device_ids, size_t device_ids_size,
                                         const uint8_t* bundles, size_t bundles_size,
                                         char* failed, size_t failed_size);

// Encrypts one plaintext to every device of a peer that has a session.
//
// One message becomes N frames. That is the real cost of per-device sessions,
// and it is why the relay learns how many devices a recipient has.
//
// Output is a sequence of records the caller walks:
//   [4] payload length | [1] id length | id (hex, may be empty)
//   | [4] frame length | frame
// Repeated until the buffer is exhausted. `out` may be NULL to get the size.
VEIL_API int veil_encrypt_to_account(void* handle, const char* user_id,
                                     const uint8_t* plain, size_t plain_size,
                                     uint8_t* out, size_t out_size);

// ---- Groups ------------------------------------------------------------
//
// Sender Keys. Each member publishes a chain of their own and broadcasts one
// message encrypted with it, so a group message costs one frame rather than N-1.
//
// The cost, stated: everyone in the group holds the key to every message, so
// removing a member *must* rotate every chain. That is what the epoch is for.
// See docs/group.md.

// Creates a group with this device's user as founder and sole member.
VEIL_API int veil_create_group(void* handle, const char* group_id);

// Replaces the member list and bumps the epoch. Returns the new epoch, or 0.
//
// Every live chain is discarded: a member who was removed must not read anything
// after this point, and re-keying is the only way to guarantee that.
VEIL_API uint32_t veil_set_group_members(void* handle, const char* group_id,
                                         const uint8_t* members, size_t members_size);

// The membership record, signed by the founder. `out` may be NULL for the size.
VEIL_API int veil_export_membership(const void* handle, const char* group_id,
                                    uint8_t* out, size_t out_size);

// Adopts a signed membership record against the founder's signing key.
//
// Once adopted, a record for the same group must carry the same founder key: a
// record that re-anchors the group is indistinguishable from a relay handing
// over a different group under the same name.
VEIL_API int veil_adopt_membership(void* handle, const uint8_t* data, size_t size,
                                   const uint8_t* founder_sign_pub);

VEIL_API uint32_t veil_group_epoch(const void* handle, const char* group_id);

// Fills `out` with the members, NUL-separated. NULL for the size.
VEIL_API int veil_group_members(const void* handle, const char* group_id,
                                char* out, size_t out_size);

// 1 when this engine is a member, 0 when not, negative on error.
VEIL_API int veil_is_group_member(const void* handle, const char* group_id);

// This device's chain for the group's current epoch, signed by its device key.
VEIL_API int veil_export_sender_key(const void* handle, const char* group_id,
                                    uint32_t epoch, uint8_t* out, size_t out_size);

// Installs a peer's chain. Refuses a chain for an epoch at or below one already
// held from that sender, which is what stops a rotated-out member re-publishing.
VEIL_API int veil_adopt_sender_key(void* handle, const uint8_t* data, size_t size,
                                   const char* expected_sender,
                                   const uint8_t* sender_sign_pub);

// Encrypts one message for the whole group.
//
// Output record: [2] sender len | sender | [4] epoch | [4] iteration
//                 | [4] ciphertext len | ciphertext
VEIL_API int veil_encrypt_to_group(void* handle, const char* group_id,
                                   const uint8_t* plain, size_t plain_size,
                                   uint8_t* out, size_t out_size);

// Decrypts a group message in that same record shape.
VEIL_API int veil_decrypt_from_group(void* handle, const char* group_id,
                                     const uint8_t* data, size_t size,
                                     uint8_t* out, size_t out_size, size_t* out_len);

// The whole group state, for the encrypted store.
//
// This carries secrets: every incoming chain key decrypts that sender's messages
// and the outgoing chain can forge them. It belongs in the same encrypted store
// as ratchet state.
VEIL_API int veil_export_group_state(const void* handle, uint8_t* out, size_t out_size);

// Restores group state. A malformed blob is refused whole, leaving live groups
// untouched rather than half-loaded.
VEIL_API int veil_import_group_state(void* handle, const uint8_t* data, size_t size);

// ---- Group invitations -------------------------------------------------
//
// An invitation is the *content* of an ordinary pairwise message, not a new
// wire type: the relay needs no changes, and the invitation inherits the
// encryption and authentication the session already has. A dedicated frame would
// tell the relay the group id, the member list and who was invited; this tells it
// only what it already knew.

// Builds the payload to encrypt and send to one invitee. NULL `out` for the size.
VEIL_API int veil_encode_invite(const void* handle, const char* group_id,
                                uint8_t* out, size_t out_size);

// 1 when a decrypted message is an invitation, 0 when it is text.
VEIL_API int veil_looks_like_invite(const uint8_t* data, size_t size);

// ---- Device linking ----------------------------------------------------
//
// The new device generates a request; the existing device (which holds the
// account key) reads the fingerprints, a person compares them, and only then does
// it sign. The signed credential travels back over a channel that already
// authenticates the account.

// This device's request, for the other device to endorse. NULL `out` for size.
VEIL_API int veil_linking_request(const void* handle, uint8_t* out, size_t out_size);

// Reads a request into `fingerprint` (4 groups of 4 hex, NUL-terminated) and the
// account it names. Either output may be NULL.
VEIL_API int veil_read_linking_request(const uint8_t* data, size_t size,
                                       char* user_id, size_t user_id_size,
                                       char* fingerprint, size_t fingerprint_size);

// Signs an endorsement for another device. NULL `out` for size.
//
// Only an engine holding the account identity can do this, which is what makes
// linking an act of the account rather than of the relay.
VEIL_API int veil_approve_linking(const void* handle,
                                  const uint8_t* request, size_t request_size,
                                  uint64_t issued_at,
                                  uint8_t* out, size_t out_size);

// 32 bytes: the account signing key, for a UI that needs to verify a credential
// or a member list without owning the account.
VEIL_API int veil_account_sign_public(const void* handle, uint8_t* out, size_t out_size);

// Accepts an invitation, against the founder's device signing key.
//
// On success the group is usable immediately: the payload carries the founder's
// chain, so there is no second round trip before the first message can be read.
// `out_group_id` receives a NUL-terminated id; a NULL `out_group_id` is allowed.
VEIL_API int veil_accept_invite(void* handle, const uint8_t* data, size_t size,
                                const char* expected_founder,
                                const uint8_t* founder_sign_pub,
                                char* out_group_id, size_t out_size);

#ifdef __cplusplus
// The device signing key a peer's credential vouches for, or VEIL_NO_SESSION.
//
// This is what an invitation is verified against: the key the peer's credential
// carries, which is the peer this client verified during the handshake rather
// than whoever sent the bytes.
VEIL_API int veil_peer_device_sign_pub(const void* handle, const char* peer,
                                       uint8_t* out, size_t out_size);

}  // extern "C"
#endif

#endif  // VEIL_C_H
