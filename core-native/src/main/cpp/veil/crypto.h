// Veil - thin wrappers over the vendored Monocypher primitives.
//
// Everything here is a *primitive*. Protocol logic lives one layer up in
// x3dh.cpp / ratchet.cpp. Keeping the split explicit makes it obvious which
// code we wrote and which code we merely bind to.
#ifndef VEIL_CRYPTO_H
#define VEIL_CRYPTO_H

#include <cstddef>
#include <cstdint>

#include "veil/common.h"

namespace veil::crypto {

// ---- Diffie-Hellman ----------------------------------------------------
// Fills `pub` with the Curve25519 public key for `priv`.
void x25519_keypair(uint8_t pub[kKeySize], const uint8_t priv[kKeySize]);

// Computes the raw Curve25519 shared secret. Returns false when the peer's
// public key is a low-order point (all-zero output), which would otherwise
// silently produce a predictable session key.
bool x25519(uint8_t shared[kKeySize],
            const uint8_t priv[kKeySize],
            const uint8_t peer_pub[kKeySize]);

// Generates a fresh Curve25519 key pair from the platform CSPRNG.
bool x25519_generate(uint8_t pub[kKeySize], uint8_t priv[kKeySize]);

// ---- Symmetric AEAD ----------------------------------------------------
// XChaCha20-Poly1305. `ad` is authenticated but not encrypted.
void aead_encrypt(uint8_t* cipher,
                  uint8_t mac[kMacSize],
                  const uint8_t key[kKeySize],
                  const uint8_t nonce[kNonceSize],
                  const uint8_t* ad, size_t ad_size,
                  const uint8_t* plain, size_t plain_size);

// Returns false on authentication failure. On failure `plain` is wiped and
// must not be used.
bool aead_decrypt(uint8_t* plain,
                  const uint8_t mac[kMacSize],
                  const uint8_t key[kKeySize],
                  const uint8_t nonce[kNonceSize],
                  const uint8_t* ad, size_t ad_size,
                  const uint8_t* cipher, size_t cipher_size);

// ---- Key derivation ----------------------------------------------------
// HKDF-SHA512. `okm_size` may be any length up to 64 * 255.
void hkdf(uint8_t* okm, size_t okm_size,
          const uint8_t* ikm, size_t ikm_size,
          const uint8_t* salt, size_t salt_size,
          const uint8_t* info, size_t info_size);

// HMAC-SHA512, truncated to 32 bytes. Used by the symmetric ratchet, where
// only 32 bytes of output are ever needed.
void hmac_sha512_32(uint8_t out[32],
                    const uint8_t key[kKeySize],
                    const uint8_t* message, size_t message_size);

// ---- Hashing -----------------------------------------------------------
void blake2b(uint8_t* out, size_t out_size,
             const uint8_t* message, size_t message_size);

// ---- Password key derivation -------------------------------------------
//
// Argon2id, for turning a password into an encryption key.
//
// The password never leaves the device it was typed on: what goes to a server is
// the *output*, encrypted under this key. So the server cannot verify a password
// because it never sees one, and a database leak hands an attacker an Argon2id
// result rather than a hash to compare against - which is the whole reason
// Argon2 exists.
//
// The cost is that password strength is the only defence against an offline
// attack on a stolen blob. Argon2id makes each guess expensive; it cannot make a
// short password long.
struct Argon2Params {
    // Memory in KiB. 64 MiB is the OWASP minimum for Argon2id and is what a
    // browser can afford once, at login.
    uint32_t memory_kib = 64 * 1024;
    uint32_t passes = 3;
    uint32_t lanes = 2;
};

// Derives `out_size` bytes from a password and a salt.
//
// `salt` must be at least 8 bytes and should be per-account; a shared salt lets
// one precomputation attack every account at once.
//
// Returns false when the parameters are outside what this build supports, rather
// than silently using weaker ones: a caller that asked for 1 GiB and got 64 MiB
// would believe its ciphertext was stronger than it is.
bool argon2id(uint8_t* out, size_t out_size,
              const uint8_t* password, size_t password_size,
              const uint8_t* salt, size_t salt_size,
              const Argon2Params& params = Argon2Params{});

// The largest memory cost this build will honour, in KiB. Exposed so a caller can
// ask for "the strongest available" without guessing at a constant.
constexpr uint32_t kArgon2MaxMemoryKiB = 256 * 1024;

// ---- Signatures --------------------------------------------------------
void ed25519_keypair(uint8_t pub[32], uint8_t secret[64], const uint8_t seed[32]);
void ed25519_sign(uint8_t sig[kSigSize],
                  const uint8_t secret[64],
                  const uint8_t* message, size_t message_size);
bool ed25519_verify(const uint8_t sig[kSigSize],
                    const uint8_t pub[32],
                    const uint8_t* message, size_t message_size);

// ---- Cleanup -----------------------------------------------------------
// Overwrites `n` bytes in place in a way the optimiser will not elide.
inline void wipe_secret(void* p, size_t n) { veil::wipe(p, n); }

}  // namespace veil::crypto

#endif  // VEIL_CRYPTO_H
