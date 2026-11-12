#include "veil/crypto.h"

#include <cstring>

#include "veil/random.h"

extern "C" {
#include "monocypher.h"
#include "monocypher-ed25519.h"
}

namespace veil::crypto {
namespace {

// Monocypher's AEAD wrapper takes the MAC separately from the ciphertext.
// We expose the same shape so callers can serialise them however they like.

}  // namespace

void x25519_keypair(uint8_t pub[kKeySize], const uint8_t priv[kKeySize]) {
    ::crypto_x25519_public_key(pub, priv);
}

bool x25519(uint8_t shared[kKeySize],
            const uint8_t priv[kKeySize],
            const uint8_t peer_pub[kKeySize]) {
    ::crypto_x25519(shared, priv, peer_pub);

    // crypto_x25519() returns an all-zero shared secret for low-order points
    // instead of failing, so the check has to happen here.
    uint8_t acc = 0;
    for (size_t i = 0; i < kKeySize; ++i) acc |= shared[i];
    if (acc == 0) {
        veil::wipe(shared, kKeySize);
        return false;
    }
    return true;
}

bool x25519_generate(uint8_t pub[kKeySize], uint8_t priv[kKeySize]) {
    if (!secure_random(priv, kKeySize)) return false;
    ::crypto_x25519_public_key(pub, priv);
    return true;
}

void aead_encrypt(uint8_t* cipher,
                  uint8_t mac[kMacSize],
                  const uint8_t key[kKeySize],
                  const uint8_t nonce[kNonceSize],
                  const uint8_t* ad, size_t ad_size,
                  const uint8_t* plain, size_t plain_size) {
    ::crypto_aead_lock(cipher, mac, key, nonce, ad, ad_size, plain, plain_size);
}

bool aead_decrypt(uint8_t* plain,
                  const uint8_t mac[kMacSize],
                  const uint8_t key[kKeySize],
                  const uint8_t nonce[kNonceSize],
                  const uint8_t* ad, size_t ad_size,
                  const uint8_t* cipher, size_t cipher_size) {
    if (::crypto_aead_unlock(plain, mac, key, nonce, ad, ad_size, cipher, cipher_size) != 0) {
        veil::wipe(plain, cipher_size);
        return false;
    }
    return true;
}

void hkdf(uint8_t* okm, size_t okm_size,
          const uint8_t* ikm, size_t ikm_size,
          const uint8_t* salt, size_t salt_size,
          const uint8_t* info, size_t info_size) {
    ::crypto_sha512_hkdf(okm, okm_size, ikm, ikm_size, salt, salt_size, info, info_size);
}

void hmac_sha512_32(uint8_t out[32],
                    const uint8_t key[kKeySize],
                    const uint8_t* message, size_t message_size) {
    uint8_t full[64];
    ::crypto_sha512_hmac(full, key, kKeySize, message, message_size);
    std::memcpy(out, full, 32);
    veil::wipe(full, sizeof(full));
}

void blake2b(uint8_t* out, size_t out_size,
             const uint8_t* message, size_t message_size) {
    ::crypto_blake2b(out, out_size, message, message_size);
}

bool argon2id(uint8_t* out, size_t out_size,
              const uint8_t* password, size_t password_size,
              const uint8_t* salt, size_t salt_size,
              const Argon2Params& params) {
    if (out == nullptr || out_size == 0) return false;
    if (password == nullptr || password_size == 0) return false;
    // A short salt defeats the point: two accounts with the same password would
    // derive the same key, and one precomputation would attack both.
    if (salt == nullptr || salt_size < 8) return false;

    // Refuse rather than silently downgrade. A caller that asked for parameters
    // this build cannot honour would otherwise believe its ciphertext is stronger
    // than it is, which is the one thing it cannot check for itself.
    if (params.memory_kib < 8 * params.lanes) return false;
    if (params.memory_kib > kArgon2MaxMemoryKiB) return false;
    if (params.passes < 1) return false;
    if (params.lanes < 1 || params.lanes > 255) return false;

    crypto_argon2_config config{};
    config.algorithm = CRYPTO_ARGON2_ID;
    config.nb_blocks = params.memory_kib;
    config.nb_passes = params.passes;
    config.nb_lanes = params.lanes;

    crypto_argon2_inputs inputs{};
    inputs.pass = password;
    inputs.pass_size = static_cast<uint32_t>(password_size);
    inputs.salt = salt;
    inputs.salt_size = static_cast<uint32_t>(salt_size);

    // No secret key and no associated data: both would have to be shared with
    // whoever needs to derive the same key, which makes them part of the salt
    // with extra steps.
    crypto_argon2_extras extras{};
    extras.key = nullptr;
    extras.key_size = 0;
    extras.ad = nullptr;
    extras.ad_size = 0;

    // The work area is the memory cost, and Argon2 writes 1024 bytes per block.
    std::vector<uint8_t> work(static_cast<size_t>(params.memory_kib) * 1024);

    ::crypto_argon2(out, static_cast<uint32_t>(out_size), work.data(),
                    config, inputs, extras);

    // The work area holds derived state for the whole cost of the run, which is
    // as close to the password as this function gets. Wiped rather than left for
    // the allocator to hand to something else.
    veil::wipe(work.data(), work.size());
    return true;
}

void ed25519_keypair(uint8_t pub[32], uint8_t secret[64], const uint8_t seed[32]) {
    uint8_t seed_copy[32];
    std::memcpy(seed_copy, seed, 32);
    // crypto_ed25519_key_pair() wipes the seed it is handed, hence the copy.
    ::crypto_ed25519_key_pair(secret, pub, seed_copy);
    veil::wipe(seed_copy, sizeof(seed_copy));
}

void ed25519_sign(uint8_t sig[kSigSize],
                  const uint8_t secret[64],
                  const uint8_t* message, size_t message_size) {
    ::crypto_ed25519_sign(sig, secret, message, message_size);
}

bool ed25519_verify(const uint8_t sig[kSigSize],
                    const uint8_t pub[32],
                    const uint8_t* message, size_t message_size) {
    return ::crypto_ed25519_check(sig, pub, message, message_size) == 0;
}

}  // namespace veil::crypto
