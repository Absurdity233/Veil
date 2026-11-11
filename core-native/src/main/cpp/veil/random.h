// Veil - cryptographically secure randomness.
#ifndef VEIL_RANDOM_H
#define VEIL_RANDOM_H

#include <cstddef>
#include <cstdint>

namespace veil {

// Fills `out` with `n` bytes from the platform CSPRNG.
// Returns false if no secure source was available; callers must not
// continue with a partially filled buffer in that case.
bool secure_random(void* out, size_t n);

// An external entropy source, used where the platform offers no CSPRNG the
// engine can call directly.
//
// WebAssembly is the case this exists for: a wasm module has no syscall, no
// /dev/urandom and no BCrypt, so the only entropy available is what the host
// JavaScript hands in through crypto.getRandomValues(). A no-op on every other
// platform, where the built-in source is used and this is never consulted.
//
// Returns non-zero on success. A callback that returns 0 is treated as "no
// entropy available", and key generation fails rather than proceeding with a
// predictable buffer.
using RandomSource = int (*)(uint8_t* buf, size_t len);

// Installs (or, with nullptr, removes) the external source.
void set_platform_random_source(RandomSource fn);

}  // namespace veil

#endif  // VEIL_RANDOM_H