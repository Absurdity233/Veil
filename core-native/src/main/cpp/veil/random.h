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

}  // namespace veil

#endif  // VEIL_RANDOM_H
