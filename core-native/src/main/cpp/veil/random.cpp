#include "veil/random.h"

#include <cerrno>
#include <cstdio>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__EMSCRIPTEN__)
// A wasm module has no syscall and no filesystem here. Entropy arrives through
// the host callback installed with set_platform_random_source.
#else
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#endif

namespace veil {
namespace {

// The external source, when one has been installed. Only the Emscripten build
// needs it; keeping the variable on every platform costs a pointer and makes
// the code path identical, which is easier to reason about than a #ifdef
// ladder inside secure_random().
RandomSource g_external_source = nullptr;

#if !defined(_WIN32) && !defined(__EMSCRIPTEN__)
bool read_urandom(void* out, size_t n) {
    int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;

    uint8_t* p = static_cast<uint8_t*>(out);
    size_t remaining = n;
    while (remaining > 0) {
        ssize_t got = ::read(fd, p, remaining);
        if (got < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return false;
        }
        if (got == 0) {
            ::close(fd);
            return false;
        }
        p += got;
        remaining -= static_cast<size_t>(got);
    }
    ::close(fd);
    return true;
}
#endif

}  // namespace

void set_platform_random_source(RandomSource fn) {
    g_external_source = fn;
}

bool secure_random(void* out, size_t n) {
    if (n == 0) return true;
    if (out == nullptr) return false;

    // An installed source takes precedence everywhere, not only on wasm: a
    // host that has gone to the trouble of supplying entropy is usually doing
    // so because it knows something the generic path does not.
    if (g_external_source != nullptr) {
        return g_external_source(static_cast<uint8_t*>(out), n) != 0;
    }

#if defined(__EMSCRIPTEN__)
    // No built-in source exists in wasm. Failing here is the correct answer:
    // generating keys from an uninitialised buffer would be worse than
    // refusing to start.
    return false;
#elif defined(_WIN32)
    NTSTATUS st = ::BCryptGenRandom(nullptr, static_cast<PUCHAR>(out),
                                    static_cast<ULONG>(n),
                                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(st);
#elif defined(__ANDROID__)
    // getrandom(2) only exists from API 28 and this module supports API 24.
    // /dev/urandom is seeded by the kernel before userspace starts on every
    // Android release, so it is the portable choice here.
    return read_urandom(out, n);
#elif defined(__linux__)
    uint8_t* p = static_cast<uint8_t*>(out);
    size_t remaining = n;
    while (remaining > 0) {
        ssize_t got = ::getrandom(p, remaining, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            return read_urandom(out, n);
        }
        p += got;
        remaining -= static_cast<size_t>(got);
    }
    return true;
#else
    return read_urandom(out, n);
#endif
}

}  // namespace veil
