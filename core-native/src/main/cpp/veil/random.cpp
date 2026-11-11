#include "veil/random.h"

#include <cerrno>
#include <cstdio>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#endif

namespace veil {
namespace {

#if !defined(_WIN32)
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

bool secure_random(void* out, size_t n) {
    if (n == 0) return true;
    if (out == nullptr) return false;

#if defined(_WIN32)
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
