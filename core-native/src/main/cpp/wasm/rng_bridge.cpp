// Veil - entropy bridge for the WebAssembly build.
//
// A wasm module has no syscall, no /dev/urandom and no BCrypt. The only
// entropy available is what the host page supplies through
// crypto.getRandomValues(), which is the browser's CSPRNG and the right answer
// here: it is seeded by the OS and is what the platform uses for its own keys.
//
// The bridge is an explicit install, not a constructor. A constructor would
// run during module initialisation, before the JavaScript side has had a chance
// to define the fill function, and the failure mode of that ordering bug is
// "keys generated from an empty buffer".
#include <emscripten.h>

#include "veil/random.h"
#include "veil/veil_c.h"

// Implemented on the JavaScript side of the module. Returns 1 when it filled
// the buffer, 0 otherwise; the C side treats 0 as "no entropy", which fails key
// generation rather than continuing with a predictable buffer.
EM_JS(int, veil_js_fill_random, (uint8_t* buf, size_t len), {
    try {
        // crypto.getRandomValues has a 64 KiB per-call cap. Nothing in this
        // engine asks for more than 32 bytes at a time, but chunking is the
        // kind of thing that silently produces a short read if it is missing.
        var remaining = len;
        var offset = buf;
        while (remaining > 0) {
            var chunk = Math.min(remaining, 65536);
            var view = HEAPU8.subarray(offset, offset + chunk);
            if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
                return 0;
            }
            crypto.getRandomValues(view);
            offset += chunk;
            remaining -= chunk;
        }
        return 1;
    } catch (e) {
        return 0;
    }
});

namespace {

int webRandom(uint8_t* buf, size_t len) {
    if (buf == nullptr || len == 0) return 0;
    return veil_js_fill_random(buf, len);
}

}  // namespace

extern "C" {

// Called by the JavaScript loader immediately after the module resolves.
// Until this runs, every key-generating call fails rather than falling back to
// anything predictable.
VEIL_API int veil_install_web_rng(void) {
    veil::set_platform_random_source(webRandom);
    return 1;
}

// Reports whether entropy is actually available, so the loader can refuse to
// start in a context where crypto.getRandomValues is missing (an insecure
// origin, for instance: browsers disable it outside https and localhost).
VEIL_API int veil_web_rng_ready(void) {
    uint8_t probe[16] = {0};
    return veil_js_fill_random(probe, sizeof(probe));
}

}  // extern "C"