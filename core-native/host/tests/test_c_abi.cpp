// Veil - tests for the C ABI.
//
// The C ABI is what the desktop client and the web client talk to, so it has to
// be tested the way those clients use it: through the header, with no C++
// visible, and with the caller owning every buffer.
//
// The failure modes this suite is aimed at are the ones a language boundary
// hides: a buffer that is one byte too small, a call that reports success but
// writes nothing, a secret left in a caller buffer after it was freed.
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>

#include "veil/veil_c.h"

namespace {

int g_checks = 0;
int g_failures = 0;

void check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) {
        ++g_failures;
        std::printf("  FAIL  %s\n", what);
    }
}

void section(const char* name) { std::printf("\n== %s ==\n", name); }

// A buffer the caller owns, the way JNA and wasm both use the ABI.
struct Buf {
    uint8_t data[8192];
    size_t len = 0;
};

// The "ask for the size, then allocate" pattern the header documents.
int callMeasured(int (*fn)(const void*, uint8_t*, size_t), const void* handle, Buf& out) {
    const int need = fn(handle, nullptr, 0);
    if (need < 0) return need;
    if (static_cast<size_t>(need) > sizeof(out.data)) return VEIL_ERR_BUFFER_TOO_SMALL;

    const int written = fn(handle, out.data, sizeof(out.data));
    if (written < 0) return written;
    out.len = static_cast<size_t>(written);
    return VEIL_OK;
}

}  // namespace

int main() {
    std::printf("veil C ABI tests\n");

    section("version and lifetime");
    {
        int major = -1, minor = -1, patch = -1;
        veil_version(&major, &minor, &patch);
        check(major == 0 && minor == 2 && patch == 0, "version reports itself");

        void* engine = veil_engine_new();
        check(engine != nullptr, "engine created");
        veil_engine_free(engine);
        veil_engine_free(nullptr);  // must not crash

        // A restore with the wrong length is refused rather than reading past
        // the caller's buffer.
        uint8_t short_blob[32] = {0};
        check(veil_engine_restore(short_blob, sizeof(short_blob)) == nullptr,
              "restore with a short blob refused");
    }

    section("null handles and arguments are refused, not crashed on");
    {
        uint8_t buf[128];
        char text[64];
        size_t len = 0;

        check(veil_identity_public(nullptr, buf, sizeof(buf)) == VEIL_ERR_NULL_HANDLE,
              "null handle, identity");
        check(veil_identity_secrets(nullptr, buf, sizeof(buf)) == VEIL_ERR_NULL_HANDLE,
              "null handle, secrets");
        check(veil_rotate_prekeys(nullptr, buf, sizeof(buf)) == VEIL_ERR_NULL_HANDLE,
              "null handle, rotate");
        check(veil_session_state(nullptr, "peer") == VEIL_ERR_NULL_HANDLE,
              "null handle, state");
        check(veil_safety_number(nullptr, "peer", text, sizeof(text)) == VEIL_ERR_NULL_HANDLE,
              "null handle, safety number");

        void* engine = veil_engine_new();
        check(veil_identity_public(engine, nullptr, 0) == VEIL_IDENTITY_PUBLIC_SIZE,
              "size query on identity");
        check(veil_sign_challenge(engine, nullptr, 1, buf, sizeof(buf)) == VEIL_ERR_NULL_ARG,
              "null challenge refused");
        check(veil_establish_outbound(engine, "peer", nullptr, 0) == VEIL_ERR_NULL_ARG,
              "null bundle refused");
        check(veil_decrypt(engine, "peer", nullptr, 0, buf, sizeof(buf), &len) == VEIL_ERR_NULL_ARG,
              "null frame refused");
        veil_engine_free(engine);
    }

    section("identity round-trip");
    {
        void* engine = veil_engine_new();

        uint8_t secrets[VEIL_IDENTITY_SECRET_SIZE];
        Buf pub;
        Buf binding;

        check(veil_identity_secrets(engine, secrets, sizeof(secrets)) ==
                  VEIL_IDENTITY_SECRET_SIZE,
              "secrets size");

        int n = veil_identity_public(engine, pub.data, sizeof(pub.data));
        check(n == VEIL_IDENTITY_PUBLIC_SIZE, "public size");
        pub.len = static_cast<size_t>(n);

        n = veil_identity_binding(engine, binding.data, sizeof(binding.data));
        check(n == VEIL_IDENTITY_BINDING_SIZE, "binding size");
        binding.len = static_cast<size_t>(n);

        // A buffer one byte too small must be refused, not silently truncated.
        uint8_t tight[63];
        check(veil_identity_public(engine, tight, sizeof(tight)) == VEIL_ERR_BUFFER_TOO_SMALL,
              "one-byte-short buffer refused");

        // Restoring from the exported secrets must yield the same identity.
        void* restored = veil_engine_restore(secrets, sizeof(secrets));
        check(restored != nullptr, "restore from exported secrets");

        uint8_t pub2[VEIL_IDENTITY_PUBLIC_SIZE];
        check(veil_identity_public(restored, pub2, sizeof(pub2)) == VEIL_IDENTITY_PUBLIC_SIZE,
              "restored public size");
        check(std::memcmp(pub.data, pub2, VEIL_IDENTITY_PUBLIC_SIZE) == 0,
              "restored identity is byte-identical");

        veil_engine_free(restored);
        veil_engine_free(engine);
    }

    section("challenge signing");
    {
        void* engine = veil_engine_new();
        const uint8_t challenge[32] = {1, 2, 3};
        uint8_t sig[VEIL_CHALLENGE_SIG_SIZE];
        uint8_t tight[VEIL_CHALLENGE_SIG_SIZE - 1];

        check(veil_sign_challenge(engine, challenge, sizeof(challenge), sig, sizeof(sig)) ==
                  VEIL_CHALLENGE_SIG_SIZE,
              "signature size");
        check(veil_sign_challenge(engine, challenge, sizeof(challenge), tight, sizeof(tight)) ==
                  VEIL_ERR_BUFFER_TOO_SMALL,
              "short buffer refused");

        // The signature must be deterministic: two calls over the same bytes
        // produce the same signature, which is what makes it verifiable.
        uint8_t sig2[VEIL_CHALLENGE_SIG_SIZE];
        check(veil_sign_challenge(engine, challenge, sizeof(challenge), sig2, sizeof(sig2)) ==
                  VEIL_CHALLENGE_SIG_SIZE,
              "second signature size");
        check(std::memcmp(sig, sig2, sizeof(sig)) == 0, "signatures agree");

        veil_engine_free(engine);
    }

    section("prekey set and state, with the measure contract");
    {
        void* engine = veil_engine_new();

        Buf set;
        int n = veil_rotate_prekeys(engine, set.data, sizeof(set.data));
        check(n > 0, "rotate writes a public set");
        set.len = static_cast<size_t>(n);

        // The layout the relay stores: [4] id | [32] pub | [64] sig | [4] count
        const uint32_t signed_id = (uint32_t(set.data[0]) << 24) | (uint32_t(set.data[1]) << 16) |
                                   (uint32_t(set.data[2]) << 8) | uint32_t(set.data[3]);
        check(signed_id == 1, "first signed prekey id is 1");

        const size_t count_off = 4 + 32 + 64;
        const uint32_t count = (uint32_t(set.data[count_off]) << 24) |
                               (uint32_t(set.data[count_off + 1]) << 16) |
                               (uint32_t(set.data[count_off + 2]) << 8) |
                               uint32_t(set.data[count_off + 3]);
        check(count == 20, "a full batch of one-time keys");

        const int measured = veil_measure_prekey_state(engine);
        check(measured > 0, "prekey state has a measurable size");

        Buf state;
        n = veil_export_prekey_state(engine, state.data, sizeof(state.data));
        check(n == measured, "export matches the measured size");
        state.len = static_cast<size_t>(n);

        // Continuing from the restored state must not reuse the id.
        void* restored = veil_engine_new();
        check(veil_import_prekey_state(restored, state.data, state.len) == VEIL_OK,
              "prekey state imports");

        Buf set2;
        n = veil_rotate_prekeys(restored, set2.data, sizeof(set2.data));
        check(n > 0, "rotate after restore");
        const uint32_t next_id = (uint32_t(set2.data[0]) << 24) | (uint32_t(set2.data[1]) << 16) |
                                 (uint32_t(set2.data[2]) << 8) | uint32_t(set2.data[3]);
        check(next_id == 2, "id keeps moving forward after a restart");

        // The refill query is reachable across the boundary. "Fewer than N unspent"
        // is the trigger, and a rotation leaves two generations of one-time keys
        // alive (current + retired, so a peer holding the previous bundle can
        // still complete), so after a second rotation the unspent count is 40.
        check(veil_needs_prekey_refill(restored, 40) == 0,
              "two live generations are not due below a threshold of 40");
        check(veil_needs_prekey_refill(restored, 41) == 1,
              "the same set is due at a threshold of 41");

        veil_engine_free(restored);
        veil_engine_free(engine);
    }

    section("a session across two engines");
    {
        void* alice = veil_engine_new();
        void* bob = veil_engine_new();

        Buf bob_set;
        int n = veil_rotate_prekeys(bob, bob_set.data, sizeof(bob_set.data));
        check(n > 0, "bob publishes prekeys");
        bob_set.len = static_cast<size_t>(n);

        // Build the bundle the relay would hand out, from the public set.
        // 64 identity + 4 id + 32 pub + 64 sig + 1 flag + 4 ot id + 32 ot pub = 201
        uint8_t bundle[256];
        size_t off = 0;
        uint8_t bob_pub[VEIL_IDENTITY_PUBLIC_SIZE];
        veil_identity_public(bob, bob_pub, sizeof(bob_pub));
        std::memcpy(bundle, bob_pub, 64); off += 64;

        // signed id | signed pub | signature, straight from the set
        const size_t count_off = 4 + 32 + 64;
        const uint32_t count = (uint32_t(bob_set.data[count_off]) << 24) |
                               (uint32_t(bob_set.data[count_off + 1]) << 16) |
                               (uint32_t(bob_set.data[count_off + 2]) << 8) |
                               uint32_t(bob_set.data[count_off + 3]);
        check(count == 20, "bob has one-time keys");

        std::memcpy(bundle + off, bob_set.data, 100); off += 100;  // id|pub|sig
        bundle[off++] = 1;  // has_one_time
        std::memcpy(bundle + off, bob_set.data + count_off + 4, 4 + 32); off += 4 + 32;

        check(veil_establish_outbound(alice, "bob", bundle, off) == VEIL_OK,
              "alice establishes from the bundle");
        check(veil_session_state(alice, "bob") == 2, "alice reports a ready session");
        check(veil_session_state(alice, "nobody") == 0, "an unknown label is NoPeer");

        // Encrypt, then decrypt on the other side.
        const char* text = "the veil parts";
        uint8_t frame[512];
        n = veil_encrypt(alice, "bob", reinterpret_cast<const uint8_t*>(text),
                         std::strlen(text), frame, sizeof(frame));
        check(n > 0, "encrypt produces a frame");

        // The ABI asks for a buffer of the frame size, because the plaintext is
        // always smaller and a probe must not consume the key. A caller that
        // allocates only what it expects to need gets a clear refusal rather
        // than a silently truncated message.
        uint8_t plain[512];
        size_t plain_len = 0;
        const int status = veil_decrypt(bob, "alice", frame, static_cast<size_t>(n),
                                        plain, sizeof(plain), &plain_len);
        check(status == VEIL_OK, "bob decrypts the first frame");
        check(plain_len == std::strlen(text), "plaintext length matches");
        check(std::memcmp(plain, text, plain_len) == 0, "plaintext matches");

        // The plaintext wipes the local copy, but the caller's buffer is its
        // own: it still holds what was written, which is the documented
        // contract.
        check(plain[0] == 't', "caller buffer survives the call");

        // A second, larger frame: the buffer requirement scales with the frame,
        // not with the message.
        const std::string longer(700, 'x');
        uint8_t big_frame[1024];
        const int big_n = veil_encrypt(alice, "bob",
                                       reinterpret_cast<const uint8_t*>(longer.data()),
                                       longer.size(), big_frame, sizeof(big_frame));
        check(big_n > 0, "a large message encrypts");

        uint8_t too_small[64];
        size_t needed = 0;
        check(veil_decrypt(bob, "alice", big_frame, static_cast<size_t>(big_n),
                           too_small, sizeof(too_small), &needed) == VEIL_ERR_BUFFER_TOO_SMALL,
              "a buffer smaller than the frame is refused");
        check(needed == static_cast<size_t>(big_n), "the refusal reports the required size");

        uint8_t big_plain[1024];
        size_t big_len = 0;
        check(veil_decrypt(bob, "alice", big_frame, static_cast<size_t>(big_n),
                           big_plain, sizeof(big_plain), &big_len) == VEIL_OK,
              "the large frame decrypts on a second attempt");
        check(big_len == longer.size(), "the large plaintext has the right length");

        veil_engine_free(alice);
        veil_engine_free(bob);
    }

    section("a size probe does not consume the message key");
    {
        // Decrypting advances the ratchet and spends the key. A "how big is
        // the plaintext" call that actually decrypted would leave the caller
        // with a length and an already-consumed frame, and the real call would
        // come back as a duplicate. This is the exact bug the JNA binding hit.
        void* alice = veil_engine_new();
        void* bob = veil_engine_new();

        Buf set;
        int n = veil_rotate_prekeys(bob, set.data, sizeof(set.data));
        check(n > 0, "bob publishes prekeys");

        uint8_t bob_pub[VEIL_IDENTITY_PUBLIC_SIZE];
        veil_identity_public(bob, bob_pub, sizeof(bob_pub));

        const size_t count_off = 4 + 32 + 64;
        uint8_t bundle[256];
        size_t off = 0;
        std::memcpy(bundle, bob_pub, 64); off += 64;
        std::memcpy(bundle + off, set.data, 100); off += 100;
        bundle[off++] = 1;
        std::memcpy(bundle + off, set.data + count_off + 4, 36); off += 36;
        check(veil_establish_outbound(alice, "bob", bundle, off) == VEIL_OK,
              "session established for the probe test");

        uint8_t frame[512];
        const char* text = "probe me";
        const int frame_len = veil_encrypt(alice, "bob",
                                           reinterpret_cast<const uint8_t*>(text),
                                           std::strlen(text), frame, sizeof(frame));
        check(frame_len > 0, "frame produced");

        // Probe: reports the bound, changes nothing.
        size_t probe = 0;
        check(veil_decrypt(bob, "alice", frame, static_cast<size_t>(frame_len),
                           nullptr, 0, &probe) == VEIL_OK,
              "probe succeeds");
        check(probe == static_cast<size_t>(frame_len),
              "probe reports the frame size as the safe bound");

        // A second probe must still succeed: the first one consumed nothing.
        size_t probe2 = 0;
        check(veil_decrypt(bob, "alice", frame, static_cast<size_t>(frame_len),
                           nullptr, 0, &probe2) == VEIL_OK,
              "a second probe also succeeds");
        check(probe2 == probe, "both probes agree");

        // And the real call still decrypts.
        uint8_t plain[512];
        size_t plain_len = 0;
        check(veil_decrypt(bob, "alice", frame, static_cast<size_t>(frame_len),
                           plain, sizeof(plain), &plain_len) == VEIL_OK,
              "the real call decrypts after two probes");
        check(std::memcmp(plain, text, plain_len) == 0, "content is intact");

        veil_engine_free(alice);
        veil_engine_free(bob);
    }

    section("safety number is a string across the boundary");
    {
        void* engine = veil_engine_new();
        char out[VEIL_SAFETY_NUMBER_MAX];

        check(veil_safety_number(engine, "nobody", out, sizeof(out)) == VEIL_NO_SESSION,
              "no session, no number");

        // Failure leaves the caller's buffer alone, so a caller that ignores
        // the status and prints it gets its own initialised bytes rather than
        // a partially written string.
        out[0] = 'X';
        check(veil_safety_number(engine, "nobody", out, sizeof(out)) == VEIL_NO_SESSION,
              "second call also reports no session");
        check(out[0] == 'X', "output untouched on failure");

        veil_engine_free(engine);
    }

    section("the peer id is a bounded C string");
    {
        void* engine = veil_engine_new();

        // 200 characters: longer than any real label, refused rather than
        // truncated to a prefix that would bind the wrong identity.
        char long_id[201];
        std::memset(long_id, 'a', 200);
        long_id[200] = 0;
        check(veil_session_state(engine, long_id) == VEIL_ERR_BAD_PARAM,
              "over-long peer id refused");

        check(veil_session_state(engine, nullptr) == VEIL_ERR_BAD_PARAM,
              "null peer id refused");

        veil_engine_free(engine);
    }

    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}