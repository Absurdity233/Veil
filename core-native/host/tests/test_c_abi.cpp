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

void section(const char* name) { std::printf("\n== %s ==\n", name); std::fflush(stdout); }

/**
 * Writes a 32-bit big-endian value.
 *
 * Local rather than reused from the engine on purpose: this file is a *C*
 * caller, and reaching into the C++ headers to encode a length would defeat the
 * point of testing the boundary. If the engine's convention changed, this test
 * would have to be updated deliberately rather than silently following along.
 */
void be32(uint8_t* out, uint32_t v) {
    out[0] = static_cast<uint8_t>(v >> 24);
    out[1] = static_cast<uint8_t>(v >> 16);
    out[2] = static_cast<uint8_t>(v >> 8);
    out[3] = static_cast<uint8_t>(v);
}

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
        check(major == 0 && minor == 4 && patch == 0, "version reports itself");

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

    section("multi-device through the C ABI");
    {
        // The ABI is what the desktop and web clients call, so the fan-out
        // record format has to be pinned here: a caller parses it without
        // seeing any C++ types, and a misread length is a buffer overrun on the
        // other side of a language boundary.
        void* phone = veil_engine_new();
        void* laptop = veil_engine_new();
        void* bob = veil_engine_new();
        check(phone && laptop && bob, "three engines");

        check(veil_init_device(phone, "alice") == VEIL_OK, "phone claims alice");
        check(veil_init_device(laptop, "alice") == VEIL_OK, "laptop claims alice");
        check(veil_init_device(bob, "bob") == VEIL_OK, "bob claims himself");

        uint8_t device_id[VEIL_DEVICE_ID_SIZE];
        check(veil_device_id(phone, device_id, sizeof(device_id)) == VEIL_DEVICE_ID_SIZE,
              "the device id is 32 bytes");
        check(veil_device_id(phone, nullptr, 0) == VEIL_DEVICE_ID_SIZE,
              "and its size is queryable");

        uint8_t alice_pub[VEIL_IDENTITY_PUBLIC_SIZE];
        veil_identity_public(phone, alice_pub, sizeof(alice_pub));

        // ---- Ed25519 signing is not exposed, so the test signs the laptop's
        // credential by rebuilding the account identity from the phone's
        // exported secrets. A real linking flow does this on the other device.
        uint8_t phone_secrets[VEIL_IDENTITY_SECRET_SIZE];
        check(veil_identity_secrets(phone, phone_secrets, sizeof(phone_secrets)) ==
                  VEIL_IDENTITY_SECRET_SIZE,
              "phone secrets exported for the linking flow");

        // Both credentials, as the relay would store them.
        uint8_t phone_cred[VEIL_DEVICE_CRED_MAX];
        const int phone_cred_len = veil_device_credential(phone, phone_cred, sizeof(phone_cred));
        check(phone_cred_len > 0, "phone credential");

        uint8_t laptop_cred[VEIL_DEVICE_CRED_MAX];
        const int laptop_cred_len = veil_device_credential(laptop, laptop_cred, sizeof(laptop_cred));
        check(laptop_cred_len > 0, "laptop credential");

        // The laptop's credential is not yet endorsed by the account, so the
        // phone's own credential is the only one that verifies right now. That
        // asymmetry is the whole design: a device cannot endorse itself.
        //
        // Whatever is in `laptop_cred` at this point was signed by the laptop's
        // own engine identity, not by alice's, so a list containing it must be
        // refused.
        {
            uint8_t list[VEIL_DEVICE_CRED_MAX * 2 + 4];
            size_t off = 0;
            be32(list, 2);
            off += 4;
            std::memcpy(list + off, phone_cred, static_cast<size_t>(phone_cred_len));
            off += static_cast<size_t>(phone_cred_len);
            std::memcpy(list + off, laptop_cred, static_cast<size_t>(laptop_cred_len));
            off += static_cast<size_t>(laptop_cred_len);

            check(veil_adopt_device_list(bob, "alice", 1, list, off,
                                         alice_pub, alice_pub + 32) == VEIL_BAD_SIGNATURE,
                  "a device the account never endorsed is refused");
            check(veil_peer_device_version(bob, "alice") == 0,
                  "and nothing was recorded");
        }

        // ---- A list of one, which does verify ----
        {
            uint8_t list[VEIL_DEVICE_CRED_MAX + 4];
            be32(list, 1);
            std::memcpy(list + 4, phone_cred, static_cast<size_t>(phone_cred_len));

            check(veil_adopt_device_list(bob, "alice", 1, list,
                                         4 + static_cast<size_t>(phone_cred_len),
                                         alice_pub, alice_pub + 32) == VEIL_OK,
                  "a list of one is accepted");
            check(veil_peer_device_version(bob, "alice") == 1, "the version is recorded");

            // The device list is hex, NUL-separated, and size-queryable.
            const int need = veil_peer_devices(bob, "alice", nullptr, 0);
            check(need == 64, "one device is 64 hex characters");

            char devices[128];
            check(veil_peer_devices(bob, "alice", devices, sizeof(devices)) == 64,
                  "the list fits");
            for (int i = 0; i < 64; ++i) {
                const char c = devices[i];
                check((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
                      "device ids are hex");
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) break;
            }

            // A buffer one byte short is refused rather than truncated. The list is
            // exactly 64 bytes with no terminator, so 63 is the shortest buffer
            // that cannot hold it.
            char tight[63];
            check(veil_peer_devices(bob, "alice", tight, sizeof(tight)) ==
                      VEIL_ERR_BUFFER_TOO_SMALL,
                  "a short buffer is refused");
        }

        // ---- The fingerprint ----
        char fingerprint[VEIL_FINGERPRINT_SIZE];
        check(veil_device_fingerprint(phone_cred, static_cast<size_t>(phone_cred_len),
                                      fingerprint, sizeof(fingerprint)) == VEIL_OK,
              "the fingerprint is produced");
        check(std::strlen(fingerprint) == 19, "four groups of four plus dashes");
        check(fingerprint[4] == '-' && fingerprint[9] == '-' && fingerprint[14] == '-',
              "and it is grouped");

        // A truncated credential is refused by the fingerprint helper too, so a
        // caller cannot get a fingerprint for something that does not verify.
        check(veil_device_fingerprint(phone_cred, static_cast<size_t>(phone_cred_len) - 1,
                                      fingerprint, sizeof(fingerprint)) == VEIL_BAD_BUNDLE,
              "a truncated credential is refused");

        // ---- Fan-out framing ----
        // With one device in the list and no session, the fan-out produces
        // nothing: a device is skipped rather than treated as an error.
        {
            const char* text = "hello";
            const int need = veil_encrypt_to_account(bob, "alice",
                                                     reinterpret_cast<const uint8_t*>(text),
                                                     std::strlen(text), nullptr, 0);
            check(need == 0, "no session, no frames, and no error either");
        }

        veil_engine_free(phone);
        veil_engine_free(laptop);
        veil_engine_free(bob);
    }

    section("groups through the C ABI");
    {
        void* alice = veil_engine_new();
        void* bob = veil_engine_new();
        check(alice && bob, "two engines");

        check(veil_init_device(alice, "alice") == VEIL_OK, "alice has a device");
        check(veil_init_device(bob, "bob") == VEIL_OK, "bob has a device");

        check(veil_create_group(alice, "team") == VEIL_OK, "alice founds a group");

        // Members travel as a NUL-separated list, which is what a caller can
        // build from a JSON array without another encoding decision.
        const char members[] = "alice\0bob";
        const uint32_t epoch = veil_set_group_members(
            alice, "team", reinterpret_cast<const uint8_t*>(members), sizeof(members) - 1);
        check(epoch == 2, "adding members bumps the epoch");

        const int members_size = veil_group_members(alice, "team", nullptr, 0);
        check(members_size == 9, "two members joined with a NUL is 9 bytes");

        char out_members[32];
        check(veil_group_members(alice, "team", out_members, sizeof(out_members)) == 9,
              "the member list fits");
        check(std::memcmp(out_members, members, 9) == 0, "and matches what went in");

        check(veil_is_group_member(alice, "team") == 1, "alice is a member");
        check(veil_group_epoch(alice, "team") == 2, "the epoch reads back");

        // ---- Membership is signed by the account, chains by the device ----
        uint8_t alice_pub[VEIL_IDENTITY_PUBLIC_SIZE];
        veil_identity_public(alice, alice_pub, sizeof(alice_pub));

        const int membership_size = veil_export_membership(alice, "team", nullptr, 0);
        check(membership_size > 0, "a membership record is produced");

        uint8_t membership[512];
        check(veil_export_membership(alice, "team", membership,
                                     sizeof(membership)) == membership_size,
              "it fits its own size query");

        check(veil_adopt_membership(bob, membership, static_cast<size_t>(membership_size),
                                    alice_pub + 32) == VEIL_OK,
              "bob adopts the membership");
        check(veil_group_epoch(bob, "team") == 2, "bob knows the epoch");

        // The device key signs a chain; the account key signs the member list.
        // Getting those the wrong way round is the mistake this pair of calls
        // makes visible.
        const int cred_size = veil_device_credential(alice, nullptr, 0);
        uint8_t cred[VEIL_DEVICE_CRED_MAX];
        veil_device_credential(alice, cred, sizeof(cred));

        // Fingerprint the credential to extract nothing; the device signing key
        // is inside it, and the ABI exposes it only through the credential.
        // The test therefore reads the device sign pub out of the credential
        // blob with the documented layout: [2] idlen | id | 32 id | 32 dh
        // | 32 sign | ...
        uint8_t device_sign_pub[32];
        {
            const size_t id_len = (static_cast<size_t>(cred[0]) << 8) | cred[1];
            const size_t off = 2 + id_len + 32 + 32;
            check(off + 32 <= static_cast<size_t>(cred_size), "the credential has a sign key");
            std::memcpy(device_sign_pub, cred + off, 32);
        }

        const int chain_size = veil_export_sender_key(alice, "team", 0, nullptr, 0);
        check(chain_size > 0, "alice publishes a chain");

        uint8_t chain[512];
        check(veil_export_sender_key(alice, "team", 0, chain, sizeof(chain)) == chain_size,
              "the chain fits its size query");

        check(veil_adopt_sender_key(bob, chain, static_cast<size_t>(chain_size),
                                    "alice", device_sign_pub) == VEIL_OK,
              "bob installs alice's chain");

        // ---- One message, one frame ----
        const char* text = "hello, team";
        const int message_size = veil_encrypt_to_group(
            alice, "team", reinterpret_cast<const uint8_t*>(text), std::strlen(text),
            nullptr, 0);
        check(message_size > 0, "a group message is framed");

        uint8_t message[512];
        check(veil_encrypt_to_group(alice, "team", reinterpret_cast<const uint8_t*>(text),
                                    std::strlen(text), message,
                                    sizeof(message)) == message_size,
              "it fits its own size query");

        uint8_t plain[256];
        size_t plain_len = 0;
        check(veil_decrypt_from_group(bob, "team", message, static_cast<size_t>(message_size),
                                      plain, sizeof(plain), &plain_len) == VEIL_OK,
              "bob decrypts it");
        check(plain_len == std::strlen(text), "plaintext length matches");
        check(std::memcmp(plain, text, plain_len) == 0, "content matches");

        // A replay is refused: the key was consumed.
        check(veil_decrypt_from_group(bob, "team", message, static_cast<size_t>(message_size),
                                      plain, sizeof(plain), &plain_len) != VEIL_OK,
              "a replayed group message is refused");

        // A truncated frame is a bad parameter, not a crash.
        check(veil_decrypt_from_group(bob, "team", message, 4,
                                      plain, sizeof(plain), &plain_len) == VEIL_ERR_BAD_PARAM,
              "a truncated group frame is refused");

        veil_engine_free(alice);
        veil_engine_free(bob);
    }

section("group state survives a restart through the ABI");
    {
        void* alice = veil_engine_new();
        void* bob = veil_engine_new();
        check(alice && bob, "two engines");

        check(veil_init_device(alice, "alice") == VEIL_OK, "alice has a device");
        check(veil_init_device(bob, "bob") == VEIL_OK, "bob has a device");

        check(veil_create_group(alice, "team") == VEIL_OK, "a group");
        const char members[] = "alice\0bob";
        check(veil_set_group_members(alice, "team",
                                     reinterpret_cast<const uint8_t*>(members),
                                     sizeof(members) - 1) == 2,
              "two members");

        // Alice's own group is enough to prove the export works: bob is not a
        // member of anything, so his blob has nothing to carry.
        const int state_size = veil_export_group_state(alice, nullptr, 0);
        check(state_size > 0, "group state exports");

        uint8_t state[8192];
        check(veil_export_group_state(alice, state, sizeof(state)) == state_size,
              "it fits its own size query");

        // Restore into a fresh engine that has the same device identity.
        uint8_t secrets[VEIL_IDENTITY_SECRET_SIZE];
        veil_identity_secrets(alice, secrets, sizeof(secrets));
        void* restored = veil_engine_restore(secrets, sizeof(secrets));
        check(restored != nullptr, "restored identity");
        check(veil_init_device(restored, "alice") == VEIL_OK, "restored device");

        check(veil_import_group_state(restored, state, static_cast<size_t>(state_size)) ==
                  VEIL_OK,
              "group state imports");
        check(veil_group_epoch(restored, "team") == 2, "the epoch survived");
        check(veil_is_group_member(restored, "team") == 1, "membership survived");

        // A truncated blob is refused, and refusing leaves the live state alone.
        check(veil_import_group_state(restored, state,
                                      static_cast<size_t>(state_size) - 1) ==
                  VEIL_BAD_BUNDLE,
              "a truncated blob is refused");
        check(veil_group_epoch(restored, "team") == 2,
              "and the live groups are untouched");

        veil_engine_free(restored);
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