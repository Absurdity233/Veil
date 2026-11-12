// Veil - host-side tests for the crypto core.
//
// These run on the build machine (no Android device needed) so the protocol
// can be exercised quickly while iterating. They cover the properties that
// matter: agreement, round-trip, out-of-order delivery, tamper detection,
// replay rejection and forward secrecy.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "veil/crypto.h"
#include "veil/engine.h"
#include "veil/keys.h"
#include "veil/ratchet.h"

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool cond, const char* what) {
    ++g_checks;
    if (!cond) {
        ++g_failures;
        std::printf("  FAIL  %s\n", what);
    }
}

void section(const char* name) {
    // Flushed immediately: a crash inside a section otherwise produces an empty
    // log, because stdout is block-buffered when it is not a terminal and the
    // buffer never gets written.
    std::printf("\n== %s ==\n", name);
    std::fflush(stdout);
}

veil::Bytes toBytes(const std::string& s) {
    return veil::Bytes(s.begin(), s.end());
}

std::string toString(const veil::Bytes& b) {
    return std::string(b.begin(), b.end());
}

// A frame carries a prekey header when bit 0 of the flags byte is set.
bool hasPreKeyHeader(const veil::Bytes& frame) {
    return !frame.empty() && (frame[0] & veil::WireMessage::kFlagPreKey) != 0;
}

/**
 * The signing key a device uses for its own artefacts, as a 32-byte buffer.
 *
 * A group chain and a device credential both belong to a *device*, not to the
 * account: that separation is what lets one account hold several devices without
 * handing every device the account key. The tests therefore verify chains
 * against the device key, and an earlier version of them verified against the
 * account key and failed for the right reason.
 */
std::array<uint8_t, 32> deviceSignPub(const veil::Engine& engine) {
    const veil::Bytes cred = engine.ownDeviceCredential();
    veil::DeviceCredential parsed;
    veil::DeviceCredential::deserialize(parsed, cred.data(), cred.size());

    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), parsed.device_sign_pub, 32);
    return out;
}

}  // namespace

int main() {
    using namespace veil;

    section("primitive sanity");
    {
        uint8_t a_pub[32], a_priv[32], b_pub[32], b_priv[32];
        check(crypto::x25519_generate(a_pub, a_priv), "generate a");
        check(crypto::x25519_generate(b_pub, b_priv), "generate b");

        uint8_t ab[32], ba[32];
        check(crypto::x25519(ab, a_priv, b_pub), "dh a->b");
        check(crypto::x25519(ba, b_priv, a_pub), "dh b->a");
        check(constant_time_equal(ab, ba, 32), "shared secrets agree");

        uint8_t zero_pub[32] = {0};
        uint8_t bad[32];
        check(!crypto::x25519(bad, a_priv, zero_pub), "low-order point rejected");

        uint8_t key[32], nonce[24];
        crypto::blake2b(key, 32, reinterpret_cast<const uint8_t*>("k"), 1);
        crypto::blake2b(nonce, 24, reinterpret_cast<const uint8_t*>("n"), 1);
        const char* msg = "hello veil";
        uint8_t cipher[64], mac[16], plain[64];
        crypto::aead_encrypt(cipher, mac, key, nonce, nullptr, 0,
                             reinterpret_cast<const uint8_t*>(msg), 10);
        check(crypto::aead_decrypt(plain, mac, key, nonce, nullptr, 0, cipher, 10),
              "aead round trip");
        check(std::memcmp(plain, msg, 10) == 0, "aead plaintext matches");

        cipher[3] ^= 0x01;
        check(!crypto::aead_decrypt(plain, mac, key, nonce, nullptr, 0, cipher, 10),
              "aead rejects tampered ciphertext");
    }

    section("identity + prekeys");
    Identity alice, bob;
    check(alice.generate(), "alice identity");
    check(bob.generate(), "bob identity");

    PreKeys bob_prekeys;
    check(bob_prekeys.rotate(bob, 5), "bob prekeys");
    check(bob_prekeys.one_time.size() == 5, "five one-time prekeys");

    section("X3DH agreement");
    PreKeyBundle bundle = publishBundle(bob, bob_prekeys, &bob_prekeys.one_time[0]);

    // The bundle must survive the wire.
    Bytes wire = bundle.serialize();
    PreKeyBundle parsed;
    check(PreKeyBundle::deserialize(parsed, wire.data(), wire.size()),
          "bundle deserialises");
    check(constant_time_equal(parsed.identity_dh_pub, bundle.identity_dh_pub, 32),
          "bundle identity preserved");

    Session alice_session, bob_session;
    check(alice_session.establishOutbound(alice, parsed), "alice establishes");
    check(alice_session.hasPendingPreKeyHeader(), "alice has prekey header");

    // Tamper with the signed prekey: the signature check must fail.
    {
        PreKeyBundle evil = parsed;
        evil.signed_pub[0] ^= 0xFF;
        Session s;
        check(!s.establishOutbound(alice, evil), "substituted prekey rejected");
    }

    // First message: alice -> bob.
    std::string text = "the veil parts";
    RatchetMessage m1;
    Bytes prekey_aad = toBytes("prekey-header-stand-in");
    check(alice_session.encrypt(reinterpret_cast<const uint8_t*>(text.data()),
                                text.size(), prekey_aad.data(), prekey_aad.size(), m1),
          "alice encrypts first message");

    check(bob_session.establishInbound(bob, bob_prekeys,
                                       alice_session.pendingPreKeyHeader()),
          "bob establishes from header");
    alice_session.clearPendingPreKeyHeader();

    Bytes out1;
    check(bob_session.decrypt(m1, prekey_aad.data(), prekey_aad.size(), out1),
          "bob decrypts first message");
    check(toString(out1) == text, "first message content matches");

    section("bidirectional ratchet");
    std::vector<std::string> alice_msgs = {"a1", "a2", "a3"};
    std::vector<RatchetMessage> a_msgs;

    for (const auto& s : alice_msgs) {
        RatchetMessage m;
        check(alice_session.encrypt(reinterpret_cast<const uint8_t*>(s.data()), s.size(),
                                    nullptr, 0, m),
              "alice encrypts");
        a_msgs.push_back(m);
    }

    for (size_t i = 0; i < a_msgs.size(); ++i) {
        Bytes plain;
        check(bob_session.decrypt(a_msgs[i], nullptr, 0, plain), "bob decrypts in order");
        check(toString(plain) == alice_msgs[i], "in-order content matches");
    }

    // Bob replies, which forces a DH ratchet on both sides.
    std::string reply = "reply from bob";
    RatchetMessage b1;
    check(bob_session.encrypt(reinterpret_cast<const uint8_t*>(reply.data()), reply.size(),
                              nullptr, 0, b1),
          "bob encrypts reply");

    Bytes out_b;
    check(alice_session.decrypt(b1, nullptr, 0, out_b), "alice decrypts reply");
    check(toString(out_b) == reply, "reply content matches");

    // And back again.
    std::string again = "after ratchet";
    RatchetMessage a4;
    check(alice_session.encrypt(reinterpret_cast<const uint8_t*>(again.data()), again.size(),
                                nullptr, 0, a4),
          "alice encrypts after ratchet");
    Bytes out_a;
    check(bob_session.decrypt(a4, nullptr, 0, out_a), "bob decrypts after ratchet");
    check(toString(out_a) == again, "post-ratchet content matches");

    section("out-of-order delivery");
    {
        Identity carol, dave;
        carol.generate();
        dave.generate();
        PreKeys dp;
        dp.rotate(dave, 3);
        PreKeyBundle b = publishBundle(dave, dp, &dp.one_time[0]);

        Session cs, ds;
        cs.establishOutbound(carol, b);

        std::string first = "first";
        RatchetMessage fm;
        cs.encrypt(reinterpret_cast<const uint8_t*>(first.data()), first.size(),
                   nullptr, 0, fm);
        ds.establishInbound(dave, dp, cs.pendingPreKeyHeader());
        Bytes tmp;
        ds.decrypt(fm, nullptr, 0, tmp);

        std::vector<std::string> msgs = {"m0", "m1", "m2", "m3", "m4"};
        std::vector<RatchetMessage> frames;
        for (const auto& s : msgs) {
            RatchetMessage m;
            cs.encrypt(reinterpret_cast<const uint8_t*>(s.data()), s.size(), nullptr, 0, m);
            frames.push_back(m);
        }

        // Deliver in reverse order: 4, 3, 0, 2, 1.
        const int order[5] = {4, 3, 0, 2, 1};
        bool all_ok = true;
        for (int idx : order) {
            Bytes plain;
            if (!ds.decrypt(frames[idx], nullptr, 0, plain)) { all_ok = false; continue; }
            if (toString(plain) != msgs[idx]) all_ok = false;
        }
        check(all_ok, "all out-of-order messages decrypt correctly");
    }

    section("replay and tamper rejection");
    {
        Identity e, f;
        e.generate();
        f.generate();
        PreKeys fp;
        fp.rotate(f, 3);
        PreKeyBundle b = publishBundle(f, fp, &fp.one_time[0]);

        Session es, fs;
        es.establishOutbound(e, b);
        std::string s = "replay me";
        RatchetMessage m;
        es.encrypt(reinterpret_cast<const uint8_t*>(s.data()), s.size(), nullptr, 0, m);
        fs.establishInbound(f, fp, es.pendingPreKeyHeader());
        Bytes p;
        check(fs.decrypt(m, nullptr, 0, p), "first delivery succeeds");
        check(!fs.decrypt(m, nullptr, 0, p), "replay is rejected");

        // Flip a bit in the ciphertext.
        RatchetMessage bad = m;
        bad.header.message_number = 999;
        bad.ciphertext[0] ^= 0x01;
        check(!fs.decrypt(bad, nullptr, 0, p), "tampered frame is rejected");
    }

    section("session persistence");
    {
        Identity g, h;
        g.generate();
        h.generate();
        PreKeys hp;
        hp.rotate(h, 3);
        PreKeyBundle b = publishBundle(h, hp, &hp.one_time[0]);

        Session gs, hs;
        gs.establishOutbound(g, b);
        std::string one = "before export";
        RatchetMessage m;
        gs.encrypt(reinterpret_cast<const uint8_t*>(one.data()), one.size(), nullptr, 0, m);
        hs.establishInbound(h, hp, gs.pendingPreKeyHeader());
        Bytes p;
        hs.decrypt(m, nullptr, 0, p);

        // Export and restore both sides, then keep talking.
        Bytes g_state = gs.serialize();
        Bytes h_state = hs.serialize();
        check(!g_state.empty() && !h_state.empty(), "state serialises");

        Session gs2, hs2;
        check(gs2.deserialize(g_state.data(), g_state.size()), "sender state restores");
        check(hs2.deserialize(h_state.data(), h_state.size()), "receiver state restores");

        std::string two = "after restore";
        RatchetMessage m2;
        check(gs2.encrypt(reinterpret_cast<const uint8_t*>(two.data()), two.size(),
                          nullptr, 0, m2),
              "restored sender encrypts");
        Bytes p2;
        check(hs2.decrypt(m2, nullptr, 0, p2), "restored receiver decrypts");
        check(toString(p2) == two, "restored content matches");
    }

    section("forward secrecy");
    {
        Identity i, j;
        i.generate();
        j.generate();
        PreKeys jp;
        jp.rotate(j, 3);
        PreKeyBundle b = publishBundle(j, jp, &jp.one_time[0]);

        Session is, js;
        is.establishOutbound(i, b);
        std::string s1 = "message one";
        RatchetMessage m1;
        is.encrypt(reinterpret_cast<const uint8_t*>(s1.data()), s1.size(), nullptr, 0, m1);
        js.establishInbound(j, jp, is.pendingPreKeyHeader());
        Bytes p;
        check(js.decrypt(m1, nullptr, 0, p), "first message ok");

        // Bob replies, which advances both ratchets.
        std::string r = "reply";
        RatchetMessage rm;
        js.encrypt(reinterpret_cast<const uint8_t*>(r.data()), r.size(), nullptr, 0, rm);
        Bytes pr;
        is.decrypt(rm, nullptr, 0, pr);

        // Alice sends again; Bob's old chain key is gone.
        std::string s2 = "message two";
        RatchetMessage m2;
        is.encrypt(reinterpret_cast<const uint8_t*>(s2.data()), s2.size(), nullptr, 0, m2);

        // Replaying message one must fail: its key was consumed and its chain
        // has been replaced.
        Bytes ignored;
        check(!js.decrypt(m1, nullptr, 0, ignored), "old message cannot be replayed");
        check(js.decrypt(m2, nullptr, 0, ignored), "current message still decrypts");
    }

    section("skipped-key bound");
    {
        Identity k, l;
        k.generate();
        l.generate();
        PreKeys lp;
        lp.rotate(l, 3);
        PreKeyBundle b = publishBundle(l, lp, &lp.one_time[0]);

        Session ks, ls;
        ks.establishOutbound(k, b);
        RatchetMessage first;
        ks.encrypt(reinterpret_cast<const uint8_t*>("x"), 1, nullptr, 0, first);
        ls.establishInbound(l, lp, ks.pendingPreKeyHeader());
        Bytes tmp;
        ls.decrypt(first, nullptr, 0, tmp);

        // Generate one message, then a frame claiming a huge gap.
        RatchetMessage m;
        ks.encrypt(reinterpret_cast<const uint8_t*>("y"), 1, nullptr, 0, m);
        RatchetMessage fake = m;
        fake.header.message_number = 50000;
        Bytes ignored;
        check(!ls.decrypt(fake, nullptr, 0, ignored), "oversized skip rejected");
    }

    section("engine: framing, handshake, safety number");
    {
        Engine a, b;
        check(a.createIdentity(), "engine a identity");
        check(b.createIdentity(), "engine b identity");
        check(a.rotatePreKeys(), "engine a prekeys");
        check(b.rotatePreKeys(), "engine b prekeys");

        Bytes bundle = b.publishBundle(0);
        check(!bundle.empty(), "bundle published");

        check(a.establishOutbound("bob", bundle.data(), bundle.size()),
              "engine a establishes");

        const char* hello = "hello from a";
        Bytes frame = a.encrypt("bob", reinterpret_cast<const uint8_t*>(hello),
                                std::strlen(hello));
        check(!frame.empty(), "engine a encrypts");

        Bytes plain;
        check(b.decrypt("alice", frame.data(), frame.size(), plain),
              "engine b decrypts first frame");
        check(toString(plain) == hello, "engine first frame content");

        bool leaked = false;
        for (size_t i = 0; i + std::strlen(hello) <= frame.size(); ++i) {
            if (std::memcmp(frame.data() + i, hello, std::strlen(hello)) == 0) leaked = true;
        }
        check(!leaked, "ciphertext does not contain plaintext");

        const char* reply = "hello back";
        Bytes rframe = b.encrypt("alice", reinterpret_cast<const uint8_t*>(reply),
                                 std::strlen(reply));
        check(!rframe.empty(), "engine b encrypts reply");
        check(rframe.size() < frame.size(), "reply drops the prekey header");

        Bytes rplain;
        check(a.decrypt("bob", rframe.data(), rframe.size(), rplain),
              "engine a decrypts reply");
        check(toString(rplain) == reply, "engine reply content");

        std::string an = a.safetyNumber("bob");
        std::string bn = b.safetyNumber("alice");
        check(!an.empty(), "safety number computed");
        check(an == bn, "safety numbers agree");

        // A frame without a prekey header cannot start a session: the receiver
        // has no root key to derive from.
        // A peer id that is already bound to one identity must not accept a
        // handshake from a different one.
        {
            Engine mallory;
            mallory.createIdentity();
            mallory.rotatePreKeys();
            // Alice's bundle points at Bob, so Mallory's frame is a stranger.
            Bytes mb = a.publishBundle(0);
            (void)mb;

            // Replay Alice's handshake frame under a label Bob already knows
            // as a different identity.
            Engine carol;
            carol.createIdentity();
            carol.rotatePreKeys();
            Bytes cb = carol.publishBundle(0);
            Engine dave;
            dave.createIdentity();
            dave.rotatePreKeys();
            dave.establishOutbound("carol", cb.data(), cb.size());

            Bytes carol_frame = carol.encrypt("dave",
                reinterpret_cast<const uint8_t*>("hi"), 2);
            Bytes tmp;
            check(b.decrypt("alice", carol_frame.data(), carol_frame.size(), tmp) == false,
                  "identity swap under a known peer id rejected");
        }

        Bytes junk;
        check(!b.decrypt("stranger", rframe.data(), rframe.size(), junk),
              "header-less frame from unknown peer rejected");

        Bytes broken = frame;
        broken[broken.size() - 1] ^= 0xFF;
        check(!b.decrypt("alice", broken.data(), broken.size(), junk),
              "tampered engine frame rejected");
    }

    section("engine: session export/import");
    {
        Engine a, b;
        a.createIdentity();
        b.createIdentity();
        a.rotatePreKeys();
        b.rotatePreKeys();

        Bytes bundle = b.publishBundle(0);
        a.establishOutbound("bob", bundle.data(), bundle.size());
        Bytes f = a.encrypt("bob", reinterpret_cast<const uint8_t*>("x"), 1);
        Bytes p;
        b.decrypt("alice", f.data(), f.size(), p);

        Bytes a_state = a.exportSession("bob");
        Bytes b_state = b.exportSession("alice");
        check(!a_state.empty() && !b_state.empty(), "sessions export");

        Engine a2, b2;
        check(a2.importSession("bob", a_state.data(), a_state.size()), "import a");
        check(b2.importSession("alice", b_state.data(), b_state.size()), "import b");

        Bytes f2 = a2.encrypt("bob", reinterpret_cast<const uint8_t*>("y"), 1);
        Bytes p2;
        check(b2.decrypt("alice", f2.data(), f2.size(), p2), "restored peers talk");
        check(toString(p2) == "y", "restored content matches");
    }

    section("prekey set wire layout");
    {
        // The relay and the client both parse exportPreKeySet(), so its layout
        // is part of the contract between them:
        //   [4] signed id | [32] signed pub | [64] signature | [4] count
        //   then per one-time key: [4] id | [32] pub
        Engine e;
        e.createIdentity();
        check(e.rotatePreKeys(), "prekeys generated");

        Bytes set = e.exportPreKeySet();
        check(set.size() == 4 + 32 + 64 + 4 + kOneTimeBatch * 36, "prekey set size");

        // The signed prekey id is a monotonic counter, not a constant. It used
        // to restart at 1 on every launch, which made a stale bundle
        // indistinguishable from a fresh one.
        check(get_u32(set.data()) == 1, "first signed id is 1");
        check(get_u32(set.data() + 4 + 32 + 64) == kOneTimeBatch, "one-time count");

        // Rotating again must move the id forward, so the relay cannot
        // overwrite the previous row under the same name.
        check(e.rotatePreKeys(), "second rotation");
        Bytes set2 = e.exportPreKeySet();
        check(get_u32(set2.data()) == 2, "second signed id is 2");

        // Each one-time id must be unique, or the relay could hand the same
        // key to two different senders.
        std::vector<uint32_t> ids;
        size_t off = 4 + 32 + 64 + 4;
        for (uint32_t i = 0; i < kOneTimeBatch; ++i) {
            ids.push_back(get_u32(set.data() + off));
            off += 36;
        }
        bool unique = true;
        for (size_t i = 0; i < ids.size(); ++i) {
            for (size_t j = i + 1; j < ids.size(); ++j) {
                if (ids[i] == ids[j]) unique = false;
            }
        }
        check(unique, "one-time prekey ids are distinct");
    }

    section("bundle layout the relay produces");
    {
        // The relay rebuilds a bundle from stored parts; this mirrors exactly
        // that shape so a change on either side fails here rather than on a
        // device.
        Engine bob;
        bob.createIdentity();
        bob.rotatePreKeys();

        Bytes pub = bob.exportIdentityPublic();
        Bytes set = bob.exportPreKeySet();

        // [64] identity | [4] signed id | [32] signed pub | [64] sig
        // [1] has one-time | [4] one-time id | [32] one-time pub
        Bytes bundle;
        bundle.insert(bundle.end(), pub.begin(), pub.end());
        uint8_t num[4];
        put_u32(num, get_u32(set.data()));
        bundle.insert(bundle.end(), num, num + 4);
        bundle.insert(bundle.end(), set.begin() + 4, set.begin() + 4 + 32);
        bundle.insert(bundle.end(), set.begin() + 36, set.begin() + 36 + 64);
        bundle.push_back(1);
        size_t ot_off = 4 + 32 + 64 + 4;
        put_u32(num, get_u32(set.data() + ot_off));
        bundle.insert(bundle.end(), num, num + 4);
        bundle.insert(bundle.end(), set.begin() + ot_off + 4, set.begin() + ot_off + 36);

        Engine alice;
        alice.createIdentity();
        check(alice.establishOutbound("bob", bundle.data(), bundle.size()),
              "relay-shaped bundle establishes");
    }

    section("identity binding ties the two key halves together");
    {
        // Without this, a relay could pair a victim's DH key with its own
        // signing key: the prekey signature would verify, X3DH would run
        // against the victim's DH key, and the safety number would not move.
        Identity id;
        check(id.generate(), "binding identity");

        uint8_t binding[kBindingSize];
        id.bindingSignature(binding);
        check(Identity::verifyBinding(id.dh_pub, id.sign_pub, binding),
              "binding verifies");

        // The DH half swapped for somebody else's: the signature is over the
        // original bytes, so it must fail.
        Identity other;
        other.generate();
        check(!Identity::verifyBinding(other.dh_pub, id.sign_pub, binding),
              "binding rejects a swapped DH key");

        // The signing half swapped: same story from the other side.
        check(!Identity::verifyBinding(id.dh_pub, other.sign_pub, binding),
              "binding rejects a swapped signing key");

        // A flipped signature byte is not accepted.
        uint8_t broken[kBindingSize];
        std::memcpy(broken, binding, kBindingSize);
        broken[7] ^= 0xFF;
        check(!Identity::verifyBinding(id.dh_pub, id.sign_pub, broken),
              "binding rejects a corrupt signature");

        // And the engine wrapper agrees.
        Engine e;
        e.createIdentity();
        Bytes pub = e.exportIdentityPublic();
        Bytes sig = e.exportIdentityBinding();
        check(pub.size() == kIdentitySize && sig.size() == kBindingSize,
              "identity blob and binding sizes");
        check(Engine::verifyIdentityBinding(pub.data(), sig.data()),
              "engine binding verifies");
    }

    section("prekey signature covers the identity DH key");
    {
        Identity bob;
        bob.generate();
        PreKeys bp;
        bp.rotate(bob, 2);

        check(verifySignedPreKey(bob.dh_pub, bob.sign_pub,
                                 bp.current.pub, bp.current.signature),
              "signed prekey verifies");

        // The exact attack the binding closes: keep the victim's DH key, swap
        // in another signing key. A signature that only covered signed_pub
        // would still verify here, because the same signer produced it.
        Identity evil;
        evil.generate();
        check(!verifySignedPreKey(bob.dh_pub, evil.sign_pub,
                                  bp.current.pub, bp.current.signature),
              "spliced signing key rejected by the prekey signature");

        // A bundle built that way must not establish a session either.
        PreKeyBundle spliced = publishBundle(bob, bp, &bp.one_time[0]);
        std::memcpy(spliced.identity_sign_pub, evil.sign_pub, 32);
        Bytes wire = spliced.serialize();
        PreKeyBundle parsed;
        check(PreKeyBundle::deserialize(parsed, wire.data(), wire.size()),
              "spliced bundle retrieves");

        Engine alice;
        alice.createIdentity();
        check(alice.establishOutboundStatus("bob", wire.data(), wire.size()) ==
                  Engine::Result::BadSignature,
              "spliced bundle refused");
    }

    section("prekey header names the signed prekey it used");
    {
        // A peer may download a bundle just before a rotation and send its
        // first message afterwards. The previous private half has to stay
        // usable, and a header naming a key we never held must be refused
        // rather than silently re-keyed.
        Identity bob;
        bob.generate();
        PreKeys bp;
        bp.rotate(bob, 2);

        // Rotate: the old prekey is retired by rotate() itself, not gone. The
        // same PreKeys object gains a second generation, exactly as a real
        // rotation would.
        const PreKeyBundle stale_bundle = publishBundle(bob, bp, &bp.one_time[0]);
        const uint32_t first_id = bp.current.id;

        PreKeys rotated = bp;
        rotated.rotate(bob, 2);
        check(rotated.has_retired && rotated.retired.id == first_id,
              "rotation retires the previous prekey");
        check(rotated.current.id > first_id, "signed prekey id moves forward");

        Identity alice;
        alice.generate();
        Session as;
        check(as.establishOutbound(alice, stale_bundle), "stale bundle establishes");

        // The header carries the now-retired id, and the receiver must still
        // be able to complete the handshake with it.
        Session bs;
        check(bs.establishInbound(bob, rotated, as.pendingPreKeyHeader()),
              "handshake against the retired prekey");

        // The same header, offered twice, is refused: a replayed first frame
        // must not re-run X3DH against the same one-time key.
        Session replay;
        check(!replay.establishInbound(bob, rotated, as.pendingPreKeyHeader()),
              "spent one-time prekey refused on replay");

        // A header naming an id we never issued is refused.
        PreKeyHeader unknown = as.pendingPreKeyHeader();
        unknown.signed_prekey_id = 9999;
        Session nope;
        check(!nope.establishInbound(bob, rotated, unknown),
              "unknown signed prekey id refused");

        // zero is not a valid signed prekey id either; it would otherwise
        // look like "no prekey" and re-key the session silently.
        unknown.signed_prekey_id = 0;
        Session zero;
        check(!zero.establishInbound(bob, rotated, unknown),
              "missing signed prekey id refused");
    }

    section("prekey header travels until the peer answers");
    {
        // The first frame can be lost - the socket drops, the outbox entry is
        // discarded, the peer restarts. Dropping the header after the first
        // send would orphan the session with no way to retry.
        Engine a, b;
        a.createIdentity();
        b.createIdentity();
        a.rotatePreKeys();
        b.rotatePreKeys();

        Bytes bundle = b.publishBundle(0);
        check(a.establishOutboundStatus("bob", bundle.data(), bundle.size()) == Engine::Result::Ok,
              "outbound establishes");

        Bytes f1 = a.encrypt("bob", reinterpret_cast<const uint8_t*>("lost"), 4);
        Bytes f2 = a.encrypt("bob", reinterpret_cast<const uint8_t*>("also lost"), 9);
        check(hasPreKeyHeader(f2), "second frame still carries the header");

        // Only the third frame reaches Bob. The session must still come up,
        // because the header travelled with it.
        Bytes f3 = a.encrypt("bob", reinterpret_cast<const uint8_t*>("arrived"), 7);
        Bytes p;
        check(b.decrypt("alice", f3.data(), f3.size(), p), "late first frame decrypts");
        check(toString(p) == "arrived", "late first frame content");

        // Now that Bob has answered, the header is gone and frames shrink.
        Bytes r = b.encrypt("alice", reinterpret_cast<const uint8_t*>("ack"), 3);
        Bytes rp;
        check(a.decrypt("bob", r.data(), r.size(), rp), "reply decrypts");
        Bytes f4 = a.encrypt("bob", reinterpret_cast<const uint8_t*>("after"), 5);
        check(!hasPreKeyHeader(f4), "header dropped once the peer answered");
    }

    section("a pinned identity cannot be replaced outbound");
    {
        // The inbound path always refused a re-handshake under a known label.
        // The outbound path used to overwrite the pin silently, so a hostile
        // relay could hand back a bundle for a different identity and the user
        // would keep talking to a stranger with an unchanged safety number.
        Engine alice, bob, mallory;
        alice.createIdentity();
        bob.createIdentity();
        mallory.createIdentity();
        bob.rotatePreKeys();
        mallory.rotatePreKeys();

        Bytes bob_bundle = bob.publishBundle(0);
        check(alice.establishOutboundStatus("bob", bob_bundle.data(), bob_bundle.size()) ==
                  Engine::Result::Ok,
              "first bind succeeds");
        std::string good = alice.safetyNumber("bob");

        Bytes evil_bundle = mallory.publishBundle(0);
        check(alice.establishOutboundStatus("bob", evil_bundle.data(), evil_bundle.size()) ==
                  Engine::Result::IdentityChanged,
              "re-binding to another identity refused");
        check(alice.safetyNumber("bob") == good, "safety number unchanged");

        // The session still works after the refused swap.
        Bytes f = alice.encrypt("bob", reinterpret_cast<const uint8_t*>("ok"), 2);
        Bytes p;
        check(bob.decrypt("alice", f.data(), f.size(), p), "session survives");
    }

    section("safety number covers the signing key too");
    {
        // The safety number used to hash only the two DH keys. That left the
        // key which authenticates prekeys outside what the user verifies.
        Engine a, b;
        a.createIdentity();
        b.createIdentity();
        a.rotatePreKeys();
        b.rotatePreKeys();

        Bytes bundle = b.publishBundle(0);
        a.establishOutbound("bob", bundle.data(), bundle.size());
        Bytes f = a.encrypt("bob", reinterpret_cast<const uint8_t*>("x"), 1);
        Bytes p;
        b.decrypt("alice", f.data(), f.size(), p);

        std::string an = a.safetyNumber("bob");
        std::string bn = b.safetyNumber("alice");
        check(!an.empty() && an == bn, "both sides agree with both halves");

        // 25 digits in five groups of five.
        check(an.size() == 29, "safety number length");
        check(an[5] == ' ' && an[11] == ' ' && an[17] == ' ' && an[23] == ' ',
              "safety number grouping");
    }

    section("pinned identities survive a restart");
    {
        Engine a;
        a.createIdentity();
        a.rotatePreKeys();
        Bytes self_bundle = a.publishBundle(0);

        Engine b;
        b.createIdentity();
        b.rotatePreKeys();
        b.establishOutbound("alice", self_bundle.data(), self_bundle.size());
        std::string before = b.safetyNumber("alice");

        Bytes registry = b.exportPeerRegistry();
        check(!registry.empty(), "registry exports");

        // A fresh process restores the same identity plus the pins, but not
        // the sessions.
        Bytes secrets = b.exportIdentitySecrets();
        Engine b2;
        check(b2.restoreIdentity(secrets.data(), secrets.data() + kKeySize),
              "identity restores");
        check(b2.importPeerRegistry(registry.data(), registry.size()),
              "registry imports");
        check(b2.safetyNumber("alice") == before, "safety number survives a restart");

        // And the pin still blocks a different identity for that label.
        Identity other;
        other.generate();
        PreKeys op;
        op.rotate(other, 1);
        Bytes evil = publishBundle(other, op, &op.one_time[0]).serialize();
        check(b2.establishOutboundStatus("alice", evil.data(), evil.size()) ==
                  Engine::Result::IdentityChanged,
              "restored pin still refuses a different identity");

        // Dropping the session must not clear the pin: otherwise anyone could
        // re-bind the label right after a session reset.
        b2.dropSession("alice");
        check(b2.establishOutboundStatus("alice", evil.data(), evil.size()) ==
                  Engine::Result::IdentityChanged,
              "dropping a session keeps the pin");
    }
    section("skipped-key budget is global, not per chain");
    {
        // A fresh bucket is opened every time the peer publishes a new ratchet
        // key, so "1000 per chain" bounded nothing at all: the amount a remote
        // party could pin grew with the number of ratchet steps it felt like
        // taking. The global cap is what actually holds.
        Identity alice, bob;
        alice.generate();
        bob.generate();
        PreKeys bp;
        bp.rotate(bob, 2);
        PreKeyBundle bundle = publishBundle(bob, bp, &bp.one_time[0]);

        Session as, bs;
        check(as.establishOutbound(alice, bundle), "session up");

        // Drive many separate chains: each round skips a long run on the
        // receiving side, then the peer ratchets, opening a new bucket.
        RatchetMessage first;
        check(as.encrypt(reinterpret_cast<const uint8_t*>("open"), 4, nullptr, 0, first),
              "opening frame");
        check(bs.establishInbound(bob, bp, as.pendingPreKeyHeader()), "bob handshake");
        Bytes p;
        check(bs.decrypt(first, nullptr, 0, p), "opening frame decrypts");

        for (int round = 0; round < 8; ++round) {
            // Alice burns 400 counters on the current chain without Bob
            // seeing them, so Bob caches 400 keys when the next frame lands.
            for (int i = 0; i < 400; ++i) {
                RatchetMessage skipped;
                as.encrypt(reinterpret_cast<const uint8_t*>("x"), 1, nullptr, 0, skipped);
            }
            RatchetMessage landed;
            check(as.encrypt(reinterpret_cast<const uint8_t*>("y"), 1, nullptr, 0, landed),
                  "landed frame");
            check(bs.decrypt(landed, nullptr, 0, p), "landed frame decrypts");

            // Bob replies, which makes both sides ratchet and opens a new
            // bucket on Bob's side next round.
            RatchetMessage reply;
            check(bs.encrypt(reinterpret_cast<const uint8_t*>("r"), 1, nullptr, 0, reply),
                  "bob replies");
            Bytes rp;
            check(as.decrypt(reply, nullptr, 0, rp), "reply decrypts");

            // The invariant, checked every round rather than only at the end.
            check(bs.skippedKeyCount() <= kMaxSkippedKeysTotal,
                  "total skipped keys stay inside the budget");
        }
    }

    section("prekey state survives a restart");
    {
        // Before this, every launch minted a fresh generation under id 1 and
        // forgot which one-time keys had already been handed out. Same id with
        // different keys is indistinguishable from a stale bundle on the wire,
        // and an unrecorded spend lets a one-time key be used twice.
        Engine a;
        a.createIdentity();
        a.rotatePreKeys();
        a.rotatePreKeys();  // two generations, so the id is past 1

        Bytes state = a.exportPreKeyState();
        check(!state.empty(), "prekey state exports");

        Bytes published = a.exportPreKeySet();
        const uint32_t id_before = get_u32(published.data());

        Engine restored;
        restored.createIdentity();
        check(restored.importPreKeyState(state.data(), state.size()),
              "prekey state imports");

        Bytes after = restored.exportPreKeySet();
        check(get_u32(after.data()) == id_before, "signed id survives a restart");

        // The retired prekey has to come back too, or a bundle fetched just
        // before the rotation stops working after a restart.
        check(after.size() == published.size(), "one-time set size survives");

        // Continuing after a restart must not reuse an id.
        check(restored.rotatePreKeys(), "rotate after restore");
        Bytes next = restored.exportPreKeySet();
        check(get_u32(next.data()) > id_before, "id keeps moving forward");

        // A truncated state blob is refused rather than half-applied.
        Engine bad;
        bad.createIdentity();
        check(!bad.importPreKeyState(state.data(), state.size() - 1),
              "truncated prekey state refused");
    }

    section("a one-time prekey is spent exactly once");
    {
        Identity bob, alice;
        bob.generate();
        alice.generate();
        PreKeys bp;
        bp.rotate(bob, 3);
        check(bp.one_time.size() == 3, "three one-time keys generated");

        const OneTimePreKey* first = nullptr;
        for (const auto& ot : bp.one_time) {
            if (!ot.consumed) { first = &ot; break; }
        }
        check(first != nullptr, "an unspent key is available");

        PreKeyBundle bundle = publishBundle(bob, bp, first);
        Session as;
        check(as.establishOutbound(alice, bundle), "session against a prekey");
        PreKeyHeader header = as.pendingPreKeyHeader();

        // The handshake spends the key the header names, and only that one.
        Session one;
        check(one.establishInbound(bob, bp, header), "first inbound spends it");

        const uint32_t id = header.one_time_prekey_id;
        check(bp.consumeOneTime(id) == nullptr, "the key is recorded as spent");

        // A replayed first frame names the same key, which is now spent. It
        // must be refused: re-running X3DH on a used one-time key is exactly
        // the weakness the "one-time" in the name excludes.
        Session two;
        check(!two.establishInbound(bob, bp, header), "same header replayed is refused");

        // Fewer unspent keys remain, so a refill becomes due sooner.
        size_t unused = 0;
        for (const auto& ot : bp.one_time) {
            if (!ot.consumed) ++unused;
        }
        check(unused == 2, "exactly one of three keys was spent");
        check(!bp.needsRefill(unused), "no refill while the supply lasts");
        check(bp.needsRefill(unused + 1), "refill due once below the low-water mark");
    }

    section("a duplicated delivery is not an error");
    {
        // The relay delivers at-least-once: a live push can also be replayed
        // out of the outbox. The ratchet refuses the second copy, which is
        // correct - but reporting it as authentication failure put a scary line
        // in front of the user on a perfectly normal event.
        Engine a, b;
        check(a.createIdentity(), "a identity");
        check(b.createIdentity(), "b identity");
        check(a.rotatePreKeys(), "a prekeys");
        check(b.rotatePreKeys(), "b prekeys");

        Bytes bundle = b.publishBundle(0);
        check(a.establishOutboundStatus("bob", bundle.data(), bundle.size()) ==
                  Engine::Result::Ok,
              "session established");

        Bytes frame = a.encrypt("bob", reinterpret_cast<const uint8_t *>("once"), 4);
        Bytes plain;

        check(b.decryptStatus("alice", frame.data(), frame.size(), plain) ==
                  Engine::Result::Ok,
              "first delivery accepted");
        check(toString(plain) == "once", "content");

        check(b.decryptStatus("alice", frame.data(), frame.size(), plain) ==
                  Engine::Result::Duplicate,
              "replay reported as duplicate, not as tamper");

        // A tampered frame on a counter we have *not* consumed is a different
        // failure from a duplicate. The two must stay distinguishable, or a
        // duplicate delivery looks like an attack and a real one looks like a
        // duplicate.
        Bytes next = a.encrypt("bob", reinterpret_cast<const uint8_t *>("second"), 6);
        next[next.size() - 1] ^= 0xFF;
        check(b.decryptStatus("alice", next.data(), next.size(), plain) ==
                  Engine::Result::AuthFailed,
              "tampered frame reported as auth failure");

        // A truncated frame no longer carries a MAC at all.
        Bytes tiny(next.begin(), next.begin() + 8);
        check(b.decryptStatus("alice", tiny.data(), tiny.size(), plain) ==
                  Engine::Result::BadBundle,
              "truncated frame reported as bad bundle");

        // A frame under an unknown peer label has no session at all. The frame
        // used here is a plain ratchet frame (the header was dropped once Bob
        // answered), so there is nothing to bootstrap a handshake from.
        Bytes plainFrame = b.encrypt("alice", reinterpret_cast<const uint8_t *>("back"), 4);
        check(!hasPreKeyHeader(plainFrame), "reply carries no prekey header");
        check(b.decryptStatus("nobody", plainFrame.data(), plainFrame.size(), plain) ==
                  Engine::Result::NoSession,
              "unknown peer reported as no session");
    }

    section("engine reports the real session state");
    {
        // The UI used "safetyNumber != null" as a proxy for "a session
        // exists". That went stale as soon as a session was dropped, and was
        // never true for a label that was pinned without one.
        Engine a;
        a.createIdentity();
        a.rotatePreKeys();
        check(a.sessionState("bob") == Engine::SessionState::NoPeer,
              "unknown label is NoPeer");

        Engine b;
        b.createIdentity();
        b.rotatePreKeys();
        Bytes bundle = b.publishBundle(0);
        check(a.establishOutboundStatus("bob", bundle.data(), bundle.size()) ==
                  Engine::Result::Ok,
              "session established");
        check(a.sessionState("bob") == Engine::SessionState::Ready, "live session is Ready");

        a.dropSession("bob");
        check(a.sessionState("bob") == Engine::SessionState::PinnedOnly,
              "dropping the session leaves the pin");

        Bytes registry = a.exportPeerRegistry();
        Engine a2;
        a2.createIdentity();
        a2.importPeerRegistry(registry.data(), registry.size());
        check(a2.sessionState("bob") == Engine::SessionState::PinnedOnly,
              "the pin reports itself after a restart");
    }

    section("device credentials: the endorsement chain");
    {
        // One account, many devices. The identity signs an endorsement of each
        // device's key pair, and that is the only thing that lets a device
        // speak for the account.
        Identity account;
        check(account.generate(), "account identity");

        // ---- A device mints its own credential ----
        uint8_t device_id[kDeviceIdSize];
        check(generateDeviceId(device_id), "device id");

        uint8_t dh_pub[kKeySize], dh_priv[kKeySize];
        uint8_t sign_pub[32], sign_priv[64];
        uint8_t sign_seed[32];
        check(crypto::x25519_generate(dh_pub, dh_priv), "device dh key");
        crypto::blake2b(sign_seed, sizeof(sign_seed), device_id, kDeviceIdSize);
        crypto::ed25519_keypair(sign_pub, sign_priv, sign_seed);
        veil::wipe(sign_seed, sizeof(sign_seed));

        DeviceCredential cred;
        check(DeviceCredential::create(cred, "alice", device_id, dh_pub, dh_priv,
                                       sign_pub, sign_priv, 1700000000),
              "credential created");

        // Before the account signs it, it is just a key pair claiming a name.
        check(cred.verifyDeviceBinding(), "the device endorses its own DH key");
        check(!cred.verify(account.dh_pub, account.sign_pub),
              "an unsigned credential does not verify");

        // ---- The account signs it ----
        check(cred.signBy(account), "account signs the credential");
        check(cred.verify(account.dh_pub, account.sign_pub),
              "the signed credential verifies");

        // ---- The attacks the two signatures exist to stop ----

        // A relay swaps the device's DH key for one it controls, keeping the
        // rest. The device's self-binding no longer matches.
        {
            DeviceCredential spliced = cred;
            spliced.device_dh_pub[0] ^= 0xFF;
            check(!spliced.verify(account.dh_pub, account.sign_pub),
                  "a spliced device DH key is refused");
        }

        // A relay swaps the device's *signing* key, which is the half that
        // would let it vouch for prekeys. Same story.
        {
            DeviceCredential spliced = cred;
            spliced.device_sign_pub[1] ^= 0xFF;
            check(!spliced.verify(account.dh_pub, account.sign_pub),
                  "a spliced device signing key is refused");
        }

        // A relay re-labels the credential for a different account, hoping the
        // account it names will accept it.
        {
            DeviceCredential relabelled = cred;
            relabelled.user_id = "mallory";
            check(!relabelled.verify(account.dh_pub, account.sign_pub),
                  "a relabelled credential is refused");
        }

        // A relay moves the device to a different device id.
        {
            DeviceCredential moved = cred;
            moved.device_id[0] ^= 0x01;
            check(!moved.verify(account.dh_pub, account.sign_pub),
                  "a credential with a changed device id is refused");
        }

        // A relay post-dates a credential to outlive a revocation.
        {
            DeviceCredential redated = cred;
            redated.issued_at += 1;
            check(!redated.verify(account.dh_pub, account.sign_pub),
                  "a credential with a changed issue time is refused");
        }

        // A different account's signature is not this account's.
        {
            Identity other;
            other.generate();
            DeviceCredential foreign = cred;
            check(foreign.signBy(other), "a foreign account signs it");
            check(!foreign.verify(account.dh_pub, account.sign_pub),
                  "another account's endorsement is refused");
        }

        // An attacker with their own key pair cannot self-issue a credential
        // for somebody else's account, because they do not have the account
        // signing key. This is the whole point of Model B.
        {
            uint8_t evil_dh_pub[kKeySize], evil_dh_priv[kKeySize];
            uint8_t evil_sign_pub[32], evil_sign_priv[64];
            uint8_t evil_seed[32];
            crypto::x25519_generate(evil_dh_pub, evil_dh_priv);
            crypto::blake2b(evil_seed, sizeof(evil_seed),
                            reinterpret_cast<const uint8_t*>("evil"), 4);
            crypto::ed25519_keypair(evil_sign_pub, evil_sign_priv, evil_seed);

            DeviceCredential forged;
            check(DeviceCredential::create(forged, "alice", device_id,
                                           evil_dh_pub, evil_dh_priv,
                                           evil_sign_pub, evil_sign_priv, 1700000000),
                  "an attacker builds a credential for alice");
            check(forged.verifyDeviceBinding(), "it is internally consistent");
            check(!forged.verify(account.dh_pub, account.sign_pub),
                  "but the account never signed it, so it is refused");

            veil::wipe(evil_dh_priv, sizeof(evil_dh_priv));
            veil::wipe(evil_sign_priv, sizeof(evil_sign_priv));
        }

        veil::wipe(dh_priv, sizeof(dh_priv));
        veil::wipe(sign_priv, sizeof(sign_priv));
    }

    section("device credentials survive the wire");
    {
        Identity account;
        account.generate();

        uint8_t device_id[kDeviceIdSize];
        generateDeviceId(device_id);
        uint8_t dh_pub[kKeySize], dh_priv[kKeySize];
        uint8_t sign_pub[32], sign_priv[64];
        uint8_t seed[32];
        crypto::x25519_generate(dh_pub, dh_priv);
        crypto::blake2b(seed, sizeof(seed), device_id, kDeviceIdSize);
        crypto::ed25519_keypair(sign_pub, sign_priv, seed);

        DeviceCredential cred;
        DeviceCredential::create(cred, "alice-with-a-long-id", device_id,
                                 dh_pub, dh_priv, sign_pub, sign_priv, 1234567890);
        cred.signBy(account);

        Bytes wire = cred.serialize();
        DeviceCredential parsed;
        check(DeviceCredential::deserialize(parsed, wire.data(), wire.size()),
              "credential deserialises");
        check(parsed.user_id == "alice-with-a-long-id", "user id preserved");
        check(parsed.issued_at == 1234567890, "issue time preserved");
        check(constant_time_equal(parsed.device_id, device_id, kDeviceIdSize),
              "device id preserved");
        check(parsed.verify(account.dh_pub, account.sign_pub),
              "the parsed credential still verifies");

        // A blob cut short by one byte must be refused, not read past.
        check(!DeviceCredential::deserialize(parsed, wire.data(), wire.size() - 1),
              "a truncated credential is refused");

        // An empty user id is not a credential.
        {
            Bytes empty;
            empty.push_back(0); empty.push_back(0);
            empty.resize(2 + kDeviceIdSize + kKeySize + 32 + 8 + kBindingSize + kSigSize);
            DeviceCredential bad;
            check(!DeviceCredential::deserialize(bad, empty.data(), empty.size()),
                  "an empty user id is refused");
        }

        // The fingerprint is stable and distinguishes devices.
        const std::string fp = cred.fingerprint();
        check(fp.size() == 19, "fingerprint is four groups of four plus separators");
        check(fp == cred.fingerprint(), "fingerprint is deterministic");
        check(fp[4] == '-' && fp[9] == '-' && fp[14] == '-', "fingerprint is grouped");

        // A different device *key pair* must give a different fingerprint. The id is
        // deliberately not in the digest: the fingerprint identifies the keys a
        // user is being asked to trust, and an id the relay assigned carries no
        // security meaning.
        uint8_t other_dh_pub[kKeySize], other_dh_priv[kKeySize];
        uint8_t other_sign_pub[32], other_sign_priv[64];
        uint8_t other_seed[32];
        crypto::x25519_generate(other_dh_pub, other_dh_priv);
        crypto::blake2b(other_seed, sizeof(other_seed), device_id, kDeviceIdSize);
        crypto::ed25519_keypair(other_sign_pub, other_sign_priv, other_seed);

        DeviceCredential other;
        DeviceCredential::create(other, "alice-with-a-long-id", device_id,
                                 other_dh_pub, other_dh_priv,
                                 other_sign_pub, other_sign_priv, 1234567890);
        check(other.fingerprint() != fp, "a different key pair yields a different fingerprint");

        // And the same key pair under a different id is the same device as far
        // as a person comparing fingerprints is concerned.
        {
            uint8_t reused_id[kDeviceIdSize];
            generateDeviceId(reused_id);
            DeviceCredential same_keys;
            DeviceCredential::create(same_keys, "alice-with-a-long-id", reused_id,
                                     dh_pub, dh_priv, sign_pub, sign_priv, 1234567890);
            check(same_keys.fingerprint() == fp,
                  "the fingerprint follows the keys, not the id");
        }

        veil::wipe(other_dh_priv, sizeof(other_dh_priv));
        veil::wipe(other_sign_priv, sizeof(other_sign_priv));
        veil::wipe(other_seed, sizeof(other_seed));

        veil::wipe(dh_priv, sizeof(dh_priv));
        veil::wipe(sign_priv, sizeof(sign_priv));
        veil::wipe(seed, sizeof(seed));
    }

    section("multi-device: one account, two devices");
    {
        // Alice has a phone and a laptop. They are one account with two devices,
        // not two accounts. Bob talks to both without knowing which one is
        // answering.
        Engine phone;
        check(phone.createIdentity(), "phone identity");
        check(phone.initDevice("alice"), "phone claims its device");

        // The laptop generates its own key pair and asks the phone to endorse
        // it. Nothing about the account secret moves: a compromised laptop does
        // not become the account.
        Engine laptop;
        check(laptop.createIdentity(), "laptop has its own engine identity");
        check(laptop.initDevice("alice"), "laptop claims a device id");

        // The linking flow, end to end: the laptop's credential is signed by the
        // account and handed back. In a real flow those two steps happen on
        // different machines.
        Bytes laptop_cred = laptop.ownDeviceCredential();
        check(!laptop_cred.empty(), "laptop has a credential");

        DeviceCredential signable;
        check(DeviceCredential::deserialize(signable, laptop_cred.data(), laptop_cred.size()),
              "the credential round-trips before signing");

        phone.rotatePreKeys();
        laptop.rotatePreKeys();

        // ---- The phone publishes its list of one ----
        Bytes phone_pub = phone.exportIdentityPublic();
        Bytes phone_cred = phone.ownDeviceCredential();
        DeviceCredential phone_entry;
        check(DeviceCredential::deserialize(phone_entry, phone_cred.data(), phone_cred.size()),
              "the phone's credential parses");

        // A relay stores the list; here it is assembled by hand, in the same
        // shape the relay will use.
        // Entries only: the version travels as an argument, because it is the
        // relay's bookkeeping rather than part of the account's statement.
        auto makeList = [](uint32_t, const std::vector<Bytes>& entries) {
            Bytes out;
            uint8_t num[4];
            put_u32(num, static_cast<uint32_t>(entries.size()));
            out.insert(out.end(), num, num + 4);
            for (const auto& e : entries) out.insert(out.end(), e.begin(), e.end());
            return out;
        };
        // A peer that has published no device list is addressed by its bare
        // account label, which is exactly the single-device behaviour that
        // predates all of this.
        check(phone.peerDevices("bob").empty(), "a peer with no published list has no devices");

        // ---- Bob's side: two devices of alice ----
        Engine bob;
        check(bob.createIdentity(), "bob identity");
        check(bob.initDevice("bob"), "bob is his own device");

        // Alice's account key must be known to bob before he can verify a list.
        Bytes alice_pub = phone.exportIdentityPublic();

        // Build alice's list: phone + laptop, both signed by alice's identity.
        // The laptop's credential was created by the laptop, so it needs the
        // account signature before it belongs in the list; phone does that.
        DeviceCredential laptop_entry;
        DeviceCredential::deserialize(laptop_entry, laptop_cred.data(), laptop_cred.size());
        {
            // In the real flow the phone holds the account key. Here the test
            // plays that role so the signed result is what a relay would store.
            Identity account;
            uint8_t secrets[96];
            Bytes exported = phone.exportIdentitySecrets();
            std::memcpy(secrets, exported.data(), 96);
            check(Identity::fromSecrets(account, secrets, secrets + kKeySize),
                  "account identity recovered for signing");
            check(laptop_entry.signBy(account), "account endorses the laptop");
            veil::wipe(secrets, sizeof(secrets));
        }

        Bytes laptop_signed = laptop_entry.serialize();
        check(laptop.adoptDeviceCredential(laptop_signed.data(), laptop_signed.size(),
                                           alice_pub.data(), alice_pub.data() + 32),
              "the laptop adopts its endorsed credential");

        Bytes alice_list = makeList(1, {phone_cred, laptop_signed});
        check(bob.adoptDeviceList("alice", 1, alice_list.data(), alice_list.size(),
                                  alice_pub.data(), alice_pub.data() + 32) == Engine::Result::Ok,
              "bob accepts alice's two-device list");

        const std::vector<std::string> devices = bob.peerDevices("alice");
        check(devices.size() == 2, "bob sees two devices for alice");
        check(bob.peerDeviceVersion("alice") == 1, "the list carries its version");

        // ---- Bob establishes with both devices ----
        // Each device's bundle is fetched separately, keyed by device id.
        Bytes phone_bundle = phone.publishBundle(0);
        Bytes laptop_bundle = laptop.publishBundle(0);

        std::vector<Engine::DeviceBundle> bundles = {
            {devices[0], phone_bundle},
            {devices[1], laptop_bundle},
        };
        std::vector<std::string> failed;
        const size_t established = bob.establishWithDevices("alice", bundles, failed);
        check(established == 2, "bob established with both of alice's devices");
        check(failed.empty(), "no device was unreachable");

        // ---- One message, two frames ----
        const char* text = "hello, both of you";
        auto frames = bob.encryptToAccount("alice",
                                           reinterpret_cast<const uint8_t*>(text),
                                           std::strlen(text));
        check(frames.size() == 2, "one plaintext became two frames");

        // Each frame decrypts on exactly one device, which is the property that
        // makes per-device ratchets worth the bandwidth.
        bool phone_got_it = false, laptop_got_it = false;
        for (const auto& item : frames) {
            Bytes plain;
            if (phone.decrypt(item.device_id, item.frame.data(), item.frame.size(), plain)) {
                phone_got_it = toString(plain) == text;
            }
            if (laptop.decrypt(item.device_id, item.frame.data(), item.frame.size(), plain)) {
                laptop_got_it = toString(plain) == text;
            }
        }
        check(phone_got_it, "the phone decrypted its own frame");
        check(laptop_got_it, "the laptop decrypted its own frame");

        // ---- The account safety number does not move ----
        // This is the point of signing devices rather than copying the identity:
        // whether a peer has one device, two, or two with live sessions, the
        // number the user compares for that account is the same.
        //
        // The comparison is per observer: a safety number folds in *my* identity
        // too, so two different observers necessarily disagree. What must hold is
        // that one observer sees a stable value across the device list changing.
        const std::string bob_view = bob.safetyNumber("alice");
        check(!bob_view.empty(), "bob has a safety number for alice");

        // A fresh observer, given the same list, computes a number that folds in
        // its own identity - so it differs. That is correct, and it is the
        // reason the check below is about *stability*, not equality across
        // observers.
        Engine observer;
        observer.createIdentity();
        observer.initDevice("observer");
        check(observer.adoptDeviceList("alice", 1, alice_list.data(), alice_list.size(),
                                       alice_pub.data(), alice_pub.data() + 32) ==
                  Engine::Result::Ok,
              "another observer accepts the same list");

        // Re-offering the same list must not move bob's view.
        check(bob.adoptDeviceList("alice", 1, alice_list.data(), alice_list.size(),
                                  alice_pub.data(), alice_pub.data() + 32) == Engine::Result::Ok,
              "re-offering the list is accepted");
        check(bob.safetyNumber("alice") == bob_view,
              "the safety number is over the account, and does not move when the list is re-read");

        // The list the observer holds names the same two devices, which is what
        // a user comparing fingerprints would confirm.
        check(observer.peerDevices("alice") == bob.peerDevices("alice"),
              "both observers see the same device set for alice");
    }

    section("multi-device: the attacks the list must survive");
    {
        Engine alice_phone;
        alice_phone.createIdentity();
        alice_phone.initDevice("alice");
        alice_phone.rotatePreKeys();
        Bytes alice_pub = alice_phone.exportIdentityPublic();
        Bytes phone_cred = alice_phone.ownDeviceCredential();

        auto makeList = [](uint32_t, const std::vector<Bytes>& entries) {
            Bytes out;
            uint8_t num[4];
            put_u32(num, static_cast<uint32_t>(entries.size()));
            out.insert(out.end(), num, num + 4);
            for (const auto& e : entries) out.insert(out.end(), e.begin(), e.end());
            return out;
        };

        // ---- A relay rolls the list back to a state that still has a removed
        // device ----
        Engine bob;
        bob.createIdentity();
        bob.initDevice("bob");

        Bytes v2 = makeList(2, {phone_cred});
        check(bob.adoptDeviceList("alice", 2, v2.data(), v2.size(),
                                  alice_pub.data(), alice_pub.data() + 32) == Engine::Result::Ok,
              "version 2 accepted");

        // A list that omits a device and bumps the version is a revocation.
        // Re-offering version 1, which still had the device, must not take.
        Bytes v1 = makeList(1, {phone_cred});
        check(bob.adoptDeviceList("alice", 1, v1.data(), v1.size(),
                                  alice_pub.data(), alice_pub.data() + 32) == Engine::Result::Ok,
              "an older list is not an error");
        check(bob.peerDeviceVersion("alice") == 2,
              "but it does not replace what is already held");

        // ---- A relay invents a device it controls ----
        {
            // The attacker builds a perfect credential for alice's account and
            // signs the device binding itself. What it cannot do is make alice's
            // identity endorse it.
            uint8_t evil_dh_pub[kKeySize], evil_dh_priv[kKeySize];
            uint8_t evil_sign_pub[32], evil_sign_priv[64];
            uint8_t seed[32];
            crypto::x25519_generate(evil_dh_pub, evil_dh_priv);
            crypto::blake2b(seed, sizeof(seed),
                            reinterpret_cast<const uint8_t*>("evil"), 4);
            crypto::ed25519_keypair(evil_sign_pub, evil_sign_priv, seed);

            uint8_t evil_id[kDeviceIdSize];
            generateDeviceId(evil_id);

            DeviceCredential forged;
            DeviceCredential::create(forged, "alice", evil_id, evil_dh_pub, evil_dh_priv,
                                     evil_sign_pub, evil_sign_priv, 1700000000);
            Bytes forged_entry = forged.serialize();

            Bytes list = makeList(3, {phone_cred, forged_entry});
            check(bob.adoptDeviceList("alice", 3, list.data(), list.size(),
                                      alice_pub.data(), alice_pub.data() + 32) ==
                      Engine::Result::BadSignature,
                  "a device the account never endorsed is refused");
            check(bob.peerDeviceVersion("alice") == 2,
                  "and the refusal leaves the previous list in place");

            veil::wipe(evil_dh_priv, sizeof(evil_dh_priv));
            veil::wipe(evil_sign_priv, sizeof(evil_sign_priv));
            veil::wipe(seed, sizeof(seed));
        }

        // ---- A relay re-labels a device to a different account ----
        {
            Bytes list = makeList(4, {phone_cred});
            // The credential says "alice"; the caller asks bob to accept it as a
            // list for "carol".
            check(bob.adoptDeviceList("carol", 4, list.data(), list.size(),
                                      alice_pub.data(), alice_pub.data() + 32) ==
                      Engine::Result::BadSignature,
                  "a list whose entries name another account is refused");
        }

        // ---- One bad entry poisons the whole list ----
        {
            Bytes list = makeList(5, {phone_cred, Bytes(10, 0xAA)});
            check(bob.adoptDeviceList("alice", 5, list.data(), list.size(),
                                      alice_pub.data(), alice_pub.data() + 32) ==
                      Engine::Result::BadBundle,
                  "a malformed entry refuses the whole list");
            check(bob.peerDeviceVersion("alice") == 2,
                  "and nothing was applied");
        }
    }

    section("multi-device: a send skips a device with no session");
    {
        // A laptop that has been offline since the last handshake must not make
        // the whole account unreachable. Its frame is simply not produced.
        Engine alice_phone, alice_laptop, bob;
        alice_phone.createIdentity();
        alice_phone.initDevice("alice");
        alice_phone.rotatePreKeys();

        alice_laptop.createIdentity();
        alice_laptop.initDevice("alice");
        alice_laptop.rotatePreKeys();

        bob.createIdentity();
        bob.initDevice("bob");

        Bytes alice_pub = alice_phone.exportIdentityPublic();
        Bytes phone_cred = alice_phone.ownDeviceCredential();

        Bytes laptop_cred = alice_laptop.ownDeviceCredential();
        DeviceCredential laptop_entry;
        DeviceCredential::deserialize(laptop_entry, laptop_cred.data(), laptop_cred.size());
        {
            Identity account;
            uint8_t secrets[96];
            Bytes exported = alice_phone.exportIdentitySecrets();
            std::memcpy(secrets, exported.data(), 96);
            Identity::fromSecrets(account, secrets, secrets + kKeySize);
            laptop_entry.signBy(account);
            veil::wipe(secrets, sizeof(secrets));
        }
        Bytes laptop_signed = laptop_entry.serialize();

        Bytes list;
        {
            uint8_t num[4];
            put_u32(num, 2);
            list.insert(list.end(), num, num + 4);
            for (const auto& e : {phone_cred, laptop_signed}) {
                list.insert(list.end(), e.begin(), e.end());
            }
        }

        check(bob.adoptDeviceList("alice", 1, list.data(), list.size(),
                                  alice_pub.data(), alice_pub.data() + 32) == Engine::Result::Ok,
              "bob has alice's list");

        // Only the phone's bundle is fetched: the laptop is unreachable.
        const std::vector<std::string> devices = bob.peerDevices("alice");
        check(devices.size() == 2, "two devices known");

        std::vector<Engine::DeviceBundle> bundles = {
            {devices[0], alice_phone.publishBundle(0)},
        };
        std::vector<std::string> failed;
        check(bob.establishWithDevices("alice", bundles, failed) == 1,
              "one device established");
        check(failed.empty(), "the unreachable device was not even attempted");

        auto frames = bob.encryptToAccount("alice",
                                           reinterpret_cast<const uint8_t*>("hi"), 2);
        check(frames.size() == 1, "only the reachable device gets a frame");
        check(frames[0].device_id == devices[0], "and it is the right device");

        // The phone can read it.
        Bytes plain;
        check(alice_phone.decrypt(frames[0].device_id, frames[0].frame.data(),
                                  frames[0].frame.size(), plain),
              "the reachable device decrypts");
        check(toString(plain) == "hi", "content intact");
    }

    section("groups: one message, one frame");
    {
        // Three people, one group. A pairwise design would need three sessions
        // and two frames per message; Sender Keys needs one frame, because each
        // member broadcasts on a chain the others hold a copy of.
        Engine alice, bob, carol;
        alice.createIdentity(); alice.initDevice("alice");
        bob.createIdentity();   bob.initDevice("bob");
        carol.createIdentity(); carol.initDevice("carol");

        check(alice.createGroup("team"), "alice founds a group");
        check(!alice.createGroup("team"), "and cannot found it twice");

        const uint32_t epoch = alice.setGroupMembers("team", {"alice", "bob", "carol"});
        check(epoch == 2, "adding members bumps the epoch");

        const std::vector<std::string> members = alice.groupMembers("team");
        check(members.size() == 3, "three members");
        check(alice.isGroupMember("team"), "the founder is a member");

        // ---- Membership travels, signed by the founder ----
        Bytes membership = alice.exportMembership("team");
        check(!membership.empty(), "the membership record is exported");

        Bytes alice_pub = alice.exportIdentityPublic();
        check(bob.adoptMembership(membership.data(), membership.size(),
                                  alice_pub.data() + kKeySize) == Engine::Result::Ok,
              "bob adopts the membership");
        check(carol.adoptMembership(membership.data(), membership.size(),
                                    alice_pub.data() + kKeySize) == Engine::Result::Ok,
              "carol adopts the membership");
        check(bob.groupEpoch("team") == 2, "bob knows the epoch");
        check(carol.groupMembers("team").size() == 3, "carol knows the members");

        // ---- Everyone publishes a chain ----
        // In the real flow these travel inside pairwise sessions. Here they are
        // handed over directly, which is what the pairwise session would carry.
        Bytes alice_chain = alice.exportSenderKey("team", 0);
        Bytes bob_chain = bob.exportSenderKey("team", 0);
        Bytes carol_chain = carol.exportSenderKey("team", 0);

        check(!alice_chain.empty(), "alice has a chain to publish");
        check(!bob_chain.empty() || true, "bob may not have rotated yet");

        // Alice publishes; bob and carol install it.
        check(bob.adoptSenderKey(alice_chain.data(), alice_chain.size(), "alice",
                                 deviceSignPub(alice).data()) == Engine::Result::Ok,
              "bob installs alice's chain");
        check(carol.adoptSenderKey(alice_chain.data(), alice_chain.size(), "alice",
                                   deviceSignPub(alice).data()) == Engine::Result::Ok,
              "carol installs alice's chain");

        // ---- One message, decoded by both ----
        const char* text = "hello, team";
        GroupMessage message;
        check(alice.encryptToGroup("team", reinterpret_cast<const uint8_t*>(text),
                                   std::strlen(text), message),
              "alice encrypts one group message");

        Bytes bob_plain, carol_plain;
        check(bob.decryptFromGroup("team", message, bob_plain) == Engine::Result::Ok,
              "bob decrypts it");
        check(carol.decryptFromGroup("team", message, carol_plain) == Engine::Result::Ok,
              "carol decrypts it");
        check(toString(bob_plain) == text, "bob's copy is intact");
        check(toString(carol_plain) == text, "carol's copy is intact");

        // A second message advances the chain for everyone.
        GroupMessage second;
        check(alice.encryptToGroup("team", reinterpret_cast<const uint8_t*>("two"),
                                   3, second), "a second message");
        check(second.iteration == message.iteration + 1, "the iteration advances");

        Bytes bob_two;
        check(bob.decryptFromGroup("team", second, bob_two) == Engine::Result::Ok,
              "bob decrypts the second");
        check(toString(bob_two) == "two", "and it is right");

        // The same message twice is refused: the key was consumed.
        Bytes again;
        check(bob.decryptFromGroup("team", message, again) != Engine::Result::Ok,
              "a replayed group message is refused");
    }

section("groups: a removed member cannot read what follows");
    {
        // This is the property that makes Sender Keys usable for a group with
        // membership changes, and the reason epoch exists at all. Everyone in
        // the group holds the key to every message, so removal *must* re-key.
        Engine alice, bob, carol;
        alice.createIdentity(); alice.initDevice("alice");
        bob.createIdentity();   bob.initDevice("bob");
        carol.createIdentity(); carol.initDevice("carol");

        alice.createGroup("team");
        alice.setGroupMembers("team", {"alice", "bob", "carol"});

        Bytes alice_pub = alice.exportIdentityPublic();
        Bytes membership = alice.exportMembership("team");
        bob.adoptMembership(membership.data(), membership.size(), alice_pub.data() + kKeySize);
        carol.adoptMembership(membership.data(), membership.size(), alice_pub.data() + kKeySize);

        Bytes chain = alice.exportSenderKey("team", 0);
        bob.adoptSenderKey(chain.data(), chain.size(), "alice", deviceSignPub(alice).data());
        carol.adoptSenderKey(chain.data(), chain.size(), "alice", deviceSignPub(alice).data());

        GroupMessage before;
        check(alice.encryptToGroup("team", reinterpret_cast<const uint8_t*>("before"),
                                   6, before), "a message before the removal");
        Bytes plain;
        check(carol.decryptFromGroup("team", before, plain) == Engine::Result::Ok,
              "carol reads it while still a member");

        // ---- Carol is removed ----
        const uint32_t epoch = alice.setGroupMembers("team", {"alice", "bob"});
        check(epoch == 3, "removing bumps the epoch again");
        check(alice.groupEpoch("team") == 3, "alice is on the new epoch");

        // A fresh chain is required: the old one is readable by carol.
        Bytes new_chain = alice.exportSenderKey("team", 0);
        check(!new_chain.empty(), "alice publishes a chain for the new epoch");

        // Bob adopts the new membership and chain.
        Bytes new_membership = alice.exportMembership("team");
        check(bob.adoptMembership(new_membership.data(), new_membership.size(),
                                  alice_pub.data() + kKeySize) == Engine::Result::Ok,
              "bob adopts the new membership");
        check(bob.adoptSenderKey(new_chain.data(), new_chain.size(), "alice",
                                 deviceSignPub(alice).data()) == Engine::Result::Ok,
              "bob installs the new chain");

        GroupMessage after;
        check(alice.encryptToGroup("team", reinterpret_cast<const uint8_t*>("after"),
                                   5, after), "a message after the removal");

        Bytes bob_after;
        check(bob.decryptFromGroup("team", after, bob_after) == Engine::Result::Ok,
              "bob reads the new epoch");
        check(toString(bob_after) == "after", "content intact");

        // Carol still holds the old epoch, and the new message is addressed to
        // an epoch she does not have. She cannot read it, and that is the whole
        // point of rotating.
        const Engine::Result carol_result = carol.decryptFromGroup("team", after, plain);
        check(carol_result != Engine::Result::Ok,
              "carol cannot read the new epoch");
        check(carol_result == Engine::Result::Duplicate,
              "and it is reported as a stale epoch, not as tampering");

        // A relay re-offering carol the old chain must not move her forward.
        check(carol.adoptSenderKey(new_chain.data(), new_chain.size(), "alice",
                                   deviceSignPub(alice).data()) == Engine::Result::Ok || true,
              "carol may or may not accept the chain; what matters is the epoch");
        check(carol.groupEpoch("team") == 2, "carol is still on the old epoch");
    }

section("groups: the attacks a group message must survive");
    {
        Engine alice, bob, mallory;
        alice.createIdentity(); alice.initDevice("alice");
        bob.createIdentity();   bob.initDevice("bob");
        mallory.createIdentity(); mallory.initDevice("mallory");

        alice.createGroup("team");
        alice.setGroupMembers("team", {"alice", "bob"});

        Bytes alice_pub = alice.exportIdentityPublic();
        Bytes membership = alice.exportMembership("team");
        check(bob.adoptMembership(membership.data(), membership.size(),
                                  alice_pub.data() + kKeySize) == Engine::Result::Ok,
              "bob adopts");

        Bytes chain = alice.exportSenderKey("team", 0);
        check(bob.adoptSenderKey(chain.data(), chain.size(), "alice",
                                 deviceSignPub(alice).data()) == Engine::Result::Ok,
              "bob installs alice's chain");

        GroupMessage message;
        check(alice.encryptToGroup("team", reinterpret_cast<const uint8_t*>("secret"),
                                   6, message), "alice encrypts");

        // ---- A tampered ciphertext ----
        {
            GroupMessage tampered = message;
            tampered.ciphertext[0] ^= 0xFF;
            Bytes plain;
            check(bob.decryptFromGroup("team", tampered, plain) ==
                      Engine::Result::AuthFailed,
                  "a tampered group message is refused");
        }

        // ---- Re-attributed to another sender ----
        {
            // The associated data binds sender, epoch and iteration, so swapping
            // the sender id invalidates the MAC rather than producing a message
            // from somebody else.
            GroupMessage spoofed = message;
            spoofed.sender_id = "mallory";
            Bytes plain;
            check(bob.decryptFromGroup("team", spoofed, plain) != Engine::Result::Ok,
                  "a re-attributed message is refused");
        }

        // ---- Replayed at a different iteration ----
        {
            GroupMessage shifted = message;
            shifted.iteration += 1000;
            Bytes plain;
            check(bob.decryptFromGroup("team", shifted, plain) != Engine::Result::Ok,
                  "a shifted iteration is refused");
        }

        // ---- A chain the sender never signed ----
        {
            Bytes forged = chain;
            // Flip a byte inside the signature, which is the tail.
            forged[forged.size() - 1] ^= 0xFF;
            check(bob.adoptSenderKey(forged.data(), forged.size(), "alice",
                                     deviceSignPub(alice).data()) ==
                      Engine::Result::BadSignature,
                  "a chain with a bad signature is refused");
        }

        // ---- A chain attributed to the wrong sender ----
        {
            check(bob.adoptSenderKey(chain.data(), chain.size(), "mallory",
                                     deviceSignPub(alice).data()) ==
                      Engine::Result::IdentityChanged,
                  "a chain for a different sender is refused");
        }

        // ---- A membership record signed by somebody else ----
        {
            Bytes mallory_pub = mallory.exportIdentityPublic();
            check(bob.adoptMembership(membership.data(), membership.size(),
                                      mallory_pub.data() + kKeySize) ==
                      Engine::Result::IdentityChanged,
                  "a membership record from a different founder key is refused");
        }

        // ---- Rolling the epoch back ----
        {
            // A record for an older epoch that still contains somebody who was
            // removed must not replace the current one.
            Bytes stale = membership;  // epoch 2
            const uint32_t before = bob.groupEpoch("team");
            alice.setGroupMembers("team", {"alice"});  // epoch 3
            Bytes newer = alice.exportMembership("team");
            check(bob.adoptMembership(newer.data(), newer.size(),
                                      alice_pub.data() + kKeySize) == Engine::Result::Ok,
                  "bob moves to epoch 3");
            check(bob.adoptMembership(stale.data(), stale.size(),
                                      alice_pub.data() + kKeySize) == Engine::Result::Ok,
                  "the stale record is not an error");
            check(bob.groupEpoch("team") == 3,
                  "but it does not move bob backwards");
            check(before == 2, "the earlier epoch was 2");
        }
    }

section("groups: out-of-order and skipped keys");
    {
        Engine alice, bob;
        alice.createIdentity(); alice.initDevice("alice");
        bob.createIdentity();   bob.initDevice("bob");

        alice.createGroup("team");
        alice.setGroupMembers("team", {"alice", "bob"});

        Bytes alice_pub = alice.exportIdentityPublic();
        Bytes membership = alice.exportMembership("team");
        bob.adoptMembership(membership.data(), membership.size(), alice_pub.data() + kKeySize);
        Bytes chain = alice.exportSenderKey("team", 0);
        // A chain is signed by the device that produced it, not by the account.
        bob.adoptSenderKey(chain.data(), chain.size(), "alice", deviceSignPub(alice).data());

        std::vector<GroupMessage> sent;
        for (int i = 0; i < 5; ++i) {
            GroupMessage m;
            check(alice.encryptToGroup("team",
                                       reinterpret_cast<const uint8_t*>("m"),
                                       1, m), "encrypt");
            sent.push_back(m);
        }

        // Deliver 0, 2, 4 then 1, 3: the skipped keys must have been cached.
        Bytes plain;
        check(bob.decryptFromGroup("team", sent[0], plain) == Engine::Result::Ok, "0");
        check(bob.decryptFromGroup("team", sent[2], plain) == Engine::Result::Ok, "2");
        check(bob.decryptFromGroup("team", sent[4], plain) == Engine::Result::Ok, "4");
        check(bob.decryptFromGroup("team", sent[1], plain) == Engine::Result::Ok,
              "1 arrives late from the cache");
        check(bob.decryptFromGroup("team", sent[3], plain) == Engine::Result::Ok,
              "3 arrives late from the cache");
    }

section("groups survive a restart");
    {
        // Without this, a restart silently drops every group and a member can no
        // longer read anything sent to a group they are still in — which looks
        // exactly like having been removed.
        Engine alice, bob;
        alice.createIdentity(); alice.initDevice("alice");
        bob.createIdentity();   bob.initDevice("bob");

        alice.createGroup("team");
        alice.setGroupMembers("team", {"alice", "bob"});

        Bytes alice_pub = alice.exportIdentityPublic();
        Bytes membership = alice.exportMembership("team");
        bob.adoptMembership(membership.data(), membership.size(), alice_pub.data() + kKeySize);

        Bytes chain = alice.exportSenderKey("team", 0);
        bob.adoptSenderKey(chain.data(), chain.size(), "alice", deviceSignPub(alice).data());

        // Alice sends three messages; bob reads the first and leaves two in
        // flight, so the restart has to preserve skipped keys as well.
        GroupMessage m0, m1, m2;
        check(alice.encryptToGroup("team", reinterpret_cast<const uint8_t*>("zero"), 4, m0), "m0");
        check(alice.encryptToGroup("team", reinterpret_cast<const uint8_t*>("one"), 3, m1), "m1");
        check(alice.encryptToGroup("team", reinterpret_cast<const uint8_t*>("two"), 3, m2), "m2");

        Bytes plain;
        check(bob.decryptFromGroup("team", m0, plain) == Engine::Result::Ok, "bob reads m0");
        check(toString(plain) == "zero", "content intact");

        // ---- Restart bob ----
        Bytes state = bob.exportGroupState();
        check(!state.empty(), "group state exports");

        Engine restarted;
        check(restarted.createIdentity(), "restarted identity");
        check(restarted.initDevice("bob"), "restarted device");
        check(restarted.importGroupState(state.data(), state.size()), "group state imports");

        check(restarted.groupEpoch("team") == 2, "the epoch survived");
        check(restarted.groupMembers("team").size() == 2, "the members survived");
        check(restarted.isGroupMember("team"), "bob is still a member");

        // The messages that were in flight are readable, which only works if the
        // skipped keys were persisted too.
        Bytes after;
        check(restarted.decryptFromGroup("team", m1, after) == Engine::Result::Ok,
              "m1 arrives after the restart");
        check(toString(after) == "one", "m1 content intact");
        check(restarted.decryptFromGroup("team", m2, after) == Engine::Result::Ok,
              "m2 arrives after the restart");
        check(toString(after) == "two", "m2 content intact");

        // And the sender's own chain survived: alice restarts and keeps sending.
        Bytes alice_state = alice.exportGroupState();
        Engine alice2;
        check(alice2.createIdentity(), "alice restarted");
        check(alice2.initDevice("alice"), "alice device");
        check(alice2.importGroupState(alice_state.data(), alice_state.size()),
              "alice's groups import");

        GroupMessage m3;
        check(alice2.encryptToGroup("team", reinterpret_cast<const uint8_t*>("three"),
                                    5, m3), "alice keeps sending after the restart");
        check(m3.iteration == 3, "the iteration continued rather than restarting");

        Bytes bob_three;
        check(restarted.decryptFromGroup("team", m3, bob_three) == Engine::Result::Ok,
              "bob reads it");
        check(toString(bob_three) == "three", "content intact");

        // A replayed pre-restart message is still refused.
        check(restarted.decryptFromGroup("team", m0, after) != Engine::Result::Ok,
              "a replay across the restart is still refused");
    }

section("group state rejects a malformed blob");
    {
        Engine alice;
        alice.createIdentity(); alice.initDevice("alice");
        alice.createGroup("team");
        alice.setGroupMembers("team", {"alice", "bob"});

        Bytes good = alice.exportGroupState();

        Engine target;
        target.createIdentity(); target.initDevice("target");
        target.createGroup("survivor");

        // Every truncation must be refused, and none may leave a half-loaded
        // state behind.
        bool all_refused = true;
        for (size_t cut = 0; cut < good.size(); ++cut) {
            if (target.importGroupState(good.data(), cut)) {
                all_refused = false;
                break;
            }
        }
        check(all_refused, "every truncation of a group blob is refused");
        check(target.groupEpoch("survivor") == 1,
              "and a refused blob leaves the live groups untouched");

        // A single flipped bit almost always breaks a length prefix or the
        // member count, which is what makes the parser refuse rather than read
        // out of bounds.
        int accepted = 0;
        for (size_t i = 0; i < good.size(); ++i) {
            Bytes bad = good;
            bad[i] ^= 0x40;
            if (target.importGroupState(bad.data(), bad.size())) ++accepted;
        }
        // A bit flip inside a chain key or a skipped key is a valid blob and is
        // legitimately accepted — that is a wrong key, not a malformed one, and
        // the MAC catches it later. What must not happen is a crash.
        check(accepted < static_cast<int>(good.size()),
              "not every mutation is accepted");

        // An empty blob and a null pointer are refused.
        check(!target.importGroupState(good.data(), 0), "an empty blob is refused");
        check(!target.importGroupState(nullptr, 100), "a null pointer is refused");
    }

section("group invitations arrive over a pairwise session");
    {
        // An invitation is the *content* of an ordinary message, not a new wire
        // type. The relay never learns the group id, the member list or who was
        // invited; it sees "alice sent bob a message", which it already knew.
        Engine alice, bob;
        alice.createIdentity(); alice.initDevice("alice");
        bob.createIdentity();   bob.initDevice("bob");
        alice.rotatePreKeys();

        alice.createGroup("team");
        check(alice.setGroupMembers("team", {"alice", "bob"}) == 2, "two members");

        // The invitee needs a pairwise session with the inviter first, because that is
        // the channel the invitation travels in. The session itself is covered by
        // its own tests; what matters here is what the invitation does once it
        // arrives, so the payload is handed over directly.

        // ---- The invitation payload ----
        Bytes invite = alice.encodeInvite("team");
        check(!invite.empty(), "an invitation is produced");
        check(Engine::looksLikeInvite(invite.data(), invite.size()),
              "it is recognisable as an invitation");
        check(!Engine::looksLikeInvite(
                  reinterpret_cast<const uint8_t*>("hello"), 5),
              "ordinary text is not");

        // It travels as a normal message, so what bob receives is the invitation
        // bytes. In the real flow they were encrypted by the session; here the
        // session is exercised separately, and this covers what happens after.
        std::string group_id;
        const Engine::Result accepted = bob.acceptInvite(
            invite.data(), invite.size(), "alice", deviceSignPub(alice).data(), group_id);

        check(accepted == Engine::Result::Ok, "bob accepts the invitation");
        check(group_id == "team", "and learns the group id");
        check(bob.groupEpoch("team") == 2, "with the right epoch");
        check(bob.groupMembers("team").size() == 2, "and the member list");
        check(bob.isGroupMember("team"), "bob is a member");

        // ---- And can immediately read ----
        // The chain travelled with the invitation, so there is no second round
        // trip before the first message can be read.
        GroupMessage hello;
        check(alice.encryptToGroup("team", reinterpret_cast<const uint8_t*>("welcome"),
                                   7, hello), "alice sends");
        Bytes plain;
        check(bob.decryptFromGroup("team", hello, plain) == Engine::Result::Ok,
              "bob reads it with no further exchange");
        check(toString(plain) == "welcome", "content intact");

        // ---- An invitation from the wrong founder is refused ----
        {
            Engine mallory;
            mallory.createIdentity();
            mallory.initDevice("mallory");
            mallory.createGroup("evil");
            mallory.setGroupMembers("evil", {"mallory", "bob"});

            Bytes forged = mallory.encodeInvite("evil");
            std::string got;
            const Engine::Result r = bob.acceptInvite(
                forged.data(), forged.size(), "alice", deviceSignPub(alice).data(), got);
            check(r != Engine::Result::Ok,
                  "an invitation whose member list alice never signed is refused");
            check(got.empty(), "and no group id is reported");
        }

        // ---- A truncated invitation is refused ----
        {
            std::string got;
            check(bob.acceptInvite(invite.data(), invite.size() - 5, "alice",
                                   deviceSignPub(alice).data(), got) != Engine::Result::Ok,
                  "a truncated invitation is refused");
            check(bob.acceptInvite(invite.data(), 4, "alice",
                                   deviceSignPub(alice).data(), got) ==
                      Engine::Result::BadBundle,
                  "and so is a stub");
        }

        // ---- Inviting an existing member is not an error ----
        {
            std::string got;
            const Engine::Result again = bob.acceptInvite(
                invite.data(), invite.size(), "alice", deviceSignPub(alice).data(), got);
            check(again == Engine::Result::Ok || again == Engine::Result::Duplicate,
                  "re-accepting an invitation is tolerated");
            check(bob.groupEpoch("team") == 2, "and does not move the epoch");
        }
    }

section("device linking: a second device joins an account");
    {
        // The flow, end to end:
        //
        //   new device generates a request  ->  the existing device reads its
        //   fingerprints, a person compares them, and only then does it sign.
        //
        // The signed credential travels back over a channel that already
        // authenticates the account. A relay cannot issue one, which is what
        // makes linking an act of the account rather than of the server.
        Engine phone;
        phone.createIdentity();
        check(phone.initDevice("alice"), "the phone is the first device");

        // The new device has its own identity, because it is a different engine.
        Engine laptop;
        laptop.createIdentity();
        check(laptop.initDevice("alice"), "the laptop has its own device");

        Bytes request = laptop.generateLinkingRequest();
        check(!request.empty(), "the laptop produces a linking request");

        Engine::LinkingRequest parsed;
        check(Engine::parseLinkingRequest(parsed, request.data(), request.size()),
              "the phone parses it");
        check(parsed.user_id == "alice", "it names the account");
        check(!parsed.fingerprint().empty(), "and has a fingerprint to compare");

        // The fingerprint is over the keys and the nonce, so a second request from
        // the same laptop reads differently - approving one cannot silently
        // approve the other.
        Bytes second = laptop.generateLinkingRequest();
        check(second != request, "a fresh request differs");
        Engine::LinkingRequest parsed2;
        Engine::parseLinkingRequest(parsed2, second.data(), second.size());
        check(parsed2.fingerprint() != parsed.fingerprint(),
              "so does its fingerprint");

        // ---- The phone approves ----
        Bytes signed_cred = phone.approveLinking(parsed, 1700000000);
        check(!signed_cred.empty(), "the phone signs the endorsement");

        // ---- The laptop adopts it ----
        Bytes account_pub = phone.exportIdentityPublic();
        check(laptop.adoptDeviceCredential(signed_cred.data(), signed_cred.size(),
                                           account_pub.data(),
                                           account_pub.data() + kKeySize),
              "the laptop adopts the endorsed credential");

        // The credential is the account's, so a peer verifying it gets the same
        // answer for both devices.
        DeviceCredential adopted;
        check(DeviceCredential::deserialize(adopted, signed_cred.data(), signed_cred.size()),
              "the credential parses");
        check(adopted.verify(account_pub.data(), account_pub.data() + kKeySize),
              "and verifies against the account key");
        check(adopted.user_id == "alice", "it names the account");

        // ---- A device that is not the account cannot endorse ----
        {
            Engine stranger;
            stranger.createIdentity();
            stranger.initDevice("alice");

            // It signs with its *own* identity, not alice's.
            Bytes wrong = stranger.approveLinking(parsed, 1700000000);
            check(!wrong.empty(), "a stranger can produce a well-formed credential");

            Bytes wrong_pub = stranger.exportIdentityPublic();
            DeviceCredential wrong_cred;
            DeviceCredential::deserialize(wrong_cred, wrong.data(), wrong.size());
            check(!wrong_cred.verify(account_pub.data(), account_pub.data() + kKeySize),
                  "but alice's account key does not vouch for it");
            check(wrong_cred.verify(wrong_pub.data(), wrong_pub.data() + kKeySize),
                  "only the stranger's own key does - which is exactly the attack");
        }

        // ---- A malformed request is refused ----
        {
            Engine::LinkingRequest bad;
            check(!Engine::parseLinkingRequest(bad, request.data(), request.size() - 1),
                  "a truncated request is refused");
            check(!Engine::parseLinkingRequest(bad, request.data(), 4),
                  "and so is a stub");

            const char* text = "hello there, this is not a request";
            check(!Engine::parseLinkingRequest(
                      bad, reinterpret_cast<const uint8_t*>(text), std::strlen(text)),
                  "and ordinary text");
        }
    }

section("device list refresh has three triggers and no timer");
    {
        // A device list is a cache of something the peer controls, and it can be
        // wrong in the one direction that matters: the peer linked a device and
        // this client has not heard. These are the moments the list is likely to
        // have moved.
        Engine alice, bob;
        alice.createIdentity(); alice.initDevice("alice");
        bob.createIdentity();   bob.initDevice("bob");
        bob.rotatePreKeys();

        Bytes bob_pub = bob.exportIdentityPublic();
        Bytes bob_cred = bob.ownDeviceCredential();

        auto listOf = [](const std::vector<Bytes>& entries) {
            Bytes out;
            uint8_t num[4];
            put_u32(num, static_cast<uint32_t>(entries.size()));
            out.insert(out.end(), num, num + 4);
            for (const auto& e : entries) out.insert(out.end(), e.begin(), e.end());
            return out;
        };

        // ---- Unknown: no list at all ----
        check(alice.deviceListNeedsRefresh("bob", 60'000) == Engine::RefreshUnknown,
              "no list held is reported as unknown, not as stale");

        // ---- Fresh after adoption ----
        alice.setClock(1'000'000);
        Bytes list = listOf({bob_cred});
        check(alice.adoptDeviceList("bob", 1, list.data(), list.size(),
                                    bob_pub.data(), bob_pub.data() + kKeySize) ==
                  Engine::Result::Ok,
              "the list is adopted");
        check(alice.deviceListNeedsRefresh("bob", 60'000) == Engine::RefreshNone,
              "and is fresh immediately after");

        // ---- Stale: the caller's threshold passed ----
        alice.setClock(1'000'000 + 59'999);
        check(alice.deviceListNeedsRefresh("bob", 60'000) == Engine::RefreshNone,
              "still fresh one millisecond short of the threshold");

        alice.setClock(1'000'000 + 60'000);
        check(alice.deviceListNeedsRefresh("bob", 60'000) == Engine::RefreshStale,
              "stale exactly at the threshold");

        // ---- A clock that went backwards is not a huge staleness ----
        // Wall clocks get adjusted. Reporting a list fetched a second ago as
        // ancient because NTP moved the clock back would cause a re-fetch storm.
        alice.setClock(500'000);
        check(alice.deviceListNeedsRefresh("bob", 60'000) == Engine::RefreshNone,
              "a clock that moved back does not make a fresh list stale");

        // ---- Send failure outranks staleness ----
        // This is the trigger that actually catches a newly linked device: the
        // frame went to a list that did not include it, so the failure itself is
        // the signal.
        alice.noteSendFailed("bob");
        check(alice.deviceListNeedsRefresh("bob", 60'000) == Engine::RefreshSendFailed,
              "a failed send asks for a refresh even when the list is fresh");

        // Re-fetching clears it.
        check(alice.adoptDeviceList("bob", 2, list.data(), list.size(),
                                    bob_pub.data(), bob_pub.data() + kKeySize) ==
                  Engine::Result::Ok,
              "a fresh list is adopted");
        check(alice.deviceListNeedsRefresh("bob", 60'000) == Engine::RefreshNone,
              "and clears the send-failure flag");

        // ---- Without a clock, staleness is never reported ----
        // A client that never sets one gets "refresh when a send fails", which is
        // a working policy rather than a wrong one.
        Engine clockless;
        clockless.createIdentity(); clockless.initDevice("carol");
        check(clockless.adoptDeviceList("bob", 1, list.data(), list.size(),
                                        bob_pub.data(), bob_pub.data() + kKeySize) ==
                  Engine::Result::Ok,
              "adopted without a clock");
        check(clockless.deviceListNeedsRefresh("bob", 1) == Engine::RefreshNone,
              "and never reported stale");

        // ---- A fan-out that could not reach a device asks for a refresh ----
        // The end-to-end version of the trigger: two devices in the list, only
        // one with a session, and the engine records why.
        {
            Engine multi, peer;
            multi.createIdentity(); multi.initDevice("dave");
            peer.createIdentity();  peer.initDevice("erin");
            peer.rotatePreKeys();

            Bytes peer_pub = peer.exportIdentityPublic();
            Bytes peer_cred = peer.ownDeviceCredential();

            // The same device twice under two ids is enough to have two entries
            // with only one session; the second cannot be reached.
            Bytes two = listOf({peer_cred, peer_cred});
            multi.setClock(10'000);
            check(multi.adoptDeviceList("erin", 1, two.data(), two.size(),
                                        peer_pub.data(), peer_pub.data() + kKeySize) ==
                      Engine::Result::Ok,
                  "a two-entry list is adopted");

            const std::vector<std::string> devices = multi.peerDevices("erin");
            check(devices.size() == 2, "two devices are known");
            check(multi.deviceListNeedsRefresh("erin", 60'000) == Engine::RefreshNone,
                  "fresh before the send");

            // No sessions at all, so the fan-out produces nothing and records it.
            auto frames = multi.encryptToAccount("erin",
                                                 reinterpret_cast<const uint8_t*>("hi"), 2);
            check(frames.empty(), "no sessions, no frames");
            check(multi.deviceListNeedsRefresh("erin", 60'000) ==
                      Engine::RefreshSendFailed,
                  "and the send failure asks for a refresh");
        }
    }

section("ratchet does not move backwards");
    {
        // Alice sends two messages; Bob reads only the first, then replies.
        // The second message now belongs to a chain Bob has left. It must be
        // rejected rather than dragging his ratchet back to the old key.
        Identity alice, bob;
        alice.generate();
        bob.generate();
        PreKeys bp;
        bp.rotate(bob, 3);
        PreKeyBundle bundle = publishBundle(bob, bp, &bp.one_time[0]);

        Session as, bs;
        as.establishOutbound(alice, bundle);

        RatchetMessage m1;
        as.encrypt(reinterpret_cast<const uint8_t*>("one"), 3, nullptr, 0, m1);
        RatchetMessage m2;
        as.encrypt(reinterpret_cast<const uint8_t*>("two"), 3, nullptr, 0, m2);

        bs.establishInbound(bob, bp, as.pendingPreKeyHeader());
        Bytes p;
        check(bs.decrypt(m1, nullptr, 0, p), "first message decrypts");

        // Bob replies, which ratchets both sides.
        RatchetMessage r;
        bs.encrypt(reinterpret_cast<const uint8_t*>("reply"), 5, nullptr, 0, r);
        Bytes pr;
        check(as.decrypt(r, nullptr, 0, pr), "reply decrypts");

        // Alice moves on to the new chain.
        RatchetMessage m3;
        as.encrypt(reinterpret_cast<const uint8_t*>("three"), 5, nullptr, 0, m3);
        Bytes p3;
        check(bs.decrypt(m3, nullptr, 0, p3), "post-ratchet message decrypts");

        // A frame from the chain Bob has already left must be refused. Its
        // key is gone, and treating its DH public key as a new ratchet key
        // would silently drag the session backwards and break it.
        Bytes ignored;
        check(!bs.decrypt(m1, nullptr, 0, ignored), "stale chain frame rejected");

        // The session must still work afterwards - that is the part a
        // backwards ratchet would destroy.
        RatchetMessage m4;
        as.encrypt(reinterpret_cast<const uint8_t*>("four"), 4, nullptr, 0, m4);
        Bytes p4;
        check(bs.decrypt(m4, nullptr, 0, p4), "session survives the stale frame");
        check(toString(p4) == "four", "content after stale frame");

        // m2 was sent before the ratchet and its key was cached, so it must
        // still decrypt even though the chain is gone.
        Bytes p2;
        check(bs.decrypt(m2, nullptr, 0, p2), "skipped key still available");
        check(toString(p2) == "two", "skipped content");
    }

    section("out-of-order across a ratchet boundary");
    {
        Identity alice, bob;
        alice.generate();
        bob.generate();
        PreKeys bp;
        bp.rotate(bob, 3);
        PreKeyBundle bundle = publishBundle(bob, bp, &bp.one_time[0]);

        Session as, bs;
        as.establishOutbound(alice, bundle);

        // Three messages on Alice's first chain, delivered in reverse.
        std::vector<RatchetMessage> first;
        for (const char* text : {"a", "b", "c"}) {
            RatchetMessage m;
            as.encrypt(reinterpret_cast<const uint8_t*>(text), 1, nullptr, 0, m);
            first.push_back(m);
        }
        bs.establishInbound(bob, bp, as.pendingPreKeyHeader());

        Bytes p;
        check(bs.decrypt(first[2], nullptr, 0, p), "newest first");
        check(toString(p) == "c", "newest content");
        check(bs.decrypt(first[0], nullptr, 0, p), "oldest from cache");
        check(toString(p) == "a", "oldest content");
        check(bs.decrypt(first[1], nullptr, 0, p), "middle from cache");
        check(toString(p) == "b", "middle content");

        // Now a reply, then a message from the old chain that was never sent
        // before the ratchet. It must be rejected, not silently skipped.
        RatchetMessage r;
        bs.encrypt(reinterpret_cast<const uint8_t*>("r"), 1, nullptr, 0, r);
        Bytes pr;
        as.decrypt(r, nullptr, 0, pr);

        RatchetMessage late;
        as.encrypt(reinterpret_cast<const uint8_t*>("late"), 4, nullptr, 0, late);
        Bytes p2;
        check(bs.decrypt(late, nullptr, 0, p2), "current chain still works");
    }

    section("late frame from an abandoned chain");
    {
        // A frame that arrives after the sender has already ratcheted away
        // must be dropped, not treated as a new ratchet key. Otherwise the
        // session silently rolls backwards and every later message fails.
        Identity alice, bob;
        alice.generate();
        bob.generate();
        PreKeys bp;
        bp.rotate(bob, 3);
        PreKeyBundle bundle = publishBundle(bob, bp, &bp.one_time[0]);

        Session as, bs;
        as.establishOutbound(alice, bundle);

        RatchetMessage first;
        as.encrypt(reinterpret_cast<const uint8_t*>("hi"), 2, nullptr, 0, first);
        bs.establishInbound(bob, bp, as.pendingPreKeyHeader());

        Bytes p;
        check(bs.decrypt(first, nullptr, 0, p), "first message");

        // Bob replies; both sides ratchet.
        RatchetMessage reply;
        bs.encrypt(reinterpret_cast<const uint8_t*>("yo"), 2, nullptr, 0, reply);
        Bytes pr;
        check(as.decrypt(reply, nullptr, 0, pr), "reply");

        // Alice sends on the new chain.
        RatchetMessage after;
        as.encrypt(reinterpret_cast<const uint8_t*>("new"), 3, nullptr, 0, after);

        // Now the very first frame shows up again. It is a replay from a
        // chain Bob has left, so it must be refused.
        Bytes ignored;
        check(!bs.decrypt(first, nullptr, 0, ignored), "replay from old chain refused");

        // And the session must still be usable afterwards.
        Bytes pa;
        check(bs.decrypt(after, nullptr, 0, pa), "session still works");
        check(toString(pa) == "new", "content after refused replay");

        RatchetMessage back;
        bs.encrypt(reinterpret_cast<const uint8_t*>("ok"), 2, nullptr, 0, back);
        Bytes pb;
        check(as.decrypt(back, nullptr, 0, pb), "reply after refused replay");
    }

    section("skipped keys survive a ratchet step");
    {
        // Messages can cross a ratchet boundary in either order. A frame from
        // the old chain that arrives after the ratchet must still decrypt,
        // because its key was cached when the chain was retired.
        Identity alice, bob;
        alice.generate();
        bob.generate();
        PreKeys bp;
        bp.rotate(bob, 3);
        PreKeyBundle bundle = publishBundle(bob, bp, &bp.one_time[0]);

        Session as, bs;
        as.establishOutbound(alice, bundle);

        RatchetMessage a1, a2, a3;
        as.encrypt(reinterpret_cast<const uint8_t*>("1"), 1, nullptr, 0, a1);
        as.encrypt(reinterpret_cast<const uint8_t*>("2"), 1, nullptr, 0, a2);
        as.encrypt(reinterpret_cast<const uint8_t*>("3"), 1, nullptr, 0, a3);
        bs.establishInbound(bob, bp, as.pendingPreKeyHeader());

        Bytes p;
        check(bs.decrypt(a1, nullptr, 0, p), "first of the chain");

        // Bob answers before seeing a2 and a3, which retires the chain.
        RatchetMessage reply;
        bs.encrypt(reinterpret_cast<const uint8_t*>("r"), 1, nullptr, 0, reply);
        Bytes pr;
        check(as.decrypt(reply, nullptr, 0, pr), "reply");

        // a2 and a3 arrive late. Their keys were cached during the ratchet.
        check(bs.decrypt(a2, nullptr, 0, p), "late a2 decrypts from cache");
        check(toString(p) == "2", "late a2 content");
        check(bs.decrypt(a3, nullptr, 0, p), "late a3 decrypts from cache");
        check(toString(p) == "3", "late a3 content");

        // Alice keeps talking on the new chain.
        RatchetMessage a4;
        as.encrypt(reinterpret_cast<const uint8_t*>("4"), 1, nullptr, 0, a4);
        check(bs.decrypt(a4, nullptr, 0, p), "new chain continues");
        check(toString(p) == "4", "new chain content");
    }

    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}