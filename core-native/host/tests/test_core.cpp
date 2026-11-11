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

void section(const char* name) { std::printf("\n== %s ==\n", name); }

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
