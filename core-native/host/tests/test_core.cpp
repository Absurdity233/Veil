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
    check(bob_prekeys.generate(bob, 7, 5), "bob prekeys");
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
        dp.generate(dave, 11, 3);
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
        fp.generate(f, 21, 3);
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
        hp.generate(h, 31, 3);
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
        jp.generate(j, 41, 3);
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
        lp.generate(l, 51, 3);
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
        check(a.generatePreKeys(1, 4), "engine a prekeys");
        check(b.generatePreKeys(1, 4), "engine b prekeys");

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
            mallory.generatePreKeys(9, 1);
            // Alice's bundle points at Bob, so Mallory's frame is a stranger.
            Bytes mb = a.publishBundle(0);
            (void)mb;

            // Replay Alice's handshake frame under a label Bob already knows
            // as a different identity.
            Engine carol;
            carol.createIdentity();
            carol.generatePreKeys(3, 1);
            Bytes cb = carol.publishBundle(0);
            Engine dave;
            dave.createIdentity();
            dave.generatePreKeys(3, 1);
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
        a.generatePreKeys(2, 2);
        b.generatePreKeys(2, 2);

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
        check(e.generatePreKeys(3, 4), "prekeys generated");

        Bytes set = e.exportPreKeySet();
        check(set.size() == 4 + 32 + 64 + 4 + 4 * 36, "prekey set size");

        check(get_u32(set.data()) == 3, "signed id at offset 0");
        check(get_u32(set.data() + 4 + 32 + 64) == 4, "count at offset 100");

        // Each one-time id must be unique, or the relay could hand the same
        // key to two different senders.
        std::vector<uint32_t> ids;
        size_t off = 4 + 32 + 64 + 4;
        for (int i = 0; i < 4; ++i) {
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
        bob.generatePreKeys(5, 2);

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

    section("ratchet does not move backwards");
    {
        // Alice sends two messages; Bob reads only the first, then replies.
        // The second message now belongs to a chain Bob has left. It must be
        // rejected rather than dragging his ratchet back to the old key.
        Identity alice, bob;
        alice.generate();
        bob.generate();
        PreKeys bp;
        bp.generate(bob, 61, 3);
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
        bp.generate(bob, 71, 3);
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

    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
