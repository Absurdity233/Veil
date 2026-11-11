// Veil - session registry around the ratchet, plus wire framing.
//
// The engine owns the identity, the prekeys and every live session. Callers
// address peers by an opaque string id; the engine never interprets it.
#ifndef VEIL_ENGINE_H
#define VEIL_ENGINE_H

#include <array>
#include <map>
#include <string>

#include "veil/common.h"
#include "veil/keys.h"
#include "veil/ratchet.h"

namespace veil {

// Wire format for one encrypted message:
//
//   [1]   flags        bit 0 = carries a prekey header
//   [104] prekey header   (only when the flag is set)
//   [40]  ratchet header
//   [n]   ciphertext || 16-byte MAC
//
// The prekey header, when present, is authenticated as associated data, so a
// relay cannot strip or rewrite it.
struct WireMessage {
    static constexpr uint8_t kFlagPreKey = 0x01;

    static Bytes encode(const Session& session, const RatchetMessage& msg);

    static bool decode(const uint8_t* data, size_t size,
                       bool& has_prekey, PreKeyHeader& prekey,
                       RatchetMessage& msg);
};

class Engine {
public:
    Engine() = default;
    ~Engine();

    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    // Why a call into the engine was refused. Callers need to tell "the bundle
    // was malformed" from "the peer's identity key changed", because only the
    // second one is a security event the user has to see.
    //
    // Unscoped on purpose: it is compared against and cast to an int at the
    // JNI boundary, and a plain enum keeps both spellings working.
    enum Result : int32_t {
        Ok               = 0,
        BadBundle        = 1,  // framing or length was wrong
        BadSignature     = 2,  // the prekey signature did not verify
        IdentityChanged  = 3,  // peer label is pinned to a different identity
        NoSession        = 4,  // no session for that peer
        AuthFailed       = 5,  // frame did not authenticate
    };

    // ---- Identity -------------------------------------------------------

    bool createIdentity();
    bool restoreIdentity(const uint8_t* dh_priv, const uint8_t* sign_priv);

    // 96 bytes: DH private || signing private. Never leaves the device.
    Bytes exportIdentitySecrets() const;

    // 64 bytes: DH public || signing public. Safe to publish.
    Bytes exportIdentityPublic() const;

    // Ed25519 signature over the DH public key, made with the signing key.
    // Published alongside the identity so a peer can prove the two halves
    // belong together; see Identity::bindingSignature.
    Bytes exportIdentityBinding() const;

    // Verifies that a 64-byte identity blob really carries two halves by the
    // same holder.
    static bool verifyIdentityBinding(const uint8_t identity[kIdentitySize],
                                      const uint8_t binding[kBindingSize]);

    // Signs an arbitrary challenge with the identity signing key. Used to
    // prove possession of the identity to the relay: registering a user id is
    // otherwise first-come-first-served, so anybody could claim somebody
    // else's id and publish prekeys of their own under it.
    Bytes signChallenge(const uint8_t* data, size_t size) const;

    // ---- Prekeys --------------------------------------------------------

    bool generatePreKeys(uint32_t signed_id, uint32_t one_time_count);

    // The public prekey set as the server should store it:
    //   [4] signed id, [32] signed pub, [64] signature, [4] count,
    //   per one-time key: [4] id, [32] pub
    Bytes exportPreKeySet() const;

    // A bundle for one peer to download. `one_time_index` < 0 omits the
    // one-time prekey.
    Bytes publishBundle(int one_time_index) const;

    // ---- Sessions -------------------------------------------------------

    bool hasSession(const std::string& peer) const;
    // Same as establishOutbound() but reports why it failed, so the caller can
    // tell a bad signature from a changed identity.
    Result establishOutboundStatus(const std::string& peer,
                                   const uint8_t* bundle, size_t size);
    bool establishOutbound(const std::string& peer, const uint8_t* bundle, size_t size);
    Result establishInbound(const std::string& peer, const PreKeyHeader& header);
    bool importSession(const std::string& peer, const uint8_t* data, size_t size);
    Bytes exportSession(const std::string& peer) const;
    void dropSession(const std::string& peer);

    // The peer's pinned identity (DH || signing), or empty when unmapped.
    Bytes peerIdentity(const std::string& peer) const;

    // ---- Pinned identity registry ---------------------------------------
    //
    // The pin lives beside the session but outlives it: a session can be
    // dropped and rebuilt, while "this label belongs to this identity" must
    // survive a restart or the whole TOFU guarantee is gone. The app stores
    // this blob next to the session blob and restores both at launch.
    //
    // Layout: [4] count, then per entry [4] id length | id | [64] identity.
    Bytes exportPeerRegistry() const;
    bool importPeerRegistry(const uint8_t* data, size_t size);

    // ---- Messaging ------------------------------------------------------

    // Returns the framed ciphertext, or an empty vector on failure.
    Bytes encrypt(const std::string& peer, const uint8_t* plain, size_t size);

    // Returns false on unknown peer, bad framing, or authentication failure.
    bool decrypt(const std::string& peer, const uint8_t* frame, size_t size, Bytes& out);

    // ---- Verification ---------------------------------------------------

    // BLAKE2b-256 over both identity public keys in sorted order, rendered
    // as five groups of five decimal digits. Both sides compute the same
    // string; comparing it out of band proves there is no middlebox.
    //
    // Both halves of each identity go in. Hashing only the DH keys would leave
    // the signing key - the one that actually authenticates prekeys - outside
    // what the user verifies.
    std::string safetyNumber(const std::string& peer) const;

private:
    Session* findSession(const std::string& peer);
    const Session* findSession(const std::string& peer) const;

    Identity identity_;
    PreKeys prekeys_;
    std::map<std::string, Session> sessions_;

    // The peer's identity key, learned during the handshake. Needed for the
    // safety number, and to keep a peer label bound to one identity.
    std::map<std::string, std::array<uint8_t, kIdentitySize>> peer_identity_;
};

}  // namespace veil

#endif  // VEIL_ENGINE_H
