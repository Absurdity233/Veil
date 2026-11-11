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

    // ---- Identity -------------------------------------------------------

    bool createIdentity();
    bool restoreIdentity(const uint8_t* dh_priv, const uint8_t* sign_priv);

    // 96 bytes: DH private || signing private. Never leaves the device.
    Bytes exportIdentitySecrets() const;

    // 64 bytes: DH public || signing public. Safe to publish.
    Bytes exportIdentityPublic() const;

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
    bool establishOutbound(const std::string& peer, const uint8_t* bundle, size_t size);
    bool establishInbound(const std::string& peer, const PreKeyHeader& header);
    bool importSession(const std::string& peer, const uint8_t* data, size_t size);
    Bytes exportSession(const std::string& peer) const;
    void dropSession(const std::string& peer);

    // ---- Messaging ------------------------------------------------------

    // Returns the framed ciphertext, or an empty vector on failure.
    Bytes encrypt(const std::string& peer, const uint8_t* plain, size_t size);

    // Returns false on unknown peer, bad framing, or authentication failure.
    bool decrypt(const std::string& peer, const uint8_t* frame, size_t size, Bytes& out);

    // ---- Verification ---------------------------------------------------

    // BLAKE2b-256 over both identity DH public keys in sorted order, rendered
    // as five groups of five decimal digits. Both sides compute the same
    // string; comparing it out of band proves there is no middlebox.
    std::string safetyNumber(const std::string& peer) const;

private:
    Session* findSession(const std::string& peer);
    const Session* findSession(const std::string& peer) const;

    Identity identity_;
    PreKeys prekeys_;
    std::map<std::string, Session> sessions_;

    // The peer's identity key, learned during the handshake. Needed for the
    // safety number, and to keep a peer label bound to one identity.
    std::map<std::string, std::array<uint8_t, kKeySize>> peer_identity_;
};

}  // namespace veil

#endif  // VEIL_ENGINE_H
