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
#include "veil/group.h"
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
        // A frame that has already been accepted once. The relay delivers
        // at-least-once - a live push plus a replay of the same entry - and
        // the ratchet refuses the second copy. That is correct behaviour, not
        // an error, and it must not be surfaced as one.
        Duplicate        = 6,
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

    // Rotates the signed prekey and generates a fresh batch of one-time keys.
    //
    // The signed prekey id comes from a counter carried in the persisted
    // prekey state, not from the caller. It used to be a constant, which made
    // a stale bundle indistinguishable from a current one across restarts.
    bool rotatePreKeys();

    // True when fewer than `low_water` one-time prekeys are unspent.
    bool needsPreKeyRefill(size_t low_water) const;

    // The public prekey set as the server should store it:
    //   [4] signed id, [32] signed pub, [64] signature, [4] count,
    //   per one-time key: [4] id, [32] pub
    Bytes exportPreKeySet() const;

    // A bundle for one peer to download. `one_time_index` < 0 omits the
    // one-time prekey, and the index counts unspent keys only.
    Bytes publishBundle(int one_time_index) const;

    // ---- Prekey state persistence ---------------------------------------
    //
    // Carries private keys: signed prekey halves and the one-time secrets.
    // Whoever holds them can read the first message of any session that used
    // them, so this goes into the same encrypted store as ratchet state.
    //
    // Persisting it is what makes the id counter and the consumed flags
    // survive a restart; without it every launch minted a new generation under
    // id 1 and forgot which one-time keys had already been spent.
    Bytes exportPreKeyState() const;
    bool importPreKeyState(const uint8_t* data, size_t size);

    // ---- Sessions -------------------------------------------------------

    bool hasSession(const std::string& peer) const;

    // The real state of a peer label, for a UI that has to show something
    // truthful. "safetyNumber != null" was being used as a proxy for "a
    // session exists", which went stale the moment a session was dropped and
    // was never true for a label that was pinned without a session.
    enum SessionState : int32_t {
        NoPeer      = 0,  // nothing known about this label
        PinnedOnly  = 1,  // identity pinned, no live ratchet
        Ready       = 2,  // session usable, safety number comparable
    };
    SessionState sessionState(const std::string& peer) const;
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

    // As above, but reports *why*. The distinction that matters is
    // Result::Duplicate: the relay delivers at-least-once, so the same frame
    // legitimately arrives twice and the second copy is refused by the
    // ratchet. Treating that as a failure put a scary status line in front of
    // the user every time a live delivery happened to also be replayed.
    Result decryptStatus(const std::string& peer, const uint8_t* frame, size_t size, Bytes& out);

    // ---- Verification ---------------------------------------------------

    // BLAKE2b-256 over both identity public keys in sorted order, rendered
    // as five groups of five decimal digits. Both sides compute the same
    // string; comparing it out of band proves there is no middlebox.
    //
    // Both halves of each identity go in. Hashing only the DH keys would leave
    // the signing key - the one that actually authenticates prekeys - outside
    // what the user verifies.
    std::string safetyNumber(const std::string& peer) const;

    // ---- Multi-device ---------------------------------------------------
    //
    // One account, many devices. A session is per *device*, not per account,
    // because a ratchet is a two-party object: sharing one between three devices
    // would mean sharing chain keys, which is the "copy the identity everywhere"
    // model with extra steps.
    //
    // Sessions therefore live under a composite label, and this section is the
    // account layer on top: which devices belong to a peer, and how to send one
    // message to all of them.
    //
    // See docs/multi-device.md.

    // This device's own credential, as the account signed it. The first device
    // of an account is the account, so it signs its own.
    bool initDevice(const std::string& user_id);

    // 32 bytes, or empty when initDevice() has not run.
    Bytes ownDeviceId() const;

    // The credential this device publishes. Empty when initialised without an
    // account identity to sign it.
    Bytes ownDeviceCredential() const;

    // Adopts a credential that the existing device signed for this one.
    //
    // This is the second half of a linking flow: the new device generates its
    // key pair, the existing device returns a signed credential, and the new
    // device installs it here. The account signature is verified against the
    // account key carried in the credential's list, so a relay cannot hand over
    // an endorsement that was never issued.
    bool adoptDeviceCredential(const uint8_t* data, size_t size,
                               const uint8_t account_dh_pub[kKeySize],
                               const uint8_t account_sign_pub[32]);

    // Records a peer's device list.
    //
    // `version` is monotonic: a list with a version at or below the one already
    // held is ignored, so a relay cannot roll an account back to a state that
    // still contains a device the user removed.
    //
    // `data` is the entries only, without the version:
    //   [4] count | per entry: DeviceCredential::serialize()
    // The version travels beside it rather than inside it because the version is
    // the relay's bookkeeping and the entries are the account's statement; a
    // single signed blob would have to carry both, and the relay is the one that
    // increments it.
    //
    // The signature on every entry is checked here, against `account_sign_pub`.
    // A list in which any entry fails is refused whole: a partially trusted list
    // is worse than a stale one.
    Result adoptDeviceList(const std::string& user_id,
                           uint32_t version,
                           const uint8_t* data, size_t size,
                           const uint8_t account_dh_pub[kKeySize],
                           const uint8_t account_sign_pub[32]);

    // The device ids currently known for a peer, in list order.
    std::vector<std::string> peerDevices(const std::string& user_id) const;

    // The version of the list held for a peer; 0 when none.
    uint32_t peerDeviceVersion(const std::string& user_id) const;

    // Starts a session with every device in a peer's list that does not have one.
    // `bundles` supplies one bundle per device id, in any order.
    struct DeviceBundle {
        std::string device_id;   // hex, as it appears in peerDevices()
        Bytes bundle;            // the fixed-width bundle the engine parses
    };
    // Returns the number of sessions established; out_failed lists the device
    // ids that could not be, so a caller can report "3 of 4 devices reachable"
    // rather than a bare failure.
    size_t establishWithDevices(const std::string& user_id,
                                const std::vector<DeviceBundle>& bundles,
                                std::vector<std::string>& out_failed);

    // A frame destined for one device of a peer.
    struct DeviceFrame {
        std::string device_id;
        Bytes frame;
    };

    // Encrypts one plaintext to every device of a peer that has a session.
    //
    // One message becomes N frames. That is the real cost of per-device
    // sessions, and it is stated in the threat model: the relay now learns how
    // many devices the recipient has, on top of what it already learned.
    std::vector<DeviceFrame> encryptToAccount(const std::string& user_id,
                                              const uint8_t* plain, size_t size);

    // The account-level safety number is unchanged: it is over the account
    // identity, so adding a device to either side does not move it. This returns
    // the same value safetyNumber() would for the account label, which is why
    // the two are not separate functions - a per-device safety number would be
    // a different, and less useful, thing to ask a user to compare.

private:
    // Session keys are "<user id>#<device id hex>". A composite label rather
    // than a struct keeps the existing session registry, persistence and
    // serialisation unchanged: a device session is a session whose label
    // happens to contain a separator.
    static std::string deviceLabel(const std::string& user_id,
                                   const std::string& device_id_hex);

    Session* findSession(const std::string& peer);
    const Session* findSession(const std::string& peer) const;

    // The account-level session label, used when a peer has published no device
    // list. A relay that has not been upgraded keeps working, and so does a peer
    // that has never linked a second device.
    std::string accountLabel(const std::string& user_id) const;

public:
    // ---- Groups ---------------------------------------------------------
    //
    // Sender Keys. Each member publishes a chain of their own and broadcasts one
    // message encrypted with it; the others advance their copy of that sender's
    // chain. A group message therefore costs one frame, not N-1.
    //
    // The cost is stated rather than hidden: everyone in the group holds the key
    // to every message, so removing a member *must* rotate every chain. That is
    // what `epoch` is for, and why membership changes invalidate the group until
    // the rotation has happened.
    //
    // See docs/group.md.

    // Creates a group with this device's user as founder and sole member.
    bool createGroup(const std::string& group_id);

    // Adds or removes a member and bumps the epoch.
    //
    // Returns the new epoch, or 0 on failure. Every live chain is discarded:
    // a member who was removed must not be able to read anything after this
    // point, and the only way to guarantee that is to re-key.
    uint32_t setGroupMembers(const std::string& group_id,
                             const std::vector<std::string>& members);

    // The membership record, signed by the founder, ready to hand to members.
    //
    // A member who receives this can verify that the list came from the person
    // who founded the group, which is what stops a relay from silently adding a
    // device or a stranger.
    Bytes exportMembership(const std::string& group_id) const;

    // Adopts a signed membership record.
    //
    // `founder_sign_pub` is the key the group is anchored to. Once a group has
    // been adopted, a record for the same group must carry the same founder key
    // or it is refused: re-anchoring a group is indistinguishable from a relay
    // handing over a different group under the same name.
    Result adoptMembership(const uint8_t* data, size_t size,
                           const uint8_t founder_sign_pub[32]);

    // The epoch currently held for a group; 0 when unknown.
    uint32_t groupEpoch(const std::string& group_id) const;

    // The members currently held for a group.
    std::vector<std::string> groupMembers(const std::string& group_id) const;

    // Whether this engine is a member of the group.
    bool isGroupMember(const std::string& group_id) const;

    // Publishes this sender's chain for the group's current epoch.
    //
    // The result is meant to travel inside pairwise sessions, one per member. It
    // is authenticated with this device's identity signing key so a relay
    // forwarding it cannot substitute a chain of its own.
    Bytes exportSenderKey(const std::string& group_id, uint32_t epoch) const;

    // Installs a peer's chain, as received over a pairwise session.
    //
    // Refuses a chain for an epoch at or below one already held from that
    // sender: a member who was rotated out must not be able to re-publish their
    // old chain and have it accepted.
    Result adoptSenderKey(const uint8_t* data, size_t size,
                          const std::string& expected_sender,
                          const uint8_t sender_sign_pub[32]);

    // Encrypts one message for the whole group.
    //
    // Requires a live sending chain for the current epoch; a group whose
    // membership just changed has none until the rotation is published, which is
    // the point.
    bool encryptToGroup(const std::string& group_id,
                        const uint8_t* plain, size_t size,
                        GroupMessage& out);

    // Decrypts a message from one member.
    Result decryptFromGroup(const std::string& group_id,
                            const GroupMessage& message,
                            Bytes& out);

    // ---- Group persistence ----------------------------------------------
    //
    // Groups carry secrets: every incoming chain key can decrypt that sender's
    // messages, and the outgoing chain can forge them. This blob goes into the
    // same encrypted store as ratchet state, and is wiped on export.
    //
    // Persisting it is what stops a restart from silently dropping every group.
    // Without it a member restarts and can no longer read anything sent to a
    // group they are still in, which looks exactly like being removed.
    //
    // Layout:
    //   [4] group count
    //   per group:
    //     [4] id len | id
    //     [4] epoch | [4] member count | per member: [4] len | id
    //     [4] founder len | founder
    //     [2] has-founder-key | [32] founder sign pub   (only when set)
    //     [64] membership signature
    //     [2] has-outgoing
    //     [4] out epoch | [4] out iteration | [32] out chain key  (when set)
    //     [4] incoming count
    //     per incoming: [4] sender len | sender | [4] epoch | [4] iteration
    //                   | [32] chain key | [4] skipped count
    //                   | per skipped: [4] index | [32] key
    Bytes exportGroupState() const;
    bool importGroupState(const uint8_t* data, size_t size);

private:
    struct GroupState {
        GroupMembership membership;
        bool has_founder_key = false;
        std::array<uint8_t, 32> founder_sign_pub{};

        // Our own sending chain, absent until we publish one for this epoch.
        GroupChain outgoing;
        bool has_outgoing = false;

        // Everyone else's chains, by sender user id.
        std::map<std::string, GroupChain> incoming;
    };

    // Rotates the sending chain for a new epoch, deriving a fresh chain key.
    bool rotateGroupChain(const std::string& group_id, GroupState& state);

    Identity identity_;
    PreKeys prekeys_;
    std::map<std::string, Session> sessions_;

    // The peer's identity key, learned during the handshake. Needed for the
    // safety number, and to keep a peer label bound to one identity.
    std::map<std::string, std::array<uint8_t, kIdentitySize>> peer_identity_;

    // ---- Multi-device state ----
    std::string user_id_;
    uint8_t     device_id_[kDeviceIdSize]{};
    bool        has_device_ = false;

    // This device's key pair, for its own credential. Separate from the account
    // identity on purpose: compromising a linked device must not hand over the
    // account.
    bool    has_device_keys_ = false;
    uint8_t device_dh_pub_[kKeySize]{};
    uint8_t device_dh_priv_[kKeySize]{};
    uint8_t device_sign_pub_[32]{};
    uint8_t device_sign_priv_[64]{};

    DeviceCredential own_credential_;
    bool             has_own_credential_ = false;

    struct PeerDevices {
        uint32_t version = 0;
        std::vector<DeviceCredential> devices;
    };
    std::map<std::string, PeerDevices> peer_devices_;

    std::map<std::string, GroupState> groups_;
};

}  // namespace veil

#endif  // VEIL_ENGINE_H
