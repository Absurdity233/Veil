// Veil - Sender Keys, for group messaging.
//
// A pairwise Double Ratchet does not scale to a group: N members would need N^2
// sessions, and every message would be N-1 frames. Sender Keys is the standard
// answer, and the shape is worth stating because it changes what a message is.
//
// In the pairwise case, the ratchet is shared between two people and both of
// them advance it. In a group, each *member* publishes a chain of their own, and
// the others hold a copy of that chain. A message is then encrypted once with
// the sender's own chain key and broadcast; the recipients advance their copy of
// that sender's chain.
//
//   Alice's chain  -- one key per message -->  everyone decrypts with the copy
//                                              they were given at join time
//
// The consequence to be honest about: a group message is encrypted with a
// symmetric key every member holds, so the set of people who can read it is the
// set of people who were given the chain. Removing a member therefore *must*
// rotate every member's chain, or the removed member keeps reading. That is what
// `Membership` below exists for.
#ifndef VEIL_GROUP_H
#define VEIL_GROUP_H

#include <array>
#include <cstdint>
#include <map>
#include <string>

#include "veil/common.h"
#include "veil/crypto.h"

namespace veil {

// A sender's chain, as distributed to the other members.
//
// `chain_key` is the head of the sender's symmetric ratchet. `iteration` says
// how far it has advanced since the chain was published, so a receiver that
// missed messages can walk forward and cache skipped keys exactly as the
// pairwise ratchet does.
//
// Distribution is per member and encrypted pairwise: the chain travels inside an
// ordinary device session, so a group message needs one pairwise frame per
// member per *epoch*, not per message.
struct SenderKey {
    std::string sender_id;
    uint32_t    epoch = 0;      // bumped on every membership change
    uint32_t    iteration = 0;  // messages sent on this chain so far
    std::array<uint8_t, 32> chain_key{};
    // The chain is authenticated as it travels, so a relay relaying a chain it
    // was handed cannot substitute one of its own.
    uint8_t     signature[kSigSize]{};

    static constexpr size_t kSize = 32 * 2 + 32 + kSigSize;
};

// One encrypted group message.
struct GroupMessage {
    std::string sender_id;
    uint32_t    epoch = 0;
    uint32_t    iteration = 0;
    Bytes       ciphertext;  // includes the 16-byte MAC
};

// The group's shared view of who is in it, and at which epoch.
//
// Membership is a list, and it is signed by the group's *founder*: someone has to
// be the authority on who was added, and in a pairwise-only design that has to
// be a person rather than the relay. A group with no such authority has no way
// to tell a legitimate re-key from a hostile one.
struct GroupMembership {
    std::string group_id;
    uint32_t    epoch = 0;
    std::string founder;                    // user id
    std::vector<std::string> members;       // user ids, sorted
    uint8_t     signature[kSigSize]{};      // founder's Ed25519 over the above

    // The bytes the founder signs, so two implementations cannot disagree.
    Bytes signedPayload() const;
};

// How many skipped group keys are cached per sender before the oldest go.
// The same reasoning as the pairwise ratchet: a member could otherwise pin
// arbitrary memory by claiming a huge gap.
constexpr size_t kMaxSkippedGroupKeys = 500;

// A sender's chain plus everything needed to decrypt their messages out of order.
struct GroupChain {
    uint32_t epoch = 0;
    uint32_t iteration = 0;
    std::array<uint8_t, 32> chain_key{};
    std::array<uint8_t, 32> root{};   // reserved; not used yet

    // Message keys for iterations we have not seen, bounded.
    std::map<uint32_t, std::array<uint8_t, 32>> skipped;

    // Advances the chain to `target` and returns the key for that iteration.
    bool keyFor(uint32_t target, std::array<uint8_t, 32>& out);
};

// The symmetric step, shared by send and receive so they cannot drift.
void groupChainStep(const std::array<uint8_t, 32>& chain_key,
                    std::array<uint8_t, 32>& next_chain,
                    std::array<uint8_t, 32>& message_key);

// Derives the AEAD key and nonce for one group message.
void groupMessageMaterial(const std::array<uint8_t, 32>& message_key,
                          uint8_t enc_key[32], uint8_t nonce[kNonceSize]);

// The associated data a group message authenticates: sender, epoch, iteration.
// Without it a member could replay a message under a different iteration, or a
// relay could re-attribute one to a different sender.
Bytes groupAssociatedData(const std::string& sender_id, uint32_t epoch, uint32_t iteration);

}  // namespace veil

#endif  // VEIL_GROUP_H