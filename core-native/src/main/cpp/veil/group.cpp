#include "veil/group.h"

#include <algorithm>
#include <cstring>

namespace veil {
namespace {

constexpr char kGroupChainDomain[] = "Veil/group/chain/v1";
constexpr char kGroupMessageDomain[] = "Veil/group/message/v1";

constexpr uint8_t kGroupChainStep = 0x02;
constexpr uint8_t kGroupMessageStep = 0x01;

}  // namespace

void groupChainStep(const std::array<uint8_t, 32>& chain_key,
                    std::array<uint8_t, 32>& next_chain,
                    std::array<uint8_t, 32>& message_key) {
    // The same HMAC step the pairwise ratchet uses, with its own constants so a
    // group key can never be mistaken for a pairwise one.
    crypto::hmac_sha512_32(next_chain.data(), chain_key.data(),
                           &kGroupChainStep, 1);
    crypto::hmac_sha512_32(message_key.data(), chain_key.data(),
                           &kGroupMessageStep, 1);
}

void groupMessageMaterial(const std::array<uint8_t, 32>& message_key,
                          uint8_t enc_key[32], uint8_t nonce[kNonceSize]) {
    uint8_t out[32 + kNonceSize];
    crypto::hkdf(out, sizeof(out),
                 message_key.data(), message_key.size(),
                 nullptr, 0,
                 reinterpret_cast<const uint8_t*>(kGroupMessageDomain),
                 sizeof(kGroupMessageDomain) - 1);
    std::memcpy(enc_key, out, 32);
    std::memcpy(nonce, out + 32, kNonceSize);
    veil::wipe(out, sizeof(out));
}

Bytes groupAssociatedData(const std::string& sender_id, uint32_t epoch, uint32_t iteration) {
    // Length-prefixed rather than concatenated: a sender id of "bo" at epoch 12
    // and one of "bo\x0c" at epoch 0 must not produce the same associated data.
    Bytes out;
    out.reserve(2 + sender_id.size() + 4 + 4);

    out.push_back(static_cast<uint8_t>((sender_id.size() >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(sender_id.size() & 0xFF));
    out.insert(out.end(), sender_id.begin(), sender_id.end());

    uint8_t num[4];
    put_u32(num, epoch);
    out.insert(out.end(), num, num + 4);
    put_u32(num, iteration);
    out.insert(out.end(), num, num + 4);
    return out;
}

Bytes GroupMembership::signedPayload() const {
    // Sorted, so two members building the same list produce the same bytes and
    // a signature over it is meaningful regardless of who serialised it.
    std::vector<std::string> sorted = members;
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());

    Bytes out;
    const char domain[] = "Veil/group-membership/v1";
    out.insert(out.end(), domain, domain + sizeof(domain) - 1);

    auto putString = [&out](const std::string& s) {
        out.push_back(static_cast<uint8_t>((s.size() >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(s.size() & 0xFF));
        out.insert(out.end(), s.begin(), s.end());
    };

    putString(group_id);
    putString(founder);

    uint8_t num[4];
    put_u32(num, epoch);
    out.insert(out.end(), num, num + 4);

    put_u32(num, static_cast<uint32_t>(sorted.size()));
    out.insert(out.end(), num, num + 4);
    for (const auto& member : sorted) putString(member);

    return out;
}

bool GroupChain::keyFor(uint32_t target, std::array<uint8_t, 32>& out) {
    if (target < iteration) {
        // Already consumed. The key may have been cached when the chain moved
        // past it; if not, it is gone.
        auto it = skipped.find(target);
        if (it == skipped.end()) return false;
        out = it->second;
        veil::wipe(it->second.data(), it->second.size());
        skipped.erase(it);
        return true;
    }

    // The gap has to fit in the cache, or a member could pin arbitrary memory.
    if (target - iteration > kMaxSkippedGroupKeys) return false;

    std::array<uint8_t, 32> message_key{};
    while (iteration < target) {
        std::array<uint8_t, 32> next_chain{};
        groupChainStep(chain_key, next_chain, message_key);

        // Cache the key we are stepping over: the message may arrive later.
        std::array<uint8_t, 32> cached = message_key;
        skipped[iteration] = cached;

        chain_key = next_chain;
        ++iteration;
    }

    // Drop the oldest cached keys once the bound is reached.
    while (skipped.size() > kMaxSkippedGroupKeys) {
        auto oldest = skipped.begin();
        veil::wipe(oldest->second.data(), oldest->second.size());
        skipped.erase(oldest);
    }

    std::array<uint8_t, 32> next_chain{};
    groupChainStep(chain_key, next_chain, message_key);
    chain_key = next_chain;
    ++iteration;

    out = message_key;
    veil::wipe(message_key.data(), message_key.size());
    return true;
}

}  // namespace veil