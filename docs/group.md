# Group messaging

How more than two people talk, why it is not just "the pairwise protocol with
more peers", and what the group gives up to be cheap.

## Why a pairwise ratchet does not scale

A Double Ratchet is a two-party object. Its whole design is that the key advances
per message *between two participants*, with each side ratcheting independently.

Put N people in a room and the pairwise approach needs N×(N-1)/2 sessions and
N-1 ciphertexts per message. For a 10-person group that is 45 sessions and 9
frames per message, and every new member adds 10 more sessions. It also has no
answer to "who is in this group" — pairwise sessions do not know about each
other.

## Sender Keys

Each member maintains a *sending chain* of their own and publishes its head to
the others. A message is encrypted once with the sender's chain and broadcast;
each recipient advances their local copy of that sender's chain.

```
        Alice's chain ──k0──k1──k2──k3──▶ broadcast
                                          │
              ┌───────────────────────────┼───────────────────────────┐
              ▼                           ▼                           ▼
        Bob's copy of                 Carol's copy of             Dave's copy of
        Alice's chain                 Alice's chain               Alice's chain
```

One message, one frame, regardless of group size. Distribution of a chain costs
one pairwise frame per member — but only once per *epoch*, not per message.

The chain step is the same HMAC construction the pairwise ratchet uses, with its
own domain constants so a group key can never be mistaken for a pairwise one.

## What this gives up

Everyone in the group holds the key to every message, so:

- **Any member can forge a message from any other member.** A group message is a
  symmetric key; whoever holds it can produce a valid MAC. This is inherent to
  Sender Keys and is why group identity is weaker than pairwise identity.
- **Removing a member requires re-keying everyone.** A removed member keeps the
  old chain key. There is no way to stop them reading messages encrypted under
  it, so the only remedy is to stop using it.

That second point is the one that shapes the API.

## Epochs

A group has an epoch, bumped on every membership change. Every chain is scoped to
one epoch.

- Adding or removing a member bumps the epoch and **discards every chain**,
  including the local sending chain.
- A message from a different epoch is refused, and reported as a stale epoch
  rather than as tampering — it is the expected outcome of a rotation, not an
  attack.
- A chain for an epoch at or below one already held from that sender is refused,
  so a rotated-out member cannot re-publish their old chain and have it accepted.

The consequence is deliberate: after a membership change the group is unusable
until every member republishes a chain. That is not a bug to work around; it is
the mechanism.

## Who decides membership

The group has a **founder**, and the founder signs the member list with their
account identity. Anyone can verify the list came from the founder.

Without an authority, a group has no way to tell a legitimate re-key from a
hostile one: a relay that could add itself to the member list could read
everything. Anchoring the list to one identity is the smallest thing that makes
the group's membership checkable.

A record claiming a different founder for a group already held is refused
outright — that is a different group wearing the same name.

## Anti-replay and binding

Every group message authenticates `(sender id, epoch, iteration)` as associated
data. That binds the ciphertext to the position it claims, so:

- a relay cannot re-attribute a message to a different sender
- a message cannot be replayed under a different iteration
- a ciphertext from one epoch cannot be accepted in another

All three are tested.

## Out-of-order delivery

The relay delivers at-least-once and not necessarily in order, so a receiver will
see gaps. Each chain caches skipped message keys, bounded at 500 per sender — the
same reasoning as the pairwise ratchet: without a bound, a member could pin
arbitrary memory by claiming a huge gap.

A replayed message is refused because its key was consumed when it was first
accepted.

## What is not implemented

- **Group membership consensus.** The founder decides; there is no voting and no
  way for members to disagree. A group is a dictatorship by design, because
  distributed consensus over who is in a chat is a much larger problem than the
  chat.
- **Forward secrecy across epochs for received chains.** Rotating drops the old
  chains, which is the right direction, but a member who cached a removed
  sender's keys before the rotation could still decrypt what they had. Deleting
  the chains is what stops that; there is no cryptographic erasure beyond it.
- **Group history for a new member.** A newly added member sees nothing from
  before they joined, because they were never given a chain for it.
- **Distribution over the wire.** A chain and a member list travel inside a
  pairwise session, and the clients expose them as export/adopt pairs rather than
  sending them automatically. A caller has to hand them over; there is no
  "invite" message yet.

## Persistence

Group state is persisted, and it has to be: the blob carries every incoming chain
key and the outgoing chain. Without it a reload drops every group and a member
can no longer read anything sent to a group they are still in — which looks
exactly like having been removed.

Two properties the format has:

- **Skipped keys are included.** Dropping them would make every message
  currently in flight permanently unreadable after a restart.
- **Import validates everything before replacing anything.** A malformed blob
  leaves the live groups untouched rather than half-loaded, which is tested by
  truncating a valid blob at every possible length.

The blob is secret material and belongs in the same encrypted store as ratchet
state — the Android Keystore, the desktop vault file, or the web client's
non-extractable key.
