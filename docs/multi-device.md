# Multi-device

How one person can talk from a phone, a laptop and a browser without becoming
three different people.

This document is the design. It states the problem, the two candidate models,
the one that was chosen, and what that choice costs.

## The problem, precisely

Today an account *is* an identity: a user id is bound to one `identity_dh` and
one `identity_sign`, and the relay refuses a second identity for the same id.
Everything downstream assumes that:

- a prekey bundle is per user id, so a bundle names exactly one device
- a session is per peer label, so "Bob" is one ratchet
- the safety number is computed over two identities
- an outbox entry is addressed to a user id and delivered to whoever holds it

Three clients therefore work, and three *devices of one person* do not: each
creates its own identity, and they are strangers to each other.

## Two models, and why the simpler one wins

**Model A: one identity, many devices, shared secret.** The identity secret is
copied to each device. Every device can sign as the user, and the safety number
stays a single value.

Rejected. Copying a private key multiplies the places it can leak, and there is
no way to revoke one device without rotating the identity — which changes the
safety number for every peer, which is precisely the event the whole verification
story is built to make visible. A stolen laptop would be indistinguishable from
the phone.

**Model B: one identity, many devices, each with its own key, chained by
signatures.** The first device holds the identity secret. Every additional device
generates its own key pair and gets a *device credential*: a signature by the
account identity over that device's public key.

Chosen. It is what Signal does, and the reasons are the same ones:

- a device's private key never leaves that device, so compromising one does not
  compromise the account
- a device can be removed by publishing a new credential list that omits it,
  without touching the identity
- the safety number keeps meaning "this is the person", not "this is one of their
  devices"

## The rules

### 1. A device credential is an endorsement, not a key

```
DeviceCredential {
    user_id             -- the account this device speaks for
    device_id           -- 32 random bytes, chosen by the device
    device_dh_pub       -- this device's Curve25519 key
    device_sign_pub     -- this device's Ed25519 key
    issued_at           -- seconds since the epoch, for display only
}
```

The credential is valid when `account_identity_sign` verifies an Ed25519
signature over the canonical encoding of the fields above, with the domain
prefix `"Veil/device-credential/v1"`.

The device's own two halves are bound to each other by the same mechanism the
account identity uses: `device_sign` signs `device_dh_pub`, and every bundle this
device publishes carries that signature. Without it, a relay could pair this
device's DH key with its own signing key — exactly the attack the account-level
binding closes, one level down.

### 2. The credential list is the account

An account is the *set* of unrevoked credentials, and the identity is what signs
them. The relay stores the list and hands it out; it cannot forge an entry,
because it does not hold the account signing key.

Revocation is omission: a new list that does not contain a device's credential,
signed by the identity, is the account saying "that device is no longer me". A
device that is merely offline is still in the list.

Because the identity signs the list, and the identity cannot be rotated without
changing the safety number, a removed device **cannot** re-add itself: it has no
account signing key. It can still impersonate itself to peers that have not
refreshed the list, which is why revocation has to reach peers, not just the
relay — see "What revocation does not do" below.

### 3. Sessions are per device, not per user

Addressing becomes `(user_id, device_id)`. Each pair gets its own X3DH handshake
and its own Double Ratchet.

This is the part that looks wasteful and is not. Two devices of one person do
not share a ratchet, because a ratchet is a two-party object: the whole point of
the double ratchet is that the key advances per message *between two
participants*. Making three devices share one would mean sharing chain keys,
which is Model A with extra steps.

### 4. Sending fans out

`encrypt(peer, plaintext)` becomes `encryptToAccount(peer, plaintext)`, which
produces **one frame per device** of the recipient, each encrypted to that
device's ratchet.

The relay sees N frames where it used to see one. That is a real metadata cost
and it is stated in the threat model rather than hidden: the relay already knows
who talks to whom and when, and now it knows how many devices the recipient has.

The client caches the recipient's device list, refreshed when a bundle is fetched
and when a message arrives from a device it has not seen.

### 5. The safety number stays per identity

A peer's safety number is over the *account* identity, not over any device. That
is what makes it usable: a user compares one string, and adding a device to their
own account does not change it.

What a device credential buys, then, is not a per-device safety number but a
chain: "this device speaks for the identity I verified". A verification UI that
shows the account safety number plus the device list is the honest presentation,
and that is what the clients are meant to show once this lands.

### 6. First-device bootstrap is unchanged

The first device of an account is the account: it generates the identity and
signs its own credential. No existing single-device flow changes, and a
single-device account is not a special case — it is a list of one.

### 7. Linking a second device

```
new device                          existing device
    |  generate device key pair              |
    |  show a linking code (QR / text)       |
    |--------------------------------------->|
    |                                        |  user confirms out of band
    |<---------------------------------------|
    |  DeviceCredential (signed by identity) |
```

The linking code carries the new device's public keys and a single-use nonce.
The existing device shows what is being linked — key fingerprints, not just
"allow?" — and the user confirms. The credential comes back signed.

This is deliberately *not* a server-mediated flow: the relay never sees the
linking code, and cannot add a device to an account.

## What this costs

| Cost | Where it lands |
|---|---|
| N ciphertexts per message instead of 1 | bandwidth, relay storage |
| Device list visible to the relay | metadata, already-partial |
| A stale device list means dropped messages | client must refresh before sending |
| Revocation is not instant | peers that are offline keep the old list |
| One more list to persist | every client's vault |

### What revocation does not do

Removing a device from the list stops the relay handing out its bundle and stops
new sessions forming with it. It does **not** decrypt anything that device
already received, and it does not stop the device sending to peers who have not
refreshed. Those peers see a credential that is no longer in the account's
current list, which is a thing a client must check and surface — "this device is
no longer part of Bob's account" is a warning, not a silent accept.

That check is the one piece of this design that cannot be skipped, and it is why
the relay must serve the *whole* list with a version, not just the bundle the
caller asked for.

## What is not in scope

- **Group messaging.** Sender Keys are a separate problem, and this design does
  not touch it.
- **Device migration of history.** A newly linked device starts with no
  transcript; carrying history across is a local encrypted-transfer problem with
  its own design.
- **Account recovery.** The identity still cannot be recovered. Adding devices
  makes losing it more expensive, not less.

## Wire changes

Aggregate and additive; nothing existing changes shape.

| Type | Direction | Purpose |
|---|---|---|
| `PUBLISH_DEVICES` | client → relay | the signed credential list for an account |
| `GET_DEVICES` | client → relay | fetch an account's current list and its version |
| `DEVICES` | relay → client | `[4] version \| [4] count \| per entry: [str] device id \| [blob] credential` |

`PUBLISH_DEVICES` replaces the whole set rather than patching it, which is what
makes revocation expressible as omission: a device missing from the new list is
gone, and there is no separate "remove" call to forget.

A connection may only publish the list of the account it authenticated as. That
check is not defensive paranoia — publishing somebody else's list is the entire
attack.

Still to come, and it needs the clients rather than more protocol:

| Change | Why it waits |
|---|---|
| `GET_BUNDLE` gains a device id | a client can only ask for the bundle of a device it has just discovered, so this lands with the linking UI |

The recipient field in `SEND` becomes `(user id, device id)`. A frame for device
D of user U is stored against U's outbox but tagged with D, and the relay only
hands it to a connection that authenticated as D.

That last point matters: authenticating as U is not sufficient, or the wrong
device would receive frames it cannot decrypt and would report an authentication
failure on a message meant for its sibling.

## Migration

A relay with an old database has one device per account: the identity itself.
The migration synthesises a credential for it — the account identity's own DH and
signing keys, signed by itself — so an upgraded relay keeps serving existing
accounts, and existing clients keep working without knowing devices exist.

That self-signed credential is exactly what the first-device bootstrap produces,
which is the reason it is expressible at all.

## Status

The protocol layer is implemented and tested; the clients are not wired to it
yet.

| Stage | Where | State |
|---|---|---|
| Credentials: signing, verification, wire form, fingerprints | `core-native/.../keys.{h,cpp}` | done |
| Account registry, per-device sessions, fan-out | `core-native/.../engine.{h,cpp}` | done |
| C ABI for both of the above | `core-native/.../veil_c.{h,cpp}` | done |
| Relay: device table, `PUBLISH_DEVICES` / `GET_DEVICES` | `server/store.go`, `server/hub.go` | done |
| Relay: `HELLO` and `SEND` carry a device id, outbox per device | `server/hub.go`, `server/store.go` | done |
| Clients: device id claimed, persisted, announced; fan-out send | `app/`, `desktop/`, `web/` | done |
| Linking: request, approval, credential adoption | `core-native/.../engine.{h,cpp}`, `veil_c` | done |
| Client UI: linking flow, device list refresh | `app/`, `desktop/`, `web/` | linking done for Android; refresh not started |

The relay is device-aware: a connection announces its device in `HELLO`, a
`SEND` may name one, and a frame addressed to a device reaches only that device's
connections. An empty device id still addresses the whole account, which is why a
single-device account keeps working unchanged.

All three clients now claim a device on connect, persist it so a restart does not
mint a second one, and send through the fan-out path: one plaintext becomes one
frame per device of the peer, with a device that has no session skipped rather
than failing the whole send.

What remains is UI — no client draws a linking flow or shows a device list.

What that means in practice: the engine can hold a multi-device account and
behave correctly, and a relay can store and serve device lists, but no client
surfaces any of it. A single-device account is unaffected — it is a list of one,
and every existing code path keeps working, which is why the tree stays green
throughout.

### What the tests pin

The interesting failures are all local, which is why stages 1 and 2 were
testable without a relay:

- a device cannot endorse itself — it has no account signing key
- a spliced DH key, a spliced signing key, a re-labelled account, a changed
  device id and a changed issue time are all refused, separately
- one bad entry refuses the whole list, because a partially trusted list is
  worse than a stale one
- a lower version does not replace a higher one, so a relay cannot roll a
  revocation back
- a fan-out frame is encrypted to one device and is not readable by its sibling
- a device with no session is skipped, so one stale laptop does not make an
  account unreachable
- the account safety number does not move when devices are added

### Linking, as implemented

```
new device                          existing device (holds the account key)
    |  generateLinkingRequest()                |
    |  ---------------- request ------------->  |  read it: account + fingerprint
    |                                           |  a person compares the fingerprints
    |  <--------------- credential ------------  |  approveLinking()
    |  adoptDeviceCredential()                  |
```

The request carries public halves only, plus the requesting device's own binding
of its DH key. That binding travels in the request because only that device can
produce it, and the credential is not valid without it — an earlier version of
this tried to derive it on the approving side and quietly produced credentials
that could never verify.

The fingerprint is over the keys *and* the request nonce, so two requests from the
same device read differently: approving "this one" cannot be answered by approving
the previous one. It is shown large and monospaced in the client, because it is the
one thing the user has to actually compare.

Linking is not server-mediated. The relay cannot issue a credential (it has no
account key), and the credential travels over a channel that already authenticates
the account.

### What is still missing

- **History transfer to a new device.** Out of scope above, and still out of
  scope.

## Device list freshness

A device list is a cache of something the peer controls, and it can be wrong in
the one direction that matters: the peer linked a device and this client has not
heard. The consequence is a frame encrypted to a device that does not exist in the
cached list, and the new device simply never receives it.

The policy has **three triggers and no timer**. Polling costs the peer a bundle
fetch each time and still leaves a window; these catch the two moments the list is
actually likely to have moved:

| reason | when |
|---|---|
| `SendFailed` | a fan-out could not address one of the devices in the list |
| `Stale` | older than the caller's threshold (the web client uses 10 minutes) |
| `Unknown` | no list held at all — the peer may be single-device, so this is not an error |

`SendFailed` outranks `Stale` in the answer because it is evidence where staleness
is a guess: the failure *is* the signal that a device was added.

Two details that are easy to get wrong:

- **The engine never reads a clock.** The caller supplies one via `setClock`. An
  engine that never receives one reports only send failures, which is a working
  policy rather than a wrong one — and it keeps the engine testable.
- **A clock that moves backwards reports nothing.** Wall clocks get adjusted by
  NTP, and reporting a list fetched a second ago as ancient would cause a
  re-fetch storm.

A successful `adoptDeviceList` clears both the staleness timestamp and the
send-failure flag in one place, so there is no way to adopt a list and forget to
record when.

## Client UI

| | groups | linking | QR |
|---|---|---|---|
| Android | yes | yes (dialog, both halves) | no |
| desktop | yes | yes (dialog, both halves) | no |
| web | yes | yes (dialog, both halves) | yes |

The QR carries the request so the other device scans rather than being read a
200-character base64 string aloud. The text is still shown and still accepted: a
camera can fail, and a flow that only works when it does not is a flow that does
not work.

The web QR encoder is a thin wrapper over `qrcode` rather than hand-written. That
was learned the hard way — a hand-rolled encoder produced codes whose finder
patterns, module counts and format bits were provably correct and which no decoder
could read, because QR is a pipeline of bit packing, Reed-Solomon, interleaving,
placement, masking and BCH where a mistake anywhere yields a well-formed square
that scans as noise. The library is generation-only, and a test decodes every size
it produces with an independent decoder.
