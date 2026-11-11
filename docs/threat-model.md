# Threat model

What Veil protects against, what it does not, and what it costs.

## The adversary the design is aimed at

**A hostile relay.** The server is the one party that must see every message in
order to route it, so it is the party whose honesty is assumed least. Everything
in the protocol is arranged so that a relay which logs, rewrites, replays and
forges cannot recover a single character of message text, and cannot sit between
two people without the safety number changing.

**Passive network observers.** TLS hides the conversation from anything on the
path.

**Later compromise.** Message keys are deleted after use and each message
advances the chain, so a stolen device does not decrypt history. A stolen
*identity* does not either: it can impersonate going forward, which is what
identity pinning and the safety number exist to catch, but it cannot read what
was already said.

## What it deliberately does not hide

| Leaks | Why it cannot be avoided here |
|---|---|
| **Who talks to whom** | the relay must route, so it must see the recipient |
| **When, and how many bytes** | timing and size are routing metadata |
| **Long-term identity keys** | they are published by design; that is what a prekey bundle is |
| **That two ids exist** | registration is public to the relay |

Sealed sender, cover traffic and mixnets are the techniques that address these.
None of them are implemented, and claiming otherwise would be worse than saying
so.

## Attacks and how they land

### A relay substitutes a prekey bundle

The sender verifies the signed prekey against the peer's identity signing key,
and the signed message covers `identity_dh_pub` as well as the prekey. So a
relay cannot pair a victim's DH key with its own signing key and then vouch for a
prekey of its choosing — the signature would not verify.

If the relay instead invents a whole identity, the safety number changes, and
the pin reports `IDENTITY_CHANGED` rather than silently re-keying.

### A relay swaps the peer's identity mid-conversation

Refused. Once a label has been bound to an identity, every later bundle for that
label must present the same identity. The pin survives a restart and is *not*
cleared by dropping the session — otherwise a re-handshake could swap the peer
afterward.

### A relay replays an old frame

The ratchet refuses a counter it has already consumed, and a frame from a chain
it has ratcheted away from cannot drag the session backwards. Both are reported
as `DUPLICATE`: routine, acknowledged silently, never shown as an attack.

### A relay tampers with a frame in flight

The MAC covers the ciphertext and the ratchet header. A modified byte fails
authentication on a counter that has not been seen, which is `AUTH_FAILED` and
is surfaced.

### Someone claims an unused user id

Registration is a challenge-response. The id is bound only after the client
proves possession of the identity signing key by signing a relay-chosen nonce.

### Someone replays a handshake's first frame

The one-time prekey it names is recorded as spent the moment the handshake
succeeds, so the same header is refused afterwards. Without that local record the
relay popping its own copy would not be enough: the private half would still be
usable here.

### Someone pins memory on the receiving device

Skipped message keys are bounded twice: 1000 per chain, 2000 across the session.
The per-chain cap alone bounds nothing, because a peer opens a fresh chain every
time it publishes a ratchet key.

### Someone fills the relay's disk

The outbox expires, is capped per recipient, and sends are paced per connection.
A relay that accepts ciphertext from anyone for anyone is otherwise free storage.

### A browser page on another origin opens a socket

Refused unless its origin is listed in `VEIL_ALLOWED_ORIGINS`. Native clients
send no `Origin` header and are accepted; a browser cannot forge its absence.

## What a compromised device gets

A stolen, unlocked device with the app installed can read the transcript, because
the plaintext is on it. How much the *keys* are worth depends on the platform,
and the three clients differ enough that the difference has to be stated:

| | Key store | A stolen copy of the data is | Script on a live session |
|---|---|---|---|
| Android | hardware-backed Keystore | useless | — |
| Desktop | `0600` file in `~/.veil` | **the identity** | — |
| Web | non-extractable AES-GCM `CryptoKey` in IndexedDB | useless | **the identity** |

The desktop is the weakest of the three: a file with owner-only permissions is
all a JVM can offer without a platform-specific keystore, and anyone who can read
that file as you can impersonate you. The web client is stronger against a stolen
profile and weaker against script injection on the page, which is the opposite
trade-off — a non-extractable key cannot be exfiltrated by a script that only
gets its handle, but a script running in the page can just call `decrypt`.

Neither is a hardware root of trust. Only the Android client has one.

`FLAG_SECURE` keeps Android plaintext out of screenshots, screen recordings and
the recents thumbnail. It does not stop a camera pointed at the screen.

## What is not implemented

Named plainly, because a threat model that omits its gaps is a sales document:

- **No group messaging.** One-to-one only.
- **No push notifications.** A message waits in the outbox until the client
  reconnects.
- **No multi-device.** The three clients are three separate identities, not three
  devices of one account. The identity is bound to one device's key store, and
  losing it loses the account; there is no linking flow and no recovery.
- **No sealed sender.** The relay knows the sender.
- **No protection against a malicious client.** A modified app can leak whatever
  it can read. Nothing here prevents that, and nothing here claims to.
- **No protection against a malicious page on the web client's origin.** The
  content policy blocks third-party and inline script, which is a real barrier,
  but a same-origin compromise is game over for any browser application.

## Reporting

If you find something in the above that is wrong — an attack that lands when
this document says it does not — that is a security bug, and the useful report
is a failing test in `core-native/host/tests/` or `server/relay_test.go`.
