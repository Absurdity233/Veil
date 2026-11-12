# Accounts

A password, so one identity can be restored on another device.

This is the one feature that deliberately adds a trust assumption, so the whole
point of this document is to state exactly what it costs and what it does not do.

## What it is not

It is **not** a login. The relay does not authenticate a password, because it
never receives one. There is no session token, no "signed in as", and nothing a
server could check.

The relay stores a blob and hands it back. That is the entire interaction.

## The shape

```
password ──Argon2id(salt)──▶ key             (on the device, once per sign-in)
identity + prekeys + groups + history
                    │
                    └──AES-256-GCM(key)──▶ ciphertext
                                            │
      uploaded: (salt, kdf params, ciphertext)  ← all the relay ever sees
```

Consequences, each of which follows directly:

- **The relay cannot verify a password.** It has no hash to compare against. A
  wrong password simply fails to authenticate the ciphertext.
- **The relay cannot open a vault.** It holds a salt, four numbers, and a sealed
  blob.
- **A stolen database is an offline attack on Argon2id**, not a password list.
- **Password strength is the entire defence.** Argon2id makes each guess cost
  64 MiB and three passes; it cannot make a short password long. This is why the
  length is enforced at 12 characters and a strength hint is shown while typing,
  rather than accepted silently.

## What it costs in metadata

The relay learns, and could log:

| | |
|---|---|
| that a user id exists | before that user ever connects |
| roughly how much data they keep | the blob's size |
| when they last wrote | a timestamp per write |

It does **not** learn the password, the identity, the contacts, the messages, or
who talks to whom beyond what the outbox already shows.

The first item is a real change: a user who creates an account is enumerable
before they say anything. A deployment that cares can rate-limit vault reads —
the relay does, using the same per-connection limiter as the send path — but that
slows enumeration rather than preventing it.

## Why the parameters travel with the blob

The salt, memory, passes and lanes are stored beside the ciphertext rather than
being a server constant. Two reasons:

- any client that knows the password must be able to reproduce the key, so it
  needs the parameters that produced it;
- a future version must be able to raise the cost without making existing vaults
  unreadable. Each vault is opened with the parameters it was sealed with.

The relay bounds them anyway — a client asking for four passes and 8 KiB is
weakening its own store, and the relay is the one place that can refuse without
knowing the password. Specifically it rejects: a salt under 8 bytes, memory below
`8 × lanes`, memory above 256 MiB, zero or more than ten passes, and lanes outside
1–8.

## Failure modes

| | |
|---|---|
| wrong password | the AEAD fails to authenticate; reported as "wrong password, or the stored account is damaged" — the two are indistinguishable and the client can do nothing different |
| no vault | not an error: the user never set a password, and the client falls back to a local identity |
| restore overwrites local state | deliberate. Two identities cannot be merged into one, and pretending otherwise produces a client whose keys do not match its messages |
| forgetting the password | the account cannot be recovered. There is no reset, because a reset would require the server to be able to open the vault |

## Why not just use a password hash on the server

Because it would give up the property the rest of the system is built on. A
server-side hash means:

- the relay can verify a password, so it can brute-force it offline;
- the relay holds something that identifies the user across services;
- a database leak is a password list.

The trade made here is the opposite one: the relay holds an opaque blob, and the
user is responsible for their password. That is a worse user experience and a
better security property, and which of those matters more is a decision a
deployment makes by choosing whether to use the feature at all.

## Scope

Implemented: create, restore, change password, and encrypted history — on the web
client; create, restore and change on desktop and Android too.

Not implemented:

- **recovery** — see above. A reset would require the server to be able to open
  the vault, which would give up the property this exists to keep.
- **a vault that survives two devices at once** — see the conflict note below.

## The two-device conflict

Changing the password re-seals the vault under a new key. Any other device still
signed in with the old password can:

- still **read** the vault, because it has the old key and the vault was written
  with it once;
- **overwrite** it on its next write, silently reverting the change.

Nothing in the protocol prevents this. It is not a bug in the KDF or the vault
format: two clients that each believe they own the account will each write what
they believe. The generation counter makes the overwrite visible after the fact,
and both the web and desktop dialogs say to sign the other device out first.

The real fix is a device list on the vault (write only from a device the account
has endorsed) — the same shape as the multi-device credential list that already
exists for messaging. That is the next step, not a change to this design.
