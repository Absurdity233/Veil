# Notifications

All three clients notify on an incoming message. They share one rule, and the rule
is the whole design.

## The rule

**A notification never contains message content.**

Not "is truncated", not "is configurable" — never. The notification is constructed
from the sender's id and nothing else:

```
alice                          alice in #team
New message                    New message in a group
```

## Why

A notification is not rendered by this application. It is rendered by the
operating system, and it goes places the page does not control:

- the lock screen of a phone that is lying on a table;
- the notification centre, which keeps a history;
- a screenshot the user takes for an unrelated reason;
- whatever the OS, the OEM skin, or a screen-recording app decides to log.

A body reading `alice: the meeting is at 4` would undo the encryption of the
message it described, in a place the user cannot audit and did not choose. End-to-end
encryption that leaks its plaintext to the lock screen is not end-to-end encryption
— it is encryption with a documented exception nobody documented.

The information a notification does carry — that *someone* sent *something* at
*this time* — is already visible to the relay, which routes the frame. Withholding
it from the user would protect nothing and make the feature useless.

## How each client enforces it

The enforcement is structural rather than a filter, because a filter is a rule that
can be applied to the wrong string later.

| client | the API cannot carry text because |
|---|---|
| web (`notify.ts`) | `notify()` takes `{from, kind, groupId}`, builds the body from a constant |
| Android (`MessageNotifier`) | `notifyMessage(senderId, isGroup, groupId)` — three parameters, none of them content |
| desktop (`TrayNotifier`) | same three parameters; a reflection test fails if a fourth is added |

The desktop test is worth its oddity: it asserts the parameter *count*, so adding a
`text` argument is a red build with a message explaining what it would break,
rather than something a reviewer has to notice.

## Platform specifics

**Web.** Permission is three-state and cannot be re-requested after a denial, so
the button is hidden once the answer is known — its absence is the honest state,
not a bug. A focused tab does not notify: the message is already in the transcript,
and notifying about something the user is looking at is what makes people turn
notifications off. Bursts are coalesced to one per two seconds, because ten
notifications would stack, get dismissed as a stack, and take the one that mattered
with them. Only while the page is alive — a service worker would be a different
project.

**Android.** `POST_NOTIFICATIONS` from API 33, asked on a gesture rather than at
launch. A single notification id, so a second message replaces the first instead of
building a column. `VISIBILITY_PRIVATE`, so the system redacts even the sender when
the device is locked — a second layer over a title that is already just a name.

**Desktop.** AWT's tray icon is the only channel a plain JVM has. It is installed at
startup rather than on first message, because registering the icon is what makes
the process visible and doing it lazily loses the first notification. The icon is
drawn rather than loaded: a missing image resource fails at runtime on the machine
that matters.

## What is not implemented

- **Push.** Every client notifies only while it is running. Real push needs
  FCM/APNs, which means a server that learns when each device is online — a
  metadata cost that belongs in the threat model, not in a footnote.
- **Per-conversation muting.** One switch, on or off.
- **Notification actions.** Reply from the notification would need the plaintext
  in the notification, which is the thing this document exists to prevent.
