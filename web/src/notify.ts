/**
 * Desktop notifications.
 *
 * The rule this module exists to enforce: **a notification never contains
 * message content.**
 *
 * That is not squeamishness. A notification is rendered by the operating system,
 * outside this page's control: it lands on a lock screen, in a notification
 * history, in a screenshot, in whatever the OS decided to log. A body that said
 * "alice: the meeting is at 4" would undo the encryption of every message it
 * described, and the user would have no way to know it had happened.
 *
 * So the text is constructed from the sender's id and nothing else. "alice sent a
 * message" tells an attacker with the lock screen exactly as much as the message
 * count already does, and tells the user the one thing they need: something
 * arrived, from whom, where to look.
 *
 * Three browsers behave differently enough to be worth naming:
 *
 *   - permission is a three-state thing (default / granted / denied), and once
 *     denied it cannot be asked again from script - so the UI asks once, on a
 *     gesture, and does not nag;
 *   - Firefox and Safari require the notification to come from a service worker
 *     when the page is not focused, which this module does not do: it notifies
 *     only while the page is alive, which is honest about what a tab can promise;
 *   - `requireInteraction` is honoured inconsistently, so the notification is
 *     allowed to auto-dismiss rather than pretending otherwise.
 */

/** The narrow slice of the Notification API this uses. */
interface NotificationApi {
  permission: "default" | "granted" | "denied";
  requestPermission(): Promise<"default" | "granted" | "denied">;
  new (title: string, options?: NotificationOptions): {
    onclick: (() => void) | null;
    close(): void;
  };
}

/** Whether this browser can notify at all. */
export function canNotify(): boolean {
  return typeof globalThis !== "undefined" &&
    "Notification" in globalThis &&
    typeof document !== "undefined" &&
    document.visibilityState !== undefined;
}

/** The current permission, or "unsupported". */
export function notifyPermission(): "default" | "granted" | "denied" | "unsupported" {
  if (!canNotify()) return "unsupported";
  return (globalThis as unknown as { Notification: NotificationApi }).Notification
    .permission;
}

/**
 * Asks for permission.
 *
 * Must be called from a user gesture: every browser refuses otherwise, and a
 * prompt that appears on page load is one a user dismisses reflexively.
 */
export async function requestNotifyPermission(): Promise<boolean> {
  if (!canNotify()) return false;

  const api = (globalThis as unknown as { Notification: NotificationApi }).Notification;
  if (api.permission === "granted") return true;
  if (api.permission === "denied") return false;

  return (await api.requestPermission()) === "granted";
}

/** What a notification is allowed to say. */
export interface NotifyTarget {
  /** The sender's id. Included verbatim: it is a name the user chose to see. */
  from: string;
  kind: "direct" | "group";
  /** Only used to say "in #team", never the message. */
  groupId?: string;
  /** Opens the conversation. */
  onOpen: () => void;
}

let lastShown = 0;

/**
 * Shows a notification, coalescing bursts.
 *
 * A conversation arriving as ten frames must not produce ten notifications: the
 * OS would stack them, the user would dismiss the whole stack, and the one
 * message that mattered would be in the middle. One notification per two seconds
 * is enough to say "something is happening" without becoming noise.
 */
export function notify(target: NotifyTarget): boolean {
  if (!canNotify()) return false;

  const api = (globalThis as unknown as { Notification: NotificationApi }).Notification;
  if (api.permission !== "granted") return false;

  // A focused window already showed the message in the transcript. Notifying
  // there is the behaviour that makes people turn notifications off.
  if (typeof document !== "undefined" && document.visibilityState === "visible") {
    return false;
  }

  const now = Date.now();
  if (now - lastShown < 2_000) return false;
  lastShown = now;

  // Constructed from the sender and the kind. Nothing from the message body
  // reaches this string, which is the whole point of the module.
  const title = target.kind === "group"
    ? `${target.from} in #${target.groupId ?? "group"}`
    : target.from;
  const body = target.kind === "group" ? "New message in a group" : "New message";

  try {
    const notification = new api(title, {
      body,
      // No icon: this build ships none, and a broken image is worse than none.
      tag: "veil-message",
      // The id is not secret - the relay already knows who sent to whom - but
      // nothing derived from the plaintext is in this string.
      data: target.from,
    });

    notification.onclick = () => {
      target.onOpen();
      notification.close();
      globalThis.focus?.();
    };

    return true;
  } catch {
    // Some browsers throw when constructing outside a service worker. Failing
    // quietly is right: the message itself was delivered.
    return false;
  }
}

/** Forgets the coalescing window, so a test or a reconnect can notify at once. */
export function resetNotifyWindow(): void {
  lastShown = 0;
}
