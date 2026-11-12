// Notifications.
//
// The important assertion is a negative one: the notification must not contain
// the message. A notification is rendered by the operating system, on a lock
// screen and in a history, so a body with the text in it would undo the
// encryption of the message it described - and the user would never know.

import assert from "node:assert/strict";
import test from "node:test";

/** A controllable stand-in for the browser's Notification API. */
class FakeNotification {
  static permission = "default";
  static requested = 0;
  static created = [];
  static failConstruction = false;

  static async requestPermission() {
    FakeNotification.requested += 1;
    return FakeNotification.permission;
  }

  constructor(title, options) {
    if (FakeNotification.failConstruction) {
      throw new Error("not allowed");
    }
    this.title = title;
    this.options = options ?? {};
    this.onclick = null;
    this.closed = false;
    FakeNotification.created.push(this);
  }

  close() {
    this.closed = true;
  }
}

/** The module reads `globalThis.Notification` and `document.visibilityState`. */
function installGlobals({ permission = "default", visibility = "hidden" } = {}) {
  FakeNotification.permission = permission;
  FakeNotification.requested = 0;
  FakeNotification.created = [];
  FakeNotification.failConstruction = false;

  globalThis.Notification = FakeNotification;
  globalThis.document = { visibilityState: visibility };
}

const {
  canNotify,
  notify,
  notifyPermission,
  requestNotifyPermission,
  resetNotifyWindow,
} = await import("../dist/notify.js");

test("a notification says who sent it and nothing else", () => {
  installGlobals({ permission: "granted", visibility: "hidden" });
  resetNotifyWindow();

  notify({ from: "alice", kind: "direct", onOpen: () => {} });

  assert.equal(FakeNotification.created.length, 1);
  const shown = FakeNotification.created[0];

  assert.equal(shown.title, "alice");
  // The one that matters: the body must not be able to contain plaintext,
  // because nothing is passed in that could produce it.
  assert.equal(shown.options.body, "New message");
});

test("a group notification names the group but not the message", () => {
  installGlobals({ permission: "granted", visibility: "hidden" });
  resetNotifyWindow();

  notify({ from: "bob", kind: "group", groupId: "team", onOpen: () => {} });

  const shown = FakeNotification.created[0];
  assert.match(shown.title, /bob/);
  assert.match(shown.title, /team/);
  assert.doesNotMatch(shown.options.body, /team/);
});

test("a focused page does not notify", () => {
  // The message is already in the transcript. Notifying about something the user
  // is looking at is what makes people turn notifications off.
  installGlobals({ permission: "granted", visibility: "visible" });
  resetNotifyWindow();

  assert.equal(notify({ from: "alice", kind: "direct", onOpen: () => {} }), false);
  assert.equal(FakeNotification.created.length, 0);
});

test("a burst is coalesced into one notification", () => {
  // Ten frames must not produce ten notifications: they would stack, the user
  // would dismiss the stack, and the message that mattered would be in the middle.
  installGlobals({ permission: "granted", visibility: "hidden" });
  resetNotifyWindow();

  for (let i = 0; i < 10; i++) {
    notify({ from: "alice", kind: "direct", onOpen: () => {} });
  }

  assert.equal(FakeNotification.created.length, 1);
});

test("nothing is shown without permission", () => {
  installGlobals({ permission: "default", visibility: "hidden" });
  resetNotifyWindow();

  assert.equal(notify({ from: "alice", kind: "direct", onOpen: () => {} }), false);
  assert.equal(FakeNotification.created.length, 0);
});

test("a denied permission is not asked again", async () => {
  // Once denied, the browser will not prompt again from script. Asking anyway
  // would produce a promise that never resolves to granted, and a UI that keeps
  // offering a control that cannot work.
  installGlobals({ permission: "denied" });

  assert.equal(await requestNotifyPermission(), false);
  assert.equal(FakeNotification.requested, 0, "the prompt must not be shown again");
});

test("permission is requested once, from a gesture", async () => {
  installGlobals({ permission: "default" });
  // The browser grants on the first prompt, as a user clicking Allow would.
  FakeNotification.requestPermission = async () => {
    FakeNotification.requested += 1;
    FakeNotification.permission = "granted";
    return "granted";
  };

  assert.equal(await requestNotifyPermission(), true);
  assert.equal(FakeNotification.requested, 1);

  // Now granted, so the second call short-circuits: no second prompt.
  assert.equal(await requestNotifyPermission(), true);
  assert.equal(FakeNotification.requested, 1, "the prompt must not be shown twice");
});

test("clicking a notification opens the conversation and closes it", () => {
  installGlobals({ permission: "granted", visibility: "hidden" });
  resetNotifyWindow();

  let opened = 0;
  notify({ from: "alice", kind: "direct", onOpen: () => { opened += 1; } });

  FakeNotification.created[0].onclick();
  assert.equal(opened, 1);
  assert.equal(FakeNotification.created[0].closed, true);
});

test("a browser that refuses construction does not throw", () => {
  // Safari throws when a notification is constructed outside a service worker.
  // Failing quietly is right: the message itself was delivered, and a page-level
  // exception would look like a messaging failure.
  installGlobals({ permission: "granted", visibility: "hidden" });
  resetNotifyWindow();
  FakeNotification.failConstruction = true;

  assert.doesNotThrow(() => {
    notify({ from: "alice", kind: "direct", onOpen: () => {} });
  });
});

test("an unsupported browser reports as much rather than pretending", () => {
  delete globalThis.Notification;
  assert.equal(canNotify(), false);
  assert.equal(notifyPermission(), "unsupported");
  assert.equal(notify({ from: "a", kind: "direct", onOpen: () => {} }), false);
});
