/**
 * The web client's DOM layer.
 *
 * Deliberately thin: [ChatApp] owns every decision worth testing, and this file
 * turns its state into elements. That split is what lets the protocol be tested
 * in Node without a browser, and what keeps this file small enough to read.
 */

import { ChatApp } from "./app.js";
import { SessionState } from "./engine.js";
import { checkPassword, describeStrength } from "./account.js";
import { canNotify, notifyPermission, requestNotifyPermission } from "./notify.js";
import { canScan, drawQr, encodeQr, startScanning } from "./qr.js";
import { encodeSelection, parseSelection, type Selection } from "./selection.js";

const $ = <T extends HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el as T;
};

const app = new ChatApp();

const relayUrl = $<HTMLInputElement>("relay-url");
const userId = $<HTMLInputElement>("user-id");
const connectButton = $<HTMLButtonElement>("connect");
const linkBadge = $<HTMLSpanElement>("link-badge");
const statusLine = $<HTMLParagraphElement>("status");

const addPeerForm = $<HTMLFormElement>("add-peer");
const peerIdInput = $<HTMLInputElement>("peer-id");
const peerList = $<HTMLUListElement>("peer-list");
const peersEmpty = $<HTMLParagraphElement>("peers-empty");

const chat = $<HTMLElement>("chat");
const chatPlaceholder = $<HTMLElement>("chat-placeholder");
const chatPeer = $<HTMLElement>("chat-peer");
const toggleSafety = $<HTMLButtonElement>("toggle-safety");
const safety = $<HTMLElement>("safety");
const safetyTitle = $<HTMLParagraphElement>("safety-title");
const safetyNumber = $<HTMLParagraphElement>("safety-number");
const transcript = $<HTMLOListElement>("transcript");

const composeForm = $<HTMLFormElement>("compose");
const draft = $<HTMLTextAreaElement>("draft");
const sendButton = $<HTMLButtonElement>("send");
const versionLabel = $<HTMLSpanElement>("version");

const newGroupForm = $<HTMLFormElement>("new-group");
const groupIdInput = $<HTMLInputElement>("group-id");
const groupPanel = $<HTMLElement>("group-panel");
const groupEpoch = $<HTMLParagraphElement>("group-epoch");
const groupMembersForm = $<HTMLFormElement>("group-members");
const membersInput = $<HTMLInputElement>("members");
const groupHint = $<HTMLParagraphElement>("group-hint");

// ---- Device linking ----

const openLink = $<HTMLButtonElement>("open-link");
const linkDialog = $<HTMLDialogElement>("link-dialog");
const tabLink = $<HTMLButtonElement>("tab-link");
const tabApprove = $<HTMLButtonElement>("tab-approve");
const paneLink = $<HTMLElement>("pane-link");
const paneApprove = $<HTMLElement>("pane-approve");
const generateRequest = $<HTMLButtonElement>("generate-request");
const qrCanvas = $<HTMLCanvasElement>("qr-canvas");
const ownRequest = $<HTMLTextAreaElement>("own-request");
const pastedCredential = $<HTMLTextAreaElement>("pasted-credential");
const pastedIdentity = $<HTMLTextAreaElement>("pasted-identity");
const adoptCredential = $<HTMLButtonElement>("adopt-credential");
const incomingRequest = $<HTMLTextAreaElement>("incoming-request");
const readRequest = $<HTMLButtonElement>("read-request");
const scanRequest = $<HTMLButtonElement>("scan-request");
const stopScan = $<HTMLButtonElement>("stop-scan");
const scanVideo = $<HTMLVideoElement>("scan-video");
const requestDetails = $<HTMLElement>("request-details");
const requestUser = $<HTMLElement>("request-user");
const requestFingerprint = $<HTMLElement>("request-fingerprint");
const approveRequest = $<HTMLButtonElement>("approve-request");
const issuedCredential = $<HTMLTextAreaElement>("issued-credential");
const linkStatus = $<HTMLParagraphElement>("link-status");
const closeLink = $<HTMLButtonElement>("close-link");

// ---- Accounts ----

const openAccount = $<HTMLButtonElement>("open-account");
const accountDialog = $<HTMLDialogElement>("account-dialog");
const tabRegister = $<HTMLButtonElement>("tab-register");
const tabRestore = $<HTMLButtonElement>("tab-restore");
const paneRegister = $<HTMLElement>("pane-register");
const paneRestore = $<HTMLElement>("pane-restore");
const registerPassword = $<HTMLInputElement>("register-password");
const registerPassword2 = $<HTMLInputElement>("register-password2");
const passwordStrength = $<HTMLParagraphElement>("password-strength");
const registerButton = $<HTMLButtonElement>("register");
const restoreId = $<HTMLInputElement>("restore-id");
const restorePassword = $<HTMLInputElement>("restore-password");
const restoreButton = $<HTMLButtonElement>("restore");
const tabChange = $<HTMLButtonElement>("tab-change");
const paneChange = $<HTMLElement>("pane-change");
const changeOld = $<HTMLInputElement>("change-old");
const changeNew = $<HTMLInputElement>("change-new");
const changeStrength = $<HTMLParagraphElement>("change-strength");
const changeButton = $<HTMLButtonElement>("change");
const accountStatus = $<HTMLParagraphElement>("account-status");
const closeAccount = $<HTMLButtonElement>("close-account");
const enableNotify = $<HTMLButtonElement>("enable-notify");

/** The conversation on screen. Kept beside the parser so the two agree. */
let selected: Selection | null = null;

/** Remembered across re-renders, so a reload keeps the conversation. */
const STORAGE_KEY = "veil.selected";

// ---- Startup ----------------------------------------------------------

async function main(): Promise<void> {
  try {
    await app.init("wasm/veil.wasm");
  } catch (e) {
    showFatal(e instanceof Error ? e.message : "could not start");
    return;
  }

  versionLabel.textContent = `protocol engine ${await engineVersion()}`;
  restoreSelection();
  refreshNotifyButton();

  app.subscribe(render);

  // The relay address and id are conveniences, not secrets; remembering them makes
  // a reload less annoying without storing anything that matters.
  //
  // The fallback is derived from the page's own origin rather than hard-coded.
  // A built-in `ws://127.0.0.1:8080/ws` means a page served from anywhere other
  // than a developer's machine tries to connect to the visitor's own computer,
  // which fails in a way that looks like the deployment is broken. Whatever host
  // served this page is the host running the relay: they are one origin by
  // design, which is what the CSP and the origin allow-list both assume.
  relayUrl.value =
    localStorage.getItem("veil.relay") ?? defaultRelayUrl();
  userId.value = localStorage.getItem("veil.userId") ?? "";

  render();
}

async function engineVersion(): Promise<string> {
  // Imported lazily so the version label cannot delay the engine being ready.
  const { VeilEngine } = await import("./engine.js");
  return VeilEngine.version();
}

function showFatal(message: string): void {
  statusLine.hidden = false;
  statusLine.textContent = message;
  connectButton.disabled = true;
}

// ---- Rendering --------------------------------------------------------

function render(): void {
  renderLink();
  renderStatus();
  renderPeers();
  renderChat();
}

function renderLink(): void {
  const link = app.link;
  linkBadge.textContent = link;
  linkBadge.className = `badge ${link}`;
  connectButton.textContent = link === "online" ? "Reconnect" : "Connect";
  connectButton.disabled = link === "connecting";
}

function renderStatus(): void {
  const status = app.status;
  statusLine.hidden = status === null;
  statusLine.textContent = status ?? "";
}

function renderPeers(): void {
  const peers = app.peerList;
  const groups = app.groupViews();
  peersEmpty.hidden = peers.length + groups.length > 0;

  const rows: HTMLElement[] = [];

  for (const peer of peers) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.peerId = peer.userId;
    button.setAttribute(
      "aria-current",
      String(selected?.kind === "peer" && selected.id === peer.userId),
    );

    const name = document.createElement("span");
    name.className = "peer-name";
    name.textContent = peer.displayName;

    const state = document.createElement("span");
    state.className = "peer-state";
    // The device count is shown only when there is more than one: a
    // single-device peer is the ordinary case, and saying "1 device" on every
    // row is noise that hides the row where it matters.
    state.textContent =
      peer.devices.length > 1
        ? `${stateLabel(peer.state)}, ${peer.devices.length} devices`
        : stateLabel(peer.state);

    button.append(name, state);
    button.addEventListener("click", () => select({ kind: "peer", id: peer.userId }));
    item.append(button);
    rows.push(item);
  }

  for (const group of groups) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.groupId = group.groupId;
    button.setAttribute(
      "aria-current",
      String(selected?.kind === "group" && selected.id === group.groupId),
    );

    const name = document.createElement("span");
    name.className = "peer-name";
    name.textContent = `# ${group.groupId}`;

    const state = document.createElement("span");
    state.className = "peer-state";
    state.textContent = group.canSend
      ? `group, epoch ${group.epoch}`
      : `group, epoch ${group.epoch} - not a member`;

    button.append(name, state);
    button.addEventListener("click", () => select({ kind: "group", id: group.groupId }));
    item.append(button);
    rows.push(item);
  }

  peerList.replaceChildren(...rows);

  // Keep the selection honest: a conversation can disappear if the store is
  // cleared, and pointing at a row that no longer exists shows a stale transcript.
  if (selected?.kind === "peer" && !peers.some((p) => p.userId === selected!.id)) {
    selected = null;
  }
  if (selected?.kind === "group" && !groups.some((g) => g.groupId === selected!.id)) {
    selected = null;
  }
}

function stateLabel(state: SessionState): string {
  switch (state) {
    case SessionState.Ready:
      return "session ready";
    case SessionState.PinnedOnly:
      return "identity pinned, no session";
    default:
      return "no session yet";
  }
}

function renderChat(): void {
  const showChat = selected !== null;
  chat.hidden = !showChat;
  chatPlaceholder.hidden = showChat;

  if (!selected) {
    groupPanel.hidden = true;
    return;
  }

  if (selected.kind === "group") {
    renderGroupChat(selected.id);
    return;
  }

  const peer = app.peerList.find((p) => p.userId === selected!.id);
  if (!peer) return;

  groupPanel.hidden = true;
  chatPeer.textContent = peer.displayName;

  // The safety number is only meaningful once a session exists, and it is the
  // one thing a user is asked to compare out of band.
  safetyTitle.textContent = `Safety number with ${peer.userId}`;
  if (peer.safetyNumber) {
    safetyNumber.textContent = peer.safetyNumber;
    safetyNumber.hidden = false;
  } else {
    safetyNumber.textContent = "No session yet: send or receive a message first.";
    safetyNumber.hidden = false;
  }

  renderTranscript(peer.userId);

  const canSend = peer.state === SessionState.Ready && app.link === "online";
  draft.disabled = !canSend;
  sendButton.disabled = !canSend;
}

/**
 * A group transcript.
 *
 * Two things differ from a peer conversation and both are stated on screen
 * rather than implied: the epoch, because a membership change discards every
 * chain and the group is unusable until each member republishes one; and the
 * sender of each message, because there is more than one of them.
 */
function renderGroupChat(groupId: string): void {
  const group = app.groupViews().find((g) => g.groupId === groupId);
  if (!group) return;

  chatPeer.textContent = `# ${group.groupId}`;
  safetyTitle.textContent = `Group ${group.groupId}`;
  safetyNumber.textContent = group.canSend
    ? "Sender Keys: one frame per message, regardless of group size."
    : "This client is not a member of this group.";
  safetyNumber.hidden = false;

  groupPanel.hidden = false;
  groupEpoch.textContent = `Epoch ${group.epoch} - members: ${group.members.join(", ")}`;
  groupHint.textContent = group.canSend
    ? ""
    : "A membership change re-keys every chain; nobody can send until each " +
      "member publishes one.";

  // Seed the field with the current members so an edit starts from what is
  // there rather than from an empty box the user has to retype.
  if (document.activeElement !== membersInput) {
    membersInput.value = group.members.join(", ");
  }

  renderGroupTranscript(groupId);

  // A group frame needs a live chain, not a pairwise session, so the readiness
  // test is the membership rather than the session state.
  const canSend = group.canSend && app.link === "online";
  draft.disabled = !canSend;
  sendButton.disabled = !canSend;
}

function renderGroupTranscript(groupId: string): void {
  const messages = app.groupMessagesFor(groupId);
  const format = new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  });

  transcript.replaceChildren(
    ...messages.map((message) => {
      const item = document.createElement("li");
      item.className = `bubble ${message.outgoing ? "out" : "in"}`;

      const text = document.createElement("div");
      text.textContent = message.text;

      const meta = document.createElement("div");
      meta.className = "meta";
      // Every group message names its sender: unlike a peer conversation, the
      // other side is not one person.
      const who = message.outgoing ? "you" : message.senderId;
      meta.textContent = `${who} - ${format.format(message.at)}`;

      item.append(text, meta);
      return item;
    }),
  );

  transcript.scrollTop = transcript.scrollHeight;
}

function renderTranscript(peerId: string): void {
  const messages = app.messagesFor(peerId);
  const format = new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  });

  transcript.replaceChildren(
    ...messages.map((message) => {
      const item = document.createElement("li");
      item.className = `bubble ${message.outgoing ? "out" : "in"}`;

      const text = document.createElement("div");
      text.textContent = message.text;

      const meta = document.createElement("div");
      meta.className = "meta";

      if (message.state !== "sent" && message.outgoing) {
        const state = document.createElement("span");
        state.className = "state";
        state.textContent = message.state === "queued" ? "sending" : "not sent";
        meta.append(state);
      }

      const time = document.createElement("time");
      time.dateTime = new Date(message.timestamp).toISOString();
      time.textContent = format.format(message.timestamp);
      meta.append(time);

      item.append(text, meta);
      return item;
    }),
  );

  // Reading a conversation means looking at the bottom of it.
  transcript.scrollTop = transcript.scrollHeight;
}

// ---- Interaction ------------------------------------------------------

function select(next: Selection): void {
  selected = next;
  // One key holding both parts, so a reload cannot read a peer id where a group
  // was meant: the kind travels with the id.
  localStorage.setItem(STORAGE_KEY, encodeSelection(next));
  render();
}

/** Restores the remembered conversation, ignoring anything malformed. */
function restoreSelection(): void {
  selected = parseSelection(localStorage.getItem(STORAGE_KEY));
}

connectButton.addEventListener("click", () => {
  const url = relayUrl.value.trim();
  const id = userId.value.trim();
  if (!url || !id) return;

  localStorage.setItem("veil.relay", url);
  localStorage.setItem("veil.userId", id);
  void app.connect(url, id);

  // The engine's view of each peer is the truth; the cached one is a guess
  // made before a reload.
  setTimeout(() => app.refreshStates(), 500);
});

addPeerForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const id = peerIdInput.value.trim();
  if (!id) return;
  app.addPeer(id);
  peerIdInput.value = "";
  select({ kind: "peer", id });
});

newGroupForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const id = groupIdInput.value.trim();
  if (!id) return;

  // Creating a group is local: it needs a device, not a connection. Awaiting it
  // is what lets the new group be selected immediately rather than after the
  // next notify().
  void app.createGroup(id).then((ok) => {
    if (!ok) return;
    groupIdInput.value = "";
    select({ kind: "group", id });
  });
});

groupMembersForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (selected?.kind !== "group") return;

  const members = membersInput.value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (members.length === 0) return;

  void app.setGroupMembers(selected.id, members);
});

composeForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!selected) return;

  const text = draft.value;
  if (!text.trim()) return;
  draft.value = "";

  if (selected.kind === "peer") {
    app.send(selected.id, text);
  } else {
    void app.sendToGroup(selected.id, text);
  }
});

// Enter sends, Shift+Enter adds a line: the convention every chat has, and one
// users notice immediately when it is missing.
draft.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    composeForm.requestSubmit();
  }
});

toggleSafety.addEventListener("click", () => {
  const open = safety.hidden;
  safety.hidden = !open;
  toggleSafety.setAttribute("aria-expanded", String(open));
  toggleSafety.textContent = open ? "Hide code" : "Verify";
});

// ---- Device linking ---------------------------------------------------

function showLinkStatus(text: string | null): void {
  linkStatus.hidden = text === null;
  linkStatus.textContent = text ?? "";
}

function selectTab(linkThis: boolean): void {
  paneLink.hidden = !linkThis;
  paneApprove.hidden = linkThis;
  tabLink.classList.toggle("selected", linkThis);
  tabApprove.classList.toggle("selected", !linkThis);
  showLinkStatus(null);
}

openLink.addEventListener("click", () => {
  linkDialog.showModal();
  selectTab(true);
});

closeLink.addEventListener("click", () => linkDialog.close());

tabLink.addEventListener("click", () => selectTab(true));
tabApprove.addEventListener("click", () => selectTab(false));

generateRequest.addEventListener("click", () => {
  const request = app.linkingRequest();
  if (!request) {
    showLinkStatus(
      "this browser has no device identity yet: connect first, then generate",
    );
    return;
  }

  // Base64 for both the text field and the QR: one representation, so a device
  // that scans and a device that is typed into receive the same bytes.
  const text = toBase64(request);
  ownRequest.value = text;
  ownRequest.hidden = false;

  try {
    const code = encodeQr(new TextEncoder().encode(text));
    qrCanvas.width = (code.size + 8) * 5;
    qrCanvas.height = (code.size + 8) * 5;
    const ctx = qrCanvas.getContext("2d");
    if (ctx) drawQr(ctx, code, { scale: 5, margin: 4 });
    qrCanvas.hidden = false;
  } catch (e) {
    // A request too large to encode is a real possibility if the format grows;
    // saying so is better than showing a code that lost its tail.
    qrCanvas.hidden = true;
    showLinkStatus(
      `too large for a QR code (${request.length} bytes); use the text below`,
    );
  }

  showLinkStatus(null);
});

readRequest.addEventListener("click", () => {
  const bytes = fromBase64(incomingRequest.value);
  if (!bytes) {
    showLinkStatus("that is not a request");
    return;
  }

  const parsed = app.readLinkingRequest(bytes);
  if (!parsed) {
    showLinkStatus("that request could not be read");
    return;
  }

  requestUser.textContent = parsed.userId;
  requestFingerprint.textContent = parsed.fingerprint;
  requestDetails.hidden = false;
  showLinkStatus(null);
});

// ---- Scanning ---------------------------------------------------------

let scanner: { stop(): void } | null = null;

function stopScanning(): void {
  scanner?.stop();
  scanner = null;
  scanVideo.hidden = true;
  stopScan.hidden = true;
  scanRequest.hidden = false;
}

scanRequest.addEventListener("click", () => {
  if (!canScan()) {
    showLinkStatus(
      "this browser has no camera access; type or paste the request instead",
    );
    return;
  }

  showLinkStatus("point the camera at the other device's code");

  void startScanning(scanVideo, (text) => {
    // The scan produces the same string the other device shows, so it lands in
    // the text field and the existing Read button takes over - one path from
    // here, whether the request was scanned or typed.
    incomingRequest.value = text;
    stopScanning();
    showLinkStatus("code captured; press Read it");
  })
    .then((handle) => {
      scanner = handle;
      scanVideo.hidden = false;
      stopScan.hidden = false;
      scanRequest.hidden = true;
    })
    .catch((e: unknown) => {
      showLinkStatus(e instanceof Error ? e.message : "the camera did not start");
      stopScanning();
    });
});

stopScan.addEventListener("click", () => {
  stopScanning();
  showLinkStatus(null);
});

// A dialog that closes while the camera is running would leave the track on,
// and the indicator light on with it.
closeLink.addEventListener("click", () => stopScanning());

approveRequest.addEventListener("click", () => {
  const bytes = fromBase64(incomingRequest.value);
  if (!bytes) {
    showLinkStatus("that is not a request");
    return;
  }

  const credential = app.approveLinking(bytes);
  if (!credential) {
    showLinkStatus("only the device that holds the account key can approve");
    return;
  }

  issuedCredential.value = toBase64(credential);
  issuedCredential.hidden = false;
  showLinkStatus("approved. Send this to the new device.");
});

adoptCredential.addEventListener("click", () => {
  const credential = fromBase64(pastedCredential.value);
  const identity = fromBase64(pastedIdentity.value);

  if (!credential || !identity) {
    showLinkStatus("paste both the credential and the account identity");
    return;
  }
  if (identity.length !== 64) {
    showLinkStatus("the account identity must be 64 bytes");
    return;
  }

  void app
    .adoptLinking(credential, identity.slice(0, 32), identity.slice(32, 64))
    .then((ok) => {
      showLinkStatus(
        ok
          ? "this device is now part of the account"
          : "that credential was refused",
      );
      if (ok) render();
    });
});

/** Base64 without padding, so it survives a copy-paste round trip intact. */
function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Accepts what toBase64 produced, and tolerates whitespace from a paste. */
function fromBase64(text: string): Uint8Array | null {
  const cleaned = text.replace(/\s+/g, "");
  if (cleaned.length === 0) return null;

  try {
    const binary = atob(cleaned);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/**
 * The relay that served this page.
 *
 * Derived rather than hard-coded: the page and the relay share one origin by
 * design, so whatever host delivered the HTML is the host with the websocket. A
 * literal address only works on the machine it was written for, and fails on
 * every other one in a way that looks like a server problem.
 *
 * `ws:` versus `wss:` follows the page's own scheme, because a secure page cannot
 * open an insecure socket - the browser blocks it as mixed content, and the
 * failure is easy to miss.
 */
function defaultRelayUrl(): string {
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${location.host}/ws`;
}

// ---- Accounts ---------------------------------------------------------

function showAccountStatus(text: string | null): void {
  accountStatus.hidden = text === null;
  accountStatus.textContent = text ?? "";
}


function selectAccountTabByName(name: "register" | "restore" | "change"): void {
  paneRegister.hidden = name !== "register";
  paneRestore.hidden = name !== "restore";
  paneChange.hidden = name !== "change";
  tabRegister.classList.toggle("selected", name === "register");
  tabRestore.classList.toggle("selected", name === "restore");
  tabChange.classList.toggle("selected", name === "change");
  showAccountStatus(null);
}

openAccount.addEventListener("click", () => {
  restoreId.value = userId.value.trim();
  accountDialog.showModal();
  selectAccountTabByName("register");
});

closeAccount.addEventListener("click", () => accountDialog.close());
tabRegister.addEventListener("click", () => selectAccountTabByName("register"));
tabRestore.addEventListener("click", () => selectAccountTabByName("restore"));
tabChange.addEventListener("click", () => selectAccountTabByName("change"));

// The strength line is the only feedback a user gets on the one thing that
// matters, so it updates as they type rather than on submit.
registerPassword.addEventListener("input", () => {
  const password = registerPassword.value;
  const problem = checkPassword(password);
  passwordStrength.textContent = problem ?? `strength: ${describeStrength(password)}`;
  passwordStrength.style.color = problem ? "var(--danger, #c62828)" : "";
});

registerButton.addEventListener("click", () => {
  const password = registerPassword.value;

  if (password !== registerPassword2.value) {
    showAccountStatus("the two passwords do not match");
    return;
  }

  const problem = checkPassword(password);
  if (problem) {
    showAccountStatus(problem);
    return;
  }

  showAccountStatus("deriving the key (this takes a moment)...");

  void app.createAccount(password).then((error) => {
    showAccountStatus(error ?? "account created");
    if (!error) {
      registerPassword.value = "";
      registerPassword2.value = "";
      passwordStrength.textContent = "";
    }
  });
});

restoreButton.addEventListener("click", () => {
  const id = restoreId.value.trim();
  if (!id) {
    showAccountStatus("enter the id to restore");
    return;
  }

  showAccountStatus("deriving the key (this takes a moment)...");

  void app.restoreAccount(id, restorePassword.value).then((error) => {
    showAccountStatus(error ?? "signed in");

    if (!error) {
      userId.value = id;
      restorePassword.value = "";
      // The restored identity is now this browser's; connecting with it is the
      // next step and the user should see that it is available.
      render();
    }
  });
});

changeNew.addEventListener("input", () => {
  const password = changeNew.value;
  const problem = checkPassword(password);
  changeStrength.textContent = problem ?? `strength: ${describeStrength(password)}`;
  changeStrength.style.color = problem ? "var(--danger, #c62828)" : "";
});

changeButton.addEventListener("click", () => {
  const oldPassword = changeOld.value;
  const newPassword = changeNew.value;

  const problem = checkPassword(newPassword);
  if (problem) {
    showAccountStatus(problem);
    return;
  }

  showAccountStatus("deriving the key (this takes a moment)...");

  void app.changePassword(oldPassword, newPassword).then((error) => {
    showAccountStatus(error ?? "password changed");
    if (!error) {
      changeOld.value = "";
      changeNew.value = "";
      changeStrength.textContent = "";
    }
  });
});

// ---- Notifications ----------------------------------------------------

/**
 * Shows the notify button only when it can do something.
 *
 * Three cases matter: an unsupported browser has no button, a browser that has
 * already been granted does not need one, and a browser that denied permission
 * cannot be asked again from script - so the button would be a control that
 * cannot work. That last case is why the button's absence is not a bug.
 */
function refreshNotifyButton(): void {
  const permission = notifyPermission();
  enableNotify.hidden = permission !== "default";
}

enableNotify.addEventListener("click", () => {
  // Called from a click because every browser refuses a permission prompt that
  // was not triggered by a gesture - and one that appears on load is dismissed
  // reflexively.
  void requestNotifyPermission().then((granted) => {
    refreshNotifyButton();
    if (!granted) {
      // Permission being refused permanently is a fact the user should hear once,
      // because the button disappears afterwards and its absence would otherwise
      // look like a bug.
      app.showStatusMessage(
        "notifications were refused; the browser will not ask again",
      );
    }
  });
});

// A notification click selects the conversation it came from. The callback's
// shape is the App's, not the Selection's, so the translation happens here -
// where the Selection type is already known.
app.onNotificationOpen = (target) => {
  selected = target.kind === "peer"
    ? { kind: "peer", id: target.peerId }
    : { kind: "group", id: target.groupId };
  render();
};

void main();