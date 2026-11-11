/**
 * The web client's DOM layer.
 *
 * Deliberately thin: [ChatApp] owns every decision worth testing, and this file
 * turns its state into elements. That split is what lets the protocol be tested
 * in Node without a browser, and what keeps this file small enough to read.
 */

import { ChatApp } from "./app.js";
import { SessionState } from "./engine.js";

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

let selectedPeerId: string | null = null;

/** Which peer the user is looking at, remembered across re-renders. */
const STORAGE_KEY = "veil.selectedPeer";

// ---- Startup ----------------------------------------------------------

async function main(): Promise<void> {
  try {
    await app.init("wasm/veil.wasm");
  } catch (e) {
    showFatal(e instanceof Error ? e.message : "could not start");
    return;
  }

  versionLabel.textContent = `protocol engine ${await engineVersion()}`;
  selectedPeerId = localStorage.getItem(STORAGE_KEY);

  app.subscribe(render);

  // The relay URL and id are conveniences, not secrets; remembering them makes
  // a reload less annoying without storing anything that matters.
  relayUrl.value = localStorage.getItem("veil.relay") ?? relayUrl.value;
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
  peersEmpty.hidden = peers.length > 0;

  peerList.replaceChildren(
    ...peers.map((peer) => {
      const item = document.createElement("li");
      const button = document.createElement("button");
      button.type = "button";
      button.dataset.peerId = peer.userId;
      button.setAttribute(
        "aria-current",
        String(peer.userId === selectedPeerId),
      );

      const name = document.createElement("span");
      name.className = "peer-name";
      name.textContent = peer.displayName;

      const state = document.createElement("span");
      state.className = "peer-state";
      state.textContent = stateLabel(peer.state);

      button.append(name, state);
      button.addEventListener("click", () => selectPeer(peer.userId));
      item.append(button);
      return item;
    }),
  );

  // Keep the selection honest: a peer can disappear if the store is cleared.
  if (selectedPeerId && !peers.some((p) => p.userId === selectedPeerId)) {
    selectedPeerId = null;
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
  const peer = app.peerList.find((p) => p.userId === selectedPeerId);
  const showChat = peer !== undefined;

  chat.hidden = !showChat;
  chatPlaceholder.hidden = showChat;

  if (!peer) return;

  chatPeer.textContent = peer.displayName;

  // The safety number is only meaningful once a session exists, and it is the
  // one thing a user is asked to compare out of band.
  safetyTitle.textContent = `Safety number with ${peer.userId}`;
  if (peer.safetyNumber) {
    safetyNumber.textContent = peer.safetyNumber;
    safetyNumber.hidden = false;
  } else {
    safetyNumber.textContent = "No session yet — send or receive a message first.";
    safetyNumber.hidden = false;
  }

  renderTranscript(peer.userId);

  const canSend = peer.state === SessionState.Ready && app.link === "online";
  draft.disabled = !canSend;
  sendButton.disabled = !canSend;
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

function selectPeer(peerId: string): void {
  selectedPeerId = peerId;
  localStorage.setItem(STORAGE_KEY, peerId);
  render();
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
  selectPeer(id);
});

composeForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!selectedPeerId) return;
  const text = draft.value;
  draft.value = "";
  app.send(selectedPeerId, text);
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

void main();