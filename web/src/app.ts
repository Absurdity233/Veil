/**
 * The web client's application logic.
 *
 * Structurally the same as the Android `ChatController` and the desktop
 * `ChatController`: encrypt on the way out, persist the exact frame if it cannot
 * be sent, restore state before decrypting anything. The parts that differ are
 * the ones that are genuinely different on the web 鈥?storage (see vault.ts) and
 * the fact that a page can be reloaded at any moment, which makes the
 * queued-frame list something to persist rather than keep in memory.
 */

import { SessionState, Status, VeilEngine } from "./engine.js";
import { RelayClient, type RelayEvent, buildBundle } from "./relay.js";
import { Reader } from "./wire.js";
import { Vault, type StoredMessage } from "./vault.js";

export type LinkState = "offline" | "connecting" | "online" | "error";

export interface PeerView {
  userId: string;
  displayName: string;
  safetyNumber: string | null;
  state: SessionState;
}

const REFILL_LOW_WATER = 10;

/** A frame that was encrypted but not handed to the relay. */
interface QueuedFrame {
  peerId: string;
  frame: number[];
  text: string;
}

/**
 * The client.
 *
 * Deliberately not a framework component: it is a plain class with listeners,
 * so it can be driven from a test or from the DOM without either knowing about
 * the other.
 */
export class ChatApp {
  private engine: VeilEngine | null = null;
  private relay: RelayClient | null = null;
  private vault = new Vault();

  private peers: PeerView[] = [];
  private messages = new Map<string, StoredMessage[]>();
  private queue: QueuedFrame[] = [];

  private nextMessageId = 1;
  private hasPublishedPreKeys = false;
  private selfUserId = "";

  private linkState: LinkState = "offline";
  private statusText: string | null = null;

  private readonly listeners = new Set<() => void>();
  private unsubscribeRelay: (() => void) | null = null;

  // ---- Observation ------------------------------------------------------

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notify(): void {
    for (const listener of this.listeners) {
      try {
        listener();
      } catch (e) {
        console.error("view listener failed", e);
      }
    }
  }

  get link(): LinkState {
    return this.linkState;
  }

  get status(): string | null {
    return this.statusText;
  }

  get peerList(): readonly PeerView[] {
    return this.peers;
  }

  messagesFor(peerId: string): readonly StoredMessage[] {
    return this.messages.get(peerId) ?? [];
  }

  // ---- Startup ----------------------------------------------------------

  /**
   * Loads the engine and everything that has to be in place before the first
   * frame is decrypted.
   *
   * The order matters: prekey state first (a session is built against a
   * generation of them, and the id counter has to come back or a reload mints a
   * new generation under an id already published), then the identity pins, then
   * the sessions.
   */
  async init(wasmUrl: string, options: { jsUrl?: string; wasmBinary?: ArrayBuffer } = {}):
    Promise<void> {
    await VeilEngine.load(wasmUrl, options);

    const secrets = await this.vault.loadIdentity();
    if (secrets) {
      this.engine = VeilEngine.restore(secrets);
      secrets.fill(0);
    } else {
      // A stored identity that will not decrypt is a lost account, not a first
      // run, and there is no recovery. Say so before overwriting it.
      if (await this.vault.isIdentityLost()) {
        throw new Error(
          "a stored identity could not be decrypted: this browser profile's key " +
            "no longer matches. The account cannot be recovered on this client.",
        );
      }
      this.engine = VeilEngine.create();
      await this.vault.storeIdentity(this.engine.identitySecrets());
    }

    const prekeyState = await this.vault.loadPreKeyState();
    if (prekeyState) {
      this.engine.importPreKeyState(prekeyState);
      prekeyState.fill(0);
    }

    const registry = await this.vault.loadRegistry();
    if (registry) {
      this.engine.importPeerRegistry(registry);
      registry.fill(0);
    }

    await this.restorePeers();
    this.notify();
  }

  /**
   * Rebuilds the peer list from whatever sessions are on disk.
   *
   * There is no separate peer table: a label exists because a session or a pin
   * exists, and saying so keeps the list from claiming a conversation that the
   * engine knows nothing about.
   */
  private async restorePeers(): Promise<void> {
    if (!this.engine) return;

    // The registry blob is the authority on which labels exist. It is parsed
    // here only to enumerate them; the engine owns the actual pins.
    const known = await this.knownPeerIds();
    for (const userId of known) {
      const blob = await this.vault.loadSession(userId);
      if (blob) {
        this.engine.importSession(userId, blob);
        blob.fill(0);
      }
      this.messages.set(userId, (await this.vault.loadMessages(userId)) ?? []);
      this.peers.push({
        userId,
        displayName: userId,
        safetyNumber: this.engine.safetyNumber(userId),
        state: this.engine.sessionState(userId),
      });
    }
  }

  /**
   * The peer labels this browser knows about.
   *
   * IndexedDB has no prefix query here without a cursor, and the set is small,
   * so the names are kept alongside the registry under a plain key.
   */
  private async knownPeerIds(): Promise<string[]> {
    const raw = await this.vault.loadPeerIds();
    return raw ?? [];
  }

  // ---- Connection -------------------------------------------------------

  async connect(url: string, userId: string): Promise<void> {
    if (!this.engine) throw new Error("not initialised");
    if (this.linkState === "connecting") return;

    this.selfUserId = userId;
    this.setLink("connecting");

    const relay = new RelayClient(url);
    this.relay = relay;

    this.unsubscribeRelay?.();
    this.unsubscribeRelay = relay.onEvent((event) => this.onRelayEvent(event));

    try {
      await relay.connect(userId, this.engine.publicIdentity());
    } catch (e) {
      this.setLink("error");
      this.setStatus(e instanceof Error ? e.message : "connection failed");
    }
  }

  disconnect(): void {
    this.unsubscribeRelay?.();
    this.unsubscribeRelay = null;
    this.relay?.close();
    // Cleared, not merely closed. `send` decides where a frame goes based on
    // this reference, and a closed-but-present client would take the frame,
    // refuse it internally, and report the message as sent.
    this.relay = null;
    this.setLink("offline");
  }

  private onRelayEvent(event: RelayEvent): void {
    switch (event.kind) {
      case "challenge": {
        const signature = this.engine!.signChallenge(event.nonce);
        this.relay?.respondToChallenge(signature);
        break;
      }
      case "connected":
        this.setLink("online");
        this.setStatus(null);
        void this.publishPreKeys().then(() => this.flushQueue());
        break;
      case "delivered":
        void this.onDelivered(event.outboxId, event.sender, event.frame);
        break;
      case "bundle":
        void this.onBundle(event);
        break;
      case "failed":
        this.setStatus(event.message);
        if (this.linkState === "connecting") this.setLink("error");
        break;
      case "disconnected":
        this.setLink("offline");
        break;
      case "morePending":
        // The ACK that follows pulls the next page; nothing to do here.
        break;
    }
  }

  /**
   * Publishes prekeys, rotating only when a refill is due.
   *
   * Rotating on every connect would throw away the private half of a signed
   * prekey a peer may already have fetched; publishing once per process would
   * mean the first twenty one-time keys are all this device ever offers.
   */
  private async publishPreKeys(): Promise<void> {
    const engine = this.engine;
    const relay = this.relay;
    if (!engine || !relay) return;

    if (this.hasPublishedPreKeys && !engine.needsPreKeyRefill(REFILL_LOW_WATER)) return;

    const set = engine.rotatePreKeys();
    await this.vault.storePreKeyState(engine.exportPreKeyState());

    // [4] signed id | [32] signed pub | [64] signature | [4] count | entries
    const r = new Reader(set);
    const signedId = r.u32();
    const signedPub = r.raw(32);
    const signature = r.raw(64);
    const oneTime = r.raw(r.remaining);

    if (relay.publishPreKeys(signedId, signedPub, signature, oneTime)) {
      this.hasPublishedPreKeys = true;
    }
    this.notify();
  }

  // ---- Peers ------------------------------------------------------------

  addPeer(peerId: string): void {
    const existing = this.peers.find((p) => p.userId === peerId);
    if (existing) {
      this.setStatus(`already talking to ${existing.displayName}`);
      return;
    }

    this.peers.push({
      userId: peerId,
      displayName: peerId,
      safetyNumber: null,
      state: SessionState.NoPeer,
    });
    this.messages.set(peerId, []);
    void this.persistPeerIds();
    this.relay?.requestBundle(peerId);
    this.notify();
  }

  private async onBundle(event: Extract<RelayEvent, { kind: "bundle" }>): Promise<void> {
    const engine = this.engine;
    if (!engine) return;

    // Never replace a live session with a volunteered bundle: re-keying
    // mid-conversation is how a hostile relay turns "the safety number did not
    // change" into a lie.
    if (engine.sessionState(event.userId) === SessionState.Ready) {
      this.setStatus(`ignored a bundle for ${event.userId}: a session is already live`);
      return;
    }

    const bundle = buildBundle(event);
    if (!bundle) {
      this.setStatus(`malformed prekey bundle for ${event.userId}`);
      return;
    }

    const status = engine.establishOutbound(event.userId, bundle);
    switch (status) {
      case Status.OK:
        break;
      case Status.IDENTITY_CHANGED:
        this.setStatus(
          `SECURITY: ${event.userId} presented a different identity key. ` +
            `Verify the new safety number before continuing.`,
        );
        return;
      case Status.BAD_SIGNATURE:
        this.setStatus(`prekey signature for ${event.userId} did not verify`);
        return;
      default:
        this.setStatus(`could not establish a session with ${event.userId}`);
        return;
    }

    const safety = engine.safetyNumber(event.userId);
    await this.persistSession(event.userId);
    await this.persistRegistry();

    const peer = this.peers.find((p) => p.userId === event.userId);
    if (peer) {
      peer.safetyNumber = safety;
      peer.state = SessionState.Ready;
    }
    this.setStatus(`session ready with ${event.userId}`);
  }

  // ---- Messaging --------------------------------------------------------

  send(peerId: string, text: string): void {
    const engine = this.engine;
    if (!engine || !text.trim()) return;

    const plain = new TextEncoder().encode(text);
    const frame = engine.encrypt(peerId, plain);
    if (!frame) {
      this.setStatus(`could not encrypt for ${peerId}: no session`);
      return;
    }

    const message: StoredMessage = {
      id: this.nextMessageId++,
      peerId,
      outgoing: true,
      text,
      timestamp: Date.now(),
      state: "queued",
    };
    this.appendMessage(message);
    void this.persistSession(peerId);

    // `=== true` rather than the value itself: a cleared relay gives `undefined`,
    // and `undefined && call()` is a falsy expression the type checker tolerates
    // but which reads like a bug. Being explicit also makes the branch below
    // obviously reachable.
    const connected = this.relay?.isConnected === true;
    if (connected && this.relay!.sendMessage(peerId, frame)) {
      this.updateMessageState(message.id, "sent");
    } else {
      // Keep the exact bytes. Re-encrypting would advance the sending chain a
      // second time and leave the peer with a hole it can never fill.
      this.queue.push({ peerId, frame: Array.from(frame), text });
      this.updateMessageState(message.id, "failed");
      this.setStatus("offline: the message is queued and will be retried");
    }
  }

  private flushQueue(): void {
    const relay = this.relay;
    if (!relay || !relay.isConnected) return;

    const stillQueued: QueuedFrame[] = [];
    for (const item of this.queue) {
      if (relay.sendMessage(item.peerId, new Uint8Array(item.frame))) {
        const messages = this.messages.get(item.peerId) ?? [];
        const last = [...messages].reverse().find((m) => m.outgoing && m.state === "failed");
        if (last) this.updateMessageState(last.id, "sent");
      } else {
        stillQueued.push(item);
        break;
      }
    }
    this.queue = stillQueued;
  }

  private async onDelivered(
    outboxId: bigint,
    peerId: string,
    frame: Uint8Array,
  ): Promise<void> {
    const engine = this.engine;
    if (!engine) return;

    const { plain, status } = engine.decrypt(peerId, frame);

    switch (status) {
      case Status.OK:
        break;
      case Status.DUPLICATE:
        // At-least-once delivery makes this routine. Acknowledge so the relay
        // stops resending, and say nothing to the user.
        if (outboxId > 0n) this.relay?.acknowledge(outboxId);
        return;
      case Status.NO_SESSION:
        this.setStatus(`dropped a message from ${peerId}: no session`);
        return;
      case Status.AUTH_FAILED:
        this.setStatus("dropped a message that failed authentication");
        return;
      default:
        this.setStatus(`dropped a message from ${peerId}`);
        return;
    }

    if (!plain) return;

    await this.persistSession(peerId);

    let peer = this.peers.find((p) => p.userId === peerId);
    if (!peer) {
      peer = {
        userId: peerId,
        displayName: peerId,
        safetyNumber: engine.safetyNumber(peerId),
        state: SessionState.Ready,
      };
      this.peers.push(peer);
      this.messages.set(peerId, []);
      await this.persistPeerIds();
      await this.persistRegistry();
    } else {
      peer.safetyNumber = engine.safetyNumber(peerId);
      peer.state = SessionState.Ready;
    }

    this.appendMessage({
      id: this.nextMessageId++,
      peerId,
      outgoing: false,
      text: new TextDecoder().decode(plain),
      timestamp: Date.now(),
      state: "sent",
    });

    if (outboxId > 0n) this.relay?.acknowledge(outboxId);

    // The peer spent a one-time prekey, so the supply may be running low.
    if (engine.needsPreKeyRefill(REFILL_LOW_WATER)) {
      await this.publishPreKeys();
    }
  }

  // ---- State ------------------------------------------------------------

  private appendMessage(message: StoredMessage): void {
    const list = this.messages.get(message.peerId) ?? [];
    list.push(message);
    this.messages.set(message.peerId, list);
    void this.vault.storeMessages(message.peerId, list);
    this.notify();
  }

  private updateMessageState(id: number, state: StoredMessage["state"]): void {
    for (const [, list] of this.messages) {
      const message = list.find((m) => m.id === id);
      if (!message) continue;
      message.state = state;
      void this.vault.storeMessages(message.peerId, list);
      break;
    }
    this.notify();
  }

  private async persistSession(peerId: string): Promise<void> {
    const blob = this.engine?.exportSession(peerId);
    if (!blob) return;
    await this.vault.storeSession(peerId, blob);
    blob.fill(0);
  }

  private async persistRegistry(): Promise<void> {
    const blob = this.engine?.exportPeerRegistry();
    if (!blob) return;
    await this.vault.storeRegistry(blob);
    blob.fill(0);
  }

  private async persistPeerIds(): Promise<void> {
    await this.vault.storePeerIds(this.peers.map((p) => p.userId));
  }

  /** Re-reads the engine's view of every peer, after a reload or a change. */
  refreshStates(): void {
    const engine = this.engine;
    if (!engine) return;
    for (const peer of this.peers) {
      peer.state = engine.sessionState(peer.userId);
      peer.safetyNumber = engine.safetyNumber(peer.userId);
    }
    this.notify();
  }

  private setLink(state: LinkState): void {
    this.linkState = state;
    this.notify();
  }

  private setStatus(text: string | null): void {
    this.statusText = text;
    this.notify();
  }
}