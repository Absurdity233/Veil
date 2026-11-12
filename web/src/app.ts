/**
 * The web client's application logic.
 *
 * Structurally the same as the Android `ChatController` and the desktop
 * `ChatController`: encrypt on the way out, persist the exact frame if it cannot
 * be sent, restore state before decrypting anything. The parts that differ are
 * the ones that are genuinely different on the web 闂?storage (see vault.ts) and
 * the fact that a page can be reloaded at any moment, which makes the
 * queued-frame list something to persist rather than keep in memory.
 */

import { RefreshReason, SessionState, Status, VeilEngine, type StatusCode } from "./engine.js";
import { RelayClient, type RelayEvent, buildBundle } from "./relay.js";
import { Reader } from "./wire.js";
import { Vault, type GroupMessageRecord, type StoredMessage } from "./vault.js";

export type LinkState = "offline" | "connecting" | "online" | "error";

export interface PeerView {
  userId: string;
  displayName: string;
  safetyNumber: string | null;
  state: SessionState;
  /** The peer's device ids, hex. Empty means a single-device peer. */
  devices: string[];
}

export interface GroupView {
  groupId: string;
  epoch: number;
  members: string[];
  /** Whether this client can send: a membership change discards the chain. */
  canSend: boolean;
}

export interface GroupMessageView {
  groupId: string;
  senderId: string;
  text: string;
  at: number;
  /**
   * Whether this client sent it.
   *
   * Stored rather than derived from `senderId === selfUserId`, because a
   * reloaded page has the transcript before it has reconnected, and a message
   * that silently switches sides on reconnect is worse than one field.
   */
  outgoing: boolean;
}

// The view and the stored record are the same shape, so a reload needs no
// translation and cannot drift.
const _groupMessageShape: GroupMessageRecord | GroupMessageView = {
  groupId: "", senderId: "", text: "", at: 0, outgoing: false,
};
void _groupMessageShape;

const REFILL_LOW_WATER = 10;

/**
 * How old a peer's device list may be before a send triggers a re-fetch.
 *
 * Ten minutes: long enough that a conversation does not re-fetch on every
 * message, short enough that a device linked during a session is picked up
 * without the user noticing. The send-failure trigger is what catches the rest,
 * so this only needs to be a backstop.
 */
const DEVICE_LIST_STALENESS_MS = 10 * 60 * 1000;

/** A frame that was encrypted but not handed to the relay. */
interface QueuedFrame {
  peerId: string;
  /** The device the frame was encrypted to; empty for a single-device peer. */
  deviceId: string;
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

  private groups: GroupView[] = [];
  private groupMessages = new Map<string, GroupMessageView[]>();

  /** This device's id, hex. Empty until the engine has one. */
  private selfDeviceId = "";

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
    await this.restoreGroups();
    this.notify();
  }

  /**
   * Restores groups, including their chain keys.
   *
   * Without this a reload drops every group, and a member can no longer read
   * anything sent to a group they are still in 闂?indistinguishable from having
   * been removed. The blob carries secrets, so it lives in the same encrypted
   * vault as ratchet state.
   */
  private async restoreGroups(): Promise<void> {
    if (!this.engine) return;

    const state = await this.vault.loadGroupState();
    if (state) {
      this.engine.importGroupState(state);
      state.fill(0);
    }

    const ids = (await this.vault.loadGroupIds()) ?? [];
    for (const groupId of ids) {
      const epoch = this.engine.groupEpoch(groupId);
      if (epoch === 0) continue;

      this.groups.push({
        groupId,
        epoch,
        members: this.engine.groupMembers(groupId),
        canSend: this.engine.isGroupMember(groupId),
      });
      this.groupMessages.set(groupId, (await this.vault.loadGroupMessages(groupId)) ?? []);
    }
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
        devices: this.engine.peerDevices(userId),
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

    // Claim this user id for a device before connecting, so HELLO can announce
    // it. A reload finds the existing credential rather than minting a second
    // device for the same account.
    if (!this.selfDeviceId) {
      const stored = await this.vault.loadDeviceId();
      if (stored) {
        this.selfDeviceId = stored;
      } else if (this.engine.initDevice(userId)) {
        const id = this.engine.deviceId();
        if (id) {
          this.selfDeviceId = Array.from(id, (b) => b.toString(16).padStart(2, "0")).join("");
          await this.vault.storeDeviceId(this.selfDeviceId);
        }
      }
    }

    const relay = new RelayClient(url);
    this.relay = relay;

    this.unsubscribeRelay?.();
    this.unsubscribeRelay = relay.onEvent((event) => this.onRelayEvent(event));

    try {
      await relay.connect(userId, this.engine.publicIdentity(), this.selfDeviceId);
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
        devices: [],
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

    // A peer with a published device list gets one frame per device; a
    // single-device peer gets exactly one. Either way the caller passes a user
    // id and does not have to know which case it is.
    const frames = engine.encryptToAccount(peerId, plain);
    if (frames.length === 0) {
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
    let allSent = connected;
    for (const item of frames) {
      if (!connected || !this.relay!.sendMessage(peerId, item.frame, item.deviceId)) {
        // Keep the exact bytes. Re-encrypting would advance the sending chain a
        // second time and leave the peer with a hole it can never fill.
        this.queue.push({
          peerId,
          deviceId: item.deviceId,
          frame: Array.from(item.frame),
          text,
        });
        allSent = false;
      }
    }

    if (allSent) {
      this.updateMessageState(message.id, "sent");
    } else {
      this.updateMessageState(message.id, "failed");
      this.setStatus("offline: the message is queued and will be retried");
    }

    // A frame addressed to a device that has no session is the signal that the
    // cached list is out of date - most likely the peer linked a device after this
    // client last fetched. Recording it here rather than polling is what makes the
    // refresh happen at the one moment it is likely to matter.
    const missing = frames.length === 0 || frames.some((f) => f.deviceId !== "");
    if (missing) void this.refreshDevicesIfNeeded(peerId);
  }

  // ---- Device list freshness -------------------------------------------

  /**
   * Re-fetches a peer's device list when the engine says it is worth doing.
   *
   * The engine decides; this only acts. Three triggers, no timer: a send that
   * could not be addressed, a list older than the threshold, or no list at all.
   */
  private async refreshDevicesIfNeeded(peerId: string): Promise<void> {
    const engine = this.engine;
    if (!engine) return;

    engine.setClock(Date.now());
    const reason = engine.deviceListNeedsRefresh(peerId, DEVICE_LIST_STALENESS_MS);

    // Unknown means the peer may be single-device, which works without a list.
    // Fetching one is worth a try but must not be treated as an error.
    if (reason === RefreshReason.None) return;

    const peer = this.peers.find((p) => p.userId === peerId);

    // The account identity this client already pins, which is the key the device
    // list is verified against. There is nothing to verify against without one,
    // and fetching a list into an unverified slot would be worse than not
    // fetching.
    const identity = engine.peerIdentity(peerId);
    if (!identity || identity.length !== 64) return;

    const adopted = await this.refreshPeerDevices(
      peerId, identity.slice(0, 32), identity.slice(32, 64),
    );
    if (!adopted) return;

    engine.noteDeviceListFetched(peerId);
    if (peer) peer.devices = engine.peerDevices(peerId);

    // A freshly learned device needs a session before it can receive anything,
    // so the next send is the first that can reach it.
    await this.connectPeerDevices(peerId);
    this.notify();
  }

  // ---- Groups -----------------------------------------------------------

  groupViews(): readonly GroupView[] {
    return this.groups;
  }

  groupMessagesFor(groupId: string): readonly GroupMessageView[] {
    return this.groupMessages.get(groupId) ?? [];
  }

  /** Creates a group with this client as founder and sole member. */
  async createGroup(groupId: string): Promise<boolean> {
    if (!this.engine || !groupId.trim()) return false;
    if (!this.engine.createGroup(groupId)) return false;

    await this.refreshGroup(groupId);
    return true;
  }

  /**
   * Replaces the member list.
   *
   * Every chain is discarded and the epoch moves, so nobody 闂?including this
   * client 闂?can send until each member republishes a chain. That is the point:
   * a removed member holds the old chain key and re-keying is the only thing
   * that stops them reading what follows.
   */
  async setGroupMembers(groupId: string, members: string[]): Promise<number> {
    if (!this.engine) return 0;

    const epoch = this.engine.setGroupMembers(groupId, members);
    if (epoch === 0) return 0;

    await this.refreshGroup(groupId);
    await this.persistGroups();
    return epoch;
  }

  /** The signed member list, to hand to the other members out of band. */
  exportMembership(groupId: string): Uint8Array | null {
    return this.engine?.exportMembership(groupId) ?? null;
  }

  /**
   * Adopts a member list a founder signed.
   *
   * `founderSignPub` is the founder's account signing key, which the caller got
   * by verifying the founder's safety number out of band 闂?the same trust anchor
   * the rest of the protocol uses.
   */
  async adoptMembership(
    groupId: string, record: Uint8Array, founderSignPub: Uint8Array,
  ): Promise<StatusCode | null> {
    if (!this.engine) return null;

    const status = this.engine.adoptMembership(record, founderSignPub);
    if (status !== Status.OK) return status;

    await this.refreshGroup(groupId);
    await this.persistGroups();
    return status;
  }

  /**
   * Publishes this device's chain, to be handed to each member inside a pairwise
   * session.
   *
   * Returned rather than sent: the caller decides how it travels, because the
   * chain has to arrive over a channel that already authenticates this device.
   */
  exportSenderKey(groupId: string): Uint8Array | null {
    return this.engine?.exportSenderKey(groupId, 0) ?? null;
  }

  /** Installs a member's chain, as received over a pairwise session. */
  async adoptSenderKey(
    groupId: string, record: Uint8Array, senderId: string, senderSignPub: Uint8Array,
  ): Promise<StatusCode | null> {
    if (!this.engine) return null;

    const status = this.engine.adoptSenderKey(record, senderId, senderSignPub);
    if (status === Status.OK) await this.persistGroups();
    return status;
  }

  /** Sends one message to the whole group: one frame, regardless of size. */
  async sendToGroup(groupId: string, text: string): Promise<void> {
    const engine = this.engine;
    if (!engine || !text.trim()) return;

    const record = engine.encryptToGroup(groupId, new TextEncoder().encode(text));
    if (!record) {
      this.setStatus(`cannot send to ${groupId}: the group has no live chain`);
      return;
    }

    this.appendGroupMessage({
      groupId,
      senderId: this.selfUserId,
      text,
      at: Date.now(),
      outgoing: true,
    });

    // A group frame is addressed by group id, not by device: every member needs
    // it, and the relay fans it out to the members' connections. Device
    // addressing is what pairwise frames use.
    if (this.relay?.isConnected !== true || !this.relay.sendMessage(groupId, record)) {
      this.setStatus("offline: the group message was not delivered");
    }
    await this.persistGroups();
  }

  /** Decrypts a group frame that arrived as a delivery. */
  private onGroupDelivered(senderId: string, body: Uint8Array): boolean {
    const engine = this.engine;
    if (!engine) return false;

    // The delivery is addressed by user id, so the group has to be inferred: try
    // each group this client is in and take the one that authenticates. The MAC
    // is what decides, not a guess.
    for (const group of this.groups) {
      const result = engine.decryptFromGroup(group.groupId, body);
      if (result.status === Status.OK && result.plain) {
        this.appendGroupMessage({
          groupId: group.groupId,
          senderId,
          text: new TextDecoder().decode(result.plain),
          at: Date.now(),
          outgoing: false,
        });
        void this.persistGroups();
        return true;
      }
    }
    return false;
  }

  private async refreshGroup(groupId: string): Promise<void> {
    if (!this.engine) return;

    const epoch = this.engine.groupEpoch(groupId);
    if (epoch === 0) return;

    const view: GroupView = {
      groupId,
      epoch,
      members: this.engine.groupMembers(groupId),
      canSend: this.engine.isGroupMember(groupId),
    };

    const index = this.groups.findIndex((g) => g.groupId === groupId);
    if (index >= 0) this.groups[index] = view;
    else this.groups.push(view);

    if (!this.groupMessages.has(groupId)) this.groupMessages.set(groupId, []);
    this.notify();
  }

  private appendGroupMessage(message: GroupMessageView): void {
    const list = this.groupMessages.get(message.groupId) ?? [];
    list.push(message);
    this.groupMessages.set(message.groupId, list);
    this.notify();
  }

  private async persistGroups(): Promise<void> {
    if (!this.engine) return;

    const state = this.engine.exportGroupState();
    if (state) await this.vault.storeGroupState(state);

    await this.vault.storeGroupIds(this.groups.map((g) => g.groupId));
    for (const [groupId, list] of this.groupMessages) {
      await this.vault.storeGroupMessages(groupId, list);
    }
  }

  // ---- Devices ----------------------------------------------------------

  /** This client's own device id, hex. */
  deviceId(): string {
    return this.selfDeviceId;
  }

  /** Fetches a peer's device list from the relay and adopts it. */
  async refreshPeerDevices(peerId: string, accountDhPub: Uint8Array,
                           accountSignPub: Uint8Array): Promise<boolean> {
    const relay = this.relay;
    if (!relay || !this.engine) return false;

    const listing = await relay.getDevices(peerId);
    if (!listing || listing.devices.length === 0) return false;

    const devices = listing.devices;

    // The ABI wants [4] count then the credential blobs; the relay hands them
    // back as a list, so the count is written here rather than trusted from the
    // wire twice.
    const total = 4 + devices.reduce((sum, d) => sum + d.credential.length, 0);
    const blob = new Uint8Array(total);
    new DataView(blob.buffer).setUint32(0, devices.length, false);

    let off = 4;
    for (const device of devices) {
      blob.set(device.credential, off);
      off += device.credential.length;
    }

    const status = this.engine.adoptDeviceList(
      peerId, listing.version, blob, accountDhPub, accountSignPub,
    );
    if (status !== Status.OK) return false;

    const peer = this.peers.find((p) => p.userId === peerId);
    if (peer) peer.devices = this.engine.peerDevices(peerId);

    this.notify();
    return true;
  }

  /**
   * Starts sessions with every device of a peer that has a published list.
   *
   * One bundle is fetched per device: a fan-out frame is encrypted to one
   * device's ratchet, so a bundle for the wrong device would produce a session
   * that can never read anything.
   */
  async connectPeerDevices(peerId: string): Promise<number> {
    const relay = this.relay;
    const engine = this.engine;
    if (!relay || !engine) return 0;

    const devices = engine.peerDevices(peerId);
    if (devices.length === 0) return 0;

    const ids: string[] = [];
    const bundles: Uint8Array[] = [];
    for (const deviceId of devices) {
      const bundle = await relay.getBundle(peerId);
      if (!bundle) continue;
      ids.push(deviceId);
      bundles.push(bundle);
    }
    if (ids.length === 0) return 0;

    // The ABI's shape: [4] count | per entry [2] len | hex id, then
    // [4] len | bundle for each, in the same order.
    const idsSize = 4 + ids.reduce((sum, id) => sum + 2 + id.length, 0);
    const bundlesSize = bundles.reduce((sum, b) => sum + 4 + b.length, 0);

    const idBlob = new Uint8Array(idsSize);
    const bundleBlob = new Uint8Array(bundlesSize);
    const idView = new DataView(idBlob.buffer);
    const bundleView = new DataView(bundleBlob.buffer);

    idView.setUint32(0, ids.length, false);
    let off = 4;
    for (const id of ids) {
      idView.setUint16(off, id.length, false);
      off += 2;
      for (let i = 0; i < id.length; ++i) idBlob[off + i] = id.charCodeAt(i);
      off += id.length;
    }

    off = 0;
    for (const bundle of bundles) {
      bundleView.setUint32(off, bundle.length, false);
      off += 4;
      bundleBlob.set(bundle, off);
      off += bundle.length;
    }

    return engine.establishWithDevices(peerId, idBlob, bundleBlob);
  }

  /** The signed member list, to hand to a device being linked. */
  deviceCredential(): Uint8Array | null {
    return this.engine?.deviceCredential() ?? null;
  }

  // ---- Device linking ---------------------------------------------------

  /** This device's linking request, for the existing device to endorse. */
  linkingRequest(): Uint8Array | null {
    return this.engine?.linkingRequest() ?? null;
  }

  /**
   * The account a request names and its fingerprint.
   *
   * Both from one call, so the fingerprint shown cannot belong to a different
   * request than the one about to be approved.
   */
  readLinkingRequest(data: Uint8Array): { userId: string; fingerprint: string } | null {
    return this.engine?.readLinkingRequest(data) ?? null;
  }

  /**
   * Signs an endorsement for another device.
   *
   * Null when this client does not hold the account key, which is the correct
   * answer rather than an error: a linked device cannot add further devices.
   */
  approveLinking(request: Uint8Array): Uint8Array | null {
    const engine = this.engine;
    if (!engine) return null;
    return engine.approveLinking(request, Math.floor(Date.now() / 1000));
  }

  /** This account's identity, for the device being linked to verify against. */
  publicIdentity(): Uint8Array | null {
    return this.engine?.publicIdentity() ?? null;
  }

  /** Adopts a device credential, and takes on its device id. */
  async adoptLinking(
    credential: Uint8Array, accountDhPub: Uint8Array, accountSignPub: Uint8Array,
  ): Promise<boolean> {
    return this.adoptDeviceCredential(credential, accountDhPub, accountSignPub);
  }

  /**
   * Links this client to an existing account.
   *
   * The credential has to arrive over a channel that already authenticates the
   * account 闁?the whole point is that a relay cannot issue one 闁?so this takes
   * an already-signed blob and verifies it against the account keys.
   */
  async adoptDeviceCredential(
    credential: Uint8Array, accountDhPub: Uint8Array, accountSignPub: Uint8Array,
  ): Promise<boolean> {
    if (!this.engine) return false;
    if (!this.engine.adoptDeviceCredential(credential, accountDhPub, accountSignPub)) {
      return false;
    }

    const id = this.engine.deviceId();
    if (id) {
      this.selfDeviceId = Array.from(id, (b) => b.toString(16).padStart(2, "0")).join("");
      await this.vault.storeDeviceId(this.selfDeviceId);
    }
    this.notify();
    return true;
  }

  private flushQueue(): void {
    const relay = this.relay;
    if (!relay || !relay.isConnected) return;

    const stillQueued: QueuedFrame[] = [];
    for (const item of this.queue) {
      if (relay.sendMessage(item.peerId, new Uint8Array(item.frame), item.deviceId)) {
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
        // Not necessarily an error: a group message arrives addressed by its
        // sender, and this client holds no pairwise session with them. Try it as
        // a group frame before deciding to drop it 闂?the MAC is what decides
        // which it is.
        if (this.onGroupDelivered(peerId, frame)) {
          if (outboxId > 0n) this.relay?.acknowledge(outboxId);
          return;
        }
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
        devices: [],
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