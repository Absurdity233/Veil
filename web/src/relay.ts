/**
 * The relay connection, in the browser.
 *
 * Same protocol, same envelope, same challenge-response as the Kotlin clients.
 * The only browser-specific concern is that a `WebSocket` in a page is subject
 * to the origin policy the relay enforces — so a deployment that serves this
 * page has to list its origin in VEIL_ALLOWED_ORIGINS, and the failure mode
 * when it has not is a 403 with no explanation in the console.
 */

import { FrameType, MAX_PAYLOAD, Reader, Writer, frame, parseFrame } from "./wire.js";

/**
 * A sealed vault, as the relay returns it.
 *
 * None of it is readable by the relay: the salt and KDF parameters exist so any
 * client that knows the password can reproduce the key, and the ciphertext is
 * what that key opens.
 */
export interface VaultReply {
  salt: Uint8Array;
  memoryKiB: number;
  passes: number;
  lanes: number;
  generation: number;
  ciphertext: Uint8Array;
}

export type RelayEvent =
  | { kind: "challenge"; nonce: Uint8Array }
  | { kind: "connected"; userId: string }
  | { kind: "delivered"; outboxId: bigint; sender: string; frame: Uint8Array }
  | {
      kind: "bundle";
      userId: string;
      identity: Uint8Array;
      signedId: number;
      signedPub: Uint8Array;
      signature: Uint8Array;
      oneTimeId: number;
      oneTimePub: Uint8Array;
    }
  | { kind: "morePending" }
  | { kind: "failed"; message: string }
  | { kind: "disconnected" };

export class RelayClient {
  private socket: WebSocket | null = null;
  private connected = false;
  private closed = false;

  private readonly listeners = new Set<(event: RelayEvent) => void>();
  private readonly openWaiters: Array<(ok: boolean) => void> = [];

  // One waiter per in-flight request, keyed by the user id being asked about.
  // A promise rather than an event because the caller wants the answer, not a
  // subscription, and a page that has to reconstruct the correlation itself is
  // a page that will eventually get it wrong.
  private readonly bundleWaiters = new Map<string, (bundle: Uint8Array | null) => void>();
  private readonly deviceWaiters = new Map<string, (result: {
    version: number;
    devices: Array<{ deviceId: string; credential: Uint8Array }>;
  } | null) => void>();

  // Vault requests have no correlation field on the wire: the reply does not
  // repeat the user id, because the relay answers the connection that asked. So
  // put and get get their own maps rather than sharing one and guessing at a
  // suffixed key.
  private readonly vaultPutWaiters = new Map<string, (generation: number | null) => void>();
  private readonly vaultGetWaiters = new Map<string, (reply: VaultReply | null) => void>();

  constructor(private readonly url: string) {}

  get isConnected(): boolean {
    return this.connected && this.socket !== null && !this.closed;
  }

  onEvent(listener: (event: RelayEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit(event: RelayEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch (e) {
        // A listener that throws must not take down the socket, or one UI bug
        // would silently stop every delivery.
        console.error("relay listener failed", e);
      }
    }
  }

  /**
   * Opens the socket and sends HELLO. Resolves once the socket is open.
   *
   * `deviceId` announces which device this connection speaks for, so the relay
   * can hand it only the frames addressed to it. Empty keeps the two-field HELLO
   * a single-device client sends.
   */
  connect(userId: string, publicIdentity: Uint8Array, deviceId = ""): Promise<void> {
    this.closed = false;

    return new Promise((resolve, reject) => {
      const socket = new WebSocket(this.url);
      socket.binaryType = "arraybuffer";
      this.socket = socket;

      this.openWaiters.push((ok) => (ok ? resolve() : reject(new Error("connect failed"))));

      socket.onopen = () => {
        const hello = new Writer().string(userId).blob(publicIdentity);
        if (deviceId) hello.string(deviceId);

        socket.send(frame(FrameType.HELLO, hello.build()));
        this.settleOpenWaiters(true);
      };

      socket.onmessage = (event) => {
        const data = new Uint8Array(event.data as ArrayBuffer);
        this.handleFrame(data);
      };

      socket.onerror = () => {
        this.connected = false;
        this.emit({ kind: "failed", message: "connection failed (is the relay reachable?)" });
        this.settleOpenWaiters(false);
      };

      socket.onclose = () => {
        this.connected = false;
        this.emit({ kind: "disconnected" });
        this.settleOpenWaiters(false);
      };
    });
  }

  private settleOpenWaiters(ok: boolean): void {
    for (const waiter of this.openWaiters.splice(0)) waiter(ok);
  }

  private handleFrame(bytes: Uint8Array): void {
    let parsed;
    try {
      parsed = parseFrame(bytes);
    } catch (e) {
      console.warn("dropping malformed frame", e);
      return;
    }

    const r = new Reader(parsed.payload);
    try {
      switch (parsed.type) {
        case FrameType.HELLO_OK: {
          this.connected = true;
          this.emit({ kind: "connected", userId: r.string() });
          break;
        }
        case FrameType.AUTH_CHALLENGE:
          this.emit({ kind: "challenge", nonce: r.blob() });
          break;
        case FrameType.MORE_PENDING:
          this.emit({ kind: "morePending" });
          break;
        case FrameType.DELIVER:
          this.emit({
            kind: "delivered",
            outboxId: r.u64(),
            sender: r.string(),
            frame: r.blob(),
          });
          break;
        case FrameType.BUNDLE: {
          const userId = r.string();
          const identity = r.blob();
          const signedId = r.u32();
          const signedPub = r.blob();
          const signature = r.blob();
          const oneTimeId = r.u32();
          const oneTimePub = r.blob();

          // The engine parses one fixed-width encoding, so the fields are
          // reassembled here rather than teaching the engine the frame layout.
          const waiters = this.bundleWaiters.get(userId);
          if (waiters) {
            waiters(encodeBundle(
              identity, signedId, signedPub, signature, oneTimeId, oneTimePub,
            ));
          }

          this.emit({
            kind: "bundle",
            userId,
            identity,
            signedId,
            signedPub,
            signature,
            oneTimeId,
            oneTimePub,
          });
          break;
        }
        case FrameType.DEVICES: {
          const version = r.u32();
          const count = r.u32();

          const devices: Array<{ deviceId: string; credential: Uint8Array }> = [];
          let owner = "";
          for (let i = 0; i < count; ++i) {
            const deviceId = r.string();
            const credential = r.blob();
            // The credential names its own account; that is the key the waiter
            // was registered under, so it is read back rather than guessed.
            owner = credentialOwner(credential);
            devices.push({ deviceId, credential });
          }

          const waiter = this.deviceWaiters.get(owner);
          if (waiter) waiter({ version, devices });
          break;
        }
        case FrameType.VAULT_ACK: {
          const generation = r.u32();
          // The reply carries no user id - the relay answers the connection that
          // asked - so this resolves the single put in flight.
          const waiter = this.vaultPutWaiters.values().next().value;
          if (waiter) waiter(generation);
          break;
        }
        case FrameType.VAULT_DATA: {
          const salt = r.blob();
          const memoryKiB = r.u32();
          const passes = r.u32();
          const lanes = r.u32();
          const generation = r.u32();
          const ciphertext = r.blob();

          const waiter = this.vaultGetWaiters.values().next().value;
          if (waiter) {
            waiter({ salt, memoryKiB, passes, lanes, generation, ciphertext });
          }
          break;
        }
        case FrameType.ERROR:
          this.emit({ kind: "failed", message: r.string() });
          break;
        default:
          // Unknown frame types are ignored rather than fatal: a newer relay
          // adding a message must not break an older page.
          break;
      }
    } catch (e) {
      console.warn("dropping unparseable frame", e);
    }
  }

  /**
   * Answers a challenge.
   *
   * Not gated on `connected`: the handshake is how the connection becomes
   * usable, so requiring it here would drop the frame that completes it.
   */
  respondToChallenge(signature: Uint8Array): boolean {
    return this.write(
      FrameType.AUTH_RESPONSE,
      new Writer().blob(signature).build(),
    );
  }

  publishPreKeys(
    signedId: number,
    signedPub: Uint8Array,
    signature: Uint8Array,
    oneTimeSet: Uint8Array,
  ): boolean {
    return this.send(
      FrameType.PUBLISH_PREKEYS,
      new Writer().u32(signedId).blob(signedPub).blob(signature).blob(oneTimeSet).build(),
    );
  }

  requestBundle(userId: string): boolean {
    return this.send(FrameType.GET_BUNDLE, new Writer().string(userId).build());
  }

  /**
   * Requests a peer's device list.
   *
   * The reply arrives asynchronously as a `devices` event, so this resolves a
   * promise rather than returning the list: the caller wants the answer, not a
   * subscription.
   */
  getDevices(userId: string, timeoutMs = 8000): Promise<{
    version: number;
    devices: Array<{ deviceId: string; credential: Uint8Array }>;
  } | null> {
    if (!this.send(FrameType.GET_DEVICES, new Writer().string(userId).build())) {
      return Promise.resolve(null);
    }

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.deviceWaiters.delete(userId);
        resolve(null);
      }, timeoutMs);

      this.deviceWaiters.set(userId, (result) => {
        clearTimeout(timer);
        this.deviceWaiters.delete(userId);
        resolve(result);
      });
    });
  }

  /**
   * Requests a prekey bundle and resolves with the encoded form the engine
   * parses.
   *
   * The relay's BUNDLE frame is a set of fields; the engine wants the fixed-width
   * encoding, so the fields are reassembled here rather than in the engine.
   */
  getBundle(userId: string, timeoutMs = 8000): Promise<Uint8Array | null> {
    if (!this.send(FrameType.GET_BUNDLE, new Writer().string(userId).build())) {
      return Promise.resolve(null);
    }

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.bundleWaiters.delete(userId);
        resolve(null);
      }, timeoutMs);

      this.bundleWaiters.set(userId, (bundle) => {
        clearTimeout(timer);
        this.bundleWaiters.delete(userId);
        resolve(bundle);
      });
    });
  }

  /**
   * Sends a frame to a recipient.
   *
   * `deviceId` addresses one device of a peer. Empty means the whole account,
   * which is what a single-device peer and a group frame both use: a group
   * message is addressed by group id so every member receives it.
   */
  sendMessage(recipient: string, frameBytes: Uint8Array, deviceId = ""): boolean {
    const writer = new Writer().string(recipient).blob(frameBytes);
    // The device id is written only when there is one, so a frame for a
    // single-device peer is byte-identical to what the relay saw before device
    // addressing existed.
    if (deviceId) writer.string(deviceId);

    return this.send(FrameType.SEND, writer.build());
  }

  acknowledge(outboxId: bigint): boolean {
    return this.send(FrameType.ACK, new Writer().u64(outboxId).build());
  }

  // ---- Password vault ---------------------------------------------------
  //
  // The only requests a client may make before authenticating, because restoring
  // an identity is exactly the case where it has nothing to authenticate with
  // yet. The relay stores a blob it cannot open.

  /** Uploads a sealed vault. Resolves with the generation the relay assigned. */
  putVault(
    userId: string,
    salt: Uint8Array,
    params: { memoryKiB: number; passes: number; lanes: number },
    ciphertext: Uint8Array,
    timeoutMs = 20_000,
  ): Promise<number | null> {
    const payload = new Writer()
      .string(userId)
      .blob(salt)
      .u32(params.memoryKiB)
      .u32(params.passes)
      .u32(params.lanes)
      .blob(ciphertext)
      .build();

    if (!this.send(FrameType.PUT_VAULT, payload)) return Promise.resolve(null);

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.vaultPutWaiters.delete(userId);
        resolve(null);
      }, timeoutMs);

      this.vaultPutWaiters.set(userId, (generation) => {
        clearTimeout(timer);
        this.vaultPutWaiters.delete(userId);
        resolve(generation);
      });
    });
  }

  /** Fetches a sealed vault, or null when the user has none. */
  getVault(userId: string, timeoutMs = 20_000): Promise<VaultReply | null> {
    if (!this.send(FrameType.GET_VAULT, new Writer().string(userId).build())) {
      return Promise.resolve(null);
    }

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.vaultGetWaiters.delete(userId);
        resolve(null);
      }, timeoutMs);

      this.vaultGetWaiters.set(userId, (reply) => {
        clearTimeout(timer);
        this.vaultGetWaiters.delete(userId);
        resolve(reply);
      });
    });
  }

  private send(type: number, payload: Uint8Array): boolean {
    if (!this.connected || this.closed) return false;
    return this.write(type, payload);
  }

  private write(type: number, payload: Uint8Array): boolean {
    const socket = this.socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) return false;
    if (payload.length > MAX_PAYLOAD) return false;
    socket.send(frame(type, payload));
    return true;
  }

  close(): void {
    this.closed = true;
    this.socket?.close(1000, "bye");
    this.socket = null;
    this.connected = false;
  }
}

/**
 * Builds the fixed-width bundle the engine parses, from the relay's fields.
 *
 *   [64] identity | [4] signed id | [32] signed pub | [64] signature
 *   [1]  has one-time | [4] one-time id | [32] one-time pub
 *
 * Both other clients do exactly this; the duplication is the price of the
 * relay carrying the fields separately instead of the blob.
 */
export function buildBundle(event: Extract<RelayEvent, { kind: "bundle" }>): Uint8Array | null {
  return encodeBundle(
    event.identity, event.signedId, event.signedPub, event.signature,
    event.oneTimeId, event.oneTimePub,
  );
}

/**
 * The engine's fixed-width bundle encoding, from the fields the relay sends.
 *
 * Kept as a free function so both the event path and the promise path produce
 * the same bytes: two encoders for one format is how a format drifts.
 */
function encodeBundle(
  identity: Uint8Array,
  signedId: number,
  signedPub: Uint8Array,
  signature: Uint8Array,
  oneTimeId: number,
  oneTimePub: Uint8Array,
): Uint8Array | null {
  if (identity.length !== 64) return null;
  if (signedPub.length !== 32) return null;
  if (signature.length !== 64) return null;

  const hasOneTime = oneTimeId !== 0 && oneTimePub.length === 32;

  const w = new Writer()
    .raw(identity)
    .u32(signedId)
    .raw(signedPub)
    .raw(signature)
    .raw(new Uint8Array([hasOneTime ? 1 : 0]));

  if (hasOneTime) {
    w.u32(oneTimeId).raw(oneTimePub);
  }
  return w.build();
}

/**
 * The account a credential names.
 *
 * A credential starts with a two-byte user id length and the id, so this reads
 * exactly that and nothing else: the relay's frame does not repeat the user id,
 * and trusting a guess would be worse than parsing four bytes.
 */
function credentialOwner(credential: Uint8Array): string {
  if (credential.length < 2) return "";

  const len = (credential[0]! << 8) | credential[1]!;
  if (len === 0 || credential.length < 2 + len) return "";

  return new TextDecoder().decode(credential.slice(2, 2 + len));
}