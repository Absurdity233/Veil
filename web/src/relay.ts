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

  /** Opens the socket and sends HELLO. Resolves once the socket is open. */
  connect(userId: string, publicIdentity: Uint8Array): Promise<void> {
    this.closed = false;

    return new Promise((resolve, reject) => {
      const socket = new WebSocket(this.url);
      socket.binaryType = "arraybuffer";
      this.socket = socket;

      this.openWaiters.push((ok) => (ok ? resolve() : reject(new Error("connect failed"))));

      socket.onopen = () => {
        const hello = new Writer().string(userId).blob(publicIdentity).build();
        socket.send(frame(FrameType.HELLO, hello));
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
        case FrameType.BUNDLE:
          this.emit({
            kind: "bundle",
            userId: r.string(),
            identity: r.blob(),
            signedId: r.u32(),
            signedPub: r.blob(),
            signature: r.blob(),
            oneTimeId: r.u32(),
            oneTimePub: r.blob(),
          });
          break;
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

  sendMessage(recipient: string, frameBytes: Uint8Array): boolean {
    return this.send(FrameType.SEND, new Writer().string(recipient).blob(frameBytes).build());
  }

  acknowledge(outboxId: bigint): boolean {
    return this.send(FrameType.ACK, new Writer().u64(outboxId).build());
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
  if (event.identity.length !== 64) return null;
  if (event.signedPub.length !== 32) return null;
  if (event.signature.length !== 64) return null;

  const hasOneTime = event.oneTimeId !== 0 && event.oneTimePub.length === 32;

  const w = new Writer()
    .raw(event.identity)
    .u32(event.signedId)
    .raw(event.signedPub)
    .raw(event.signature)
    .raw(new Uint8Array([hasOneTime ? 1 : 0]));

  if (hasOneTime) {
    w.u32(event.oneTimeId).raw(event.oneTimePub);
  }
  return w.build();
}