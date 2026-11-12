/**
 * The relay wire protocol, in TypeScript.
 *
 * The third implementation of the same format, and deliberately so: the Go
 * relay, the Kotlin clients and this one all read and write the same bytes, and
 * the fastest way to catch a disagreement is to have three independent
 * encoders. `wire.test.ts` pins the byte layouts against the others.
 */

export const WIRE_VERSION = 1;

export const FrameType = {
  HELLO: 0x01,
  HELLO_OK: 0x02,
  PUBLISH_PREKEYS: 0x03,
  GET_BUNDLE: 0x04,
  BUNDLE: 0x05,
  SEND: 0x06,
  DELIVER: 0x07,
  ACK: 0x08,
  ERROR: 0x09,
  AUTH_CHALLENGE: 0x0a,
  AUTH_RESPONSE: 0x0b,
  MORE_PENDING: 0x0c,
  // Device lists. See docs/multi-device.md.
  PUBLISH_DEVICES: 0x0d,
  GET_DEVICES: 0x0e,
  DEVICES: 0x0f,
  // Password vaults. The only types usable before authenticating: restoring an
  // identity is exactly the case where a client has nothing to sign with yet.
  PUT_VAULT: 0x10,
  GET_VAULT: 0x11,
  VAULT_DATA: 0x12,
  VAULT_ACK: 0x13,
} as const;

export type FrameTypeValue = (typeof FrameType)[keyof typeof FrameType];

export const MAX_PAYLOAD = 1 << 20;

/** Envelope: [1] version | [1] type | [4] length (BE) | payload. */
export function frame(type: number, payload: Uint8Array): Uint8Array {
  if (payload.length > MAX_PAYLOAD) throw new Error("payload too large");

  const out = new Uint8Array(6 + payload.length);
  out[0] = WIRE_VERSION;
  out[1] = type;
  // DataView writes big-endian by default when littleEndian is omitted.
  new DataView(out.buffer).setUint32(2, payload.length, false);
  out.set(payload, 6);
  return out;
}

export interface ParsedFrame {
  type: number;
  payload: Uint8Array;
}

export function parseFrame(bytes: Uint8Array): ParsedFrame {
  if (bytes.length < 6) throw new Error("short frame");

  // `bytes[0]` is `number | undefined` under noUncheckedIndexedAccess, which is
  // the setting that keeps every other index honest. This is a bounds-checked
  // read, so the assertion is the local answer rather than loosening the rule
  // for the whole file.
  const version = bytes[0]!;
  if (version !== WIRE_VERSION) {
    throw new Error(`unsupported protocol version ${version}`);
  }

  const len = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    .getUint32(2, false);

  if (6 + len !== bytes.length) throw new Error("bad frame length");
  return { type: bytes[1]!, payload: bytes.subarray(6) };
}

/** Appends length-prefixed fields, big endian. */
export class Writer {
  private parts: Uint8Array[] = [];
  private length = 0;

  u32(v: number): this {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v >>> 0, false);
    return this.raw(b);
  }

  /**
   * Outbox ids are 64-bit.
   *
   * They used to be a 32-bit view of a global rowid, which overflows; the
   * per-recipient counter the relay uses now is 8 bytes on the wire.
   */
  u64(v: bigint | number): this {
    const b = new Uint8Array(8);
    const view = new DataView(b.buffer);
    const value = typeof v === "bigint" ? v : BigInt(v);
    view.setUint32(0, Number((value >> 32n) & 0xffffffffn), false);
    view.setUint32(4, Number(value & 0xffffffffn), false);
    return this.raw(b);
  }

  blob(b: Uint8Array): this {
    this.u32(b.length);
    return this.raw(b);
  }

  string(s: string): this {
    return this.blob(new TextEncoder().encode(s));
  }

  raw(b: Uint8Array): this {
    this.parts.push(b);
    this.length += b.length;
    return this;
  }

  build(): Uint8Array {
    const out = new Uint8Array(this.length);
    let off = 0;
    for (const part of this.parts) {
      out.set(part, off);
      off += part.length;
    }
    return out;
  }
}

/** Reads length-prefixed fields, throwing on any truncation. */
export class Reader {
  private pos = 0;
  private readonly view: DataView;

  constructor(private readonly data: Uint8Array) {
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  }

  get remaining(): number {
    return this.data.length - this.pos;
  }

  u32(): number {
    if (this.remaining < 4) throw new Error("truncated");
    const v = this.view.getUint32(this.pos, false);
    this.pos += 4;
    return v;
  }

  u64(): bigint {
    if (this.remaining < 8) throw new Error("truncated");
    const hi = BigInt(this.view.getUint32(this.pos, false));
    const lo = BigInt(this.view.getUint32(this.pos + 4, false));
    this.pos += 8;
    return (hi << 32n) | lo;
  }

  blob(): Uint8Array {
    const n = this.u32();
    if (n < 0 || n > MAX_PAYLOAD || n > this.remaining) throw new Error("truncated");
    const out = this.data.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  string(): string {
    return new TextDecoder().decode(this.blob());
  }

  raw(n: number): Uint8Array {
    if (n < 0 || n > this.remaining) throw new Error("truncated");
    const out = this.data.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  done(): void {
    if (this.remaining !== 0) throw new Error("trailing bytes");
  }
}