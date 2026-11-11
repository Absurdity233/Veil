/**
 * The wire format, checked against the other two implementations.
 *
 * Three clients and a relay read and write the same bytes. The cheap way to keep
 * them honest is to pin the exact bytes here: if a Kotlin or Go change moves a
 * field, this file disagrees and the build fails, rather than the mismatch
 * showing up as "the relay rejected the prekeys" in production.
 *
 * The vectors below are literal byte strings, not computed from the code under
 * test: a test that derives its expectation from the implementation it is
 * checking proves only that the implementation is self-consistent.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { FrameType, Reader, Writer, frame, parseFrame, WIRE_VERSION } from "../dist/wire.js";

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const bytes = (h) => new Uint8Array(Buffer.from(h, "hex"));

test("the envelope layout is fixed", () => {
  // [1] version | [1] type | [4] length BE | payload
  const framed = frame(FrameType.SEND, bytes("deadbeef"));
  assert.equal(hex(framed), "01" + "06" + "00000004" + "deadbeef");
});

test("an empty payload is legal", () => {
  // MORE_PENDING carries nothing.
  const framed = frame(FrameType.MORE_PENDING, new Uint8Array(0));
  assert.equal(hex(framed), "01" + "0c" + "00000000");
});

test("parsing rejects a mismatched length", () => {
  const framed = frame(FrameType.SEND, bytes("aa"));
  framed[5] = 2;  // claim two bytes where there is one
  assert.throws(() => parseFrame(framed), /bad frame length/);
});

test("parsing rejects a different version", () => {
  const framed = frame(FrameType.SEND, bytes("aa"));
  framed[0] = 2;
  assert.throws(() => parseFrame(framed), /unsupported protocol version/);
});

test("parsing rejects a short frame", () => {
  assert.throws(() => parseFrame(new Uint8Array([WIRE_VERSION, 1])), /short frame/);
});

test("u32 is big endian", () => {
  // The Kotlin Reader.u32() and the Go be32() both read big endian; a little
  // endian encoder here would have passed every round-trip test in this file
  // and failed against the relay. That is exactly the bug this pins.
  const w = new Writer().u32(0x01020304);
  assert.equal(hex(w.build()), "01020304");

  const r = new Reader(w.build());
  assert.equal(r.u32(), 0x01020304);
});

test("u64 is big endian and survives the 32-bit boundary", () => {
  // Outbox ids are 64-bit because the old 32-bit wire value wrapped. The value
  // below is 2^32 + 7, which a u32 encoder would silently truncate to 7.
  const w = new Writer().u64(4_294_967_303n);
  assert.equal(hex(w.build()), "0000000100000007");

  const r = new Reader(w.build());
  assert.equal(r.u64(), 4_294_967_303n);
});

test("length-prefixed fields round-trip", () => {
  const w = new Writer().string("alice").blob(bytes("0102"));
  // "alice" is 5 bytes, prefixed with 0x00000005.
  assert.equal(hex(w.build()), "00000005" + Buffer.from("alice").toString("hex") + "00000002" + "0102");

  const r = new Reader(w.build());
  assert.equal(r.string(), "alice");
  assert.equal(hex(r.blob()), "0102");
  r.done();
});

test("a truncated blob is refused rather than over-read", () => {
  // Claim 16 bytes where there are 2.
  const r = new Reader(bytes("00000010aabb"));
  assert.throws(() => r.blob(), /truncated/);
});

test("trailing bytes are a protocol error", () => {
  const w = new Writer().string("alice").raw(bytes("ff"));
  const r = new Reader(w.build());
  r.string();
  assert.throws(() => r.done(), /trailing bytes/);
});

test("the HELLO payload matches the Kotlin and Go encoding", () => {
  // [len] user id | [len] identity (64 bytes)
  const identity = new Uint8Array(64).fill(0x11);
  const w = new Writer().string("alice").blob(identity);
  const payload = w.build();

  assert.equal(payload.length, 4 + 5 + 4 + 64);
  assert.equal(hex(payload.subarray(0, 9)), "00000005" + Buffer.from("alice").toString("hex"));

  const r = new Reader(payload);
  assert.equal(r.string(), "alice");
  assert.equal(r.blob().length, 64);
  r.done();
});

test("the DELIVER payload carries an 8-byte id", () => {
  // [8] outbox id | [len] sender | [len] body
  const w = new Writer().u64(70000n).string("bob").blob(bytes("cafe"));
  const payload = w.build();

  assert.equal(hex(payload.subarray(0, 8)), "0000000000011170");

  const r = new Reader(payload);
  assert.equal(r.u64(), 70000n);
  assert.equal(r.string(), "bob");
  assert.equal(hex(r.blob()), "cafe");
  r.done();
});

test("the ACK payload is exactly an 8-byte id", () => {
  const payload = new Writer().u64(42n).build();
  assert.equal(hex(payload), "000000000000002a");

  const r = new Reader(payload);
  assert.equal(r.u64(), 42n);
  r.done();
});

test("frame type values match the relay's protocol.go", () => {
  // These are wire constants: renumbering them is a breaking change, and the
  // Go side has the same table with the same numbers.
  assert.equal(FrameType.HELLO, 0x01);
  assert.equal(FrameType.HELLO_OK, 0x02);
  assert.equal(FrameType.PUBLISH_PREKEYS, 0x03);
  assert.equal(FrameType.GET_BUNDLE, 0x04);
  assert.equal(FrameType.BUNDLE, 0x05);
  assert.equal(FrameType.SEND, 0x06);
  assert.equal(FrameType.DELIVER, 0x07);
  assert.equal(FrameType.ACK, 0x08);
  assert.equal(FrameType.ERROR, 0x09);
  assert.equal(FrameType.AUTH_CHALLENGE, 0x0a);
  assert.equal(FrameType.AUTH_RESPONSE, 0x0b);
  assert.equal(FrameType.MORE_PENDING, 0x0c);
});