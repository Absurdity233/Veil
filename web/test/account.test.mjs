// The account vault: password-derived keys, sealing, and the failure modes.
//
// These run against the real wasm, because Argon2id lives there - the browser has
// no implementation, and testing against a stub would test the stub.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import test from "node:test";

// Argon2 at the production cost would make this suite slow; what is being tested
// is the plumbing, and the cost parameters are already covered in C++.
process.env.VEIL_TEST_FAST_KDF = "1";

// Node 20+ has webcrypto on globalThis, which is what the AEAD path uses.
globalThis.crypto ??= (await import("node:crypto")).webcrypto;

const jsUrl = pathToFileURL(
  new URL("../public/wasm/veil.js", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"),
).href;
const bin = await readFile(
  new URL("../public/wasm/veil.wasm", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"),
);

const factory = (await import(jsUrl)).default;
const mod = await factory({
  wasmBinary: bin.buffer.slice(bin.byteOffset, bin.byteOffset + bin.byteLength),
  print: () => {},
  printErr: () => {},
});

const { attachCrypto, argon2id, randomBytes, openAead, sealAead } =
  await import("../dist/crypto.js");
const { checkPassword, describeStrength, openVault, sealVault } =
  await import("../dist/account.js");

attachCrypto(mod);

// The production cost is 64 MiB x 3; this suite uses a smaller one so a
// password-derivation test does not dominate the run.
const FAST = { memoryKiB: 256, passes: 1, lanes: 1 };

test("Argon2id derives a key inside the wasm", async () => {
  const salt = new Uint8Array(16).fill(9);
  const password = new TextEncoder().encode("correct horse battery staple");

  const a = await argon2id(password, salt, FAST);
  const b = await argon2id(password, salt, FAST);

  assert.equal(a.length, 32);
  assert.deepEqual(Array.from(a), Array.from(b), "the same inputs give the same key");
});

test("a different salt gives a different key", async () => {
  const password = new TextEncoder().encode("hunter2hunter2hunter2");
  const saltA = new Uint8Array(16).fill(1);
  const saltB = new Uint8Array(16).fill(2);

  const a = await argon2id(password, saltA, FAST);
  const b = await argon2id(password, saltB, FAST);

  assert.notDeepEqual(Array.from(a), Array.from(b));
});

test("AEAD round-trips, and a wrong key does not open", async () => {
  const key = randomBytes(32);
  const wrong = randomBytes(32);
  const plain = new TextEncoder().encode("the identity secret");

  const sealed = await sealAead(key, plain);
  const opened = await openAead(key, sealed);

  assert.deepEqual(Array.from(opened), Array.from(plain));

  assert.equal(await openAead(wrong, sealed), null, "a wrong key fails");
});

test("tampering with a sealed blob is detected", async () => {
  const key = randomBytes(32);
  const sealed = await sealAead(key, new TextEncoder().encode("x"));

  // Flip a byte in the body, past the nonce.
  const tampered = sealed.slice();
  tampered[tampered.length - 1] ^= 0xFF;

  assert.equal(await openAead(key, tampered), null);
});

test("a vault round-trips, and the contents come back intact", async () => {
  const contents = {
    identity: randomBytes(96),
    preKeyState: randomBytes(200),
    peerRegistry: randomBytes(64),
    groupState: randomBytes(300),
    history: {
      alice: [{ id: 1, peerId: "alice", outgoing: true, text: "hi", timestamp: 1, state: "sent" }],
      "group:team": [{ groupId: "team", senderId: "alice", text: "yo", at: 2, outgoing: true }],
    },
  };

  // Use the account module's derivation, with the fast cost patched in.
  const vault = await sealVault(contents, "a-long-enough-password", FAST);
  const opened = await openVault(
    { ...vault, memoryKiB: FAST.memoryKiB, passes: FAST.passes, lanes: FAST.lanes },
    "a-long-enough-password",
  );

  assert.ok(opened, "the vault opens with the right password");
  assert.deepEqual(Array.from(opened.identity), Array.from(contents.identity));
  assert.deepEqual(Array.from(opened.preKeyState), Array.from(contents.preKeyState));
  assert.deepEqual(Array.from(opened.peerRegistry), Array.from(contents.peerRegistry));
  assert.deepEqual(Array.from(opened.groupState), Array.from(contents.groupState));
  assert.deepEqual(opened.history, contents.history);
});

test("a wrong password does not open the vault", async () => {
  const vault = await sealVault(
    {
      identity: randomBytes(96),
      preKeyState: null,
      peerRegistry: null,
      groupState: null,
      history: {},
    },
    "the-right-password-here",
  );

  const opened = await openVault(
    { ...vault, memoryKiB: FAST.memoryKiB, passes: FAST.passes, lanes: FAST.lanes },
    "the-wrong-password-here",
  );

  // This is the only check available: there is no password hash, and a wrong key
  // simply fails to authenticate the ciphertext.
  assert.equal(opened, null);
});

test("absent fields round-trip as absent rather than empty", async () => {
  // A client with no prekey state and a client with an empty one are different,
  // and the encoding has to keep them apart: the reader treats a zero length as
  // "absent" and would otherwise hand back a zero-byte blob the engine cannot
  // parse.
  const vault = await sealVault(
    {
      identity: randomBytes(96),
      preKeyState: null,
      peerRegistry: null,
      groupState: null,
      history: {},
    },
    "a-long-enough-password",
    FAST,
  );

  const opened = await openVault(
    { ...vault, memoryKiB: FAST.memoryKiB, passes: FAST.passes, lanes: FAST.lanes },
    "a-long-enough-password",
  );

  assert.ok(opened);
  assert.equal(opened.preKeyState, null);
  assert.equal(opened.peerRegistry, null);
  assert.equal(opened.groupState, null);
});

test("a short password is refused with a reason", () => {
  const problem = checkPassword("short");
  assert.ok(problem, "a short password must be refused");
  assert.match(problem, /12/);
});

test("the strength hint catches a long but repetitive password", () => {
  // Length alone is not strength: a pattern is guessable regardless of how many
  // characters it takes to write down.
  assert.match(describeStrength("aaaaaaaaaaaaaaaaaaaa"), /repetitive|weak/);
  assert.match(describeStrength("correct-horse-battery-staple"), /strong|reasonable/);
});