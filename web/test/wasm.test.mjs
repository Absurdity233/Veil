/**
 * The WebAssembly module, exercised in Node.
 *
 * This is the test that proves the third client is real: it loads the actual
 * .wasm the page loads, installs a real CSPRNG, and runs a full handshake and
 * message exchange between two engines inside one process.
 *
 * Node is not a browser, but everything that matters here is the same: the same
 * module bytes, the same ABI, the same C++. The only thing this does not cover
 * is the DOM, and that is not where the cryptography lives.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const wasmDir = join(here, "..", "public", "wasm");

/**
 * The module needs an entropy source before any key is generated. In Node that
 * is webcrypto, which is the same API the browser exposes.
 *
 * The Emscripten build ships a JS-side hook that reads from `crypto` on the
 * global object, so putting Node's webcrypto there is enough for
 * `veil_web_rng_ready` to succeed — which is itself part of what is being
 * tested.
 */
globalThis.crypto ??= webcrypto;

async function loadModule() {
  const factoryPath = join(wasmDir, "veil.js");
  // Windows paths are not valid ESM specifiers: node needs a file:// URL.
  const factory = (await import(pathToFileURL(factoryPath).href)).default;

  // In a browser the module fetches veil.wasm over HTTP, which is correct
  // there. Node cannot fetch a file:// URL, so the bytes are read here and
  // handed in directly — the module and its instantiation are otherwise
  // identical to what the page gets.
  const wasmBinary = await readFile(join(wasmDir, "veil.wasm"));

  return factory({
    wasmBinary,
    locateFile: (path) => path.endsWith(".wasm") ? join(wasmDir, "veil.wasm") : path,
    print: () => {},
    printErr: () => {},
  });
}

test("the module loads and has secure entropy", async () => {
  const mod = await loadModule();
  assert.equal(mod._veil_web_rng_ready(), 1, "crypto.getRandomValues must be reachable");
  mod._veil_install_web_rng();
});

test("the ABI version is reported", async () => {
  const mod = await loadModule();
  const ptr = mod._malloc(12);
  try {
    mod._veil_version(ptr, ptr + 4, ptr + 8);
    const view = new DataView(mod.HEAPU8.buffer, ptr, 12);
    assert.equal(view.getInt32(0, true), 0);
    assert.equal(view.getInt32(4, true), 2);
    assert.equal(view.getInt32(8, true), 0);
  } finally {
    mod._free(ptr);
  }
});

test("an engine creates an identity", async () => {
  const mod = await loadModule();
  mod._veil_install_web_rng();

  const handle = mod._veil_engine_new();
  assert.notEqual(handle, 0, "engine creation must succeed with entropy installed");

  try {
    const out = mod._malloc(64);
    try {
      const n = mod._veil_identity_public(handle, out, 64);
      assert.equal(n, 64);
      // A real X25519 + Ed25519 public key is not all zeros.
      const bytes = mod.HEAPU8.slice(out, out + 64);
      assert.ok(bytes.some((b) => b !== 0), "the identity must not be zeroed");
    } finally {
      mod._free(out);
    }
  } finally {
    mod._veil_engine_free(handle);
  }
});

test("two engines complete a handshake and exchange a message", async () => {
  const mod = await loadModule();
  mod._veil_install_web_rng();

  const alice = mod._veil_engine_new();
  const bob = mod._veil_engine_new();
  assert.notEqual(alice, 0);
  assert.notEqual(bob, 0);

  try {
    // Bob publishes prekeys.
    const setPtr = mod._malloc(4096);
    const setLen = mod._veil_rotate_prekeys(bob, setPtr, 4096);
    assert.ok(setLen > 0, "prekey rotation must produce a set");

    // [4] signed id | [32] pub | [64] sig | [4] count | entries
    const set = mod.HEAPU8.slice(setPtr, setPtr + setLen);
    const signedId = new DataView(set.buffer, set.byteOffset).getUint32(0, false);
    assert.equal(signedId, 1, "the first signed prekey id is 1");

    const countOff = 4 + 32 + 64;
    const count = new DataView(set.buffer, set.byteOffset).getUint32(countOff, false);
    assert.equal(count, 20, "a full batch is published");

    // Build the bundle the relay would hand out.
    const identityPtr = mod._malloc(64);
    mod._veil_identity_public(bob, identityPtr, 64);
    const identity = mod.HEAPU8.slice(identityPtr, identityPtr + 64);
    mod._free(identityPtr);

    const bundle = new Uint8Array([
      ...identity,
      ...set.subarray(0, countOff),          // id | pub | sig
      1,                                     // has one-time
      ...set.subarray(countOff + 4, countOff + 4 + 36),
    ]);

    const bundlePtr = mod._malloc(bundle.length);
    const peerPtr = writeCString(mod, "bob");
    try {
      mod.HEAPU8.set(bundle, bundlePtr);
      const status = mod._veil_establish_outbound(alice, peerPtr, bundlePtr, bundle.length);
      assert.equal(status, 0, "the session must establish");
    } finally {
      mod._free(bundlePtr);
      mod._free(peerPtr);
    }

    // Encrypt.
    const text = new TextEncoder().encode("the veil parts");
    const plainPtr = mod._malloc(text.length);
    const framePtr = mod._malloc(text.length + 512);
    let frameLen;
    const alicePeer = writeCString(mod, "bob");
    try {
      mod.HEAPU8.set(text, plainPtr);
      frameLen = mod._veil_encrypt(alice, alicePeer, plainPtr, text.length,
                                   framePtr, text.length + 512);
      assert.ok(frameLen > 0, "encryption must produce a frame");
    } finally {
      mod._free(plainPtr);
      mod._free(framePtr);
      mod._free(alicePeer);
    }

    const frame = mod.HEAPU8.slice(framePtr, framePtr + frameLen);

    // Decrypt on Bob's side.
    const inPtr = mod._malloc(frame.length);
    const outPtr = mod._malloc(frame.length + 64);
    const lenPtr = mod._malloc(4);
    const bobPeer = writeCString(mod, "alice");
    try {
      mod.HEAPU8.set(frame, inPtr);
      const status = mod._veil_decrypt(bob, bobPeer, inPtr, frame.length,
                                       outPtr, frame.length + 64, lenPtr);
      assert.equal(status, 0, "decryption must succeed");

      const n = new DataView(mod.HEAPU8.buffer, lenPtr, 4).getUint32(0, true);
      const plain = new TextDecoder().decode(mod.HEAPU8.slice(outPtr, outPtr + n));
      assert.equal(plain, "the veil parts");
    } finally {
      mod._free(inPtr);
      mod._free(outPtr);
      mod._free(lenPtr);
      mod._free(bobPeer);
    }
  } finally {
    mod._veil_engine_free(alice);
    mod._veil_engine_free(bob);
  }
});

test("a replayed frame is reported as a duplicate", async () => {
  const mod = await loadModule();
  mod._veil_install_web_rng();

  const alice = mod._veil_engine_new();
  const bob = mod._veil_engine_new();

  try {
    const setPtr = mod._malloc(4096);
    const setLen = mod._veil_rotate_prekeys(bob, setPtr, 4096);
    const set = mod.HEAPU8.slice(setPtr, setPtr + setLen);
    mod._free(setPtr);

    const identityPtr = mod._malloc(64);
    mod._veil_identity_public(bob, identityPtr, 64);
    const identity = mod.HEAPU8.slice(identityPtr, identityPtr + 64);
    mod._free(identityPtr);

    const countOff = 4 + 32 + 64;
    const bundle = new Uint8Array([
      ...identity,
      ...set.subarray(0, countOff),
      1,
      ...set.subarray(countOff + 4, countOff + 4 + 36),
    ]);

    const bPtr = mod._malloc(bundle.length);
    const bobId = writeCString(mod, "bob");
    mod.HEAPU8.set(bundle, bPtr);
    assert.equal(mod._veil_establish_outbound(alice, bobId, bPtr, bundle.length), 0);
    mod._free(bPtr);
    mod._free(bobId);

    const text = new TextEncoder().encode("once");
    const pPtr = mod._malloc(text.length);
    const fPtr = mod._malloc(1024);
    const aliceId = writeCString(mod, "bob");
    mod.HEAPU8.set(text, pPtr);
    const frameLen = mod._veil_encrypt(alice, aliceId, pPtr, text.length, fPtr, 1024);
    mod._free(pPtr);
    mod._free(aliceId);

    const frame = mod.HEAPU8.slice(fPtr, fPtr + frameLen);
    mod._free(fPtr);

    const inPtr = mod._malloc(frame.length);
    const outPtr = mod._malloc(frame.length + 64);
    const lenPtr = mod._malloc(4);
    const bobPeer = writeCString(mod, "alice");
    mod.HEAPU8.set(frame, inPtr);

    assert.equal(mod._veil_decrypt(bob, bobPeer, inPtr, frame.length,
                                   outPtr, frame.length + 64, lenPtr), 0,
                 "first delivery is accepted");
    assert.equal(mod._veil_decrypt(bob, bobPeer, inPtr, frame.length,
                                   outPtr, frame.length + 64, lenPtr), 6,
                 "the replay is a duplicate (status 6), not a failure");

    mod._free(inPtr);
    mod._free(outPtr);
    mod._free(lenPtr);
    mod._free(bobPeer);
  } finally {
    mod._veil_engine_free(alice);
    mod._veil_engine_free(bob);
  }
});

function writeCString(mod, text) {
  const bytes = new TextEncoder().encode(text);
  const ptr = mod._malloc(bytes.length + 1);
  mod.HEAPU8.set(bytes, ptr);
  mod.HEAPU8[ptr + bytes.length] = 0;
  return ptr;
}