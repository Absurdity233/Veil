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
    assert.equal(view.getInt32(4, true), 3);
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

test("multi-device: an account creates a device", async () => {
  const mod = await loadModule();
  mod._veil_install_web_rng();

  const handle = mod._veil_engine_new();
  try {
    const alice = writeCString(mod, "alice");
    assert.equal(mod._veil_init_device(handle, alice), 0, "the device is created");
    mod._free(alice);

    const id = mod._malloc(32);
    try {
      assert.equal(mod._veil_device_id(handle, id, 32), 32, "a 32-byte device id");
      const bytes = mod.HEAPU8.slice(id, id + 32);
      assert.ok(bytes.some((b) => b !== 0), "the device id is not zeroed");
    } finally {
      mod._free(id);
    }

    // The credential is self-signed: the first device of an account *is* the
    // account, which is why no linking flow is needed to get started.
    const credSize = mod._veil_device_credential(handle, 0, 0);
    assert.ok(credSize > 0, "a credential is produced");

    const cred = mod._malloc(credSize);
    try {
      assert.equal(mod._veil_device_credential(handle, cred, credSize), credSize,
        "the credential fits its own size query");

      // A fingerprint is what a linking flow would show the user.
      const fpSize = mod._veil_device_fingerprint(cred, credSize, 0, 0);
      assert.ok(fpSize > 0, "a fingerprint is available");

      const fp = mod._malloc(fpSize);
      try {
        assert.equal(mod._veil_device_fingerprint(cred, credSize, fp, fpSize), 0,
          "the fingerprint is produced");
        const text = new TextDecoder().decode(mod.HEAPU8.slice(fp, fp + fpSize - 1));
        assert.equal(text.length, 19, "four groups of four plus dashes");
        assert.match(text, /^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$/);
      } finally {
        mod._free(fp);
      }
    } finally {
      mod._free(cred);
    }
  } finally {
    mod._veil_engine_free(handle);
  }
});

test("multi-device: a device the account never endorsed is refused", async () => {
  const mod = await loadModule();
  mod._veil_install_web_rng();

  const phone = mod._veil_engine_new();
  const laptop = mod._veil_engine_new();
  const bob = mod._veil_engine_new();

  try {
    const name = writeCString(mod, "alice");
    assert.equal(mod._veil_init_device(phone, name), 0);
    assert.equal(mod._veil_init_device(laptop, name), 0);
    mod._free(name);

    const bobName = writeCString(mod, "bob");
    assert.equal(mod._veil_init_device(bob, bobName), 0);
    mod._free(bobName);

    // Alice's account public key, which bob would already pin.
    const alicePub = mod._malloc(64);
    mod._veil_identity_public(phone, alicePub, 64);

    // Both credentials, as the relay would serve them. The laptop's is signed
    // by the laptop's *own* engine identity, not by alice's account, so a list
    // containing it must be refused whole.
    const phoneCredSize = mod._veil_device_credential(phone, 0, 0);
    const phoneCred = mod._malloc(phoneCredSize);
    mod._veil_device_credential(phone, phoneCred, phoneCredSize);

    const laptopCredSize = mod._veil_device_credential(laptop, 0, 0);
    const laptopCred = mod._malloc(laptopCredSize);
    mod._veil_device_credential(laptop, laptopCred, laptopCredSize);

    const listSize = 4 + phoneCredSize + laptopCredSize;
    const list = mod._malloc(listSize);
    try {
      new DataView(mod.HEAPU8.buffer, list, listSize).setUint32(0, 2, false);
      mod.HEAPU8.set(mod.HEAPU8.slice(phoneCred, phoneCred + phoneCredSize), list + 4);
      mod.HEAPU8.set(
        mod.HEAPU8.slice(laptopCred, laptopCred + laptopCredSize),
        list + 4 + phoneCredSize,
      );

      const target = writeCString(mod, "alice");
      try {
        const status = mod._veil_adopt_device_list(
          bob, target, 1, list, listSize, alicePub, alicePub + 32,
        );
        // VEIL_BAD_SIGNATURE = 2: the laptop's credential does not verify
        // against alice's account key.
        assert.equal(status, 2, "a device the account never endorsed is refused");
        assert.equal(mod._veil_peer_device_version(bob, target), 0,
          "and nothing was recorded");
      } finally {
        mod._free(target);
      }
    } finally {
      mod._free(list);
      mod._free(phoneCred);
      mod._free(laptopCred);
      mod._free(alicePub);
    }
  } finally {
    mod._veil_engine_free(phone);
    mod._veil_engine_free(laptop);
    mod._veil_engine_free(bob);
  }
});

test("multi-device: a fan-out produces one frame per reachable device", async () => {
  const mod = await loadModule();
  mod._veil_install_web_rng();

  const alice = mod._veil_engine_new();
  const bob = mod._veil_engine_new();

  try {
    const aliceName = writeCString(mod, "alice");
    assert.equal(mod._veil_init_device(alice, aliceName), 0);
    mod._veil_rotate_prekeys(alice, mod._malloc(4096), 4096);
    mod._free(aliceName);

    const bobName = writeCString(mod, "bob");
    assert.equal(mod._veil_init_device(bob, bobName), 0);
    mod._free(bobName);

    // Alice's own list of one, adopted by bob. Her credential is self-signed,
    // which is exactly what a first device produces.
    const alicePub = mod._malloc(64);
    mod._veil_identity_public(alice, alicePub, 64);

    const credSize = mod._veil_device_credential(alice, 0, 0);
    const cred = mod._malloc(credSize);
    mod._veil_device_credential(alice, cred, credSize);

    const listSize = 4 + credSize;
    const list = mod._malloc(listSize);
    new DataView(mod.HEAPU8.buffer, list, listSize).setUint32(0, 1, false);
    mod.HEAPU8.set(mod.HEAPU8.slice(cred, cred + credSize), list + 4);

    const target = writeCString(mod, "alice");
    try {
      assert.equal(
        mod._veil_adopt_device_list(bob, target, 1, list, listSize, alicePub, alicePub + 32),
        0,
        "bob accepts alice's list of one",
      );

      const devicesSize = mod._veil_peer_devices(bob, target, 0, 0);
      assert.equal(devicesSize, 64, "one device is 64 hex characters");

      // No session yet, so the fan-out produces nothing and is not an error.
      const text = new TextEncoder().encode("hello");
      const inPtr = mod._malloc(text.length);
      mod.HEAPU8.set(text, inPtr);
      try {
        const empty = mod._veil_encrypt_to_account(
          bob, target, inPtr, text.length, 0, 0,
        );
        assert.equal(empty, 0, "no session, no frames");
      } finally {
        mod._free(inPtr);
      }
    } finally {
      mod._free(target);
      mod._free(list);
      mod._free(cred);
      mod._free(alicePub);
    }
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