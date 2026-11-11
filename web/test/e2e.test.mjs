/**
 * The web client against a real relay process.
 *
 * This is the test that closes the loop: the web client's own `ChatApp`, driving
 * the real WebAssembly engine, over the real wire format, against the real Go
 * relay. Everything between the UI and the socket is exercised; only the DOM and
 * the storage engine are stubbed, because neither is where the cryptography
 * lives.
 *
 * Skipped when the relay binary has not been built, the same way the other
 * interop suites skip.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { createServer } from "node:net";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const here = dirname(fileURLToPath(import.meta.url));
const web = join(here, "..");
const repo = join(web, "..");
const wasmDir = join(web, "public", "wasm");

/**
 * `ChatApp` needs a browser environment: IndexedDB, localStorage, crypto, WebSocket.
 *
 * Node has crypto, WebSocket and fetch; it does not have IndexedDB or
 * localStorage. Rather than pull in a shim, this installs the smallest thing
 * that satisfies what `Vault` and the UI layer actually call 鈥?a Map-backed
 * store with the same shape. That keeps the test honest about *what* it is
 * substituting: storage, not cryptography or transport.
 */
/**
 * The storage every Vault instance shares in this process.
 *
 * A real deployment has one store per browser profile, so two clients are two
 * profiles. Tests that need a second *identity* therefore need a second store,
 * and [resetStorage] is how they get one 鈥?without it, both ChatApps would load
 * the same identity and the "second identity is refused" test would be
 * exercising nothing at all.
 */
const storage = new Map();

function installBrowserShims() {
  globalThis.crypto ??= webcrypto;

  const memory = storage;

  // A store bound to the real memory map. Every operation resolves its
  // onsuccess asynchronously, the way the real API does 鈥?a synchronous
  // success would let the test pass against a shape the browser never has.
  const makeStore = () => ({
    get(key) {
      const req = { result: memory.get(key), onsuccess: null, onerror: null };
      queueMicrotask(() => req.onsuccess?.({ target: req }));
      return req;
    },
    put(value, key) {
      memory.set(key, value);
      const req = { onsuccess: null, onerror: null };
      queueMicrotask(() => req.onsuccess?.({ target: req }));
      return req;
    },
    delete(key) {
      memory.delete(key);
      const req = { onsuccess: null, onerror: null };
      queueMicrotask(() => req.onsuccess?.({ target: req }));
      return req;
    },
  });

  globalThis.indexedDB = {
    open() {
      const request = {
        result: null, error: null,
        onsuccess: null, onerror: null, onupgradeneeded: null, onblocked: null,
      };

      queueMicrotask(() => {
        const db = {
          objectStoreNames: { contains: () => true },
          createObjectStore: () => makeStore(),
          transaction() {
            // The store has to be captured here, not created per lookup:
            // `tx.objectStore("x").put(v, k)` is one call on one object, and a
            // shim that returns a fresh store each time silently drops the
            // write.
            const store = makeStore();
            const tx = {
              oncomplete: null, onerror: null, error: null,
              objectStore: () => store,
            };
            queueMicrotask(() => tx.oncomplete?.());
            return tx;
          },
          close() {},
        };

        request.result = db;
        request.onupgradeneeded?.({ target: request });
        request.onsuccess?.({ target: request });
      });

      return request;
    },
    deleteDatabase() {
      const request = { onsuccess: null, onerror: null, onblocked: null };
      memory.clear();
      queueMicrotask(() => request.onsuccess?.({}));
      return request;
    },
  };

  const localStore = new Map();
  globalThis.localStorage = {
    getItem: (k) => localStore.get(k) ?? null,
    setItem: (k, v) => localStore.set(k, String(v)),
    removeItem: (k) => localStore.delete(k),
    clear: () => localStore.clear(),
  };
}

/** Gives the next ChatApp its own storage, the way a second browser has. */
function resetStorage() {
  storage.clear();
}

installBrowserShims();

// ---- Relay process -----------------------------------------------------

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

/**
 * True when something is listening on the port.
 *
 * The trick is that binding it succeeds when it is *free*: if we can listen,
 * nobody else is there, so the answer is false. A refused connection means
 * there is a listener, which is what the caller wants to know.
 */
function isListening(port) {
  return new Promise((resolve) => {
    const probe = createServer();
    probe.once("error", () => resolve(true));
    probe.listen(port, "127.0.0.1", () => probe.close(() => resolve(false)));
  });
}

async function startRelay() {
  const name = process.platform === "win32" ? "veil-relay.exe" : "veil-relay";
  const exe = join(repo, "build", "relay", name);
  if (!existsSync(exe)) return null;

  const port = await freePort();
  const dbDir = mkdtempSync(join(tmpdir(), "veil-web-"));
  const proc = spawn(exe, [
    "-addr", `127.0.0.1:${port}`,
    "-db", join(dbDir, "relay.db"),
  ], { stdio: "ignore" });

  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) break;
    if (await isListening(port)) return { proc, port };
    await new Promise((r) => setTimeout(r, 50));
  }
  proc.kill();
  throw new Error("the relay did not start");
}

// ---- Helpers -----------------------------------------------------------

async function loadChatApp() {
  // The compiled JS is what the page runs; importing it means the test covers
  // the same module graph the browser loads.
  const mod = await import(pathToFileURL(join(web, "dist", "app.js")).href);
  return new mod.ChatApp();
}

/**
 * Points the app at the local module files.
 *
 * The page loads `wasm/veil.wasm` relative to the document and the glue as a
 * relative module specifier. A test runner has neither, so it hands over file://
 * URLs and the wasm bytes directly 鈥?Node cannot fetch a file:// URL, and a
 * Windows path is not a valid ESM specifier.
 */
async function initApp(app) {
  const wasmBinary = await readFile(join(wasmDir, "veil.wasm"));
  await app.init(join(wasmDir, "veil.wasm"), {
    jsUrl: pathToFileURL(join(wasmDir, "veil.js")).href,
    wasmBinary: wasmBinary.buffer.slice(
      wasmBinary.byteOffset,
      wasmBinary.byteOffset + wasmBinary.byteLength,
    ),
  });
}

function waitFor(predicate, timeoutMs, label) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    const tick = () => {
      if (predicate()) return resolve();
      if (Date.now() > deadline) return reject(new Error(`timed out waiting for ${label}`));
      setTimeout(tick, 25);
    };
    tick();
  });
}

const settle = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- Tests -------------------------------------------------------------

test("the app starts with a fresh identity", async () => {
  resetStorage();
  const app = await loadChatApp();
  await initApp(app);

  assert.equal(app.link, "offline");
  assert.deepEqual([...app.peerList], []);
});

test("two web clients exchange a message through the relay", async (t) => {
  resetStorage();
  const relay = await startRelay();
  if (!relay) {
    t.skip("relay binary not built at build/relay/");
    return;
  }

  const url = `ws://127.0.0.1:${relay.port}/ws`;

  try {
    const alice = await loadChatApp();
    const bob = await loadChatApp();

    await initApp(alice);
    await initApp(bob);

    await alice.connect(url, "alice");
    await bob.connect(url, "bob");

    await waitFor(() => alice.link === "online", 10_000, "alice to come online");
    await waitFor(() => bob.link === "online", 10_000, "bob to come online");

    // Both publish prekeys on connect; the relay processes that on its reader
    // goroutine, so a bundle request needs a moment rather than a race.
    await settle(400);

    alice.addPeer("bob");
    await waitFor(
      () => alice.peerList.find((p) => p.userId === "bob")?.state === 2,
      10_000,
      "alice to establish a session with bob",
    );

    const peer = alice.peerList.find((p) => p.userId === "bob");
    assert.ok(peer?.safetyNumber, "a safety number must be available");

    alice.send("bob", "hello from the web");

    await waitFor(
      () => bob.messagesFor("alice").length > 0,
      10_000,
      "bob to receive the message",
    );

    const received = bob.messagesFor("alice")[0];
    assert.equal(received?.text, "hello from the web");
    assert.equal(received?.outgoing, false);

    // And Bob's view of the safety number must agree with Alice's, which is
    // the property the whole verification story rests on.
    const bobPeer = bob.peerList.find((p) => p.userId === "alice");
    assert.equal(bobPeer?.safetyNumber, peer?.safetyNumber);

    alice.disconnect();
    bob.disconnect();
  } finally {
    relay.proc.kill();
  }
});

test("a send while offline is marked, queued, and replayed on reconnect", async (t) => {
  resetStorage();
  const relay = await startRelay();
  if (!relay) {
    t.skip("relay binary not built at build/relay/");
    return;
  }

  const url = `ws://127.0.0.1:${relay.port}/ws`;

  try {
    const alice = await loadChatApp();
    const bob = await loadChatApp();

    await initApp(alice);
    await initApp(bob);

    await bob.connect(url, "bob");
    await waitFor(() => bob.link === "online", 10_000, "bob online");

    await alice.connect(url, "alice");
    await waitFor(() => alice.link === "online", 10_000, "alice online");
    await settle(400);

    alice.addPeer("bob");
    await waitFor(
      () => alice.peerList.find((p) => p.userId === "bob")?.state === 2,
      10_000,
      "alice session",
    );

    // Alice drops her own connection, which is the case a frame can actually
    // fail to leave the process. (With Alice online the relay will happily
    // queue the message for an offline Bob, and the send succeeds 鈥?a different
    // path, and the one the relay's own suite covers.)
    alice.disconnect();
    await settle(200);
    assert.equal(alice.link, "offline");

    alice.send("bob", "sent while alice was offline");
    await settle(200);

    const queued = alice.messagesFor("bob").at(-1);
    assert.equal(queued?.state, "failed",
      "a frame that could not leave the device must be marked, not shown as sent");

    // Reconnecting replays the exact bytes. Re-encrypting would advance the
    // sending chain a second time and leave Bob with a hole.
    await alice.connect(url, "alice");
    await waitFor(() => alice.link === "online", 10_000, "alice back online");

    await waitFor(
      () => bob.messagesFor("alice").some((m) => m.text === "sent while alice was offline"),
      10_000,
      "bob to receive the replayed message",
    );

    const delivered = alice.messagesFor("bob").at(-1);
    assert.equal(delivered?.state, "sent", "the replayed message must be marked sent");

    alice.disconnect();
    bob.disconnect();
  } finally {
    relay.proc.kill();
  }
});

test("a second identity for the same id is refused", async (t) => {
  resetStorage();
  const relay = await startRelay();
  if (!relay) {
    t.skip("relay binary not built at build/relay/");
    return;
  }

  const url = `ws://127.0.0.1:${relay.port}/ws`;

  try {
    const first = await loadChatApp();
    await initApp(first);
    await first.connect(url, "carol");
    await waitFor(() => first.link === "online", 10_000, "carol online");

    // A *different* identity claiming the same id. It needs its own storage,
    // or it would simply load the identity that already holds the id and there
    // would be nothing to refuse.
    resetStorage();
    const impostor = await loadChatApp();
    await initApp(impostor);

    await impostor.connect(url, "carol");

    await waitFor(
      () => impostor.status !== null || impostor.link === "offline" || impostor.link === "error",
      10_000,
      "the impostor to be refused",
    );
    assert.notEqual(impostor.link, "online", "a second identity must not be accepted");

    first.disconnect();
    impostor.disconnect();
  } finally {
    relay.proc.kill();
  }
});