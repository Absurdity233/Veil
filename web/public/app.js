var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/crypto.ts
function attachCrypto(module) {
  wasm = module;
}
function requireWasm() {
  if (!wasm) {
    throw new Error("crypto: the engine is not loaded yet");
  }
  return wasm;
}
function randomBytes(length) {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}
async function argon2id(password, salt, params) {
  const mod = requireWasm();
  const outSize = 32;
  const out = mod._malloc(outSize);
  const passwordPtr = mod._malloc(password.length || 1);
  const saltPtr = mod._malloc(salt.length || 1);
  if (!out || !passwordPtr || !saltPtr) {
    mod._free(out);
    mod._free(passwordPtr);
    mod._free(saltPtr);
    throw new Error("crypto: out of memory");
  }
  try {
    if (password.length) mod.HEAPU8.set(password, passwordPtr);
    if (salt.length) mod.HEAPU8.set(salt, saltPtr);
    const status = mod._veil_argon2id(
      out,
      outSize,
      passwordPtr,
      password.length,
      saltPtr,
      salt.length,
      params.memoryKiB,
      params.passes,
      params.lanes
    );
    if (status !== 0) {
      throw new Error(
        `crypto: argon2id refused its parameters (status ${status})`
      );
    }
    return mod.HEAPU8.slice(out, out + outSize);
  } finally {
    mod._free(out);
    mod._free(passwordPtr);
    mod._free(saltPtr);
  }
}
async function sealAead(key, plain, aad) {
  const cryptoKey = await importAesKey(key, "encrypt");
  const nonce = randomBytes(12);
  const sealed = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      ...aad ? { additionalData: aad } : {}
    },
    cryptoKey,
    plain
  );
  const out = new Uint8Array(12 + sealed.byteLength);
  out.set(nonce, 0);
  out.set(new Uint8Array(sealed), 12);
  return out;
}
async function openAead(key, sealed, aad) {
  if (sealed.length < 12 + 16) return null;
  const nonce = sealed.slice(0, 12);
  const body = sealed.slice(12);
  try {
    const cryptoKey = await importAesKey(key, "decrypt");
    const plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        ...aad ? { additionalData: aad } : {}
      },
      cryptoKey,
      body
    );
    return new Uint8Array(plain);
  } catch {
    return null;
  }
}
async function importAesKey(raw, usage) {
  if (raw.length !== 32) {
    throw new Error("crypto: an AES-256 key must be 32 bytes");
  }
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, [usage]);
}
var wasm;
var init_crypto = __esm({
  "src/crypto.ts"() {
    "use strict";
    wasm = null;
  }
});

// src/engine.ts
var engine_exports = {};
__export(engine_exports, {
  RefreshReason: () => RefreshReason,
  SessionState: () => SessionState,
  Status: () => Status,
  VeilEngine: () => VeilEngine
});
function resolveModuleUrl(specifier) {
  const base = typeof document !== "undefined" && document.baseURI ? document.baseURI : void 0;
  if (base === void 0) return specifier;
  return new URL(specifier, base).href;
}
var Status, RefreshReason, SessionState, utf8, VeilEngine;
var init_engine = __esm({
  "src/engine.ts"() {
    "use strict";
    init_crypto();
    Status = {
      OK: 0,
      BAD_BUNDLE: 1,
      BAD_SIGNATURE: 2,
      IDENTITY_CHANGED: 3,
      NO_SESSION: 4,
      AUTH_FAILED: 5,
      DUPLICATE: 6,
      ERR_NULL_HANDLE: -1,
      ERR_NULL_ARG: -2,
      ERR_BUFFER_TOO_SMALL: -3,
      ERR_OUT_OF_MEMORY: -4,
      ERR_NO_RANDOM: -5,
      ERR_BAD_PARAM: -6,
      ERR_INTERNAL: -7
    };
    RefreshReason = /* @__PURE__ */ ((RefreshReason2) => {
      RefreshReason2[RefreshReason2["None"] = 0] = "None";
      RefreshReason2[RefreshReason2["Stale"] = 1] = "Stale";
      RefreshReason2[RefreshReason2["SendFailed"] = 2] = "SendFailed";
      RefreshReason2[RefreshReason2["Unknown"] = 3] = "Unknown";
      return RefreshReason2;
    })(RefreshReason || {});
    SessionState = /* @__PURE__ */ ((SessionState2) => {
      SessionState2[SessionState2["NoPeer"] = 0] = "NoPeer";
      SessionState2[SessionState2["PinnedOnly"] = 1] = "PinnedOnly";
      SessionState2[SessionState2["Ready"] = 2] = "Ready";
      return SessionState2;
    })(SessionState || {});
    utf8 = new TextEncoder();
    VeilEngine = class _VeilEngine {
      constructor(handle) {
        this.handle = handle;
      }
      static module = null;
      /**
       * Loads the module.
       *
       * `wasmUrl` is a URL the page can fetch 閳?in the browser it is a relative
       * path that resolves against the document. `jsUrl` is where the Emscripten
       * glue lives, and is separate because the two play different games: the glue
       * is an ES module import (so it must be a real specifier), while the .wasm is
       * fetched as bytes. A test runner needs to point both at file:// URLs; a page
       * leaves both as defaults.
       */
      static async load(wasmUrl, options = {}) {
        if (_VeilEngine.module) return;
        const jsUrl = options.jsUrl ?? wasmUrl.replace(/\.wasm$/, ".js");
        const factory = (await import(
          /* @vite-ignore */
          resolveModuleUrl(jsUrl)
        )).default;
        const mod = await factory({
          // Node cannot fetch a file:// URL, so a runner may hand the bytes in
          // directly. In a browser this is undefined and the module fetches.
          ...options.wasmBinary ? { wasmBinary: options.wasmBinary } : {},
          locateFile: (path) => (
            // Emscripten fetches this itself. A relative path would resolve against
            // whatever it considers the base, which is not necessarily the document;
            // resolving it here makes both halves of the module agree.
            path.endsWith(".wasm") ? resolveModuleUrl(wasmUrl) : path
          ),
          print: () => {
          },
          printErr: () => {
          }
        });
        if (!mod._veil_web_rng_ready()) {
          throw new Error(
            "no secure randomness available: serve this page over https or from localhost"
          );
        }
        mod._veil_install_web_rng();
        _VeilEngine.module = mod;
        attachCrypto(mod);
      }
      /** The ABI version, so a stale .wasm is loud rather than subtle. */
      static version() {
        const mod = _VeilEngine.require();
        const ptr = mod._malloc(12);
        try {
          mod._veil_version(ptr, ptr + 4, ptr + 8);
          const view = new DataView(mod.HEAPU8.buffer, ptr, 12);
          return `${view.getInt32(0, true)}.${view.getInt32(4, true)}.${view.getInt32(8, true)}`;
        } finally {
          mod._free(ptr);
        }
      }
      static create() {
        const handle = _VeilEngine.require()._veil_engine_new();
        if (handle === 0) {
          throw new Error("could not create the engine (no entropy source?)");
        }
        return new _VeilEngine(handle);
      }
      static restore(secrets) {
        const mod = _VeilEngine.require();
        const ptr = mod._malloc(secrets.length);
        try {
          mod.HEAPU8.set(secrets, ptr);
          const handle = mod._veil_engine_restore(ptr, secrets.length);
          if (handle === 0) throw new Error("could not restore the identity");
          return new _VeilEngine(handle);
        } finally {
          mod._free(ptr);
        }
      }
      static require() {
        if (!_VeilEngine.module) throw new Error("call VeilEngine.load() first");
        return _VeilEngine.module;
      }
      // ---- Identity ---------------------------------------------------------
      identitySecrets() {
        return this.produceFixed(96, (mod, out) => mod._veil_identity_secrets(this.handle, out, 96));
      }
      publicIdentity() {
        return this.produceFixed(64, (mod, out) => mod._veil_identity_public(this.handle, out, 64));
      }
      signChallenge(challenge) {
        const mod = _VeilEngine.require();
        const c = mod._malloc(challenge.length);
        const out = mod._malloc(64);
        try {
          mod.HEAPU8.set(challenge, c);
          const n = mod._veil_sign_challenge(this.handle, c, challenge.length, out, 64);
          if (n < 0) throw new Error(`sign challenge failed (${n})`);
          return mod.HEAPU8.slice(out, out + n);
        } finally {
          mod._free(c);
          mod._free(out);
        }
      }
      // ---- Prekeys ----------------------------------------------------------
      rotatePreKeys() {
        return this.produceVariable(4096, (mod, out, size) => mod._veil_rotate_prekeys(this.handle, out, size));
      }
      exportPreKeySet() {
        return this.produceVariable(4096, (mod, out, size) => mod._veil_export_prekey_set(this.handle, out, size));
      }
      needsPreKeyRefill(lowWater) {
        return _VeilEngine.require()._veil_needs_prekey_refill(this.handle, lowWater) === 1;
      }
      exportPreKeyState() {
        return this.produceVariable(8192, (mod, out, size) => mod._veil_export_prekey_state(this.handle, out, size));
      }
      importPreKeyState(state) {
        return this.callWithBlob(state, (mod, ptr, size) => mod._veil_import_prekey_state(this.handle, ptr, size)) === Status.OK;
      }
      // ---- Sessions ---------------------------------------------------------
      establishOutbound(peer, bundle) {
        const mod = _VeilEngine.require();
        const p = this.withPeer(peer, (ptr) => {
          const b = mod._malloc(bundle.length);
          try {
            mod.HEAPU8.set(bundle, b);
            return mod._veil_establish_outbound(this.handle, ptr, b, bundle.length);
          } finally {
            mod._free(b);
          }
        });
        return p;
      }
      sessionState(peer) {
        const mod = _VeilEngine.require();
        const code = this.withPeer(peer, (ptr) => mod._veil_session_state(this.handle, ptr));
        return code === 2 ? 2 /* Ready */ : code === 1 ? 1 /* PinnedOnly */ : 0 /* NoPeer */;
      }
      exportSession(peer) {
        const mod = _VeilEngine.require();
        return this.withPeer(peer, (ptr) => {
          const need = mod._veil_measure_session(this.handle, ptr);
          if (need <= 0) return null;
          const out = mod._malloc(need);
          try {
            const n = mod._veil_export_session(this.handle, ptr, out, need);
            if (n < 0) return null;
            return mod.HEAPU8.slice(out, out + n);
          } finally {
            mod._free(out);
          }
        });
      }
      importSession(peer, blob) {
        const mod = _VeilEngine.require();
        return this.withPeer(peer, (ptr) => {
          const b = mod._malloc(blob.length);
          try {
            mod.HEAPU8.set(blob, b);
            return mod._veil_import_session(this.handle, ptr, b, blob.length) === Status.OK;
          } finally {
            mod._free(b);
          }
        });
      }
      dropSession(peer) {
        const mod = _VeilEngine.require();
        this.withPeer(peer, (ptr) => {
          mod._veil_drop_session(this.handle, ptr);
          return 0;
        });
      }
      exportPeerRegistry() {
        return this.produceVariable(65536, (mod, out, size) => mod._veil_export_peer_registry(this.handle, out, size));
      }
      importPeerRegistry(blob) {
        return this.callWithBlob(blob, (mod, ptr, size) => mod._veil_import_peer_registry(this.handle, ptr, size)) === Status.OK;
      }
      // ---- Messaging --------------------------------------------------------
      encrypt(peer, plain) {
        const mod = _VeilEngine.require();
        return this.withPeer(peer, (ptr) => {
          const capacity = plain.length + 512;
          const p = mod._malloc(plain.length || 1);
          const out = mod._malloc(capacity);
          try {
            if (plain.length) mod.HEAPU8.set(plain, p);
            const n = mod._veil_encrypt(this.handle, ptr, p, plain.length, out, capacity);
            if (n < 0) return null;
            return mod.HEAPU8.slice(out, out + n);
          } finally {
            mod._free(p);
            mod._free(out);
          }
        });
      }
      /**
       * Decrypts a frame.
       *
       * Returns the plaintext with the status. `DUPLICATE` is a normal event on an
       * at-least-once relay and is surfaced as a status rather than as an error,
       * because the caller has to tell it apart from a failed authentication.
       *
       * The buffer is sized from the frame and never probed first: a probe would
       * have to decrypt to know the length, and that consumes the message key.
       */
      decrypt(peer, frame2) {
        const mod = _VeilEngine.require();
        return this.withPeer(peer, (ptr) => {
          const capacity = frame2.length + 64;
          const f = mod._malloc(frame2.length);
          const out = mod._malloc(capacity);
          const len = mod._malloc(4);
          try {
            mod.HEAPU8.set(frame2, f);
            const status = mod._veil_decrypt(
              this.handle,
              ptr,
              f,
              frame2.length,
              out,
              capacity,
              len
            );
            if (status !== Status.OK) return { plain: null, status };
            const n = new DataView(mod.HEAPU8.buffer, len, 4).getUint32(0, true);
            return { plain: mod.HEAPU8.slice(out, out + n), status: Status.OK };
          } finally {
            mod._free(f);
            mod._free(out);
            mod._free(len);
          }
        });
      }
      safetyNumber(peer) {
        const mod = _VeilEngine.require();
        return this.withPeer(peer, (ptr) => {
          const out = mod._malloc(64);
          try {
            if (mod._veil_safety_number(this.handle, ptr, out, 64) !== Status.OK) return null;
            let end = out;
            while (end < out + 64 && mod.HEAPU8[end] !== 0) end++;
            return new TextDecoder().decode(mod.HEAPU8.slice(out, end));
          } finally {
            mod._free(out);
          }
        });
      }
      close() {
        _VeilEngine.require()._veil_engine_free(this.handle);
      }
      // ---- Groups -----------------------------------------------------------
      //
      // Sender Keys. One message, one frame, regardless of group size. See
      // docs/group.md, including what a group gives up to be cheap.
      createGroup(groupId) {
        const mod = _VeilEngine.require();
        return this.withPeer(groupId, (ptr) => mod._veil_create_group(this.handle, ptr) === Status.OK);
      }
      /**
       * Replaces the member list and bumps the epoch.
       *
       * Every live chain is discarded: a removed member holds the old chain key, and
       * re-keying is the only thing that stops them reading what follows.
       */
      setGroupMembers(groupId, members) {
        const mod = _VeilEngine.require();
        const joined = members.join("\0");
        const bytes = new TextEncoder().encode(joined);
        return this.withPeer(groupId, (ptr) => {
          const p = mod._malloc(bytes.length || 1);
          try {
            if (bytes.length) mod.HEAPU8.set(bytes, p);
            return mod._veil_set_group_members(this.handle, ptr, p, bytes.length);
          } finally {
            mod._free(p);
          }
        });
      }
      groupEpoch(groupId) {
        const mod = _VeilEngine.require();
        return this.withPeer(groupId, (ptr) => mod._veil_group_epoch(this.handle, ptr));
      }
      groupMembers(groupId) {
        const mod = _VeilEngine.require();
        return this.withPeer(groupId, (ptr) => {
          const need = mod._veil_group_members(this.handle, ptr, 0, 0);
          if (need <= 0) return [];
          const out = mod._malloc(need);
          try {
            if (mod._veil_group_members(this.handle, ptr, out, need) !== need) return [];
            return new TextDecoder().decode(mod.HEAPU8.slice(out, out + need)).split("\0").filter((s) => s.length > 0);
          } finally {
            mod._free(out);
          }
        });
      }
      isGroupMember(groupId) {
        const mod = _VeilEngine.require();
        return this.withPeer(groupId, (ptr) => mod._veil_is_group_member(this.handle, ptr) === 1);
      }
      /** The signed member list, to hand to members. */
      exportMembership(groupId) {
        return this.withPeer(groupId, (ptr) => this.produceVariable(2048, (mod, out, size) => mod._veil_export_membership(this.handle, ptr, out, size)));
      }
      adoptMembership(data, founderSignPub) {
        const mod = _VeilEngine.require();
        if (founderSignPub.length !== 32) return Status.BAD_SIGNATURE;
        const d = mod._malloc(data.length || 1);
        const key = mod._malloc(32);
        try {
          if (data.length) mod.HEAPU8.set(data, d);
          mod.HEAPU8.set(founderSignPub, key);
          return mod._veil_adopt_membership(this.handle, d, data.length, key);
        } finally {
          mod._free(d);
          mod._free(key);
        }
      }
      /** This device's chain for the current epoch, signed by its device key. */
      exportSenderKey(groupId, epoch = 0) {
        return this.withPeer(groupId, (ptr) => this.produceVariable(512, (mod, out, size) => mod._veil_export_sender_key(this.handle, ptr, epoch, out, size)));
      }
      adoptSenderKey(data, expectedSender, senderSignPub) {
        const mod = _VeilEngine.require();
        if (senderSignPub.length !== 32) return Status.BAD_SIGNATURE;
        const d = mod._malloc(data.length || 1);
        const key = mod._malloc(32);
        try {
          if (data.length) mod.HEAPU8.set(data, d);
          mod.HEAPU8.set(senderSignPub, key);
          return this.withPeer(expectedSender, (ptr) => mod._veil_adopt_sender_key(this.handle, d, data.length, ptr, key));
        } finally {
          mod._free(d);
          mod._free(key);
        }
      }
      /**
       * Encrypts one message for the whole group.
       *
       * The result is the ABI's single record, passed through unchanged: a caller
       * hands it to the relay as an opaque blob.
       */
      encryptToGroup(groupId, plain) {
        const mod = _VeilEngine.require();
        return this.withPeer(groupId, (ptr) => {
          const p = mod._malloc(plain.length || 1);
          try {
            if (plain.length) mod.HEAPU8.set(plain, p);
            const need = mod._veil_encrypt_to_group(this.handle, ptr, p, plain.length, 0, 0);
            if (need <= 0) return null;
            const out = mod._malloc(need);
            try {
              const total = mod._veil_encrypt_to_group(
                this.handle,
                ptr,
                p,
                plain.length,
                out,
                need
              );
              return total === need ? mod.HEAPU8.slice(out, out + total) : null;
            } finally {
              mod._free(out);
            }
          } finally {
            mod._free(p);
          }
        });
      }
      decryptFromGroup(groupId, record) {
        const mod = _VeilEngine.require();
        return this.withPeer(groupId, (ptr) => {
          const d = mod._malloc(record.length || 1);
          const out = mod._malloc(record.length || 1);
          const outLen = mod._malloc(4);
          try {
            if (record.length) mod.HEAPU8.set(record, d);
            const status = mod._veil_decrypt_from_group(
              this.handle,
              ptr,
              d,
              record.length,
              out,
              record.length,
              outLen
            );
            if (status !== Status.OK) return { status, plain: null };
            const n = new DataView(mod.HEAPU8.buffer, outLen, 4).getUint32(0, true);
            return { status, plain: mod.HEAPU8.slice(out, out + n) };
          } finally {
            mod._free(d);
            mod._free(out);
            mod._free(outLen);
          }
        });
      }
      // ---- Multi-device -----------------------------------------------------
      //
      // The same account layer the Kotlin clients call. See docs/multi-device.md.
      /** Claims a user id and creates this device. */
      initDevice(userId2) {
        const mod = _VeilEngine.require();
        return this.withPeer(userId2, (ptr) => mod._veil_init_device(this.handle, ptr) === Status.OK);
      }
      /** 32 bytes, or null when no device is initialised. */
      deviceId() {
        const mod = _VeilEngine.require();
        const out = mod._malloc(32);
        try {
          const n = mod._veil_device_id(this.handle, out, 32);
          return n === 32 ? mod.HEAPU8.slice(out, out + n) : null;
        } finally {
          mod._free(out);
        }
      }
      /** This device's credential, ready to publish. */
      deviceCredential() {
        return this.produceVariable(512, (mod, out, size) => mod._veil_device_credential(this.handle, out, size));
      }
      /**
       * Adopts a credential the existing device signed for this one.
       *
       * The endorsement is verified against the account keys passed in, so a relay
       * cannot hand over a credential that was never issued.
       */
      adoptDeviceCredential(credential, accountDhPub, accountSignPub) {
        const mod = _VeilEngine.require();
        if (accountDhPub.length !== 32 || accountSignPub.length !== 32) return false;
        const c = mod._malloc(credential.length || 1);
        const dh = mod._malloc(32);
        const sign = mod._malloc(32);
        try {
          if (credential.length) mod.HEAPU8.set(credential, c);
          mod.HEAPU8.set(accountDhPub, dh);
          mod.HEAPU8.set(accountSignPub, sign);
          return mod._veil_adopt_device_credential(this.handle, c, credential.length, dh, sign) === Status.OK;
        } finally {
          mod._free(c);
          mod._free(dh);
          mod._free(sign);
        }
      }
      /**
       * Records a peer's device list.
       *
       * A version at or below the one already held is ignored, so a relay cannot
       * roll an account back to a list that still contains a device the user
       * removed. A list in which any entry fails is refused whole.
       */
      adoptDeviceList(userId2, version, entries, accountDhPub, accountSignPub) {
        const mod = _VeilEngine.require();
        if (accountDhPub.length !== 32 || accountSignPub.length !== 32) return Status.BAD_BUNDLE;
        return this.withPeer(userId2, (ptr) => {
          const d = mod._malloc(entries.length || 1);
          const dh = mod._malloc(32);
          const sign = mod._malloc(32);
          try {
            if (entries.length) mod.HEAPU8.set(entries, d);
            mod.HEAPU8.set(accountDhPub, dh);
            mod.HEAPU8.set(accountSignPub, sign);
            return mod._veil_adopt_device_list(
              this.handle,
              ptr,
              version,
              d,
              entries.length,
              dh,
              sign
            );
          } finally {
            mod._free(d);
            mod._free(dh);
            mod._free(sign);
          }
        });
      }
      /** The hex device ids known for a peer. */
      peerDevices(userId2) {
        const mod = _VeilEngine.require();
        return this.withPeer(userId2, (ptr) => {
          const need = mod._veil_peer_devices(this.handle, ptr, 0, 0);
          if (need <= 0) return [];
          const out = mod._malloc(need);
          try {
            if (mod._veil_peer_devices(this.handle, ptr, out, need) !== need) return [];
            const text = new TextDecoder().decode(mod.HEAPU8.slice(out, out + need));
            return text.split("\0").filter((s) => s.length > 0);
          } finally {
            mod._free(out);
          }
        });
      }
      /** The version of the list held for a peer; 0 when none. */
      peerDeviceVersion(userId2) {
        const mod = _VeilEngine.require();
        return this.withPeer(userId2, (ptr) => mod._veil_peer_device_version(this.handle, ptr));
      }
      /**
       * Starts sessions with each device of a peer.
       *
       * Both blobs are already in the ABI's shape by the time they arrive here; the
       * caller builds them because it is the one that knows which bundles it managed
       * to fetch.
       */
      establishWithDevices(userId2, deviceIds, bundles) {
        const mod = _VeilEngine.require();
        return this.withPeer(userId2, (ptr) => {
          const idsPtr = mod._malloc(deviceIds.length || 1);
          const bundlesPtr = mod._malloc(bundles.length || 1);
          const failed = mod._malloc(1024);
          try {
            if (deviceIds.length) mod.HEAPU8.set(deviceIds, idsPtr);
            if (bundles.length) mod.HEAPU8.set(bundles, bundlesPtr);
            return mod._veil_establish_with_devices(
              this.handle,
              ptr,
              idsPtr,
              deviceIds.length,
              bundlesPtr,
              bundles.length,
              failed,
              1024
            );
          } finally {
            mod._free(idsPtr);
            mod._free(bundlesPtr);
            mod._free(failed);
          }
        });
      }
      /**
       * Fills `out` with one frame per device of a peer.
       *
       * The ABI's size query needs a valid plaintext pointer, so this allocates the
       * plaintext first and asks with it, rather than passing NULL. Two calls, no
       * guessing at a bound that would have to be kept in sync with the C side.
       */
      encryptToAccount(userId2, plain) {
        const mod = _VeilEngine.require();
        return this.withPeer(userId2, (ptr) => {
          const p = mod._malloc(plain.length || 1);
          try {
            if (plain.length) mod.HEAPU8.set(plain, p);
            const need = mod._veil_encrypt_to_account(
              this.handle,
              ptr,
              p,
              plain.length,
              0,
              0
            );
            if (need <= 0) return [];
            const out = mod._malloc(need);
            try {
              const total = mod._veil_encrypt_to_account(
                this.handle,
                ptr,
                p,
                plain.length,
                out,
                need
              );
              if (total <= 0) return [];
              const view = new DataView(mod.HEAPU8.buffer, out, total);
              const frames = [];
              let off = 0;
              while (off + 5 <= total) {
                off += 4;
                const idLen = view.getUint8(off);
                off += 1;
                const deviceId = new TextDecoder().decode(
                  mod.HEAPU8.slice(out + off, out + off + idLen)
                );
                off += idLen;
                const frameLen = view.getUint32(off, false);
                off += 4;
                frames.push({ deviceId, frame: mod.HEAPU8.slice(out + off, out + off + frameLen) });
                off += frameLen;
              }
              return frames;
            } finally {
              mod._free(out);
            }
          } finally {
            mod._free(p);
          }
        });
      }
      // ---- Plumbing ---------------------------------------------------------
      produceFixed(size, call) {
        const mod = _VeilEngine.require();
        const out = mod._malloc(size);
        try {
          const n = call(mod, out);
          if (n < 0) throw new Error(`native call failed (${n})`);
          return mod.HEAPU8.slice(out, out + n);
        } finally {
          mod._free(out);
        }
      }
      /**
       * Runs a producing call, growing once if the documented bound was wrong.
       *
       * The bound is generous, but a caller should not crash because an
       * implementation detail changed; a retry with twice the room is cheaper than
       * a page of arithmetic that has to be kept in sync with the C side.
       */
      produceVariable(initial, call) {
        const mod = _VeilEngine.require();
        let size = initial;
        for (let attempt = 0; attempt < 2; attempt++) {
          const out = mod._malloc(size);
          try {
            const n = call(mod, out, size);
            if (n >= 0) return mod.HEAPU8.slice(out, out + n);
            if (n !== Status.ERR_BUFFER_TOO_SMALL) throw new Error(`native call failed (${n})`);
          } finally {
            mod._free(out);
          }
          size *= 2;
        }
        throw new Error("native call kept refusing the buffer size");
      }
      callWithBlob(blob, call) {
        const mod = _VeilEngine.require();
        const p = mod._malloc(blob.length || 1);
        try {
          if (blob.length) mod.HEAPU8.set(blob, p);
          return call(mod, p, blob.length);
        } finally {
          mod._free(p);
        }
      }
      /** Copies a peer id into the heap, runs `body`, and always frees it. */
      withPeer(peer, body) {
        const mod = _VeilEngine.require();
        const bytes = utf8.encode(peer);
        const p = mod._malloc(bytes.length + 1);
        try {
          mod.HEAPU8.set(bytes, p);
          mod.HEAPU8[p + bytes.length] = 0;
          return body(p);
        } finally {
          mod._free(p);
        }
      }
      // ---- Group persistence ------------------------------------------------
      //
      // The blob carries chain keys: every incoming chain decrypts that sender's
      // messages and the outgoing chain can forge them. It belongs in the sealed
      // vault, beside ratchet state.
      //
      // Without it a reload drops every group and a member can no longer read
      // anything sent to a group they are still in, which is indistinguishable from
      // having been removed.
      exportGroupState() {
        return this.produceVariable(65536, (mod, out, size) => mod._veil_export_group_state(this.handle, out, size));
      }
      importGroupState(blob) {
        const mod = _VeilEngine.require();
        return this.callWithBlob(blob, (m, ptr, size) => m._veil_import_group_state(this.handle, ptr, size));
      }
      // ---- Device list freshness --------------------------------------------
      //
      // A device list is a cache the peer controls, and it can be wrong in the one
      // direction that matters: they linked a device this client has not heard of,
      // and frames encrypted to it are simply never received.
      /** Supplies this client's notion of now. Without it, only send failures count. */
      setClock(nowMs) {
        _VeilEngine.require()._veil_set_clock(this.handle, nowMs);
      }
      deviceListNeedsRefresh(userId2, stalenessMs) {
        const mod = _VeilEngine.require();
        return this.withPeer(userId2, (ptr) => mod._veil_device_list_needs_refresh(this.handle, ptr, stalenessMs));
      }
      /** Records that a send could not reach one of the peer's devices. */
      noteSendFailed(userId2) {
        const mod = _VeilEngine.require();
        this.withPeer(userId2, (ptr) => mod._veil_note_send_failed(this.handle, ptr));
      }
      noteDeviceListFetched(userId2) {
        const mod = _VeilEngine.require();
        this.withPeer(userId2, (ptr) => mod._veil_note_device_list_fetched(this.handle, ptr));
      }
      // ---- Invitations ------------------------------------------------------
      /** The invitation payload, to encrypt and send to one invitee. */
      encodeInvite(groupId) {
        return this.withPeer(groupId, (ptr) => this.produceVariable(4096, (mod, out, size) => mod._veil_encode_invite(this.handle, ptr, out, size)));
      }
      looksLikeInvite(data) {
        const mod = _VeilEngine.require();
        const p = mod._malloc(data.length || 1);
        try {
          if (data.length) mod.HEAPU8.set(data, p);
          return mod._veil_looks_like_invite(p, data.length) === 1;
        } finally {
          mod._free(p);
        }
      }
      /**
       * Accepts an invitation against the founder's device signing key.
       *
       * Returns the group id, or null when refused - so a caller cannot read a
       * refusal as "accepted into a group with no name".
       */
      acceptInvite(data, founder, founderSignPub) {
        const mod = _VeilEngine.require();
        if (founderSignPub.length !== 32) return null;
        const d = mod._malloc(data.length || 1);
        const key = mod._malloc(32);
        const out = mod._malloc(128);
        try {
          if (data.length) mod.HEAPU8.set(data, d);
          mod.HEAPU8.set(founderSignPub, key);
          const status = this.withPeer(founder, (ptr) => mod._veil_accept_invite(this.handle, d, data.length, ptr, key, out, 128));
          if (status !== Status.OK) return null;
          const end = mod.HEAPU8.indexOf(0, out);
          return new TextDecoder().decode(
            mod.HEAPU8.slice(out, end < 0 ? out + 128 : end)
          );
        } finally {
          mod._free(d);
          mod._free(key);
          mod._free(out);
        }
      }
      // ---- Device linking ---------------------------------------------------
      /** This device's request, for the existing device to endorse. */
      linkingRequest() {
        return this.produceVariable(1024, (mod, out, size) => mod._veil_linking_request(this.handle, out, size));
      }
      /** The account a request names and its fingerprint, from the same bytes. */
      readLinkingRequest(data) {
        const mod = _VeilEngine.require();
        const p = mod._malloc(data.length || 1);
        const userId2 = mod._malloc(128);
        const fp = mod._malloc(64);
        try {
          if (data.length) mod.HEAPU8.set(data, p);
          const status = mod._veil_read_linking_request(
            p,
            data.length,
            userId2,
            128,
            fp,
            64
          );
          if (status !== Status.OK) return null;
          const readCString = (at, bound) => {
            const end = mod.HEAPU8.indexOf(0, at);
            const stop = end < 0 || end > at + bound ? at + bound : end;
            return new TextDecoder().decode(mod.HEAPU8.slice(at, stop));
          };
          return {
            userId: readCString(userId2, 128),
            fingerprint: readCString(fp, 64)
          };
        } finally {
          mod._free(p);
          mod._free(userId2);
          mod._free(fp);
        }
      }
      /** Signs an endorsement. Null when this engine does not hold the account key. */
      approveLinking(request, issuedAt) {
        const mod = _VeilEngine.require();
        const p = mod._malloc(request.length || 1);
        try {
          if (request.length) mod.HEAPU8.set(request, p);
          return this.produceVariable(512, (m, out, size) => m._veil_approve_linking(this.handle, p, request.length, issuedAt, out, size));
        } finally {
          mod._free(p);
        }
      }
      accountSignPublic() {
        return this.produceVariable(32, (mod, out, size) => mod._veil_account_sign_public(this.handle, out, size));
      }
      /**
       * The device signing key a peer's credential vouches for.
       *
       * This is what an invitation is verified against: the key the peer's credential
       * carries, which is the peer this client verified, not whoever sent the bytes.
       */
      peerDeviceSignPublic(peer) {
        return this.withPeer(peer, (ptr) => this.produceVariable(32, (mod, out, size) => mod._veil_peer_device_sign_pub(this.handle, ptr, out, size)));
      }
      /**
       * A peer's pinned account identity: DH public || signing public, 64 bytes.
       *
       * This is the key the client already verified during the handshake, which is
       * why device lists are verified against it rather than against anything carried
       * in a reply.
       */
      peerIdentity(peer) {
        return this.withPeer(peer, (ptr) => this.produceVariable(64, (mod, out, size) => mod._veil_peer_identity(this.handle, ptr, out, size)));
      }
    };
  }
});

// node_modules/qrcode/lib/can-promise.js
var require_can_promise = __commonJS({
  "node_modules/qrcode/lib/can-promise.js"(exports, module) {
    module.exports = function() {
      return typeof Promise === "function" && Promise.prototype && Promise.prototype.then;
    };
  }
});

// node_modules/qrcode/lib/core/utils.js
var require_utils = __commonJS({
  "node_modules/qrcode/lib/core/utils.js"(exports) {
    var toSJISFunction;
    var CODEWORDS_COUNT = [
      0,
      // Not used
      26,
      44,
      70,
      100,
      134,
      172,
      196,
      242,
      292,
      346,
      404,
      466,
      532,
      581,
      655,
      733,
      815,
      901,
      991,
      1085,
      1156,
      1258,
      1364,
      1474,
      1588,
      1706,
      1828,
      1921,
      2051,
      2185,
      2323,
      2465,
      2611,
      2761,
      2876,
      3034,
      3196,
      3362,
      3532,
      3706
    ];
    exports.getSymbolSize = function getSymbolSize(version) {
      if (!version) throw new Error('"version" cannot be null or undefined');
      if (version < 1 || version > 40) throw new Error('"version" should be in range from 1 to 40');
      return version * 4 + 17;
    };
    exports.getSymbolTotalCodewords = function getSymbolTotalCodewords(version) {
      return CODEWORDS_COUNT[version];
    };
    exports.getBCHDigit = function(data) {
      let digit = 0;
      while (data !== 0) {
        digit++;
        data >>>= 1;
      }
      return digit;
    };
    exports.setToSJISFunction = function setToSJISFunction(f) {
      if (typeof f !== "function") {
        throw new Error('"toSJISFunc" is not a valid function.');
      }
      toSJISFunction = f;
    };
    exports.isKanjiModeEnabled = function() {
      return typeof toSJISFunction !== "undefined";
    };
    exports.toSJIS = function toSJIS(kanji) {
      return toSJISFunction(kanji);
    };
  }
});

// node_modules/qrcode/lib/core/error-correction-level.js
var require_error_correction_level = __commonJS({
  "node_modules/qrcode/lib/core/error-correction-level.js"(exports) {
    exports.L = { bit: 1 };
    exports.M = { bit: 0 };
    exports.Q = { bit: 3 };
    exports.H = { bit: 2 };
    function fromString(string) {
      if (typeof string !== "string") {
        throw new Error("Param is not a string");
      }
      const lcStr = string.toLowerCase();
      switch (lcStr) {
        case "l":
        case "low":
          return exports.L;
        case "m":
        case "medium":
          return exports.M;
        case "q":
        case "quartile":
          return exports.Q;
        case "h":
        case "high":
          return exports.H;
        default:
          throw new Error("Unknown EC Level: " + string);
      }
    }
    exports.isValid = function isValid(level) {
      return level && typeof level.bit !== "undefined" && level.bit >= 0 && level.bit < 4;
    };
    exports.from = function from(value, defaultValue) {
      if (exports.isValid(value)) {
        return value;
      }
      try {
        return fromString(value);
      } catch (e) {
        return defaultValue;
      }
    };
  }
});

// node_modules/qrcode/lib/core/bit-buffer.js
var require_bit_buffer = __commonJS({
  "node_modules/qrcode/lib/core/bit-buffer.js"(exports, module) {
    function BitBuffer() {
      this.buffer = [];
      this.length = 0;
    }
    BitBuffer.prototype = {
      get: function(index) {
        const bufIndex = Math.floor(index / 8);
        return (this.buffer[bufIndex] >>> 7 - index % 8 & 1) === 1;
      },
      put: function(num, length) {
        for (let i = 0; i < length; i++) {
          this.putBit((num >>> length - i - 1 & 1) === 1);
        }
      },
      getLengthInBits: function() {
        return this.length;
      },
      putBit: function(bit) {
        const bufIndex = Math.floor(this.length / 8);
        if (this.buffer.length <= bufIndex) {
          this.buffer.push(0);
        }
        if (bit) {
          this.buffer[bufIndex] |= 128 >>> this.length % 8;
        }
        this.length++;
      }
    };
    module.exports = BitBuffer;
  }
});

// node_modules/qrcode/lib/core/bit-matrix.js
var require_bit_matrix = __commonJS({
  "node_modules/qrcode/lib/core/bit-matrix.js"(exports, module) {
    function BitMatrix(size) {
      if (!size || size < 1) {
        throw new Error("BitMatrix size must be defined and greater than 0");
      }
      this.size = size;
      this.data = new Uint8Array(size * size);
      this.reservedBit = new Uint8Array(size * size);
    }
    BitMatrix.prototype.set = function(row, col, value, reserved) {
      const index = row * this.size + col;
      this.data[index] = value;
      if (reserved) this.reservedBit[index] = true;
    };
    BitMatrix.prototype.get = function(row, col) {
      return this.data[row * this.size + col];
    };
    BitMatrix.prototype.xor = function(row, col, value) {
      this.data[row * this.size + col] ^= value;
    };
    BitMatrix.prototype.isReserved = function(row, col) {
      return this.reservedBit[row * this.size + col];
    };
    module.exports = BitMatrix;
  }
});

// node_modules/qrcode/lib/core/alignment-pattern.js
var require_alignment_pattern = __commonJS({
  "node_modules/qrcode/lib/core/alignment-pattern.js"(exports) {
    var getSymbolSize = require_utils().getSymbolSize;
    exports.getRowColCoords = function getRowColCoords(version) {
      if (version === 1) return [];
      const posCount = Math.floor(version / 7) + 2;
      const size = getSymbolSize(version);
      const intervals = size === 145 ? 26 : Math.ceil((size - 13) / (2 * posCount - 2)) * 2;
      const positions = [size - 7];
      for (let i = 1; i < posCount - 1; i++) {
        positions[i] = positions[i - 1] - intervals;
      }
      positions.push(6);
      return positions.reverse();
    };
    exports.getPositions = function getPositions(version) {
      const coords = [];
      const pos = exports.getRowColCoords(version);
      const posLength = pos.length;
      for (let i = 0; i < posLength; i++) {
        for (let j = 0; j < posLength; j++) {
          if (i === 0 && j === 0 || // top-left
          i === 0 && j === posLength - 1 || // bottom-left
          i === posLength - 1 && j === 0) {
            continue;
          }
          coords.push([pos[i], pos[j]]);
        }
      }
      return coords;
    };
  }
});

// node_modules/qrcode/lib/core/finder-pattern.js
var require_finder_pattern = __commonJS({
  "node_modules/qrcode/lib/core/finder-pattern.js"(exports) {
    var getSymbolSize = require_utils().getSymbolSize;
    var FINDER_PATTERN_SIZE = 7;
    exports.getPositions = function getPositions(version) {
      const size = getSymbolSize(version);
      return [
        // top-left
        [0, 0],
        // top-right
        [size - FINDER_PATTERN_SIZE, 0],
        // bottom-left
        [0, size - FINDER_PATTERN_SIZE]
      ];
    };
  }
});

// node_modules/qrcode/lib/core/mask-pattern.js
var require_mask_pattern = __commonJS({
  "node_modules/qrcode/lib/core/mask-pattern.js"(exports) {
    exports.Patterns = {
      PATTERN000: 0,
      PATTERN001: 1,
      PATTERN010: 2,
      PATTERN011: 3,
      PATTERN100: 4,
      PATTERN101: 5,
      PATTERN110: 6,
      PATTERN111: 7
    };
    var PenaltyScores = {
      N1: 3,
      N2: 3,
      N3: 40,
      N4: 10
    };
    exports.isValid = function isValid(mask) {
      return mask != null && mask !== "" && !isNaN(mask) && mask >= 0 && mask <= 7;
    };
    exports.from = function from(value) {
      return exports.isValid(value) ? parseInt(value, 10) : void 0;
    };
    exports.getPenaltyN1 = function getPenaltyN1(data) {
      const size = data.size;
      let points = 0;
      let sameCountCol = 0;
      let sameCountRow = 0;
      let lastCol = null;
      let lastRow = null;
      for (let row = 0; row < size; row++) {
        sameCountCol = sameCountRow = 0;
        lastCol = lastRow = null;
        for (let col = 0; col < size; col++) {
          let module2 = data.get(row, col);
          if (module2 === lastCol) {
            sameCountCol++;
          } else {
            if (sameCountCol >= 5) points += PenaltyScores.N1 + (sameCountCol - 5);
            lastCol = module2;
            sameCountCol = 1;
          }
          module2 = data.get(col, row);
          if (module2 === lastRow) {
            sameCountRow++;
          } else {
            if (sameCountRow >= 5) points += PenaltyScores.N1 + (sameCountRow - 5);
            lastRow = module2;
            sameCountRow = 1;
          }
        }
        if (sameCountCol >= 5) points += PenaltyScores.N1 + (sameCountCol - 5);
        if (sameCountRow >= 5) points += PenaltyScores.N1 + (sameCountRow - 5);
      }
      return points;
    };
    exports.getPenaltyN2 = function getPenaltyN2(data) {
      const size = data.size;
      let points = 0;
      for (let row = 0; row < size - 1; row++) {
        for (let col = 0; col < size - 1; col++) {
          const last = data.get(row, col) + data.get(row, col + 1) + data.get(row + 1, col) + data.get(row + 1, col + 1);
          if (last === 4 || last === 0) points++;
        }
      }
      return points * PenaltyScores.N2;
    };
    exports.getPenaltyN3 = function getPenaltyN3(data) {
      const size = data.size;
      let points = 0;
      let bitsCol = 0;
      let bitsRow = 0;
      for (let row = 0; row < size; row++) {
        bitsCol = bitsRow = 0;
        for (let col = 0; col < size; col++) {
          bitsCol = bitsCol << 1 & 2047 | data.get(row, col);
          if (col >= 10 && (bitsCol === 1488 || bitsCol === 93)) points++;
          bitsRow = bitsRow << 1 & 2047 | data.get(col, row);
          if (col >= 10 && (bitsRow === 1488 || bitsRow === 93)) points++;
        }
      }
      return points * PenaltyScores.N3;
    };
    exports.getPenaltyN4 = function getPenaltyN4(data) {
      let darkCount = 0;
      const modulesCount = data.data.length;
      for (let i = 0; i < modulesCount; i++) darkCount += data.data[i];
      const k = Math.abs(Math.ceil(darkCount * 100 / modulesCount / 5) - 10);
      return k * PenaltyScores.N4;
    };
    function getMaskAt(maskPattern, i, j) {
      switch (maskPattern) {
        case exports.Patterns.PATTERN000:
          return (i + j) % 2 === 0;
        case exports.Patterns.PATTERN001:
          return i % 2 === 0;
        case exports.Patterns.PATTERN010:
          return j % 3 === 0;
        case exports.Patterns.PATTERN011:
          return (i + j) % 3 === 0;
        case exports.Patterns.PATTERN100:
          return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0;
        case exports.Patterns.PATTERN101:
          return i * j % 2 + i * j % 3 === 0;
        case exports.Patterns.PATTERN110:
          return (i * j % 2 + i * j % 3) % 2 === 0;
        case exports.Patterns.PATTERN111:
          return (i * j % 3 + (i + j) % 2) % 2 === 0;
        default:
          throw new Error("bad maskPattern:" + maskPattern);
      }
    }
    exports.applyMask = function applyMask(pattern, data) {
      const size = data.size;
      for (let col = 0; col < size; col++) {
        for (let row = 0; row < size; row++) {
          if (data.isReserved(row, col)) continue;
          data.xor(row, col, getMaskAt(pattern, row, col));
        }
      }
    };
    exports.getBestMask = function getBestMask(data, setupFormatFunc) {
      const numPatterns = Object.keys(exports.Patterns).length;
      let bestPattern = 0;
      let lowerPenalty = Infinity;
      for (let p = 0; p < numPatterns; p++) {
        setupFormatFunc(p);
        exports.applyMask(p, data);
        const penalty = exports.getPenaltyN1(data) + exports.getPenaltyN2(data) + exports.getPenaltyN3(data) + exports.getPenaltyN4(data);
        exports.applyMask(p, data);
        if (penalty < lowerPenalty) {
          lowerPenalty = penalty;
          bestPattern = p;
        }
      }
      return bestPattern;
    };
  }
});

// node_modules/qrcode/lib/core/error-correction-code.js
var require_error_correction_code = __commonJS({
  "node_modules/qrcode/lib/core/error-correction-code.js"(exports) {
    var ECLevel = require_error_correction_level();
    var EC_BLOCKS_TABLE = [
      // L  M  Q  H
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      2,
      2,
      1,
      2,
      2,
      4,
      1,
      2,
      4,
      4,
      2,
      4,
      4,
      4,
      2,
      4,
      6,
      5,
      2,
      4,
      6,
      6,
      2,
      5,
      8,
      8,
      4,
      5,
      8,
      8,
      4,
      5,
      8,
      11,
      4,
      8,
      10,
      11,
      4,
      9,
      12,
      16,
      4,
      9,
      16,
      16,
      6,
      10,
      12,
      18,
      6,
      10,
      17,
      16,
      6,
      11,
      16,
      19,
      6,
      13,
      18,
      21,
      7,
      14,
      21,
      25,
      8,
      16,
      20,
      25,
      8,
      17,
      23,
      25,
      9,
      17,
      23,
      34,
      9,
      18,
      25,
      30,
      10,
      20,
      27,
      32,
      12,
      21,
      29,
      35,
      12,
      23,
      34,
      37,
      12,
      25,
      34,
      40,
      13,
      26,
      35,
      42,
      14,
      28,
      38,
      45,
      15,
      29,
      40,
      48,
      16,
      31,
      43,
      51,
      17,
      33,
      45,
      54,
      18,
      35,
      48,
      57,
      19,
      37,
      51,
      60,
      19,
      38,
      53,
      63,
      20,
      40,
      56,
      66,
      21,
      43,
      59,
      70,
      22,
      45,
      62,
      74,
      24,
      47,
      65,
      77,
      25,
      49,
      68,
      81
    ];
    var EC_CODEWORDS_TABLE = [
      // L  M  Q  H
      7,
      10,
      13,
      17,
      10,
      16,
      22,
      28,
      15,
      26,
      36,
      44,
      20,
      36,
      52,
      64,
      26,
      48,
      72,
      88,
      36,
      64,
      96,
      112,
      40,
      72,
      108,
      130,
      48,
      88,
      132,
      156,
      60,
      110,
      160,
      192,
      72,
      130,
      192,
      224,
      80,
      150,
      224,
      264,
      96,
      176,
      260,
      308,
      104,
      198,
      288,
      352,
      120,
      216,
      320,
      384,
      132,
      240,
      360,
      432,
      144,
      280,
      408,
      480,
      168,
      308,
      448,
      532,
      180,
      338,
      504,
      588,
      196,
      364,
      546,
      650,
      224,
      416,
      600,
      700,
      224,
      442,
      644,
      750,
      252,
      476,
      690,
      816,
      270,
      504,
      750,
      900,
      300,
      560,
      810,
      960,
      312,
      588,
      870,
      1050,
      336,
      644,
      952,
      1110,
      360,
      700,
      1020,
      1200,
      390,
      728,
      1050,
      1260,
      420,
      784,
      1140,
      1350,
      450,
      812,
      1200,
      1440,
      480,
      868,
      1290,
      1530,
      510,
      924,
      1350,
      1620,
      540,
      980,
      1440,
      1710,
      570,
      1036,
      1530,
      1800,
      570,
      1064,
      1590,
      1890,
      600,
      1120,
      1680,
      1980,
      630,
      1204,
      1770,
      2100,
      660,
      1260,
      1860,
      2220,
      720,
      1316,
      1950,
      2310,
      750,
      1372,
      2040,
      2430
    ];
    exports.getBlocksCount = function getBlocksCount(version, errorCorrectionLevel) {
      switch (errorCorrectionLevel) {
        case ECLevel.L:
          return EC_BLOCKS_TABLE[(version - 1) * 4 + 0];
        case ECLevel.M:
          return EC_BLOCKS_TABLE[(version - 1) * 4 + 1];
        case ECLevel.Q:
          return EC_BLOCKS_TABLE[(version - 1) * 4 + 2];
        case ECLevel.H:
          return EC_BLOCKS_TABLE[(version - 1) * 4 + 3];
        default:
          return void 0;
      }
    };
    exports.getTotalCodewordsCount = function getTotalCodewordsCount(version, errorCorrectionLevel) {
      switch (errorCorrectionLevel) {
        case ECLevel.L:
          return EC_CODEWORDS_TABLE[(version - 1) * 4 + 0];
        case ECLevel.M:
          return EC_CODEWORDS_TABLE[(version - 1) * 4 + 1];
        case ECLevel.Q:
          return EC_CODEWORDS_TABLE[(version - 1) * 4 + 2];
        case ECLevel.H:
          return EC_CODEWORDS_TABLE[(version - 1) * 4 + 3];
        default:
          return void 0;
      }
    };
  }
});

// node_modules/qrcode/lib/core/galois-field.js
var require_galois_field = __commonJS({
  "node_modules/qrcode/lib/core/galois-field.js"(exports) {
    var EXP_TABLE = new Uint8Array(512);
    var LOG_TABLE = new Uint8Array(256);
    (function initTables() {
      let x = 1;
      for (let i = 0; i < 255; i++) {
        EXP_TABLE[i] = x;
        LOG_TABLE[x] = i;
        x <<= 1;
        if (x & 256) {
          x ^= 285;
        }
      }
      for (let i = 255; i < 512; i++) {
        EXP_TABLE[i] = EXP_TABLE[i - 255];
      }
    })();
    exports.log = function log(n) {
      if (n < 1) throw new Error("log(" + n + ")");
      return LOG_TABLE[n];
    };
    exports.exp = function exp(n) {
      return EXP_TABLE[n];
    };
    exports.mul = function mul(x, y) {
      if (x === 0 || y === 0) return 0;
      return EXP_TABLE[LOG_TABLE[x] + LOG_TABLE[y]];
    };
  }
});

// node_modules/qrcode/lib/core/polynomial.js
var require_polynomial = __commonJS({
  "node_modules/qrcode/lib/core/polynomial.js"(exports) {
    var GF = require_galois_field();
    exports.mul = function mul(p1, p2) {
      const coeff = new Uint8Array(p1.length + p2.length - 1);
      for (let i = 0; i < p1.length; i++) {
        for (let j = 0; j < p2.length; j++) {
          coeff[i + j] ^= GF.mul(p1[i], p2[j]);
        }
      }
      return coeff;
    };
    exports.mod = function mod(divident, divisor) {
      let result = new Uint8Array(divident);
      while (result.length - divisor.length >= 0) {
        const coeff = result[0];
        for (let i = 0; i < divisor.length; i++) {
          result[i] ^= GF.mul(divisor[i], coeff);
        }
        let offset = 0;
        while (offset < result.length && result[offset] === 0) offset++;
        result = result.slice(offset);
      }
      return result;
    };
    exports.generateECPolynomial = function generateECPolynomial(degree) {
      let poly = new Uint8Array([1]);
      for (let i = 0; i < degree; i++) {
        poly = exports.mul(poly, new Uint8Array([1, GF.exp(i)]));
      }
      return poly;
    };
  }
});

// node_modules/qrcode/lib/core/reed-solomon-encoder.js
var require_reed_solomon_encoder = __commonJS({
  "node_modules/qrcode/lib/core/reed-solomon-encoder.js"(exports, module) {
    var Polynomial = require_polynomial();
    function ReedSolomonEncoder(degree) {
      this.genPoly = void 0;
      this.degree = degree;
      if (this.degree) this.initialize(this.degree);
    }
    ReedSolomonEncoder.prototype.initialize = function initialize(degree) {
      this.degree = degree;
      this.genPoly = Polynomial.generateECPolynomial(this.degree);
    };
    ReedSolomonEncoder.prototype.encode = function encode(data) {
      if (!this.genPoly) {
        throw new Error("Encoder not initialized");
      }
      const paddedData = new Uint8Array(data.length + this.degree);
      paddedData.set(data);
      const remainder = Polynomial.mod(paddedData, this.genPoly);
      const start = this.degree - remainder.length;
      if (start > 0) {
        const buff = new Uint8Array(this.degree);
        buff.set(remainder, start);
        return buff;
      }
      return remainder;
    };
    module.exports = ReedSolomonEncoder;
  }
});

// node_modules/qrcode/lib/core/version-check.js
var require_version_check = __commonJS({
  "node_modules/qrcode/lib/core/version-check.js"(exports) {
    exports.isValid = function isValid(version) {
      return !isNaN(version) && version >= 1 && version <= 40;
    };
  }
});

// node_modules/qrcode/lib/core/regex.js
var require_regex = __commonJS({
  "node_modules/qrcode/lib/core/regex.js"(exports) {
    var numeric = "[0-9]+";
    var alphanumeric = "[A-Z $%*+\\-./:]+";
    var kanji = "(?:[u3000-u303F]|[u3040-u309F]|[u30A0-u30FF]|[uFF00-uFFEF]|[u4E00-u9FAF]|[u2605-u2606]|[u2190-u2195]|u203B|[u2010u2015u2018u2019u2025u2026u201Cu201Du2225u2260]|[u0391-u0451]|[u00A7u00A8u00B1u00B4u00D7u00F7])+";
    kanji = kanji.replace(/u/g, "\\u");
    var byte = "(?:(?![A-Z0-9 $%*+\\-./:]|" + kanji + ")(?:.|[\r\n]))+";
    exports.KANJI = new RegExp(kanji, "g");
    exports.BYTE_KANJI = new RegExp("[^A-Z0-9 $%*+\\-./:]+", "g");
    exports.BYTE = new RegExp(byte, "g");
    exports.NUMERIC = new RegExp(numeric, "g");
    exports.ALPHANUMERIC = new RegExp(alphanumeric, "g");
    var TEST_KANJI = new RegExp("^" + kanji + "$");
    var TEST_NUMERIC = new RegExp("^" + numeric + "$");
    var TEST_ALPHANUMERIC = new RegExp("^[A-Z0-9 $%*+\\-./:]+$");
    exports.testKanji = function testKanji(str) {
      return TEST_KANJI.test(str);
    };
    exports.testNumeric = function testNumeric(str) {
      return TEST_NUMERIC.test(str);
    };
    exports.testAlphanumeric = function testAlphanumeric(str) {
      return TEST_ALPHANUMERIC.test(str);
    };
  }
});

// node_modules/qrcode/lib/core/mode.js
var require_mode = __commonJS({
  "node_modules/qrcode/lib/core/mode.js"(exports) {
    var VersionCheck = require_version_check();
    var Regex = require_regex();
    exports.NUMERIC = {
      id: "Numeric",
      bit: 1 << 0,
      ccBits: [10, 12, 14]
    };
    exports.ALPHANUMERIC = {
      id: "Alphanumeric",
      bit: 1 << 1,
      ccBits: [9, 11, 13]
    };
    exports.BYTE = {
      id: "Byte",
      bit: 1 << 2,
      ccBits: [8, 16, 16]
    };
    exports.KANJI = {
      id: "Kanji",
      bit: 1 << 3,
      ccBits: [8, 10, 12]
    };
    exports.MIXED = {
      bit: -1
    };
    exports.getCharCountIndicator = function getCharCountIndicator(mode, version) {
      if (!mode.ccBits) throw new Error("Invalid mode: " + mode);
      if (!VersionCheck.isValid(version)) {
        throw new Error("Invalid version: " + version);
      }
      if (version >= 1 && version < 10) return mode.ccBits[0];
      else if (version < 27) return mode.ccBits[1];
      return mode.ccBits[2];
    };
    exports.getBestModeForData = function getBestModeForData(dataStr) {
      if (Regex.testNumeric(dataStr)) return exports.NUMERIC;
      else if (Regex.testAlphanumeric(dataStr)) return exports.ALPHANUMERIC;
      else if (Regex.testKanji(dataStr)) return exports.KANJI;
      else return exports.BYTE;
    };
    exports.toString = function toString(mode) {
      if (mode && mode.id) return mode.id;
      throw new Error("Invalid mode");
    };
    exports.isValid = function isValid(mode) {
      return mode && mode.bit && mode.ccBits;
    };
    function fromString(string) {
      if (typeof string !== "string") {
        throw new Error("Param is not a string");
      }
      const lcStr = string.toLowerCase();
      switch (lcStr) {
        case "numeric":
          return exports.NUMERIC;
        case "alphanumeric":
          return exports.ALPHANUMERIC;
        case "kanji":
          return exports.KANJI;
        case "byte":
          return exports.BYTE;
        default:
          throw new Error("Unknown mode: " + string);
      }
    }
    exports.from = function from(value, defaultValue) {
      if (exports.isValid(value)) {
        return value;
      }
      try {
        return fromString(value);
      } catch (e) {
        return defaultValue;
      }
    };
  }
});

// node_modules/qrcode/lib/core/version.js
var require_version = __commonJS({
  "node_modules/qrcode/lib/core/version.js"(exports) {
    var Utils = require_utils();
    var ECCode = require_error_correction_code();
    var ECLevel = require_error_correction_level();
    var Mode = require_mode();
    var VersionCheck = require_version_check();
    var G18 = 1 << 12 | 1 << 11 | 1 << 10 | 1 << 9 | 1 << 8 | 1 << 5 | 1 << 2 | 1 << 0;
    var G18_BCH = Utils.getBCHDigit(G18);
    function getBestVersionForDataLength(mode, length, errorCorrectionLevel) {
      for (let currentVersion = 1; currentVersion <= 40; currentVersion++) {
        if (length <= exports.getCapacity(currentVersion, errorCorrectionLevel, mode)) {
          return currentVersion;
        }
      }
      return void 0;
    }
    function getReservedBitsCount(mode, version) {
      return Mode.getCharCountIndicator(mode, version) + 4;
    }
    function getTotalBitsFromDataArray(segments, version) {
      let totalBits = 0;
      segments.forEach(function(data) {
        const reservedBits = getReservedBitsCount(data.mode, version);
        totalBits += reservedBits + data.getBitsLength();
      });
      return totalBits;
    }
    function getBestVersionForMixedData(segments, errorCorrectionLevel) {
      for (let currentVersion = 1; currentVersion <= 40; currentVersion++) {
        const length = getTotalBitsFromDataArray(segments, currentVersion);
        if (length <= exports.getCapacity(currentVersion, errorCorrectionLevel, Mode.MIXED)) {
          return currentVersion;
        }
      }
      return void 0;
    }
    exports.from = function from(value, defaultValue) {
      if (VersionCheck.isValid(value)) {
        return parseInt(value, 10);
      }
      return defaultValue;
    };
    exports.getCapacity = function getCapacity(version, errorCorrectionLevel, mode) {
      if (!VersionCheck.isValid(version)) {
        throw new Error("Invalid QR Code version");
      }
      if (typeof mode === "undefined") mode = Mode.BYTE;
      const totalCodewords = Utils.getSymbolTotalCodewords(version);
      const ecTotalCodewords = ECCode.getTotalCodewordsCount(version, errorCorrectionLevel);
      const dataTotalCodewordsBits = (totalCodewords - ecTotalCodewords) * 8;
      if (mode === Mode.MIXED) return dataTotalCodewordsBits;
      const usableBits = dataTotalCodewordsBits - getReservedBitsCount(mode, version);
      switch (mode) {
        case Mode.NUMERIC:
          return Math.floor(usableBits / 10 * 3);
        case Mode.ALPHANUMERIC:
          return Math.floor(usableBits / 11 * 2);
        case Mode.KANJI:
          return Math.floor(usableBits / 13);
        case Mode.BYTE:
        default:
          return Math.floor(usableBits / 8);
      }
    };
    exports.getBestVersionForData = function getBestVersionForData(data, errorCorrectionLevel) {
      let seg;
      const ecl = ECLevel.from(errorCorrectionLevel, ECLevel.M);
      if (Array.isArray(data)) {
        if (data.length > 1) {
          return getBestVersionForMixedData(data, ecl);
        }
        if (data.length === 0) {
          return 1;
        }
        seg = data[0];
      } else {
        seg = data;
      }
      return getBestVersionForDataLength(seg.mode, seg.getLength(), ecl);
    };
    exports.getEncodedBits = function getEncodedBits(version) {
      if (!VersionCheck.isValid(version) || version < 7) {
        throw new Error("Invalid QR Code version");
      }
      let d = version << 12;
      while (Utils.getBCHDigit(d) - G18_BCH >= 0) {
        d ^= G18 << Utils.getBCHDigit(d) - G18_BCH;
      }
      return version << 12 | d;
    };
  }
});

// node_modules/qrcode/lib/core/format-info.js
var require_format_info = __commonJS({
  "node_modules/qrcode/lib/core/format-info.js"(exports) {
    var Utils = require_utils();
    var G15 = 1 << 10 | 1 << 8 | 1 << 5 | 1 << 4 | 1 << 2 | 1 << 1 | 1 << 0;
    var G15_MASK = 1 << 14 | 1 << 12 | 1 << 10 | 1 << 4 | 1 << 1;
    var G15_BCH = Utils.getBCHDigit(G15);
    exports.getEncodedBits = function getEncodedBits(errorCorrectionLevel, mask) {
      const data = errorCorrectionLevel.bit << 3 | mask;
      let d = data << 10;
      while (Utils.getBCHDigit(d) - G15_BCH >= 0) {
        d ^= G15 << Utils.getBCHDigit(d) - G15_BCH;
      }
      return (data << 10 | d) ^ G15_MASK;
    };
  }
});

// node_modules/qrcode/lib/core/numeric-data.js
var require_numeric_data = __commonJS({
  "node_modules/qrcode/lib/core/numeric-data.js"(exports, module) {
    var Mode = require_mode();
    function NumericData(data) {
      this.mode = Mode.NUMERIC;
      this.data = data.toString();
    }
    NumericData.getBitsLength = function getBitsLength(length) {
      return 10 * Math.floor(length / 3) + (length % 3 ? length % 3 * 3 + 1 : 0);
    };
    NumericData.prototype.getLength = function getLength() {
      return this.data.length;
    };
    NumericData.prototype.getBitsLength = function getBitsLength() {
      return NumericData.getBitsLength(this.data.length);
    };
    NumericData.prototype.write = function write(bitBuffer) {
      let i, group, value;
      for (i = 0; i + 3 <= this.data.length; i += 3) {
        group = this.data.substr(i, 3);
        value = parseInt(group, 10);
        bitBuffer.put(value, 10);
      }
      const remainingNum = this.data.length - i;
      if (remainingNum > 0) {
        group = this.data.substr(i);
        value = parseInt(group, 10);
        bitBuffer.put(value, remainingNum * 3 + 1);
      }
    };
    module.exports = NumericData;
  }
});

// node_modules/qrcode/lib/core/alphanumeric-data.js
var require_alphanumeric_data = __commonJS({
  "node_modules/qrcode/lib/core/alphanumeric-data.js"(exports, module) {
    var Mode = require_mode();
    var ALPHA_NUM_CHARS = [
      "0",
      "1",
      "2",
      "3",
      "4",
      "5",
      "6",
      "7",
      "8",
      "9",
      "A",
      "B",
      "C",
      "D",
      "E",
      "F",
      "G",
      "H",
      "I",
      "J",
      "K",
      "L",
      "M",
      "N",
      "O",
      "P",
      "Q",
      "R",
      "S",
      "T",
      "U",
      "V",
      "W",
      "X",
      "Y",
      "Z",
      " ",
      "$",
      "%",
      "*",
      "+",
      "-",
      ".",
      "/",
      ":"
    ];
    function AlphanumericData(data) {
      this.mode = Mode.ALPHANUMERIC;
      this.data = data;
    }
    AlphanumericData.getBitsLength = function getBitsLength(length) {
      return 11 * Math.floor(length / 2) + 6 * (length % 2);
    };
    AlphanumericData.prototype.getLength = function getLength() {
      return this.data.length;
    };
    AlphanumericData.prototype.getBitsLength = function getBitsLength() {
      return AlphanumericData.getBitsLength(this.data.length);
    };
    AlphanumericData.prototype.write = function write(bitBuffer) {
      let i;
      for (i = 0; i + 2 <= this.data.length; i += 2) {
        let value = ALPHA_NUM_CHARS.indexOf(this.data[i]) * 45;
        value += ALPHA_NUM_CHARS.indexOf(this.data[i + 1]);
        bitBuffer.put(value, 11);
      }
      if (this.data.length % 2) {
        bitBuffer.put(ALPHA_NUM_CHARS.indexOf(this.data[i]), 6);
      }
    };
    module.exports = AlphanumericData;
  }
});

// node_modules/qrcode/lib/core/byte-data.js
var require_byte_data = __commonJS({
  "node_modules/qrcode/lib/core/byte-data.js"(exports, module) {
    var Mode = require_mode();
    function ByteData(data) {
      this.mode = Mode.BYTE;
      if (typeof data === "string") {
        this.data = new TextEncoder().encode(data);
      } else {
        this.data = new Uint8Array(data);
      }
    }
    ByteData.getBitsLength = function getBitsLength(length) {
      return length * 8;
    };
    ByteData.prototype.getLength = function getLength() {
      return this.data.length;
    };
    ByteData.prototype.getBitsLength = function getBitsLength() {
      return ByteData.getBitsLength(this.data.length);
    };
    ByteData.prototype.write = function(bitBuffer) {
      for (let i = 0, l = this.data.length; i < l; i++) {
        bitBuffer.put(this.data[i], 8);
      }
    };
    module.exports = ByteData;
  }
});

// node_modules/qrcode/lib/core/kanji-data.js
var require_kanji_data = __commonJS({
  "node_modules/qrcode/lib/core/kanji-data.js"(exports, module) {
    var Mode = require_mode();
    var Utils = require_utils();
    function KanjiData(data) {
      this.mode = Mode.KANJI;
      this.data = data;
    }
    KanjiData.getBitsLength = function getBitsLength(length) {
      return length * 13;
    };
    KanjiData.prototype.getLength = function getLength() {
      return this.data.length;
    };
    KanjiData.prototype.getBitsLength = function getBitsLength() {
      return KanjiData.getBitsLength(this.data.length);
    };
    KanjiData.prototype.write = function(bitBuffer) {
      let i;
      for (i = 0; i < this.data.length; i++) {
        let value = Utils.toSJIS(this.data[i]);
        if (value >= 33088 && value <= 40956) {
          value -= 33088;
        } else if (value >= 57408 && value <= 60351) {
          value -= 49472;
        } else {
          throw new Error(
            "Invalid SJIS character: " + this.data[i] + "\nMake sure your charset is UTF-8"
          );
        }
        value = (value >>> 8 & 255) * 192 + (value & 255);
        bitBuffer.put(value, 13);
      }
    };
    module.exports = KanjiData;
  }
});

// node_modules/dijkstrajs/dijkstra.js
var require_dijkstra = __commonJS({
  "node_modules/dijkstrajs/dijkstra.js"(exports, module) {
    "use strict";
    var dijkstra = {
      single_source_shortest_paths: function(graph, s, d) {
        var predecessors = {};
        var costs = {};
        costs[s] = 0;
        var open = dijkstra.PriorityQueue.make();
        open.push(s, 0);
        var closest, u, v, cost_of_s_to_u, adjacent_nodes, cost_of_e, cost_of_s_to_u_plus_cost_of_e, cost_of_s_to_v, first_visit;
        while (!open.empty()) {
          closest = open.pop();
          u = closest.value;
          cost_of_s_to_u = closest.cost;
          adjacent_nodes = graph[u] || {};
          for (v in adjacent_nodes) {
            if (adjacent_nodes.hasOwnProperty(v)) {
              cost_of_e = adjacent_nodes[v];
              cost_of_s_to_u_plus_cost_of_e = cost_of_s_to_u + cost_of_e;
              cost_of_s_to_v = costs[v];
              first_visit = typeof costs[v] === "undefined";
              if (first_visit || cost_of_s_to_v > cost_of_s_to_u_plus_cost_of_e) {
                costs[v] = cost_of_s_to_u_plus_cost_of_e;
                open.push(v, cost_of_s_to_u_plus_cost_of_e);
                predecessors[v] = u;
              }
            }
          }
        }
        if (typeof d !== "undefined" && typeof costs[d] === "undefined") {
          var msg = ["Could not find a path from ", s, " to ", d, "."].join("");
          throw new Error(msg);
        }
        return predecessors;
      },
      extract_shortest_path_from_predecessor_list: function(predecessors, d) {
        var nodes = [];
        var u = d;
        var predecessor;
        while (u) {
          nodes.push(u);
          predecessor = predecessors[u];
          u = predecessors[u];
        }
        nodes.reverse();
        return nodes;
      },
      find_path: function(graph, s, d) {
        var predecessors = dijkstra.single_source_shortest_paths(graph, s, d);
        return dijkstra.extract_shortest_path_from_predecessor_list(
          predecessors,
          d
        );
      },
      /**
       * A very naive priority queue implementation.
       */
      PriorityQueue: {
        make: function(opts) {
          var T = dijkstra.PriorityQueue, t = {}, key;
          opts = opts || {};
          for (key in T) {
            if (T.hasOwnProperty(key)) {
              t[key] = T[key];
            }
          }
          t.queue = [];
          t.sorter = opts.sorter || T.default_sorter;
          return t;
        },
        default_sorter: function(a, b) {
          return a.cost - b.cost;
        },
        /**
         * Add a new item to the queue and ensure the highest priority element
         * is at the front of the queue.
         */
        push: function(value, cost) {
          var item = { value, cost };
          this.queue.push(item);
          this.queue.sort(this.sorter);
        },
        /**
         * Return the highest priority element in the queue.
         */
        pop: function() {
          return this.queue.shift();
        },
        empty: function() {
          return this.queue.length === 0;
        }
      }
    };
    if (typeof module !== "undefined") {
      module.exports = dijkstra;
    }
  }
});

// node_modules/qrcode/lib/core/segments.js
var require_segments = __commonJS({
  "node_modules/qrcode/lib/core/segments.js"(exports) {
    var Mode = require_mode();
    var NumericData = require_numeric_data();
    var AlphanumericData = require_alphanumeric_data();
    var ByteData = require_byte_data();
    var KanjiData = require_kanji_data();
    var Regex = require_regex();
    var Utils = require_utils();
    var dijkstra = require_dijkstra();
    function getStringByteLength(str) {
      return unescape(encodeURIComponent(str)).length;
    }
    function getSegments(regex, mode, str) {
      const segments = [];
      let result;
      while ((result = regex.exec(str)) !== null) {
        segments.push({
          data: result[0],
          index: result.index,
          mode,
          length: result[0].length
        });
      }
      return segments;
    }
    function getSegmentsFromString(dataStr) {
      const numSegs = getSegments(Regex.NUMERIC, Mode.NUMERIC, dataStr);
      const alphaNumSegs = getSegments(Regex.ALPHANUMERIC, Mode.ALPHANUMERIC, dataStr);
      let byteSegs;
      let kanjiSegs;
      if (Utils.isKanjiModeEnabled()) {
        byteSegs = getSegments(Regex.BYTE, Mode.BYTE, dataStr);
        kanjiSegs = getSegments(Regex.KANJI, Mode.KANJI, dataStr);
      } else {
        byteSegs = getSegments(Regex.BYTE_KANJI, Mode.BYTE, dataStr);
        kanjiSegs = [];
      }
      const segs = numSegs.concat(alphaNumSegs, byteSegs, kanjiSegs);
      return segs.sort(function(s1, s2) {
        return s1.index - s2.index;
      }).map(function(obj) {
        return {
          data: obj.data,
          mode: obj.mode,
          length: obj.length
        };
      });
    }
    function getSegmentBitsLength(length, mode) {
      switch (mode) {
        case Mode.NUMERIC:
          return NumericData.getBitsLength(length);
        case Mode.ALPHANUMERIC:
          return AlphanumericData.getBitsLength(length);
        case Mode.KANJI:
          return KanjiData.getBitsLength(length);
        case Mode.BYTE:
          return ByteData.getBitsLength(length);
      }
    }
    function mergeSegments(segs) {
      return segs.reduce(function(acc, curr) {
        const prevSeg = acc.length - 1 >= 0 ? acc[acc.length - 1] : null;
        if (prevSeg && prevSeg.mode === curr.mode) {
          acc[acc.length - 1].data += curr.data;
          return acc;
        }
        acc.push(curr);
        return acc;
      }, []);
    }
    function buildNodes(segs) {
      const nodes = [];
      for (let i = 0; i < segs.length; i++) {
        const seg = segs[i];
        switch (seg.mode) {
          case Mode.NUMERIC:
            nodes.push([
              seg,
              { data: seg.data, mode: Mode.ALPHANUMERIC, length: seg.length },
              { data: seg.data, mode: Mode.BYTE, length: seg.length }
            ]);
            break;
          case Mode.ALPHANUMERIC:
            nodes.push([
              seg,
              { data: seg.data, mode: Mode.BYTE, length: seg.length }
            ]);
            break;
          case Mode.KANJI:
            nodes.push([
              seg,
              { data: seg.data, mode: Mode.BYTE, length: getStringByteLength(seg.data) }
            ]);
            break;
          case Mode.BYTE:
            nodes.push([
              { data: seg.data, mode: Mode.BYTE, length: getStringByteLength(seg.data) }
            ]);
        }
      }
      return nodes;
    }
    function buildGraph(nodes, version) {
      const table = {};
      const graph = { start: {} };
      let prevNodeIds = ["start"];
      for (let i = 0; i < nodes.length; i++) {
        const nodeGroup = nodes[i];
        const currentNodeIds = [];
        for (let j = 0; j < nodeGroup.length; j++) {
          const node = nodeGroup[j];
          const key = "" + i + j;
          currentNodeIds.push(key);
          table[key] = { node, lastCount: 0 };
          graph[key] = {};
          for (let n = 0; n < prevNodeIds.length; n++) {
            const prevNodeId = prevNodeIds[n];
            if (table[prevNodeId] && table[prevNodeId].node.mode === node.mode) {
              graph[prevNodeId][key] = getSegmentBitsLength(table[prevNodeId].lastCount + node.length, node.mode) - getSegmentBitsLength(table[prevNodeId].lastCount, node.mode);
              table[prevNodeId].lastCount += node.length;
            } else {
              if (table[prevNodeId]) table[prevNodeId].lastCount = node.length;
              graph[prevNodeId][key] = getSegmentBitsLength(node.length, node.mode) + 4 + Mode.getCharCountIndicator(node.mode, version);
            }
          }
        }
        prevNodeIds = currentNodeIds;
      }
      for (let n = 0; n < prevNodeIds.length; n++) {
        graph[prevNodeIds[n]].end = 0;
      }
      return { map: graph, table };
    }
    function buildSingleSegment(data, modesHint) {
      let mode;
      const bestMode = Mode.getBestModeForData(data);
      mode = Mode.from(modesHint, bestMode);
      if (mode !== Mode.BYTE && mode.bit < bestMode.bit) {
        throw new Error('"' + data + '" cannot be encoded with mode ' + Mode.toString(mode) + ".\n Suggested mode is: " + Mode.toString(bestMode));
      }
      if (mode === Mode.KANJI && !Utils.isKanjiModeEnabled()) {
        mode = Mode.BYTE;
      }
      switch (mode) {
        case Mode.NUMERIC:
          return new NumericData(data);
        case Mode.ALPHANUMERIC:
          return new AlphanumericData(data);
        case Mode.KANJI:
          return new KanjiData(data);
        case Mode.BYTE:
          return new ByteData(data);
      }
    }
    exports.fromArray = function fromArray(array) {
      return array.reduce(function(acc, seg) {
        if (typeof seg === "string") {
          acc.push(buildSingleSegment(seg, null));
        } else if (seg.data) {
          acc.push(buildSingleSegment(seg.data, seg.mode));
        }
        return acc;
      }, []);
    };
    exports.fromString = function fromString(data, version) {
      const segs = getSegmentsFromString(data, Utils.isKanjiModeEnabled());
      const nodes = buildNodes(segs);
      const graph = buildGraph(nodes, version);
      const path = dijkstra.find_path(graph.map, "start", "end");
      const optimizedSegs = [];
      for (let i = 1; i < path.length - 1; i++) {
        optimizedSegs.push(graph.table[path[i]].node);
      }
      return exports.fromArray(mergeSegments(optimizedSegs));
    };
    exports.rawSplit = function rawSplit(data) {
      return exports.fromArray(
        getSegmentsFromString(data, Utils.isKanjiModeEnabled())
      );
    };
  }
});

// node_modules/qrcode/lib/core/qrcode.js
var require_qrcode = __commonJS({
  "node_modules/qrcode/lib/core/qrcode.js"(exports) {
    var Utils = require_utils();
    var ECLevel = require_error_correction_level();
    var BitBuffer = require_bit_buffer();
    var BitMatrix = require_bit_matrix();
    var AlignmentPattern = require_alignment_pattern();
    var FinderPattern = require_finder_pattern();
    var MaskPattern = require_mask_pattern();
    var ECCode = require_error_correction_code();
    var ReedSolomonEncoder = require_reed_solomon_encoder();
    var Version = require_version();
    var FormatInfo = require_format_info();
    var Mode = require_mode();
    var Segments = require_segments();
    function setupFinderPattern(matrix, version) {
      const size = matrix.size;
      const pos = FinderPattern.getPositions(version);
      for (let i = 0; i < pos.length; i++) {
        const row = pos[i][0];
        const col = pos[i][1];
        for (let r = -1; r <= 7; r++) {
          if (row + r <= -1 || size <= row + r) continue;
          for (let c = -1; c <= 7; c++) {
            if (col + c <= -1 || size <= col + c) continue;
            if (r >= 0 && r <= 6 && (c === 0 || c === 6) || c >= 0 && c <= 6 && (r === 0 || r === 6) || r >= 2 && r <= 4 && c >= 2 && c <= 4) {
              matrix.set(row + r, col + c, true, true);
            } else {
              matrix.set(row + r, col + c, false, true);
            }
          }
        }
      }
    }
    function setupTimingPattern(matrix) {
      const size = matrix.size;
      for (let r = 8; r < size - 8; r++) {
        const value = r % 2 === 0;
        matrix.set(r, 6, value, true);
        matrix.set(6, r, value, true);
      }
    }
    function setupAlignmentPattern(matrix, version) {
      const pos = AlignmentPattern.getPositions(version);
      for (let i = 0; i < pos.length; i++) {
        const row = pos[i][0];
        const col = pos[i][1];
        for (let r = -2; r <= 2; r++) {
          for (let c = -2; c <= 2; c++) {
            if (r === -2 || r === 2 || c === -2 || c === 2 || r === 0 && c === 0) {
              matrix.set(row + r, col + c, true, true);
            } else {
              matrix.set(row + r, col + c, false, true);
            }
          }
        }
      }
    }
    function setupVersionInfo(matrix, version) {
      const size = matrix.size;
      const bits = Version.getEncodedBits(version);
      let row, col, mod;
      for (let i = 0; i < 18; i++) {
        row = Math.floor(i / 3);
        col = i % 3 + size - 8 - 3;
        mod = (bits >> i & 1) === 1;
        matrix.set(row, col, mod, true);
        matrix.set(col, row, mod, true);
      }
    }
    function setupFormatInfo(matrix, errorCorrectionLevel, maskPattern) {
      const size = matrix.size;
      const bits = FormatInfo.getEncodedBits(errorCorrectionLevel, maskPattern);
      let i, mod;
      for (i = 0; i < 15; i++) {
        mod = (bits >> i & 1) === 1;
        if (i < 6) {
          matrix.set(i, 8, mod, true);
        } else if (i < 8) {
          matrix.set(i + 1, 8, mod, true);
        } else {
          matrix.set(size - 15 + i, 8, mod, true);
        }
        if (i < 8) {
          matrix.set(8, size - i - 1, mod, true);
        } else if (i < 9) {
          matrix.set(8, 15 - i - 1 + 1, mod, true);
        } else {
          matrix.set(8, 15 - i - 1, mod, true);
        }
      }
      matrix.set(size - 8, 8, 1, true);
    }
    function setupData(matrix, data) {
      const size = matrix.size;
      let inc = -1;
      let row = size - 1;
      let bitIndex = 7;
      let byteIndex = 0;
      for (let col = size - 1; col > 0; col -= 2) {
        if (col === 6) col--;
        while (true) {
          for (let c = 0; c < 2; c++) {
            if (!matrix.isReserved(row, col - c)) {
              let dark = false;
              if (byteIndex < data.length) {
                dark = (data[byteIndex] >>> bitIndex & 1) === 1;
              }
              matrix.set(row, col - c, dark);
              bitIndex--;
              if (bitIndex === -1) {
                byteIndex++;
                bitIndex = 7;
              }
            }
          }
          row += inc;
          if (row < 0 || size <= row) {
            row -= inc;
            inc = -inc;
            break;
          }
        }
      }
    }
    function createData(version, errorCorrectionLevel, segments) {
      const buffer = new BitBuffer();
      segments.forEach(function(data) {
        buffer.put(data.mode.bit, 4);
        buffer.put(data.getLength(), Mode.getCharCountIndicator(data.mode, version));
        data.write(buffer);
      });
      const totalCodewords = Utils.getSymbolTotalCodewords(version);
      const ecTotalCodewords = ECCode.getTotalCodewordsCount(version, errorCorrectionLevel);
      const dataTotalCodewordsBits = (totalCodewords - ecTotalCodewords) * 8;
      if (buffer.getLengthInBits() + 4 <= dataTotalCodewordsBits) {
        buffer.put(0, 4);
      }
      while (buffer.getLengthInBits() % 8 !== 0) {
        buffer.putBit(0);
      }
      const remainingByte = (dataTotalCodewordsBits - buffer.getLengthInBits()) / 8;
      for (let i = 0; i < remainingByte; i++) {
        buffer.put(i % 2 ? 17 : 236, 8);
      }
      return createCodewords(buffer, version, errorCorrectionLevel);
    }
    function createCodewords(bitBuffer, version, errorCorrectionLevel) {
      const totalCodewords = Utils.getSymbolTotalCodewords(version);
      const ecTotalCodewords = ECCode.getTotalCodewordsCount(version, errorCorrectionLevel);
      const dataTotalCodewords = totalCodewords - ecTotalCodewords;
      const ecTotalBlocks = ECCode.getBlocksCount(version, errorCorrectionLevel);
      const blocksInGroup2 = totalCodewords % ecTotalBlocks;
      const blocksInGroup1 = ecTotalBlocks - blocksInGroup2;
      const totalCodewordsInGroup1 = Math.floor(totalCodewords / ecTotalBlocks);
      const dataCodewordsInGroup1 = Math.floor(dataTotalCodewords / ecTotalBlocks);
      const dataCodewordsInGroup2 = dataCodewordsInGroup1 + 1;
      const ecCount = totalCodewordsInGroup1 - dataCodewordsInGroup1;
      const rs = new ReedSolomonEncoder(ecCount);
      let offset = 0;
      const dcData = new Array(ecTotalBlocks);
      const ecData = new Array(ecTotalBlocks);
      let maxDataSize = 0;
      const buffer = new Uint8Array(bitBuffer.buffer);
      for (let b = 0; b < ecTotalBlocks; b++) {
        const dataSize = b < blocksInGroup1 ? dataCodewordsInGroup1 : dataCodewordsInGroup2;
        dcData[b] = buffer.slice(offset, offset + dataSize);
        ecData[b] = rs.encode(dcData[b]);
        offset += dataSize;
        maxDataSize = Math.max(maxDataSize, dataSize);
      }
      const data = new Uint8Array(totalCodewords);
      let index = 0;
      let i, r;
      for (i = 0; i < maxDataSize; i++) {
        for (r = 0; r < ecTotalBlocks; r++) {
          if (i < dcData[r].length) {
            data[index++] = dcData[r][i];
          }
        }
      }
      for (i = 0; i < ecCount; i++) {
        for (r = 0; r < ecTotalBlocks; r++) {
          data[index++] = ecData[r][i];
        }
      }
      return data;
    }
    function createSymbol(data, version, errorCorrectionLevel, maskPattern) {
      let segments;
      if (Array.isArray(data)) {
        segments = Segments.fromArray(data);
      } else if (typeof data === "string") {
        let estimatedVersion = version;
        if (!estimatedVersion) {
          const rawSegments = Segments.rawSplit(data);
          estimatedVersion = Version.getBestVersionForData(rawSegments, errorCorrectionLevel);
        }
        segments = Segments.fromString(data, estimatedVersion || 40);
      } else {
        throw new Error("Invalid data");
      }
      const bestVersion = Version.getBestVersionForData(segments, errorCorrectionLevel);
      if (!bestVersion) {
        throw new Error("The amount of data is too big to be stored in a QR Code");
      }
      if (!version) {
        version = bestVersion;
      } else if (version < bestVersion) {
        throw new Error(
          "\nThe chosen QR Code version cannot contain this amount of data.\nMinimum version required to store current data is: " + bestVersion + ".\n"
        );
      }
      const dataBits = createData(version, errorCorrectionLevel, segments);
      const moduleCount = Utils.getSymbolSize(version);
      const modules = new BitMatrix(moduleCount);
      setupFinderPattern(modules, version);
      setupTimingPattern(modules);
      setupAlignmentPattern(modules, version);
      setupFormatInfo(modules, errorCorrectionLevel, 0);
      if (version >= 7) {
        setupVersionInfo(modules, version);
      }
      setupData(modules, dataBits);
      if (isNaN(maskPattern)) {
        maskPattern = MaskPattern.getBestMask(
          modules,
          setupFormatInfo.bind(null, modules, errorCorrectionLevel)
        );
      }
      MaskPattern.applyMask(maskPattern, modules);
      setupFormatInfo(modules, errorCorrectionLevel, maskPattern);
      return {
        modules,
        version,
        errorCorrectionLevel,
        maskPattern,
        segments
      };
    }
    exports.create = function create(data, options) {
      if (typeof data === "undefined" || data === "") {
        throw new Error("No input text");
      }
      let errorCorrectionLevel = ECLevel.M;
      let version;
      let mask;
      if (typeof options !== "undefined") {
        errorCorrectionLevel = ECLevel.from(options.errorCorrectionLevel, ECLevel.M);
        version = Version.from(options.version);
        mask = MaskPattern.from(options.maskPattern);
        if (options.toSJISFunc) {
          Utils.setToSJISFunction(options.toSJISFunc);
        }
      }
      return createSymbol(data, version, errorCorrectionLevel, mask);
    };
  }
});

// node_modules/qrcode/lib/renderer/utils.js
var require_utils2 = __commonJS({
  "node_modules/qrcode/lib/renderer/utils.js"(exports) {
    function hex2rgba(hex) {
      if (typeof hex === "number") {
        hex = hex.toString();
      }
      if (typeof hex !== "string") {
        throw new Error("Color should be defined as hex string");
      }
      let hexCode = hex.slice().replace("#", "").split("");
      if (hexCode.length < 3 || hexCode.length === 5 || hexCode.length > 8) {
        throw new Error("Invalid hex color: " + hex);
      }
      if (hexCode.length === 3 || hexCode.length === 4) {
        hexCode = Array.prototype.concat.apply([], hexCode.map(function(c) {
          return [c, c];
        }));
      }
      if (hexCode.length === 6) hexCode.push("F", "F");
      const hexValue = parseInt(hexCode.join(""), 16);
      return {
        r: hexValue >> 24 & 255,
        g: hexValue >> 16 & 255,
        b: hexValue >> 8 & 255,
        a: hexValue & 255,
        hex: "#" + hexCode.slice(0, 6).join("")
      };
    }
    exports.getOptions = function getOptions(options) {
      if (!options) options = {};
      if (!options.color) options.color = {};
      const margin = typeof options.margin === "undefined" || options.margin === null || options.margin < 0 ? 4 : options.margin;
      const width = options.width && options.width >= 21 ? options.width : void 0;
      const scale = options.scale || 4;
      return {
        width,
        scale: width ? 4 : scale,
        margin,
        color: {
          dark: hex2rgba(options.color.dark || "#000000ff"),
          light: hex2rgba(options.color.light || "#ffffffff")
        },
        type: options.type,
        rendererOpts: options.rendererOpts || {}
      };
    };
    exports.getScale = function getScale(qrSize, opts) {
      return opts.width && opts.width >= qrSize + opts.margin * 2 ? opts.width / (qrSize + opts.margin * 2) : opts.scale;
    };
    exports.getImageWidth = function getImageWidth(qrSize, opts) {
      const scale = exports.getScale(qrSize, opts);
      return Math.floor((qrSize + opts.margin * 2) * scale);
    };
    exports.qrToImageData = function qrToImageData(imgData, qr, opts) {
      const size = qr.modules.size;
      const data = qr.modules.data;
      const scale = exports.getScale(size, opts);
      const symbolSize = Math.floor((size + opts.margin * 2) * scale);
      const scaledMargin = opts.margin * scale;
      const palette = [opts.color.light, opts.color.dark];
      for (let i = 0; i < symbolSize; i++) {
        for (let j = 0; j < symbolSize; j++) {
          let posDst = (i * symbolSize + j) * 4;
          let pxColor = opts.color.light;
          if (i >= scaledMargin && j >= scaledMargin && i < symbolSize - scaledMargin && j < symbolSize - scaledMargin) {
            const iSrc = Math.floor((i - scaledMargin) / scale);
            const jSrc = Math.floor((j - scaledMargin) / scale);
            pxColor = palette[data[iSrc * size + jSrc] ? 1 : 0];
          }
          imgData[posDst++] = pxColor.r;
          imgData[posDst++] = pxColor.g;
          imgData[posDst++] = pxColor.b;
          imgData[posDst] = pxColor.a;
        }
      }
    };
  }
});

// node_modules/qrcode/lib/renderer/canvas.js
var require_canvas = __commonJS({
  "node_modules/qrcode/lib/renderer/canvas.js"(exports) {
    var Utils = require_utils2();
    function clearCanvas(ctx, canvas, size) {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      if (!canvas.style) canvas.style = {};
      canvas.height = size;
      canvas.width = size;
      canvas.style.height = size + "px";
      canvas.style.width = size + "px";
    }
    function getCanvasElement() {
      try {
        return document.createElement("canvas");
      } catch (e) {
        throw new Error("You need to specify a canvas element");
      }
    }
    exports.render = function render2(qrData, canvas, options) {
      let opts = options;
      let canvasEl = canvas;
      if (typeof opts === "undefined" && (!canvas || !canvas.getContext)) {
        opts = canvas;
        canvas = void 0;
      }
      if (!canvas) {
        canvasEl = getCanvasElement();
      }
      opts = Utils.getOptions(opts);
      const size = Utils.getImageWidth(qrData.modules.size, opts);
      const ctx = canvasEl.getContext("2d");
      const image = ctx.createImageData(size, size);
      Utils.qrToImageData(image.data, qrData, opts);
      clearCanvas(ctx, canvasEl, size);
      ctx.putImageData(image, 0, 0);
      return canvasEl;
    };
    exports.renderToDataURL = function renderToDataURL(qrData, canvas, options) {
      let opts = options;
      if (typeof opts === "undefined" && (!canvas || !canvas.getContext)) {
        opts = canvas;
        canvas = void 0;
      }
      if (!opts) opts = {};
      const canvasEl = exports.render(qrData, canvas, opts);
      const type = opts.type || "image/png";
      const rendererOpts = opts.rendererOpts || {};
      return canvasEl.toDataURL(type, rendererOpts.quality);
    };
  }
});

// node_modules/qrcode/lib/renderer/svg-tag.js
var require_svg_tag = __commonJS({
  "node_modules/qrcode/lib/renderer/svg-tag.js"(exports) {
    var Utils = require_utils2();
    function getColorAttrib(color, attrib) {
      const alpha = color.a / 255;
      const str = attrib + '="' + color.hex + '"';
      return alpha < 1 ? str + " " + attrib + '-opacity="' + alpha.toFixed(2).slice(1) + '"' : str;
    }
    function svgCmd(cmd, x, y) {
      let str = cmd + x;
      if (typeof y !== "undefined") str += " " + y;
      return str;
    }
    function qrToPath(data, size, margin) {
      let path = "";
      let moveBy = 0;
      let newRow = false;
      let lineLength = 0;
      for (let i = 0; i < data.length; i++) {
        const col = Math.floor(i % size);
        const row = Math.floor(i / size);
        if (!col && !newRow) newRow = true;
        if (data[i]) {
          lineLength++;
          if (!(i > 0 && col > 0 && data[i - 1])) {
            path += newRow ? svgCmd("M", col + margin, 0.5 + row + margin) : svgCmd("m", moveBy, 0);
            moveBy = 0;
            newRow = false;
          }
          if (!(col + 1 < size && data[i + 1])) {
            path += svgCmd("h", lineLength);
            lineLength = 0;
          }
        } else {
          moveBy++;
        }
      }
      return path;
    }
    exports.render = function render2(qrData, options, cb) {
      const opts = Utils.getOptions(options);
      const size = qrData.modules.size;
      const data = qrData.modules.data;
      const qrcodesize = size + opts.margin * 2;
      const bg = !opts.color.light.a ? "" : "<path " + getColorAttrib(opts.color.light, "fill") + ' d="M0 0h' + qrcodesize + "v" + qrcodesize + 'H0z"/>';
      const path = "<path " + getColorAttrib(opts.color.dark, "stroke") + ' d="' + qrToPath(data, size, opts.margin) + '"/>';
      const viewBox = 'viewBox="0 0 ' + qrcodesize + " " + qrcodesize + '"';
      const width = !opts.width ? "" : 'width="' + opts.width + '" height="' + opts.width + '" ';
      const svgTag = '<svg xmlns="http://www.w3.org/2000/svg" ' + width + viewBox + ' shape-rendering="crispEdges">' + bg + path + "</svg>\n";
      if (typeof cb === "function") {
        cb(null, svgTag);
      }
      return svgTag;
    };
  }
});

// node_modules/qrcode/lib/browser.js
var require_browser = __commonJS({
  "node_modules/qrcode/lib/browser.js"(exports) {
    var canPromise = require_can_promise();
    var QRCode2 = require_qrcode();
    var CanvasRenderer = require_canvas();
    var SvgRenderer = require_svg_tag();
    function renderCanvas(renderFunc, canvas, text, opts, cb) {
      const args = [].slice.call(arguments, 1);
      const argsNum = args.length;
      const isLastArgCb = typeof args[argsNum - 1] === "function";
      if (!isLastArgCb && !canPromise()) {
        throw new Error("Callback required as last argument");
      }
      if (isLastArgCb) {
        if (argsNum < 2) {
          throw new Error("Too few arguments provided");
        }
        if (argsNum === 2) {
          cb = text;
          text = canvas;
          canvas = opts = void 0;
        } else if (argsNum === 3) {
          if (canvas.getContext && typeof cb === "undefined") {
            cb = opts;
            opts = void 0;
          } else {
            cb = opts;
            opts = text;
            text = canvas;
            canvas = void 0;
          }
        }
      } else {
        if (argsNum < 1) {
          throw new Error("Too few arguments provided");
        }
        if (argsNum === 1) {
          text = canvas;
          canvas = opts = void 0;
        } else if (argsNum === 2 && !canvas.getContext) {
          opts = text;
          text = canvas;
          canvas = void 0;
        }
        return new Promise(function(resolve, reject) {
          try {
            const data = QRCode2.create(text, opts);
            resolve(renderFunc(data, canvas, opts));
          } catch (e) {
            reject(e);
          }
        });
      }
      try {
        const data = QRCode2.create(text, opts);
        cb(null, renderFunc(data, canvas, opts));
      } catch (e) {
        cb(e);
      }
    }
    exports.create = QRCode2.create;
    exports.toCanvas = renderCanvas.bind(null, CanvasRenderer.render);
    exports.toDataURL = renderCanvas.bind(null, CanvasRenderer.renderToDataURL);
    exports.toString = renderCanvas.bind(null, function(data, _, opts) {
      return SvgRenderer.render(data, opts);
    });
  }
});

// src/account.ts
init_crypto();
var MIN_PASSWORD_LENGTH = 12;
var KDF_MEMORY_KIB = 64 * 1024;
var KDF_PASSES = 3;
var KDF_LANES = 2;
var SALT_SIZE = 16;
function checkPassword(password) {
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `at least ${MIN_PASSWORD_LENGTH} characters: this password is the only thing protecting the account, because the server cannot check it for you`;
  }
  return null;
}
function describeStrength(password) {
  if (password.length < MIN_PASSWORD_LENGTH) return "too short";
  const classes = (/[a-z]/.test(password) ? 1 : 0) + (/[A-Z]/.test(password) ? 1 : 0) + (/[0-9]/.test(password) ? 1 : 0) + (/[^a-zA-Z0-9]/.test(password) ? 1 : 0);
  const unique = new Set(password).size;
  const variety = unique / password.length;
  if (variety < 0.3) return "weak: too repetitive";
  if (password.length >= 20 && classes >= 3) return "strong";
  if (password.length >= 16 || classes >= 3) return "reasonable";
  return "weak: add length or variety";
}
async function deriveVaultKey(password, salt, params = {
  memoryKiB: KDF_MEMORY_KIB,
  passes: KDF_PASSES,
  lanes: KDF_LANES
}) {
  const encoder = new TextEncoder();
  return argon2id(encoder.encode(password), salt, params);
}
async function sealVault(contents, password, params = {
  memoryKiB: KDF_MEMORY_KIB,
  passes: KDF_PASSES,
  lanes: KDF_LANES
}) {
  const salt = randomBytes(SALT_SIZE);
  const key = await deriveVaultKey(password, salt, params);
  try {
    const plain = encodeContents(contents);
    const ciphertext = await sealAead(key, plain);
    return {
      salt,
      memoryKiB: params.memoryKiB,
      passes: params.passes,
      lanes: params.lanes,
      generation: 0,
      ciphertext
    };
  } finally {
    key.fill(0);
  }
}
async function openVault(vault, password) {
  const key = await deriveVaultKey(password, vault.salt, {
    memoryKiB: vault.memoryKiB,
    passes: vault.passes,
    lanes: vault.lanes
  });
  try {
    const plain = await openAead(key, vault.ciphertext);
    return plain === null ? null : decodeContents(plain);
  } finally {
    key.fill(0);
  }
}
function encodeContents(contents) {
  const parts = [];
  const putBlob = (bytes) => {
    const length = bytes?.length ?? 0;
    const head = new Uint8Array(4);
    new DataView(head.buffer).setUint32(0, length, false);
    parts.push(head);
    if (bytes) parts.push(bytes);
  };
  putBlob(contents.identity);
  putBlob(contents.preKeyState);
  putBlob(contents.peerRegistry);
  putBlob(contents.groupState);
  putBlob(new TextEncoder().encode(JSON.stringify(contents.history)));
  return concat(parts);
}
function decodeContents(plain) {
  let offset = 0;
  const readBlob = () => {
    if (plain.length - offset < 4) throw new Error("vault is truncated");
    const length = new DataView(plain.buffer, plain.byteOffset + offset, 4).getUint32(0, false);
    offset += 4;
    if (plain.length - offset < length) throw new Error("vault is truncated");
    const out = plain.slice(offset, offset + length);
    offset += length;
    return length === 0 ? null : out;
  };
  const identity = readBlob();
  if (!identity) throw new Error("vault has no identity");
  const preKeyState = readBlob();
  const peerRegistry = readBlob();
  const groupState = readBlob();
  const historyJson = readBlob();
  const history = historyJson ? JSON.parse(new TextDecoder().decode(historyJson)) : {};
  return { identity, preKeyState, peerRegistry, groupState, history };
}
function concat(parts) {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

// src/app.ts
init_engine();

// src/wire.ts
var WIRE_VERSION = 1;
var FrameType = {
  HELLO: 1,
  HELLO_OK: 2,
  PUBLISH_PREKEYS: 3,
  GET_BUNDLE: 4,
  BUNDLE: 5,
  SEND: 6,
  DELIVER: 7,
  ACK: 8,
  ERROR: 9,
  AUTH_CHALLENGE: 10,
  AUTH_RESPONSE: 11,
  MORE_PENDING: 12,
  // Device lists. See docs/multi-device.md.
  PUBLISH_DEVICES: 13,
  GET_DEVICES: 14,
  DEVICES: 15,
  // Password vaults. The only types usable before authenticating: restoring an
  // identity is exactly the case where a client has nothing to sign with yet.
  PUT_VAULT: 16,
  GET_VAULT: 17,
  VAULT_DATA: 18,
  VAULT_ACK: 19
};
var MAX_PAYLOAD = 1 << 20;
function frame(type, payload) {
  if (payload.length > MAX_PAYLOAD) throw new Error("payload too large");
  const out = new Uint8Array(6 + payload.length);
  out[0] = WIRE_VERSION;
  out[1] = type;
  new DataView(out.buffer).setUint32(2, payload.length, false);
  out.set(payload, 6);
  return out;
}
function parseFrame(bytes) {
  if (bytes.length < 6) throw new Error("short frame");
  const version = bytes[0];
  if (version !== WIRE_VERSION) {
    throw new Error(`unsupported protocol version ${version}`);
  }
  const len = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(2, false);
  if (6 + len !== bytes.length) throw new Error("bad frame length");
  return { type: bytes[1], payload: bytes.subarray(6) };
}
var Writer = class {
  parts = [];
  length = 0;
  u32(v) {
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
  u64(v) {
    const b = new Uint8Array(8);
    const view = new DataView(b.buffer);
    const value = typeof v === "bigint" ? v : BigInt(v);
    view.setUint32(0, Number(value >> 32n & 0xffffffffn), false);
    view.setUint32(4, Number(value & 0xffffffffn), false);
    return this.raw(b);
  }
  blob(b) {
    this.u32(b.length);
    return this.raw(b);
  }
  string(s) {
    return this.blob(new TextEncoder().encode(s));
  }
  raw(b) {
    this.parts.push(b);
    this.length += b.length;
    return this;
  }
  build() {
    const out = new Uint8Array(this.length);
    let off = 0;
    for (const part of this.parts) {
      out.set(part, off);
      off += part.length;
    }
    return out;
  }
};
var Reader = class {
  constructor(data) {
    this.data = data;
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  }
  pos = 0;
  view;
  get remaining() {
    return this.data.length - this.pos;
  }
  u32() {
    if (this.remaining < 4) throw new Error("truncated");
    const v = this.view.getUint32(this.pos, false);
    this.pos += 4;
    return v;
  }
  u64() {
    if (this.remaining < 8) throw new Error("truncated");
    const hi = BigInt(this.view.getUint32(this.pos, false));
    const lo = BigInt(this.view.getUint32(this.pos + 4, false));
    this.pos += 8;
    return hi << 32n | lo;
  }
  blob() {
    const n = this.u32();
    if (n < 0 || n > MAX_PAYLOAD || n > this.remaining) throw new Error("truncated");
    const out = this.data.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  string() {
    return new TextDecoder().decode(this.blob());
  }
  raw(n) {
    if (n < 0 || n > this.remaining) throw new Error("truncated");
    const out = this.data.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  done() {
    if (this.remaining !== 0) throw new Error("trailing bytes");
  }
};

// src/relay.ts
var RelayClient = class {
  constructor(url) {
    this.url = url;
  }
  socket = null;
  connected = false;
  closed = false;
  listeners = /* @__PURE__ */ new Set();
  openWaiters = [];
  // One waiter per in-flight request, keyed by the user id being asked about.
  // A promise rather than an event because the caller wants the answer, not a
  // subscription, and a page that has to reconstruct the correlation itself is
  // a page that will eventually get it wrong.
  bundleWaiters = /* @__PURE__ */ new Map();
  deviceWaiters = /* @__PURE__ */ new Map();
  // Vault requests have no correlation field on the wire: the reply does not
  // repeat the user id, because the relay answers the connection that asked. So
  // put and get get their own maps rather than sharing one and guessing at a
  // suffixed key.
  vaultPutWaiters = /* @__PURE__ */ new Map();
  vaultGetWaiters = /* @__PURE__ */ new Map();
  get isConnected() {
    return this.connected && this.socket !== null && !this.closed;
  }
  onEvent(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
  emit(event) {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch (e) {
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
  connect(userId2, publicIdentity, deviceId = "") {
    this.closed = false;
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(this.url);
      socket.binaryType = "arraybuffer";
      this.socket = socket;
      this.openWaiters.push((ok) => ok ? resolve() : reject(new Error("connect failed")));
      socket.onopen = () => {
        const hello = new Writer().string(userId2).blob(publicIdentity);
        if (deviceId) hello.string(deviceId);
        socket.send(frame(FrameType.HELLO, hello.build()));
        this.settleOpenWaiters(true);
      };
      socket.onmessage = (event) => {
        const data = new Uint8Array(event.data);
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
  settleOpenWaiters(ok) {
    for (const waiter of this.openWaiters.splice(0)) waiter(ok);
  }
  handleFrame(bytes) {
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
            frame: r.blob()
          });
          break;
        case FrameType.BUNDLE: {
          const userId2 = r.string();
          const identity = r.blob();
          const signedId = r.u32();
          const signedPub = r.blob();
          const signature = r.blob();
          const oneTimeId = r.u32();
          const oneTimePub = r.blob();
          const waiters = this.bundleWaiters.get(userId2);
          if (waiters) {
            waiters(encodeBundle(
              identity,
              signedId,
              signedPub,
              signature,
              oneTimeId,
              oneTimePub
            ));
          }
          this.emit({
            kind: "bundle",
            userId: userId2,
            identity,
            signedId,
            signedPub,
            signature,
            oneTimeId,
            oneTimePub
          });
          break;
        }
        case FrameType.DEVICES: {
          const version = r.u32();
          const count = r.u32();
          const devices = [];
          let owner = "";
          for (let i = 0; i < count; ++i) {
            const deviceId = r.string();
            const credential = r.blob();
            owner = credentialOwner(credential);
            devices.push({ deviceId, credential });
          }
          const waiter = this.deviceWaiters.get(owner);
          if (waiter) waiter({ version, devices });
          break;
        }
        case FrameType.VAULT_ACK: {
          const generation = r.u32();
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
  respondToChallenge(signature) {
    return this.write(
      FrameType.AUTH_RESPONSE,
      new Writer().blob(signature).build()
    );
  }
  publishPreKeys(signedId, signedPub, signature, oneTimeSet) {
    return this.send(
      FrameType.PUBLISH_PREKEYS,
      new Writer().u32(signedId).blob(signedPub).blob(signature).blob(oneTimeSet).build()
    );
  }
  requestBundle(userId2) {
    return this.send(FrameType.GET_BUNDLE, new Writer().string(userId2).build());
  }
  /**
   * Requests a peer's device list.
   *
   * The reply arrives asynchronously as a `devices` event, so this resolves a
   * promise rather than returning the list: the caller wants the answer, not a
   * subscription.
   */
  getDevices(userId2, timeoutMs = 8e3) {
    if (!this.send(FrameType.GET_DEVICES, new Writer().string(userId2).build())) {
      return Promise.resolve(null);
    }
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.deviceWaiters.delete(userId2);
        resolve(null);
      }, timeoutMs);
      this.deviceWaiters.set(userId2, (result) => {
        clearTimeout(timer);
        this.deviceWaiters.delete(userId2);
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
  getBundle(userId2, timeoutMs = 8e3) {
    if (!this.send(FrameType.GET_BUNDLE, new Writer().string(userId2).build())) {
      return Promise.resolve(null);
    }
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.bundleWaiters.delete(userId2);
        resolve(null);
      }, timeoutMs);
      this.bundleWaiters.set(userId2, (bundle) => {
        clearTimeout(timer);
        this.bundleWaiters.delete(userId2);
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
  sendMessage(recipient, frameBytes, deviceId = "") {
    const writer = new Writer().string(recipient).blob(frameBytes);
    if (deviceId) writer.string(deviceId);
    return this.send(FrameType.SEND, writer.build());
  }
  acknowledge(outboxId) {
    return this.send(FrameType.ACK, new Writer().u64(outboxId).build());
  }
  // ---- Password vault ---------------------------------------------------
  //
  // The only requests a client may make before authenticating, because restoring
  // an identity is exactly the case where it has nothing to authenticate with
  // yet. The relay stores a blob it cannot open.
  /** Uploads a sealed vault. Resolves with the generation the relay assigned. */
  putVault(userId2, salt, params, ciphertext, timeoutMs = 2e4) {
    const payload = new Writer().string(userId2).blob(salt).u32(params.memoryKiB).u32(params.passes).u32(params.lanes).blob(ciphertext).build();
    if (!this.send(FrameType.PUT_VAULT, payload)) return Promise.resolve(null);
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.vaultPutWaiters.delete(userId2);
        resolve(null);
      }, timeoutMs);
      this.vaultPutWaiters.set(userId2, (generation) => {
        clearTimeout(timer);
        this.vaultPutWaiters.delete(userId2);
        resolve(generation);
      });
    });
  }
  /** Fetches a sealed vault, or null when the user has none. */
  getVault(userId2, timeoutMs = 2e4) {
    if (!this.send(FrameType.GET_VAULT, new Writer().string(userId2).build())) {
      return Promise.resolve(null);
    }
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.vaultGetWaiters.delete(userId2);
        resolve(null);
      }, timeoutMs);
      this.vaultGetWaiters.set(userId2, (reply) => {
        clearTimeout(timer);
        this.vaultGetWaiters.delete(userId2);
        resolve(reply);
      });
    });
  }
  send(type, payload) {
    if (!this.connected || this.closed) return false;
    return this.write(type, payload);
  }
  write(type, payload) {
    const socket = this.socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) return false;
    if (payload.length > MAX_PAYLOAD) return false;
    socket.send(frame(type, payload));
    return true;
  }
  close() {
    this.closed = true;
    this.socket?.close(1e3, "bye");
    this.socket = null;
    this.connected = false;
  }
};
function buildBundle(event) {
  return encodeBundle(
    event.identity,
    event.signedId,
    event.signedPub,
    event.signature,
    event.oneTimeId,
    event.oneTimePub
  );
}
function encodeBundle(identity, signedId, signedPub, signature, oneTimeId, oneTimePub) {
  if (identity.length !== 64) return null;
  if (signedPub.length !== 32) return null;
  if (signature.length !== 64) return null;
  const hasOneTime = oneTimeId !== 0 && oneTimePub.length === 32;
  const w = new Writer().raw(identity).u32(signedId).raw(signedPub).raw(signature).raw(new Uint8Array([hasOneTime ? 1 : 0]));
  if (hasOneTime) {
    w.u32(oneTimeId).raw(oneTimePub);
  }
  return w.build();
}
function credentialOwner(credential) {
  if (credential.length < 2) return "";
  const len = credential[0] << 8 | credential[1];
  if (len === 0 || credential.length < 2 + len) return "";
  return new TextDecoder().decode(credential.slice(2, 2 + len));
}

// src/vault.ts
var DB_NAME = "veil";
var DB_VERSION = 1;
var STORE = "keys";
async function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("could not open IndexedDB"));
  });
}
async function get(key) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const request = tx.objectStore(STORE).get(key);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  } finally {
    db.close();
  }
}
async function put(key, value) {
  const db = await openDb();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(value, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}
async function remove(key) {
  const db = await openDb();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}
var Vault = class {
  keyPromise = null;
  /** The wrapping key, created on first use and never exportable. */
  async wrappingKey() {
    if (this.keyPromise) return this.keyPromise;
    this.keyPromise = (async () => {
      const existing = await get("wrapping-key");
      if (existing) return existing;
      const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        // Non-extractable: JavaScript cannot read the raw bytes, so the key
        // cannot be exfiltrated by a script that only gets its handle.
        false,
        ["encrypt", "decrypt"]
      );
      await put("wrapping-key", key);
      return key;
    })();
    return this.keyPromise;
  }
  async seal(plaintext) {
    const key = await this.wrappingKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext)
    );
    return { iv, ciphertext };
  }
  async unseal(stored) {
    const key = await this.wrappingKey();
    try {
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: stored.iv },
        key,
        stored.ciphertext
      );
      return new Uint8Array(plain);
    } catch {
      return null;
    }
  }
  // ---- Identity ---------------------------------------------------------
  async hasIdentity() {
    return await get("identity") !== void 0;
  }
  async loadIdentity() {
    const stored = await get("identity");
    if (!stored) return null;
    return this.unseal(stored);
  }
  async storeIdentity(secrets) {
    await put("identity", await this.seal(secrets));
  }
  /** True when an identity exists but cannot be decrypted any more. */
  async isIdentityLost() {
    const stored = await get("identity");
    if (!stored) return false;
    return await this.unseal(stored) === null;
  }
  async clearIdentity() {
    await remove("identity");
    await remove("wrapping-key");
  }
  // ---- Protocol state ---------------------------------------------------
  //
  // Prekey state and sessions carry private keys too, so they go through the
  // same seal. The pin registry is public keys only, but keeping it here means
  // one place to reason about.
  async loadPreKeyState() {
    const stored = await get("prekeys");
    return stored ? this.unseal(stored) : null;
  }
  async storePreKeyState(blob) {
    await put("prekeys", await this.seal(blob));
  }
  async loadRegistry() {
    const stored = await get("registry");
    return stored ? this.unseal(stored) : null;
  }
  async storeRegistry(blob) {
    await put("registry", await this.seal(blob));
  }
  async loadSession(peerId) {
    const stored = await get(`session:${peerId}`);
    return stored ? this.unseal(stored) : null;
  }
  async storeSession(peerId, blob) {
    await put(`session:${peerId}`, await this.seal(blob));
  }
  async removeSession(peerId) {
    await remove(`session:${peerId}`);
  }
  // ---- Peer index -------------------------------------------------------
  //
  // The registry blob the engine exports is the authority on pins, but it is an
  // opaque byte string: it cannot be enumerated from JavaScript to rebuild a
  // peer list after a reload. This is that list, kept plainly because it is
  // only names — every actual key lives in the sealed blobs above.
  async loadPeerIds() {
    return await get("peer-ids") ?? null;
  }
  async storePeerIds(ids) {
    await put("peer-ids", ids);
  }
  // ---- Transcript -------------------------------------------------------
  //
  // Message text is the one thing that is *not* sealed: it is written to
  // IndexedDB in the clear, because sealing it with the same non-extractable
  // key would add no real protection against the threat model above (script on
  // the page) and would cost a decrypt on every render. It is stored under a
  // separate key so a future version can seal it without a migration.
  async loadMessages(peerId) {
    return await get(`messages:${peerId}`) ?? [];
  }
  async storeMessages(peerId, messages) {
    await put(`messages:${peerId}`, messages);
  }
  // ---- Groups -----------------------------------------------------------
  //
  // Group state carries chain keys: every incoming chain decrypts that sender's
  // messages and the outgoing chain can forge them. It is sealed like ratchet
  // state, for the same reason.
  async loadGroupState() {
    const stored = await get("group-state");
    return stored ? this.unseal(stored) : null;
  }
  async storeGroupState(blob) {
    await put("group-state", await this.seal(blob));
  }
  /** The group ids this client is in, so a reload can enumerate them. */
  async loadGroupIds() {
    return await get("group-ids") ?? null;
  }
  async storeGroupIds(ids) {
    await put("group-ids", ids);
  }
  // ---- Device identity --------------------------------------------------
  /** This device's hex id, so a reload keeps the same device rather than
   *  minting a second one for the same account. */
  async loadDeviceId() {
    return await get("device-id") ?? null;
  }
  async storeDeviceId(id) {
    await put("device-id", id);
  }
  async loadGroupMessages(groupId) {
    return await get(`group-messages:${groupId}`) ?? [];
  }
  async storeGroupMessages(groupId, messages) {
    await put(`group-messages:${groupId}`, messages);
  }
  async clearAll() {
    const db = await openDb();
    db.close();
    await new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase(DB_NAME);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
      request.onblocked = () => resolve();
    });
  }
};

// src/app.ts
var REFILL_LOW_WATER = 10;
var DEVICE_LIST_STALENESS_MS = 10 * 60 * 1e3;
var ChatApp = class {
  engine = null;
  relay = null;
  vault = new Vault();
  peers = [];
  messages = /* @__PURE__ */ new Map();
  queue = [];
  groups = [];
  groupMessages = /* @__PURE__ */ new Map();
  /** This device's id, hex. Empty until the engine has one. */
  selfDeviceId = "";
  nextMessageId = 1;
  hasPublishedPreKeys = false;
  selfUserId = "";
  linkState = "offline";
  statusText = null;
  listeners = /* @__PURE__ */ new Set();
  unsubscribeRelay = null;
  // ---- Observation ------------------------------------------------------
  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
  notify() {
    for (const listener of this.listeners) {
      try {
        listener();
      } catch (e) {
        console.error("view listener failed", e);
      }
    }
  }
  get link() {
    return this.linkState;
  }
  get status() {
    return this.statusText;
  }
  get peerList() {
    return this.peers;
  }
  messagesFor(peerId) {
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
  async init(wasmUrl, options = {}) {
    await VeilEngine.load(wasmUrl, options);
    const secrets = await this.vault.loadIdentity();
    if (secrets) {
      this.engine = VeilEngine.restore(secrets);
      secrets.fill(0);
    } else {
      if (await this.vault.isIdentityLost()) {
        throw new Error(
          "a stored identity could not be decrypted: this browser profile's key no longer matches. The account cannot be recovered on this client."
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
  async restoreGroups() {
    if (!this.engine) return;
    const state = await this.vault.loadGroupState();
    if (state) {
      this.engine.importGroupState(state);
      state.fill(0);
    }
    const ids = await this.vault.loadGroupIds() ?? [];
    for (const groupId of ids) {
      const epoch = this.engine.groupEpoch(groupId);
      if (epoch === 0) continue;
      this.groups.push({
        groupId,
        epoch,
        members: this.engine.groupMembers(groupId),
        canSend: this.engine.isGroupMember(groupId)
      });
      this.groupMessages.set(groupId, await this.vault.loadGroupMessages(groupId) ?? []);
    }
  }
  /**
   * Rebuilds the peer list from whatever sessions are on disk.
   *
   * There is no separate peer table: a label exists because a session or a pin
   * exists, and saying so keeps the list from claiming a conversation that the
   * engine knows nothing about.
   */
  async restorePeers() {
    if (!this.engine) return;
    const known = await this.knownPeerIds();
    for (const userId2 of known) {
      const blob = await this.vault.loadSession(userId2);
      if (blob) {
        this.engine.importSession(userId2, blob);
        blob.fill(0);
      }
      this.messages.set(userId2, await this.vault.loadMessages(userId2) ?? []);
      this.peers.push({
        userId: userId2,
        displayName: userId2,
        safetyNumber: this.engine.safetyNumber(userId2),
        state: this.engine.sessionState(userId2),
        devices: this.engine.peerDevices(userId2)
      });
    }
  }
  /**
   * The peer labels this browser knows about.
   *
   * IndexedDB has no prefix query here without a cursor, and the set is small,
   * so the names are kept alongside the registry under a plain key.
   */
  async knownPeerIds() {
    const raw = await this.vault.loadPeerIds();
    return raw ?? [];
  }
  // ---- Connection -------------------------------------------------------
  async connect(url, userId2) {
    if (!this.engine) throw new Error("not initialised");
    if (this.linkState === "connecting") return;
    this.selfUserId = userId2;
    this.setLink("connecting");
    if (!this.selfDeviceId) {
      const stored = await this.vault.loadDeviceId();
      if (stored) {
        this.selfDeviceId = stored;
      } else if (this.engine.initDevice(userId2)) {
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
      await relay.connect(userId2, this.engine.publicIdentity(), this.selfDeviceId);
    } catch (e) {
      this.setLink("error");
      this.setStatus(e instanceof Error ? e.message : "connection failed");
    }
  }
  disconnect() {
    this.unsubscribeRelay?.();
    this.unsubscribeRelay = null;
    this.relay?.close();
    this.relay = null;
    this.setLink("offline");
  }
  onRelayEvent(event) {
    switch (event.kind) {
      case "challenge": {
        const signature = this.engine.signChallenge(event.nonce);
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
  async publishPreKeys() {
    const engine = this.engine;
    const relay = this.relay;
    if (!engine || !relay) return;
    if (this.hasPublishedPreKeys && !engine.needsPreKeyRefill(REFILL_LOW_WATER)) return;
    const set = engine.rotatePreKeys();
    await this.vault.storePreKeyState(engine.exportPreKeyState());
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
  addPeer(peerId) {
    const existing = this.peers.find((p) => p.userId === peerId);
    if (existing) {
      this.setStatus(`already talking to ${existing.displayName}`);
      return;
    }
    this.peers.push({
      userId: peerId,
      displayName: peerId,
      safetyNumber: null,
      state: 0 /* NoPeer */,
      devices: []
    });
    this.messages.set(peerId, []);
    void this.persistPeerIds();
    this.relay?.requestBundle(peerId);
    this.notify();
  }
  async onBundle(event) {
    const engine = this.engine;
    if (!engine) return;
    if (engine.sessionState(event.userId) === 2 /* Ready */) {
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
          `SECURITY: ${event.userId} presented a different identity key. Verify the new safety number before continuing.`
        );
        return;
      case Status.BAD_SIGNATURE:
        this.setStatus(`prekey signature for ${event.userId} did not verify`);
        return;
      default:
        this.setStatus(`could not establish a session with ${event.userId}`);
        return;
    }
    const safety2 = engine.safetyNumber(event.userId);
    await this.persistSession(event.userId);
    await this.persistRegistry();
    const peer = this.peers.find((p) => p.userId === event.userId);
    if (peer) {
      peer.safetyNumber = safety2;
      peer.state = 2 /* Ready */;
    }
    this.setStatus(`session ready with ${event.userId}`);
  }
  // ---- Messaging --------------------------------------------------------
  send(peerId, text) {
    const engine = this.engine;
    if (!engine || !text.trim()) return;
    const plain = new TextEncoder().encode(text);
    const frames = engine.encryptToAccount(peerId, plain);
    if (frames.length === 0) {
      this.setStatus(`could not encrypt for ${peerId}: no session`);
      return;
    }
    const message = {
      id: this.nextMessageId++,
      peerId,
      outgoing: true,
      text,
      timestamp: Date.now(),
      state: "queued"
    };
    this.appendMessage(message);
    void this.persistSession(peerId);
    const connected = this.relay?.isConnected === true;
    let allSent = connected;
    for (const item of frames) {
      if (!connected || !this.relay.sendMessage(peerId, item.frame, item.deviceId)) {
        this.queue.push({
          peerId,
          deviceId: item.deviceId,
          frame: Array.from(item.frame),
          text
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
  async refreshDevicesIfNeeded(peerId) {
    const engine = this.engine;
    if (!engine) return;
    engine.setClock(Date.now());
    const reason = engine.deviceListNeedsRefresh(peerId, DEVICE_LIST_STALENESS_MS);
    if (reason === 0 /* None */) return;
    const peer = this.peers.find((p) => p.userId === peerId);
    const identity = engine.peerIdentity(peerId);
    if (!identity || identity.length !== 64) return;
    const adopted = await this.refreshPeerDevices(
      peerId,
      identity.slice(0, 32),
      identity.slice(32, 64)
    );
    if (!adopted) return;
    engine.noteDeviceListFetched(peerId);
    if (peer) peer.devices = engine.peerDevices(peerId);
    await this.connectPeerDevices(peerId);
    this.notify();
  }
  // ---- Groups -----------------------------------------------------------
  groupViews() {
    return this.groups;
  }
  groupMessagesFor(groupId) {
    return this.groupMessages.get(groupId) ?? [];
  }
  /** Creates a group with this client as founder and sole member. */
  async createGroup(groupId) {
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
  async setGroupMembers(groupId, members) {
    if (!this.engine) return 0;
    const epoch = this.engine.setGroupMembers(groupId, members);
    if (epoch === 0) return 0;
    await this.refreshGroup(groupId);
    await this.persistGroups();
    return epoch;
  }
  /** The signed member list, to hand to the other members out of band. */
  exportMembership(groupId) {
    return this.engine?.exportMembership(groupId) ?? null;
  }
  /**
   * Adopts a member list a founder signed.
   *
   * `founderSignPub` is the founder's account signing key, which the caller got
   * by verifying the founder's safety number out of band 闂?the same trust anchor
   * the rest of the protocol uses.
   */
  async adoptMembership(groupId, record, founderSignPub) {
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
  exportSenderKey(groupId) {
    return this.engine?.exportSenderKey(groupId, 0) ?? null;
  }
  /** Installs a member's chain, as received over a pairwise session. */
  async adoptSenderKey(groupId, record, senderId, senderSignPub) {
    if (!this.engine) return null;
    const status = this.engine.adoptSenderKey(record, senderId, senderSignPub);
    if (status === Status.OK) await this.persistGroups();
    return status;
  }
  /** Sends one message to the whole group: one frame, regardless of size. */
  async sendToGroup(groupId, text) {
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
      outgoing: true
    });
    if (this.relay?.isConnected !== true || !this.relay.sendMessage(groupId, record)) {
      this.setStatus("offline: the group message was not delivered");
    }
    await this.persistGroups();
  }
  /** Decrypts a group frame that arrived as a delivery. */
  onGroupDelivered(senderId, body) {
    const engine = this.engine;
    if (!engine) return false;
    for (const group of this.groups) {
      const result = engine.decryptFromGroup(group.groupId, body);
      if (result.status === Status.OK && result.plain) {
        this.appendGroupMessage({
          groupId: group.groupId,
          senderId,
          text: new TextDecoder().decode(result.plain),
          at: Date.now(),
          outgoing: false
        });
        void this.persistGroups();
        return true;
      }
    }
    return false;
  }
  async refreshGroup(groupId) {
    if (!this.engine) return;
    const epoch = this.engine.groupEpoch(groupId);
    if (epoch === 0) return;
    const view = {
      groupId,
      epoch,
      members: this.engine.groupMembers(groupId),
      canSend: this.engine.isGroupMember(groupId)
    };
    const index = this.groups.findIndex((g) => g.groupId === groupId);
    if (index >= 0) this.groups[index] = view;
    else this.groups.push(view);
    if (!this.groupMessages.has(groupId)) this.groupMessages.set(groupId, []);
    this.notify();
  }
  appendGroupMessage(message) {
    const list = this.groupMessages.get(message.groupId) ?? [];
    list.push(message);
    this.groupMessages.set(message.groupId, list);
    this.notify();
  }
  async persistGroups() {
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
  deviceId() {
    return this.selfDeviceId;
  }
  /** Fetches a peer's device list from the relay and adopts it. */
  async refreshPeerDevices(peerId, accountDhPub, accountSignPub) {
    const relay = this.relay;
    if (!relay || !this.engine) return false;
    const listing = await relay.getDevices(peerId);
    if (!listing || listing.devices.length === 0) return false;
    const devices = listing.devices;
    const total = 4 + devices.reduce((sum, d) => sum + d.credential.length, 0);
    const blob = new Uint8Array(total);
    new DataView(blob.buffer).setUint32(0, devices.length, false);
    let off = 4;
    for (const device of devices) {
      blob.set(device.credential, off);
      off += device.credential.length;
    }
    const status = this.engine.adoptDeviceList(
      peerId,
      listing.version,
      blob,
      accountDhPub,
      accountSignPub
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
  async connectPeerDevices(peerId) {
    const relay = this.relay;
    const engine = this.engine;
    if (!relay || !engine) return 0;
    const devices = engine.peerDevices(peerId);
    if (devices.length === 0) return 0;
    const ids = [];
    const bundles = [];
    for (const deviceId of devices) {
      const bundle = await relay.getBundle(peerId);
      if (!bundle) continue;
      ids.push(deviceId);
      bundles.push(bundle);
    }
    if (ids.length === 0) return 0;
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
  deviceCredential() {
    return this.engine?.deviceCredential() ?? null;
  }
  // ---- Device linking ---------------------------------------------------
  /** This device's linking request, for the existing device to endorse. */
  linkingRequest() {
    return this.engine?.linkingRequest() ?? null;
  }
  /**
   * The account a request names and its fingerprint.
   *
   * Both from one call, so the fingerprint shown cannot belong to a different
   * request than the one about to be approved.
   */
  readLinkingRequest(data) {
    return this.engine?.readLinkingRequest(data) ?? null;
  }
  /**
   * Signs an endorsement for another device.
   *
   * Null when this client does not hold the account key, which is the correct
   * answer rather than an error: a linked device cannot add further devices.
   */
  approveLinking(request) {
    const engine = this.engine;
    if (!engine) return null;
    return engine.approveLinking(request, Math.floor(Date.now() / 1e3));
  }
  /** This account's identity, for the device being linked to verify against. */
  publicIdentity() {
    return this.engine?.publicIdentity() ?? null;
  }
  /** Adopts a device credential, and takes on its device id. */
  async adoptLinking(credential, accountDhPub, accountSignPub) {
    return this.adoptDeviceCredential(credential, accountDhPub, accountSignPub);
  }
  // ---- Accounts ---------------------------------------------------------
  //
  // A password that lets the identity be restored on another device. What goes
  // over the wire is a blob sealed under a key derived from it, so the relay
  // cannot verify the password and cannot open the vault.
  /**
   * Uploads this client's whole state, sealed under the password.
   *
   * Requires a connection: the vault lives on the relay, which is the point -
   * another device has to be able to reach it.
   */
  async createAccount(password) {
    const engine = this.engine;
    const relay = this.relay;
    if (!engine) return "the engine is not loaded";
    if (!relay || !relay.isConnected) return "connect before creating an account";
    if (!this.selfUserId) return "connect with an id first";
    const problem = checkPassword(password);
    if (problem) return problem;
    const contents = {
      identity: engine.identitySecrets(),
      preKeyState: engine.exportPreKeyState(),
      peerRegistry: engine.exportPeerRegistry(),
      groupState: engine.exportGroupState(),
      history: this.collectHistory()
    };
    const sealed = await sealVault(contents, password);
    const generation = await relay.putVault(
      this.selfUserId,
      sealed.salt,
      { memoryKiB: sealed.memoryKiB, passes: sealed.passes, lanes: sealed.lanes },
      sealed.ciphertext
    );
    contents.identity.fill(0);
    if (generation === null) return "the relay did not accept the vault";
    this.setStatus(
      `account stored (generation ${generation}): sign in with this password on another device to restore it`
    );
    return null;
  }
  /**
   * Restores this client's state from the vault, and adopts it.
   *
   * A wrong password fails to open the vault, which is the only check available:
   * there is no password hash to compare against, and a wrong key simply fails to
   * authenticate the ciphertext.
   */
  async restoreAccount(userId2, password) {
    const relay = this.relay;
    if (!relay || !relay.isConnected) return "connect before signing in";
    const vault = await relay.getVault(userId2);
    if (!vault) return `no account stored for ${userId2}`;
    const contents = await openVault(
      {
        salt: vault.salt,
        memoryKiB: vault.memoryKiB,
        passes: vault.passes,
        lanes: vault.lanes,
        generation: vault.generation,
        ciphertext: vault.ciphertext
      },
      password
    );
    if (!contents) return "wrong password, or the stored account is damaged";
    this.engine?.close();
    this.engine = VeilEngine.restore(contents.identity);
    await this.vault.storeIdentity(contents.identity);
    contents.identity.fill(0);
    if (contents.preKeyState) this.engine.importPreKeyState(contents.preKeyState);
    if (contents.peerRegistry) this.engine.importPeerRegistry(contents.peerRegistry);
    if (contents.groupState) this.engine.importGroupState(contents.groupState);
    await this.vault.storePreKeyState(this.engine.exportPreKeyState() ?? new Uint8Array());
    await this.vault.storeRegistry(this.engine.exportPeerRegistry() ?? new Uint8Array());
    const groupState = this.engine.exportGroupState();
    if (groupState) await this.vault.storeGroupState(groupState);
    this.selfUserId = userId2;
    await this.restorePeers();
    await this.restoreGroups();
    this.applyHistory(contents.history);
    this.setStatus(`restored ${userId2} from the account store`);
    this.notify();
    return null;
  }
  /** Every conversation, for the vault. */
  collectHistory() {
    const out = {};
    for (const [peerId, messages] of this.messages) out[peerId] = messages;
    for (const [groupId, messages] of this.groupMessages) {
      out[`group:${groupId}`] = messages;
    }
    return out;
  }
  applyHistory(history) {
    for (const [key, value] of Object.entries(history)) {
      if (key.startsWith("group:")) {
        this.groupMessages.set(key.slice("group:".length), value);
      } else {
        this.messages.set(key, value);
      }
    }
  }
  /**
   * Links this client to an existing account.
   *
   * The credential has to arrive over a channel that already authenticates the
   * account 闂?the whole point is that a relay cannot issue one 闂?so this takes
   * an already-signed blob and verifies it against the account keys.
   */
  async adoptDeviceCredential(credential, accountDhPub, accountSignPub) {
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
  flushQueue() {
    const relay = this.relay;
    if (!relay || !relay.isConnected) return;
    const stillQueued = [];
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
  async onDelivered(outboxId, peerId, frame2) {
    const engine = this.engine;
    if (!engine) return;
    const { plain, status } = engine.decrypt(peerId, frame2);
    switch (status) {
      case Status.OK:
        break;
      case Status.DUPLICATE:
        if (outboxId > 0n) this.relay?.acknowledge(outboxId);
        return;
      case Status.NO_SESSION:
        if (this.onGroupDelivered(peerId, frame2)) {
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
        state: 2 /* Ready */,
        devices: []
      };
      this.peers.push(peer);
      this.messages.set(peerId, []);
      await this.persistPeerIds();
      await this.persistRegistry();
    } else {
      peer.safetyNumber = engine.safetyNumber(peerId);
      peer.state = 2 /* Ready */;
    }
    this.appendMessage({
      id: this.nextMessageId++,
      peerId,
      outgoing: false,
      text: new TextDecoder().decode(plain),
      timestamp: Date.now(),
      state: "sent"
    });
    if (outboxId > 0n) this.relay?.acknowledge(outboxId);
    if (engine.needsPreKeyRefill(REFILL_LOW_WATER)) {
      await this.publishPreKeys();
    }
  }
  // ---- State ------------------------------------------------------------
  appendMessage(message) {
    const list = this.messages.get(message.peerId) ?? [];
    list.push(message);
    this.messages.set(message.peerId, list);
    void this.vault.storeMessages(message.peerId, list);
    this.notify();
  }
  updateMessageState(id, state) {
    for (const [, list] of this.messages) {
      const message = list.find((m) => m.id === id);
      if (!message) continue;
      message.state = state;
      void this.vault.storeMessages(message.peerId, list);
      break;
    }
    this.notify();
  }
  async persistSession(peerId) {
    const blob = this.engine?.exportSession(peerId);
    if (!blob) return;
    await this.vault.storeSession(peerId, blob);
    blob.fill(0);
  }
  async persistRegistry() {
    const blob = this.engine?.exportPeerRegistry();
    if (!blob) return;
    await this.vault.storeRegistry(blob);
    blob.fill(0);
  }
  async persistPeerIds() {
    await this.vault.storePeerIds(this.peers.map((p) => p.userId));
  }
  /** Re-reads the engine's view of every peer, after a reload or a change. */
  refreshStates() {
    const engine = this.engine;
    if (!engine) return;
    for (const peer of this.peers) {
      peer.state = engine.sessionState(peer.userId);
      peer.safetyNumber = engine.safetyNumber(peer.userId);
    }
    this.notify();
  }
  setLink(state) {
    this.linkState = state;
    this.notify();
  }
  setStatus(text) {
    this.statusText = text;
    this.notify();
  }
};

// src/main.ts
init_engine();

// src/qr.ts
var import_qrcode = __toESM(require_browser(), 1);
function encodeQr(data) {
  const qr = import_qrcode.default.create([{ data, mode: "byte" }], {
    errorCorrectionLevel: "L"
  });
  const size = qr.modules.size;
  const modules = new Uint8Array(size * size);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      modules[y * size + x] = qr.modules.get(y, x) ? 1 : 0;
    }
  }
  return { size, version: qr.version, modules };
}
function drawQr(ctx, code, options = {}) {
  const scale = options.scale ?? 5;
  const margin = options.margin ?? 4;
  const full = (code.size + margin * 2) * scale;
  ctx.fillStyle = options.light ?? "#ffffff";
  ctx.fillRect(0, 0, full, full);
  ctx.fillStyle = options.dark ?? "#000000";
  for (let y = 0; y < code.size; y++) {
    for (let x = 0; x < code.size; x++) {
      if (code.modules[y * code.size + x] === 1) {
        ctx.fillRect((x + margin) * scale, (y + margin) * scale, scale, scale);
      }
    }
  }
}

// src/selection.ts
function parseSelection(raw) {
  if (raw === null || raw.length === 0) return null;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    const looksTruncated = raw.startsWith("{") || raw.startsWith("[");
    return looksTruncated ? null : { kind: "peer", id: raw };
  }
  if (parsed === null || typeof parsed !== "object") return null;
  const candidate = parsed;
  if (candidate.kind !== "peer" && candidate.kind !== "group") return null;
  if (typeof candidate.id !== "string" || candidate.id.length === 0) return null;
  return { kind: candidate.kind, id: candidate.id };
}
function encodeSelection(selection) {
  return JSON.stringify(selection);
}

// src/main.ts
var $ = (id) => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el;
};
var app = new ChatApp();
var relayUrl = $("relay-url");
var userId = $("user-id");
var connectButton = $("connect");
var linkBadge = $("link-badge");
var statusLine = $("status");
var addPeerForm = $("add-peer");
var peerIdInput = $("peer-id");
var peerList = $("peer-list");
var peersEmpty = $("peers-empty");
var chat = $("chat");
var chatPlaceholder = $("chat-placeholder");
var chatPeer = $("chat-peer");
var toggleSafety = $("toggle-safety");
var safety = $("safety");
var safetyTitle = $("safety-title");
var safetyNumber = $("safety-number");
var transcript = $("transcript");
var composeForm = $("compose");
var draft = $("draft");
var sendButton = $("send");
var versionLabel = $("version");
var newGroupForm = $("new-group");
var groupIdInput = $("group-id");
var groupPanel = $("group-panel");
var groupEpoch = $("group-epoch");
var groupMembersForm = $("group-members");
var membersInput = $("members");
var groupHint = $("group-hint");
var openLink = $("open-link");
var linkDialog = $("link-dialog");
var tabLink = $("tab-link");
var tabApprove = $("tab-approve");
var paneLink = $("pane-link");
var paneApprove = $("pane-approve");
var generateRequest = $("generate-request");
var qrCanvas = $("qr-canvas");
var ownRequest = $("own-request");
var pastedCredential = $("pasted-credential");
var pastedIdentity = $("pasted-identity");
var adoptCredential = $("adopt-credential");
var incomingRequest = $("incoming-request");
var readRequest = $("read-request");
var requestDetails = $("request-details");
var requestUser = $("request-user");
var requestFingerprint = $("request-fingerprint");
var approveRequest = $("approve-request");
var issuedCredential = $("issued-credential");
var linkStatus = $("link-status");
var closeLink = $("close-link");
var openAccount = $("open-account");
var accountDialog = $("account-dialog");
var tabRegister = $("tab-register");
var tabRestore = $("tab-restore");
var paneRegister = $("pane-register");
var paneRestore = $("pane-restore");
var registerPassword = $("register-password");
var registerPassword2 = $("register-password2");
var passwordStrength = $("password-strength");
var registerButton = $("register");
var restoreId = $("restore-id");
var restorePassword = $("restore-password");
var restoreButton = $("restore");
var accountStatus = $("account-status");
var closeAccount = $("close-account");
var selected = null;
var STORAGE_KEY = "veil.selected";
async function main() {
  try {
    await app.init("wasm/veil.wasm");
  } catch (e) {
    showFatal(e instanceof Error ? e.message : "could not start");
    return;
  }
  versionLabel.textContent = `protocol engine ${await engineVersion()}`;
  restoreSelection();
  app.subscribe(render);
  relayUrl.value = localStorage.getItem("veil.relay") ?? defaultRelayUrl();
  userId.value = localStorage.getItem("veil.userId") ?? "";
  render();
}
async function engineVersion() {
  const { VeilEngine: VeilEngine2 } = await Promise.resolve().then(() => (init_engine(), engine_exports));
  return VeilEngine2.version();
}
function showFatal(message) {
  statusLine.hidden = false;
  statusLine.textContent = message;
  connectButton.disabled = true;
}
function render() {
  renderLink();
  renderStatus();
  renderPeers();
  renderChat();
}
function renderLink() {
  const link = app.link;
  linkBadge.textContent = link;
  linkBadge.className = `badge ${link}`;
  connectButton.textContent = link === "online" ? "Reconnect" : "Connect";
  connectButton.disabled = link === "connecting";
}
function renderStatus() {
  const status = app.status;
  statusLine.hidden = status === null;
  statusLine.textContent = status ?? "";
}
function renderPeers() {
  const peers = app.peerList;
  const groups = app.groupViews();
  peersEmpty.hidden = peers.length + groups.length > 0;
  const rows = [];
  for (const peer of peers) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.peerId = peer.userId;
    button.setAttribute(
      "aria-current",
      String(selected?.kind === "peer" && selected.id === peer.userId)
    );
    const name = document.createElement("span");
    name.className = "peer-name";
    name.textContent = peer.displayName;
    const state = document.createElement("span");
    state.className = "peer-state";
    state.textContent = peer.devices.length > 1 ? `${stateLabel(peer.state)}, ${peer.devices.length} devices` : stateLabel(peer.state);
    button.append(name, state);
    button.addEventListener("click", () => select({ kind: "peer", id: peer.userId }));
    item.append(button);
    rows.push(item);
  }
  for (const group of groups) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.groupId = group.groupId;
    button.setAttribute(
      "aria-current",
      String(selected?.kind === "group" && selected.id === group.groupId)
    );
    const name = document.createElement("span");
    name.className = "peer-name";
    name.textContent = `# ${group.groupId}`;
    const state = document.createElement("span");
    state.className = "peer-state";
    state.textContent = group.canSend ? `group, epoch ${group.epoch}` : `group, epoch ${group.epoch} - not a member`;
    button.append(name, state);
    button.addEventListener("click", () => select({ kind: "group", id: group.groupId }));
    item.append(button);
    rows.push(item);
  }
  peerList.replaceChildren(...rows);
  if (selected?.kind === "peer" && !peers.some((p) => p.userId === selected.id)) {
    selected = null;
  }
  if (selected?.kind === "group" && !groups.some((g) => g.groupId === selected.id)) {
    selected = null;
  }
}
function stateLabel(state) {
  switch (state) {
    case 2 /* Ready */:
      return "session ready";
    case 1 /* PinnedOnly */:
      return "identity pinned, no session";
    default:
      return "no session yet";
  }
}
function renderChat() {
  const showChat = selected !== null;
  chat.hidden = !showChat;
  chatPlaceholder.hidden = showChat;
  if (!selected) {
    groupPanel.hidden = true;
    return;
  }
  if (selected.kind === "group") {
    renderGroupChat(selected.id);
    return;
  }
  const peer = app.peerList.find((p) => p.userId === selected.id);
  if (!peer) return;
  groupPanel.hidden = true;
  chatPeer.textContent = peer.displayName;
  safetyTitle.textContent = `Safety number with ${peer.userId}`;
  if (peer.safetyNumber) {
    safetyNumber.textContent = peer.safetyNumber;
    safetyNumber.hidden = false;
  } else {
    safetyNumber.textContent = "No session yet: send or receive a message first.";
    safetyNumber.hidden = false;
  }
  renderTranscript(peer.userId);
  const canSend = peer.state === 2 /* Ready */ && app.link === "online";
  draft.disabled = !canSend;
  sendButton.disabled = !canSend;
}
function renderGroupChat(groupId) {
  const group = app.groupViews().find((g) => g.groupId === groupId);
  if (!group) return;
  chatPeer.textContent = `# ${group.groupId}`;
  safetyTitle.textContent = `Group ${group.groupId}`;
  safetyNumber.textContent = group.canSend ? "Sender Keys: one frame per message, regardless of group size." : "This client is not a member of this group.";
  safetyNumber.hidden = false;
  groupPanel.hidden = false;
  groupEpoch.textContent = `Epoch ${group.epoch} - members: ${group.members.join(", ")}`;
  groupHint.textContent = group.canSend ? "" : "A membership change re-keys every chain; nobody can send until each member publishes one.";
  if (document.activeElement !== membersInput) {
    membersInput.value = group.members.join(", ");
  }
  renderGroupTranscript(groupId);
  const canSend = group.canSend && app.link === "online";
  draft.disabled = !canSend;
  sendButton.disabled = !canSend;
}
function renderGroupTranscript(groupId) {
  const messages = app.groupMessagesFor(groupId);
  const format = new Intl.DateTimeFormat(void 0, {
    hour: "2-digit",
    minute: "2-digit"
  });
  transcript.replaceChildren(
    ...messages.map((message) => {
      const item = document.createElement("li");
      item.className = `bubble ${message.outgoing ? "out" : "in"}`;
      const text = document.createElement("div");
      text.textContent = message.text;
      const meta = document.createElement("div");
      meta.className = "meta";
      const who = message.outgoing ? "you" : message.senderId;
      meta.textContent = `${who} - ${format.format(message.at)}`;
      item.append(text, meta);
      return item;
    })
  );
  transcript.scrollTop = transcript.scrollHeight;
}
function renderTranscript(peerId) {
  const messages = app.messagesFor(peerId);
  const format = new Intl.DateTimeFormat(void 0, {
    hour: "2-digit",
    minute: "2-digit"
  });
  transcript.replaceChildren(
    ...messages.map((message) => {
      const item = document.createElement("li");
      item.className = `bubble ${message.outgoing ? "out" : "in"}`;
      const text = document.createElement("div");
      text.textContent = message.text;
      const meta = document.createElement("div");
      meta.className = "meta";
      if (message.state !== "sent" && message.outgoing) {
        const state = document.createElement("span");
        state.className = "state";
        state.textContent = message.state === "queued" ? "sending" : "not sent";
        meta.append(state);
      }
      const time = document.createElement("time");
      time.dateTime = new Date(message.timestamp).toISOString();
      time.textContent = format.format(message.timestamp);
      meta.append(time);
      item.append(text, meta);
      return item;
    })
  );
  transcript.scrollTop = transcript.scrollHeight;
}
function select(next) {
  selected = next;
  localStorage.setItem(STORAGE_KEY, encodeSelection(next));
  render();
}
function restoreSelection() {
  selected = parseSelection(localStorage.getItem(STORAGE_KEY));
}
connectButton.addEventListener("click", () => {
  const url = relayUrl.value.trim();
  const id = userId.value.trim();
  if (!url || !id) return;
  localStorage.setItem("veil.relay", url);
  localStorage.setItem("veil.userId", id);
  void app.connect(url, id);
  setTimeout(() => app.refreshStates(), 500);
});
addPeerForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const id = peerIdInput.value.trim();
  if (!id) return;
  app.addPeer(id);
  peerIdInput.value = "";
  select({ kind: "peer", id });
});
newGroupForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const id = groupIdInput.value.trim();
  if (!id) return;
  void app.createGroup(id).then((ok) => {
    if (!ok) return;
    groupIdInput.value = "";
    select({ kind: "group", id });
  });
});
groupMembersForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (selected?.kind !== "group") return;
  const members = membersInput.value.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  if (members.length === 0) return;
  void app.setGroupMembers(selected.id, members);
});
composeForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!selected) return;
  const text = draft.value;
  if (!text.trim()) return;
  draft.value = "";
  if (selected.kind === "peer") {
    app.send(selected.id, text);
  } else {
    void app.sendToGroup(selected.id, text);
  }
});
draft.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    composeForm.requestSubmit();
  }
});
toggleSafety.addEventListener("click", () => {
  const open = safety.hidden;
  safety.hidden = !open;
  toggleSafety.setAttribute("aria-expanded", String(open));
  toggleSafety.textContent = open ? "Hide code" : "Verify";
});
function showLinkStatus(text) {
  linkStatus.hidden = text === null;
  linkStatus.textContent = text ?? "";
}
function selectTab(linkThis) {
  paneLink.hidden = !linkThis;
  paneApprove.hidden = linkThis;
  tabLink.classList.toggle("selected", linkThis);
  tabApprove.classList.toggle("selected", !linkThis);
  showLinkStatus(null);
}
openLink.addEventListener("click", () => {
  linkDialog.showModal();
  selectTab(true);
});
closeLink.addEventListener("click", () => linkDialog.close());
tabLink.addEventListener("click", () => selectTab(true));
tabApprove.addEventListener("click", () => selectTab(false));
generateRequest.addEventListener("click", () => {
  const request = app.linkingRequest();
  if (!request) {
    showLinkStatus(
      "this browser has no device identity yet: connect first, then generate"
    );
    return;
  }
  const text = toBase64(request);
  ownRequest.value = text;
  ownRequest.hidden = false;
  try {
    const code = encodeQr(new TextEncoder().encode(text));
    qrCanvas.width = (code.size + 8) * 5;
    qrCanvas.height = (code.size + 8) * 5;
    const ctx = qrCanvas.getContext("2d");
    if (ctx) drawQr(ctx, code, { scale: 5, margin: 4 });
    qrCanvas.hidden = false;
  } catch (e) {
    qrCanvas.hidden = true;
    showLinkStatus(
      `too large for a QR code (${request.length} bytes); use the text below`
    );
  }
  showLinkStatus(null);
});
readRequest.addEventListener("click", () => {
  const bytes = fromBase64(incomingRequest.value);
  if (!bytes) {
    showLinkStatus("that is not a request");
    return;
  }
  const parsed = app.readLinkingRequest(bytes);
  if (!parsed) {
    showLinkStatus("that request could not be read");
    return;
  }
  requestUser.textContent = parsed.userId;
  requestFingerprint.textContent = parsed.fingerprint;
  requestDetails.hidden = false;
  showLinkStatus(null);
});
approveRequest.addEventListener("click", () => {
  const bytes = fromBase64(incomingRequest.value);
  if (!bytes) {
    showLinkStatus("that is not a request");
    return;
  }
  const credential = app.approveLinking(bytes);
  if (!credential) {
    showLinkStatus("only the device that holds the account key can approve");
    return;
  }
  issuedCredential.value = toBase64(credential);
  issuedCredential.hidden = false;
  showLinkStatus("approved. Send this to the new device.");
});
adoptCredential.addEventListener("click", () => {
  const credential = fromBase64(pastedCredential.value);
  const identity = fromBase64(pastedIdentity.value);
  if (!credential || !identity) {
    showLinkStatus("paste both the credential and the account identity");
    return;
  }
  if (identity.length !== 64) {
    showLinkStatus("the account identity must be 64 bytes");
    return;
  }
  void app.adoptLinking(credential, identity.slice(0, 32), identity.slice(32, 64)).then((ok) => {
    showLinkStatus(
      ok ? "this device is now part of the account" : "that credential was refused"
    );
    if (ok) render();
  });
});
function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
function fromBase64(text) {
  const cleaned = text.replace(/\s+/g, "");
  if (cleaned.length === 0) return null;
  try {
    const binary = atob(cleaned);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}
function defaultRelayUrl() {
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${location.host}/ws`;
}
function showAccountStatus(text) {
  accountStatus.hidden = text === null;
  accountStatus.textContent = text ?? "";
}
function selectAccountTab(create) {
  paneRegister.hidden = !create;
  paneRestore.hidden = create;
  tabRegister.classList.toggle("selected", create);
  tabRestore.classList.toggle("selected", !create);
  showAccountStatus(null);
}
openAccount.addEventListener("click", () => {
  restoreId.value = userId.value.trim();
  accountDialog.showModal();
  selectAccountTab(true);
});
closeAccount.addEventListener("click", () => accountDialog.close());
tabRegister.addEventListener("click", () => selectAccountTab(true));
tabRestore.addEventListener("click", () => selectAccountTab(false));
registerPassword.addEventListener("input", () => {
  const password = registerPassword.value;
  const problem = checkPassword(password);
  passwordStrength.textContent = problem ?? `strength: ${describeStrength(password)}`;
  passwordStrength.style.color = problem ? "var(--danger, #c62828)" : "";
});
registerButton.addEventListener("click", () => {
  const password = registerPassword.value;
  if (password !== registerPassword2.value) {
    showAccountStatus("the two passwords do not match");
    return;
  }
  const problem = checkPassword(password);
  if (problem) {
    showAccountStatus(problem);
    return;
  }
  showAccountStatus("deriving the key (this takes a moment)...");
  void app.createAccount(password).then((error) => {
    showAccountStatus(error ?? "account created");
    if (!error) {
      registerPassword.value = "";
      registerPassword2.value = "";
      passwordStrength.textContent = "";
    }
  });
});
restoreButton.addEventListener("click", () => {
  const id = restoreId.value.trim();
  if (!id) {
    showAccountStatus("enter the id to restore");
    return;
  }
  showAccountStatus("deriving the key (this takes a moment)...");
  void app.restoreAccount(id, restorePassword.value).then((error) => {
    showAccountStatus(error ?? "signed in");
    if (!error) {
      userId.value = id;
      restorePassword.value = "";
      render();
    }
  });
});
void main();
