var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/engine.ts
var engine_exports = {};
__export(engine_exports, {
  SessionState: () => SessionState,
  Status: () => Status,
  VeilEngine: () => VeilEngine
});
var Status, SessionState, utf8, VeilEngine;
var init_engine = __esm({
  "src/engine.ts"() {
    "use strict";
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
       * `wasmUrl` is a URL the page can fetch 鈥?in the browser it is a relative
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
          jsUrl
        )).default;
        const mod = await factory({
          // Node cannot fetch a file:// URL, so a runner may hand the bytes in
          // directly. In a browser this is undefined and the module fetches.
          ...options.wasmBinary ? { wasmBinary: options.wasmBinary } : {},
          locateFile: (path) => path.endsWith(".wasm") ? wasmUrl : path,
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
    };
  }
});

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
  DEVICES: 15
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
   * anything sent to a group they are still in 閳?indistinguishable from having
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
   * Every chain is discarded and the epoch moves, so nobody 閳?including this
   * client 閳?can send until each member republishes a chain. That is the point:
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
   * by verifying the founder's safety number out of band 閳?the same trust anchor
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
      at: Date.now()
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
          at: Date.now()
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
  /**
   * Links this client to an existing account.
   *
   * The credential has to arrive over a channel that already authenticates the
   * account — the whole point is that a relay cannot issue one — so this takes
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
var selectedPeerId = null;
var STORAGE_KEY = "veil.selectedPeer";
async function main() {
  try {
    await app.init("wasm/veil.wasm");
  } catch (e) {
    showFatal(e instanceof Error ? e.message : "could not start");
    return;
  }
  versionLabel.textContent = `protocol engine ${await engineVersion()}`;
  selectedPeerId = localStorage.getItem(STORAGE_KEY);
  app.subscribe(render);
  relayUrl.value = localStorage.getItem("veil.relay") ?? relayUrl.value;
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
  peersEmpty.hidden = peers.length > 0;
  peerList.replaceChildren(
    ...peers.map((peer) => {
      const item = document.createElement("li");
      const button = document.createElement("button");
      button.type = "button";
      button.dataset.peerId = peer.userId;
      button.setAttribute(
        "aria-current",
        String(peer.userId === selectedPeerId)
      );
      const name = document.createElement("span");
      name.className = "peer-name";
      name.textContent = peer.displayName;
      const state = document.createElement("span");
      state.className = "peer-state";
      state.textContent = stateLabel(peer.state);
      button.append(name, state);
      button.addEventListener("click", () => selectPeer(peer.userId));
      item.append(button);
      return item;
    })
  );
  if (selectedPeerId && !peers.some((p) => p.userId === selectedPeerId)) {
    selectedPeerId = null;
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
  const peer = app.peerList.find((p) => p.userId === selectedPeerId);
  const showChat = peer !== void 0;
  chat.hidden = !showChat;
  chatPlaceholder.hidden = showChat;
  if (!peer) return;
  chatPeer.textContent = peer.displayName;
  safetyTitle.textContent = `Safety number with ${peer.userId}`;
  if (peer.safetyNumber) {
    safetyNumber.textContent = peer.safetyNumber;
    safetyNumber.hidden = false;
  } else {
    safetyNumber.textContent = "No session yet \u2014 send or receive a message first.";
    safetyNumber.hidden = false;
  }
  renderTranscript(peer.userId);
  const canSend = peer.state === 2 /* Ready */ && app.link === "online";
  draft.disabled = !canSend;
  sendButton.disabled = !canSend;
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
function selectPeer(peerId) {
  selectedPeerId = peerId;
  localStorage.setItem(STORAGE_KEY, peerId);
  render();
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
  selectPeer(id);
});
composeForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!selectedPeerId) return;
  const text = draft.value;
  draft.value = "";
  app.send(selectedPeerId, text);
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
void main();
