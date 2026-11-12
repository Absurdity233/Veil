/**
 * The WebAssembly build of the protocol engine, behind the C ABI.
 *
 * The module is the same C++ the phone runs. Nothing in this file implements
 * any cryptography: it allocates buffers in the wasm heap, calls the ABI, and
 * copies the result back out. That is the whole design goal 鈥?one engine, three
 * clients, no second implementation to drift.
 *
 * Entropy deserves a note. A wasm module has no syscall and no /dev/urandom, so
 * before any engine is created this module installs crypto.getRandomValues as
 * the engine's RNG. If the browser refuses it 鈥?a non-secure origin disables it 鈥? * key generation fails rather than proceeding with predictable bytes.
 */

interface EmscriptenModule {
  HEAPU8: Uint8Array;
  _malloc(size: number): number;
  _free(ptr: number): void;
  _veil_engine_new(): number;
  _veil_engine_restore(secrets: number, size: number): number;
  _veil_engine_free(handle: number): void;
  _veil_identity_secrets(handle: number, out: number, size: number): number;
  _veil_identity_public(handle: number, out: number, size: number): number;
  _veil_identity_binding(handle: number, out: number, size: number): number;
  _veil_sign_challenge(
    handle: number, challenge: number, size: number, out: number, outSize: number,
  ): number;
  _veil_rotate_prekeys(handle: number, out: number, size: number): number;
  _veil_export_prekey_set(handle: number, out: number, size: number): number;
  _veil_needs_prekey_refill(handle: number, lowWater: number): number;
  _veil_export_prekey_state(handle: number, out: number, size: number): number;
  _veil_import_prekey_state(handle: number, data: number, size: number): number;
  _veil_measure_session(handle: number, peer: number): number;
  _veil_establish_outbound(handle: number, peer: number, bundle: number, size: number): number;
  _veil_session_state(handle: number, peer: number): number;
  _veil_export_session(handle: number, peer: number, out: number, size: number): number;
  _veil_import_session(handle: number, peer: number, data: number, size: number): number;
  _veil_drop_session(handle: number, peer: number): void;
  _veil_export_peer_registry(handle: number, out: number, size: number): number;
  _veil_import_peer_registry(handle: number, data: number, size: number): number;
  _veil_encrypt(
    handle: number, peer: number, plain: number, plainSize: number,
    out: number, outSize: number,
  ): number;
  _veil_decrypt(
    handle: number, peer: number, frame: number, frameSize: number,
    out: number, outSize: number, outLen: number,
  ): number;
  _veil_safety_number(handle: number, peer: number, out: number, size: number): number;
  _veil_version(major: number, minor: number, patch: number): void;
  _veil_install_web_rng(): number;
  _veil_web_rng_ready(): number;

  // Multi-device.
  _veil_init_device(handle: number, userId: number): number;
  _veil_device_id(handle: number, out: number, size: number): number;
  _veil_device_credential(handle: number, out: number, size: number): number;
  _veil_adopt_device_credential(
    handle: number, credential: number, size: number,
    accountDhPub: number, accountSignPub: number,
  ): number;
  _veil_adopt_device_list(
    handle: number, userId: number, version: number,
    data: number, size: number, accountDhPub: number, accountSignPub: number,
  ): number;
  _veil_peer_devices(handle: number, userId: number, out: number, size: number): number;
  _veil_peer_device_version(handle: number, userId: number): number;
  _veil_device_fingerprint(
    credential: number, size: number, out: number, outSize: number,
  ): number;
  _veil_establish_with_devices(
    handle: number, userId: number,
    deviceIds: number, deviceIdsSize: number,
    bundles: number, bundlesSize: number,
    failed: number, failedSize: number,
  ): number;
  _veil_encrypt_to_account(
    handle: number, userId: number, plain: number, plainSize: number,
    out: number, outSize: number,
  ): number;

  // Groups.
  _veil_create_group(handle: number, groupId: number): number;
  _veil_set_group_members(
    handle: number, groupId: number, members: number, membersSize: number,
  ): number;
  _veil_export_membership(
    handle: number, groupId: number, out: number, outSize: number,
  ): number;
  _veil_adopt_membership(
    handle: number, data: number, size: number, founderSignPub: number,
  ): number;
  _veil_group_epoch(handle: number, groupId: number): number;
  _veil_group_members(
    handle: number, groupId: number, out: number, outSize: number,
  ): number;
  _veil_is_group_member(handle: number, groupId: number): number;
  _veil_export_sender_key(
    handle: number, groupId: number, epoch: number, out: number, outSize: number,
  ): number;
  _veil_adopt_sender_key(
    handle: number, data: number, size: number,
    expectedSender: number, senderSignPub: number,
  ): number;
  _veil_encrypt_to_group(
    handle: number, groupId: number, plain: number, plainSize: number,
    out: number, outSize: number,
  ): number;
  _veil_decrypt_from_group(
    handle: number, groupId: number, data: number, size: number,
    out: number, outSize: number, outLen: number,
  ): number;
  _veil_export_group_state(handle: number, out: number, outSize: number): number;
  _veil_import_group_state(handle: number, data: number, size: number): number;

  // Device list freshness.
  _veil_set_clock(handle: number, nowMs: number): void;
  _veil_device_list_needs_refresh(
    handle: number, userId: number, stalenessMs: number,
  ): number;
  _veil_note_send_failed(handle: number, userId: number): void;
  _veil_note_device_list_fetched(handle: number, userId: number): void;

  // Invitations and linking.
  _veil_encode_invite(handle: number, groupId: number, out: number, outSize: number): number;
  _veil_looks_like_invite(data: number, size: number): number;
  _veil_accept_invite(
    handle: number, data: number, size: number, founder: number,
    founderSignPub: number, outGroupId: number, outSize: number,
  ): number;
  _veil_linking_request(handle: number, out: number, outSize: number): number;
  _veil_read_linking_request(
    data: number, size: number, userId: number, userIdSize: number,
    fingerprint: number, fingerprintSize: number,
  ): number;
  _veil_approve_linking(
    handle: number, request: number, requestSize: number,
    issuedAt: number, out: number, outSize: number,
  ): number;
  _veil_account_sign_public(handle: number, out: number, outSize: number): number;
  _veil_peer_device_sign_pub(
    handle: number, peer: number, out: number, outSize: number,
  ): number;

  _veil_peer_identity(
    handle: number, peer: number, out: number, outSize: number,
  ): number;
}

declare const createVeilModule: (opts?: unknown) => Promise<EmscriptenModule>;

/** Status codes, mirroring `veil_c.h`. */
export const Status = {
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
  ERR_INTERNAL: -7,
} as const;

export type StatusCode = (typeof Status)[keyof typeof Status];

/**
 * Why a peer's device list should be re-fetched.
 *
 * Mirrors the C ABI's constants. `SendFailed` outranks `Stale` in the engine's
 * answer because it is evidence rather than a guess.
 */
export enum RefreshReason {
  None = 0,
  Stale = 1,
  SendFailed = 2,
  Unknown = 3,
}

export enum SessionState {
  NoPeer = 0,
  PinnedOnly = 1,
  Ready = 2,
}

const utf8 = new TextEncoder();

/**
 * A handle plus the scratch space a call needs.
 *
 * wasm has no garbage collector and this module deliberately does not hand out
 * memory to JavaScript, so every call allocates inside the wasm heap, copies in,
 * calls, copies out, and frees. The buffers are reused across calls to keep a
 * chat from churning the heap.
 */
export class VeilEngine {
  private static module: EmscriptenModule | null = null;

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
  static async load(
    wasmUrl: string,
    options: { jsUrl?: string; wasmBinary?: ArrayBuffer } = {},
  ): Promise<void> {
    if (VeilEngine.module) return;

    const jsUrl = options.jsUrl ?? wasmUrl.replace(/\.wasm$/, ".js");
    const factory = (await import(/* @vite-ignore */ jsUrl))
      .default as typeof createVeilModule;

    const mod = await factory({
      // Node cannot fetch a file:// URL, so a runner may hand the bytes in
      // directly. In a browser this is undefined and the module fetches.
      ...(options.wasmBinary ? { wasmBinary: options.wasmBinary } : {}),
      locateFile: (path: string) => (path.endsWith(".wasm") ? wasmUrl : path),
      print: () => {},
      printErr: () => {},
    });

    // Refuse to start without entropy. The check is not paranoia: an insecure
    // origin silently disables crypto.getRandomValues, and generating keys from
    // whatever is left would be worse than showing an error.
    if (!mod._veil_web_rng_ready()) {
      throw new Error(
        "no secure randomness available: serve this page over https or from localhost",
      );
    }
    mod._veil_install_web_rng();

    VeilEngine.module = mod;
  }

  /** The ABI version, so a stale .wasm is loud rather than subtle. */
  static version(): string {
    const mod = VeilEngine.require();
    const ptr = mod._malloc(12);
    try {
      mod._veil_version(ptr, ptr + 4, ptr + 8);
      const view = new DataView(mod.HEAPU8.buffer, ptr, 12);
      return `${view.getInt32(0, true)}.${view.getInt32(4, true)}.${view.getInt32(8, true)}`;
    } finally {
      mod._free(ptr);
    }
  }

  static create(): VeilEngine {
    const handle = VeilEngine.require()._veil_engine_new();
    if (handle === 0) {
      throw new Error("could not create the engine (no entropy source?)");
    }
    return new VeilEngine(handle);
  }

  static restore(secrets: Uint8Array): VeilEngine {
    const mod = VeilEngine.require();
    const ptr = mod._malloc(secrets.length);
    try {
      mod.HEAPU8.set(secrets, ptr);
      const handle = mod._veil_engine_restore(ptr, secrets.length);
      if (handle === 0) throw new Error("could not restore the identity");
      return new VeilEngine(handle);
    } finally {
      mod._free(ptr);
    }
  }

  private static require(): EmscriptenModule {
    if (!VeilEngine.module) throw new Error("call VeilEngine.load() first");
    return VeilEngine.module;
  }

  private constructor(private readonly handle: number) {}

  // ---- Identity ---------------------------------------------------------

  identitySecrets(): Uint8Array {
    return this.produceFixed(96, (mod, out) =>
      mod._veil_identity_secrets(this.handle, out, 96));
  }

  publicIdentity(): Uint8Array {
    return this.produceFixed(64, (mod, out) =>
      mod._veil_identity_public(this.handle, out, 64));
  }

  signChallenge(challenge: Uint8Array): Uint8Array {
    const mod = VeilEngine.require();
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

  rotatePreKeys(): Uint8Array {
    return this.produceVariable(4096, (mod, out, size) =>
      mod._veil_rotate_prekeys(this.handle, out, size));
  }

  exportPreKeySet(): Uint8Array {
    return this.produceVariable(4096, (mod, out, size) =>
      mod._veil_export_prekey_set(this.handle, out, size));
  }

  needsPreKeyRefill(lowWater: number): boolean {
    return VeilEngine.require()._veil_needs_prekey_refill(this.handle, lowWater) === 1;
  }

  exportPreKeyState(): Uint8Array {
    return this.produceVariable(8192, (mod, out, size) =>
      mod._veil_export_prekey_state(this.handle, out, size));
  }

  importPreKeyState(state: Uint8Array): boolean {
    return this.callWithBlob(state, (mod, ptr, size) =>
      mod._veil_import_prekey_state(this.handle, ptr, size)) === Status.OK;
  }

  // ---- Sessions ---------------------------------------------------------

  establishOutbound(peer: string, bundle: Uint8Array): StatusCode {
    const mod = VeilEngine.require();
    const p = this.withPeer(peer, (ptr) => {
      const b = mod._malloc(bundle.length);
      try {
        mod.HEAPU8.set(bundle, b);
        return mod._veil_establish_outbound(this.handle, ptr, b, bundle.length);
      } finally {
        mod._free(b);
      }
    });
    return p as StatusCode;
  }

  sessionState(peer: string): SessionState {
    const mod = VeilEngine.require();
    const code = this.withPeer(peer, (ptr) => mod._veil_session_state(this.handle, ptr));
    return code === 2 ? SessionState.Ready : code === 1 ? SessionState.PinnedOnly
      : SessionState.NoPeer;
  }

  exportSession(peer: string): Uint8Array | null {
    const mod = VeilEngine.require();
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

  importSession(peer: string, blob: Uint8Array): boolean {
    const mod = VeilEngine.require();
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

  dropSession(peer: string): void {
    const mod = VeilEngine.require();
    this.withPeer(peer, (ptr) => {
      mod._veil_drop_session(this.handle, ptr);
      return 0;
    });
  }

  exportPeerRegistry(): Uint8Array {
    return this.produceVariable(65536, (mod, out, size) =>
      mod._veil_export_peer_registry(this.handle, out, size));
  }

  importPeerRegistry(blob: Uint8Array): boolean {
    return this.callWithBlob(blob, (mod, ptr, size) =>
      mod._veil_import_peer_registry(this.handle, ptr, size)) === Status.OK;
  }

  // ---- Messaging --------------------------------------------------------

  encrypt(peer: string, plain: Uint8Array): Uint8Array | null {
    const mod = VeilEngine.require();
    return this.withPeer(peer, (ptr) => {
      // Plaintext plus the largest frame overhead (prekey header + ratchet
      // header + MAC), so a first frame fits without a second attempt.
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
  decrypt(peer: string, frame: Uint8Array): { plain: Uint8Array | null; status: StatusCode } {
    const mod = VeilEngine.require();
    return this.withPeer(peer, (ptr) => {
      const capacity = frame.length + 64;
      const f = mod._malloc(frame.length);
      const out = mod._malloc(capacity);
      const len = mod._malloc(4);
      try {
        mod.HEAPU8.set(frame, f);
        const status = mod._veil_decrypt(
          this.handle, ptr, f, frame.length, out, capacity, len,
        );
        if (status !== Status.OK) return { plain: null, status: status as StatusCode };

        const n = new DataView(mod.HEAPU8.buffer, len, 4).getUint32(0, true);
        return { plain: mod.HEAPU8.slice(out, out + n), status: Status.OK };
      } finally {
        mod._free(f);
        mod._free(out);
        mod._free(len);
      }
    });
  }

  safetyNumber(peer: string): string | null {
    const mod = VeilEngine.require();
    return this.withPeer(peer, (ptr) => {
      const out = mod._malloc(64);
      try {
        if (mod._veil_safety_number(this.handle, ptr, out, 64) !== Status.OK) return null;
        // The ABI writes a NUL-terminated ASCII string.
        let end = out;
        while (end < out + 64 && mod.HEAPU8[end] !== 0) end++;
        return new TextDecoder().decode(mod.HEAPU8.slice(out, end));
      } finally {
        mod._free(out);
      }
    });
  }

  close(): void {
    VeilEngine.require()._veil_engine_free(this.handle);
  }

  // ---- Groups -----------------------------------------------------------
  //
  // Sender Keys. One message, one frame, regardless of group size. See
  // docs/group.md, including what a group gives up to be cheap.

  createGroup(groupId: string): boolean {
    const mod = VeilEngine.require();
    return this.withPeer(groupId, (ptr) =>
      mod._veil_create_group(this.handle, ptr) === Status.OK);
  }

  /**
   * Replaces the member list and bumps the epoch.
   *
   * Every live chain is discarded: a removed member holds the old chain key, and
   * re-keying is the only thing that stops them reading what follows.
   */
  setGroupMembers(groupId: string, members: string[]): number {
    const mod = VeilEngine.require();
    const joined = members.join("\u0000");
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

  groupEpoch(groupId: string): number {
    const mod = VeilEngine.require();
    return this.withPeer(groupId, (ptr) => mod._veil_group_epoch(this.handle, ptr));
  }

  groupMembers(groupId: string): string[] {
    const mod = VeilEngine.require();
    return this.withPeer(groupId, (ptr) => {
      const need = mod._veil_group_members(this.handle, ptr, 0, 0);
      if (need <= 0) return [];

      const out = mod._malloc(need);
      try {
        if (mod._veil_group_members(this.handle, ptr, out, need) !== need) return [];
        return new TextDecoder().decode(mod.HEAPU8.slice(out, out + need))
          .split("\u0000").filter((s) => s.length > 0);
      } finally {
        mod._free(out);
      }
    });
  }

  isGroupMember(groupId: string): boolean {
    const mod = VeilEngine.require();
    return this.withPeer(groupId, (ptr) =>
      mod._veil_is_group_member(this.handle, ptr) === 1);
  }

  /** The signed member list, to hand to members. */
  exportMembership(groupId: string): Uint8Array | null {
    return this.withPeer(groupId, (ptr) =>
      this.produceVariable(2048, (mod, out, size) =>
        mod._veil_export_membership(this.handle, ptr, out, size)));
  }

  adoptMembership(data: Uint8Array, founderSignPub: Uint8Array): StatusCode {
    const mod = VeilEngine.require();
    if (founderSignPub.length !== 32) return Status.BAD_SIGNATURE;

    const d = mod._malloc(data.length || 1);
    const key = mod._malloc(32);
    try {
      if (data.length) mod.HEAPU8.set(data, d);
      mod.HEAPU8.set(founderSignPub, key);
      return mod._veil_adopt_membership(this.handle, d, data.length, key) as StatusCode;
    } finally {
      mod._free(d);
      mod._free(key);
    }
  }

  /** This device's chain for the current epoch, signed by its device key. */
  exportSenderKey(groupId: string, epoch = 0): Uint8Array | null {
    return this.withPeer(groupId, (ptr) =>
      this.produceVariable(512, (mod, out, size) =>
        mod._veil_export_sender_key(this.handle, ptr, epoch, out, size)));
  }

  adoptSenderKey(
    data: Uint8Array, expectedSender: string, senderSignPub: Uint8Array,
  ): StatusCode {
    const mod = VeilEngine.require();
    if (senderSignPub.length !== 32) return Status.BAD_SIGNATURE;

    const d = mod._malloc(data.length || 1);
    const key = mod._malloc(32);
    try {
      if (data.length) mod.HEAPU8.set(data, d);
      mod.HEAPU8.set(senderSignPub, key);

      return this.withPeer(expectedSender, (ptr) =>
        mod._veil_adopt_sender_key(this.handle, d, data.length, ptr, key) as StatusCode);
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
  encryptToGroup(groupId: string, plain: Uint8Array): Uint8Array | null {
    const mod = VeilEngine.require();
    return this.withPeer(groupId, (ptr) => {
      const p = mod._malloc(plain.length || 1);
      try {
        if (plain.length) mod.HEAPU8.set(plain, p);

        const need = mod._veil_encrypt_to_group(this.handle, ptr, p, plain.length, 0, 0);
        if (need <= 0) return null;

        const out = mod._malloc(need);
        try {
          const total = mod._veil_encrypt_to_group(
            this.handle, ptr, p, plain.length, out, need,
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

  decryptFromGroup(groupId: string, record: Uint8Array):
    { status: StatusCode; plain: Uint8Array | null } {
    const mod = VeilEngine.require();
    return this.withPeer(groupId, (ptr) => {
      const d = mod._malloc(record.length || 1);
      // The plaintext is always smaller than the record that carries it, so
      // sizing from the frame needs no probe 鈥?which matters because a probe
      // must not consume the message key.
      const out = mod._malloc(record.length || 1);
      const outLen = mod._malloc(4);
      try {
        if (record.length) mod.HEAPU8.set(record, d);

        const status = mod._veil_decrypt_from_group(
          this.handle, ptr, d, record.length, out, record.length, outLen,
        ) as StatusCode;
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
  initDevice(userId: string): boolean {
    const mod = VeilEngine.require();
    return this.withPeer(userId, (ptr) =>
      mod._veil_init_device(this.handle, ptr) === Status.OK);
  }

  /** 32 bytes, or null when no device is initialised. */
  deviceId(): Uint8Array | null {
    const mod = VeilEngine.require();
    const out = mod._malloc(32);
    try {
      const n = mod._veil_device_id(this.handle, out, 32);
      return n === 32 ? mod.HEAPU8.slice(out, out + n) : null;
    } finally {
      mod._free(out);
    }
  }

  /** This device's credential, ready to publish. */
  deviceCredential(): Uint8Array | null {
    return this.produceVariable(512, (mod, out, size) =>
      mod._veil_device_credential(this.handle, out, size));
  }

  /**
   * Adopts a credential the existing device signed for this one.
   *
   * The endorsement is verified against the account keys passed in, so a relay
   * cannot hand over a credential that was never issued.
   */
  adoptDeviceCredential(
    credential: Uint8Array,
    accountDhPub: Uint8Array,
    accountSignPub: Uint8Array,
  ): boolean {
    const mod = VeilEngine.require();
    if (accountDhPub.length !== 32 || accountSignPub.length !== 32) return false;

    const c = mod._malloc(credential.length || 1);
    const dh = mod._malloc(32);
    const sign = mod._malloc(32);
    try {
      if (credential.length) mod.HEAPU8.set(credential, c);
      mod.HEAPU8.set(accountDhPub, dh);
      mod.HEAPU8.set(accountSignPub, sign);
      return mod._veil_adopt_device_credential(this.handle, c, credential.length, dh, sign) ===
        Status.OK;
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
  adoptDeviceList(
    userId: string,
    version: number,
    entries: Uint8Array,
    accountDhPub: Uint8Array,
    accountSignPub: Uint8Array,
  ): StatusCode {
    const mod = VeilEngine.require();
    if (accountDhPub.length !== 32 || accountSignPub.length !== 32) return Status.BAD_BUNDLE;

    return this.withPeer(userId, (ptr) => {
      const d = mod._malloc(entries.length || 1);
      const dh = mod._malloc(32);
      const sign = mod._malloc(32);
      try {
        if (entries.length) mod.HEAPU8.set(entries, d);
        mod.HEAPU8.set(accountDhPub, dh);
        mod.HEAPU8.set(accountSignPub, sign);
        return mod._veil_adopt_device_list(
          this.handle, ptr, version, d, entries.length, dh, sign,
        ) as StatusCode;
      } finally {
        mod._free(d);
        mod._free(dh);
        mod._free(sign);
      }
    });
  }

  /** The hex device ids known for a peer. */
  peerDevices(userId: string): string[] {    const mod = VeilEngine.require();
    return this.withPeer(userId, (ptr) => {
      const need = mod._veil_peer_devices(this.handle, ptr, 0, 0);
      if (need <= 0) return [];

      const out = mod._malloc(need);
      try {
        if (mod._veil_peer_devices(this.handle, ptr, out, need) !== need) return [];
        const text = new TextDecoder().decode(mod.HEAPU8.slice(out, out + need));
        return text.split("\u0000").filter((s) => s.length > 0);
      } finally {
        mod._free(out);
      }
    });
  }

  /** The version of the list held for a peer; 0 when none. */
  peerDeviceVersion(userId: string): number {
    const mod = VeilEngine.require();
    return this.withPeer(userId, (ptr) => mod._veil_peer_device_version(this.handle, ptr));
  }

  /**
   * Starts sessions with each device of a peer.
   *
   * Both blobs are already in the ABI's shape by the time they arrive here; the
   * caller builds them because it is the one that knows which bundles it managed
   * to fetch.
   */
  establishWithDevices(
    userId: string, deviceIds: Uint8Array, bundles: Uint8Array,
  ): number {
    const mod = VeilEngine.require();
    return this.withPeer(userId, (ptr) => {
      const idsPtr = mod._malloc(deviceIds.length || 1);
      const bundlesPtr = mod._malloc(bundles.length || 1);
      const failed = mod._malloc(1024);
      try {
        if (deviceIds.length) mod.HEAPU8.set(deviceIds, idsPtr);
        if (bundles.length) mod.HEAPU8.set(bundles, bundlesPtr);

        return mod._veil_establish_with_devices(
          this.handle, ptr, idsPtr, deviceIds.length,
          bundlesPtr, bundles.length, failed, 1024,
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
  encryptToAccount(userId: string, plain: Uint8Array):
    Array<{ deviceId: string; frame: Uint8Array }> {
    const mod = VeilEngine.require();
    return this.withPeer(userId, (ptr) => {
      const p = mod._malloc(plain.length || 1);
      try {
        if (plain.length) mod.HEAPU8.set(plain, p);

        const need = mod._veil_encrypt_to_account(
          this.handle, ptr, p, plain.length, 0, 0,
        );
        if (need <= 0) return [];

        const out = mod._malloc(need);
        try {
          const total = mod._veil_encrypt_to_account(
            this.handle, ptr, p, plain.length, out, need,
          );
          if (total <= 0) return [];

          const view = new DataView(mod.HEAPU8.buffer, out, total);
          const frames: Array<{ deviceId: string; frame: Uint8Array }> = [];
          let off = 0;
          while (off + 5 <= total) {
            off += 4;  // record length; the loop is bounded by `total`
            const idLen = view.getUint8(off);
            off += 1;
            const deviceId = new TextDecoder().decode(
              mod.HEAPU8.slice(out + off, out + off + idLen));
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

  private produceFixed(size: number, call: (mod: EmscriptenModule, out: number) => number):
    Uint8Array {
    const mod = VeilEngine.require();
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
  private produceVariable(
    initial: number,
    call: (mod: EmscriptenModule, out: number, size: number) => number,
  ): Uint8Array {
    const mod = VeilEngine.require();
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

  private callWithBlob(
    blob: Uint8Array,
    call: (mod: EmscriptenModule, ptr: number, size: number) => number,
  ): number {
    const mod = VeilEngine.require();
    const p = mod._malloc(blob.length || 1);
    try {
      if (blob.length) mod.HEAPU8.set(blob, p);
      return call(mod, p, blob.length);
    } finally {
      mod._free(p);
    }
  }

  /** Copies a peer id into the heap, runs `body`, and always frees it. */
  private withPeer<T>(peer: string, body: (ptr: number) => T): T {
    const mod = VeilEngine.require();
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

  exportGroupState(): Uint8Array | null {
    return this.produceVariable(65536, (mod, out, size) =>
      mod._veil_export_group_state(this.handle, out, size));
  }

  importGroupState(blob: Uint8Array): StatusCode {
    const mod = VeilEngine.require();
    return this.callWithBlob(blob, (m, ptr, size) =>
      m._veil_import_group_state(this.handle, ptr, size)) as StatusCode;
  }

  // ---- Device list freshness --------------------------------------------
  //
  // A device list is a cache the peer controls, and it can be wrong in the one
  // direction that matters: they linked a device this client has not heard of,
  // and frames encrypted to it are simply never received.

  /** Supplies this client's notion of now. Without it, only send failures count. */
  setClock(nowMs: number): void {
    VeilEngine.require()._veil_set_clock(this.handle, nowMs);
  }

  deviceListNeedsRefresh(userId: string, stalenessMs: number): RefreshReason {
    const mod = VeilEngine.require();
    return this.withPeer(userId, (ptr) =>
      mod._veil_device_list_needs_refresh(this.handle, ptr, stalenessMs) as RefreshReason);
  }

  /** Records that a send could not reach one of the peer's devices. */
  noteSendFailed(userId: string): void {
    const mod = VeilEngine.require();
    this.withPeer(userId, (ptr) => mod._veil_note_send_failed(this.handle, ptr));
  }

  noteDeviceListFetched(userId: string): void {
    const mod = VeilEngine.require();
    this.withPeer(userId, (ptr) => mod._veil_note_device_list_fetched(this.handle, ptr));
  }

  // ---- Invitations ------------------------------------------------------

  /** The invitation payload, to encrypt and send to one invitee. */
  encodeInvite(groupId: string): Uint8Array | null {
    return this.withPeer(groupId, (ptr) =>
      this.produceVariable(4096, (mod, out, size) =>
        mod._veil_encode_invite(this.handle, ptr, out, size)));
  }

  looksLikeInvite(data: Uint8Array): boolean {
    const mod = VeilEngine.require();
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
  acceptInvite(
    data: Uint8Array, founder: string, founderSignPub: Uint8Array,
  ): string | null {
    const mod = VeilEngine.require();
    if (founderSignPub.length !== 32) return null;

    const d = mod._malloc(data.length || 1);
    const key = mod._malloc(32);
    const out = mod._malloc(128);
    try {
      if (data.length) mod.HEAPU8.set(data, d);
      mod.HEAPU8.set(founderSignPub, key);

      const status = this.withPeer(founder, (ptr) =>
        mod._veil_accept_invite(this.handle, d, data.length, ptr, key, out, 128));

      if (status !== Status.OK) return null;
      const end = mod.HEAPU8.indexOf(0, out);
      return new TextDecoder().decode(
        mod.HEAPU8.slice(out, end < 0 ? out + 128 : end),
      );
    } finally {
      mod._free(d);
      mod._free(key);
      mod._free(out);
    }
  }

  // ---- Device linking ---------------------------------------------------

  /** This device's request, for the existing device to endorse. */
  linkingRequest(): Uint8Array | null {
    return this.produceVariable(1024, (mod, out, size) =>
      mod._veil_linking_request(this.handle, out, size));
  }

  /** The account a request names and its fingerprint, from the same bytes. */
  readLinkingRequest(data: Uint8Array): { userId: string; fingerprint: string } | null {
    const mod = VeilEngine.require();
    const p = mod._malloc(data.length || 1);
    const userId = mod._malloc(128);
    const fp = mod._malloc(64);
    try {
      if (data.length) mod.HEAPU8.set(data, p);

      const status = mod._veil_read_linking_request(
        p, data.length, userId, 128, fp, 64,
      );
      if (status !== Status.OK) return null;

      const readCString = (at: number, bound: number): string => {
        const end = mod.HEAPU8.indexOf(0, at);
        const stop = end < 0 || end > at + bound ? at + bound : end;
        return new TextDecoder().decode(mod.HEAPU8.slice(at, stop));
      };

      return {
        userId: readCString(userId, 128),
        fingerprint: readCString(fp, 64),
      };
    } finally {
      mod._free(p);
      mod._free(userId);
      mod._free(fp);
    }
  }

  /** Signs an endorsement. Null when this engine does not hold the account key. */
  approveLinking(request: Uint8Array, issuedAt: number): Uint8Array | null {
    const mod = VeilEngine.require();
    const p = mod._malloc(request.length || 1);
    try {
      if (request.length) mod.HEAPU8.set(request, p);

      return this.produceVariable(512, (m, out, size) =>
        m._veil_approve_linking(this.handle, p, request.length, issuedAt, out, size));
    } finally {
      mod._free(p);
    }
  }

  accountSignPublic(): Uint8Array | null {
    return this.produceVariable(32, (mod, out, size) =>
      mod._veil_account_sign_public(this.handle, out, size));
  }

  /**
   * The device signing key a peer's credential vouches for.
   *
   * This is what an invitation is verified against: the key the peer's credential
   * carries, which is the peer this client verified, not whoever sent the bytes.
   */
  peerDeviceSignPublic(peer: string): Uint8Array | null {
    return this.withPeer(peer, (ptr) =>
      this.produceVariable(32, (mod, out, size) =>
        mod._veil_peer_device_sign_pub(this.handle, ptr, out, size)));
  }

  /**
   * A peer's pinned account identity: DH public || signing public, 64 bytes.
   *
   * This is the key the client already verified during the handshake, which is
   * why device lists are verified against it rather than against anything carried
   * in a reply.
   */
  peerIdentity(peer: string): Uint8Array | null {
    return this.withPeer(peer, (ptr) =>
      this.produceVariable(64, (mod, out, size) =>
        mod._veil_peer_identity(this.handle, ptr, out, size)));
  }
}