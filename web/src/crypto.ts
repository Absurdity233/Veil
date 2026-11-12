/**
 * Primitives the web client needs that the browser does not provide.
 *
 * AEAD and random bytes come from `crypto.subtle`, which is audited and fast.
 * Argon2id does not exist there, so it comes from the engine's wasm module - the
 * same Monocypher build the phone uses, which is one implementation of one
 * algorithm rather than two that could disagree about a key.
 */

let wasm: {
  _veil_argon2id: (
    out: number, outSize: number,
    password: number, passwordSize: number,
    salt: number, saltSize: number,
    memoryKib: number, passes: number, lanes: number,
  ) => number;
  _malloc(size: number): number;
  _free(ptr: number): void;
  HEAPU8: Uint8Array;
} | null = null;

/**
 * Points this module at the loaded engine.
 *
 * Called once by `VeilEngine.load`, because the wasm instance is shared and there
 * must be exactly one: two copies would mean two places holding Argon2's work
 * area, and only one of them would be wiped by the engine's teardown.
 */
export function attachCrypto(module: NonNullable<typeof wasm>): void {
  wasm = module;
}

function requireWasm(): NonNullable<typeof wasm> {
  if (!wasm) {
    throw new Error("crypto: the engine is not loaded yet");
  }
  return wasm;
}

/** Cryptographically strong random bytes. */
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

/**
 * Argon2id.
 *
 * Throws when the parameters are outside what the build supports rather than
 * deriving a weaker key: a caller that asked for 1 GiB and silently got 64 MiB
 * would believe its ciphertext is stronger than it is.
 */
export async function argon2id(
  password: Uint8Array,
  salt: Uint8Array,
  params: { memoryKiB: number; passes: number; lanes: number },
): Promise<Uint8Array> {
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
      out, outSize,
      passwordPtr, password.length,
      saltPtr, salt.length,
      params.memoryKiB, params.passes, params.lanes,
    );

    if (status !== 0) {
      throw new Error(
        `crypto: argon2id refused its parameters (status ${status})`,
      );
    }

    return mod.HEAPU8.slice(out, out + outSize);
  } finally {
    mod._free(out);
    mod._free(passwordPtr);
    mod._free(saltPtr);
  }
}

/**
 * AES-256-GCM seal, with the nonce prepended.
 *
 * `crypto.subtle` is used rather than the engine's XChaCha20 because a browser
 * implements AES in hardware and this runs on every vault write: 64 MiB of
 * Argon2 dominates the cost, and the AEAD should not add to it. The algorithm is
 * fixed rather than recorded in the blob, because a vault written by a future
 * client with a different cipher would fail to authenticate rather than be
 * silently reinterpreted as something else.
 */
export async function sealAead(
  key: Uint8Array,
  plain: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await importAesKey(key, "encrypt");
  const nonce = randomBytes(12);

  const sealed = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      ...(aad ? { additionalData: aad } : {}),
    },
    cryptoKey,
    plain,
  );

  const out = new Uint8Array(12 + sealed.byteLength);
  out.set(nonce, 0);
  out.set(new Uint8Array(sealed), 12);
  return out;
}

/** Opens what [sealAead] produced. Returns null on a bad key or tampering. */
export async function openAead(
  key: Uint8Array,
  sealed: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array | null> {
  if (sealed.length < 12 + 16) return null;

  const nonce = sealed.slice(0, 12);
  const body = sealed.slice(12);

  try {
    const cryptoKey = await importAesKey(key, "decrypt");
    const plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        ...(aad ? { additionalData: aad } : {}),
      },
      cryptoKey,
      body,
    );
    return new Uint8Array(plain);
  } catch {
    // A wrong key and a tampered blob are the same event here: AES-GCM cannot
    // tell them apart, and neither can the caller do anything different.
    return null;
  }
}

async function importAesKey(
  raw: Uint8Array,
  usage: "encrypt" | "decrypt",
): Promise<CryptoKey> {
  if (raw.length !== 32) {
    throw new Error("crypto: an AES-256 key must be 32 bytes");
  }
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, [usage]);
}
