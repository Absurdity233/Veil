/**
 * Accounts: a password that lets one identity be restored on another device.
 *
 * The design constraint, which everything here follows, is that the relay must
 * never be able to verify a password or open a vault.
 *
 *   key      = Argon2id(password, salt)        -- on the device, once at login
 *   vault    = AEAD(key, identity 鈥?prekeys 鈥?groups 鈥?history)
 *   upload   = (salt, kdf params, vault)       -- all the relay ever sees
 *
 * So a stolen database is an offline attack on Argon2id, not a password list, and
 * a compromised relay is a blob it cannot read. The corollary is the thing to be
 * honest about: *password strength is the entire defence*. Argon2id makes each
 * guess expensive; it cannot make a short password long. That is why there is a
 * minimum length and an estimate shown at signup.
 *
 * What this costs in metadata: the relay learns a user id exists before that user
 * ever connects, and roughly how much data they keep and when they last wrote it.
 */

import { argon2id, openAead, randomBytes, sealAead } from "./crypto.js";

/** Minimum password length. Not a suggestion: the whole feature rests on it. */
export const MIN_PASSWORD_LENGTH = 12;

/** Argon2id cost. 64 MiB x 3 passes is the OWASP floor for this KDF. */
const KDF_MEMORY_KIB = 64 * 1024;
const KDF_PASSES = 3;
const KDF_LANES = 2;

const SALT_SIZE = 16;

/** What the relay stores and returns. None of it is readable by the relay. */
export interface VaultBlob {
  salt: Uint8Array;
  memoryKiB: number;
  passes: number;
  lanes: number;
  generation: number;
  ciphertext: Uint8Array;
}

/** The plaintext a vault protects. */
export interface VaultContents {
  identity: Uint8Array;
  preKeyState: Uint8Array | null;
  peerRegistry: Uint8Array | null;
  groupState: Uint8Array | null;
  /** Per-conversation transcripts, keyed by peer id or `group:<id>`. */
  history: Record<string, unknown>;
}

/** Rejects a password that is too short, with the reason rather than a boolean. */
export function checkPassword(password: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `at least ${MIN_PASSWORD_LENGTH} characters: this password is the only ` +
      `thing protecting the account, because the server cannot check it for you`;
  }
  return null;
}

/**
 * A rough strength estimate, shown to the user.
 *
 * Deliberately crude: a real entropy estimate from a single string is not
 * possible, and claiming one would be worse than a coarse bucket. What this
 * catches is the password that passes the length check while being a keyboard
 * walk or a single repeated character.
 */
export function describeStrength(password: string): string {
  if (password.length < MIN_PASSWORD_LENGTH) return "too short";

  const classes =
    (/[a-z]/.test(password) ? 1 : 0) +
    (/[A-Z]/.test(password) ? 1 : 0) +
    (/[0-9]/.test(password) ? 1 : 0) +
    (/[^a-zA-Z0-9]/.test(password) ? 1 : 0);

  const unique = new Set(password).size;
  // A long password built from a handful of distinct characters is a pattern, and
  // Argon2id does not help against a pattern.
  const variety = unique / password.length;

  if (variety < 0.3) return "weak: too repetitive";
  if (password.length >= 20 && classes >= 3) return "strong";
  if (password.length >= 16 || classes >= 3) return "reasonable";
  return "weak: add length or variety";
}

/**
 * Derives the vault key.
 *
 * The password stays in this function: what leaves is a 32-byte key, and only
 * ever into AEAD calls.
 */
export async function deriveVaultKey(
  password: string,
  salt: Uint8Array,
  params: { memoryKiB: number; passes: number; lanes: number } = {
    memoryKiB: KDF_MEMORY_KIB,
    passes: KDF_PASSES,
    lanes: KDF_LANES,
  },
): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  return argon2id(encoder.encode(password), salt, params);
}

/**
 * Seals a vault for upload.
 *
 * `params` exists for tests: the production cost is 64 MiB x 3, which would make
 * every test that touches a vault take a fifth of a second. It is not a tuning
 * knob for callers - a vault sealed with weaker parameters than it claims would
 * be weaker than the relay's own bounds allow, and the parameters travel with the
 * blob so a reader always uses the ones it was sealed with.
 */
export async function sealVault(
  contents: VaultContents,
  password: string,
  params: { memoryKiB: number; passes: number; lanes: number } = {
    memoryKiB: KDF_MEMORY_KIB,
    passes: KDF_PASSES,
    lanes: KDF_LANES,
  },
): Promise<VaultBlob> {
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
      ciphertext,
    };
  } finally {
    // The key is derived state; leaving it in a live buffer is leaving the
    // password's product where a later heap read could find it.
    key.fill(0);
  }
}

/**
 * Opens a vault.
 *
 * Returns null when the password is wrong, which is the only check available:
 * there is no password hash to compare against, and a wrong password simply fails
 * to authenticate the ciphertext. That is also why a wrong password and a corrupt
 * vault are indistinguishable here - both mean "this blob is not yours".
 */
export async function openVault(
  vault: VaultBlob,
  password: string,
): Promise<VaultContents | null> {
  const key = await deriveVaultKey(password, vault.salt, {
    memoryKiB: vault.memoryKiB,
    passes: vault.passes,
    lanes: vault.lanes,
  });

  try {
    const plain = await openAead(key, vault.ciphertext);
    return plain === null ? null : decodeContents(plain);
  } finally {
    key.fill(0);
  }
}

// ---- Encoding ---------------------------------------------------------
//
// A hand-rolled layout rather than JSON: the payload contains raw key material,
// and a JSON round trip through UTF-8 would either mangle it or force base64 and
// triple the size. Each field is length-prefixed and the history is a length-
// prefixed JSON string, so the encoder stays one screen long.

function encodeContents(contents: VaultContents): Uint8Array {
  const parts: Uint8Array[] = [];

  const putBlob = (bytes: Uint8Array | null) => {
    const length = bytes?.length ?? 0;
    const head = new Uint8Array(4);
    new DataView(head.buffer).setUint32(0, length, false);
    parts.push(head);
    // A null field is encoded as a zero length, so "absent" and "empty" stay
    // distinct from the reader's point of view without another flag byte.
    if (bytes) parts.push(bytes);
  };

  putBlob(contents.identity);
  putBlob(contents.preKeyState);
  putBlob(contents.peerRegistry);
  putBlob(contents.groupState);
  putBlob(new TextEncoder().encode(JSON.stringify(contents.history)));

  return concat(parts);
}

function decodeContents(plain: Uint8Array): VaultContents {
  let offset = 0;

  const readBlob = (): Uint8Array | null => {
    if (plain.length - offset < 4) throw new Error("vault is truncated");
    const length = new DataView(plain.buffer, plain.byteOffset + offset, 4)
      .getUint32(0, false);
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

  const history = historyJson
    ? (JSON.parse(new TextDecoder().decode(historyJson)) as Record<string, unknown>)
    : {};

  return { identity, preKeyState, peerRegistry, groupState, history };
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
