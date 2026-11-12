package com.veil.desktop

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

/**
 * The account vault: password-derived keys and sealing.
 *
 * The design constraint, which everything here follows, is that the relay must
 * never be able to verify a password or open a vault:
 *
 *     key      = Argon2id(password, salt)        on this machine, once per sign-in
 *     vault    = AES-256-GCM(key, identity || prekeys || groups || history)
 *     upload   = (salt, kdf params, ciphertext)  all the relay ever sees
 *
 * Argon2id comes from the engine's C ABI rather than from the JVM: the JDK has no
 * implementation, and two implementations of a key-derivation function are two
 * chances to disagree about a key. AES comes from the JVM, which has hardware
 * support for it.
 *
 * The corollary to be honest about: password strength is the entire defence. The
 * KDF makes each guess expensive; it cannot make a short password long, which is
 * why the length is enforced rather than suggested.
 */

/** Minimum password length. Not a suggestion: the whole feature rests on it. */
const val MIN_PASSWORD_LENGTH = 12

/** Argon2id cost, matching the web client. 64 MiB x 3 is the OWASP floor. */
private const val KDF_MEMORY_KIB = 64 * 1024
private const val KDF_PASSES = 3
private const val KDF_LANES = 2

private const val SALT_SIZE = 16

/** The plaintext a vault protects. */
data class VaultPlain(
    val identity: ByteArray,
    val preKeyState: ByteArray?,
    val peerRegistry: ByteArray?,
    val groupState: ByteArray?,
    /** The transcript, as opaque bytes this class does not interpret. */
    val history: ByteArray,
)

/** What the relay stores and returns. */
data class SealedVault(
    val salt: ByteArray,
    val memoryKiB: Int,
    val passes: Int,
    val lanes: Int,
    val generation: Int,
    val ciphertext: ByteArray,
)

/** Rejects a password that is too short, with the reason rather than a boolean. */
fun checkPassword(password: String): String? =
    if (password.length < MIN_PASSWORD_LENGTH) {
        "at least $MIN_PASSWORD_LENGTH characters: this password is the only thing " +
            "protecting the account, because the server cannot check it for you"
    } else {
        null
    }

/** A rough strength estimate, for a UI. Deliberately coarse; see the web client. */
fun describeStrength(password: String): String {
    if (password.length < MIN_PASSWORD_LENGTH) return "too short"

    val classes = listOf(
        password.any { it.isLowerCase() },
        password.any { it.isUpperCase() },
        password.any { it.isDigit() },
        password.any { !it.isLetterOrDigit() },
    ).count { it }

    val variety = password.toSet().size.toDouble() / password.length
    if (variety < 0.3) return "weak: too repetitive"
    if (password.length >= 20 && classes >= 3) return "strong"
    if (password.length >= 16 || classes >= 3) return "reasonable"
    return "weak: add length or variety"
}

/** Derives the vault key, calling into the engine's Argon2id. */
fun deriveVaultKey(
    password: String,
    salt: ByteArray,
    memoryKiB: Int = KDF_MEMORY_KIB,
    passes: Int = KDF_PASSES,
    lanes: Int = KDF_LANES,
): ByteArray {
    val out = ByteArray(32)
    val bytes = password.toByteArray(Charsets.UTF_8)

    val status = VeilC.load().veil_argon2id(
        out, out.size,
        bytes, bytes.size,
        salt, salt.size,
        memoryKiB, passes, lanes,
    )
    bytes.fill(0)

    if (status != VeilC.OK) {
        throw IllegalStateException("argon2id refused its parameters (status $status)")
    }
    return out
}

/** Seals a vault for upload. */
fun sealVault(plain: VaultPlain, password: String): SealedVault {
    val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
    val key = deriveVaultKey(password, salt)

    try {
        val body = encode(plain)
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        val sealed = cipher.doFinal(body)

        // Nonce prepended, so a reader needs nothing but the blob.
        val out = ByteArray(nonce.size + sealed.size)
        nonce.copyInto(out, 0)
        sealed.copyInto(out, nonce.size)

        return SealedVault(salt, KDF_MEMORY_KIB, KDF_PASSES, KDF_LANES, 0, out)
    } finally {
        key.fill(0)
    }
}

/**
 * Opens a vault.
 *
 * Returns null on a wrong password. That is the only check available: there is no
 * password hash to compare against, and a wrong key simply fails to authenticate
 * the ciphertext.
 */
fun openVault(vault: SealedVault, password: String): VaultPlain? {
    if (vault.ciphertext.size < 12 + 16) return null

    val key = deriveVaultKey(password, vault.salt, vault.memoryKiB, vault.passes, vault.lanes)
    try {
        val nonce = vault.ciphertext.copyOfRange(0, 12)
        val body = vault.ciphertext.copyOfRange(12, vault.ciphertext.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        val plain = cipher.doFinal(body)
        return decode(plain)
    } catch (e: Exception) {
        // A wrong password and a tampered blob are the same event here.
        return null
    } finally {
        key.fill(0)
    }
}

// ---- Encoding ---------------------------------------------------------
//
// Length-prefixed fields rather than JSON: the payload contains raw key material,
// and a JSON round trip through UTF-8 would either mangle it or force base64 and
// triple the size.

private fun encode(plain: VaultPlain): ByteArray {
    val parts = mutableListOf<ByteArray>()

    fun put(bytes: ByteArray?) {
        val length = bytes?.size ?: 0
        parts += byteArrayOf(
            (length ushr 24).toByte(), (length ushr 16).toByte(),
            (length ushr 8).toByte(), length.toByte(),
        )
        if (bytes != null && bytes.isNotEmpty()) parts += bytes
    }

    put(plain.identity)
    put(plain.preKeyState)
    put(plain.peerRegistry)
    put(plain.groupState)
    put(plain.history)
    return parts.fold(ByteArray(0)) { acc, p -> acc + p }
}

private fun decode(bytes: ByteArray): VaultPlain {
    var offset = 0

    fun read(): ByteArray? {
        require(bytes.size - offset >= 4) { "vault is truncated" }
        val length = ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)
        offset += 4
        require(bytes.size - offset >= length) { "vault is truncated" }

        val out = bytes.copyOfRange(offset, offset + length)
        offset += length
        return if (length == 0) null else out
    }

    val identity = read() ?: error("vault has no identity")
    val preKeyState = read()
    val peerRegistry = read()
    val groupState = read()
    val history = read() ?: ByteArray(0)

    return VaultPlain(identity, preKeyState, peerRegistry, groupState, history)
}
