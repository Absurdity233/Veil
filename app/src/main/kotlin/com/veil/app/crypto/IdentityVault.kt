package com.veil.app.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Wraps the long-term identity secrets in an AES-GCM key held by the Android
 * Keystore.
 *
 * The keystore key never leaves secure hardware, so the blob on disk is
 * useless without the device unlock state. The plaintext identity only exists
 * in memory for the moment it takes to hand it to the native engine.
 */
class IdentityVault(context: Context) {

    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private val keyStore: KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun orCreateKey(): SecretKey {
        val existing = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // Not requiring user authentication keeps the app usable from
                // a background sync; the key is still non-exportable and
                // bound to this device.
                .setUserAuthenticationRequired(false)
                .build(),
        )
        return generator.generateKey()
    }

    fun hasIdentity(): Boolean = prefs.contains(PREF_BLOB)

    /** Encrypts and stores the 96-byte identity secret. */
    fun store(secrets: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, orCreateKey())
        val ciphertext = cipher.doFinal(secrets)
        prefs.edit()
            .putString(PREF_IV, cipher.iv.toHex())
            .putString(PREF_BLOB, ciphertext.toHex())
            .apply()
    }

    /** Returns the identity secret, or null when none has been stored. */
    fun load(): ByteArray? {
        val iv = prefs.getString(PREF_IV, null)?.fromHex() ?: return null
        val blob = prefs.getString(PREF_BLOB, null)?.fromHex() ?: return null
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, orCreateKey(), GCMParameterSpec(128, iv))
            cipher.doFinal(blob)
        } catch (e: Exception) {
            // A keystore reset (factory reset, lock screen change) makes the
            // old blob undecryptable. Treat that as "no identity" rather than
            // crashing on every launch.
            clear()
            null
        }
    }

    fun clear() {
        prefs.edit().remove(PREF_IV).remove(PREF_BLOB).apply()
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it) }

    private fun String.fromHex(): ByteArray =
        ByteArray(length / 2) { i -> substring(i * 2, i * 2 + 2).toInt(16).toByte() }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "veil.identity.v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val PREFS = "veil.vault"
        const val PREF_IV = "iv"
        const val PREF_BLOB = "blob"
    }
}
