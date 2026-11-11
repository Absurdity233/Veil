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
 * Encrypted at-rest storage for opaque protocol blobs.
 *
 * Same construction as [IdentityVault] - an AES-GCM key held by the Android
 * Keystore, one blob per name - but a separate key alias, so a compromise of
 * one store does not hand over the other.
 *
 * What goes in is ratchet state and identity pins. Ratchet state is as
 * sensitive as the identity itself: whoever holds it can read every message the
 * peer has not yet answered, and can impersonate this device to that peer. It
 * therefore never touches disk in the clear, and a keystore reset drops it
 * rather than leaving it readable.
 */
class SessionVault(context: Context, private val namespace: String) {

    private val prefs = context.getSharedPreferences(namespace, Context.MODE_PRIVATE)

    private val keyStore: KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private val alias = "$namespace.key"

    private fun orCreateKey(): SecretKey {
        val existing = keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // The app has to be able to decrypt at launch, before any user
                // interaction, or every restart would silently lose the
                // conversation history. The key is still non-exportable and
                // bound to this device.
                .setUserAuthenticationRequired(false)
                .build(),
        )
        return generator.generateKey()
    }

    fun has(name: String): Boolean = prefs.contains(blobKey(name))

    /** Encrypts [blob] and stores it under [name]. */
    fun store(name: String, blob: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, orCreateKey())
        val ciphertext = cipher.doFinal(blob)
        prefs.edit()
            .putString(ivKey(name), cipher.iv.toHex())
            .putString(blobKey(name), ciphertext.toHex())
            .apply()
    }

    /** Returns the stored blob for [name], or null when absent or undecryptable. */
    fun load(name: String = PIN_REGISTRY): ByteArray? {
        val iv = prefs.getString(ivKey(name), null)?.fromHex() ?: return null
        val blob = prefs.getString(blobKey(name), null)?.fromHex() ?: return null
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, orCreateKey(), GCMParameterSpec(128, iv))
            cipher.doFinal(blob)
        } catch (e: Exception) {
            // A keystore reset makes the old blob undecryptable. Drop it rather
            // than crashing on every launch; the caller treats "no state" the
            // same way it treats a first run.
            remove(name)
            null
        }
    }

    fun remove(name: String) {
        prefs.edit().remove(ivKey(name)).remove(blobKey(name)).apply()
    }

    private fun blobKey(name: String) = "$name.blob"
    private fun ivKey(name: String) = "$name.iv"

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it) }

    private fun String.fromHex(): ByteArray =
        ByteArray(length / 2) { i -> substring(i * 2, i * 2 + 2).toInt(16).toByte() }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"

        /** Default name for the pinned-identity registry. */
        const val PIN_REGISTRY = "registry"
    }
}