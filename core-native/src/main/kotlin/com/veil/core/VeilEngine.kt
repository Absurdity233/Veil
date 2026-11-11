// Veil - Kotlin-side wrapper around the native engine.
//
// Everything public here is either a plain value or an opaque handle. Key
// material is created, used and destroyed inside the native layer; the only
// bytes that cross the boundary are public keys, ciphertext and, for
// backup/restore, the identity secrets the caller explicitly asked for.
package com.veil.core

import java.lang.ref.Cleaner

/** Raised when the native engine refuses an operation. */
class VeilException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * A live protocol engine.
 *
 * [close] wipes all key material. The instance is unusable afterwards.
 */
class VeilEngine private constructor(handle: Long) : AutoCloseable {

    private val state = State(handle)
    private val cleaner = CLEANER.register(this, state)

    // ---- Identity -------------------------------------------------------

    /** 64 bytes: DH public key followed by the Ed25519 public key. */
    fun publicIdentity(): ByteArray =
        VeilNative.nativePublicIdentity(state.handle)
            ?: throw VeilException("no identity")

    /**
     * 96 bytes: DH private key followed by the Ed25519 private key.
     *
     * The caller is responsible for protecting the result - store it behind
     * the platform keystore rather than in plain preferences.
     */
    fun exportIdentitySecrets(): ByteArray =
        VeilNative.nativeExportIdentity(state.handle)
            ?: throw VeilException("no identity")

    // ---- Prekeys --------------------------------------------------------

    /** Generates a signed prekey and [oneTimeCount] one-time prekeys. */
    fun generatePreKeys(signedId: Int, oneTimeCount: Int): ByteArray =
        VeilNative.nativeGeneratePreKeys(state.handle, signedId, oneTimeCount)
            ?: throw VeilException("prekey generation failed")

    /**
     * The bundle another peer needs to start a session with us.
     * Pass a negative index to publish without a one-time prekey.
     */
    fun publishBundle(oneTimeIndex: Int): ByteArray =
        VeilNative.nativePublishBundle(state.handle, oneTimeIndex)
            ?: throw VeilException("bundle unavailable for index $oneTimeIndex")

    // ---- Sessions -------------------------------------------------------

    fun hasSession(peerId: String): Boolean =
        VeilNative.nativeHasSession(state.handle, peerId)

    /** Starts a session from a peer's published bundle. */
    fun establishOutbound(peerId: String, bundle: ByteArray): Boolean =
        VeilNative.nativeEstablishOutbound(state.handle, peerId, bundle)

    fun exportSession(peerId: String): ByteArray? =
        VeilNative.nativeExportSession(state.handle, peerId)

    fun importSession(peerId: String, blob: ByteArray): Boolean =
        VeilNative.nativeImportSession(state.handle, peerId, blob)

    fun dropSession(peerId: String) = VeilNative.nativeDropSession(state.handle, peerId)

    // ---- Messaging ------------------------------------------------------

    /** Encrypts [plain] for [peerId] and returns the wire frame. */
    fun encrypt(peerId: String, plain: ByteArray): ByteArray =
        VeilNative.nativeEncrypt(state.handle, peerId, plain)
            ?: throw VeilException("cannot encrypt for $peerId")

    /**
     * Decrypts a wire frame. Returns null when authentication fails - a
     * tampered, replayed or undecryptable frame is not an error condition the
     * caller needs to distinguish.
     */
    fun decrypt(peerId: String, frame: ByteArray): ByteArray? =
        VeilNative.nativeDecrypt(state.handle, peerId, frame)

    // ---- Verification ---------------------------------------------------

    /** The shared safety number, or null if no session exists yet. */
    fun safetyNumber(peerId: String): String? =
        VeilNative.nativeSafetyNumber(state.handle, peerId)

    override fun close() {
        cleaner.clean()
    }

    private class State(@Volatile var handle: Long) : Runnable {
        override fun run() {
            val h = handle
            if (h != 0L) {
                handle = 0L
                VeilNative.nativeDestroy(h)
            }
        }
    }

    companion object {
        private val CLEANER: Cleaner = Cleaner.create()

        /** Creates a brand new identity. */
        fun create(): VeilEngine = VeilEngine(VeilNative.nativeCreate())

        /** Restores an identity from [exportIdentitySecrets] output. */
        fun restore(identitySecrets: ByteArray): VeilEngine =
            VeilEngine(VeilNative.nativeRestore(identitySecrets))
    }
}
