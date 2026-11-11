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
 * Why establishing a session succeeded or failed.
 *
 * Mirrors `veil::Engine::Result`. The distinction matters at the UI layer:
 * [BAD_BUNDLE] and [BAD_SIGNATURE] mean the peer or the relay sent something
 * broken, while [IDENTITY_CHANGED] means the peer we were talking to is no
 * longer the peer we pinned - which the user has to confirm before anything
 * else is sent.
 */
enum class Handshake {
    OK,
    BAD_BUNDLE,
    BAD_SIGNATURE,
    IDENTITY_CHANGED,
    NO_SESSION,
    AUTH_FAILED;

    companion object {
        fun fromCode(code: Int): Handshake = when (code) {
            0 -> OK
            1 -> BAD_BUNDLE
            2 -> BAD_SIGNATURE
            3 -> IDENTITY_CHANGED
            4 -> NO_SESSION
            5 -> AUTH_FAILED
            else -> BAD_BUNDLE
        }
    }
}

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

    /**
     * Starts a session from a peer's published bundle.
     *
     * Returns a [Handshake] rather than a bare boolean because the caller has
     * to react differently to each failure: a bad signature is a broken peer,
     * while a changed identity is a security event the user must be shown.
     */
    fun establishOutbound(peerId: String, bundle: ByteArray): Handshake =
        Handshake.fromCode(VeilNative.nativeEstablishOutbound(state.handle, peerId, bundle))

    /** Ed25519 signature over this identity's DH public key. */
    fun identityBinding(): ByteArray? = VeilNative.nativeIdentityBinding(state.handle)

    /** Signs a relay challenge, proving possession of the identity. */
    fun signChallenge(challenge: ByteArray): ByteArray? =
        VeilNative.nativeSignChallenge(state.handle, challenge)

    /** The peer's pinned identity as last learned, or null when unmapped. */
    fun peerIdentity(peerId: String): ByteArray? =
        VeilNative.nativePeerIdentity(state.handle, peerId)

    // ---- Pinned identity registry ---------------------------------------

    /**
     * Every peer label pinned to an identity. The pin has to outlive both the
     * process and the session: if it is forgotten, a re-handshake can silently
     * swap the peer's identity and the safety number would move without
     * anyone noticing.
     */
    fun exportPeerRegistry(): ByteArray? = VeilNative.nativeExportPeerRegistry(state.handle)

    fun importPeerRegistry(registry: ByteArray): Boolean =
        VeilNative.nativeImportPeerRegistry(state.handle, registry)

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
