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
 * Why a delivery was accepted or refused.
 *
 * [DUPLICATE] is the interesting one: the relay is at-least-once, so one frame
 * can arrive live and again from the outbox. Treating that as a failure put a
 * security warning in front of the user on an ordinary event.
 */
enum class DecryptOutcome {
    OK,

    /** Already accepted once. Normal, and silent. */
    DUPLICATE,

    /** Failed to authenticate on a counter never seen before. Worth reporting. */
    AUTH_FAILED,

    /** The counter is far enough ahead that honouring it would break the budget. */
    TOO_FAR_AHEAD,

    /** No session, or a frame that could not be parsed. */
    NO_SESSION;

    companion object {
        fun fromCode(code: Int): DecryptOutcome = when (code) {
            0 -> OK
            4 -> NO_SESSION
            5 -> AUTH_FAILED
            6 -> DUPLICATE
            else -> AUTH_FAILED
        }
    }
}

/** What the engine actually knows about a peer label. */
enum class SessionState {
    /** Nothing known about this label. */
    NO_PEER,

    /** The identity is pinned but there is no live ratchet. */
    PINNED_ONLY,

    /** A session is usable and the safety number is comparable. */
    READY;

    companion object {
        fun fromCode(code: Int): SessionState = when (code) {
            2 -> READY
            1 -> PINNED_ONLY
            else -> NO_PEER
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
    // ---- Prekeys --------------------------------------------------------

    /**
     * Rotates the signed prekey and generates a fresh batch of one-time keys.
     *
     * There is no signed-id parameter any more: the id comes from a counter
     * carried in the persisted prekey state. Passing one in made every launch
     * reuse the same id with different keys, which is indistinguishable from a
     * stale bundle on the wire.
     */
    fun generatePreKeys(): ByteArray =
        VeilNative.nativeRotatePreKeys(state.handle)
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

    // ---- Multi-device -----------------------------------------------------

    /** Claims a user id and creates this device. */
    fun initDevice(userId: String): Boolean =
        VeilNative.nativeInitDevice(state.handle, userId)

    /** The 32-byte device id, or null when no device has been initialised. */
    fun deviceId(): ByteArray? = VeilNative.nativeDeviceId(state.handle)

    /** This device's credential, ready to publish. */
    fun deviceCredential(): ByteArray? = VeilNative.nativeDeviceCredential(state.handle)

    fun adoptDeviceCredential(
        credential: ByteArray,
        accountDhPub: ByteArray,
        accountSignPub: ByteArray,
    ): Boolean = VeilNative.nativeAdoptDeviceCredential(
        state.handle, credential, accountDhPub, accountSignPub,
    )

    /** 0 = ok. See [DecryptOutcome] for the shared result codes. */
    fun adoptDeviceList(
        userId: String,
        version: Int,
        entries: ByteArray,
        accountDhPub: ByteArray,
        accountSignPub: ByteArray,
    ): Int = VeilNative.nativeAdoptDeviceList(
        state.handle, userId, version, entries, accountDhPub, accountSignPub,
    )

    /**
     * Encrypts one plaintext to every device of a peer that has a session.
     *
     * One message becomes N frames: that is the cost of per-device sessions, and
     * it is why the relay learns how many devices a recipient has.
     *
     * A device with no session is skipped rather than failing the send, so one
     * stale laptop does not make an account unreachable.
     */
    fun encryptToAccount(userId: String, plain: ByteArray): List<Pair<String, ByteArray>> {
        val blob = VeilNative.nativeEncryptToAccount(state.handle, userId, plain)
            ?: return emptyList()

        val out = mutableListOf<Pair<String, ByteArray>>()
        var off = 0
        while (off + 5 <= blob.size) {
            off += 4  // record length; the loop is bounded by the array
            val idLen = blob[off].toInt() and 0xFF
            off += 1

            val deviceId = String(blob, off, idLen, Charsets.UTF_8)
            off += idLen

            val frameLen = readU32(blob, off)
            off += 4
            if (off + frameLen > blob.size) break

            out += deviceId to blob.copyOfRange(off, off + frameLen)
            off += frameLen
        }
        return out
    }

    private fun readU32(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 24) or
            ((buf[off + 1].toInt() and 0xFF) shl 16) or
            ((buf[off + 2].toInt() and 0xFF) shl 8) or
            (buf[off + 3].toInt() and 0xFF)

    // ---- Groups -----------------------------------------------------------

    /**
     * Creates a group with this device's user as founder.
     *
     * Membership is signed by the founder, because a group with no authority has
     * no way to tell a legitimate re-key from a hostile one. See docs/group.md.
     */
    fun createGroup(groupId: String): Boolean =
        VeilNative.nativeCreateGroup(state.handle, groupId)

    /**
     * Replaces the member list and bumps the epoch.
     *
     * Every chain is discarded, including this client's: a removed member holds
     * the old chain key, and re-keying is the only thing that stops them reading
     * what follows. Returns the new epoch, or 0 on failure.
     */
    fun setGroupMembers(groupId: String, members: List<String>): Int =
        VeilNative.nativeSetGroupMembers(state.handle, groupId, members.toTypedArray())

    fun groupEpoch(groupId: String): Int =
        VeilNative.nativeGroupEpoch(state.handle, groupId)

    fun groupMembers(groupId: String): List<String> =
        VeilNative.nativeGroupMembers(state.handle, groupId)?.toList() ?: emptyList()

    fun isGroupMember(groupId: String): Boolean =
        VeilNative.nativeIsGroupMember(state.handle, groupId)

    fun exportMembership(groupId: String): ByteArray? =
        VeilNative.nativeExportMembership(state.handle, groupId)

    fun adoptMembership(data: ByteArray, founderSignPub: ByteArray): Int =
        VeilNative.nativeAdoptMembership(state.handle, data, founderSignPub)

    fun exportSenderKey(groupId: String, epoch: Int = 0): ByteArray? =
        VeilNative.nativeExportSenderKey(state.handle, groupId, epoch)

    fun adoptSenderKey(data: ByteArray, senderId: String, senderSignPub: ByteArray): Int =
        VeilNative.nativeAdoptSenderKey(state.handle, data, senderId, senderSignPub)

    /** One message, one frame, regardless of group size. */
    fun encryptToGroup(groupId: String, plain: ByteArray): ByteArray? =
        VeilNative.nativeEncryptToGroup(state.handle, groupId, plain)

    fun decryptFromGroup(groupId: String, record: ByteArray): ByteArray? =
        VeilNative.nativeDecryptFromGroup(state.handle, groupId, record)

    /** Carries chain keys: this belongs in the Keystore-backed vault. */
    fun exportGroupState(): ByteArray? = VeilNative.nativeExportGroupState(state.handle)

    fun importGroupState(blob: ByteArray): Boolean =
        VeilNative.nativeImportGroupState(state.handle, blob)

    /**
     * Decrypts a wire frame.
     *
     * Returns the plaintext with the outcome, so the caller can tell a
     * duplicated delivery from a tampered one. Collapsing both into "null"
     * meant every duplicate showed up as an authentication failure.
     */
    fun decrypt(peerId: String, frame: ByteArray): Pair<ByteArray?, DecryptOutcome> {
        val out = arrayOfNulls<ByteArray>(1)
        val code = VeilNative.nativeDecrypt(state.handle, peerId, frame, out)
        return out[0] to DecryptOutcome.fromCode(code)
    }

    /** What the engine knows about a label: no peer, pinned only, or ready. */
    fun sessionState(peerId: String): SessionState =
        SessionState.fromCode(VeilNative.nativeSessionState(state.handle, peerId))

    // ---- Prekey state ---------------------------------------------------

    /**
     * The signed prekey generation and every one-time secret, including which
     * ones have been spent.
     *
     * Carries private keys: it belongs in the same encrypted store as the
     * ratchet state, never in plain preferences.
     */
    fun exportPreKeyState(): ByteArray? = VeilNative.nativeExportPreKeyState(state.handle)

    fun importPreKeyState(blob: ByteArray): Boolean =
        VeilNative.nativeImportPreKeyState(state.handle, blob)

    /**
     * Rotates the signed prekey and generates a fresh batch of one-time keys.
     * The signed id comes from the persisted counter, so it never repeats.
     */
    fun rotatePreKeys(): ByteArray? = VeilNative.nativeRotatePreKeys(state.handle)

    fun needsPreKeyRefill(lowWater: Int): Boolean =
        VeilNative.nativeNeedsPreKeyRefill(state.handle, lowWater)

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
