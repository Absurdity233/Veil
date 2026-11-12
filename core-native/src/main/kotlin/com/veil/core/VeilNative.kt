// Veil - JNI entry points.
//
// The Kotlin side never sees a raw pointer: every handle is a jlong produced
// by nativeCreate()/nativeRestore() and released by nativeDestroy(). All
// protocol state stays on the native heap.
package com.veil.core

/**
 * Thin binding over the native protocol engine.
 *
 * Not thread safe: the engine serialises ratchet state per peer, and a single
 * instance must not be used from two threads at once. Callers should confine
 * each instance to one dispatcher.
 */
internal object VeilNative {

    init {
        System.loadLibrary("veil")
    }

    external fun nativeCreate(): Long
    external fun nativeRestore(identitySecrets: ByteArray): Long
    external fun nativeDestroy(handle: Long)

    external fun nativeExportIdentity(handle: Long): ByteArray?
    external fun nativePublicIdentity(handle: Long): ByteArray?

    external fun nativeGeneratePreKeys(handle: Long, signedId: Int, oneTimeCount: Int): ByteArray?
    external fun nativePublishBundle(handle: Long, oneTimeIndex: Int): ByteArray?

    external fun nativeEstablishOutbound(handle: Long, peerId: String, bundle: ByteArray): Int
    external fun nativeHasSession(handle: Long, peerId: String): Boolean

    external fun nativeIdentityBinding(handle: Long): ByteArray?
    external fun nativeVerifyIdentityBinding(identity: ByteArray, binding: ByteArray): Boolean
    external fun nativeSignChallenge(handle: Long, challenge: ByteArray): ByteArray?
    external fun nativePeerIdentity(handle: Long, peerId: String): ByteArray?
    external fun nativeExportPeerRegistry(handle: Long): ByteArray?
    external fun nativeImportPeerRegistry(handle: Long, registry: ByteArray): Boolean

    external fun nativeEncrypt(handle: Long, peerId: String, plain: ByteArray): ByteArray?

    /**
     * Decrypts [frame] into `outPlain[0]` and returns a [DecryptOutcome] code.
     *
     * The reason is returned rather than collapsed into a null because a
     * duplicated delivery is a normal event on an at-least-once relay, while a
     * frame that fails on an unseen counter is not.
     */
    external fun nativeDecrypt(
        handle: Long,
        peerId: String,
        frame: ByteArray,
        outPlain: Array<ByteArray?>,
    ): Int

    external fun nativeExportSession(handle: Long, peerId: String): ByteArray?
    external fun nativeImportSession(handle: Long, peerId: String, blob: ByteArray): Boolean
    external fun nativeDropSession(handle: Long, peerId: String)

    /** 0 = no peer, 1 = pinned without a session, 2 = a live session. */
    external fun nativeSessionState(handle: Long, peerId: String): Int

    external fun nativeExportPreKeyState(handle: Long): ByteArray?
    external fun nativeImportPreKeyState(handle: Long, state: ByteArray): Boolean
    external fun nativeRotatePreKeys(handle: Long): ByteArray?
    external fun nativeNeedsPreKeyRefill(handle: Long, lowWater: Int): Boolean

    external fun nativeSafetyNumber(handle: Long, peerId: String): String?

    // ---- Multi-device -----------------------------------------------------
    //
    // The phone is normally the first device of an account, so what it needs is
    // the ability to create and publish its own credential and to fan out to a
    // peer's devices. Linking a *second* device happens on the device being
    // linked, which is why the full surface lives on the C ABI.

    external fun nativeInitDevice(handle: Long, userId: String): Boolean
    external fun nativeDeviceId(handle: Long): ByteArray?
    external fun nativeDeviceCredential(handle: Long): ByteArray?

    external fun nativeAdoptDeviceCredential(
        handle: Long,
        credential: ByteArray,
        accountDhPub: ByteArray,
        accountSignPub: ByteArray,
    ): Boolean

    /** Engine result code: 0 = ok, 1 = bad bundle, 2 = bad signature. */
    external fun nativeAdoptDeviceList(
        handle: Long,
        userId: String,
        version: Int,
        data: ByteArray,
        accountDhPub: ByteArray,
        accountSignPub: ByteArray,
    ): Int

    /**
     * One frame per device of a peer, in the ABI's record sequence.
     *
     * Parsed by [com.veil.core.VeilEngine.encryptToAccount]; a raw array here so
     * the JNI layer does not have to construct Kotlin objects.
     */
    external fun nativeEncryptToAccount(handle: Long, userId: String, plain: ByteArray): ByteArray?

    // ---- Groups -----------------------------------------------------------

    external fun nativeCreateGroup(handle: Long, groupId: String): Boolean
    external fun nativeSetGroupMembers(handle: Long, groupId: String, members: Array<String>): Int
    external fun nativeGroupEpoch(handle: Long, groupId: String): Int
    external fun nativeGroupMembers(handle: Long, groupId: String): Array<String>?
    external fun nativeIsGroupMember(handle: Long, groupId: String): Boolean

    external fun nativeExportMembership(handle: Long, groupId: String): ByteArray?
    external fun nativeAdoptMembership(
        handle: Long, data: ByteArray, founderSignPub: ByteArray,
    ): Int

    external fun nativeExportSenderKey(handle: Long, groupId: String, epoch: Int): ByteArray?
    external fun nativeAdoptSenderKey(
        handle: Long, data: ByteArray, senderId: String, senderSignPub: ByteArray,
    ): Int

    external fun nativeEncryptToGroup(handle: Long, groupId: String, plain: ByteArray): ByteArray?

    /** The plaintext, or null when the frame does not authenticate. */
    external fun nativeDecryptFromGroup(handle: Long, groupId: String, record: ByteArray): ByteArray?

    /** Carries chain keys: store it in the Keystore-backed vault, not in the clear. */
    external fun nativeExportGroupState(handle: Long): ByteArray?
    external fun nativeImportGroupState(handle: Long, blob: ByteArray): Boolean

    // ---- Group invitations -------------------------------------------------
    //
    // An invitation is the content of an ordinary pairwise message, not a new
    // wire type: the relay needs no changes and never learns the group id.

    external fun nativeEncodeInvite(handle: Long, groupId: String): ByteArray?
    external fun nativeLooksLikeInvite(data: ByteArray): Boolean

    /**
     * Accepts an invitation. Returns the group id, or null when it was refused.
     *
     * A refused invitation carries no group id rather than an empty one, so a
     * caller cannot mistake "refused" for "accepted into a nameless group".
     */
    external fun nativeAcceptInvite(
        handle: Long,
        data: ByteArray,
        expectedFounder: String,
        founderSignPub: ByteArray,
    ): String?

    // ---- Device linking ----------------------------------------------------

    /** This device's request, for the existing device to endorse. */
    external fun nativeLinkingRequest(handle: Long): ByteArray?

    /**
     * The account a request names and its fingerprint, as a two-element array.
     *
     * Returned together because a UI needs both to show anything useful, and two
     * calls would let the two answers come from different bytes.
     */
    external fun nativeReadLinkingRequest(data: ByteArray): Array<String>?

    /** Signs an endorsement. Null when this engine does not hold the account key. */
    external fun nativeApproveLinking(handle: Long, request: ByteArray, issuedAt: Long): ByteArray?

    /** 32 bytes: the account signing key, for verifying credentials and lists. */
    external fun nativeAccountSignPublic(handle: Long): ByteArray?

    /** The device signing key a peer's credential vouches for; null when unknown. */
    external fun nativePeerDeviceSignPub(handle: Long, peer: String): ByteArray?
}
