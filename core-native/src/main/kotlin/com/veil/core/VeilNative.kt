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
    external fun nativeDecrypt(handle: Long, peerId: String, frame: ByteArray): ByteArray?

    external fun nativeExportSession(handle: Long, peerId: String): ByteArray?
    external fun nativeImportSession(handle: Long, peerId: String, blob: ByteArray): Boolean
    external fun nativeDropSession(handle: Long, peerId: String)

    external fun nativeSafetyNumber(handle: Long, peerId: String): String?
}
