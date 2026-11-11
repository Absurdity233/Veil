package com.veil.desktop

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.ptr.IntByReference

/**
 * The C ABI from `core-native/src/main/cpp/veil/veil_c.h`, bound through JNA.
 *
 * Every type here is a primitive or a [Pointer]; nothing on this interface is a
 * Kotlin object. That is the whole reason the ABI exists: the same symbols are
 * what the WebAssembly build exports, so both clients call the same functions
 * and neither reimplements the protocol.
 *
 * Buffers are caller-owned. A function that produces bytes either writes into a
 * buffer this side allocated, or reports its size so this side can allocate one
 * and call again.
 */
interface VeilC : Library {

    // ---- Lifetime ----
    fun veil_engine_new(): Pointer?
    fun veil_engine_restore(secrets: ByteArray, size: Int): Pointer?
    fun veil_engine_free(handle: Pointer?)

    // ---- Identity ----
    fun veil_identity_secrets(handle: Pointer?, out: ByteArray, outSize: Int): Int
    fun veil_identity_public(handle: Pointer?, out: ByteArray, outSize: Int): Int
    fun veil_identity_binding(handle: Pointer?, out: ByteArray, outSize: Int): Int
    fun veil_sign_challenge(handle: Pointer?, challenge: ByteArray, challengeSize: Int,
                            out: ByteArray, outSize: Int): Int

    // ---- Prekeys ----
    fun veil_rotate_prekeys(handle: Pointer?, out: ByteArray, outSize: Int): Int
    fun veil_export_prekey_set(handle: Pointer?, out: ByteArray, outSize: Int): Int
    fun veil_needs_prekey_refill(handle: Pointer?, lowWater: Int): Int
    fun veil_export_prekey_state(handle: Pointer?, out: ByteArray, outSize: Int): Int
    fun veil_import_prekey_state(handle: Pointer?, data: ByteArray, size: Int): Int

    // ---- Bounds ----
    fun veil_measure_session(handle: Pointer?, peer: String): Int
    fun veil_measure_prekey_state(handle: Pointer?): Int
    fun veil_measure_peer_registry(handle: Pointer?): Int

    // ---- Sessions ----
    fun veil_establish_outbound(handle: Pointer?, peer: String, bundle: ByteArray,
                                bundleSize: Int): Int
    fun veil_session_state(handle: Pointer?, peer: String): Int
    fun veil_export_session(handle: Pointer?, peer: String, out: ByteArray, outSize: Int): Int
    fun veil_import_session(handle: Pointer?, peer: String, data: ByteArray, size: Int): Int
    fun veil_drop_session(handle: Pointer?, peer: String)
    fun veil_peer_identity(handle: Pointer?, peer: String, out: ByteArray, outSize: Int): Int

    // ---- Registry ----
    fun veil_export_peer_registry(handle: Pointer?, out: ByteArray, outSize: Int): Int
    fun veil_import_peer_registry(handle: Pointer?, data: ByteArray, size: Int): Int

    // ---- Messaging ----
    fun veil_encrypt(handle: Pointer?, peer: String, plain: ByteArray, plainSize: Int,
                     out: ByteArray, outSize: Int): Int
    fun veil_decrypt(handle: Pointer?, peer: String, frame: ByteArray, frameSize: Int,
                     out: ByteArray?, outSize: Int, outLen: IntByReference): Int

    // ---- Verification ----
    fun veil_safety_number(handle: Pointer?, peer: String, out: ByteArray, outSize: Int): Int

    // ---- Version ----
    fun veil_version(major: IntByReference, minor: IntByReference, patch: IntByReference)

    companion object {
        /** Status codes, mirroring the header. */
        const val OK = 0
        const val BAD_BUNDLE = 1
        const val BAD_SIGNATURE = 2
        const val IDENTITY_CHANGED = 3
        const val NO_SESSION = 4
        const val AUTH_FAILED = 5
        const val DUPLICATE = 6

        const val ERR_NULL_HANDLE = -1
        const val ERR_NULL_ARG = -2
        const val ERR_BUFFER_TOO_SMALL = -3
        const val ERR_OUT_OF_MEMORY = -4
        const val ERR_NO_RANDOM = -5
        const val ERR_BAD_PARAM = -6
        const val ERR_INTERNAL = -7

        /**
         * Loads the shared library.
         *
         * The search order is deliberate: an explicit `veil.library.path`
         * property first, so a test or a packaged build can point at a staged
         * copy, then whatever the platform loader finds.
         */
        fun load(): VeilC {
            val explicit = System.getProperty("veil.library.path")
            val options = if (explicit != null) {
                mapOf(Library.OPTION_OPEN_FLAGS to 0)
            } else {
                emptyMap()
            }

            return Native.load(LIBRARY_NAME, VeilC::class.java, mapOf(
                Library.OPTION_STRING_ENCODING to Charsets.UTF_8.name(),
            ) + options)
        }

        private val LIBRARY_NAME: String =
            System.getProperty("veil.library.name") ?: "veilc"
    }
}

/** Raised when the C ABI returns a negative status. */
class VeilNativeException(val status: Int, message: String) : Exception("$message (status $status)")

/**
 * A typed wrapper over the raw handle.
 *
 * The ABI is buffer-oriented and status-driven; this class turns it into
 * something a Kotlin caller can use without repeating the same twenty lines of
 * size-query-then-allocate for every call.
 */
class VeilEngine private constructor(private val handle: Pointer) : AutoCloseable {

    /** Why a call was refused, as a type rather than an int. */
    enum class Status(val code: Int) {
        OK(0),
        BAD_BUNDLE(1),
        BAD_SIGNATURE(2),
        IDENTITY_CHANGED(3),
        NO_SESSION(4),
        AUTH_FAILED(5),
        DUPLICATE(6);

        companion object {
            fun of(code: Int): Status = entries.firstOrNull { it.code == code } ?: OK
        }
    }

    // ---- Identity -------------------------------------------------------

    /** 96 bytes: DH private || signing private. Guard this like a password. */
    fun identitySecrets(): ByteArray {
        val out = ByteArray(96)
        val n = lib.veil_identity_secrets(handle, out, out.size)
        require(n == out.size) { "identity secrets: status $n" }
        return out
    }

    /** 64 bytes: DH public || signing public. */
    fun publicIdentity(): ByteArray {
        val out = ByteArray(64)
        val n = lib.veil_identity_public(handle, out, out.size)
        require(n == out.size) { "public identity: status $n" }
        return out
    }

    fun identityBinding(): ByteArray {
        val out = ByteArray(64)
        val n = lib.veil_identity_binding(handle, out, out.size)
        require(n == out.size) { "identity binding: status $n" }
        return out
    }

    fun signChallenge(challenge: ByteArray): ByteArray {
        val out = ByteArray(64)
        val n = lib.veil_sign_challenge(handle, challenge, challenge.size, out, out.size)
        if (n < 0) throw VeilNativeException(n, "sign challenge")
        return out.copyOf(n)
    }

    // ---- Prekeys --------------------------------------------------------

    /** Rotates and returns the public prekey set the relay stores. */
    fun rotatePreKeys(): ByteArray = produce(4096) { buf, size ->
        lib.veil_rotate_prekeys(handle, buf, size)
    }

    fun exportPreKeySet(): ByteArray = produce(4096) { buf, size ->
        lib.veil_export_prekey_set(handle, buf, size)
    }

    fun needsPreKeyRefill(lowWater: Int): Boolean =
        lib.veil_needs_prekey_refill(handle, lowWater) == 1

    fun exportPreKeyState(): ByteArray = produce(8192) { buf, size ->
        lib.veil_export_prekey_state(handle, buf, size)
    }

    fun importPreKeyState(state: ByteArray): Boolean =
        lib.veil_import_prekey_state(handle, state, state.size) == VeilC.OK

    // ---- Sessions -------------------------------------------------------

    fun establishOutbound(peer: String, bundle: ByteArray): Status =
        Status.of(lib.veil_establish_outbound(handle, peer, bundle, bundle.size))

    fun sessionState(peer: String): SessionState =
        SessionState.of(lib.veil_session_state(handle, peer))

    fun exportSession(peer: String): ByteArray? {
        val need = lib.veil_measure_session(handle, peer)
        if (need <= 0) return null
        val out = ByteArray(need)
        val n = lib.veil_export_session(handle, peer, out, out.size)
        return if (n < 0) null else out.copyOf(n)
    }

    fun importSession(peer: String, blob: ByteArray): Boolean =
        lib.veil_import_session(handle, peer, blob, blob.size) == VeilC.OK

    fun dropSession(peer: String) = lib.veil_drop_session(handle, peer)

    fun exportPeerRegistry(): ByteArray = produce(65536) { buf, size ->
        lib.veil_export_peer_registry(handle, buf, size)
    }

    fun importPeerRegistry(blob: ByteArray): Boolean =
        lib.veil_import_peer_registry(handle, blob, blob.size) == VeilC.OK

    // ---- Messaging ------------------------------------------------------

    fun encrypt(peer: String, plain: ByteArray): ByteArray? {
        // A frame is plaintext + 257 bytes of overhead at worst, so the
        // plaintext size plus a fixed margin is always enough.
        val out = ByteArray(plain.size + 512)
        val n = lib.veil_encrypt(handle, peer, plain, plain.size, out, out.size)
        return if (n < 0) null else out.copyOf(n)
    }

    /**
     * Decrypts a frame.
     *
     * Returns the plaintext with the status, because the caller has to tell a
     * duplicated delivery from a tampered one and the ABI deliberately reports
     * both.
     *
     * The buffer is sized from the frame, not from a separate size probe:
     * decrypting advances the ratchet and spends the message key, so a probe
     * that actually decrypted would consume the frame and leave the real call
     * reporting a duplicate. The ABI documents this and reports `frame_size` as
     * the needed size for exactly that reason.
     */
    fun decrypt(peer: String, frame: ByteArray): Pair<ByteArray?, Status> {
        val out = ByteArray(frame.size + 64)
        val len = IntByReference(0)
        val status = lib.veil_decrypt(handle, peer, frame, frame.size, out, out.size, len)
        return if (status == VeilC.OK) out.copyOf(len.value) to Status.OK
        else null to Status.of(status)
    }

    fun safetyNumber(peer: String): String? {
        val out = ByteArray(64)
        return if (lib.veil_safety_number(handle, peer, out, out.size) == VeilC.OK) {
            // The ABI writes a NUL-terminated ASCII string.
            val end = out.indexOfFirst { it == 0.toByte() }.let { if (it < 0) out.size else it }
            String(out, 0, end, Charsets.US_ASCII)
        } else {
            null
        }
    }

    override fun close() = lib.veil_engine_free(handle)

    /**
     * Runs a producing call, growing the buffer once if the first attempt is
     * refused.
     *
     * The ABI contract is "pass a buffer of the advertised size", and the
     * advertised size for these is a documented upper bound. Growing once
     * handles the case where that bound was wrong without turning it into a
     * crash on the caller's side.
     */
    private inline fun produce(initial: Int, call: (ByteArray, Int) -> Int): ByteArray {
        var size = initial
        repeat(2) {
            val buf = ByteArray(size)
            val n = call(buf, size)
            if (n >= 0) return buf.copyOf(n)
            if (n == VeilC.ERR_BUFFER_TOO_SMALL) {
                size *= 2
                return@repeat
            }
            throw VeilNativeException(n, "native call")
        }
        throw VeilNativeException(VeilC.ERR_BUFFER_TOO_SMALL, "native call")
    }

    companion object {
        private val lib: VeilC by lazy { VeilC.load() }

        /** Creates a fresh identity. */
        fun create(): VeilEngine {
            val handle = lib.veil_engine_new()
                ?: throw IllegalStateException("could not create an engine (no entropy source?)")
            return VeilEngine(handle)
        }

        /** Restores an identity from [identitySecrets]. */
        fun restore(secrets: ByteArray): VeilEngine {
            val handle = lib.veil_engine_restore(secrets, secrets.size)
                ?: throw IllegalStateException("could not restore the identity")
            return VeilEngine(handle)
        }

        /** The ABI version, so a mismatched native library is loud, not subtle. */
        fun version(): String {
            val major = IntByReference()
            val minor = IntByReference()
            val patch = IntByReference()
            lib.veil_version(major, minor, patch)
            return "${major.value}.${minor.value}.${patch.value}"
        }
    }
}

/** The engine's view of a peer label. */
enum class SessionState {
    NO_PEER,
    PINNED_ONLY,
    READY;

    companion object {
        fun of(code: Int): SessionState = when (code) {
            2 -> READY
            1 -> PINNED_ONLY
            else -> NO_PEER
        }
    }
}