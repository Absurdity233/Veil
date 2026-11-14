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

    // ---- Multi-device ----
    fun veil_init_device(handle: Pointer?, userId: String): Int
    fun veil_device_id(handle: Pointer?, out: ByteArray, outSize: Int): Int
    fun veil_device_credential(handle: Pointer?, out: ByteArray?, outSize: Int): Int
    fun veil_adopt_device_credential(handle: Pointer?, credential: ByteArray,
                                     credentialSize: Int, accountDhPub: ByteArray,
                                     accountSignPub: ByteArray): Int
    fun veil_adopt_device_list(handle: Pointer?, userId: String, version: Int,
                               data: ByteArray, size: Int, accountDhPub: ByteArray,
                               accountSignPub: ByteArray): Int
    fun veil_peer_devices(handle: Pointer?, userId: String, out: ByteArray?,
                          outSize: Int): Int
    fun veil_peer_device_version(handle: Pointer?, userId: String): Int

    // ---- Device list freshness ----
    fun veil_set_clock(handle: Pointer?, nowMs: Long)
    fun veil_device_list_needs_refresh(handle: Pointer?, userId: String,
                                       stalenessMs: Long): Int
    fun veil_note_send_failed(handle: Pointer?, userId: String)
    fun veil_note_device_list_fetched(handle: Pointer?, userId: String)

    // ---- Invitations and linking ----
    fun veil_encode_invite(handle: Pointer?, groupId: String, out: ByteArray?,
                           outSize: Int): Int
    fun veil_looks_like_invite(data: ByteArray, size: Int): Int
    fun veil_accept_invite(handle: Pointer?, data: ByteArray, size: Int,
                           expectedFounder: String, founderSignPub: ByteArray,
                           outGroupId: ByteArray?, outSize: Int): Int
    fun veil_read_linking_request(data: ByteArray, size: Int, userId: ByteArray?,
                                  userIdSize: Int, fingerprint: ByteArray?,
                                  fingerprintSize: Int): Int
    fun veil_linking_request(handle: Pointer?, out: ByteArray?, outSize: Int): Int
    fun veil_approve_linking(handle: Pointer?, request: ByteArray, requestSize: Int,
                             issuedAt: Long, out: ByteArray?, outSize: Int): Int
    fun veil_account_sign_public(handle: Pointer?, out: ByteArray?, outSize: Int): Int
    fun veil_peer_device_sign_pub(handle: Pointer?, peer: String, out: ByteArray?,
                                  outSize: Int): Int
    fun veil_peer_identity(handle: Pointer?, peer: String, out: ByteArray?,
                           outSize: Int): Int

    /** Argon2id, for the account vault. The password never leaves this process. */
    fun veil_argon2id(out: ByteArray?, outSize: Int,
                      password: ByteArray, passwordSize: Int,
                      salt: ByteArray, saltSize: Int,
                      memoryKib: Int, passes: Int, lanes: Int): Int
    fun veil_device_fingerprint(credential: ByteArray, size: Int, out: ByteArray,
                                outSize: Int): Int
    fun veil_establish_with_devices(handle: Pointer?, userId: String,
                                    deviceIds: ByteArray, deviceIdsSize: Int,
                                    bundles: ByteArray, bundlesSize: Int,
                                    failed: ByteArray, failedSize: Int): Int
    fun veil_encrypt_to_account(handle: Pointer?, userId: String, plain: ByteArray,
                                plainSize: Int, out: ByteArray?, outSize: Int): Int

    // ---- Groups ----
    fun veil_create_group(handle: Pointer?, groupId: String): Int
    fun veil_set_group_members(handle: Pointer?, groupId: String, members: ByteArray,
                               membersSize: Int): Int
    fun veil_export_membership(handle: Pointer?, groupId: String, out: ByteArray?,
                               outSize: Int): Int
    fun veil_adopt_membership(handle: Pointer?, data: ByteArray, size: Int,
                              founderSignPub: ByteArray): Int
    fun veil_group_epoch(handle: Pointer?, groupId: String): Int
    fun veil_group_members(handle: Pointer?, groupId: String, out: ByteArray?,
                           outSize: Int): Int
    fun veil_is_group_member(handle: Pointer?, groupId: String): Int
    fun veil_export_sender_key(handle: Pointer?, groupId: String, epoch: Int,
                               out: ByteArray?, outSize: Int): Int
    fun veil_adopt_sender_key(handle: Pointer?, data: ByteArray, size: Int,
                              expectedSender: String, senderSignPub: ByteArray): Int
    fun veil_encrypt_to_group(handle: Pointer?, groupId: String, plain: ByteArray,
                              plainSize: Int, out: ByteArray?, outSize: Int): Int
    fun veil_decrypt_from_group(handle: Pointer?, groupId: String, data: ByteArray,
                                size: Int, out: ByteArray?, outSize: Int,
                                outLen: IntByReference): Int
    fun veil_export_group_state(handle: Pointer?, out: ByteArray?, outSize: Int): Int
    fun veil_import_group_state(handle: Pointer?, data: ByteArray, size: Int): Int

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
         *
         * `OPTION_OPEN_FLAGS` is deliberately *not* set. It used to be set to 0
         * whenever a path was given, on the reasoning that the path already said
         * where to look. On Windows that is harmless - LoadLibrary ignores the
         * flags - but on Linux JNA passes the value straight to dlopen, and
         * `dlopen(path, 0)` is EINVAL: "invalid mode for dlopen(): Invalid
         * argument". So the library loaded everywhere except the platform the CI
         * runs on, which is the worst place for a difference like that to hide.
         *
         * Leaving the option out lets JNA use its default (RTLD_LAZY), which is
         * what every other JNA user gets.
         */
        fun load(): VeilC = Native.load(LIBRARY_NAME, VeilC::class.java, mapOf(
            Library.OPTION_STRING_ENCODING to Charsets.UTF_8.name(),
        ))

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

    // ---- Multi-device -----------------------------------------------------

    /** Claims a user id and creates this device. */
    fun initDevice(userId: String): Boolean = lib.veil_init_device(handle, userId) == VeilC.OK

    /** The 32-byte device id, or null when no device is initialised. */
    fun deviceId(): ByteArray? {
        val out = ByteArray(32)
        val n = lib.veil_device_id(handle, out, out.size)
        return if (n == 32) out else null
    }

    /** This device's credential, ready to publish. */
    fun deviceCredential(): ByteArray? =
        produce(512) { buf, size -> lib.veil_device_credential(handle, buf, size) }

    fun adoptDeviceCredential(
        credential: ByteArray,
        accountDhPub: ByteArray,
        accountSignPub: ByteArray,
    ): Boolean =
        lib.veil_adopt_device_credential(
            handle, credential, credential.size, accountDhPub, accountSignPub,
        ) == VeilC.OK

    fun adoptDeviceList(
        userId: String,
        version: Int,
        entries: ByteArray,
        accountDhPub: ByteArray,
        accountSignPub: ByteArray,
    ): Int = lib.veil_adopt_device_list(
        handle, userId, version, entries, entries.size, accountDhPub, accountSignPub,
    )

    /** The hex device ids known for a peer. */
    fun peerDevices(userId: String): List<String> {
        // A size query has to pass NULL, not a zero-length array: the ABI
        // distinguishes "tell me the size" from "write here" by the pointer,
        // and JNA will happily hand it a valid pointer to an empty array.
        val need = lib.veil_peer_devices(handle, userId, null, 0)
        if (need <= 0) return emptyList()

        val buf = ByteArray(need)
        if (lib.veil_peer_devices(handle, userId, buf, need) != need) return emptyList()
        return String(buf, Charsets.UTF_8).split('\u0000').filter { it.isNotEmpty() }
    }

    fun peerDeviceVersion(userId: String): Int =
        lib.veil_peer_device_version(handle, userId)

    // ---- Device list freshness -------------------------------------------
    //
    // A device list is a cache the peer controls, and it can be wrong in the one
    // direction that matters: they linked a device this client has not heard of,
    // and frames encrypted to it are simply never received.

    /** Supplies this client's notion of now. Without it, only send failures count. */
    fun setClock(nowMs: Long) = lib.veil_set_clock(handle, nowMs)

    /** 0 = none, 1 = stale, 2 = a send failed, 3 = no list held. */
    fun deviceListNeedsRefresh(userId: String, stalenessMs: Long): Int =
        lib.veil_device_list_needs_refresh(handle, userId, stalenessMs)

    fun noteSendFailed(userId: String) = lib.veil_note_send_failed(handle, userId)

    fun noteDeviceListFetched(userId: String) =
        lib.veil_note_device_list_fetched(handle, userId)

    /** A peer's pinned account identity: DH public || signing public, 64 bytes. */
    fun peerIdentity(peer: String): ByteArray? =
        produce(64) { buf, size -> lib.veil_peer_identity(handle, peer, buf, size) }

    // ---- Invitations and linking -----------------------------------------

    fun encodeInvite(groupId: String): ByteArray? =
        produce(4096) { buf, size -> lib.veil_encode_invite(handle, groupId, buf, size) }

    fun looksLikeInvite(data: ByteArray): Boolean =
        lib.veil_looks_like_invite(data, data.size) == 1

    /**
     * Accepts an invitation against the founder's device signing key.
     *
     * Returns the group id, or null when refused - so a caller cannot read a
     * refusal as "accepted into a group with no name".
     */
    fun acceptInvite(data: ByteArray, founder: String, founderSignPub: ByteArray): String? {
        if (founderSignPub.size != 32) return null

        val out = ByteArray(128)
        val status = lib.veil_accept_invite(
            handle, data, data.size, founder, founderSignPub, out, out.size,
        )
        if (status != VeilC.OK) return null

        val end = out.indexOfFirst { it == 0.toByte() }
        return String(out, 0, if (end < 0) out.size else end, Charsets.UTF_8)
    }

    /** The account a request names and its fingerprint, from the same bytes. */
    fun readLinkingRequest(data: ByteArray): Pair<String, String>? {
        val user = ByteArray(128)
        val fp = ByteArray(64)
        val status = lib.veil_read_linking_request(data, data.size, user, user.size, fp, fp.size)
        if (status != VeilC.OK) return null

        fun readCString(buf: ByteArray): String {
            val end = buf.indexOfFirst { it == 0.toByte() }
            return String(buf, 0, if (end < 0) buf.size else end, Charsets.UTF_8)
        }
        return readCString(user) to readCString(fp)
    }

    fun linkingRequest(): ByteArray? =
        produce(1024) { buf, size -> lib.veil_linking_request(handle, buf, size) }

    /** Signs an endorsement. Null when this engine does not hold the account key. */
    fun approveLinking(request: ByteArray, issuedAt: Long): ByteArray? =
        produce(512) { buf, size ->
            lib.veil_approve_linking(handle, request, request.size, issuedAt, buf, size)
        }

    fun accountSignPublic(): ByteArray? =
        produce(32) { buf, size -> lib.veil_account_sign_public(handle, buf, size) }

    /**
     * The device signing key a peer's credential vouches for.
     *
     * This is what an invitation is verified against: the key the peer's
     * credential carries, which is the peer this client verified, not whoever
     * sent the bytes.
     */
    fun peerDeviceSignPublic(peer: String): ByteArray? =
        produce(32) { buf, size ->
            lib.veil_peer_device_sign_pub(handle, peer, buf, size)
        }

    /**
     * Encrypts one plaintext to every device of a peer that has a session.
     *
     * The ABI returns a record sequence; this parses it so a caller iterates
     * instead of hand-walking lengths.
     */
    fun encryptToAccount(userId: String, plain: ByteArray): List<Pair<String, ByteArray>> {
        val need = lib.veil_encrypt_to_account(handle, userId, plain, plain.size, null, 0)
        if (need <= 0) return emptyList()

        val buf = ByteArray(need)
        val total = lib.veil_encrypt_to_account(handle, userId, plain, plain.size, buf, need)
        if (total <= 0) return emptyList()

        val out = mutableListOf<Pair<String, ByteArray>>()
        var off = 0
        while (off + 5 <= total) {
            off += 4  // record length; the loop is bounded by `total`
            val idLen = buf[off].toInt() and 0xFF
            off += 1
            val deviceId = String(buf, off, idLen, Charsets.UTF_8)
            off += idLen

            val frameLen = readU32(buf, off)
            off += 4
            out += deviceId to buf.copyOfRange(off, off + frameLen)
            off += frameLen
        }
        return out
    }

    // ---- Groups -----------------------------------------------------------

    fun createGroup(groupId: String): Boolean =
        lib.veil_create_group(handle, groupId) == VeilC.OK

    /** Replaces the member list; returns the new epoch, or 0 on failure. */
    fun setGroupMembers(groupId: String, members: List<String>): Int {
        val joined = members.joinToString("\u0000").toByteArray(Charsets.UTF_8)
        return lib.veil_set_group_members(handle, groupId, joined, joined.size)
    }

    fun groupEpoch(groupId: String): Int = lib.veil_group_epoch(handle, groupId)

    fun groupMembers(groupId: String): List<String> {
        val need = lib.veil_group_members(handle, groupId, null, 0)
        if (need <= 0) return emptyList()

        val buf = ByteArray(need)
        if (lib.veil_group_members(handle, groupId, buf, need) != need) return emptyList()
        return String(buf, Charsets.UTF_8).split('\u0000').filter { it.isNotEmpty() }
    }

    fun isGroupMember(groupId: String): Boolean =
        lib.veil_is_group_member(handle, groupId) == 1

    fun exportMembership(groupId: String): ByteArray? =
        produce(2048) { buf, size -> lib.veil_export_membership(handle, groupId, buf, size) }

    fun adoptMembership(data: ByteArray, founderSignPub: ByteArray): Int =
        lib.veil_adopt_membership(handle, data, data.size, founderSignPub)

    fun exportSenderKey(groupId: String, epoch: Int = 0): ByteArray? =
        produce(512) { buf, size ->
            lib.veil_export_sender_key(handle, groupId, epoch, buf, size)
        }

    fun adoptSenderKey(data: ByteArray, senderId: String, senderSignPub: ByteArray): Int =
        lib.veil_adopt_sender_key(handle, data, data.size, senderId, senderSignPub)

    fun encryptToGroup(groupId: String, plain: ByteArray): ByteArray? {
        val need = lib.veil_encrypt_to_group(handle, groupId, plain, plain.size, null, 0)
        if (need <= 0) return null

        val buf = ByteArray(need)
        val total = lib.veil_encrypt_to_group(handle, groupId, plain, plain.size, buf, need)
        return if (total == need) buf else null
    }

    /** Decrypts a group record; returns the plaintext or null. */
    fun decryptFromGroup(groupId: String, record: ByteArray): ByteArray? {
        // The plaintext is always smaller than the record that carries it, so
        // sizing from the frame needs no probe - which matters because a probe
        // must not consume the message key.
        val out = ByteArray(record.size)
        val len = IntByReference(0)

        val status = lib.veil_decrypt_from_group(handle, groupId, record, record.size,
            out, out.size, len)
        return if (status == VeilC.OK) out.copyOf(len.value) else null
    }

    fun exportGroupState(): ByteArray? =
        produce(65536) { buf, size -> lib.veil_export_group_state(handle, buf, size) }

    fun importGroupState(blob: ByteArray): Boolean =
        lib.veil_import_group_state(handle, blob, blob.size) == VeilC.OK

    /** Reads a big-endian u32, matching the ABI's record format. */
    private fun readU32(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 24) or
            ((buf[off + 1].toInt() and 0xFF) shl 16) or
            ((buf[off + 2].toInt() and 0xFF) shl 8) or
            (buf[off + 3].toInt() and 0xFF)

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