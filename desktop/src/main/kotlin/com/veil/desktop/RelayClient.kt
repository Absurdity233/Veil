package com.veil.desktop

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString.Companion.toByteString
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume

/**
 * The websocket link to the relay.
 *
 * Identical in shape to the Android client's `RelayClient`, which is the point:
 * the relay does not know or care which platform is on the other end, so the
 * only platform-specific part of a client is where the keys are stored and how
 * the window is drawn.
 */
class RelayClient(private val url: String) {

    sealed interface Event {
        data class Challenge(val nonce: ByteArray) : Event
        data class Connected(val userId: String) : Event
        data class Delivered(val outboxId: Long, val sender: String, val frame: ByteArray) : Event
        data class Bundle(
            val userId: String,
            val identity: ByteArray,
            val signedId: Int,
            val signedPub: ByteArray,
            val signature: ByteArray,
            val oneTimeId: Int,
            val oneTimePub: ByteArray,
        ) : Event

        data object MorePending : Event

        /**
         * A sealed vault, as the relay returned it.
         *
         * Every field is opaque to the relay: the salt and KDF parameters exist so
         * any client that knows the password can reproduce the key, and the
         * ciphertext is what that key opens.
         */
        data class Vault(
            val salt: ByteArray,
            val memoryKiB: Int,
            val passes: Int,
            val lanes: Int,
            val generation: Int,
            val ciphertext: ByteArray,
        ) : Event

        data class VaultStored(val generation: Int) : Event
        data class Failed(val message: String) : Event
        data object Disconnected : Event
    }

    private val http = OkHttpClient.Builder()
        .pingInterval(20, TimeUnit.SECONDS)
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .build()

    private val events = Channel<Event>(Channel.BUFFERED)
    val stream: Flow<Event> = events.receiveAsFlow()

    private var socket: WebSocket? = null

    @Volatile
    private var connected = false

    @Volatile
    private var closed = false

    val isConnected: Boolean get() = connected && socket != null && !closed

    suspend fun connect(userId: String, publicIdentity: ByteArray, deviceId: String = "") {
        closed = false
        val request = Request.Builder().url(url).build()

        val opened = suspendCancellableCoroutine { cont ->
            val listener = object : WebSocketListener() {
                override fun onOpen(ws: WebSocket, response: Response) {
                    socket = ws
                    // The device id is written only when there is one, so a
                    // single-device client sends the same two-field HELLO the
                    // relay accepted before device addressing existed.
                    val hello = Writer().string(userId).blob(publicIdentity)
                    if (deviceId.isNotEmpty()) hello.string(deviceId)
                    ws.send(Wire.frame(Wire.TYPE_HELLO, hello.build()).toByteString())
                    if (cont.isActive) cont.resume(true)
                }

                override fun onMessage(ws: WebSocket, bytes: okio.ByteString) {
                    handleFrame(bytes.toByteArray())
                }

                override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
                    connected = false
                    events.trySend(Event.Failed(t.message ?: "connection failed"))
                    if (cont.isActive) cont.resume(false)
                }

                override fun onClosed(ws: WebSocket, code: Int, reason: String) {
                    connected = false
                    events.trySend(Event.Disconnected)
                }
            }
            http.newWebSocket(request, listener)
            cont.invokeOnCancellation { socket?.cancel() }
        }
        if (opened != true) error("could not reach the relay")
    }

    /**
     * Answers a [Event.Challenge].
     *
     * Not gated on `connected`: the handshake is *how* the connection becomes
     * usable, so requiring it here would drop the frame that completes it.
     */
    fun respondToChallenge(signature: ByteArray): Boolean =
        write(Wire.TYPE_AUTH_RESPONSE, Writer().blob(signature).build())

    private fun handleFrame(bytes: ByteArray) {
        val frame = try {
            Wire.parse(bytes)
        } catch (e: Exception) {
            return
        }
        val r = Reader(frame.payload)
        try {
            when (frame.type) {
                Wire.TYPE_HELLO_OK -> {
                    connected = true
                    events.trySend(Event.Connected(r.string()))
                }
                Wire.TYPE_AUTH_CHALLENGE -> events.trySend(Event.Challenge(r.blob()))
                Wire.TYPE_MORE_PENDING -> events.trySend(Event.MorePending)
                Wire.TYPE_DELIVER -> {
                    val outboxId = r.u64()
                    val sender = r.string()
                    val body = r.blob()
                    events.trySend(Event.Delivered(outboxId, sender, body))
                }
                Wire.TYPE_BUNDLE -> {
                    val userId = r.string()
                    val identity = r.blob()
                    val signedId = r.u32()
                    val signedPub = r.blob()
                    val signature = r.blob()
                    val otId = r.u32()
                    val otPub = r.blob()
                    events.trySend(
                        Event.Bundle(userId, identity, signedId, signedPub, signature, otId, otPub),
                    )
                }
                Wire.TYPE_ERROR -> events.trySend(Event.Failed(r.string()))

                Wire.TYPE_VAULT_ACK -> {
                    val generation = r.u32()
                    vaultReply.offer(Event.VaultStored(generation))
                }

                Wire.TYPE_VAULT_DATA -> {
                    val salt = r.blob()
                    val memoryKiB = r.u32()
                    val passes = r.u32()
                    val lanes = r.u32()
                    val generation = r.u32()
                    val ciphertext = r.blob()
                    vaultReply.offer(
                        Event.Vault(salt, memoryKiB, passes, lanes, generation, ciphertext),
                    )
                }
            }
        } catch (e: Exception) {
            // A frame that does not parse is a relay bug or a version skew, not
            // something the UI can act on. Dropping it keeps the socket alive.
        }
    }

    fun publishPreKeys(signedId: Int, signedPub: ByteArray, signature: ByteArray,
                       oneTimeSet: ByteArray): Boolean =
        send(
            Wire.TYPE_PUBLISH_PREKEYS,
            Writer().u32(signedId).blob(signedPub).blob(signature).blob(oneTimeSet).build(),
        )

    fun requestBundle(userId: String): Boolean =
        send(Wire.TYPE_GET_BUNDLE, Writer().string(userId).build())

    /**
     * Sends a frame to a recipient.
     *
     * `deviceId` addresses one device of a peer; empty means the whole account,
     * which is what a single-device peer and a group frame both use.
     */
    fun sendMessage(recipient: String, frame: ByteArray, deviceId: String = ""): Boolean {
        val writer = Writer().string(recipient).blob(frame)
        if (deviceId.isNotEmpty()) writer.string(deviceId)
        return send(Wire.TYPE_SEND, writer.build())
    }

    fun acknowledge(outboxId: Long): Boolean =
        send(Wire.TYPE_ACK, Writer().u64(outboxId).build())

    // ---- Password vault ---------------------------------------------------
    //
    // Blocking rather than event-driven: account operations happen once, from a
    // dialog, and a caller that had to subscribe to an event stream to read its
    // own vault would be more code for no benefit. The request and the reply are
    // correlated by the connection, one at a time.

    /** Uploads a sealed vault, returning the generation the relay assigned. */
    suspend fun putVault(
        userId: String,
        salt: ByteArray,
        memoryKiB: Int,
        passes: Int,
        lanes: Int,
        ciphertext: ByteArray,
        timeoutMs: Long = 30_000,
    ): Int? {
        val payload = Writer()
            .string(userId)
            .blob(salt)
            .u32(memoryKiB)
            .u32(passes)
            .u32(lanes)
            .blob(ciphertext)
            .build()

        if (!send(Wire.TYPE_PUT_VAULT, payload)) return null

        return try {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                val event = awaitVaultReply(deadline - System.currentTimeMillis()) ?: return null
                if (event is Event.VaultStored) return event.generation
                if (event is Event.Failed) return null
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    /** Fetches a sealed vault, or null when the user has none. */
    suspend fun getVault(userId: String, timeoutMs: Long = 30_000): SealedVault? {
        if (!send(Wire.TYPE_GET_VAULT, Writer().string(userId).build())) return null

        return try {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                val event = awaitVaultReply(deadline - System.currentTimeMillis()) ?: return null
                if (event is Event.Vault) {
                    return SealedVault(
                        salt = event.salt,
                        memoryKiB = event.memoryKiB,
                        passes = event.passes,
                        lanes = event.lanes,
                        generation = event.generation,
                        ciphertext = event.ciphertext,
                    )
                }
                if (event is Event.Failed) return null
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Vault requests, correlated by the connection.
     *
     * A single slot rather than a map: the account dialog makes one request at a
     * time, and the relay answers the connection that asked. The important part is
     * that these do *not* consume the event channel - a delivery arriving while a
     * vault read is in flight would be swallowed by whoever read the channel
     * first, and a lost message is worse than a slow account dialog.
     */
    private val vaultReply = java.util.concurrent.ArrayBlockingQueue<Event>(1)

    /** Waits up to [timeoutMs] for the vault reply that a request asked for. */
    private suspend fun awaitVaultReply(timeoutMs: Long): Event? {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val event = vaultReply.poll(100, java.util.concurrent.TimeUnit.MILLISECONDS)
                ?: continue
            return event
        }
        return null
    }

    private fun send(type: Int, payload: ByteArray): Boolean {
        if (!connected || closed) return false
        return write(type, payload)
    }

    private fun write(type: Int, payload: ByteArray): Boolean {
        val ws = socket ?: return false
        return ws.send(Wire.frame(type, payload).toByteString())
    }

    fun close() {
        closed = true
        socket?.close(1000, "bye")
        socket = null
        connected = false
    }
}