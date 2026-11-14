package com.veil.app.net

import android.util.Log
import com.veil.app.SealedVault
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.OkHttpClient
import okio.ByteString.Companion.toByteString
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume

/**
 * The websocket link to the relay.
 *
 * Everything this class carries is either a public key or ciphertext; the
 * relay cannot read any of it. Frames are matched to callers by request type,
 * so a caller that asks for a prekey bundle gets the next bundle frame and
 * nothing else.
 */
class RelayClient(private val url: String) {

    sealed interface Event {
        data class Connected(val userId: String) : Event

        /** The relay wants a proof of identity before it binds the user id. */
        data class Challenge(val nonce: ByteArray) : Event
        data class Delivered(val outboxId: Long, val sender: String, val frame: ByteArray) : Event
        data class Bundle(val userId: String, val identity: ByteArray, val signedId: Int,
                          val signedPub: ByteArray, val signature: ByteArray,
                          val oneTimeId: Int, val oneTimePub: ByteArray) : Event

        /** A full page of replayed entries went out; the next ACK pulls more. */
        data object MorePending : Event

        /** A sealed vault. Every field is opaque to the relay. */
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
        .readTimeout(0, TimeUnit.MILLISECONDS)  // long lived; ping keeps it alive
        .build()

    private val events = Channel<Event>(Channel.BUFFERED)

    /**
     * Vault replies, kept out of the event channel.
     *
     * A delivery arriving while a vault read is in flight would otherwise be
     * swallowed by whoever read the channel first, and a lost message is worse than
     * a slow account dialog. One slot because the dialog makes one request at a
     * time and the relay answers the connection that asked.
     */
    private val vaultReply = java.util.concurrent.ArrayBlockingQueue<Event>(1)

    /** Prekey-publish acknowledgements. A channel because they can arrive early. */
    private val preKeysAck = Channel<Boolean>(Channel.CONFLATED)

    // ---- Password vault ---------------------------------------------------

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

        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val event = withTimeoutOrNull(500) {
                kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                    vaultReply.poll(400, java.util.concurrent.TimeUnit.MILLISECONDS)
                }
            } ?: continue

            if (event is Event.VaultStored) return event.generation
            if (event is Event.Failed) return null
        }
        return null
    }

    /** Fetches a sealed vault, or null when the user has none. */
    suspend fun getVault(userId: String, timeoutMs: Long = 30_000): SealedVault? {
        if (!send(Wire.TYPE_GET_VAULT, Writer().string(userId).build())) return null

        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val event = withTimeoutOrNull(500) {
                kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                    vaultReply.poll(400, java.util.concurrent.TimeUnit.MILLISECONDS)
                }
            } ?: continue

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
        return null
    }
    val stream: Flow<Event> = events.receiveAsFlow()

    private var socket: WebSocket? = null

    @Volatile
    private var closed = false

    @Volatile
    private var connected = false

    /** True while the socket can accept a frame without it being dropped. */
    val isConnected: Boolean get() = connected && socket != null

    /**
     * Opens the connection and sends HELLO.
     *
     * HELLO no longer completes the registration by itself: the relay answers
     * with a nonce, and the caller has to sign it. [respondToChallenge] is
     * that second half, kept separate so the signing key never has to enter
     * this class.
     */
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

    /** Answers a [Event.Challenge]; the relay binds the user id on success. */
    fun respondToChallenge(signature: ByteArray) {
        // Deliberately not gated on `connected`: the handshake is *how* the
        // connection becomes usable, so requiring it here would drop the very
        // frame that completes it.
        write(Wire.TYPE_AUTH_RESPONSE, Writer().blob(signature).build())
    }

    private fun handleFrame(bytes: ByteArray) {
        val frame = try {
            Wire.parse(bytes)
        } catch (e: Exception) {
            Log.w(TAG, "dropping malformed frame", e)
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
                        Event.Bundle(userId, identity, signedId, signedPub, signature, otId, otPub)
                    )
                }
                Wire.TYPE_ERROR -> events.trySend(Event.Failed(r.string()))

                Wire.TYPE_PREKEYS_ACK -> preKeysAck.trySend(true)

                Wire.TYPE_VAULT_ACK -> vaultReply.offer(Event.VaultStored(r.u32()))

                Wire.TYPE_VAULT_DATA -> {
                    vaultReply.offer(
                        Event.Vault(
                            salt = r.blob(),
                            memoryKiB = r.u32(),
                            passes = r.u32(),
                            lanes = r.u32(),
                            generation = r.u32(),
                            ciphertext = r.blob(),
                        ),
                    )
                }
                else -> Log.d(TAG, "ignoring frame type ${frame.type}")
            }
        } catch (e: Exception) {
            Log.w(TAG, "dropping unparseable frame", e)
        }
    }

    fun publishPreKeys(signedId: Int, signedPub: ByteArray, signature: ByteArray,
                       oneTimeSet: ByteArray): Boolean {
        val payload = Writer()
            .u32(signedId)
            .blob(signedPub)
            .blob(signature)
            .blob(oneTimeSet)
            .build()
        return send(Wire.TYPE_PUBLISH_PREKEYS, payload)
    }

    /**
     * Waits for the relay to confirm a prekey publish.
     *
     * Returns false on timeout, which the caller treats as "not published" and
     * retries on the next connect. Without this the only way to know was to
     * sleep, and a sleep is wrong on whichever machine is slower.
     */
    suspend fun awaitPreKeysAck(timeoutMs: Long = 5_000): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (!isConnected) return false
            val event = withTimeoutOrNull(200) { preKeysAck.receive() } ?: continue
            if (event) return true
        }
        return false
    }

    fun requestBundle(userId: String): Boolean =
        send(Wire.TYPE_GET_BUNDLE, Writer().string(userId).build())
    /**
     * Queues one ciphertext frame.
     *
     * Returns false when the socket cannot take it. That is not a detail the
     * caller may ignore: the frame already advanced the ratchet, so silently
     * dropping it leaves a hole in the sending chain that the peer can never
     * decrypt.
     */
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

    private fun send(type: Int, payload: ByteArray): Boolean {
        if (!connected || closed) return false
        return write(type, payload)
    }

    /** Writes a frame if a socket exists at all, without the readiness check. */
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

    private companion object {
        const val TAG = "RelayClient"
    }
}
