package com.veil.app.net

import android.util.Log
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
        data class Delivered(val outboxId: Long, val sender: String, val frame: ByteArray) : Event
        data class Bundle(val userId: String, val identity: ByteArray, val signedId: Int,
                          val signedPub: ByteArray, val signature: ByteArray,
                          val oneTimeId: Int, val oneTimePub: ByteArray) : Event
        data class Failed(val message: String) : Event
        data object Disconnected : Event
    }

    private val http = OkHttpClient.Builder()
        .pingInterval(20, TimeUnit.SECONDS)
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.MILLISECONDS)  // long lived; ping keeps it alive
        .build()

    private val events = Channel<Event>(Channel.BUFFERED)
    val stream: Flow<Event> = events.receiveAsFlow()

    private var socket: WebSocket? = null
    private var connected = false

    /** Opens the connection and sends HELLO. */
    suspend fun connect(userId: String, publicIdentity: ByteArray) {
        val request = Request.Builder().url(url).build()
        val opened = suspendCancellableCoroutine { cont ->
            val listener = object : WebSocketListener() {
                override fun onOpen(ws: WebSocket, response: Response) {
                    socket = ws
                    val hello = Writer().string(userId).blob(publicIdentity).build()
                    ws.send(Wire.frame(Wire.TYPE_HELLO, hello).toByteString())
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
                Wire.TYPE_DELIVER -> {
                    val outboxId = r.u32().toLong() and 0xFFFFFFFFL
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
                else -> Log.d(TAG, "ignoring frame type ${frame.type}")
            }
        } catch (e: Exception) {
            Log.w(TAG, "dropping unparseable frame", e)
        }
    }

    fun publishPreKeys(signedId: Int, signedPub: ByteArray, signature: ByteArray,
                       oneTimeSet: ByteArray) {
        val payload = Writer()
            .u32(signedId)
            .blob(signedPub)
            .blob(signature)
            .blob(oneTimeSet)
            .build()
        send(Wire.TYPE_PUBLISH_PREKEYS, payload)
    }

    fun requestBundle(userId: String) {
        send(Wire.TYPE_GET_BUNDLE, Writer().string(userId).build())
    }

    fun sendMessage(recipient: String, frame: ByteArray) {
        send(Wire.TYPE_SEND, Writer().string(recipient).blob(frame).build())
    }

    fun acknowledge(outboxId: Long) {
        send(Wire.TYPE_ACK, Writer().u32(outboxId.toInt()).build())
    }

    private fun send(type: Int, payload: ByteArray) {
        val ws = socket ?: return
        ws.send(Wire.frame(type, payload).toByteString())
    }

    fun close() {
        socket?.close(1000, "bye")
        socket = null
        connected = false
    }

    private companion object {
        const val TAG = "RelayClient"
    }
}
