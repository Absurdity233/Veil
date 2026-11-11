package com.veil.app.data

/**
 * One conversation partner and the messages exchanged with them.
 *
 * Message text is only ever present in memory or in the local database; it is
 * never sent anywhere except as ciphertext inside a ratchet frame.
 */
data class Peer(
    val userId: String,
    val displayName: String,
    val safetyNumber: String? = null,
)

/**
 * Where an outgoing message actually got to.
 *
 * The distinction exists because the app used to show a sent bubble for a
 * frame the relay never received. Encryption advances the ratchet, so a frame
 * that does not leave the process is a hole in the sending chain - the user has
 * to see that rather than a green tick.
 */
enum class SendState {
    /** Encrypted and waiting for the socket. */
    QUEUED,

    /** Handed to the relay. */
    SENT,

    /** The relay could not take it; it is queued for retry. */
    FAILED,
}

data class ChatMessage(
    val id: Long,
    val peerId: String,
    val outgoing: Boolean,
    val text: String,
    val timestamp: Long,
    /** Outbox id assigned by the relay; 0 for messages sent live. */
    val outboxId: Long = 0,
    /** Delivery state, meaningful for outgoing messages only. */
    val state: SendState = SendState.SENT,
)

/** Local persistence for conversations and messages. */
interface ChatStore {
    fun loadMessages(peerId: String): List<ChatMessage>
    fun append(message: ChatMessage): Long

    /**
     * Rewrites the newest outgoing message for [peerId] to [state].
     *
     * Returns false when there is nothing to update, so callers can skip the
     * refresh.
     */
    fun markLastOutgoing(peerId: String, state: SendState): Boolean

    fun peers(): List<Peer>
    fun upsertPeer(peer: Peer)
    fun peer(peerId: String): Peer?
    fun clear()
}