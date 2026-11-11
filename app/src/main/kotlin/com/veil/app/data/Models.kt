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

data class ChatMessage(
    val id: Long,
    val peerId: String,
    val outgoing: Boolean,
    val text: String,
    val timestamp: Long,
    /** Outbox id assigned by the relay; 0 for messages sent live. */
    val outboxId: Long = 0,
)

/** Local persistence for conversations and messages. */
interface ChatStore {
    fun loadMessages(peerId: String): List<ChatMessage>
    fun append(message: ChatMessage): Long
    fun peers(): List<Peer>
    fun upsertPeer(peer: Peer)
    fun peer(peerId: String): Peer?
    fun clear()
}
