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
    /**
     * What the engine actually knows about this peer.
     *
     * A cached safety number was being used as a proxy for "a session exists".
     * That outlived a restart in which the session did not, so the list could
     * claim a session was live while every message was being dropped.
     */
    val sessionState: SessionUiState = SessionUiState.NO_PEER,
)

/** Mirrors the engine's view of a peer label. */
enum class SessionUiState {
    NO_PEER,
    PINNED_ONLY,
    READY,
}

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

/**
 * A group this client is in.
 *
 * [canSend] is false right after a membership change: every chain is discarded
 * and the epoch moves, so nobody can send until each member republishes one.
 * That is the mechanism, not a bug to work around - see docs/group.md.
 */
data class GroupUi(
    val groupId: String,
    val epoch: Int,
    val members: List<String>,
    val canSend: Boolean,
)

/** One group message. No peer id: the conversation is the group. */
data class GroupMessageUi(
    val groupId: String,
    val senderId: String,
    val text: String,
    val timestamp: Long,
    val outgoing: Boolean,
)