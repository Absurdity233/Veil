package com.veil.app.data

import android.content.Context
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * In-memory store.
 *
 * Deliberately simple: the interesting part of this project is the protocol,
 * and a database layer would add a schema to maintain without changing what
 * the app can do. The interface is narrow enough that swapping in Room later
 * is a single file change.
 */
class MemoryChatStore : ChatStore {

    private val messages = ConcurrentHashMap<String, MutableList<ChatMessage>>()
    private val peers = ConcurrentHashMap<String, Peer>()
    private val nextId = AtomicLong(1)

    @Synchronized
    override fun loadMessages(peerId: String): List<ChatMessage> =
        messages[peerId]?.toList() ?: emptyList()

    @Synchronized
    override fun append(message: ChatMessage): Long {
        val id = nextId.getAndIncrement()
        val stored = message.copy(id = id)
        messages.getOrPut(message.peerId) { mutableListOf() }.add(stored)
        return id
    }

    override fun peers(): List<Peer> = peers.values.sortedBy { it.displayName }

    override fun markLastOutgoing(peerId: String, state: SendState): Boolean {
        synchronized(this) {
            val list = messages[peerId] ?: return false
            for (i in list.indices.reversed()) {
                val message = list[i]
                if (!message.outgoing) continue
                list[i] = message.copy(state = state)
                return true
            }
            return false
        }
    }

    override fun upsertPeer(peer: Peer) {
        peers[peer.userId] = peer
    }

    override fun peer(peerId: String): Peer? = peers[peerId]

    @Synchronized
    override fun clear() {
        messages.clear()
        peers.clear()
    }
}

/** Convenience accessor so callers do not have to thread the store around. */
object StoreHolder {
    @Volatile
    private var instance: ChatStore? = null

    fun get(context: Context): ChatStore =
        instance ?: synchronized(this) {
            instance ?: MemoryChatStore().also { instance = it }
        }
}
