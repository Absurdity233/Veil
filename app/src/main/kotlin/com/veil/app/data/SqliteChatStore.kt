package com.veil.app.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * SQLite-backed message store.
 *
 * The previous implementation was in memory, and its comment said swapping in a
 * database was a single-file change - which turned out to be true, and also the
 * reason the previous version was a bug rather than a shortcut: a chat client that
 * loses its transcript on restart is not a chat client.
 *
 * Two things about the schema:
 *
 *   - Messages are keyed by a monotonic id rather than by position, so a
 *     conversation can be paged without an offset that shifts when new messages
 *     arrive.
 *   - The send state of an outgoing message survives a restart, because a message
 *     that was queued when the process died is still queued when it comes back. The
 *     controller re-sends from the persisted frame, not from a re-encryption.
 *
 * What is stored here is plaintext on disk, inside the app's private directory.
 * That is the same trade the web client makes with its transcript: sealing it
 * would need a key held in the Keystore for every read, and the threat it defends
 * against (a script on the page, or another app) is already outside what an
 * unrooted device allows.
 */
class SqliteChatStore(context: Context) : ChatStore {

    private val helper = object : SQLiteOpenHelper(context, DB_NAME, null, DB_VERSION) {
        override fun onCreate(db: SQLiteDatabase) {
            db.execSQL(
                """
                CREATE TABLE messages (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    peer_id   TEXT    NOT NULL,
                    outgoing  INTEGER NOT NULL,
                    body      TEXT    NOT NULL,
                    sent_at   INTEGER NOT NULL,
                    state     TEXT    NOT NULL
                )
                """.trimIndent(),
            )
            // Every read is "the transcript for one conversation, oldest first",
            // so the index is exactly that.
            db.execSQL("CREATE INDEX messages_by_peer ON messages(peer_id, id)")

            db.execSQL(
                """
                CREATE TABLE peers (
                    user_id     TEXT PRIMARY KEY,
                    name        TEXT    NOT NULL,
                    safety      TEXT,
                    state       TEXT    NOT NULL
                )
                """.trimIndent(),
            )
        }

        override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            // Additive migrations only. A store that drops its table on upgrade
            // would lose every conversation the first time the schema changed,
            // which is the failure this class exists to prevent.
            if (oldVersion < 2) {
                db.execSQL("ALTER TABLE peers ADD COLUMN device_count INTEGER NOT NULL DEFAULT 0")
            }
        }
    }

    override fun loadMessages(peerId: String): List<ChatMessage> {
        val out = mutableListOf<ChatMessage>()
        helper.readableDatabase.query(
            "messages",
            arrayOf("id", "peer_id", "outgoing", "body", "sent_at", "state"),
            "peer_id = ?",
            arrayOf(peerId),
            null, null,
            "id ASC",
        ).use { cursor ->
            while (cursor.moveToNext()) {
                out += ChatMessage(
                    id = cursor.getLong(0),
                    peerId = cursor.getString(1),
                    outgoing = cursor.getInt(2) != 0,
                    text = cursor.getString(3),
                    timestamp = cursor.getLong(4),
                    state = SendState.valueOf(cursor.getString(5)),
                )
            }
        }
        return out
    }

    override fun append(message: ChatMessage): Long {
        val values = ContentValues().apply {
            put("peer_id", message.peerId)
            put("outgoing", if (message.outgoing) 1 else 0)
            put("body", message.text)
            put("sent_at", message.timestamp)
            put("state", message.state.name)
        }
        return helper.writableDatabase.insert("messages", null, values)
    }

    override fun peers(): List<Peer> {
        val out = mutableListOf<Peer>()
        helper.readableDatabase.query(
            "peers",
            arrayOf("user_id", "name", "safety", "state"),
            null, null, null, null,
            "name ASC",
        ).use { cursor ->
            while (cursor.moveToNext()) {
                out += Peer(
                    userId = cursor.getString(0),
                    displayName = cursor.getString(1),
                    safetyNumber = cursor.getString(2),
                    sessionState = SessionUiState.valueOf(cursor.getString(3)),
                )
            }
        }
        return out
    }

    override fun markLastOutgoing(peerId: String, state: SendState): Boolean {
        val db = helper.writableDatabase

        // The newest outgoing message for this peer. `id DESC LIMIT 1` rather than
        // a stored position, because a position would be wrong the moment another
        // message arrived in between.
        var target = -1L
        db.query(
            "messages", arrayOf("id"),
            "peer_id = ? AND outgoing = 1", arrayOf(peerId),
            null, null, "id DESC", "1",
        ).use { cursor ->
            if (cursor.moveToFirst()) target = cursor.getLong(0)
        }
        if (target < 0) return false

        val values = ContentValues().apply { put("state", state.name) }
        return db.update("messages", values, "id = ?", arrayOf(target.toString())) > 0
    }

    override fun upsertPeer(peer: Peer) {
        val values = ContentValues().apply {
            put("user_id", peer.userId)
            put("name", peer.displayName)
            put("safety", peer.safetyNumber)
            put("state", peer.sessionState.name)
        }
        helper.writableDatabase.insertWithOnConflict(
            "peers", null, values, SQLiteDatabase.CONFLICT_REPLACE,
        )
    }

    override fun peer(peerId: String): Peer? {
        helper.readableDatabase.query(
            "peers",
            arrayOf("user_id", "name", "safety", "state"),
            "user_id = ?", arrayOf(peerId),
            null, null, null,
        ).use { cursor ->
            if (!cursor.moveToFirst()) return null
            return Peer(
                userId = cursor.getString(0),
                displayName = cursor.getString(1),
                safetyNumber = cursor.getString(2),
                sessionState = SessionUiState.valueOf(cursor.getString(3)),
            )
        }
    }

    override fun clear() {
        helper.writableDatabase.apply {
            delete("messages", null, null)
            delete("peers", null, null)
        }
    }

    private companion object {
        const val DB_NAME = "veil-chat.db"
        const val DB_VERSION = 2
    }
}

/** Convenience accessor so callers do not have to thread the store around. */
object StoreHolder {
    @Volatile
    private var instance: ChatStore? = null

    fun get(context: Context): ChatStore =
        instance ?: synchronized(this) {
            instance ?: SqliteChatStore(context.applicationContext).also { instance = it }
        }
}
