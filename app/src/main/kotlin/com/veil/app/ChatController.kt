package com.veil.app

import android.content.Context
import com.veil.app.crypto.IdentityVault
import com.veil.app.crypto.SessionVault
import com.veil.app.data.ChatMessage
import com.veil.app.data.ChatStore
import com.veil.app.data.Peer
import com.veil.app.data.SendState
import com.veil.app.data.SessionUiState
import com.veil.app.data.StoreHolder
import com.veil.app.net.RelayClient
import com.veil.app.net.Reader
import com.veil.app.net.Writer
import com.veil.core.DecryptOutcome
import com.veil.core.Handshake
import com.veil.core.SessionState
import com.veil.core.VeilEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.Executors

/** What the UI needs to know about the connection. */
enum class LinkState { Offline, Connecting, Online, Error }

/** A frame that has been encrypted but not yet handed to the relay. */
private data class PendingFrame(val peerId: String, val frame: ByteArray, val text: String)

/**
 * Glue between the UI, the relay and the native crypto engine.
 *
 * The engine owns every key. This class never sees a private key except when
 * it hands the identity secret from the vault to the engine at startup, and
 * it wipes that array immediately afterwards.
 */
class ChatController(context: Context) {

    private val appContext = context.applicationContext
    private val vault = IdentityVault(appContext)
    private val sessions = SessionVault(appContext, "veil.sessions.v1")
    private val peerPins = SessionVault(appContext, "veil.peers.v1")
    private val prekeyState = SessionVault(appContext, "veil.prekeys.v1")
    private val store: ChatStore = StoreHolder.get(appContext)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // The native engine keeps per-peer ratchet state with no internal locking,
    // so every call into it has to run on one thread. A single-threaded
    // dispatcher is cheaper than a mutex and removes the ordering question
    // entirely.
    private val crypto = Executors.newSingleThreadExecutor { r ->
        Thread(r, "veil-crypto").apply { isDaemon = true }
    }.asCoroutineDispatcher()

    @Volatile
    private var engine: VeilEngine? = null

    private var relay: RelayClient? = null
    private var pump: Job? = null

    private val _link = MutableStateFlow(LinkState.Offline)
    val link: StateFlow<LinkState> = _link.asStateFlow()

    private val _peers = MutableStateFlow<List<Peer>>(emptyList())
    val peers: StateFlow<List<Peer>> = _peers.asStateFlow()

    private val _messages = MutableStateFlow<Map<String, List<ChatMessage>>>(emptyMap())
    val messages: StateFlow<Map<String, List<ChatMessage>>> = _messages.asStateFlow()

    private val _status = MutableStateFlow<String?>(null)
    val status: StateFlow<String?> = _status.asStateFlow()

    /**
     * Frames whose encryption succeeded but whose hand-off to the relay did
     * not. They are re-sent unchanged on reconnect.
     *
     * Re-sending the *same* frame matters: encrypting again would advance the
     * sending chain a second time, and the peer would be left with a gap it
     * can never fill. The frame is already authenticated for exactly one
     * counter value, so replaying those bytes is correct and re-deriving them
     * is not.
     */
    private val pending = ArrayDeque<PendingFrame>()

    // Regenerating prekeys on every reconnect would destroy the private half of a
    // signed prekey that peers may already have fetched, silently breaking
    // their next handshake. The state is persisted instead, so a restart
    // continues the same generation (and the same id counter) rather than
    // minting a new one under a reused id.
    @Volatile
    private var hasPublishedPreKeys = false

    @Volatile
    private var selfUserId: String = ""

    // ---- Identity -------------------------------------------------------

    /**
     * Loads the stored identity, or creates one on first launch.
     *
     * Returns the 64-byte public identity, which is what the relay binds the
     * user id to.
     */
    suspend fun ensureIdentity(): ByteArray = withContext(crypto) {
        engine?.let { return@withContext it.publicIdentity() }

        val secrets = vault.load()
        val created = if (secrets != null) {
            try {
                VeilEngine.restore(secrets)
            } finally {
                secrets.fill(0)
            }
        } else {
            VeilEngine.create().also { vault.store(it.exportIdentitySecrets()) }
        }

        // Sessions and identity pins come back with the engine, before any
        // frame is decrypted. Without this a restarted process would answer
        // every message with "failed authentication", because the peer is
        // still on the ratchet the old process had.
        restoreSessions(created)

        engine = created
        created.publicIdentity()
    }

    private fun restoreSessions(engine: VeilEngine) {
        // Prekeys first: a session is built against a generation of them, and
        // the id counter plus the spent flags have to come back with the
        // engine or a restart mints a new generation under an id that was
        // already published, and forgets which one-time keys are gone.
        prekeyState.load(PREKEY_STATE)?.let { blob ->
            try {
                if (!engine.importPreKeyState(blob)) {
                    _status.value = "stored prekey state was unreadable; a fresh set will be published"
                }
            } finally {
                blob.fill(0)
            }
        }

        // Pins before sessions: a session is only meaningful for the identity
        // it was built against.
        peerPins.load()?.let { blob ->
            try {
                engine.importPeerRegistry(blob)
            } finally {
                blob.fill(0)
            }
        }

        for (peer in store.peers()) {
            val blob = sessions.load(peer.userId) ?: continue
            try {
                engine.importSession(peer.userId, blob)
            } finally {
                blob.fill(0)
            }
        }
    }

    /** Persists one session after it has advanced. Called on the crypto thread. */
    private fun persistSession(peerId: String) {
        val engine = engine ?: return
        val blob = engine.exportSession(peerId) ?: return
        try {
            sessions.store(peerId, blob)
        } finally {
            blob.fill(0)
        }
    }

    private fun persistPins() {
        val engine = engine ?: return
        val blob = engine.exportPeerRegistry() ?: return
        try {
            peerPins.store(PIN_REGISTRY, blob)
        } finally {
            blob.fill(0)
        }
    }

    private fun persistPreKeyState() {
        val engine = engine ?: return
        val blob = engine.exportPreKeyState() ?: return
        try {
            prekeyState.store(PREKEY_STATE, blob)
        } finally {
            blob.fill(0)
        }
    }

    /** The 96-byte secret blob, for the "back up identity" screen. */
    suspend fun exportIdentitySecrets(): ByteArray = withContext(crypto) {
        engine?.exportIdentitySecrets() ?: ByteArray(0)
    }

    // ---- Connection -----------------------------------------------------

    fun connect(serverUrl: String, userId: String) {
        if (_link.value == LinkState.Connecting) return

        selfUserId = userId
        _link.value = LinkState.Connecting
        _status.value = null

        scope.launch {
            try {
                val identity = ensureIdentity()
                val client = RelayClient(serverUrl)
                relay = client
                pump?.cancel()
                pump = scope.launch { pumpEvents(client) }
                client.connect(userId, identity)
            } catch (e: Exception) {
                _link.value = LinkState.Error
                _status.value = e.message ?: "connection failed"
            }
        }
    }

    fun disconnect() {
        pump?.cancel()
        relay?.close()
        relay = null
        _link.value = LinkState.Offline
    }

    private suspend fun pumpEvents(client: RelayClient) {
        client.stream.collect { event ->
            when (event) {
                is RelayClient.Event.Challenge -> answerChallenge(client, event.nonce)
                is RelayClient.Event.Connected -> {
                    _link.value = LinkState.Online
                    _status.value = null
                    publishPreKeys()
                    flushPending()
                }
                is RelayClient.Event.MorePending -> { /* the ACK that follows pulls the rest */ }
                is RelayClient.Event.Delivered -> onDelivered(event)
                is RelayClient.Event.Bundle -> onBundle(event)
                is RelayClient.Event.Failed -> {
                    _status.value = event.message
                    if (_link.value == LinkState.Connecting) _link.value = LinkState.Error
                }
                RelayClient.Event.Disconnected -> {
                    _link.value = LinkState.Offline
                }
            }
        }
    }

    /**
     * Signs the relay's nonce with the identity signing key.
     *
     * This is what makes a user id claimable only by its holder: without it the
     * relay registered whoever asked first, and anyone could take an unused id
     * and publish prekeys of their own under it.
     */
    private suspend fun answerChallenge(client: RelayClient, nonce: ByteArray) {
        val engine = engine ?: run {
            _status.value = "no identity to prove"
            return
        }
        val signature = withContext(crypto) { engine.signChallenge(nonce) }
        if (signature == null) {
            _status.value = "could not sign the relay challenge"
            return
        }
        client.respondToChallenge(signature)
    }

    /**
     * Publishes this device's prekeys so others can start a session.
     *
     * The native export is a single blob; the relay wants the signed half and
     * the one-time list separately, so the fields are split here.
     */
    private suspend fun publishPreKeys() {
        val engine = engine ?: return
        val client = relay ?: return

        // A refill is needed when the unspent supply runs low, not "once per
        // process". The old flag meant the twenty keys published at first
        // launch were the only ones this device would ever offer, so every
        // session after the twentieth silently dropped the one-time prekey.
        val needsRotation = withContext(crypto) {
            !hasPublishedPreKeys || engine.needsPreKeyRefill(REFILL_LOW_WATER)
        }
        if (!needsRotation) return

        val set = withContext(crypto) {
            engine.generatePreKeys().also {
                persistPreKeyState()   // the id counter and spent flags move on
            }
        }

        // exportPreKeySet() is a compact fixed-width layout, not the
        // length-prefixed one used on the wire:
        //   [4] signed id | [32] signed pub | [64] signature | [4] count
        //   then per one-time key: [4] id | [32] pub
        val r = Reader(set)
        val signedId = r.u32()
        val signedPub = r.raw(32)
        val signature = r.raw(64)
        val oneTime = r.raw(r.remaining)

        if (client.publishPreKeys(signedId, signedPub, signature, oneTime)) {
            hasPublishedPreKeys = true
        }
    }

    // ---- Conversations --------------------------------------------------

    /** Adds a peer, and asks the relay for a bundle only if none is pinned. */
    fun addPeer(peerId: String, displayName: String = peerId) {
        val peer = Peer(peerId, displayName)
        store.upsertPeer(peer)
        refreshPeers()

        if (peer.safetyNumber != null) {
            // A session exists: fetching another bundle would replace it, and
            // the peer's next message would no longer decrypt. Leaving the
            // session alone is the only safe answer.
            _status.value = "already talking to ${peer.displayName}"
            return
        }
        relay?.requestBundle(peerId)
    }

    private suspend fun onBundle(event: RelayClient.Event.Bundle) {
        val engine = engine ?: return

        val peer = store.peer(event.userId) ?: Peer(event.userId, event.userId)

        // An established session must never be replaced by a fresh bundle,
        // even one the relay volunteered. Re-keying mid-conversation is how a
        // hostile relay turns "the safety number did not change" into a lie.
        if (withContext(crypto) { engine.hasSession(peer.userId) }) {
            _status.value = "ignored a bundle for ${peer.displayName}: a session is already live"
            return
        }

        val bundle = buildNativeBundle(event) ?: run {
            _status.value = "malformed prekey bundle for ${event.userId}"
            return
        }

        when (withContext(crypto) { engine.establishOutbound(peer.userId, bundle) }) {
            Handshake.OK -> Unit
            Handshake.IDENTITY_CHANGED -> {
                // Not a normal error: the label was pinned to one identity and
                // the relay just answered with another. Nothing is sent until
                // the user has re-verified out of band.
                _status.value =
                    "SECURITY: ${peer.displayName} presented a different identity key. " +
                        "Do not continue until you have verified the new safety number."
                return
            }
            Handshake.BAD_SIGNATURE -> {
                _status.value = "prekey signature for ${peer.userId} did not verify"
                return
            }
            else -> {
                _status.value = "could not establish a session with ${peer.userId}"
                return
            }
        }

        val safety = withContext(crypto) {
            engine.safetyNumber(peer.userId).also { persistSession(peer.userId); persistPins() }
        }
        store.upsertPeer(peer.copy(safetyNumber = safety))
        refreshPeers()
        _status.value = "session ready with ${peer.displayName}"
    }

    /**
     * The relay sends the identity as one 64-byte blob and the one-time key
     * as separate id/public fields; the native parser wants the fixed layout
     * the engine defines.
     */
    private fun buildNativeBundle(event: RelayClient.Event.Bundle): ByteArray? {
        if (event.identity.size != 64) return null
        if (event.signedPub.size != 32) return null
        if (event.signature.size != 64) return null

        val hasOneTime = event.oneTimeId != 0 && event.oneTimePub.size == 32

        // The native parser wants fixed-width fields, so this cannot reuse
        // the length-prefixed writer used for relay frames.
        val w = Writer()
        w.raw(event.identity)      // [32] dh pub | [32] signing pub
        w.u32(event.signedId)
        w.raw(event.signedPub)
        w.raw(event.signature)
        w.raw(byteArrayOf(if (hasOneTime) 1 else 0))
        if (hasOneTime) {
            w.u32(event.oneTimeId)
            w.raw(event.oneTimePub)
        }
        return w.build()
    }

    // ---- Messaging ------------------------------------------------------

    fun sendMessage(peerId: String, text: String) {
        val engine = engine ?: return
        val client = relay ?: run {
            _status.value = "not connected: the message was not sent"
            return
        }
        if (text.isBlank()) return

        scope.launch {
            // Encrypt and send must be one step as far as the UI is concerned.
            // Encrypting advances the ratchet, so a frame that never reaches
            // the relay leaves a hole the peer cannot fill - it has to be
            // retried, not re-encrypted.
            val frame = withContext(crypto) {
                try {
                    engine.encrypt(peerId, text.toByteArray(Charsets.UTF_8))
                } catch (e: Exception) {
                    null
                }
            }
            if (frame == null) {
                _status.value = "could not encrypt for $peerId: no session"
                return@launch
            }

            appendMessage(peerId, outgoing = true, text = text, state = SendState.QUEUED)
            withContext(crypto) { persistSession(peerId) }

            if (client.isConnected && client.sendMessage(peerId, frame)) {
                markLastAs(peerId, SendState.SENT)
            } else {
                // Keep the exact bytes. A reconnect replays them rather than
                // deriving a fresh frame from an already-advanced chain.
                pending.addLast(PendingFrame(peerId, frame, text))
                markLastAs(peerId, SendState.FAILED)
                _status.value = "offline: the message is queued and will be retried"
            }
        }
    }

    /** Re-sends frames that never made it out of the process. */
    private suspend fun flushPending() {
        val client = relay ?: return
        if (!client.isConnected) return

        val stillPending = ArrayDeque<PendingFrame>()
        while (pending.isNotEmpty()) {
            val item = pending.removeFirst()
            if (client.sendMessage(item.peerId, item.frame)) {
                markLastAs(item.peerId, SendState.SENT)
            } else {
                stillPending.addLast(item)
                break
            }
        }
        if (stillPending.isNotEmpty()) {
            pending.addAll(stillPending)
            markLastAs(stillPending.first().peerId, SendState.FAILED)
        }
    }

    private suspend fun onDelivered(event: RelayClient.Event.Delivered) {
        val engine = engine ?: return
        val peerId = event.sender

        val (plain, outcome) = withContext(crypto) {
            val result = engine.decrypt(peerId, event.frame)
            if (result.second == DecryptOutcome.OK) persistSession(peerId)
            result
        }

        when (outcome) {
            DecryptOutcome.OK -> Unit

            DecryptOutcome.DUPLICATE -> {
                // The relay delivers at-least-once: a live push plus a replay
                // of the same outbox entry is routine. Acknowledge it so the
                // relay stops resending, and say nothing to the user.
                if (event.outboxId > 0) relay?.acknowledge(event.outboxId)
                return
            }

            DecryptOutcome.NO_SESSION -> {
                _status.value = "dropped a message from $peerId: no session"
                return
            }

            DecryptOutcome.TOO_FAR_AHEAD -> {
                _status.value = "dropped a message from $peerId: too far ahead of the ratchet"
                return
            }

            DecryptOutcome.AUTH_FAILED -> {
                _status.value = "dropped a message that failed authentication"
                return
            }
        }

        if (plain == null) return

        val text = String(plain, Charsets.UTF_8)
        if (store.peer(peerId) == null) {
            val safety = withContext(crypto) {
                engine.safetyNumber(peerId).also { persistPins() }
            }
            store.upsertPeer(Peer(peerId, peerId, safety))
            refreshPeers()
        }
        appendMessage(peerId, outgoing = false, text = text, state = SendState.SENT)

        if (event.outboxId > 0) relay?.acknowledge(event.outboxId)

        // The peer used up a one-time prekey, so the supply may be running
        // low. Publishing a refill now keeps the next handshake cheap.
        val client = relay
        if (client != null && withContext(crypto) { engine.needsPreKeyRefill(REFILL_LOW_WATER) }) {
            publishPreKeys()
        }
    }

    private fun appendMessage(peerId: String, outgoing: Boolean, text: String, state: SendState) {
        store.append(
            ChatMessage(
                id = 0,
                peerId = peerId,
                outgoing = outgoing,
                text = text,
                timestamp = System.currentTimeMillis(),
                state = state,
            ),
        )
        _messages.value = _messages.value + (peerId to store.loadMessages(peerId))
    }

    /** Updates the delivery state of the newest outgoing message for a peer. */
    private fun markLastAs(peerId: String, state: SendState) {
        if (store.markLastOutgoing(peerId, state)) {
            _messages.value = _messages.value + (peerId to store.loadMessages(peerId))
        }
    }

    fun messagesFor(peerId: String): List<ChatMessage> =
        _messages.value[peerId] ?: store.loadMessages(peerId)

    private fun refreshPeers() {
        // Ask the engine for the truth about each peer rather than trusting
        // the cached safety number. It is a snapshot, so it is taken on the
        // crypto thread and published as a plain list.
        val engine = engine
        val cached = store.peers()
        if (engine == null) {
            _peers.value = cached
            return
        }
        scope.launch {
            val withState = withContext(crypto) {
                cached.map { peer ->
                    peer.copy(sessionState = engineStates(engine, peer.userId))
                }
            }
            _peers.value = withState
        }
    }

    private fun engineStates(engine: VeilEngine, peerId: String): SessionUiState =
        when (engine.sessionState(peerId)) {
            SessionState.READY -> SessionUiState.READY
            SessionState.PINNED_ONLY -> SessionUiState.PINNED_ONLY
            SessionState.NO_PEER -> SessionUiState.NO_PEER
        }

    /** Cached value from the store; safe to call from the UI thread. */
    fun safetyNumberFor(peerId: String): String? = store.peer(peerId)?.safetyNumber

    /**
     * The engine's view of a peer, which is the only one that stays true.
     *
     * The UI used "a safety number is cached" as a proxy for "a session
     * exists". That survived a restart in which the session did not, so the
     * screen could claim a session was live while every message in both
     * directions was being dropped.
     */
    suspend fun sessionState(peerId: String): SessionUiState = withContext(crypto) {
        val engine = engine ?: return@withContext SessionUiState.NO_PEER
        engineStates(engine, peerId)
    }

    fun hasSession(peerId: String): Boolean = store.peer(peerId)?.safetyNumber != null

    private companion object {
        const val PIN_REGISTRY = "registry"
        const val PREKEY_STATE = "state"

        // How few unspent one-time prekeys trigger a refill. Half a batch
        // leaves room for a burst of new peers without ever running dry.
        const val REFILL_LOW_WATER = 10
    }
}