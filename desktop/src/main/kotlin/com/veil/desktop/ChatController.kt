package com.veil.desktop

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
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.Executors

/** What the UI needs to know about the connection. */
enum class LinkState { OFFLINE, CONNECTING, ONLINE, ERROR }

/** Where an outgoing message actually got to. */
enum class SendState { QUEUED, SENT, FAILED }

data class ChatMessage(
    val id: Long,
    val peerId: String,
    val outgoing: Boolean,
    val text: String,
    val timestamp: Long,
    val state: SendState = SendState.SENT,
)

data class Peer(
    val userId: String,
    val displayName: String,
    val safetyNumber: String? = null,
    val state: SessionState = SessionState.NO_PEER,
    /** The peer's device ids, hex. Empty means a single-device peer. */
    val devices: List<String> = emptyList(),
)

/**
 * A group this client is in.
 *
 * [canSend] is false right after a membership change: every chain is discarded
 * and the epoch moves, so nobody can send until each member republishes one.
 * That is the mechanism, not a bug to work around - see docs/group.md.
 */
data class Group(
    val groupId: String,
    val epoch: Int,
    val members: List<String>,
    val canSend: Boolean,
)

/** One group message. No peer id: the conversation is the group. */
data class GroupMessage(
    val groupId: String,
    val senderId: String,
    val text: String,
    val timestamp: Long,
    val outgoing: Boolean,
)

/**
 * Glue between the window, the relay and the C ABI.
 *
 * Structurally the same as the Android client's `ChatController`, and for the
 * same reason: the interesting logic is in the engine, and a platform client is
 * transport plus storage plus a window. The one genuinely platform-specific
 * thing here is [Vault] - on the phone the keys live behind the Android
 * Keystore; on a desktop there is no equivalent, so they live in a file with
 * owner-only permissions and the difference is stated rather than hidden.
 */
class ChatController(private val stateDir: Path) {

    private val vault = Vault(stateDir)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** One thread for the engine: it has no internal locking, by design. */
    private val crypto = Executors.newSingleThreadExecutor { r ->
        Thread(r, "veil-crypto").apply { isDaemon = true }
    }.asCoroutineDispatcher()

    @Volatile
    private var engine: VeilEngine? = null

    private var relay: RelayClient? = null
    private var pump: Job? = null

    private val _link = MutableStateFlow(LinkState.OFFLINE)
    val link: StateFlow<LinkState> = _link.asStateFlow()

    private val _peers = MutableStateFlow<List<Peer>>(emptyList())
    val peers: StateFlow<List<Peer>> = _peers.asStateFlow()

    private val _messages = MutableStateFlow<Map<String, List<ChatMessage>>>(emptyMap())
    val messages: StateFlow<Map<String, List<ChatMessage>>> = _messages.asStateFlow()

    private val _status = MutableStateFlow<String?>(null)
    val status: StateFlow<String?> = _status.asStateFlow()

    private val _groups = MutableStateFlow<List<Group>>(emptyList())
    val groups: StateFlow<List<Group>> = _groups.asStateFlow()

    private val _groupMessages = MutableStateFlow<Map<String, List<GroupMessage>>>(emptyMap())
    val groupMessages: StateFlow<Map<String, List<GroupMessage>>> = _groupMessages.asStateFlow()

    /** This client's own device id, hex. Empty until one has been created. */
    var deviceId: String = ""
        private set

    /** The user id this client connected as; empty before the first connect. */
    private var userId: String = ""

    /**
     * Gives this client a device identity without connecting.
     *
     * A device is local state: a group is created, a member list is signed and a
     * chain is published without a relay being involved. Requiring a connection
     * for those would make an offline client unable to set anything up, and it
     * would make the requirement invisible until the first call failed.
     */
    suspend fun claimDevice(userId: String): Boolean = withContext(crypto) {
        this@ChatController.userId = userId
        ensureDevice(userId)
        return@withContext deviceId.isNotEmpty()
    }

    /** Frames encrypted but not yet handed to the relay. */
    private val pending = ArrayDeque<PendingFrame>()

    /**
     * A frame waiting to be sent.
     *
     * The device id travels beside the bytes rather than being recovered at send
     * time: the frame was encrypted to one device's ratchet, and re-deriving
     * which one would be a guess that gets it wrong exactly when a peer links a
     * second device.
     */
    private data class PendingFrame(
        val peerId: String,
        val deviceId: String,
        val frame: ByteArray,
    )

    private var messageSeq = 0L
    private var nextMessageId = 1L

    @Volatile
    private var hasPublishedPreKeys = false

    // ---- Identity -------------------------------------------------------

    suspend fun ensureIdentity(): ByteArray = withContext(crypto) {
        engine?.let { return@withContext it.publicIdentity() }

        val loaded = vault.loadIdentity()
        val created = if (loaded != null) {
            try {
                VeilEngine.restore(loaded)
            } finally {
                loaded.fill(0)
            }
        } else {
            VeilEngine.create().also { vault.storeIdentity(it.identitySecrets()) }
        }

        restoreState(created)
        engine = created
        created.publicIdentity()
    }

    private fun restoreState(engine: VeilEngine) {
        // Prekey state first: a session is built against a generation of them,
        // and the id counter plus the spent flags have to come back or a
        // restart mints a new generation under an id already published.
        vault.loadPreKeyState()?.let { blob ->
            try {
                engine.importPreKeyState(blob)
            } finally {
                blob.fill(0)
            }
        }

        vault.loadRegistry()?.let { blob ->
            try {
                engine.importPeerRegistry(blob)
            } finally {
                blob.fill(0)
            }
        }

        for (peer in _peers.value) {
            vault.loadSession(peer.userId)?.let { blob ->
                try {
                    engine.importSession(peer.userId, blob)
                } finally {
                    blob.fill(0)
                }
            }

            // The transcript comes back from disk. A chat client that lost it on
            // restart would show an empty conversation for a peer it had been
            // talking to for a week.
            val thread = vault.loadMessages(peer.userId)
            if (thread.isNotEmpty()) {
                _messages.value = _messages.value + (peer.userId to thread)
                // The id counter has to resume above what was loaded, or a new
                // message would reuse an id and a state update would hit the
                // wrong one.
                nextMessageId = maxOf(nextMessageId, thread.maxOf { it.id } + 1)
            }
        }

        // Groups and the device id last, because both depend on the engine
        // having its identity: a group's chain keys are derived from it, and a
        // device id is only meaningful alongside one.
        restoreGroups(engine)
        vault.loadDeviceId()?.let { deviceId = it }
    }

    private fun persistSession(peerId: String) {
        val engine = engine ?: return
        val blob = engine.exportSession(peerId) ?: return
        try {
            vault.storeSession(peerId, blob)
        } finally {
            blob.fill(0)
        }
    }

    private fun persistPreKeys() {
        val engine = engine ?: return
        val blob = engine.exportPreKeyState()
        try {
            vault.storePreKeyState(blob)
        } finally {
            blob.fill(0)
        }
    }

    private fun persistRegistry() {
        val engine = engine ?: return
        val blob = engine.exportPeerRegistry()
        try {
            vault.storeRegistry(blob)
        } finally {
            blob.fill(0)
        }
    }

    // ---- Connection -----------------------------------------------------

    fun connect(serverUrl: String, userId: String) {
        if (_link.value == LinkState.CONNECTING) return

        _link.value = LinkState.CONNECTING
        _status.value = null

        scope.launch {
            try {
                this@ChatController.userId = userId
                val identity = ensureIdentity()

                // Claim a device before connecting, so HELLO can announce it.
                // A restart finds the stored id rather than minting a second
                // device for the same account.
                withContext(crypto) { ensureDevice(userId) }

                val client = RelayClient(serverUrl)
                relay = client
                pump?.cancel()
                pump = scope.launch { pumpEvents(client) }
                client.connect(userId, identity, deviceId)
            } catch (e: Exception) {
                _link.value = LinkState.ERROR
                _status.value = e.message ?: "connection failed"
            }
        }
    }

    /**
     * Gives this client a device identity, reusing the stored one when present.
     *
     * Must run on the crypto executor: it touches the engine and the vault.
     */
    private fun ensureDevice(userId: String) {
        val engine = engine ?: return

        val stored = vault.loadDeviceId()
        if (stored != null) {
            deviceId = stored
            return
        }

        if (!engine.initDevice(userId)) return
        val raw = engine.deviceId() ?: return

        deviceId = raw.joinToString("") { "%02x".format(it) }
        vault.storeDeviceId(deviceId)
    }

    fun disconnect() {
        pump?.cancel()
        relay?.close()
        relay = null
        _link.value = LinkState.OFFLINE
    }

    private suspend fun pumpEvents(client: RelayClient) {
        client.stream.collect { event ->
            when (event) {
                is RelayClient.Event.Challenge -> answerChallenge(client, event.nonce)
                is RelayClient.Event.Connected -> {
                    _link.value = LinkState.ONLINE
                    _status.value = null
                    publishPreKeys()
                    flushPending()
                }
                is RelayClient.Event.MorePending -> Unit
                is RelayClient.Event.Delivered -> onDelivered(event)
                is RelayClient.Event.Bundle -> onBundle(event)
                is RelayClient.Event.Failed -> {
                    _status.value = event.message
                    if (_link.value == LinkState.CONNECTING) _link.value = LinkState.ERROR
                }
                RelayClient.Event.Disconnected -> _link.value = LinkState.OFFLINE

                // Vault replies never reach this pump: they are delivered to the
                // account dialog through RelayClient's own slot, so a message
                // arriving mid-request is not swallowed by whoever reads the
                // channel first.
                is RelayClient.Event.Vault, is RelayClient.Event.VaultStored -> Unit
            }
        }
    }

    private suspend fun answerChallenge(client: RelayClient, nonce: ByteArray) {
        val engine = engine ?: return
        val signature = withContext(crypto) { engine.signChallenge(nonce) }
        client.respondToChallenge(signature)
    }

    private suspend fun publishPreKeys() {
        val engine = engine ?: return
        val client = relay ?: return

        val due = withContext(crypto) {
            !hasPublishedPreKeys || engine.needsPreKeyRefill(REFILL_LOW_WATER)
        }
        if (!due) return

        val set = withContext(crypto) {
            engine.rotatePreKeys().also { persistPreKeys() }
        }

        // [4] signed id | [32] signed pub | [64] signature | [4] count | entries
        val r = Reader(set)
        val signedId = r.u32()
        val signedPub = r.raw(32)
        val signature = r.raw(64)
        r.u32()  // count, not needed: the set is passed through verbatim
        val oneTime = r.raw(r.remaining)

        if (client.publishPreKeys(signedId, signedPub, signature, oneTime)) {
            hasPublishedPreKeys = true
        }
    }

    // ---- Peers ----------------------------------------------------------

    fun addPeer(peerId: String) {
        val existing = _peers.value.firstOrNull { it.userId == peerId }
        if (existing != null) {
            _status.value = "already talking to ${existing.displayName}"
            return
        }
        _peers.value = _peers.value + Peer(peerId, peerId)
        relay?.requestBundle(peerId)
    }

    private suspend fun onBundle(event: RelayClient.Event.Bundle) {
        val engine = engine ?: return

        // Never replace a live session with a volunteered bundle. Re-keying
        // mid-conversation is how a hostile relay turns "the safety number did
        // not change" into a lie.
        if (withContext(crypto) { engine.sessionState(event.userId) } == SessionState.READY) {
            _status.value = "ignored a bundle for ${event.userId}: a session is already live"
            return
        }

        val bundle = buildBundle(event) ?: run {
            _status.value = "malformed prekey bundle for ${event.userId}"
            return
        }

        when (withContext(crypto) { engine.establishOutbound(event.userId, bundle) }) {
            VeilEngine.Status.OK -> Unit
            VeilEngine.Status.IDENTITY_CHANGED -> {
                _status.value =
                    "SECURITY: ${event.userId} presented a different identity key. " +
                        "Verify the new safety number before continuing."
                return
            }
            VeilEngine.Status.BAD_SIGNATURE -> {
                _status.value = "prekey signature for ${event.userId} did not verify"
                return
            }
            else -> {
                _status.value = "could not establish a session with ${event.userId}"
                return
            }
        }

        val safety = withContext(crypto) {
            engine.safetyNumber(event.userId).also {
                persistSession(event.userId)
                persistRegistry()
            }
        }
        updatePeer(event.userId) { it.copy(safetyNumber = safety, state = SessionState.READY) }
        _status.value = "session ready with ${event.userId}"
    }

    /**
     * Rebuilds the fixed-width bundle the engine parses from the relay's fields.
     *
     *   [64] identity | [4] signed id | [32] signed pub | [64] signature
     *   [1]  has one-time | [4] one-time id | [32] one-time pub
     */
    private fun buildBundle(event: RelayClient.Event.Bundle): ByteArray? {
        if (event.identity.size != 64) return null
        if (event.signedPub.size != 32) return null
        if (event.signature.size != 64) return null

        val hasOneTime = event.oneTimeId != 0 && event.oneTimePub.size == 32

        val w = Writer()
        w.raw(event.identity)
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
        val client = relay
        if (text.isBlank()) return

        scope.launch {
            // One plaintext, one frame per device of the peer. A single-device
            // peer yields exactly one frame, so the caller still passes a user
            // id and does not have to know which case it is.
            val frames = withContext(crypto) {
                engine.encryptToAccount(peerId, text.toByteArray(Charsets.UTF_8))
            }
            if (frames.isEmpty()) {
                _status.value = "could not encrypt for $peerId: no session"
                return@launch
            }

            appendMessage(peerId, outgoing = true, text = text, state = SendState.QUEUED)
            withContext(crypto) { persistSession(peerId) }

            var allSent = true
            if (client != null && client.isConnected) {
                for ((targetDevice, frame) in frames) {
                    if (!client.sendMessage(peerId, frame, targetDevice)) allSent = false
                }
            } else {
                allSent = false
            }

            if (allSent) {
                markLastAs(peerId, SendState.SENT)
            } else {
                // Keep the exact bytes: re-encrypting would advance the sending
                // chain a second time and leave the peer with a hole it can
                // never fill.
                for ((targetDevice, frame) in frames) {
                    pending.addLast(PendingFrame(peerId, targetDevice, frame))
                }
                markLastAs(peerId, SendState.FAILED)
                _status.value = "offline: the message is queued and will be retried"
            }
        }
    }

    // ---- Groups -----------------------------------------------------------

    /** Creates a group with this client as founder and sole member. */
    fun createGroup(groupId: String) {
        val engine = engine ?: return
        if (groupId.isBlank()) return

        scope.launch {
            // A group needs a founder, and the founder is this device's user, so
            // the device has to exist. It does *not* need a connection: creating
            // a group is local until the member list is handed to somebody, and
            // gating it on the relay would make an offline client unable to set
            // one up.
            val ready = withContext(crypto) {
                if (deviceId.isEmpty()) {
                    if (userId.isEmpty()) return@withContext false
                    ensureDevice(userId)
                }
                deviceId.isNotEmpty() && engine.createGroup(groupId)
            }
            if (!ready) {
                _status.value = "could not create $groupId: no device identity"
                return@launch
            }
            refreshGroup(groupId)
        }
    }

    /**
     * Replaces the member list and bumps the epoch.
     *
     * Every chain is discarded, including this client's: a removed member holds
     * the old chain key, and re-keying is the only thing that stops them reading
     * what follows.
     */
    fun setGroupMembers(groupId: String, members: List<String>) {
        val engine = engine ?: return

        scope.launch {
            val epoch = withContext(crypto) { engine.setGroupMembers(groupId, members) }
            if (epoch == 0) {
                _status.value = "only the founder may change $groupId's members"
                return@launch
            }
            refreshGroup(groupId)
        }
    }

    /** The signed member list, to hand to the other members. */
    fun exportMembership(groupId: String): ByteArray? =
        engine?.let { withContextBlocking { it.exportMembership(groupId) } }

    /** Adopts a member list the founder signed. */
    fun adoptMembership(groupId: String, record: ByteArray, founderSignPub: ByteArray) {
        val engine = engine ?: return

        scope.launch {
            val status = withContext(crypto) { engine.adoptMembership(record, founderSignPub) }
            if (status != VeilC.OK) {
                _status.value = "that member list was refused (status $status)"
                return@launch
            }
            refreshGroup(groupId)
        }
    }

    /** This device's chain for the group's current epoch. */
    fun exportSenderKey(groupId: String): ByteArray? =
        engine?.let { withContextBlocking { it.exportSenderKey(groupId) } }

    /** Installs a member's chain, as received over a pairwise session. */
    fun adoptSenderKey(groupId: String, record: ByteArray, senderId: String,
                       senderSignPub: ByteArray) {
        val engine = engine ?: return

        scope.launch {
            val status = withContext(crypto) {
                engine.adoptSenderKey(record, senderId, senderSignPub)
            }
            if (status != VeilC.OK) {
                _status.value = "that chain was refused (status $status)"
                return@launch
            }
            refreshGroup(groupId)
        }
    }

    /** One message to the whole group: one frame, regardless of size. */
    fun sendToGroup(groupId: String, text: String) {
        val engine = engine ?: return
        val client = relay
        if (text.isBlank()) return

        scope.launch {
            val record = withContext(crypto) {
                engine.encryptToGroup(groupId, text.toByteArray(Charsets.UTF_8))
            }
            if (record == null) {
                _status.value = "cannot send to $groupId: the group has no live chain"
                return@launch
            }

            appendGroupMessage(groupId, senderId = "", text = text, outgoing = true)

            // A group frame is addressed by group id, not by device: every member
            // needs it, and device addressing is what pairwise frames use.
            if (client == null || !client.isConnected || !client.sendMessage(groupId, record)) {
                _status.value = "offline: the group message was not delivered"
            }
            persistGroups()
        }
    }

    private suspend fun flushPending() {
        val client = relay ?: return
        if (!client.isConnected) return

        val still = ArrayDeque<PendingFrame>()
        while (pending.isNotEmpty()) {
            val item = pending.removeFirst()
            if (client.sendMessage(item.peerId, item.frame, item.deviceId)) {
                markLastAs(item.peerId, SendState.SENT)
            } else {
                still.addLast(item)
                break
            }
        }
        pending.addAll(still)
    }

    private suspend fun onDelivered(event: RelayClient.Event.Delivered) {
        val engine = engine ?: return
        val peerId = event.sender

        val (plain, status) = withContext(crypto) {
            val result = engine.decrypt(peerId, event.frame)
            if (result.second == VeilEngine.Status.OK) persistSession(peerId)
            result
        }

        when (status) {
            VeilEngine.Status.OK -> Unit
            VeilEngine.Status.DUPLICATE -> {
                // At-least-once delivery makes this routine. Acknowledge so the
                // relay stops resending, and say nothing.
                if (event.outboxId > 0) relay?.acknowledge(event.outboxId)
                return
            }
            VeilEngine.Status.NO_SESSION -> {
                // Not necessarily an error: a group message arrives addressed by
                // its sender, and this client may hold no pairwise session with
                // them. Try it as a group frame before dropping it - the MAC on
                // each group decides, not a guess.
                if (withContext(crypto) { tryDeliverAsGroup(peerId, event.frame) }) {
                    if (event.outboxId > 0) relay?.acknowledge(event.outboxId)
                    return
                }
                _status.value = "dropped a message from $peerId: no session"
                return
            }
            VeilEngine.Status.AUTH_FAILED -> {
                _status.value = "dropped a message that failed authentication"
                return
            }
            else -> {
                _status.value = "dropped a message from $peerId (${status.name.lowercase()})"
                return
            }
        }

        if (plain == null) return

        val engineForInvite = engine

        // An invitation is message content, not a wire type, so it is recognised
        // here rather than by the relay. It never reaches the transcript: a blob
        // of prefix and lengths is not something a person wants to read.
        val isInvite = withContext(crypto) { engineForInvite.looksLikeInvite(plain) }
        if (isInvite) {
            withContext(crypto) { acceptInviteFrom(peerId, plain) }
            if (event.outboxId > 0) relay?.acknowledge(event.outboxId)
            return
        }

        val text = String(plain, Charsets.UTF_8)
        if (_peers.value.none { it.userId == peerId }) {
            _peers.value = _peers.value + Peer(peerId, peerId)
        }
        val safety = withContext(crypto) {
            engine.safetyNumber(peerId).also { persistRegistry() }
        }
        updatePeer(peerId) { it.copy(safetyNumber = safety, state = SessionState.READY) }

        appendMessage(peerId, outgoing = false, text = text, state = SendState.SENT)
        if (event.outboxId > 0) relay?.acknowledge(event.outboxId)

        val client = relay
        if (client != null && withContext(crypto) { engine.needsPreKeyRefill(REFILL_LOW_WATER) }) {
            publishPreKeys()
        }
    }

    private fun appendMessage(peerId: String, outgoing: Boolean, text: String, state: SendState) {
        val message = ChatMessage(
            id = nextMessageId++,
            peerId = peerId,
            outgoing = outgoing,
            text = text,
            timestamp = System.currentTimeMillis(),
            state = state,
        )
        val current = _messages.value[peerId].orEmpty()
        _messages.value = _messages.value + (peerId to current + message)
        messageSeq++
        persistMessages(peerId)
    }

    /**
     * Writes one conversation to disk.
     *
     * Called on every append and every state change rather than on a timer: a
     * client that lost the last message of a conversation to a crash would look
     * like the peer never sent it, and the user has no way to tell the difference.
     */
    private fun persistMessages(peerId: String) {
        val thread = _messages.value[peerId] ?: return
        runCatching {
            vault.storeMessages(
                peerId,
                thread.map {
                    ChatMessage(
                        id = it.id,
                        peerId = it.peerId,
                        outgoing = it.outgoing,
                        text = it.text,
                        timestamp = it.timestamp,
                        state = it.state,
                    )
                },
            )
        }
    }

    private fun markLastAs(peerId: String, state: SendState) {
        val current = _messages.value[peerId] ?: return
        val index = current.indexOfLast { it.outgoing }
        if (index < 0) return
        val updated = current.toMutableList()
        updated[index] = updated[index].copy(state = state)
        _messages.value = _messages.value + (peerId to updated)
    }

    private fun updatePeer(peerId: String, change: (Peer) -> Peer) {
        _peers.value = _peers.value.map { if (it.userId == peerId) change(it) else it }
    }

    // ---- Group plumbing ---------------------------------------------------

    fun messagesForGroup(groupId: String): List<GroupMessage> =
        _groupMessages.value[groupId] ?: emptyList()

    /** Re-reads a group from the engine and republishes the view. */
    private suspend fun refreshGroup(groupId: String) {
        val engine = engine ?: return

        val snapshot = withContext(crypto) {
            val epoch = engine.groupEpoch(groupId)
            if (epoch == 0) return@withContext null

            Group(
                groupId = groupId,
                epoch = epoch,
                members = engine.groupMembers(groupId),
                canSend = engine.isGroupMember(groupId),
            )
        } ?: return

        _groups.value = (_groups.value.filterNot { it.groupId == groupId } + snapshot)
            .sortedBy { it.groupId }

        if (!_groupMessages.value.containsKey(groupId)) {
            _groupMessages.value = _groupMessages.value + (groupId to emptyList())
        }

        persistGroups()
    }

    private fun appendGroupMessage(groupId: String, senderId: String, text: String,
                                   outgoing: Boolean) {
        val message = GroupMessage(
            groupId = groupId,
            senderId = senderId,
            text = text,
            timestamp = System.currentTimeMillis(),
            outgoing = outgoing,
        )
        val existing = _groupMessages.value[groupId] ?: emptyList()
        _groupMessages.value = _groupMessages.value + (groupId to (existing + message))
    }

    /**
     * Tries a delivery as a group frame.
     *
     * A group message arrives addressed by its sender, and this client may hold
     * no pairwise session with them. The MAC on each group decides whether it
     * was one - trying each group is a search over a small set, and the
     * alternative would be guessing which conversation a frame belongs to.
     */
    private fun tryDeliverAsGroup(senderId: String, frame: ByteArray): Boolean {
        val engine = engine ?: return false

        for (group in _groups.value) {
            val plain = withContextBlocking { engine.decryptFromGroup(group.groupId, frame) }
                ?: continue

            appendGroupMessage(group.groupId, senderId, String(plain, Charsets.UTF_8),
                outgoing = false)
            withContextBlocking { persistGroups() }
            return true
        }
        return false
    }

    /** Persists group state and the id list. Carries chain keys. */
    private fun persistGroups() {
        val engine = engine ?: return

        engine.exportGroupState()?.let { vault.storeGroupState(it) }
        vault.storeGroupIds(_groups.value.map { it.groupId })
    }

    // ---- Invitations and linking ------------------------------------------

    /**
     * Invites one person to a group.
     *
     * The invitation is an ordinary message: encrypted to their session and sent
     * like anything else, so the relay learns only that a message was sent.
     * Requires a pairwise session, which is what authenticates the founder.
     */
    fun inviteToGroup(groupId: String, peerId: String) {
        val engine = engine ?: return
        val client = relay ?: return

        scope.launch {
            val invite = withContext(crypto) { engine.encodeInvite(groupId) }
            if (invite == null) {
                _status.value = "cannot invite: $groupId has no chain yet"
                return@launch
            }

            val frames = withContext(crypto) {
                engine.encryptToAccount(peerId, invite)
            }
            if (frames.isEmpty()) {
                _status.value = "cannot invite $peerId: no session with them yet"
                return@launch
            }

            var sent = false
            if (client.isConnected) {
                for ((device, frame) in frames) {
                    if (client.sendMessage(peerId, frame, device)) sent = true
                }
            }
            _status.value = if (sent) {
                "invitation sent to $peerId"
            } else {
                "offline: the invitation was not delivered"
            }
        }
    }

    /** This device's linking request, for the existing device to endorse. */
    suspend fun linkingRequest(): ByteArray? = withContext(crypto) {
        engine?.linkingRequest()
    }

    /** The account a request names and its fingerprint, from the same bytes. */
    suspend fun readLinkingRequest(data: ByteArray): Pair<String, String>? =
        withContext(crypto) { engine?.readLinkingRequest(data) }

    /**
     * Signs an endorsement for another device.
     *
     * Null when this client does not hold the account key, which is the correct
     * answer rather than an error: a linked device cannot add further devices.
     */
    suspend fun approveLinking(request: ByteArray): ByteArray? = withContext(crypto) {
        engine?.approveLinking(request, System.currentTimeMillis() / 1000)
    }

    /**
     * Adopts an endorsement from two base64 strings the user pasted.
     *
     * The account identity arrives as one 64-byte blob (DH public || signing
     * public), which is what the approving device produces. Splitting it here
     * rather than asking the user for two strings is deliberate: one field is one
     * thing to copy, and the split is not a decision a person should have to make.
     */
    suspend fun adoptLinkingFromText(credentialText: String, identityText: String): Boolean {
        val credential = fromBase64(credentialText) ?: return false
        val identity = fromBase64(identityText) ?: return false
        if (identity.size != 64) return false

        return withContext(crypto) {
            val ok = engine?.adoptDeviceCredential(
                credential,
                identity.copyOfRange(0, 32),
                identity.copyOfRange(32, 64),
            )
            if (ok == true) {
                engine?.deviceId()?.let { raw ->
                    deviceId = raw.joinToString("") { "%02x".format(it) }
                    vault.storeDeviceId(deviceId)
                }
                persistGroups()
            }
            ok == true
        }
    }

    private fun fromBase64(text: String): ByteArray? = try {
        val cleaned = text.filterNot { it.isWhitespace() }
        if (cleaned.isEmpty()) null else java.util.Base64.getDecoder().decode(cleaned)
    } catch (e: IllegalArgumentException) {
        null
    }

    // ---- Accounts ---------------------------------------------------------
    //
    // A password that lets the identity be restored on another device. What goes
    // over the wire is a blob sealed under a key derived from it with Argon2id,
    // so the relay cannot verify the password and cannot open the vault.

    /** Uploads this client's whole state, sealed under the password. */
    suspend fun createAccount(password: String): String? = withContext(crypto) {
        val engine = engine ?: return@withContext "the engine is not loaded"
        val client = relay ?: return@withContext "connect before creating an account"
        if (userId.isEmpty()) return@withContext "connect with an id first"

        val problem = checkPassword(password)
        if (problem != null) return@withContext problem

        val identity = engine.identitySecrets()
        val plain = buildVaultPlaintext(engine, identity)
        identity.fill(0)

        val sealed = sealVault(plain, password)
        val generation = client.putVault(
            userId,
            sealed.salt,
            sealed.memoryKiB,
            sealed.passes,
            sealed.lanes,
            sealed.ciphertext,
        ) ?: return@withContext "the relay did not accept the vault"

        _status.value = "account stored (generation $generation)"
        null
    }

    /**
     * Restores this client's state from the vault.
     *
     * A wrong password fails to open the vault, which is the only check available:
     * there is no password hash to compare against.
     */
    suspend fun restoreAccount(id: String, password: String): String? = withContext(crypto) {
        val client = relay ?: return@withContext "connect before signing in"

        val stored = client.getVault(id) ?: return@withContext "no account stored for $id"
        val plain = openVault(stored, password)
            ?: return@withContext "wrong password, or the stored account is damaged"

        engine?.close()
        val restored = VeilEngine.restore(plain.identity)
        engine = restored
        vault.storeIdentity(plain.identity)
        plain.identity.fill(0)

        plain.preKeyState?.let { restored.importPreKeyState(it) }
        plain.peerRegistry?.let { restored.importPeerRegistry(it) }
        plain.groupState?.let { restored.importGroupState(it) }

        restored.exportPreKeyState()?.let { vault.storePreKeyState(it) }
        restored.exportPeerRegistry()?.let { vault.storeRegistry(it) }
        restored.exportGroupState()?.let { vault.storeGroupState(it) }

        this@ChatController.userId = id
        restoreState(restored)

        _status.value = "restored $id from the account store"
        null
    }

    /** Re-seals the vault under a new password, after proving the old one. */
    suspend fun changePassword(oldPassword: String, newPassword: String): String? =
        withContext(crypto) {
            val engine = engine ?: return@withContext "the engine is not loaded"
            val client = relay ?: return@withContext "connect before changing the password"
            if (userId.isEmpty()) return@withContext "connect with an id first"

            val problem = checkPassword(newPassword)
            if (problem != null) return@withContext problem

            // Prove the old password against the stored vault. Re-sealing is the
            // one moment a typo would produce an account this browser cannot open.
            val current = client.getVault(userId)
                ?: return@withContext "there is no account stored yet"
            val opened = openVault(current, oldPassword)
                ?: return@withContext "the current password is wrong"
            opened.identity.fill(0)

            val identity = engine.identitySecrets()
            val plain = buildVaultPlaintext(engine, identity)
            identity.fill(0)

            val sealed = sealVault(plain, newPassword)
            val generation = client.putVault(
                userId,
                sealed.salt,
                sealed.memoryKiB,
                sealed.passes,
                sealed.lanes,
                sealed.ciphertext,
            ) ?: return@withContext "the relay did not accept the new password"

            _status.value = "password changed (generation $generation). Sign out " +
                "other devices first: their next write would overwrite this one."
            null
        }

    /**
     * Flattens the transcript for the vault.
     *
     * A delimiter-separated string rather than a nested structure: the vault only
     * needs to carry it, and a format the reader can rebuild with one `split` is
     * one that cannot drift from a schema nobody maintains. The separators are
     * control characters that a message body cannot contain unescaped, because
     * they are stripped on input.
     */
    private fun buildVaultPlaintext(engine: VeilEngine, identity: ByteArray): VaultPlain {
        val records = mutableListOf<String>()
        for ((peerId, thread) in _messages.value) {
            for (m in thread) {
                records += buildString {
                    append(peerId).append('\u0002')
                    append(if (m.outgoing) 1 else 0).append('\u0002')
                    append(m.timestamp).append('\u0002')
                    append(m.state.name).append('\u0002')
                    append(m.text.replace("\u0002", " ").replace("\u0000", " ").replace("\u0001", " "))
                }
            }
        }
        val history = records.joinToString("\u0001")

        return VaultPlain(
            identity = identity,
            preKeyState = engine.exportPreKeyState(),
            peerRegistry = engine.exportPeerRegistry(),
            groupState = engine.exportGroupState(),
            history = history.toByteArray(Charsets.UTF_8),
        )
    }

    /**
     * Accepts an invitation that arrived from [peerId].
     *
     * The founder's signing key comes from the peer's own credential, which this
     * client already pins 閳?so "alice invited me" is checked against the alice
     * this client verified, not against whoever sent the bytes.
     */
    private suspend fun acceptInviteFrom(peerId: String, payload: ByteArray) {
        val engine = engine ?: return

        val founderSignPub = engine.peerDeviceSignPublic(peerId)
        if (founderSignPub == null) {
            _status.value = "an invitation arrived from $peerId but could not be verified"
            return
        }

        val groupId = engine.acceptInvite(payload, peerId, founderSignPub)
        if (groupId == null) {
            _status.value = "an invitation from $peerId was refused"
            return
        }

        refreshGroup(groupId)
        appendGroupMessage(groupId, senderId = peerId, text = "joined the group",
            outgoing = false)
        _status.value = "joined $groupId"
    }

    /** Reloads groups after a restart, so a reload does not drop every one. */
    private fun restoreGroups(engine: VeilEngine) {
        vault.loadGroupState()?.let { engine.importGroupState(it) }

        val restored = vault.loadGroupIds().mapNotNull { groupId ->
            val epoch = engine.groupEpoch(groupId)
            if (epoch == 0) return@mapNotNull null

            Group(
                groupId = groupId,
                epoch = epoch,
                members = engine.groupMembers(groupId),
                canSend = engine.isGroupMember(groupId),
            )
        }

        if (restored.isNotEmpty()) {
            _groups.value = restored
            _groupMessages.value = restored.associate { it.groupId to emptyList() }
        }
    }

    fun refreshStates() {
        val engine = engine ?: return
        scope.launch {
            val states = withContext(crypto) {
                _peers.value.associate { it.userId to engine.sessionState(it.userId) }
            }
            _peers.value = _peers.value.map { it.copy(state = states[it.userId] ?: it.state) }
        }
    }

    fun safetyNumberFor(peerId: String): String? =
        engine?.let { withContextBlocking { it.safetyNumber(peerId) } }
            ?: _peers.value.firstOrNull { it.userId == peerId }?.safetyNumber

    private fun <T> withContextBlocking(block: () -> T): T =
        kotlinx.coroutines.runBlocking { withContext(crypto) { block() } }

    fun close() {
        disconnect()
        engine?.close()
        engine = null
    }

    private companion object {
        const val REFILL_LOW_WATER = 10
    }
}

/**
 * Where the desktop client keeps its keys.
 *
 * The Android client puts them behind the Keystore, which is hardware-backed and
 * cannot be exported. A desktop has no equivalent, so this is the honest
 * version: a directory with owner-only permissions, and no pretend that it is
 * anything stronger.
 *
 * The identity itself is *not* stored here in plain text 閳?[Vault.storeIdentity]
 * receives 96 bytes of secret material, and the file is created 0600 before the
 * bytes are written, so there is no window in which it is world-readable.
 */
class Vault(private val dir: Path) {

    init {
        Files.createDirectories(dir)
        restrictPermissions(dir)
    }

    fun loadIdentity(): ByteArray? = read(IDENTITY)

    fun storeIdentity(secrets: ByteArray) = write(IDENTITY, secrets)

    fun loadPreKeyState(): ByteArray? = read("prekeys.bin")

    fun storePreKeyState(blob: ByteArray) = write("prekeys.bin", blob)

    fun loadRegistry(): ByteArray? = read("peers.bin")

    fun storeRegistry(blob: ByteArray) = write("peers.bin", blob)

    fun loadSession(peerId: String): ByteArray? = read("session-${safe(peerId)}.bin")

    fun storeSession(peerId: String, blob: ByteArray) = write("session-${safe(peerId)}.bin", blob)

    // ---- Transcript -------------------------------------------------------
    //
    // One file per conversation, rather than one file for everything: a write
    // touches only the conversation that changed, so a busy chat does not rewrite
    // every other transcript on each message.
    //
    // The format is line-delimited JSON. It is not the most compact choice, but it
    // survives a partially-written file: a crash mid-write loses the last line
    // rather than the whole transcript, which is the failure this store exists to
    // prevent.

    fun loadMessages(peerId: String): List<ChatMessage> {
        val raw = read("messages-${safe(peerId)}.jsonl") ?: return emptyList()
        return raw.toString(Charsets.UTF_8)
            .lineSequence()
            .filter { it.isNotBlank() }
            .mapNotNull { line -> parseMessageLine(line, peerId) }
            .toList()
    }

    fun storeMessages(peerId: String, messages: List<ChatMessage>) {
        val body = messages.joinToString("\n") { m ->
            "{" +
                "\"id\":${m.id}," +
                "\"out\":${m.outgoing}," +
                "\"text\":\"${escapeJson(m.text)}\"," +
                "\"at\":${m.timestamp}," +
                "\"state\":\"${m.state.name}\"" +
                "}"
        }
        write("messages-${safe(peerId)}.jsonl", body.toByteArray(Charsets.UTF_8))
    }

    /**
     * Minimal JSON encoding, for one flat record.
     *
     * Hand-written rather than pulling in a serialization plugin: the shape is five
     * fixed fields, and a plugin would be a build configuration change for a
     * problem that is one escaping function. The reader is deliberately lenient -
     * a line that does not parse is dropped rather than failing the whole
     * transcript, which is what makes a partially-written file survivable.
     */
    private fun escapeJson(text: String): String {
        val out = StringBuilder(text.length + 8)
        for (c in text) {
            when (c) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                else -> if (c < ' ') {
                    out.append("\\u").append("%04x".format(c.code))
                } else {
                    out.append(c)
                }
            }
        }
        return out.toString()
    }

    private fun parseMessageLine(line: String, peerId: String): ChatMessage? {
        fun field(name: String): String? {
            val key = "\"$name\":"
            val start = line.indexOf(key) ?: return null
            val from = start + key.length
            return if (name == "text") {
                // A string field: read to the closing quote, honouring escapes.
                val sb = StringBuilder()
                var i = from + 1  // skip the opening quote
                while (i < line.length) {
                    when (val c = line[i]) {
                        '"' -> return sb.toString()
                        '\\' -> {
                            i++
                            when (val e = line.getOrNull(i)) {
                                '"' -> sb.append('"')
                                '\\' -> sb.append('\\')
                                'n' -> sb.append('\n')
                                'r' -> sb.append('\r')
                                't' -> sb.append('\t')
                                'u' -> {
                                    val hex = line.substring(i + 1, minOf(i + 5, line.length))
                                    sb.append(hex.toIntOrNull(16)?.toChar() ?: '?')
                                    i += 4
                                }
                                else -> if (e != null) sb.append(e)
                            }
                        }
                        else -> sb.append(c)
                    }
                    i++
                }
                null
            } else {
                val end = line.indexOf(',', from).let { if (it < 0) line.length else it }
                line.substring(from, end).trim().trim('"')
            }
        }

        return runCatching {
            ChatMessage(
                id = field("id")?.toLongOrNull() ?: return null,
                peerId = peerId,
                outgoing = field("out")?.toBooleanStrictOrNull() ?: return null,
                text = field("text") ?: return null,
                timestamp = field("at")?.toLongOrNull() ?: return null,
                state = field("state")?.let { SendState.valueOf(it) } ?: return null,
            )
        }.getOrNull()
    }

    // ---- Device and group state -------------------------------------------
    //
    // Group state carries chain keys: every incoming chain decrypts that
    // sender's messages, and the outgoing one can forge them. It goes through
    // the same owner-only file as ratchet state, for the same reason.

    fun loadDeviceId(): String? =
        read("device-id.txt")?.toString(Charsets.UTF_8)?.trim()?.ifEmpty { null }

    fun storeDeviceId(id: String) = write("device-id.txt", id.toByteArray(Charsets.UTF_8))

    fun loadGroupState(): ByteArray? = read("groups.bin")

    fun storeGroupState(blob: ByteArray) = write("groups.bin", blob)

    fun loadGroupIds(): List<String> =
        read("group-ids.txt")
            ?.toString(Charsets.UTF_8)
            ?.lines()
            ?.filter { it.isNotBlank() }
            ?: emptyList()

    fun storeGroupIds(ids: List<String>) =
        write("group-ids.txt", ids.joinToString("\n").toByteArray(Charsets.UTF_8))

    private fun read(name: String): ByteArray? {
        val path = dir.resolve(name)
        if (!Files.exists(path)) return null
        return try {
            Files.readAllBytes(path)
        } catch (e: Exception) {
            null
        }
    }

    private fun write(name: String, bytes: ByteArray) {
        val path = dir.resolve(name)
        val tmp = dir.resolve("$name.tmp")

        // Create with the tight mode first, then write, then move into place:
        // creating the file readable and fixing it afterwards leaves a window
        // where the secrets are on disk with the wrong permissions.
        Files.deleteIfExists(tmp)
        Files.createFile(tmp)
        restrictPermissions(tmp)
        Files.write(tmp, bytes)
        Files.move(tmp, path, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
    }

    private fun restrictPermissions(path: Path) {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
        } catch (e: UnsupportedOperationException) {
            // Windows: POSIX modes do not apply. The file inherits the user
            // profile's ACL, which is the best a desktop can do without a
            // platform-specific keystore.
        } catch (e: Exception) {
            // Same reasoning.
        }
    }

    private fun safe(peerId: String): String =
        peerId.map { if (it.isLetterOrDigit() || it == '-' || it == '_') it else '_' }.joinToString("")

    private companion object {
        const val IDENTITY = "identity.bin"
    }
}