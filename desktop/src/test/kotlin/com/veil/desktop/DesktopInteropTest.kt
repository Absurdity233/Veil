package com.veil.desktop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.net.ServerSocket
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

/**
 * The desktop client against a real relay process.
 *
 * This is the test that justifies the C ABI: it drives the *same* engine the
 * phone does, through a different language binding, over the same wire format,
 * and expects a real conversation to come out the other end.
 *
 * It also exercises the parts a phone cannot easily show -- that the identity
 * and session state survive a restart on a filesystem, and that two clients on
 * one machine are distinguishable by their state directories.
 *
 * Skipped when the relay binary has not been built, the same way the Android
 * interop test skips.
 */
class DesktopInteropTest {

    // ---- The ABI itself --------------------------------------------------

    @Test
    fun `the native library loads and reports its version`() {
        val version = VeilEngine.version()
        assertEquals("0.4.0", version)
    }

    @Test
    fun `two engines agree on a safety number`() {
        val alice = VeilEngine.create()
        val bob = VeilEngine.create()

        val bobSet = bob.rotatePreKeys()
        val bundle = bundleFrom(bob, bobSet)

        assertEquals(VeilEngine.Status.OK, alice.establishOutbound("bob", bundle))
        assertEquals(SessionState.READY, alice.sessionState("bob"))

        val aliceSet = alice.rotatePreKeys()
        val aliceBundle = bundleFrom(alice, aliceSet)
        assertEquals(VeilEngine.Status.OK, bob.establishOutbound("alice", aliceBundle))

        val fromAlice = alice.safetyNumber("bob")
        val fromBob = bob.safetyNumber("alice")
        assertNotNull(fromAlice)
        assertEquals(fromAlice, fromBob)
        // Five groups of five digits.
        assertEquals(29, fromAlice!!.length)

        alice.close()
        bob.close()
    }

    @Test
    fun `a message round-trips through the ABI`() {
        val alice = VeilEngine.create()
        val bob = VeilEngine.create()

        val bundle = bundleFrom(bob, bob.rotatePreKeys())
        alice.establishOutbound("bob", bundle)

        val frame = alice.encrypt("bob", "the veil parts".toByteArray())
        assertNotNull(frame)

        val (plain, status) = bob.decrypt("alice", frame!!)
        assertEquals(VeilEngine.Status.OK, status)
        assertEquals("the veil parts", String(plain!!))

        // The same frame again is a duplicate, not a failure: the relay is
        // at-least-once, and the desktop client has to tell the difference.
        val (_, again) = bob.decrypt("alice", frame)
        assertEquals(VeilEngine.Status.DUPLICATE, again)

        alice.close()
        bob.close()
    }

    @Test
    fun `a tampered frame is reported as an authentication failure`() {
        val alice = VeilEngine.create()
        val bob = VeilEngine.create()

        alice.establishOutbound("bob", bundleFrom(bob, bob.rotatePreKeys()))

        // The first frame carries the prekey header and completes the
        // handshake on Bob's side, so it has to be delivered intact before a
        // later frame can be judged on its own merits.
        val first = alice.encrypt("bob", "one".toByteArray())!!
        assertEquals(VeilEngine.Status.OK, bob.decrypt("alice", first).second)

        // A frame on an unseen counter, with one byte flipped near the end so
        // the MAC no longer matches.
        val second = alice.encrypt("bob", "two".toByteArray())!!
        second[second.size - 1] = (second[second.size - 1].toInt() xor 0xFF).toByte()

        val (_, status) = bob.decrypt("alice", second)
        assertEquals(VeilEngine.Status.AUTH_FAILED, status)

        alice.close()
        bob.close()
    }

    @Test
    fun `identity and session state survive a restart`() {
        // This is what the phone does with the Keystore, done with a directory.
        val dir = Files.createTempDirectory("veil-desktop-restart")

        val first = VeilEngine.restoreOrCreate(dir)
        val identityBefore = first.publicIdentity()
        first.rotateAndPersist(dir)
        first.close()

        val second = VeilEngine.restoreOrCreate(dir)
        val identityAfter = second.publicIdentity()
        assertTrue("the identity must be the same across a restart",
            identityBefore.contentEquals(identityAfter))

        // The prekey id counter must keep moving, not restart at 1.
        val set = second.rotatePreKeys()
        val id = ((set[0].toInt() and 0xFF) shl 24) or ((set[1].toInt() and 0xFF) shl 16) or
                 ((set[2].toInt() and 0xFF) shl 8) or (set[3].toInt() and 0xFF)
        assertTrue("the signed prekey id must move forward, got $id", id > 1)

        second.close()
    }

    // ---- Against a real relay -------------------------------------------

    @Test
    fun `two desktop clients exchange a message through the relay`() {
        val relay = startRelay()
        try {
            val port = relay.port
            val dirAlice = Files.createTempDirectory("veil-alice")
            val dirBob = Files.createTempDirectory("veil-bob")

            val alice = TestPeer("ws://127.0.0.1:$port/ws", dirAlice, "alice")
            val bob = TestPeer("ws://127.0.0.1:$port/ws", dirBob, "bob")

            alice.connect()
            bob.connect()

            // Both publish prekeys, as the real client does on connect.
            alice.publishPreKeys()
            bob.publishPreKeys()

            // Alice fetches Bob's bundle and establishes.
            val bundle = alice.fetchBundle("bob")
            assertNotNull("the relay must serve a bundle", bundle)
            assertEquals(VeilEngine.Status.OK, alice.establish("bob", bundle!!))

            alice.send("bob", "hello over the wire")

            val received = bob.awaitMessage(10_000)
            assertNotNull("bob must receive the message", received)
            assertEquals("alice", received!!.first)
            assertEquals("hello over the wire", received.second)

            alice.close()
            bob.close()
        } finally {
            relay.process.destroy()
        }
    }

    // ---- Helpers ---------------------------------------------------------

    /** Builds the fixed-width bundle the engine parses, from a public set. */
    @Test
    fun `multi-device and groups work through the JNA binding`() {
        // The ABI surface for devices and groups is only useful if the Kotlin
        // wrapper can actually drive it: a mis-declared JNA signature fails at
        // call time, not at compile time, so this asserts behaviour rather than
        // the presence of the functions.
        val alice = VeilEngine.create()
        val bob = VeilEngine.create()
        try {
            assertTrue("alice has a device", alice.initDevice("alice"))
            assertTrue("bob has a device", bob.initDevice("bob"))

            val aliceDeviceId = alice.deviceId()
            assertNotNull("alice's device id", aliceDeviceId)
            assertEquals("a device id is 32 bytes", 32, aliceDeviceId!!.size)

            val alicePub = alice.publicIdentity()!!

            // ---- A group of two ----
            assertTrue("alice founds a group", alice.createGroup("team"))
            assertEquals("adding a member bumps the epoch", 2,
                alice.setGroupMembers("team", listOf("alice", "bob")))
            assertEquals("the epoch reads back", 2, alice.groupEpoch("team"))
            assertEquals("the members read back", listOf("alice", "bob"),
                alice.groupMembers("team"))
            assertTrue("alice is a member", alice.isGroupMember("team"))

            val membership = alice.exportMembership("team")
            assertNotNull("a membership record is produced", membership)

            // Membership is signed by the *account*: the founder is the
            // authority on who is in the group, and that authority is the
            // identity rather than a device.
            assertEquals("bob adopts the membership", VeilC.OK,
                bob.adoptMembership(membership!!, alicePub.copyOfRange(32, 64)))
            assertEquals("bob knows the epoch", 2, bob.groupEpoch("team"))

            // ---- A removed member cannot read the next epoch ----
            assertEquals("removal bumps the epoch", 3,
                alice.setGroupMembers("team", listOf("alice")))

            val staleAfterRemoval = alice.encryptToGroup("team", "after".toByteArray())
            assertNotNull("alice can still send on the new epoch", staleAfterRemoval)

            // Bob was never told about the rotation, so he is on epoch 2 and the
            // message is addressed to epoch 3. Unreadable is the point.
            assertEquals("bob cannot read the new epoch", null,
                bob.decryptFromGroup("team", staleAfterRemoval!!))

            // ---- Group state survives a restart ----
            val state = alice.exportGroupState()
            assertNotNull("group state exports", state)

            val restarted = VeilEngine.restore(alice.identitySecrets())
            try {
                assertTrue("the device is re-claimed", restarted.initDevice("alice"))
                assertTrue("group state imports", restarted.importGroupState(state!!))
                assertEquals("the epoch survived", 3, restarted.groupEpoch("team"))
                assertTrue("membership survived", restarted.isGroupMember("team"))
            } finally {
                restarted.close()
            }
        } finally {
            alice.close()
            bob.close()
        }
    }

    @Test
    fun `a device list is adopted from the relay's shape`() {
        // The ABI takes [4] count followed by credential blobs, which is what a
        // client assembles from a GET_DEVICES reply. Getting that shape wrong is
        // a runtime parse failure, so the assembly is exercised here.
        val alice = VeilEngine.create()
        val bob = VeilEngine.create()
        try {
            alice.initDevice("alice")
            bob.initDevice("bob")

            val alicePub = alice.publicIdentity()!!
            val credential = alice.deviceCredential()!!

            // [4] count = 1, then the credential.
            val blob = ByteArray(4 + credential.size)
            blob[3] = 1
            credential.copyInto(blob, 4)

            val status = bob.adoptDeviceList(
                "alice", 1, blob, alicePub.copyOfRange(0, 32), alicePub.copyOfRange(32, 64),
            )
            assertEquals("the list is accepted", VeilC.OK, status)

            val devices = bob.peerDevices("alice")
            assertEquals("one device is known", 1, devices.size)
            assertEquals("the id is hex", 64, devices[0].length)
            assertEquals("the version is recorded", 1, bob.peerDeviceVersion("alice"))

            // A list at the same version must not replace what is held, so a
            // relay cannot roll a revocation back.
            val stale = ByteArray(4 + credential.size)
            stale[3] = 1
            credential.copyInto(stale, 4)
            bob.adoptDeviceList(
                "alice", 1, stale, alicePub.copyOfRange(0, 32), alicePub.copyOfRange(32, 64),
            )
            assertEquals("a stale list does not move the version", 1,
                bob.peerDeviceVersion("alice"))

            // A credential the account never signed is refused whole.
            val forged = credential.copyOf()
            forged[forged.size - 1] = (forged[forged.size - 1].toInt() xor 0xFF).toByte()
            val forgedBlob = ByteArray(4 + forged.size)
            forgedBlob[3] = 1
            forged.copyInto(forgedBlob, 4)

            assertEquals("a forged credential is refused", VeilC.BAD_SIGNATURE,
                bob.adoptDeviceList("alice", 2, forgedBlob,
                    alicePub.copyOfRange(0, 32), alicePub.copyOfRange(32, 64)))
            assertEquals("and the version did not move", 1, bob.peerDeviceVersion("alice"))
        } finally {
            alice.close()
            bob.close()
        }
    }

    @Test
    fun `a fan-out send produces one frame per device with a session`() {
        // The wiring, not the engine: ChatController.sendMessage has to go
        // through encryptToAccount. Asserting the engine alone would not catch a
        // client that still calls encrypt().
        val alice = VeilEngine.create()
        val bob = VeilEngine.create()
        try {
            alice.initDevice("alice")
            bob.initDevice("bob")
            alice.rotatePreKeys()

            val bobPub = bob.publicIdentity()!!

            // Bob publishes a list of one, so alice knows to fan out rather than
            // address the bare account label.
            val bobCred = bob.deviceCredential()!!
            val blob = ByteArray(4 + bobCred.size)
            blob[3] = 1
            bobCred.copyInto(blob, 4)
            assertEquals(VeilC.OK, alice.adoptDeviceList(
                "bob", 1, blob, bobPub.copyOfRange(0, 32), bobPub.copyOfRange(32, 64),
            ))

            val devices = alice.peerDevices("bob")
            assertEquals("bob has one device", 1, devices.size)

            // No session yet: the device is skipped, and an empty result is not
            // an error.
            assertEquals("a device with no session produces no frame", 0,
                alice.encryptToAccount("bob", "hello".toByteArray()).size)

            val bundle = bundleFrom(bob, bob.rotatePreKeys())
            val established = alice.establishOutbound("bob#${devices[0]}", bundle)
            assertEquals("the session to that device is established", VeilEngine.Status.OK, established)

            val frames = alice.encryptToAccount("bob", "hello".toByteArray())
            assertEquals("one device with a session yields one frame", 1, frames.size)
            assertEquals("and it is addressed to that device", devices[0], frames[0].first)
        } finally {
            alice.close()
            bob.close()
        }
    }

    @Test
    fun `a group survives a controller restart`() {
        // The persistence path: group state exported on close and restored on the
        // next start. A client that never persisted it would lose every group on
        // relaunch, which looks exactly like being removed from them.
        val dir = Files.createTempDirectory("veil-group")

        val first = ChatController(dir)
        try {
            runBlocking {
                first.ensureIdentity()
                assertTrue("the device is claimed", first.claimDevice("alice"))
            }

            // The controller writes asynchronously, so the wait is explicit
            // rather than a sleep: a fixed delay would make this test slow on a
            // fast machine and flaky on a loaded one.
            first.createGroup("team")
            waitUntil(3_000) { first.groups.value.isNotEmpty() }
            first.setGroupMembers("team", listOf("alice", "bob"))
            waitUntil(3_000) { first.groups.value.firstOrNull()?.epoch == 2 }

            waitUntil(5_000) { Files.exists(dir.resolve("groups.bin")) }
        } finally {
            first.close()
        }

        // A fresh controller on the same directory: this is the restart.
        val second = ChatController(dir)
        try {
            runBlocking { second.ensureIdentity() }

            val groups = second.groups.value
            assertEquals("the group came back", 1, groups.size)
            assertEquals("with its epoch", 2, groups[0].epoch)
            assertEquals("and its members", listOf("alice", "bob"), groups[0].members)
        } finally {
            second.close()
        }
    }

    /** Polls until [condition] holds, or fails after [timeoutMs]. */
    private fun waitUntil(timeoutMs: Long, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return
            Thread.sleep(25)
        }
        throw AssertionError("condition did not hold within ${timeoutMs}ms")
    }

    private fun bundleFrom(engine: VeilEngine, set: ByteArray): ByteArray {
        val identity = engine.publicIdentity()
        val r = Reader(set)
        val signedId = r.u32()
        val signedPub = r.raw(32)
        val signature = r.raw(64)
        val count = r.u32()
        assertTrue("the set must carry one-time keys", count > 0)
        val otId = r.u32()
        val otPub = r.raw(32)

        return Writer()
            .raw(identity)
            .u32(signedId)
            .raw(signedPub)
            .raw(signature)
            .raw(byteArrayOf(1))
            .u32(otId)
            .raw(otPub)
            .build()
    }

    private class RelayHandle(val process: Process, val port: Int)

    private fun startRelay(): RelayHandle {
        val port = ServerSocket(0).use { it.localPort }
        val exe = relayBinary()
        org.junit.Assume.assumeTrue(
            "relay binary not built at ${exe.absolutePath}",
            exe.isFile,
        )

        val process = ProcessBuilder(
            exe.absolutePath,
            "-addr", "127.0.0.1:$port",
            "-db", File.createTempFile("veil-desktop", ".db").also { it.delete() }.absolutePath,
        ).redirectErrorStream(true).start()

        val deadline = System.currentTimeMillis() + 10_000
        while (System.currentTimeMillis() < deadline) {
            if (process.isAlive && canConnect(port)) return RelayHandle(process, port)
            Thread.sleep(50)
        }
        process.destroy()
        error("the relay did not start on port $port")
    }

    private fun canConnect(port: Int): Boolean = try {
        java.net.Socket("127.0.0.1", port).use { true }
    } catch (e: Exception) {
        false
    }

    private fun relayBinary(): File {
        val root = File(System.getProperty("user.dir")).let {
            if (it.endsWith("desktop")) it.parentFile else it
        }
        val name = if (System.getProperty("os.name").startsWith("Windows")) {
            "veil-relay.exe"
        } else {
            "veil-relay"
        }
        return File(root, "build/relay/$name")
    }

    /** One desktop client: engine, relay socket, and the plumbing between them. */
    private class TestPeer(url: String, stateDir: Path, private val userId: String) {

        private val vault = Vault(stateDir)
        private val engine: VeilEngine = VeilEngine.restoreOrCreate(stateDir)
        private val client = RelayClient(url)
        private val inbox = java.util.concurrent.LinkedBlockingQueue<Pair<String, String>>()
        private val bundles =
            java.util.concurrent.LinkedBlockingQueue<Pair<String, ByteArray>>()
        private val scope = kotlinx.coroutines.CoroutineScope(
            kotlinx.coroutines.Dispatchers.IO + kotlinx.coroutines.SupervisorJob(),
        )
        private var pump: kotlinx.coroutines.Job? = null

        fun connect() {
            // One collector for the whole connection. A flow can only be
            // collected once, so every event type is dispatched from here
            // rather than by the caller that happens to be interested.
            pump = scope.launch {
                client.stream.collect { event ->
                    when (event) {
                        is RelayClient.Event.Challenge ->
                            client.respondToChallenge(engine.signChallenge(event.nonce))
                        is RelayClient.Event.Delivered -> {
                            val (plain, status) = engine.decrypt(event.sender, event.frame)
                            if (status == VeilEngine.Status.OK && plain != null) {
                                inbox.add(event.sender to String(plain))
                            }
                            // A duplicate is routine; acknowledge it so the
                            // relay stops resending, and move on.
                            if (event.outboxId > 0) client.acknowledge(event.outboxId)
                        }
                        is RelayClient.Event.Bundle -> bundles.add(
                            event.userId to Writer()
                                .raw(event.identity)
                                .u32(event.signedId)
                                .raw(event.signedPub)
                                .raw(event.signature)
                                .raw(byteArrayOf(if (event.oneTimeId != 0) 1 else 0))
                                .u32(event.oneTimeId)
                                .raw(event.oneTimePub)
                                .build(),
                        )
                        else -> Unit
                    }
                }
            }
            kotlinx.coroutines.runBlocking { client.connect(userId, engine.publicIdentity()) }
            awaitConnected(5_000)
        }

        private fun awaitConnected(timeoutMs: Long) {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                if (client.isConnected) return
                Thread.sleep(20)
            }
            error("the relay did not accept the connection")
        }

        fun publishPreKeys() {
            val set = engine.rotatePreKeys()
            vault.storePreKeyState(engine.exportPreKeyState())

            // Export layout:
            //   [4] signed id | [32] signed pub | [64] signature | [4] count
            //   then per one-time key: [4] id | [32] pub
            //
            // The relay wants the one-time list as [4] count followed by the
            // entries, which is exactly the tail of this blob. Slicing from the
            // count field, not from the first entry, is what makes the count
            // and the body agree.
            val r = Reader(set)
            val signedId = r.u32()
            val signedPub = r.raw(32)
            val signature = r.raw(64)
            val oneTime = r.raw(r.remaining)

            val published = client.publishPreKeys(signedId, signedPub, signature, oneTime)
            assertTrue("the prekeys must reach the relay", published)

            // PUBLISH_PREKEYS is processed on the relay's reader goroutine, so
            // a GET_BUNDLE sent immediately afterwards can arrive before the
            // row exists. Give it a moment rather than racing it.
            Thread.sleep(200)
        }

        fun fetchBundle(target: String): ByteArray? {
            client.requestBundle(target)
            val deadline = System.currentTimeMillis() + 5_000
            while (System.currentTimeMillis() < deadline) {
                val got = bundles.poll(100, TimeUnit.MILLISECONDS) ?: continue
                if (got.first == target) return got.second
            }
            return null
        }

        fun establish(peer: String, bundle: ByteArray): VeilEngine.Status =
            engine.establishOutbound(peer, bundle)

        fun send(peer: String, text: String) {
            val frame = engine.encrypt(peer, text.toByteArray())
                ?: error("could not encrypt for $peer")
            assertTrue("the frame must reach the relay", client.sendMessage(peer, frame))
        }

        fun awaitMessage(timeoutMs: Long): Pair<String, String>? {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                val got = inbox.poll(100, TimeUnit.MILLISECONDS) ?: continue
                return got
            }
            return null
        }

        fun close() {
            pump?.cancel()
            client.close()
            engine.close()
        }
    }
}

/**
 * Restores an engine from the state directory, or creates one there.
 *
 * A top-level helper rather than a method because both the test and the app
 * need exactly this, and the Android client has the same shape of call against
 * its Keystore.
 */
fun VeilEngine.Companion.restoreOrCreate(dir: Path): VeilEngine {
    val vault = Vault(dir)
    val existing = vault.loadIdentity()
    val engine = if (existing != null) {
        try {
            restore(existing)
        } finally {
            existing.fill(0)
        }
    } else {
        create().also { vault.storeIdentity(it.identitySecrets()) }
    }

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
    return engine
}

/**
 * Rotates and persists in one step, which is what a client has to do together.
 *
 * Rotating without persisting is the bug this helper exists to prevent: the
 * next process starts from the old state and reissues an id that was already
 * published.
 */
fun VeilEngine.rotateAndPersist(dir: Path): ByteArray {
    val set = rotatePreKeys()
    val vault = Vault(dir)
    val blob = exportPreKeyState()
    try {
        vault.storePreKeyState(blob)
    } finally {
        blob.fill(0)
    }
    return set
}