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
        assertEquals("0.2.0", version)
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