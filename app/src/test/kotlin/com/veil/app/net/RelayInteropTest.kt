package com.veil.app.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.net.ServerSocket
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.launch

/**
 * End-to-end check of the client wire code against the real relay.
 *
 * The relay is started as a child process from the built binary, so this test
 * exercises the actual framing both sides agree on rather than a mock of it.
 * Message crypto is stubbed out: the relay never verifies message signatures,
 * it only stores and forwards public keys and opaque bodies, which is exactly
 * the contract being tested here.
 *
 * The HELLO handshake is *not* stubbed: the relay verifies a real Ed25519
 * signature over its challenge, so the identity keys here are real key pairs
 * with a stand-in DH half.
 *
 * Skipped automatically when the relay binary has not been built.
 */
class RelayInteropTest {

    @Test
    fun `two clients exchange a message through the relay`() {
        val port = freePort()
        val relay = startRelay(port)

        try {
            val alice = TestPeer("ws://127.0.0.1:$port/ws")
            val bob = TestPeer("ws://127.0.0.1:$port/ws")

            alice.connect("alice", fakeIdentity(1))
            bob.connect("bob", fakeIdentity(2))

            // Bob publishes a prekey set the way the app does.
            bob.publishPreKeys(
                signedId = 1,
                signedPub = ByteArray(32) { 0x11 },
                signature = ByteArray(64) { 0x22 },
                oneTime = oneTimeSet(ids = intArrayOf(1001, 1002)),
            )

            // Alice fetches it and must get the first one-time key back.
            val bundle = alice.fetchBundle("bob")
            assertNotNull("bundle should arrive", bundle)
            assertEquals(64, bundle!!.identity.size)
            assertEquals(1, bundle.signedId)
            assertEquals("first one-time prekey", 1001, bundle.oneTimeId)
            assertEquals(32, bundle.oneTimePub.size)

            // A second fetch must get the next one-time key, never the same
            // one twice.
            val second = alice.fetchBundle("bob")
            assertNotNull(second)
            assertEquals("second one-time prekey", 1002, second!!.oneTimeId)

            // The set is now exhausted; the bundle must still be served.
            val third = alice.fetchBundle("bob")
            assertNotNull(third)
            assertEquals("no one-time prekey left", 0, third!!.oneTimeId)

            // Alice sends an opaque body; Bob must receive it verbatim.
            val body = ByteArray(120) { (it * 7).toByte() }
            alice.send("bob", body)

            val delivered = bob.awaitDeliver()
            assertNotNull("bob should receive the message", delivered)
            assertEquals("alice", delivered!!.sender)
            assertTrue("body must arrive intact", delivered.body.contentEquals(body))
            assertEquals("live delivery carries id 0", 0L, delivered.outboxId)

            alice.close()
            bob.close()
        } finally {
            relay.destroy()
        }
    }

    @Test
    fun `offline message is queued and replayed on reconnect`() {
        val port = freePort()
        val relay = startRelay(port)

        try {
            val alice = TestPeer("ws://127.0.0.1:$port/ws")
            alice.connect("alice", fakeIdentity(10))

            val body = "queued while away".toByteArray()
            alice.send("bob", body)

            // Bob was never connected, so this must have been stored.
            val bob = TestPeer("ws://127.0.0.1:$port/ws")
            bob.connect("bob", fakeIdentity(11))

            val delivered = bob.awaitDeliver()
            assertNotNull("queued message should be replayed", delivered)
            assertEquals("alice", delivered!!.sender)
            assertTrue(delivered.body.contentEquals(body))
            assertTrue("queued delivery carries an outbox id", delivered.outboxId > 0)

            alice.close()
            bob.close()
        } finally {
            relay.destroy()
        }
    }

    @Test
    fun `relay rejects a second identity for the same user id`() {
        val port = freePort()
        val relay = startRelay(port)

        try {
            val first = TestPeer("ws://127.0.0.1:$port/ws")
            first.connect("carol", fakeIdentity(20))
            first.close()

            val second = TestPeer("ws://127.0.0.1:$port/ws")
            val outcome = second.tryConnect("carol", fakeIdentity(21))
            assertTrue("a different identity must be refused", outcome.isFailure)

            second.close()
        } finally {
            relay.destroy()
        }
    }

    // ---- Relay process --------------------------------------------------

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    private fun startRelay(port: Int): Process {
        val exe = File(relayBinaryPath())
        assumeTrue("relay binary not built at ${exe.absolutePath}", exe.isFile)

        val proc = ProcessBuilder(
            exe.absolutePath,
            "-addr", "127.0.0.1:$port",
            "-db", File.createTempFile("veil-test", ".db").also { it.delete() }.absolutePath,
        )
            .redirectErrorStream(true)
            .start()

        // Wait for the listener rather than sleeping a fixed amount.
        val deadline = System.currentTimeMillis() + 10_000
        while (System.currentTimeMillis() < deadline) {
            if (proc.isAlive && canConnect(port)) return proc
            Thread.sleep(50)
        }
        proc.destroy()
        error("relay did not start on port $port")
    }

    private fun canConnect(port: Int): Boolean = try {
        java.net.Socket("127.0.0.1", port).use { true }
    } catch (e: Exception) {
        false
    }

    private fun relayBinaryPath(): String {
        val root = File(System.getProperty("user.dir")).let {
            // Gradle runs tests from the module directory.
            if (it.endsWith("app")) it.parentFile else it
        }
        val name = if (System.getProperty("os.name").startsWith("Windows")) {
            "veil-relay.exe"
        } else {
            "veil-relay"
        }
        return File(root, "build/relay/$name").absolutePath
    }

    // ---- Fake key material ----------------------------------------------

    /**
     * A real Ed25519 key pair with a stand-in DH half.
     *
     * The relay only ever looks at the signing half (offset 32..64), and only
     * to check the HELLO challenge signature, so the first 32 bytes just have
     * to be distinct per peer.
     */
    private class FakeIdentity(val blob: ByteArray, val signer: java.security.PrivateKey) {
        fun sign(nonce: ByteArray): ByteArray {
            val s = Signature.getInstance("Ed25519")
            s.initSign(signer)
            s.update(nonce)
            return s.sign()
        }
    }

    private fun fakeIdentity(seed: Int): FakeIdentity {
        val pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val blob = ByteArray(64) { (seed * 13 + it).toByte() }
        // Overwrite the signing half so the relay sees the real public key.
        val pub = pair.public.encoded
        // X.509 SubjectPublicKeyInfo for Ed25519 is a 12-byte prefix + 32 bytes.
        System.arraycopy(pub, pub.size - 32, blob, 32, 32)
        return FakeIdentity(blob, pair.private)
    }

    /** [4] count, then per entry [4] id | [32] public key. */
    private fun oneTimeSet(ids: IntArray): ByteArray {
        val w = Writer().u32(ids.size)
        ids.forEach { id ->
            w.u32(id)
            w.raw(ByteArray(32) { (id + it).toByte() })
        }
        return w.build()
    }

    // ---- Test client ----------------------------------------------------

    private class Delivered(val outboxId: Long, val sender: String, val body: ByteArray)

    private class BundleInfo(
        val identity: ByteArray,
        val signedId: Int,
        val signedPub: ByteArray,
        val signature: ByteArray,
        val oneTimeId: Int,
        val oneTimePub: ByteArray,
    )

    private class TestPeer(private val url: String) {

        private val inbox = java.util.concurrent.LinkedBlockingQueue<Wire.Frame>()
        private val client = RelayClient(url)
        private val scope = kotlinx.coroutines.CoroutineScope(
            kotlinx.coroutines.Dispatchers.IO + kotlinx.coroutines.SupervisorJob(),
        )

        fun connect(userId: String, identity: FakeIdentity) {
            kotlinx.coroutines.runBlocking { client.connect(userId, identity.blob) }
            scope.launch {
                client.stream.collect { event ->
                    when (event) {
                        // Vault replies travel on the client's own slot rather
                        // than this channel, so the test never sees them.
                        is RelayClient.Event.Vault, is RelayClient.Event.VaultStored -> Unit
                        is RelayClient.Event.Connected -> inbox.add(
                            Wire.Frame(Wire.TYPE_HELLO_OK, ByteArray(0)),
                        )
                        is RelayClient.Event.Challenge -> {
                            // The relay verifies this for real, so it cannot be
                            // faked: sign the nonce with the identity key.
                            client.respondToChallenge(identity.sign(event.nonce))
                        }
                        is RelayClient.Event.Delivered -> inbox.add(
                            Wire.Frame(
                                Wire.TYPE_DELIVER,
                                Writer()
                                    .u32(event.outboxId.toInt())
                                    .string(event.sender)
                                    .blob(event.frame)
                                    .build(),
                            ),
                        )
                        is RelayClient.Event.Bundle -> inbox.add(
                            Wire.Frame(
                                Wire.TYPE_BUNDLE,
                                Writer()
                                    .string(event.userId)
                                    .blob(event.identity)
                                    .u32(event.signedId)
                                    .blob(event.signedPub)
                                    .blob(event.signature)
                                    .u32(event.oneTimeId)
                                    .blob(event.oneTimePub)
                                    .build(),
                            ),
                        )
                        is RelayClient.Event.MorePending -> inbox.add(
                            Wire.Frame(Wire.TYPE_MORE_PENDING, ByteArray(0)),
                        )
                        is RelayClient.Event.Failed -> inbox.add(
                            Wire.Frame(Wire.TYPE_ERROR, Writer().string(event.message).build()),
                        )
                        RelayClient.Event.Disconnected -> Unit
                    }
                }
            }
            // The connect call returns once the socket opens; the HELLO_OK
            // frame is what proves the relay accepted the identity.
            val ok = awaitType(Wire.TYPE_HELLO_OK, 10_000)
            checkNotNull(ok) { "relay did not accept HELLO" }
        }

        fun tryConnect(userId: String, identity: FakeIdentity): Result<Unit> = runCatching {
            connect(userId, identity)
        }

        fun publishPreKeys(signedId: Int, signedPub: ByteArray, signature: ByteArray,
                           oneTime: ByteArray) {
            client.publishPreKeys(signedId, signedPub, signature, oneTime)
        }

        fun fetchBundle(userId: String): BundleInfo? {
            client.requestBundle(userId)
            val frame = awaitType(Wire.TYPE_BUNDLE, 5_000) ?: return null
            val r = Reader(frame.payload)
            r.string()
            val identity = r.blob()
            val signedId = r.u32()
            val signedPub = r.blob()
            val signature = r.blob()
            val oneTimeId = r.u32()
            val oneTimePub = r.blob()
            return BundleInfo(identity, signedId, signedPub, signature, oneTimeId, oneTimePub)
        }

        fun send(recipient: String, body: ByteArray) {
            client.sendMessage(recipient, body)
        }

        fun awaitDeliver(): Delivered? {
            val frame = awaitType(Wire.TYPE_DELIVER, 5_000) ?: return null
            val r = Reader(frame.payload)
            val id = r.u32().toLong() and 0xFFFFFFFFL
            val sender = r.string()
            val body = r.blob()
            return Delivered(id, sender, body)
        }

        private fun awaitType(type: Int, timeoutMs: Long): Wire.Frame? {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                val frame = inbox.poll(100, TimeUnit.MILLISECONDS) ?: continue
                if (frame.type == type) return frame
            }
            return null
        }

        fun close() {
            client.close()
        }
    }
}
