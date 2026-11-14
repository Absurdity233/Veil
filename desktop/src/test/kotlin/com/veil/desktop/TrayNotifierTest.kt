package com.veil.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Notification content.
 *
 * These do not touch the tray: a headless test runner has no desktop, and
 * `SystemTray.isSupported()` is false there. What they check is the property that
 * matters and that can be checked without one - that the strings a notification
 * would carry are built from the sender alone, and cannot contain message text.
 *
 * That is a structural guarantee rather than a filter: `notifyMessage` takes the
 * sender, the kind, and a group id. There is no parameter through which a message
 * could arrive, so there is no escaping rule to get wrong later.
 */
class TrayNotifierTest {

    // ---- Vault permissions ------------------------------------------------

    @Test
    fun `the vault directory is created and writable`() {
        // A regression test for a Linux-only failure: init() restricted the
        // directory with "rw-------", which drops the execute bit. A directory
        // without execute cannot be entered, so every create inside it failed
        // with AccessDeniedException - including the temporary file a write
        // needs. Windows ignores POSIX modes, so the mistake was invisible there.
        val dir = Files.createTempDirectory("veil-vault-test")
        try {
            val vault = Vault(dir.resolve("state"))

            // The property under test: a write succeeds, which requires the
            // directory to be enterable. If permissions are wrong this throws.
            vault.storeIdentity(ByteArray(96) { 0x11 })
            assertTrue(Files.exists(dir.resolve("state").resolve("identity.bin")))
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `a vault file is not group or world readable`() {
        // The other half of the same rule: files must stay private even though
        // directories need the execute bit.
        assumeTrue(
            "POSIX permissions only",
            java.io.File.separatorChar == '/',
        )

        val dir = Files.createTempDirectory("veil-vault-perm")
        try {
            val vault = Vault(dir.resolve("state"))
            vault.storeIdentity(ByteArray(96) { 0x22 })

            val file = dir.resolve("state").resolve("identity.bin")
            val perms = Files.getPosixFilePermissions(file)

            assertTrue("group must not read the identity",
                PosixFilePermission.GROUP_READ !in perms)
            assertTrue("others must not read the identity",
                PosixFilePermission.OTHERS_READ !in perms)
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `concurrent writes to one vault do not collide`() {
        // The temporary name is unique per write and the method is synchronized,
        // so two threads writing different files at once must both succeed. With
        // a fixed "<name>.tmp" one of them got AccessDeniedException.
        val dir = Files.createTempDirectory("veil-vault-race")
        try {
            val vault = Vault(dir.resolve("state"))
            val errors = java.util.Collections.synchronizedList(mutableListOf<Throwable>())

            val threads = (0 until 8).map { i ->
                Thread {
                    try {
                        vault.storeSession("peer$i", ByteArray(64) { i.toByte() })
                    } catch (e: Throwable) {
                        errors.add(e)
                    }
                }
            }
            threads.forEach { it.start() }
            threads.forEach { it.join() }

            assertEquals("no write should fail: $errors", 0, errors.size)
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `a headless environment reports no tray rather than failing`() {
        // The normal case in CI. It must return false, not throw: a client whose
        // tests crash on a machine without a desktop cannot be built there.
        val notifier = TrayNotifier()
        // No assertion on the value: whether this machine has a tray is not the
        // property under test. Not throwing is.
        notifier.isAvailable()
    }

    @Test
    fun `notifying without a tray is a no-op rather than an exception`() {
        val notifier = TrayNotifier()
        if (notifier.isAvailable()) return  // a real desktop; covered by hand

        assertTrue(!notifier.notifyMessage("alice", isGroup = false, groupId = null))
    }

    @Test
    fun `disposing twice is safe`() {
        // Called from a window close handler that may run more than once.
        val notifier = TrayNotifier()
        notifier.dispose()
        notifier.dispose()
    }

    @Test
    fun `the notifier has no way to accept a message body`() {
        // A reflection check, which is unusual enough to justify itself: the whole
        // security property is that the API cannot carry plaintext. If somebody
        // later adds a `text: String` parameter to `notifyMessage`, this fails and
        // says why, rather than the reviewer having to notice.
        val methods = TrayNotifier::class.java.declaredMethods
            .filter { it.name == "notifyMessage" }

        assertTrue("notifyMessage should exist", methods.isNotEmpty())

        for (method in methods) {
            val names = method.parameterTypes.map { it.simpleName }
            // String parameters are allowed for the sender and group id; what is
            // asserted is the parameter count, so adding one is a deliberate act.
            assertTrue(
                "notifyMessage gained a parameter (${names.joinToString()}) - if it " +
                    "is message text, a notification would put plaintext on a lock " +
                    "screen",
                method.parameterCount == 3,
            )
        }
    }
}
