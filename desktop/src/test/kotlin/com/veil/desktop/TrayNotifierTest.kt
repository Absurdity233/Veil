package com.veil.desktop

import org.junit.Assert.assertTrue
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
