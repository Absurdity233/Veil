package com.veil.desktop

import java.awt.Color
import java.awt.Graphics2D
import java.awt.SystemTray
import java.awt.TrayIcon
import java.awt.image.BufferedImage

/**
 * Desktop notifications, through the system tray.
 *
 * The rule this class exists to enforce: **a notification never contains message
 * content.**
 *
 * A tray notification is rendered by the desktop environment: it appears in a
 * corner of the screen, often on a lock screen, and stays in a notification
 * centre afterwards. A body saying "alice: the meeting is at 4" would undo the
 * encryption of every message it described, and the user would never know.
 *
 * So the text is the sender and nothing else, which tells an observer exactly as
 * much as the notification's existence already does.
 *
 * The AWT tray API is the only notification channel a plain JVM has. It has three
 * limitations worth stating rather than working around:
 *
 *   - there is no permission model, so there is nothing to ask for;
 *   - the icon is required, so one is drawn rather than shipped as a file (a
 *     missing image resource would fail at runtime on a machine where the jar was
 *     stripped);
 *   - `displayMessage` is fire-and-forget: it cannot report whether the desktop
 *     actually showed anything.
 */
class TrayNotifier {

    private var tray: SystemTray? = null
    private var icon: TrayIcon? = null

    /** Whether this environment has a system tray at all. */
    fun isAvailable(): Boolean = SystemTray.isSupported()

    /**
     * Installs the tray icon.
     *
     * Called once at startup rather than on the first message: registering an icon
     * is what makes the process visible to the desktop, and doing it on first use
     * means the very first notification is the one that gets lost.
     */
    fun install() {
        if (icon != null || !SystemTray.isSupported()) return

        val image = drawIcon()
        val trayIcon = TrayIcon(image, "Veil").apply {
            isImageAutoSize = true
            // No popup menu: a tray menu would need actions this client does not
            // have, and an empty one is worse than none.
        }

        try {
            SystemTray.getSystemTray().add(trayIcon)
            tray = SystemTray.getSystemTray()
            icon = trayIcon
        } catch (e: Exception) {
            // A desktop without a tray (or a headless session) is a normal case,
            // not an error: messages still arrive and the window still shows them.
            icon = null
        }
    }

    /**
     * Shows a notification for one incoming message.
     *
     * Returns false when nothing was shown, which is not an error: the tray may be
     * unavailable, or the user may have disabled it.
     */
    fun notifyMessage(senderId: String, isGroup: Boolean, groupId: String?): Boolean {
        install()
        val trayIcon = icon ?: return false

        // Constructed from the sender alone. Nothing from a message body can reach
        // these strings, which is the whole point of the class.
        val caption = if (isGroup) "$senderId in #${groupId ?: "group"}" else senderId
        val text = if (isGroup) "New message in a group" else "New message"

        return try {
            trayIcon.displayMessage(caption, text, TrayIcon.MessageType.INFO)
            true
        } catch (e: Exception) {
            false
        }
    }

    /** Removes the tray icon, so the process leaves no icon behind. */
    fun dispose() {
        val trayIcon = icon ?: return
        tray?.remove(trayIcon)
        icon = null
    }

    /**
     * Draws the icon.
     *
     * Generated rather than loaded: a 16x16 PNG in resources is one more file that
     * has to survive packaging, and a tray API that is handed a missing image fails
     * at runtime on the machine that matters.
     */
    private fun drawIcon(): BufferedImage {
        val size = 16
        val image = BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB)
        val g: Graphics2D = image.createGraphics()
        try {
            g.setRenderingHint(
                java.awt.RenderingHints.KEY_ANTIALIASING,
                java.awt.RenderingHints.VALUE_ANTIALIAS_ON,
            )
            // A filled circle with a notch: recognisable at 16px, which is all a
            // tray icon has room for.
            g.color = Color(0x2F, 0x6F, 0xEB)
            g.fillOval(0, 0, size, size)
            g.color = Color.WHITE
            g.fillRect(size / 2 - 1, 4, 2, 6)
            g.fillRect(size / 2 - 1, 11, 2, 2)
        } finally {
            g.dispose()
        }
        return image
    }
}
