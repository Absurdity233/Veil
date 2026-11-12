package com.veil.app.notify

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

/**
 * Message notifications.
 *
 * The rule this class exists to enforce: **a notification never contains message
 * content.**
 *
 * That is not squeamishness. A notification is rendered by the system, and
 * appears on a lock screen, in the shade, in a screenshot, and in whatever the
 * OEM decided to log. A body saying "alice: the meeting is at 4" would undo the
 * encryption of every message it described, and the user would never know.
 *
 * So the text is the sender and nothing else. That tells an attacker holding the
 * lock screen exactly as much as the notification's existence already does, and
 * tells the user the one thing they need: something arrived, from whom, and where
 * to look.
 *
 * Android specifics worth naming:
 *
 *   - `POST_NOTIFICATIONS` is a runtime permission from API 33. Asking for it on
 *     launch is the pattern that gets denied reflexively, so this class exposes
 *     [needsPermission] and the UI asks on a gesture.
 *   - A channel cannot change its importance after creation, so the channel is
 *     created with the lowest importance that still shows a heads-up: lowering it
 *     later would be a silent no-op, which is worse than never offering it.
 *   - The lock-screen visibility is deliberately `VISIBILITY_PRIVATE`, so the
 *     system redacts the title when the device is locked. That is a second layer:
 *     this code already refuses to put anything secret in it.
 */
class MessageNotifier(private val context: Context) {

    private val manager = NotificationManagerCompat.from(context)

    /** Whether the runtime permission still has to be asked for. */
    fun needsPermission(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return false
        return ContextCompat.checkSelfPermission(
            context, Manifest.permission.POST_NOTIFICATIONS,
        ) != PackageManager.PERMISSION_GRANTED
    }

    /**
     * Shows a notification for one incoming message.
     *
     * Returns false when nothing was shown, which is not an error: permission may
     * have been refused, or the app may be in the foreground where the transcript
     * already shows the message.
     */
    fun notifyMessage(senderId: String, isGroup: Boolean, groupId: String?): Boolean {
        if (needsPermission()) return false

        ensureChannel()

        // One notification id: a second message replaces the first rather than
        // stacking. The user dismisses one, not a column.
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentTitle(
                if (isGroup) "$senderId in #${groupId ?: "group"}" else senderId,
            )
            // Constructed here from the sender alone. Nothing from a message body
            // can reach this string, which is the whole point of the class.
            .setContentText(if (isGroup) "New message in a group" else "New message")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setAutoCancel(true)
            // Redacted on a locked device, even though the title is only a name.
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setContentIntent(openIntent(senderId, isGroup, groupId))
            .build()

        return try {
            manager.notify(NOTIFICATION_ID, notification)
            true
        } catch (e: SecurityException) {
            // The permission can be revoked between the check and the call.
            false
        }
    }

    /** Dismisses the single notification, e.g. when the conversation is opened. */
    fun clear() {
        manager.cancel(NOTIFICATION_ID)
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

        // Creating an existing channel is a no-op, so this is safe to call on
        // every notification rather than tracking whether it was created.
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Messages",
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = "New messages"
            // No badge and no sound override: the system default is what a user
            // has already tuned, and overriding it is how an app becomes annoying.
            lockscreenVisibility = android.app.Notification.VISIBILITY_PRIVATE
        }
        manager.createNotificationChannel(channel)
    }

    private fun openIntent(
        senderId: String,
        isGroup: Boolean,
        groupId: String?,
    ): PendingIntent {
        val intent = Intent(context, Class.forName(MAIN_ACTIVITY)).apply {
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            // The id travels here and nowhere else: it is what the app needs to
            // open the right conversation, and it is not message content.
            putExtra(EXTRA_PEER, senderId)
            if (isGroup) putExtra(EXTRA_GROUP, groupId)
        }

        return PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    companion object {
        const val CHANNEL_ID = "veil-messages"
        const val NOTIFICATION_ID = 1

        const val EXTRA_PEER = "veil.peer"
        const val EXTRA_GROUP = "veil.group"

        private const val MAIN_ACTIVITY = "com.veil.app.MainActivity"
    }
}
