package com.veil.app

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import com.veil.app.data.Peer
import com.veil.app.data.SessionUiState
import com.veil.app.ui.ChatScreen
import com.veil.app.ui.HomeScreen
import com.veil.app.ui.VeilTheme

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Ciphertext on the wire is worthless to an attacker if the plaintext
        // is visible in the recents thumbnail. FLAG_SECURE keeps the window out
        // of screenshots, screen recordings and the task switcher, which is the
        // difference between "the relay cannot read this" and "nobody can
        // casually photograph this".
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )

        enableEdgeToEdge()
        setContent {
            VeilTheme {
                VeilApp()
            }
        }
    }
}

@Composable
private fun VeilApp() {
    val context = LocalContext.current
    val controller = remember {
        (context.applicationContext as VeilApplication).controller
    }

    val link by controller.link.collectAsState()
    val peers by controller.peers.collectAsState()
    val status by controller.status.collectAsState()

    var openPeer by remember { mutableStateOf<Peer?>(null) }
    var selfUserId by remember { mutableStateOf("") }

    val peer = openPeer
    if (peer == null) {
        HomeScreen(
            selfUserId = selfUserId,
            serverUrl = DEFAULT_RELAY,
            link = link,
            peers = peers,
            status = status,
            onConnect = { url, id ->
                selfUserId = id
                controller.connect(url, id)
            },
            onAddPeer = { controller.addPeer(it) },
            onOpenPeer = { openPeer = it },
        )
    } else {
        val messages by controller.messages.collectAsState()

        // Ask the engine, not the cached copy of the safety number. The cache
        // survives a restart that the session does not, so the screen could
        // claim a session existed while every frame was being dropped.
        var state by remember(peer.userId) { mutableStateOf(SessionUiState.NO_PEER) }
        LaunchedEffect(peer.userId, link) {
            state = controller.sessionState(peer.userId)
        }

        ChatScreen(
            peer = peer.copy(sessionState = state),
            link = link,
            messages = messages[peer.userId] ?: controller.messagesFor(peer.userId),
            safetyNumber = controller.safetyNumberFor(peer.userId),
            status = status,
            onSend = { controller.sendMessage(peer.userId, it) },
            onBack = { openPeer = null },
        )
    }
}

// The emulator reaches the host loopback through 10.0.2.2. On a real device
// this needs the relay's LAN or public address.
private const val DEFAULT_RELAY = "ws://10.0.2.2:8080/ws"
