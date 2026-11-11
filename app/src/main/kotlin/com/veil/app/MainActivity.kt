package com.veil.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import com.veil.app.data.Peer
import com.veil.app.ui.ChatScreen
import com.veil.app.ui.HomeScreen
import com.veil.app.ui.VeilTheme

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
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
        ChatScreen(
            peer = peer,
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
