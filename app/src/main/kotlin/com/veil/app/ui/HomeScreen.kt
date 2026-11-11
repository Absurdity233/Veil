package com.veil.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.veil.app.LinkState
import com.veil.app.data.Peer

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    selfUserId: String,
    serverUrl: String,
    link: LinkState,
    peers: List<Peer>,
    status: String?,
    onConnect: (serverUrl: String, userId: String) -> Unit,
    onAddPeer: (String) -> Unit,
    onOpenPeer: (Peer) -> Unit,
) {
    var url by remember { mutableStateOf(serverUrl) }
    var userId by remember { mutableStateOf(selfUserId) }
    var peerId by remember { mutableStateOf("") }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Veil", fontWeight = FontWeight.SemiBold) },
                actions = { LinkBadge(link) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
        ) {
            Spacer(Modifier.height(8.dp))

            Card(colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant,
            )) {
                Column(Modifier.padding(14.dp)) {
                    Text("Relay", fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = url,
                        onValueChange = { url = it },
                        label = { Text("WebSocket URL") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = userId,
                        onValueChange = { userId = it },
                        label = { Text("Your id") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                    )
                    Spacer(Modifier.height(10.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Button(
                            onClick = { onConnect(url, userId) },
                            enabled = url.isNotBlank() && userId.isNotBlank() &&
                                link != LinkState.Connecting,
                        ) {
                            Text(if (link == LinkState.Online) "Reconnect" else "Connect")
                        }
                        Spacer(Modifier.width(12.dp))
                        status?.let {
                            Text(
                                it,
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }

            Spacer(Modifier.height(16.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = peerId,
                    onValueChange = { peerId = it },
                    label = { Text("Add someone by id") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                )
                Spacer(Modifier.width(8.dp))
                Button(
                    onClick = {
                        val id = peerId.trim()
                        peerId = ""
                        if (id.isNotEmpty()) onAddPeer(id)
                    },
                    enabled = peerId.isNotBlank() && link == LinkState.Online,
                ) {
                    Text("Add")
                }
            }

            Spacer(Modifier.height(16.dp))
            Text("Conversations", fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(8.dp))

            if (peers.isEmpty()) {
                Text(
                    "No conversations yet. Add someone by their id once both " +
                        "devices are connected to the same relay.",
                    fontSize = 13.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                LazyColumn(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    items(peers, key = { it.userId }) { peer ->
                        PeerRow(peer) { onOpenPeer(peer) }
                        HorizontalDivider()
                    }
                }
            }
        }
    }
}

@Composable
private fun PeerRow(peer: Peer, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .width(38.dp)
                .height(38.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.primaryContainer),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                peer.displayName.take(1).uppercase(),
                fontWeight = FontWeight.Bold,
            )
        }
        Spacer(Modifier.width(12.dp))
        Column {
            Text(peer.displayName, fontWeight = FontWeight.Medium)
            Text(
                if (peer.safetyNumber == null) "no session yet" else "verified key available",
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
