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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.veil.app.LinkState
import com.veil.app.R
import com.veil.app.data.Peer
import com.veil.app.data.SessionUiState

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
                title = { Text(stringResource(R.string.home_title), fontWeight = FontWeight.SemiBold) },
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
                    Text(stringResource(R.string.relay_section), fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = url,
                        onValueChange = { url = it },
                        label = { Text(stringResource(R.string.relay_url_label)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = userId,
                        onValueChange = { userId = it },
                        label = { Text(stringResource(R.string.user_id_label)) },
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
                            Text(
                                stringResource(
                                    if (link == LinkState.Online) R.string.action_reconnect
                                    else R.string.action_connect,
                                ),
                            )
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
                    label = { Text(stringResource(R.string.add_peer_label)) },
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
                    Text(stringResource(R.string.action_add))
                }
            }

            Spacer(Modifier.height(16.dp))
            Text(stringResource(R.string.conversations), fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(8.dp))

            if (peers.isEmpty()) {
                Text(
                    stringResource(R.string.empty_conversations),
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
    val stateLabel = when (peer.sessionState) {
        SessionUiState.READY -> stringResource(R.string.peer_state_ready)
        SessionUiState.PINNED_ONLY -> stringResource(R.string.peer_state_pinned)
        SessionUiState.NO_PEER -> stringResource(R.string.peer_state_no_session)
    }
    val openLabel = stringResource(R.string.cd_open_conversation, peer.displayName)

    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClickLabel = openLabel, onClick = onClick)
            .semantics(mergeDescendants = true) { contentDescription = openLabel }
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
                stateLabel,
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
