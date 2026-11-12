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
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.launch
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
import com.veil.app.data.GroupUi
import com.veil.app.data.Peer
import com.veil.app.data.SessionUiState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    selfUserId: String,
    serverUrl: String,
    link: LinkState,
    peers: List<Peer>,
    groups: List<GroupUi>,
    status: String?,
    onConnect: (serverUrl: String, userId: String) -> Unit,
    onAddPeer: (String) -> Unit,
    onOpenPeer: (Peer) -> Unit,
    onCreateGroup: (String) -> Unit,
    onOpenGroup: (String) -> Unit,
    onLinkThis: suspend () -> String?,
    onReadRequest: suspend (String) -> Pair<String, String>?,
    onApprove: suspend (String) -> String?,
    onAdopt: suspend (String, String) -> Boolean,
) {
    var url by remember { mutableStateOf(serverUrl) }
    var userId by remember { mutableStateOf(selfUserId) }
    var peerId by remember { mutableStateOf("") }
    var groupName by remember { mutableStateOf("") }

    var linkMode by remember { mutableStateOf<LinkMode?>(null) }
    var linkRequest by remember { mutableStateOf<String?>(null) }
    var linkStatus by remember { mutableStateOf<String?>(null) }
    var fingerprint by remember { mutableStateOf<String?>(null) }
    var requestedUser by remember { mutableStateOf<String?>(null) }

    val scope = rememberCoroutineScope()

    // The dialog is hoisted out of the Scaffold so it survives a recomposition of
    // the list behind it: a linking flow interrupted by an incoming message
    // arriving should not lose the request the user just generated.
    linkMode?.let { mode ->
        DeviceLinkDialog(
            mode = mode,
            request = linkRequest,
            status = linkStatus,
            onDismiss = { linkMode = null },
            onGenerateRequest = {
                scope.launch {
                    linkRequest = onLinkThis()
                    linkStatus = if (linkRequest == null) {
                        "this client has no device identity yet; connect first"
                    } else {
                        null
                    }
                }
            },
            onReadRequest = { text ->
                scope.launch {
                    // The decoder lives with the controller, which owns the one
                    // definition of how a request is encoded. Doing it here too
                    // would be a second definition to keep in step.
                    fingerprint = null
                    val read = onReadRequest(text)
                    if (read == null) {
                        linkStatus = "that request could not be read"
                        return@launch
                    }
                    requestedUser = read.first
                    fingerprint = read.second
                    linkStatus = null
                }
            },
            onApprove = { text ->
                scope.launch {
                    val credentialed = onApprove(text)
                    linkStatus = if (credentialed == null) {
                        "only the device that holds the account key can approve"
                    } else {
                        "approved. Copy this to the new device:\n$credentialed"
                    }
                }
            },
            onAdopt = { combined ->
                scope.launch {
                    val parts = combined.split('|', limit = 2)
                    if (parts.size != 2) {
                        linkStatus = "paste the credential and the account key"
                        return@launch
                    }
                    linkStatus = if (onAdopt(parts[0], parts[1])) {
                        "this device is now part of the account"
                    } else {
                        "that credential was refused"
                    }
                }
            },
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.home_title), fontWeight = FontWeight.SemiBold) },
                actions = {
                    // Two halves of one flow: a device that has the account
                    // approves a new one, and a device that does not asks to be
                    // approved. Both live here because the user is holding one
                    // device and looking at the other.
                    TextButton(onClick = {
                        linkMode = LinkMode.LINK_THIS
                        linkRequest = null
                        linkStatus = null
                    }) { Text("Link", fontSize = 12.sp) }
                    TextButton(onClick = {
                        linkMode = LinkMode.APPROVE_OTHER
                        linkStatus = null
                        fingerprint = null
                    }) { Text("Approve", fontSize = 12.sp) }
                    LinkBadge(link)
                },
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

            // Creating a group is local: it needs a device, not a connection, so
            // this stays enabled while offline. A client that could not prepare a
            // group before its members were reachable would be a worse client.
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = groupName,
                    onValueChange = { groupName = it },
                    label = { Text("New group name") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                )
                Spacer(Modifier.width(8.dp))
                Button(
                    onClick = {
                        val name = groupName.trim()
                        groupName = ""
                        if (name.isNotEmpty()) onCreateGroup(name)
                    },
                    enabled = groupName.isNotBlank() && link != LinkState.Connecting,
                ) {
                    Text("Group")
                }
            }

            Spacer(Modifier.height(16.dp))
            Text(stringResource(R.string.conversations), fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(8.dp))

            if (peers.isEmpty() && groups.isEmpty()) {
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
                    items(groups, key = { "group-${it.groupId}" }) { group ->
                        GroupRow(group) { onOpenGroup(group.groupId) }
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
