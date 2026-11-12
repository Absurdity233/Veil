package com.veil.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.veil.app.LinkState
import com.veil.app.data.GroupMessageUi
import com.veil.app.data.GroupUi

/**
 * A group conversation.
 *
 * Two things differ from a peer conversation and both are on screen: the epoch,
 * because a membership change discards every chain and nobody can send until each
 * member republishes one; and the sender of each message, because there is more
 * than one of them.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GroupScreen(
    group: GroupUi,
    link: LinkState,
    messages: List<GroupMessageUi>,
    peers: List<com.veil.app.data.Peer>,
    status: String?,
    onSend: (String) -> Unit,
    onSetMembers: (List<String>) -> Unit,
    onInvite: (String) -> Unit,
    onBack: () -> Unit,
) {
    var draft by remember { mutableStateOf("") }
    var members by remember(group.groupId) { mutableStateOf(group.members.joinToString(", ")) }
    var invitee by remember { mutableStateOf("") }
    var showMembers by remember { mutableStateOf(false) }

    val listState = rememberLazyListState()
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) listState.animateScrollToItem(messages.lastIndex)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("# ${group.groupId}", fontWeight = FontWeight.SemiBold)
                        // The epoch is shown because it is the reason a send may be
                        // unavailable, and a silent failure reads as a bug.
                        Text(
                            "epoch ${group.epoch} - ${group.members.size} members",
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                actions = {
                    TextButton(onClick = { showMembers = !showMembers }) {
                        Text(if (showMembers) "Hide" else "Members")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
                navigationIcon = {
                    TextButton(onClick = onBack) { Text("Back") }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding(),
        ) {
            if (showMembers) {
                Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                    OutlinedTextField(
                        value = members,
                        onValueChange = { members = it },
                        label = { Text("Members, comma separated") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                    )
                    Spacer(Modifier.height(6.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Button(
                            onClick = {
                                val list = members.split(',')
                                    .map { it.trim() }
                                    .filter { it.isNotEmpty() }
                                if (list.isNotEmpty()) onSetMembers(list)
                            },
                        ) { Text("Set members") }

                        Spacer(Modifier.width(12.dp))
                        Text(
                            "Only the founder may change this.",
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }

                    Spacer(Modifier.height(10.dp))

                    // Inviting is a pairwise act: it needs a session with the
                    // person, because that session is what authenticates the
                    // founder to them.
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        OutlinedTextField(
                            value = invitee,
                            onValueChange = { invitee = it },
                            label = { Text("Invite by id") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                        )
                        Spacer(Modifier.width(8.dp))
                        Button(
                            onClick = {
                                val id = invitee.trim()
                                invitee = ""
                                if (id.isNotEmpty()) onInvite(id)
                            },
                            enabled = invitee.isNotBlank(),
                        ) { Text("Invite") }
                    }
                    HorizontalDivider(Modifier.padding(vertical = 10.dp))
                }
            }

            if (!group.canSend) {
                Text(
                    "This client is not a member, so it cannot send.",
                    Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 6.dp),
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            status?.let {
                Text(
                    it,
                    Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 6.dp),
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            LazyColumn(
                state = listState,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(
                    horizontal = 16.dp,
                    vertical = 8.dp,
                ),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                items(messages) { message ->
                    GroupBubble(message)
                }
            }

            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = draft,
                    onValueChange = { draft = it },
                    label = { Text("Message") },
                    modifier = Modifier.weight(1f),
                    maxLines = 4,
                    enabled = group.canSend && link == LinkState.Online,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                    keyboardActions = KeyboardActions(
                        onSend = {
                            if (draft.isNotBlank()) {
                                onSend(draft)
                                draft = ""
                            }
                        },
                    ),
                )
                Spacer(Modifier.width(8.dp))
                Button(
                    onClick = {
                        if (draft.isNotBlank()) {
                            onSend(draft)
                            draft = ""
                        }
                    },
                    enabled = draft.isNotBlank() && group.canSend && link == LinkState.Online,
                ) { Text("Send") }
            }
        }
    }
}

@Composable
private fun GroupBubble(message: GroupMessageUi) {
    Column(
        Modifier.fillMaxWidth(),
        horizontalAlignment = if (message.outgoing) Alignment.End else Alignment.Start,
    ) {
        // Every group message names its sender: unlike a peer conversation, the
        // other side is not one person.
        Text(
            if (message.outgoing) "you" else message.senderId,
            fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            message.text,
            Modifier
                .padding(top = 2.dp)
                .fillMaxWidth(0.85f),
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

/** One row in the home list, for a group. */
@Composable
fun GroupRow(group: GroupUi, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                "# ${group.groupId}",
                fontWeight = FontWeight.Medium,
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                if (group.canSend) {
                    "group, epoch ${group.epoch}"
                } else {
                    "group, epoch ${group.epoch} - not a member"
                },
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        TextButton(onClick = onClick) { Text("Open") }
    }
}