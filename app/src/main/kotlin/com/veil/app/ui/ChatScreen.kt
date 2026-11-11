package com.veil.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.veil.app.LinkState
import com.veil.app.R
import com.veil.app.data.ChatMessage
import com.veil.app.data.Peer
import com.veil.app.data.SendState
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val timeFormat = SimpleDateFormat("HH:mm", Locale.getDefault())

@Composable
fun LinkBadge(state: LinkState) {
    val labelRes = when (state) {
        LinkState.Online -> R.string.link_online
        LinkState.Connecting -> R.string.link_connecting
        LinkState.Error -> R.string.link_error
        LinkState.Offline -> R.string.link_offline
    }
    val color = when (state) {
        LinkState.Online -> Color(0xFF4ADE80)
        LinkState.Connecting -> Color(0xFFFBBF24)
        LinkState.Error -> Color(0xFFF87171)
        LinkState.Offline -> Color(0xFF94A3B8)
    }
    val label = stringResource(labelRes)
    val description = stringResource(R.string.cd_link_state, label)

    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.semantics(mergeDescendants = true) { contentDescription = description },
    ) {
        Box(
            Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(color),
        )
        Spacer(Modifier.width(6.dp))
        // The colour alone carries no meaning for a screen reader, and very
        // little for a colour-blind reader either; the word is the message.
        Text(label, fontSize = 12.sp, color = color)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    peer: Peer,
    link: LinkState,
    messages: List<ChatMessage>,
    safetyNumber: String?,
    status: String?,
    onSend: (String) -> Unit,
    onBack: () -> Unit,
) {
    var draft by remember { mutableStateOf("") }
    var showSafety by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) listState.animateScrollToItem(messages.lastIndex)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(peer.displayName, fontWeight = FontWeight.SemiBold)
                        LinkBadge(link)
                    }
                },
                actions = {
                    TextButton(onClick = { showSafety = !showSafety }) {
                        Text(
                            stringResource(
                                if (showSafety) R.string.action_hide_code else R.string.action_verify,
                            ),
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
                navigationIcon = {
                    TextButton(onClick = onBack) { Text(stringResource(R.string.action_back)) }
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
            if (showSafety) {
                SafetyBanner(peer.userId, safetyNumber)
            }
            status?.let {
                Text(
                    it,
                    Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 6.dp),
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.error,
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
                items(messages, key = { it.id }) { message ->
                    MessageBubble(message, peer.displayName)
                }
            }

            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = draft,
                    onValueChange = { draft = it },
                    modifier = Modifier.weight(1f),
                    placeholder = { Text(stringResource(R.string.message_placeholder)) },
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                    maxLines = 4,
                )
                Spacer(Modifier.width(8.dp))
                Button(
                    onClick = {
                        val text = draft
                        draft = ""
                        onSend(text)
                    },
                    enabled = draft.isNotBlank() && link == LinkState.Online,
                ) {
                    Text(stringResource(R.string.action_send))
                }
            }
        }
    }
}

@Composable
private fun MessageBubble(message: ChatMessage, peerName: String) {
    val alignment = if (message.outgoing) Alignment.CenterEnd else Alignment.CenterStart
    val color = if (message.outgoing) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }

    val stamp = timeFormat.format(Date(message.timestamp))
    val bubbleDescription = stringResource(
        if (message.outgoing) R.string.cd_message_to else R.string.cd_message_from,
        peerName,
        stamp,
    )

    Box(Modifier.fillMaxWidth(), contentAlignment = alignment) {
        Card(
            Modifier
                .widthIn(max = 280.dp)
                .semantics(mergeDescendants = true) { contentDescription = bubbleDescription },
            shape = RoundedCornerShape(
                topStart = 16.dp,
                topEnd = 16.dp,
                bottomStart = if (message.outgoing) 16.dp else 4.dp,
                bottomEnd = if (message.outgoing) 4.dp else 16.dp,
            ),
            colors = CardDefaults.cardColors(containerColor = color),
        ) {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                Text(message.text)
                Spacer(Modifier.height(2.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    // A bubble only ever looked "sent". The state is spelled
                    // out now, because a frame that never left the device is a
                    // hole in the ratchet, not a cosmetic detail.
                    message.stateRes()?.let { stateRes ->
                        val label = stringResource(stateRes)
                        Text(
                            label,
                            fontSize = 10.sp,
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.semantics {
                                contentDescription = label
                            },
                        )
                        Spacer(Modifier.width(6.dp))
                    }
                    Text(
                        stamp,
                        fontSize = 10.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

/** The label shown next to an outgoing bubble, or null when there is nothing to say. */
private fun ChatMessage.stateRes(): Int? = when (state) {
    SendState.SENT -> null
    SendState.QUEUED -> R.string.send_state_queued
    SendState.FAILED -> R.string.send_state_failed
}

@Composable
private fun SafetyBanner(peerId: String, safetyNumber: String?) {
    Card(
        Modifier
            .fillMaxWidth()
            .padding(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer,
        ),
    ) {
        Column(Modifier.padding(14.dp)) {
            Text(
                stringResource(R.string.safety_title, peerId),
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(Modifier.height(6.dp))
            if (safetyNumber.isNullOrEmpty()) {
                Text(
                    stringResource(R.string.safety_no_session),
                    fontSize = 12.sp,
                )
            } else {
                val description = stringResource(R.string.cd_safety_number)
                Text(
                    safetyNumber,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 15.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .fillMaxWidth()
                        .semantics { contentDescription = description },
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    stringResource(R.string.safety_hint),
                    fontSize = 11.sp,
                )
            }
        }
    }
}
