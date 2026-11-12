package com.veil.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Linking this device to an existing account, or endorsing a new one.
 *
 * Two halves of one flow, because they happen on two devices and the user is
 * usually holding both:
 *
 *   - the *new* device shows a request and a fingerprint, then pastes back the
 *     credential it receives;
 *   - the *existing* device (which holds the account key) pastes a request, sees
 *     what it is about to approve, and signs it.
 *
 * The fingerprint is the whole security story of this dialog. Approving a request
 * without comparing it is approving whatever the clipboard contains, so the
 * fingerprint is shown large and in a monospace face rather than buried in a
 * paragraph.
 */
@Composable
fun DeviceLinkDialog(
    mode: LinkMode,
    request: String?,
    status: String?,
    onDismiss: () -> Unit,
    onGenerateRequest: () -> Unit,
    onReadRequest: (String) -> Unit,
    onApprove: (String) -> Unit,
    onAdopt: (String) -> Unit,
) {
    var requestText by remember { mutableStateOf("") }
    var credentialText by remember { mutableStateOf("") }
    var accountText by remember { mutableStateOf("") }
    var fingerprint by remember { mutableStateOf<String?>(null) }
    var requestedUser by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                when (mode) {
                    LinkMode.LINK_THIS -> "Link this device"
                    LinkMode.APPROVE_OTHER -> "Approve another device"
                },
                fontWeight = FontWeight.SemiBold,
            )
        },
        text = {
            Column(
                Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
            ) {
                when (mode) {
                    LinkMode.LINK_THIS -> {
                        Text(
                            "Show this request to the device that already has your " +
                                "account, then paste the credential it gives you back.",
                            fontSize = 13.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(10.dp))

                        Button(onClick = onGenerateRequest) { Text("Generate request") }

                        request?.let {
                            Spacer(Modifier.height(8.dp))
                            Text("Your request", fontSize = 12.sp, fontWeight = FontWeight.Medium)
                            Text(
                                it,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp,
                                modifier = Modifier.padding(top = 4.dp),
                            )
                        }

                        Spacer(Modifier.height(12.dp))
                        HorizontalDivider()
                        Spacer(Modifier.height(12.dp))

                        OutlinedTextField(
                            value = credentialText,
                            onValueChange = { credentialText = it },
                            label = { Text("Credential from the other device") },
                            modifier = Modifier.fillMaxWidth(),
                            minLines = 3,
                        )
                        Spacer(Modifier.height(6.dp))
                        OutlinedTextField(
                            value = accountText,
                            onValueChange = { accountText = it },
                            label = { Text("Account public key (from that device)") },
                            modifier = Modifier.fillMaxWidth(),
                            minLines = 2,
                        )
                        Spacer(Modifier.height(8.dp))
                        Button(
                            onClick = { onAdopt("$credentialText|$accountText") },
                            enabled = credentialText.isNotBlank() && accountText.isNotBlank(),
                        ) { Text("Adopt credential") }
                    }

                    LinkMode.APPROVE_OTHER -> {
                        Text(
                            "Paste the request the new device is showing. Compare the " +
                                "fingerprint before you approve it.",
                            fontSize = 13.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(10.dp))

                        OutlinedTextField(
                            value = requestText,
                            onValueChange = {
                                requestText = it
                                fingerprint = null
                                requestedUser = null
                            },
                            label = { Text("Request") },
                            modifier = Modifier.fillMaxWidth(),
                            minLines = 3,
                        )
                        Spacer(Modifier.height(6.dp))
                        Button(
                            onClick = { onReadRequest(requestText) },
                            enabled = requestText.isNotBlank(),
                        ) { Text("Read it") }

                        fingerprint?.let { fp ->
                            Spacer(Modifier.height(12.dp))
                            Text("Account", fontSize = 12.sp, fontWeight = FontWeight.Medium)
                            Text(requestedUser ?: "", fontSize = 13.sp)
                            Spacer(Modifier.height(6.dp))
                            Text(
                                "Fingerprint - must match the other device",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Medium,
                            )
                            // Large and monospaced: this is the one thing the user
                            // has to actually compare, so it cannot be the smallest
                            // text on screen.
                            Text(
                                fp,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 18.sp,
                                modifier = Modifier.padding(top = 4.dp),
                            )

                            Spacer(Modifier.height(10.dp))
                            Button(onClick = { onApprove(requestText) }) {
                                Text("Approve and copy the credential")
                            }
                        }
                    }
                }

                status?.let {
                    Spacer(Modifier.height(10.dp))
                    Text(
                        it,
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        },
    )
}

/** Which half of the linking flow this dialog is showing. */
enum class LinkMode { LINK_THIS, APPROVE_OTHER }
