package com.veil.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import com.veil.app.checkPassword
import com.veil.app.describeStrength

/**
 * The account dialog: create, restore, and change the password.
 *
 * The password never leaves the device: what goes to the relay is a blob sealed
 * under a key derived from it with Argon2id. So the relay cannot verify the
 * password and cannot open the vault - and the honest corollary, stated on the
 * create tab, is that a forgotten password means a lost account.
 */
@Composable
fun AccountDialog(
    signedInAs: String,
    onDismiss: () -> Unit,
    onCreate: suspend (String) -> String?,
    onRestore: suspend (String, String) -> String?,
    onChange: suspend (String, String) -> String?,
) {
    var tab by remember { mutableStateOf(0) }
    var status by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Account") },
        text = {
            Column(
                Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
            ) {
                TabRow(selectedTabIndex = tab) {
                    Tab(selected = tab == 0, onClick = { tab = 0; status = null },
                        text = { Text("Create", fontSize = 12.sp) })
                    Tab(selected = tab == 1, onClick = { tab = 1; status = null },
                        text = { Text("Sign in", fontSize = 12.sp) })
                    Tab(selected = tab == 2, onClick = { tab = 2; status = null },
                        text = { Text("Change", fontSize = 12.sp) })
                }

                Spacer(Modifier.height(12.dp))

                when (tab) {
                    0 -> CreatePane(onCreate = onCreate, onStatus = { status = it }, status = status)
                    1 -> RestorePane(
                        signedInAs = signedInAs,
                        onRestore = onRestore,
                        onStatus = { status = it },
                        status = status,
                    )
                    else -> ChangePane(onChange = onChange, onStatus = { status = it }, status = status)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        },
    )
}

@Composable
private fun CreatePane(
    onCreate: suspend (String) -> String?,
    onStatus: (String?) -> Unit,
    status: String?,
) {
    var password by remember { mutableStateOf("") }
    var repeat by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val scope = androidx.compose.runtime.rememberCoroutineScope()

    val problem = checkPassword(password)

    Text(
        "Protects the identity on this device so it can be restored elsewhere. " +
            "The password is never sent anywhere: if you forget it, the account " +
            "cannot be recovered.",
        fontSize = 12.sp,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.height(10.dp))

    OutlinedTextField(
        value = password,
        onValueChange = { password = it },
        label = { Text("Password") },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.Password,
            imeAction = ImeAction.Next,
        ),
    )
    Text(
        problem ?: "strength: ${describeStrength(password)}",
        fontSize = 11.sp,
        color = if (problem != null) MaterialTheme.colorScheme.error
        else MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(top = 4.dp),
    )

    Spacer(Modifier.height(8.dp))
    OutlinedTextField(
        value = repeat,
        onValueChange = { repeat = it },
        label = { Text("Repeat") },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
    )

    Spacer(Modifier.height(10.dp))
    Button(
        onClick = {
            if (password != repeat) {
                onStatus("the two passwords do not match")
                return@Button
            }
            if (problem != null) {
                onStatus(problem)
                return@Button
            }
            busy = true
            onStatus("deriving the key (this takes a moment)...")
            scope.launch {
                val error = onCreate(password)
                busy = false
                onStatus(error ?: "account created")
                if (error == null) {
                    password = ""
                    repeat = ""
                }
            }
        },
        enabled = !busy && password.isNotEmpty() && repeat.isNotEmpty(),
    ) { Text(if (busy) "Working..." else "Create and upload") }

    status?.let {
        Spacer(Modifier.height(8.dp))
        Text(it, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun RestorePane(
    signedInAs: String,
    onRestore: suspend (String, String) -> String?,
    onStatus: (String?) -> Unit,
    status: String?,
) {
    var id by remember { mutableStateOf(signedInAs) }
    var password by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val scope = androidx.compose.runtime.rememberCoroutineScope()

    Text(
        "Restores the identity stored for this id. Everything sealed in the vault " +
            "comes back: contacts, groups and message history.",
        fontSize = 12.sp,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.height(10.dp))

    OutlinedTextField(
        value = id,
        onValueChange = { id = it },
        label = { Text("Id") },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
    )
    Spacer(Modifier.height(8.dp))
    OutlinedTextField(
        value = password,
        onValueChange = { password = it },
        label = { Text("Password") },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
    )

    Spacer(Modifier.height(10.dp))
    Button(
        onClick = {
            busy = true
            onStatus("deriving the key (this takes a moment)...")
            scope.launch {
                val error = onRestore(id.trim(), password)
                busy = false
                onStatus(error ?: "signed in")
                if (error == null) password = ""
            }
        },
        enabled = !busy && id.isNotBlank() && password.isNotEmpty(),
    ) { Text(if (busy) "Working..." else "Sign in") }

    status?.let {
        Spacer(Modifier.height(8.dp))
        Text(it, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun ChangePane(
    onChange: suspend (String, String) -> String?,
    onStatus: (String?) -> Unit,
    status: String?,
) {
    var oldPassword by remember { mutableStateOf("") }
    var newPassword by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val scope = androidx.compose.runtime.rememberCoroutineScope()

    val problem = checkPassword(newPassword)

    Text(
        "Re-seals the stored account under a new password. The current one is " +
            "required: re-sealing is the one moment a typo would produce an " +
            "account this device cannot open later.",
        fontSize = 12.sp,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.height(10.dp))

    OutlinedTextField(
        value = oldPassword,
        onValueChange = { oldPassword = it },
        label = { Text("Current password") },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
    )
    Spacer(Modifier.height(8.dp))
    OutlinedTextField(
        value = newPassword,
        onValueChange = { newPassword = it },
        label = { Text("New password") },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
    )
    Text(
        problem ?: "strength: ${describeStrength(newPassword)}",
        fontSize = 11.sp,
        color = if (problem != null) MaterialTheme.colorScheme.error
        else MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(top = 4.dp),
    )

    Spacer(Modifier.height(10.dp))
    Button(
        onClick = {
            if (problem != null) {
                onStatus(problem)
                return@Button
            }
            busy = true
            onStatus("deriving the key (this takes a moment)...")
            scope.launch {
                val error = onChange(oldPassword, newPassword)
                busy = false
                onStatus(error ?: "password changed")
                if (error == null) {
                    oldPassword = ""
                    newPassword = ""
                }
            }
        },
        enabled = !busy && oldPassword.isNotEmpty() && newPassword.isNotEmpty(),
    ) { Text(if (busy) "Working..." else "Change password") }

    status?.let {
        Spacer(Modifier.height(8.dp))
        Text(it, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
