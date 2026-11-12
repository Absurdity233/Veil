package com.veil.desktop

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Graphics
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.event.FocusAdapter
import java.awt.event.FocusEvent
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import java.nio.file.Path
import java.nio.file.Paths
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.DefaultListCellRenderer
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JDialog
import javax.swing.JTabbedPane
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.JScrollBar
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities
import javax.swing.UIManager
import javax.swing.border.EmptyBorder

/**
 * The desktop client's window.
 *
 * Swing, not Compose, on purpose: this client exists to demonstrate that the
 * protocol engine and the wire format are portable, and pulling in a
 * cross-platform UI toolkit would make the build about the toolkit instead. A
 * plain JVM window keeps the dependency list to three entries 閳?JNA for the C
 * ABI, OkHttp for the socket, coroutines for the plumbing.
 */
fun main() {
    try {
        UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName())
    } catch (e: Exception) {
        // A platform look-and-feel that will not load is not a reason to fail
        // to start; the default one is fine.
    }

    val stateDir: Path = System.getProperty("veil.state.dir")
        ?.let { Paths.get(it) }
        ?: Paths.get(System.getProperty("user.home"), ".veil")

    SwingUtilities.invokeLater {
        try {
            DesktopWindow(stateDir).show()
        } catch (e: Throwable) {
            e.printStackTrace()
            javax.swing.JOptionPane.showMessageDialog(
                null,
                "Veil could not start.\n\n${e.message}\n\nThe native library may not be built. " +
                    "See docs/building.md.",
                "Veil",
                javax.swing.JOptionPane.ERROR_MESSAGE,
            )
            kotlin.system.exitProcess(1)
        }
    }
}

private const val DEFAULT_RELAY = "ws://127.0.0.1:8080/ws"
private const val REFRESH_LOW_WATER = 10

class DesktopWindow(stateDir: Path) {

    private val controller = ChatController(stateDir)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private val frame = JFrame("Veil")
    private val relayField = JTextField(DEFAULT_RELAY, 28)
    private val userField = HintField(16)
    private val connectButton = JButton("Connect")
    private val addPeerField = HintField(18)
    private val addPeerButton = JButton("Add")
    private val statusLabel = JLabel(" ")
    private val linkLabel = JLabel("offline")

    private val peerModel = DefaultListModel<Any>()
    private val peerList = JList(peerModel)

    private val transcriptArea = JTextArea()
    private val messageField = JTextField()
    private val sendButton = JButton("Send")
    private val safetyLabel = JLabel(" ")

    // ---- Groups ----
    //
    // One list holds both kinds of conversation rather than two lists or tabs.
    // A chat client's left column is "who you can talk to", and a group is one of
    // those - splitting it by type makes the user remember which tab a
    // conversation lives in, which is a fact about the implementation.
    private val groupIdField = HintField(14)
    private val createGroupButton = JButton("New group")
    private val membersField = HintField(18)
    private val membersButton = JButton("Set members")
    private val groupInfoLabel = JLabel(" ")

    // ---- Device linking ----
    //
    // Both halves of the flow in one dialog, because the user is holding one
    // device and looking at the other.
    private val linkButton = JButton("Link device")
    private val inviteField = HintField(18)
    private val inviteButton = JButton("Invite")

    /** What the transcript pane is currently showing. */
    private sealed class Conversation {
        data class WithPeer(val peer: Peer) : Conversation()
        data class WithGroup(val group: Group) : Conversation()
    }

    private var selection: Conversation? = null

    init {
        buildUi()
        wireEvents()
        observeState()
    }

    private fun buildUi() {
        frame.defaultCloseOperation = JFrame.DO_NOTHING_ON_CLOSE
        frame.minimumSize = Dimension(880, 560)
        frame.setSize(1040, 680)

        val root = JPanel(BorderLayout())

        // ---- Top: identity and relay ----
        val top = JPanel(GridBagLayout())
        top.border = EmptyBorder(10, 12, 6, 12)
        val gbc = GridBagConstraints().apply {
            insets = Insets(2, 4, 2, 4)
            anchor = GridBagConstraints.WEST
        }

        gbc.gridx = 0; gbc.gridy = 0
        top.add(JLabel("Relay"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL
        top.add(relayField, gbc)

        gbc.gridx = 2; gbc.weightx = 0.0; gbc.fill = GridBagConstraints.NONE
        top.add(JLabel("Your id"), gbc)
        gbc.gridx = 3
        top.add(userField, gbc)

        gbc.gridx = 4
        top.add(connectButton, gbc)

        gbc.gridx = 5
        top.add(linkLabel, gbc)

        gbc.gridx = 6
        top.add(linkButton, gbc)

        root.add(top, BorderLayout.NORTH)

        // ---- Left: peers ----
        val left = JPanel(BorderLayout())
        left.border = EmptyBorder(0, 12, 12, 6)

        val addRow = JPanel(BorderLayout(6, 0))
        addRow.add(addPeerField, BorderLayout.CENTER)
        addRow.add(addPeerButton, BorderLayout.EAST)
        addRow.border = EmptyBorder(0, 0, 8, 0)
        placeholder(addPeerField, "Add someone by id")

        // Creating a group sits beside adding a peer because both are "add a
        // conversation", which is the only thing the left column is for.
        val groupRow = JPanel(BorderLayout(6, 0))
        groupRow.add(groupIdField, BorderLayout.CENTER)
        groupRow.add(createGroupButton, BorderLayout.EAST)
        groupRow.border = EmptyBorder(0, 0, 8, 0)
        placeholder(groupIdField, "New group name")

        val leftTop = JPanel(BorderLayout())
        leftTop.add(addRow, BorderLayout.NORTH)
        leftTop.add(groupRow, BorderLayout.SOUTH)
        left.add(leftTop, BorderLayout.NORTH)

        peerList.selectionMode = ListSelectionModel.SINGLE_SELECTION
        peerList.cellRenderer = PeerCell()
        left.add(JScrollPane(peerList), BorderLayout.CENTER)
        left.preferredSize = Dimension(300, 0)

        // ---- Right: transcript ----
        val right = JPanel(BorderLayout())
        right.border = EmptyBorder(0, 6, 12, 12)

        transcriptArea.isEditable = false
        transcriptArea.lineWrap = true
        transcriptArea.wrapStyleWord = true
        transcriptArea.font = Font(Font.MONOSPACED, Font.PLAIN, 13)
        transcriptArea.background = Color(0xFAFAFA)
        transcriptArea.border = EmptyBorder(10, 12, 10, 12)

        // A read-only JTextArea takes focus when nothing else has it, and then
        // paints the whole transcript in the selection colour. It looks like the
        // text is selected and ready to be replaced, which it is not.
        transcriptArea.isFocusable = false
        transcriptArea.highlighter = null
        transcriptArea.caret.isVisible = false
        right.add(JScrollPane(transcriptArea), BorderLayout.CENTER)

        val safetyRow = JPanel(BorderLayout())
        safetyRow.border = EmptyBorder(8, 0, 0, 0)
        safetyLabel.font = Font(Font.MONOSPACED, Font.PLAIN, 12)
        safetyRow.add(safetyLabel, BorderLayout.CENTER)
        right.add(safetyRow, BorderLayout.SOUTH)

        // Group membership editor. Hidden for a peer conversation rather than
        // disabled: a control that never applies to what is on screen is noise.
        val memberRow = JPanel(BorderLayout(6, 0))
        memberRow.border = EmptyBorder(8, 0, 0, 0)
        memberRow.add(membersField, BorderLayout.CENTER)
        memberRow.add(membersButton, BorderLayout.EAST)
        memberRow.isVisible = false
        placeholder(membersField, "alice, bob")

        val groupInfoRow = JPanel(BorderLayout())
        groupInfoRow.border = EmptyBorder(4, 0, 0, 0)
        groupInfoLabel.font = Font(Font.MONOSPACED, Font.PLAIN, 11)
        groupInfoRow.add(groupInfoLabel, BorderLayout.CENTER)
        groupInfoRow.isVisible = false

        // Inviting is a pairwise act: it needs a session with the person, because
        // that session is what authenticates the founder to them.
        val inviteRow = JPanel(BorderLayout(6, 0))
        inviteRow.border = EmptyBorder(4, 0, 0, 0)
        inviteRow.add(inviteField, BorderLayout.CENTER)
        inviteRow.add(inviteButton, BorderLayout.EAST)
        inviteRow.isVisible = false
        placeholder(inviteField, "invite by id")

        val groupRows = JPanel(BorderLayout())
        groupRows.add(groupInfoRow, BorderLayout.NORTH)
        groupRows.add(memberRow, BorderLayout.CENTER)
        groupRows.add(inviteRow, BorderLayout.SOUTH)

        val compose = JPanel(BorderLayout(8, 0))
        compose.add(messageField, BorderLayout.CENTER)
        compose.add(sendButton, BorderLayout.EAST)
        compose.border = EmptyBorder(8, 0, 0, 0)

        val rightStack = JPanel(BorderLayout())
        rightStack.add(right, BorderLayout.CENTER)

        val rightBottom = JPanel(BorderLayout())
        rightBottom.add(groupRows, BorderLayout.NORTH)
        rightBottom.add(compose, BorderLayout.SOUTH)
        rightStack.add(rightBottom, BorderLayout.SOUTH)

        val split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, rightStack)
        split.resizeWeight = 0.28
        split.dividerSize = 6
        split.border = EmptyBorder(0, 0, 0, 0)
        root.add(split, BorderLayout.CENTER)

        // ---- Bottom: status ----
        val bottom = JPanel(FlowLayout(FlowLayout.LEFT, 12, 4))
        bottom.add(statusLabel)
        root.add(bottom, BorderLayout.SOUTH)

        frame.contentPane = root
        updateEnabledState()
    }

    private fun wireEvents() {
        connectButton.addActionListener {
            val url = relayField.text.trim()
            val id = userField.text.trim()
            if (url.isNotEmpty() && id.isNotEmpty()) {
                controller.connect(url, id)
            }
        }

        addPeerButton.addActionListener {
            val id = addPeerField.text.trim()
            if (id.isNotEmpty()) {
                controller.addPeer(id)
                addPeerField.text = ""
            }
        }
        addPeerField.addActionListener { addPeerButton.doClick() }

        sendButton.addActionListener { sendCurrent() }
        messageField.addActionListener { sendCurrent() }

        createGroupButton.addActionListener {
            val id = groupIdField.text.trim()
            if (id.isNotEmpty()) {
                controller.createGroup(id)
                groupIdField.text = ""
            }
        }
        groupIdField.addActionListener { createGroupButton.doClick() }

        membersButton.addActionListener { applyMembers() }
        membersField.addActionListener { applyMembers() }

        inviteButton.addActionListener {
            val group = (selection as? Conversation.WithGroup)?.group ?: return@addActionListener
            val peer = inviteField.text.trim()
            inviteField.text = ""
            if (peer.isNotEmpty()) controller.inviteToGroup(group.groupId, peer)
        }
        inviteField.addActionListener { inviteButton.doClick() }

        linkButton.addActionListener { showLinkingDialog() }

        peerList.addListSelectionListener {
            if (it.valueIsAdjusting) return@addListSelectionListener
            selection = when (val picked = peerList.selectedValue) {
                is Peer -> Conversation.WithPeer(picked)
                is Group -> Conversation.WithGroup(picked)
                else -> null
            }
            renderTranscript()
            updateEnabledState()
        }

        frame.addWindowListener(object : WindowAdapter() {
            override fun windowClosing(e: WindowEvent) {
                controller.close()
                scope.cancel()
                frame.dispose()
            }
        })
    }

    /**
     * Replaces a group's member list with whatever is in the field.
     *
     * Comma-separated because that is what a person types. The founder must
     * include themselves, which the engine would otherwise report as a group
     * they are not in.
     */
    private fun applyMembers() {
        val group = (selection as? Conversation.WithGroup)?.group ?: return
        val members = membersField.text.split(',', '\n')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        if (members.isEmpty()) return

        controller.setGroupMembers(group.groupId, members)
    }

    private fun sendCurrent() {
        val text = messageField.text
        if (text.isBlank()) return

        when (val current = selection) {
            is Conversation.WithPeer -> {
                messageField.text = ""
                controller.sendMessage(current.peer.userId, text)
            }
            is Conversation.WithGroup -> {
                messageField.text = ""
                controller.sendToGroup(current.group.groupId, text)
            }
            null -> Unit
        }
    }

    private fun observeState() {
        scope.launch {
            controller.link.collectLatest { link ->
                SwingUtilities.invokeLater {
                    linkLabel.text = when (link) {
                        LinkState.ONLINE -> "online"
                        LinkState.CONNECTING -> "connecting"
                        LinkState.ERROR -> "error"
                        LinkState.OFFLINE -> "offline"
                    }
                    linkLabel.foreground = when (link) {
                        LinkState.ONLINE -> Color(0x2E7D32)
                        LinkState.CONNECTING -> Color(0xB26A00)
                        LinkState.ERROR -> Color(0xC62828)
                        LinkState.OFFLINE -> Color(0x607D8B)
                    }
                    updateEnabledState()
                }
            }
        }

        scope.launch {
            controller.status.collectLatest { status ->
                SwingUtilities.invokeLater { statusLabel.text = status ?: " " }
            }
        }

        scope.launch {
            controller.peers.collectLatest { peers ->
                SwingUtilities.invokeLater {
                    applyConversations(peers, controller.groups.value)
                }
            }
        }

        scope.launch {
            controller.groups.collectLatest { groups ->
                SwingUtilities.invokeLater {
                    applyConversations(controller.peers.value, groups)
                }
            }
        }

        scope.launch {
            controller.messages.collectLatest {
                SwingUtilities.invokeLater { renderTranscript() }
            }
        }

        scope.launch {
            controller.groupMessages.collectLatest {
                SwingUtilities.invokeLater { renderTranscript() }
            }
        }
    }

    /**
     * Rebuilds the conversation list from peers and groups.
     *
     * One list rather than two: a chat client's left column is "who you can talk
     * to", and a group is one of those. Selection is preserved by identity rather
     * than by index, so a group appearing does not move what the user was
     * reading.
     */
    private fun applyConversations(peers: List<Peer>, groups: List<Group>) {
        val previous = selection

        peerModel.clear()
        peers.forEach { peerModel.addElement(it) }
        groups.forEach { peerModel.addElement(it) }

        val restoredIndex = when (previous) {
            is Conversation.WithPeer ->
                peers.indexOfFirst { it.userId == previous.peer.userId }.takeIf { it >= 0 }
            is Conversation.WithGroup ->
                groups.indexOfFirst { it.groupId == previous.group.groupId }
                    .takeIf { it >= 0 }?.plus(peers.size)
            null -> null
        }

        if (restoredIndex != null) {
            peerList.selectedIndex = restoredIndex
        } else {
            selection = null
        }

        renderTranscript()
        updateEnabledState()
    }

    private fun renderTranscript() {
        when (val current = selection) {
            is Conversation.WithPeer -> renderPeerTranscript(current.peer)
            is Conversation.WithGroup -> renderGroupTranscript(current.group)
            null -> {
                transcriptArea.text =
                    "Add someone by their id, or create a group, once both clients " +
                        "are connected to the same relay."
                safetyLabel.text = " "
            }
        }
    }

    private fun renderPeerTranscript(peer: Peer) {
        val messages = controller.messages.value[peer.userId].orEmpty()
        val format = SimpleDateFormat("HH:mm", Locale.getDefault())

        transcriptArea.text = buildString {
            if (messages.isEmpty()) appendLine("No messages yet.")
            for (message in messages) {
                val who = if (message.outgoing) "you" else peer.userId
                val stamp = format.format(Date(message.timestamp))
                val marker = when (message.state) {
                    SendState.SENT -> ""
                    SendState.QUEUED -> "  (sending)"
                    SendState.FAILED -> "  (NOT SENT - queued for retry)"
                }
                appendLine("[$stamp] $who: ${message.text}$marker")
            }
        }

        val safety = controller.safetyNumberFor(peer.userId)
        safetyLabel.text = if (safety.isNullOrEmpty()) {
            "Safety number: no session yet"
        } else {
            "Safety number: $safety   (compare with the other device)"
        }

        transcriptArea.caretPosition = transcriptArea.document.length
    }

    /**
     * A group transcript names every sender, because there is more than one.
     *
     * The epoch is shown when it is the reason a send will fail: a membership
     * change discards every chain, so the group is unusable until each member
     * republishes one. Saying so is better than letting the send fail silently.
     */
    private fun renderGroupTranscript(group: Group) {
        val messages = controller.groupMessages.value[group.groupId].orEmpty()
        val format = SimpleDateFormat("HH:mm", Locale.getDefault())

        transcriptArea.text = buildString {
            if (messages.isEmpty()) appendLine("No group messages yet.")
            for (message in messages) {
                val who = if (message.outgoing) "you" else message.senderId
                val stamp = format.format(Date(message.timestamp))
                appendLine("[$stamp] $who: ${message.text}")
            }
        }

        groupInfoLabel.text = buildString {
            append("Members (epoch ${group.epoch}): ")
            append(group.members.joinToString(", "))
            if (!group.canSend) {
                append("   - this client is not a member, so it cannot send")
            }
        }
        groupInfoLabel.isVisible = true

        // Seed the field with the current members so an edit starts from what is
        // there rather than from an empty box the user has to retype.
        if (!membersField.hasFocus()) {
            membersField.text = group.members.joinToString(", ")
        }
        membersButton.isEnabled = controller.link.value != LinkState.CONNECTING
        membersField.isVisible = true
        membersButton.isVisible = true

        transcriptArea.caretPosition = transcriptArea.document.length
    }

    private fun updateEnabledState() {
        val online = controller.link.value == LinkState.ONLINE
        val current = selection

        connectButton.text =
            if (controller.link.value == LinkState.ONLINE) "Reconnect" else "Connect"
        connectButton.isEnabled = controller.link.value != LinkState.CONNECTING

        addPeerButton.isEnabled = online
        addPeerField.isEnabled = online

        // Creating a group is local, so it needs a device rather than a network.
        // A client that cannot do it offline would be a client that cannot
        // prepare a group before its members are reachable.
        createGroupButton.isEnabled = controller.link.value != LinkState.CONNECTING
        groupIdField.isEnabled = controller.link.value != LinkState.CONNECTING

        val canCompose = when (current) {
            is Conversation.WithPeer -> current.peer.state == SessionState.READY
            is Conversation.WithGroup -> current.group.canSend
            null -> false
        }

        messageField.isEnabled = canCompose
        sendButton.isEnabled = canCompose

        // The membership editor and the epoch line belong to a group only.
        val onGroup = current is Conversation.WithGroup
        groupInfoLabel.isVisible = onGroup
        memberRowVisible(onGroup)
    }

    /**
     * The device linking dialog.
     *
     * Both halves in one window, with tabs, because the user is holding one device
     * and looking at the other. The fingerprint is shown in a large monospaced
     * font: it is the one thing a person has to actually compare, so it cannot be
     * the smallest text on screen.
     */
    private fun showLinkingDialog() {
        val dialog = JDialog(frame, "Link a device", true)
        dialog.defaultCloseOperation = JDialog.DISPOSE_ON_CLOSE
        dialog.setSize(520, 560)
        dialog.setLocationRelativeTo(frame)

        val tabs = JTabbedPane()

        // ---- Link this device ----
        val linkPane = JPanel(BorderLayout(0, 8))
        linkPane.border = EmptyBorder(12, 12, 12, 12)

        val ownRequest = JTextArea(3, 40)
        ownRequest.isEditable = false
        ownRequest.lineWrap = true
        ownRequest.font = Font(Font.MONOSPACED, Font.PLAIN, 10)

        val generate = JButton("Generate request")
        val linkStatus = JLabel(" ")

        val credentialField = JTextArea(3, 40)
        credentialField.font = Font(Font.MONOSPACED, Font.PLAIN, 10)
        val identityField = JTextArea(2, 40)
        identityField.font = Font(Font.MONOSPACED, Font.PLAIN, 10)
        val adopt = JButton("Adopt credential")

        val linkTop = JPanel(BorderLayout(0, 6))
        linkTop.add(generate, BorderLayout.NORTH)
        linkTop.add(JScrollPane(ownRequest), BorderLayout.CENTER)

        val linkForm = JPanel(GridBagLayout())
        val gbc = GridBagConstraints().apply {
            insets = Insets(3, 0, 3, 0)
            fill = GridBagConstraints.HORIZONTAL
            weightx = 1.0
            gridx = 0
        }
        fun addRow(label: String, field: java.awt.Component, row: Int) {
            gbc.gridy = row * 2
            gbc.weighty = 0.0
            linkForm.add(JLabel(label), gbc)
            gbc.gridy = row * 2 + 1
            gbc.weighty = 1.0
            linkForm.add(JScrollPane(field), gbc)
        }
        addRow("Credential from the other device", credentialField, 0)
        addRow("Account identity from that device", identityField, 1)

        val linkBottom = JPanel(BorderLayout(0, 6))
        linkBottom.add(linkForm, BorderLayout.CENTER)
        linkBottom.add(adopt, BorderLayout.SOUTH)

        linkPane.add(linkTop, BorderLayout.NORTH)
        linkPane.add(linkBottom, BorderLayout.CENTER)
        linkPane.add(linkStatus, BorderLayout.SOUTH)
        tabs.addTab("Link this device", linkPane)

        // ---- Approve another ----
        val approvePane = JPanel(BorderLayout(0, 8))
        approvePane.border = EmptyBorder(12, 12, 12, 12)

        val requestField = JTextArea(3, 40)
        requestField.font = Font(Font.MONOSPACED, Font.PLAIN, 10)
        val readIt = JButton("Read it")

        val accountLabel = JLabel(" ")
        val fingerprintLabel = JLabel(" ")
        fingerprintLabel.font = Font(Font.MONOSPACED, Font.BOLD, 20)
        val approve = JButton("Approve and show the credential")
        val issued = JTextArea(3, 40)
        issued.isEditable = false
        issued.font = Font(Font.MONOSPACED, Font.PLAIN, 10)
        issued.isVisible = false
        val approveStatus = JLabel(" ")

        val details = JPanel(GridBagLayout())
        val dgbc = GridBagConstraints().apply {
            insets = Insets(4, 0, 4, 0)
            fill = GridBagConstraints.HORIZONTAL
            weightx = 1.0
            gridx = 0
            gridy = 0
        }
        details.add(JLabel("Account"), dgbc)
        dgbc.gridy = 1
        details.add(accountLabel, dgbc)
        dgbc.gridy = 2
        details.add(JLabel("Fingerprint - must match the other device"), dgbc)
        dgbc.gridy = 3
        details.add(fingerprintLabel, dgbc)
        dgbc.gridy = 4
        details.add(approve, dgbc)
        dgbc.gridy = 5
        dgbc.fill = GridBagConstraints.BOTH
        dgbc.weighty = 1.0
        details.add(JScrollPane(issued), dgbc)
        details.isVisible = false

        val approveTop = JPanel(BorderLayout(0, 6))
        approveTop.add(JScrollPane(requestField), BorderLayout.CENTER)
        approveTop.add(readIt, BorderLayout.SOUTH)

        approvePane.add(approveTop, BorderLayout.NORTH)
        approvePane.add(details, BorderLayout.CENTER)
        approvePane.add(approveStatus, BorderLayout.SOUTH)
        tabs.addTab("Approve another", approvePane)

        generate.addActionListener {
            scope.launch {
                val request = controller.linkingRequest()
                if (request == null) {
                    linkStatus.text = "this client has no device identity yet: connect first"
                    return@launch
                }
                ownRequest.text = base64(request)
                linkStatus.text = " "
            }
        }

        adopt.addActionListener {
            scope.launch {
                val ok = controller.adoptLinkingFromText(
                    credentialField.text, identityField.text,
                )
                linkStatus.text = if (ok) {
                    "this device is now part of the account"
                } else {
                    "that credential was refused"
                }
            }
        }

        readIt.addActionListener {
            scope.launch {
                val bytes = fromBase64(requestField.text)
                val parsed = bytes?.let { controller.readLinkingRequest(it) }
                if (parsed == null) {
                    approveStatus.text = "that request could not be read"
                    return@launch
                }
                accountLabel.text = parsed.first
                fingerprintLabel.text = parsed.second
                details.isVisible = true
                approveStatus.text = " "
            }
        }

        approve.addActionListener {
            scope.launch {
                val bytes = fromBase64(requestField.text)
                val credential = bytes?.let { controller.approveLinking(it) }
                if (credential == null) {
                    approveStatus.text =
                        "only the device that holds the account key can approve"
                    return@launch
                }
                issued.text = base64(credential)
                issued.isVisible = true
                approveStatus.text = "approved. Send this to the new device."
            }
        }

        dialog.contentPane = tabs
        dialog.isVisible = true
    }

    private fun base64(bytes: ByteArray): String =
        java.util.Base64.getEncoder().encodeToString(bytes)

    private fun fromBase64(text: String): ByteArray? = try {
        val cleaned = text.filterNot { it.isWhitespace() }
        if (cleaned.isEmpty()) null else java.util.Base64.getDecoder().decode(cleaned)
    } catch (e: IllegalArgumentException) {
        null
    }

    private fun memberRowVisible(visible: Boolean) {
        // These are children of a compound row; toggling them is what actually
        // shows or hides it in a BorderLayout.
        membersField.isVisible = visible
        membersButton.isVisible = visible
        inviteField.isVisible = visible
        inviteButton.isVisible = visible
    }

    /**
     * Gives a text field a grey hint that disappears as soon as it is typed in.
     *
     * Swing has no placeholder, and an unlabelled box beside a button that says
     * "Add" does not tell the user what to add. The hint lives on the component
     * rather than in the model, so it can never be read back as a value by the
     * code that sends a message or creates a group.
     */
    private fun placeholder(field: HintField, hint: String) {
        field.hint = hint
    }

    fun show() {
        frame.isVisible = true
        // Ask the engine for the real session state once the window is up, so
        // the list does not show a stale "ready" from a previous run.
        controller.refreshStates()
    }

    private inner class PeerCell : DefaultListCellRenderer() {
        override fun getListCellRendererComponent(
            list: JList<*>,
            value: Any?,
            index: Int,
            isSelected: Boolean,
            cellHasFocus: Boolean,
        ): java.awt.Component {
            val label = super.getListCellRendererComponent(
                list, value, index, isSelected, cellHasFocus,
            ) as JLabel

            when (val item = value) {
                is Peer -> {
                    val state = when (item.state) {
                        SessionState.READY -> "session ready"
                        SessionState.PINNED_ONLY -> "identity pinned, no session"
                        SessionState.NO_PEER -> "no session yet"
                    }
                    // The device count is shown only when there is more than
                    // one: a single-device peer is the ordinary case, and
                    // saying "1 device" on every row is noise that hides the
                    // row where it matters.
                    val devices = if (item.devices.size > 1) {
                        ", ${item.devices.size} devices"
                    } else {
                        ""
                    }
                    label.text = "<html><b>${escape(item.displayName)}</b>" +
                        "<br><font size='2'>$state$devices</font></html>"
                }
                is Group -> {
                    val state = if (item.canSend) {
                        "group, epoch ${item.epoch}"
                    } else {
                        "group, epoch ${item.epoch} - not a member"
                    }
                    label.text = "<html><b># ${escape(item.groupId)}</b>" +
                        "<br><font size='2'>$state</font></html>"
                }
                else -> return label
            }

            label.border = EmptyBorder(6, 8, 6, 8)
            return label
        }

        private fun escape(s: String): String =
            s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    }
}
/**
 * A text field that draws a grey hint while it is empty.
 *
 * Swing has no placeholder support, and the alternative - seeding the model with
 * the hint text - makes the hint a value: a user who clicks "Add" without typing
 * would add a peer called "Add someone by id". Painting it in the component
 * keeps the model honest, which is why this exists rather than a one-line hack.
 */
private class HintField(columns: Int) : JTextField("", columns) {

    var hint: String = ""
        set(value) {
            field = value
            repaint()
        }

    init {
        // The hint has to disappear when there is text, and appear again when it
        // is cleared, so every path that can change the content repaints.
        addFocusListener(object : FocusAdapter() {
            override fun focusGained(e: FocusEvent) = repaint()
            override fun focusLost(e: FocusEvent) = repaint()
        })
        addKeyListener(object : KeyAdapter() {
            override fun keyReleased(e: KeyEvent) = repaint()
        })
        document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = repaint()
            override fun removeUpdate(e: DocumentEvent) = repaint()
            override fun changedUpdate(e: DocumentEvent) = repaint()
        })
    }

    override fun paintComponent(g: Graphics) {
        super.paintComponent(g)

        if (text.isNotEmpty() || hint.isEmpty()) return

        // Drawn after the text so it sits on an otherwise empty field, in the
        // disabled foreground colour: readable, obviously not a value.
        val g2 = g.create()
        try {
            g2.color = Color(0x9E9E9E)
            g2.font = font
            val metrics = g2.fontMetrics
            val x = insets.left + 4
            val y = (height + metrics.ascent - metrics.descent) / 2
            g2.drawString(hint, x, y)
        } finally {
            g2.dispose()
        }
    }
}