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
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
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
 * plain JVM window keeps the dependency list to three entries — JNA for the C
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
    private val userField = JTextField("", 16)
    private val connectButton = JButton("Connect")
    private val addPeerField = JTextField("", 18)
    private val addPeerButton = JButton("Add")
    private val statusLabel = JLabel(" ")
    private val linkLabel = JLabel("offline")

    private val peerModel = DefaultListModel<Peer>()
    private val peerList = JList(peerModel)

    private val transcriptArea = JTextArea()
    private val messageField = JTextField()
    private val sendButton = JButton("Send")
    private val safetyLabel = JLabel(" ")

    private var selectedPeer: Peer? = null

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

        root.add(top, BorderLayout.NORTH)

        // ---- Left: peers ----
        val left = JPanel(BorderLayout())
        left.border = EmptyBorder(0, 12, 12, 6)

        val addRow = JPanel(BorderLayout(6, 0))
        addRow.add(addPeerField, BorderLayout.CENTER)
        addRow.add(addPeerButton, BorderLayout.EAST)
        addRow.border = EmptyBorder(0, 0, 8, 0)
        left.add(addRow, BorderLayout.NORTH)

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
        right.add(JScrollPane(transcriptArea), BorderLayout.CENTER)

        val safetyRow = JPanel(BorderLayout())
        safetyRow.border = EmptyBorder(8, 0, 0, 0)
        safetyLabel.font = Font(Font.MONOSPACED, Font.PLAIN, 12)
        safetyRow.add(safetyLabel, BorderLayout.CENTER)
        right.add(safetyRow, BorderLayout.SOUTH)

        val compose = JPanel(BorderLayout(8, 0))
        compose.add(messageField, BorderLayout.CENTER)
        compose.add(sendButton, BorderLayout.EAST)
        compose.border = EmptyBorder(8, 0, 0, 0)

        val rightStack = JPanel(BorderLayout())
        rightStack.add(right, BorderLayout.CENTER)
        rightStack.add(compose, BorderLayout.SOUTH)

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

        peerList.addListSelectionListener {
            if (it.valueIsAdjusting) return@addListSelectionListener
            selectedPeer = peerList.selectedValue
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

    private fun sendCurrent() {
        val peer = selectedPeer ?: return
        val text = messageField.text
        if (text.isBlank()) return
        messageField.text = ""
        controller.sendMessage(peer.userId, text)
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
                SwingUtilities.invokeLater { applyPeers(peers) }
            }
        }

        scope.launch {
            controller.messages.collectLatest {
                SwingUtilities.invokeLater { renderTranscript() }
            }
        }
    }

    private fun applyPeers(peers: List<Peer>) {
        val selectedId = selectedPeer?.userId
        peerModel.clear()
        peers.forEach { peerModel.addElement(it) }

        if (selectedId != null) {
            val index = peers.indexOfFirst { it.userId == selectedId }
            if (index >= 0) {
                peerList.selectedIndex = index
                selectedPeer = peers[index]
            } else {
                selectedPeer = null
            }
        }
        renderTranscript()
        updateEnabledState()
    }

    private fun renderTranscript() {
        val peer = selectedPeer
        if (peer == null) {
            transcriptArea.text = "Add someone by their id once both clients are connected to the same relay."
            safetyLabel.text = " "
            return
        }

        val messages = controller.messages.value[peer.userId].orEmpty()
        val format = SimpleDateFormat("HH:mm", Locale.getDefault())

        transcriptArea.text = buildString {
            if (messages.isEmpty()) {
                appendLine("No messages yet.")
            }
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

        // Put the caret at the bottom, which is where a conversation reader
        // looks.
        transcriptArea.caretPosition = transcriptArea.document.length
    }

    private fun updateEnabledState() {
        val online = controller.link.value == LinkState.ONLINE
        val hasPeer = selectedPeer != null
        val hasSession = selectedPeer?.state == SessionState.READY

        connectButton.text = if (controller.link.value == LinkState.ONLINE) "Reconnect" else "Connect"
        connectButton.isEnabled = controller.link.value != LinkState.CONNECTING

        addPeerButton.isEnabled = online
        addPeerField.isEnabled = online

        messageField.isEnabled = hasPeer && hasSession
        sendButton.isEnabled = hasPeer && hasSession
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

            val peer = value as? Peer ?: return label
            val state = when (peer.state) {
                SessionState.READY -> "session ready"
                SessionState.PINNED_ONLY -> "identity pinned, no session"
                SessionState.NO_PEER -> "no session yet"
            }
            label.text = "<html><b>${escape(peer.displayName)}</b><br><font size='2'>$state</font></html>"
            label.border = EmptyBorder(6, 8, 6, 8)
            return label
        }

        private fun escape(s: String): String =
            s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    }
}