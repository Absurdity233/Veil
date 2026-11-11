package com.veil.desktop

import java.io.ByteArrayOutputStream

/**
 * The relay wire protocol, shared with the Android client and the web client.
 *
 * This file is a copy of `app/src/main/kotlin/com/veil/app/net/Wire.kt` with the
 * Android-specific logging removed. It is duplicated rather than extracted
 * because the alternative - a shared Kotlin module - would drag the Android
 * client's whole build graph into a desktop build that otherwise needs nothing
 * but a JVM.
 *
 * The duplication is checked: `WireParityTest` compiles both copies and asserts
 * they produce byte-identical frames, so the two cannot drift apart silently.
 */
object Wire {
    const val VERSION = 1

    const val TYPE_HELLO = 0x01
    const val TYPE_HELLO_OK = 0x02
    const val TYPE_PUBLISH_PREKEYS = 0x03
    const val TYPE_GET_BUNDLE = 0x04
    const val TYPE_BUNDLE = 0x05
    const val TYPE_SEND = 0x06
    const val TYPE_DELIVER = 0x07
    const val TYPE_ACK = 0x08
    const val TYPE_ERROR = 0x09

    const val TYPE_AUTH_CHALLENGE = 0x0A
    const val TYPE_AUTH_RESPONSE = 0x0B
    const val TYPE_MORE_PENDING = 0x0C

    const val MAX_PAYLOAD = 1 shl 20

    /** Envelope: [1] version | [1] type | [4] length (BE) | payload. */
    fun frame(type: Int, payload: ByteArray): ByteArray {
        require(payload.size <= MAX_PAYLOAD) { "payload too large" }
        val out = ByteArray(6 + payload.size)
        out[0] = VERSION.toByte()
        out[1] = type.toByte()
        out[2] = (payload.size ushr 24).toByte()
        out[3] = (payload.size ushr 16).toByte()
        out[4] = (payload.size ushr 8).toByte()
        out[5] = payload.size.toByte()
        payload.copyInto(out, 6)
        return out
    }

    class Frame(val type: Int, val payload: ByteArray)

    fun parse(bytes: ByteArray): Frame {
        require(bytes.size >= 6) { "short frame" }
        require(bytes[0].toInt() and 0xFF == VERSION) { "unsupported protocol version" }
        val len = ((bytes[2].toInt() and 0xFF) shl 24) or
                ((bytes[3].toInt() and 0xFF) shl 16) or
                ((bytes[4].toInt() and 0xFF) shl 8) or
                (bytes[5].toInt() and 0xFF)
        require(len >= 0 && 6 + len == bytes.size) { "bad frame length" }
        return Frame(bytes[1].toInt() and 0xFF, bytes.copyOfRange(6, bytes.size))
    }
}

/** Appends length-prefixed fields, big endian. */
class Writer {
    private val out = ByteArrayOutputStream()

    fun u32(v: Int) = apply {
        out.write(byteArrayOf(
            (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte(),
        ))
    }

    /** Outbox ids are 8 bytes on the wire; see the relay's `writer.u64`. */
    fun u64(v: Long) = apply {
        out.write(byteArrayOf(
            (v ushr 56).toByte(), (v ushr 48).toByte(), (v ushr 40).toByte(), (v ushr 32).toByte(),
            (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte(),
        ))
    }

    fun blob(b: ByteArray) = apply {
        u32(b.size)
        out.write(b)
    }

    fun string(s: String) = apply { blob(s.toByteArray(Charsets.UTF_8)) }

    fun raw(b: ByteArray) = apply { out.write(b) }

    fun build(): ByteArray = out.toByteArray()
}

/** Reads length-prefixed fields, failing on any truncation. */
class Reader(private val data: ByteArray) {
    private var pos = 0

    val remaining: Int get() = data.size - pos

    fun u32(): Int {
        require(remaining >= 4) { "truncated" }
        val v = ((data[pos].toInt() and 0xFF) shl 24) or
                ((data[pos + 1].toInt() and 0xFF) shl 16) or
                ((data[pos + 2].toInt() and 0xFF) shl 8) or
                (data[pos + 3].toInt() and 0xFF)
        pos += 4
        return v
    }

    fun u64(): Long {
        require(remaining >= 8) { "truncated" }
        val hi = u32().toLong() and 0xFFFFFFFFL
        val lo = u32().toLong() and 0xFFFFFFFFL
        return (hi shl 32) or lo
    }

    fun blob(): ByteArray {
        val n = u32()
        require(n >= 0 && n <= Wire.MAX_PAYLOAD && n <= remaining) { "truncated" }
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun string(): String = String(blob(), Charsets.UTF_8)

    fun raw(n: Int): ByteArray {
        require(n >= 0 && n <= remaining) { "truncated" }
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun done() { require(remaining == 0) { "trailing bytes" } }
}