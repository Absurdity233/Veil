package main

import (
	"errors"
	"fmt"
)

// Wire protocol shared by the client and the relay.
//
// Envelope:
//
//	[1] version
//	[1] type
//	[4] payload length, big endian
//	[n] payload
//
// Every payload is a sequence of length-prefixed fields, so a malformed frame
// fails cleanly instead of reading past its end.
const (
	protocolVersion = 1

	typeHello          = 0x01
	typeHelloOK        = 0x02
	typePublishPreKeys = 0x03
	typeGetBundle      = 0x04
	typeBundle         = 0x05
	typeSend           = 0x06
	typeDeliver        = 0x07
	typeAck            = 0x08
	typeError          = 0x09
)

const (
	envelopeHeaderSize = 6
	maxPayload         = 1 << 20 // 1 MiB
)

var errShortFrame = errors.New("short frame")

// frame wraps a payload in the envelope.
func frame(msgType byte, payload []byte) ([]byte, error) {
	if len(payload) > maxPayload {
		return nil, fmt.Errorf("payload too large: %d", len(payload))
	}
	out := make([]byte, envelopeHeaderSize+len(payload))
	out[0] = protocolVersion
	out[1] = msgType
	n := uint32(len(payload))
	out[2] = byte(n >> 24)
	out[3] = byte(n >> 16)
	out[4] = byte(n >> 8)
	out[5] = byte(n)
	copy(out[envelopeHeaderSize:], payload)
	return out, nil
}

// parseEnvelope splits a websocket message into its type and payload.
func parseEnvelope(b []byte) (msgType byte, payload []byte, err error) {
	if len(b) < envelopeHeaderSize {
		return 0, nil, errShortFrame
	}
	if b[0] != protocolVersion {
		return 0, nil, fmt.Errorf("unsupported protocol version %d", b[0])
	}
	n := uint32(b[2])<<24 | uint32(b[3])<<16 | uint32(b[4])<<8 | uint32(b[5])
	if n > maxPayload {
		return 0, nil, fmt.Errorf("payload too large: %d", n)
	}
	if int(n) != len(b)-envelopeHeaderSize {
		return 0, nil, errShortFrame
	}
	return b[1], b[envelopeHeaderSize:], nil
}

// ---- Field codec -------------------------------------------------------

type writer struct{ buf []byte }

func (w *writer) u32(v uint32) {
	w.buf = append(w.buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (w *writer) blob(b []byte) {
	w.u32(uint32(len(b)))
	w.buf = append(w.buf, b...)
}

func (w *writer) str(s string) { w.blob([]byte(s)) }

// raw appends bytes with no length prefix.
func (w *writer) raw(b []byte) { w.buf = append(w.buf, b...) }

func (w *writer) bytes() []byte { return w.buf }

type reader struct {
	buf []byte
	pos int
}

var errTruncated = errors.New("truncated payload")

func (r *reader) u32() (uint32, error) {
	if len(r.buf)-r.pos < 4 {
		return 0, errTruncated
	}
	v := uint32(r.buf[r.pos])<<24 | uint32(r.buf[r.pos+1])<<16 |
		uint32(r.buf[r.pos+2])<<8 | uint32(r.buf[r.pos+3])
	r.pos += 4
	return v, nil
}

func (r *reader) blob() ([]byte, error) {
	n, err := r.u32()
	if err != nil {
		return nil, err
	}
	if n > maxPayload || int(n) > len(r.buf)-r.pos {
		return nil, errTruncated
	}
	out := r.buf[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return out, nil
}

func (r *reader) str() (string, error) {
	b, err := r.blob()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (r *reader) done() bool { return r.pos == len(r.buf) }
