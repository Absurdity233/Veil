package main

import (
	"bytes"
	"testing"
)

// Fuzz targets for the parsers that see attacker bytes.
//
// The relay reads a websocket frame, splits an envelope, then a sequence of
// length-prefixed fields. Every one of those steps is driven by numbers the
// sender chose, so a length check that is off by one is a panic at best and a
// read past the buffer at worst. Go's fuzzer finds those for the cost of a
// seed corpus.
//
//	go test -fuzz=FuzzEnvelope -fuzztime=60s
//	go test -fuzz=FuzzOneTimeSet -fuzztime=60s

func FuzzEnvelope(f *testing.F) {
	f.Add([]byte{1, typeSend, 0, 0, 0, 3, 'a', 'b', 'c'})
	f.Add([]byte{1, typeHello, 0, 0, 0, 0})
	f.Add([]byte{1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		msgType, payload, err := parseEnvelope(data)
		if err != nil {
			return
		}
		// A frame that parsed must round-trip through the same codec.
		env, ferr := frame(msgType, payload)
		if ferr != nil {
			return
		}
		gotType, gotPayload, err := parseEnvelope(env)
		if err != nil {
			t.Fatalf("re-framed envelope does not parse: %v", err)
		}
		if gotType != msgType {
			t.Fatalf("type = %#x, want %#x", gotType, msgType)
		}
		if !bytes.Equal(gotPayload, payload) {
			t.Fatalf("payload changed across a round trip")
		}
	})
}

func FuzzFields(f *testing.F) {
	var seed writer
	seed.str("alice")
	seed.blob([]byte{1, 2, 3})
	seed.u32(7)
	seed.u64(1 << 40)
	f.Add(seed.bytes())
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		r := reader{buf: data}
		// Read a fixed sequence; any truncation must be an error, never a
		// silent short read or a panic.
		_, _ = r.str()
		_, _ = r.blob()
		_, _ = r.u32()
		_, _ = r.u64()
		// done() is only meaningful when every read succeeded.
		_ = r.done()
	})
}

func FuzzOneTimeSet(f *testing.F) {
	// A valid two-entry set.
	valid := []byte{0, 0, 0, 2, 0, 0, 0x10, 1}
	valid = append(valid, bytes.Repeat([]byte{0x22}, 32)...)
	valid = append(valid, 0, 0, 0x10, 2)
	valid = append(valid, bytes.Repeat([]byte{0x33}, 32)...)
	f.Add(valid)
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 1})

	f.Fuzz(func(t *testing.T, data []byte) {
		set, err := parseOneTimeSet(data)
		if err != nil {
			return
		}
		// The count field must agree with the body, so a parsed set always
		// divides evenly.
		if len(set.entries)%preKeyEntryLen != 0 {
			t.Fatalf("entries = %d bytes, not a multiple of %d", len(set.entries), preKeyEntryLen)
		}
		// Taking every entry must terminate and never over-read.
		for {
			id, pub := set.take()
			if id == 0 {
				break
			}
			if len(pub) != 32 {
				t.Fatalf("pub = %d bytes, want 32", len(pub))
			}
		}
		// Re-encoding an exhausted set yields a valid empty set.
		if _, err := parseOneTimeSet(set.encode()); err != nil {
			t.Fatalf("re-encoded set does not parse: %v", err)
		}
	})
}