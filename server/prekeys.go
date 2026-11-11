package main

import "fmt"

// A client publishes its signed prekey and its one-time prekeys as separate
// fields, so the only structured part the relay receives is the one-time
// list, in the client's own encoding:
//
//	[4] number of one-time prekeys
//	per one-time prekey: [4] id, [32] public key
//
// Everything in it is public key material. The relay parses it for one
// reason: a one-time prekey must be handed out exactly once. This is the only
// place the relay looks inside a client payload; message bodies stay opaque.
const preKeyEntryLen = 4 + 32

type oneTimeSet struct {
	entries []byte
}

func parseOneTimeSet(b []byte) (*oneTimeSet, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("one-time set too short: %d", len(b))
	}
	count := be32(b[0:4])
	if int(count)*preKeyEntryLen != len(b)-4 {
		return nil, fmt.Errorf("one-time set has %d entries but %d trailing bytes",
			count, len(b)-4)
	}
	return &oneTimeSet{entries: b[4:]}, nil
}

func (s *oneTimeSet) len() int { return len(s.entries) / preKeyEntryLen }

// take removes and returns the first one-time prekey, or a zero id when the
// set is exhausted.
func (s *oneTimeSet) take() (id uint32, pub []byte) {
	if len(s.entries) < preKeyEntryLen {
		return 0, nil
	}
	id = be32(s.entries[0:4])
	pub = s.entries[4:preKeyEntryLen]
	s.entries = s.entries[preKeyEntryLen:]
	return id, pub
}

// encode returns the set in the wire form the client understands.
func (s *oneTimeSet) encode() []byte {
	out := make([]byte, 4, 4+len(s.entries))
	n := uint32(s.len())
	out[0] = byte(n >> 24)
	out[1] = byte(n >> 16)
	out[2] = byte(n >> 8)
	out[3] = byte(n)
	return append(out, s.entries...)
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
