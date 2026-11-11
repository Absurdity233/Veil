package main

import "errors"

var (
	errUnknownType      = errors.New("unknown message type")
	errBadUserID        = errors.New("invalid user id")
	errBadIdentity      = errors.New("identity key must be 64 bytes")
	errIdentityMismatch = errors.New("identity key does not match the one on record")
	errHelloFirst       = errors.New("send HELLO before anything else")
	errBadPreKeys       = errors.New("malformed prekey set")
	errNoBundle         = errors.New("no prekeys published for that user")
	errBadRecipient     = errors.New("invalid recipient")
	errSelfSend         = errors.New("cannot send a message to yourself")
)
