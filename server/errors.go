package main

import "errors"

var (
	errUnknownType       = errors.New("unknown message type")
	errBadUserID         = errors.New("invalid user id")
	errBadIdentity       = errors.New("identity key must be 64 bytes")
	errIdentityMismatch  = errors.New("identity key does not match the one on record")
	errHelloFirst        = errors.New("complete the identity challenge before anything else")
	errBadPreKeys        = errors.New("malformed prekey set")
	errNoBundle          = errors.New("no prekeys published for that user")
	errBadRecipient      = errors.New("invalid recipient")
	errSelfSend          = errors.New("cannot send a message to yourself")
	errAlreadyChallenged = errors.New("a challenge was already issued on this connection")
	errNoChallenge       = errors.New("send HELLO to request a challenge first")
	errBadSignature      = errors.New("identity proof did not verify")
	errRateLimited       = errors.New("too many sends on this connection; back off")
	errShuttingDown      = errors.New("relay is shutting down")
	errBadDevices        = errors.New("malformed device list")
	errForeignAccount    = errors.New("a connection may only publish its own device list")
	errBadDeviceID       = errors.New("invalid device id")
)
