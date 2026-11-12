package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = maxPayload + envelopeHeaderSize

	// One page of replayable outbox entries. The client is told to ask for
	// more whenever a page came back full, so a large backlog drains over
	// several round trips instead of stalling at the first page.
	flushPageSize = 200

	// How long a graceful shutdown waits for connections to close politely
	// before the process exits anyway.
	drainGraceful = 5 * time.Second
)

// allowedOrigins is an explicit allow-list. Browsers send an Origin header on
// every websocket handshake they initiate; a page served from anywhere else
// must not be able to open a socket, because the handshake would otherwise
// inherit whatever ambient credentials that page enjoys against this host.
//
// An empty list means "native clients only": those send no Origin at all. A
// deployment that serves a browser build sets VEIL_ALLOWED_ORIGINS.
type originPolicy struct {
	exact []string
}

func newOriginPolicy(raw string) originPolicy {
	var out originPolicy
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Normalise so "https://example.com/" and "https://example.com"
		// compare equal.
		if u, err := url.Parse(entry); err == nil {
			if u.Scheme != "" && u.Host != "" {
				entry = u.Scheme + "://" + u.Host
			}
		}
		out.exact = append(out.exact, entry)
	}
	return out
}

// check reports whether a handshake may proceed.
//
// No Origin header at all is accepted: that is what the Android client and
// every other non-browser client sends, and a browser cannot forge its
// absence. A browser request must name an origin on the list.
func (p originPolicy) check(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if u, err := url.Parse(origin); err == nil && u.Scheme != "" && u.Host != "" {
		origin = u.Scheme + "://" + u.Host
	}
	for _, allowed := range p.exact {
		if subtle.ConstantTimeCompare([]byte(origin), []byte(allowed)) == 1 {
			return true
		}
	}
	return false
}

// Hub tracks live connections and owns the fan-out.
type Hub struct {
	store  *Store
	log    *slog.Logger
	origin originPolicy

	mu     sync.RWMutex
	byUser map[string]map[*client]struct{}

	// Set once the process is shutting down. New handshakes are refused and
	// live sockets are closed with a "going away" code, so a client knows to
	// reconnect rather than sitting on a socket that will never speak again.
	draining atomic.Bool

	// Counters the readiness endpoint reports. They are cheap and they are the
	// only way to notice that something is rejecting frames in bulk.
	statRejected atomic.Int64
	statAccepted atomic.Int64
}

func NewHub(store *Store, log *slog.Logger) *Hub {
	return NewHubWithOrigins(store, log, "")
}

// NewHubWithOrigins is what main() uses; NewHub keeps the tests terse.
func NewHubWithOrigins(store *Store, log *slog.Logger, allowedOrigins string) *Hub {
	return &Hub{
		store:  store,
		log:    log,
		origin: newOriginPolicy(allowedOrigins),
		byUser: make(map[string]map[*client]struct{}),
	}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// The real decision is made by originPolicy.check() before the upgrade,
	// so this callback only has to confirm it.
	CheckOrigin: func(r *http.Request) bool { return true },
}

func (h *Hub) attach(c *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	set, ok := h.byUser[c.userID]
	if !ok {
		set = make(map[*client]struct{})
		h.byUser[c.userID] = set
	}
	set[c] = struct{}{}
}

func (h *Hub) detach(c *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	set, ok := h.byUser[c.userID]
	if !ok {
		return
	}
	delete(set, c)
	if len(set) == 0 {
		delete(h.byUser, c.userID)
	}
}

func (h *Hub) sessions(userID string) []*client {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*client, 0, len(h.byUser[userID]))
	for c := range h.byUser[userID] {
		out = append(out, c)
	}
	return out
}

// deliver pushes body to every live session of recipient, queueing it when
// none are connected. Returns whether it went out immediately.
//
// Both paths hand the client the same shape:
//
//	[8] outbox id (0 for a live delivery) | [sender] | [body]
//
// The id is 8 bytes now, not 4. It used to be the SQLite rowid truncated to
// u32, which overflows at 2^32 across all recipients and made an
// acknowledgement able to delete the wrong entry once it wrapped.
// deliver pushes body to the recipient, queueing it when nobody is connected.
//
// `deviceID` is the device the frame is encrypted to. Empty means "the whole
// account", which is what a single-device peer and a client that has not
// fetched a device list send. See sessionsFor for why the distinction matters.
func (h *Hub) deliver(recipient, deviceID, sender string, body []byte) (bool, error) {
	var stored writer
	stored.str(sender)
	stored.blob(body)
	payload := stored.bytes()

	// A frame addressed to a device only reaches that device. An empty device id
	// means the sender does not know the recipient's devices 鈥?a single-device
	// account, or a client that has not fetched the list 鈥?and is delivered to
	// every connection of the user, which is the behaviour that existed before
	// device addressing.
	targets := h.sessionsFor(recipient, deviceID)
	if len(targets) == 0 {
		seq, err := h.store.Seq(recipient)
		if err != nil {
			return false, err
		}
		if err := h.enforceCeiling(recipient); err != nil {
			return false, err
		}
		return false, h.store.EnqueueDevice(recipient, deviceID, sender, seq, payload)
	}

	var live writer
	live.u64(0)
	live.buf = append(live.buf, payload...)
	env, err := frame(typeDeliver, live.bytes())
	if err != nil {
		return false, err
	}

	sent := false
	for _, c := range targets {
		if c.enqueue(env) {
			sent = true
		}
	}
	if !sent {
		seq, err := h.store.Seq(recipient)
		if err != nil {
			return false, err
		}
		return false, h.store.EnqueueDevice(recipient, deviceID, sender, seq, payload)
	}
	return true, nil
}

// sessionsFor returns the connections of `recipient` that may receive a frame
// addressed to `deviceID`.
//
// An empty deviceID matches every connection, which is how a single-device
// account and a not-yet-upgraded client keep working. A non-empty one matches
// only connections that authenticated as that device: a fan-out frame is
// encrypted to one device's ratchet, so handing it to a sibling would produce an
// authentication failure on a message that was never meant for it.
func (h *Hub) sessionsFor(recipient, deviceID string) []*client {
	all := h.sessions(recipient)
	if deviceID == "" {
		return all
	}

	out := make([]*client, 0, 1)
	for _, c := range all {
		if c.deviceID == deviceID {
			out = append(out, c)
		}
	}
	return out
}

// enforceCeiling keeps one recipient's backlog inside the per-user limit by
// sweeping before the insert rather than after it, so the ceiling is never
// exceeded even briefly.
func (h *Hub) enforceCeiling(recipient string) error {
	n, err := h.store.PendingFor(recipient)
	if err != nil || n < outboxPerRecipient {
		return err
	}
	_, _, err = h.store.Sweep(time.Now())
	return err
}

// flush replays the outbox for a freshly connected client, one page at a time.
//
// The client acknowledges each page as it is consumed; the relay keeps a
// cursor per connection and offers the next page whenever the client asks.
// The old behaviour - a single 200-entry page at HELLO - left everything past
// the first page stranded until the next reconnect, with the UI showing an
// empty conversation and no indication that more was waiting.
func (h *Hub) flush(c *client, afterID uint64) (uint64, error) {
	pending, err := h.store.DrainForDevice(c.userID, c.deviceID, afterID, flushPageSize)
	if err != nil {
		return afterID, err
	}

	last := afterID
	for _, m := range pending {
		// m.Payload already carries sender|body; prepend the outbox id so
		// the client can acknowledge it.
		var w writer
		w.u64(m.ID)
		w.buf = append(w.buf, m.Payload...)
		env, err := frame(typeDeliver, w.bytes())
		if err != nil {
			return last, err
		}
		if !c.enqueue(env) {
			return last, nil
		}
		last = m.ID
	}

	// A full page means there is probably more behind it. Say so, and let the
	// client's next ACK pull the following page.
	if len(pending) == flushPageSize {
		c.morePending = true
		if env, err := frame(typeMorePending, nil); err == nil {
			c.enqueue(env)
		}
	} else {
		c.morePending = false
	}
	return last, nil
}

// newMux wires the relay routes. Kept separate from main so tests exercise
// exactly the same routing as production.
func newMux(h *Hub) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/ws", h)

	// Liveness: "the process is up". Deliberately does not touch the store,
	// so a slow disk cannot get a healthy process restarted.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})

	// Readiness: "I can serve". Reports what actually breaks in practice -
	// queue depth, live connections, and a write that proves the store is
	// usable - and returns 503 when the store cannot be written.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		h.serveReady(w)
	})

	// Kept as an alias: the image healthcheck and older deployments probe it.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		h.serveReady(w)
	})
	return mux
}

func (h *Hub) serveReady(w http.ResponseWriter) {
	pending, err := h.store.PendingCount()
	if err != nil {
		h.log.Warn("readiness: store unavailable", "err", err)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("store unavailable\n"))
		return
	}

	// A read can succeed against a file that cannot be written, so the probe
	// writes something and takes it back. This is what actually catches a full
	// disk or a read-only mount.
	if _, _, err := h.store.Sweep(time.Now()); err != nil {
		h.log.Warn("readiness: sweep failed", "err", err)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("store not writable\n"))
		return
	}

	live := 0
	h.mu.RLock()
	for _, set := range h.byUser {
		live += len(set)
	}
	h.mu.RUnlock()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintf(w, "ok\noutbox=%d\nconnections=%d\naccepted=%d\nrejected=%d\n",
		pending, live, h.statAccepted.Load(), h.statRejected.Load())
}

// Shutdown closes every live socket with a "going away" status and waits for
// the handlers to unwind.
//
// http.Server.Shutdown does not touch hijacked connections, so without this the
// process exited 10 seconds later and clients only found out when their next
// write failed - which, with ratchet state in play, is a worse failure than a
// clean close.
func (h *Hub) Shutdown(ctx context.Context) {
	h.draining.Store(true)

	h.mu.RLock()
	var all []*client
	for _, set := range h.byUser {
		for c := range set {
			all = append(all, c)
		}
	}
	h.mu.RUnlock()

	for _, c := range all {
		c.goodbye()
	}

	deadline := time.After(drainGraceful)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			h.mu.RLock()
			live := 0
			for _, set := range h.byUser {
				live += len(set)
			}
			h.mu.RUnlock()
			if live == 0 {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(25 * time.Millisecond):
			}
		}
	}()

	select {
	case <-done:
	case <-deadline:
	case <-ctx.Done():
	}
	h.log.Info("relay drained", "remaining", len(all))
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.draining.Load() {
		http.Error(w, "shutting down", http.StatusServiceUnavailable)
		return
	}
	if !h.origin.check(r) {
		// Deliberately terse: a client probing the policy learns nothing
		// beyond "no", but the operator gets the counter and the reason.
		h.statRejected.Add(1)
		h.log.Warn("rejected cross-origin handshake", "origin", r.Header.Get("Origin"))
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.statRejected.Add(1)
		h.log.Warn("upgrade failed", "err", err)
		return
	}

	c := &client{
		hub:    h,
		conn:   conn,
		send:   make(chan []byte, 256),
		closed: make(chan struct{}),
		limit:  newRateLimiter(sendBurst, sendRefill),
	}
	go c.writeLoop()
	c.readLoop()
}

// client is one websocket connection.
type client struct {
	hub  *Hub
	conn *websocket.Conn

	userID  string
	// The device this connection speaks for, as hex. Empty means the client did
	// not present one: a relay that predates device addressing, or a
	// single-device account whose frames are addressed by the bare user id.
	//
	// A connection may only receive frames addressed to its own device. That is
	// the whole point: a fan-out frame for device A is encrypted to A's ratchet,
	// so handing it to device B would not just leak it, it would produce an
	// authentication failure on a message that was never meant for B.
	deviceID string

	send    chan []byte
	closed  chan struct{}
	closeMu sync.Once

	// ---- HELLO challenge ----
	//
	// The nonce is issued once per connection and dies with it. A client that
	// never answers is disconnected rather than left holding it.
challenge         []byte
	challengeSeen     bool
	authed            bool
	pendingUserID     string
	pendingDeviceID   string
	pendingIdentity   []byte

	// ---- outbox replay cursor ----
	flushCursor uint64
	morePending bool

	// Per-connection send pacing.
	limit *rateLimiter
}

// rateLimiter is a token bucket in the simple sense: a burst allowance that
// refills at a fixed rate.
//
// A relay will accept ciphertext from any authenticated sender for any
// recipient, so without a ceiling one connection can fill the outbox for
// everybody else. Refusing with an error is better than silently dropping,
// because the sender can back off.
type rateLimiter struct {
	mu      sync.Mutex
	tokens  float64
	burst   float64
	perTick float64
	period  time.Duration
	last    time.Time
}

func newRateLimiter(burst int, period time.Duration) *rateLimiter {
	return &rateLimiter{
		tokens:  float64(burst),
		burst:   float64(burst),
		perTick: 1,
		period:  period,
		last:    time.Now(),
	}
}

func (l *rateLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if elapsed := now.Sub(l.last); elapsed >= l.period {
		refill := float64(elapsed/l.period) * l.perTick
		l.tokens = min(l.burst, l.tokens+refill)
		l.last = now
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// enqueue never blocks: a slow peer is disconnected rather than allowed to
// stall the whole hub.
func (c *client) enqueue(b []byte) bool {
	select {
	case c.send <- b:
		return true
	case <-c.closed:
		return false
	default:
		return false
	}
}

func (c *client) shutdown() {
	c.closeMu.Do(func() {
		close(c.closed)
		_ = c.conn.Close()
	})
}

// goodbye closes politely: a real close frame with "going away", which tells
// the client to reconnect instead of assuming the network died.
func (c *client) goodbye() {
	c.closeMu.Do(func() {
		// Best effort: the peer may already be gone.
		_ = c.conn.SetWriteDeadline(time.Now().Add(time.Second))
		_ = c.conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseGoingAway, "relay shutting down"))
		close(c.closed)
		_ = c.conn.Close()
	})
}

func (c *client) writeLoop() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.shutdown()
	}()

	for {
		select {
		case <-c.closed:
			return
		case b := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *client) readLoop() {
	defer func() {
		if c.userID != "" {
			c.hub.detach(c)
			c.hub.log.Info("disconnected", "user", c.userID)
		}
		c.shutdown()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		// Before the handshake completes the deadline is the auth budget, not
		// the liveness budget: an unauthenticated socket must not be able to
		// hold a challenge open for an hour by trickling frames.
		if c.authed {
			_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
		} else if len(c.challenge) != 0 {
			_ = c.conn.SetReadDeadline(time.Now().Add(authTimeout))
		} else {
			_ = c.conn.SetReadDeadline(time.Now().Add(authTimeout))
		}

		if err := c.handle(data); err != nil {
			c.fail(err.Error())
		}
	}
}

func (c *client) fail(msg string) {
	var w writer
	w.str(msg)
	if env, err := frame(typeError, w.bytes()); err == nil {
		c.enqueue(env)
	}
}

func (c *client) draining() bool { return c.hub.draining.Load() }

func (c *client) handle(data []byte) error {
	msgType, payload, err := parseEnvelope(data)
	if err != nil {
		return err
	}

	switch msgType {
	case typeHello:
		return c.handleHello(payload)
	case typeAuthResponse:
		return c.handleAuthResponse(payload)
	case typePublishPreKeys:
		return c.handlePublishPreKeys(payload)
	case typeGetBundle:
		return c.handleGetBundle(payload)
	case typeSend:
		return c.handleSend(payload)
	case typeAck:
		return c.handleAck(payload)
	case typePublishDevices:
		return c.handlePublishDevices(payload)
	case typeGetDevices:
		return c.handleGetDevices(payload)
	case typePutVault:
		return c.handlePutVault(payload)
	case typeGetVault:
		return c.handleGetVault(payload)
	default:
		return errUnknownType
	}
}

// ---- Password vaults ---------------------------------------------------
//
// A vault is the only thing a client can use before authenticating, because a
// client restoring its identity has no key to sign a challenge with yet. That is
// not a hole: the vault is sealed under a key derived from a password the relay
// never sees, so reading it without the password yields nothing.
//
// What the relay *does* learn, and the price of this feature:
//
//   - that a user id exists, before they ever connect;
//   - roughly how much data they keep;
//   - when they last wrote, because a write carries a timestamp.
//
// It does not learn the password, the identity, or anything about who they talk
// to beyond what the outbox already showed.

// maxVaultBlob is the vault ceiling, expressed in terms of the transport's.
//
// It used to be a flat 4 MiB, which is *larger* than maxPayload - so the check
// could never fire, and a 4 MiB vault would have been refused by the frame codec
// with an error that says nothing about vaults. Deriving it from the transport
// limit keeps the two consistent by construction: a test asserts the relationship
// rather than a comment claiming it.
const maxVaultBlob = maxPayload - 1024  // room for the salt, params and lengths

// handlePutVault stores a sealed vault.
//
// Payload: [str] user | [blob] salt | [4] memory | [4] passes | [4] lanes
//          | [blob] blob
func (c *client) handlePutVault(payload []byte) error {
	r := reader{buf: payload}

	userID, err := r.str()
	if err != nil {
		return err
	}
	if userID == "" || len(userID) > 128 {
		return errBadUserID
	}

	// An authenticated connection may only write its own vault; an unauthenticated
	// one is writing for the first time and has nothing to authenticate with yet.
	if c.userID != "" && c.userID != userID {
		c.hub.log.Warn("vault write for another account refused",
			"authenticated", c.userID, "claimed", userID)
		c.hub.statRejected.Add(1)
		return errForeignAccount
	}

	salt, err := r.blob()
	if err != nil {
		return err
	}
	memory, err := r.u32()
	if err != nil {
		return err
	}
	passes, err := r.u32()
	if err != nil {
		return err
	}
	lanes, err := r.u32()
	if err != nil {
		return err
	}
	blob, err := r.blob()
	if err != nil {
		return err
	}
	if !r.done() {
		return errTruncated
	}

	// Bounds on the KDF parameters. A client asking for an absurd memory cost is
	// not this relay's problem to pay for, but a client asking for *too little* is
	// weakening its own vault - and the relay is the one place that can refuse
	// without knowing the password.
	if len(salt) < 8 || len(salt) > 64 {
		return errBadVault
	}
	if memory < 8*lanes || memory > 256*1024 {
		return errBadVault
	}
	if passes < 1 || passes > 10 {
		return errBadVault
	}
	if lanes < 1 || lanes > 8 {
		return errBadVault
	}
	if len(blob) == 0 || len(blob) > maxVaultBlob {
		return errBadVault
	}

	generation, err := c.hub.store.PutVault(userID, VaultRecord{
		Salt:      append([]byte(nil), salt...),
		MemoryKiB: memory,
		Passes:    passes,
		Lanes:     lanes,
		Blob:      append([]byte(nil), blob...),
	})
	if err != nil {
		return err
	}

	c.hub.log.Info("vault written", "user", userID,
		"bytes", len(blob), "generation", generation)

	var w writer
	w.u32(generation)
	env, err := frame(typeVaultAck, w.bytes())
	if err != nil {
		return err
	}
	c.enqueue(env)
	return nil
}

// handleGetVault returns a sealed vault for a client restoring its identity.
//
// Payload: [str] user
// Reply:   [blob] salt | [4] memory | [4] passes | [4] lanes
//          | [4] generation | [blob] blob
func (c *client) handleGetVault(payload []byte) error {
	r := reader{buf: payload}

	userID, err := r.str()
	if err != nil {
		return err
	}
	if !r.done() {
		return errTruncated
	}

	record, err := c.hub.store.GetVault(userID)
	if err != nil {
		return err
	}
	if record == nil {
		// Not an error the client needs to see as one: "no vault" is the normal
		// state of a user that never set a password, and a client falls back to
		// creating a local identity.
		return errNoVault
	}

	// A vault fetch is the one pre-authentication read that could be used to probe
	// for which user ids exist. Rate-limiting it does not stop that - a patient
	// attacker enumerates anyway - but it stops a fast one, and the same limiter
	// the send path uses is already per connection.
	if !c.limit.allow() {
		c.hub.statRejected.Add(1)
		c.hub.log.Warn("vault read rate limited", "user", userID)
		return errRateLimited
	}

	var w writer
	w.blob(record.Salt)
	w.u32(record.MemoryKiB)
	w.u32(record.Passes)
	w.u32(record.Lanes)
	w.u32(record.Generation)
	w.blob(record.Blob)

	env, err := frame(typeVaultData, w.bytes())
	if err != nil {
		return err
	}
	c.enqueue(env)
	return nil
}

// handlePublishDevices stores an account's device list.
//
// The relay cannot verify any signature in here 鈥?it has no account key 鈥?and
// does not try. What it enforces is that the list is *whole*: a device id that
// does not appear in the new set is removed, and the version moves forward so a
// peer holding an older copy can tell it is stale.
//
// Payload: [str] user id | [4] count | per entry: [str] device id | [blob] credential
func (c *client) handlePublishDevices(payload []byte) error {
	if c.userID == "" {
		return errHelloFirst
	}

	r := reader{buf: payload}
	userID, err := r.str()
	if err != nil {
		return err
	}
	if userID != c.userID {
		// A connection speaks only for the id it authenticated as. Publishing a
		// list for somebody else would be the whole attack this design exists
		// to prevent, and there is no legitimate client that needs it.
		c.hub.log.Warn("device list for another account refused",
			"authenticated", c.userID, "claimed", userID)
		c.hub.statRejected.Add(1)
		return errForeignAccount
	}

	count, err := r.u32()
	if err != nil {
		return err
	}
	if count == 0 || count > 64 {
		return errBadDevices
	}

	credentials := make([][]byte, 0, count)
	deviceIDs := make([]string, 0, count)
	for i := uint32(0); i < count; i++ {
		deviceID, err := r.str()
		if err != nil {
			return err
		}
		credential, err := r.blob()
		if err != nil {
			return err
		}
		if deviceID == "" || len(deviceID) > 128 {
			return errBadDevices
		}
		if len(credential) == 0 || len(credential) > 1024 {
			return errBadDevices
		}

		// The credential's own encoding starts with a two-byte user id length
		// and the user id. Checking that it names the same account is cheap and
		// catches a client that assembled the list from the wrong peer's data;
		// the signature check the client does would catch it too, but failing
		// early keeps a broken list off the relay entirely.
		if !credentialNamesUser(credential, userID) {
			return errBadDevices
		}

		credentials = append(credentials, credential)
		deviceIDs = append(deviceIDs, deviceID)
	}
	if !r.done() {
		return errTruncated
	}

	version, err := c.hub.store.PublishDevices(userID, credentials, deviceIDs)
	if err != nil {
		return err
	}
	c.hub.log.Info("device list published", "user", userID, "version", version, "devices", count)
	return nil
}

// handleGetDevices serves an account's list to anybody who asks.
//
// A device list is public in the same sense a prekey bundle is: it has to be,
// or nobody could start a session with a stranger. The credentials inside it are
// signed, so a relay that tampered with them would be caught by the client.
//
// Payload: [str] user id
// Reply:   [4] version | [4] count | per entry: [str] device id | [blob] credential
func (c *client) handleGetDevices(payload []byte) error {
	if c.userID == "" {
		return errHelloFirst
	}

	r := reader{buf: payload}
	target, err := r.str()
	if err != nil {
		return err
	}
	if !r.done() {
		return errTruncated
	}

	devices, version, err := c.hub.store.Devices(target)
	if err != nil {
		return err
	}
	if len(devices) == 0 {
		return errNoBundle
	}

	var w writer
	w.u32(version)
	w.u32(uint32(len(devices)))
	for _, d := range devices {
		w.str(d.DeviceID)
		w.blob(d.Credential)
	}

	env, err := frame(typeDevices, w.bytes())
	if err != nil {
		return err
	}
	c.enqueue(env)
	return nil
}

// credentialNamesUser reads the account a credential claims, without parsing
// anything else. Layout: [2] length | user id | ...
func credentialNamesUser(credential []byte, userID string) bool {
	if len(credential) < 2 {
		return false
	}
	n := int(credential[0])<<8 | int(credential[1])
	if n <= 0 || len(credential) < 2+n {
		return false
	}
	return string(credential[2:2+n]) == userID
}

// handleHello issues a challenge instead of binding the user id outright.
//
// Registering an id used to be first-come-first-served: whoever sent HELLO
// first owned that id, and could publish prekeys of their own choosing under
// it. Requiring a signature over a relay-chosen nonce means an id can only be
// claimed by the holder of the matching identity signing key.
func (c *client) handleHello(payload []byte) error {
	if c.draining() {
		return errShuttingDown
	}
	if len(c.challenge) != 0 {
		// One challenge per connection. Issuing a second would let a client
		// grind solutions without paying for a new socket.
		return errAlreadyChallenged
	}

	r := reader{buf: payload}
	userID, err := r.str()
	if err != nil {
		return err
	}
	identity, err := r.blob()
	if err != nil {
		return err
	}

	// The device id is optional and comes last, so a client that predates
	// device addressing 鈥?or one whose account has never linked a second
	// device 鈥?sends the same bytes it always did. Checking `remaining` rather
	// than requiring the field is what keeps the old shape working.
	deviceID := ""
	if r.remaining() > 0 {
		deviceID, err = r.str()
		if err != nil {
			return err
		}
		if deviceID == "" || len(deviceID) > 128 {
			return errBadDeviceID
		}
	}

	if !r.done() {
		return errTruncated
	}
	if userID == "" || len(userID) > 128 {
		return errBadUserID
	}
	if len(identity) != 64 {
		return errBadIdentity
	}

	nonce := make([]byte, challengeSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	c.challenge = nonce
	c.challengeSeen = true
	c.pendingUserID = userID
	c.pendingDeviceID = deviceID
	c.pendingIdentity = append([]byte(nil), identity...)

	// Deadline is per-read; the client only has to beat authTimeout overall,
	// not per frame, because every frame of the handshake resets it.
	_ = c.conn.SetReadDeadline(time.Now().Add(authTimeout))

	var w writer
	w.blob(nonce)
	env, err := frame(typeAuthChallenge, w.bytes())
	if err != nil {
		return err
	}
	c.enqueue(env)
	return nil
}

// handleAuthResponse verifies the signature and only then binds the id.
func (c *client) handleAuthResponse(payload []byte) error {
	if len(c.challenge) == 0 {
		return errNoChallenge
	}

	r := reader{buf: payload}
	signature, err := r.blob()
	if err != nil {
		return err
	}
	if !r.done() {
		return errTruncated
	}
	if len(signature) != ed25519.SignatureSize {
		return errBadSignature
	}

	// The identity blob is DH public || signing public, so the verifying key
	// is the second half.
	verifyKey := ed25519.PublicKey(c.pendingIdentity[kKeyOffset:])
	if !ed25519.Verify(verifyKey, c.challenge, signature) {
		c.hub.log.Warn("identity proof failed", "user", c.pendingUserID)
		return errBadSignature
	}

	ok, err := c.hub.store.EnsureAccount(c.pendingUserID, c.pendingIdentity)
	if err != nil {
		return err
	}
	if !ok {
		c.hub.log.Warn("identity mismatch on hello", "user", c.pendingUserID)
		return errIdentityMismatch
	}

	// The nonce is single-use.
	c.challenge = nil
	c.authed = true
	c.userID = c.pendingUserID
	c.deviceID = c.pendingDeviceID
	c.pendingUserID = ""
	c.pendingDeviceID = ""
	c.pendingIdentity = nil

	c.hub.attach(c)
	c.hub.log.Info("connected", "user", c.userID, "device", c.deviceID)

	// HELLO_OK echoes the device id the relay bound, so a client can tell what
	// the relay thinks it is talking to rather than assuming.
	var w writer
	w.str(c.userID)
	w.str(c.deviceID)
	env, err := frame(typeHelloOK, w.bytes())
	if err != nil {
		return err
	}
	c.enqueue(env)

	// Anything queued while the peer was away goes out right away.
	c.flushCursor, _ = c.hub.flush(c, 0)
	return nil
}

func (c *client) handlePublishPreKeys(payload []byte) error {
	if c.userID == "" {
		return errHelloFirst
	}
	r := reader{buf: payload}
	signedID, err := r.u32()
	if err != nil {
		return err
	}
	signedPub, err := r.blob()
	if err != nil {
		return err
	}
	signature, err := r.blob()
	if err != nil {
		return err
	}
	oneTime, err := r.blob()
	if err != nil {
		return err
	}
	if !r.done() {
		return errTruncated
	}
	if len(signedPub) != 32 || len(signature) != 64 {
		return errBadPreKeys
	}
	// The relay hands out each one-time prekey exactly once, which means it
	// has to understand this one payload shape. Everything else it forwards
	// stays opaque.
	set, err := parseOneTimeSet(oneTime)
	if err != nil {
		return err
	}

	return c.hub.store.PublishPreKeys(c.userID, preKeyRow{
		SignedID:  signedID,
		SignedPub: signedPub,
		Signature: signature,
		OneTime:   set.encode(),
	})
}

func (c *client) handleGetBundle(payload []byte) error {
	if c.userID == "" {
		return errHelloFirst
	}
	r := reader{buf: payload}
	target, err := r.str()
	if err != nil {
		return err
	}
	if !r.done() {
		return errTruncated
	}

	identity, err := c.hub.store.Identity(target)
	if err != nil {
		return err
	}
	pk, err := c.hub.store.PreKeys(target)
	if err != nil {
		return err
	}
	if identity == nil || pk == nil {
		return errNoBundle
	}

	// A one-time prekey may only ever be handed out once, so the relay pops
	// the first entry and stores the remainder. This is public key material,
	// not message content, so parsing it does not weaken the zero-knowledge
	// property the relay holds over conversations.
	set, err := parseOneTimeSet(pk.OneTime)
	if err != nil {
		return err
	}
	otID, otPub := set.take()
	if otID != 0 {
		if err := c.hub.store.ReplaceOneTime(target, set.encode()); err != nil {
			return err
		}
	}

	var w writer
	w.str(target)
	w.blob(identity)
	w.u32(pk.SignedID)
	w.blob(pk.SignedPub)
	w.blob(pk.Signature)
	w.u32(otID)
	w.blob(otPub)

	env, err := frame(typeBundle, w.bytes())
	if err != nil {
		return err
	}
	c.enqueue(env)
	return nil
}

func (c *client) handleSend(payload []byte) error {
	if c.userID == "" {
		return errHelloFirst
	}
	r := reader{buf: payload}
	recipient, err := r.str()
	if err != nil {
		return err
	}
	body, err := r.blob()
	if err != nil {
		return err
	}

	// The target device is optional and comes last, so a frame from a client
	// that does not know the recipient's devices has exactly the shape it had
	// before. A SEND that names a device reaches only that device.
	deviceID := ""
	if r.remaining() > 0 {
		deviceID, err = r.str()
		if err != nil {
			return err
		}
		if len(deviceID) > 128 {
			return errBadDeviceID
		}
	}

	if !r.done() {
		return errTruncated
	}
	if recipient == "" {
		return errBadRecipient
	}
	if recipient == c.userID {
		return errSelfSend
	}
	if !c.limit.allow() {
		c.hub.statRejected.Add(1)
		c.hub.log.Warn("send rate limited", "user", c.userID, "recipient", recipient)
		return errRateLimited
	}

	_, err = c.hub.deliver(recipient, deviceID, c.userID, body)
	if err == nil {
		c.hub.statAccepted.Add(1)
	}
	return err
}

func (c *client) handleAck(payload []byte) error {
	if c.userID == "" {
		return errHelloFirst
	}
	r := reader{buf: payload}
	upTo, err := r.u64()
	if err != nil {
		return err
	}
	if !r.done() {
		return errTruncated
	}
	if err := c.hub.store.Acknowledge(c.userID, upTo); err != nil {
		return err
	}

	// An ACK is also the client saying "I have this page, send the next one".
	// Without this the replay stalled at a single page and everything behind
	// it waited for another reconnect.
	if c.morePending {
		cursor, err := c.hub.flush(c, upTo)
		if err != nil {
			return err
		}
		c.flushCursor = cursor
	}
	return nil
}
