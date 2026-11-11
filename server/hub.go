package main

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = maxPayload + envelopeHeaderSize
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// The relay is meant to sit behind a TLS terminator; the origin check
	// below keeps browser pages from opening a socket with a stolen cookie.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Hub tracks live connections and owns the fan-out.
type Hub struct {
	store  *Store
	log    *slog.Logger
	mu     sync.RWMutex
	byUser map[string]map[*client]struct{}
}

func NewHub(store *Store, log *slog.Logger) *Hub {
	return &Hub{
		store:  store,
		log:    log,
		byUser: make(map[string]map[*client]struct{}),
	}
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
//	[4] outbox id (0 for a live delivery) | [sender] | [body]
func (h *Hub) deliver(recipient, sender string, body []byte) (bool, error) {
	// The queued form is everything after the id, so the same bytes serve
	// both the live and the replay path.
	var stored writer
	stored.str(sender)
	stored.blob(body)

	targets := h.sessions(recipient)
	if len(targets) == 0 {
		return false, h.store.Enqueue(recipient, sender, stored.bytes())
	}

	var live writer
	live.u32(0)
	live.buf = append(live.buf, stored.bytes()...)
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
		return false, h.store.Enqueue(recipient, sender, stored.bytes())
	}
	return true, nil
}

// flush replays the outbox for a freshly connected client.
func (h *Hub) flush(c *client, afterID int64) (int64, error) {
	pending, err := h.store.Drain(c.userID, afterID, 200)
	if err != nil {
		return afterID, err
	}
	last := afterID
	for _, m := range pending {
		// m.Payload already carries sender|body; prepend the outbox id so
		// the client can acknowledge it.
		var w writer
		w.u32(uint32(m.ID))
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
	return last, nil
}

// newMux wires the relay routes. Kept separate from main so tests exercise
// exactly the same routing as production.
func newMux(h *Hub) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/ws", h)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Warn("upgrade failed", "err", err)
		return
	}

	c := &client{
		hub:    h,
		conn:   conn,
		send:   make(chan []byte, 256),
		closed: make(chan struct{}),
	}
	go c.writeLoop()
	c.readLoop()
}

// client is one websocket connection.
type client struct {
	hub  *Hub
	conn *websocket.Conn

	userID  string
	send    chan []byte
	closed  chan struct{}
	closeMu sync.Once
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
		_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))

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

func (c *client) handle(data []byte) error {
	msgType, payload, err := parseEnvelope(data)
	if err != nil {
		return err
	}

	switch msgType {
	case typeHello:
		return c.handleHello(payload)
	case typePublishPreKeys:
		return c.handlePublishPreKeys(payload)
	case typeGetBundle:
		return c.handleGetBundle(payload)
	case typeSend:
		return c.handleSend(payload)
	case typeAck:
		return c.handleAck(payload)
	default:
		return errUnknownType
	}
}

func (c *client) handleHello(payload []byte) error {
	r := reader{buf: payload}
	userID, err := r.str()
	if err != nil {
		return err
	}
	identity, err := r.blob()
	if err != nil {
		return err
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

	ok, err := c.hub.store.EnsureAccount(userID, identity)
	if err != nil {
		return err
	}
	if !ok {
		return errIdentityMismatch
	}

	c.userID = userID
	c.hub.attach(c)
	c.hub.log.Info("connected", "user", userID)

	var w writer
	w.str(userID)
	env, err := frame(typeHelloOK, w.bytes())
	if err != nil {
		return err
	}
	c.enqueue(env)

	// Anything queued while the peer was away goes out right away.
	_, _ = c.hub.flush(c, 0)
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
	if !r.done() {
		return errTruncated
	}
	if recipient == "" {
		return errBadRecipient
	}
	if recipient == c.userID {
		return errSelfSend
	}

	_, err = c.hub.deliver(recipient, c.userID, body)
	return err
}

func (c *client) handleAck(payload []byte) error {
	if c.userID == "" {
		return errHelloFirst
	}
	r := reader{buf: payload}
	upTo, err := r.u32()
	if err != nil {
		return err
	}
	if !r.done() {
		return errTruncated
	}
	return c.hub.store.Acknowledge(c.userID, int64(upTo))
}
