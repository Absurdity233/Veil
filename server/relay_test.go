package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ---- Harness -----------------------------------------------------------

type harness struct {
	store *Store
	srv   *httptest.Server
	wsURL string
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	store, err := OpenStore(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(newMux(NewHub(store, logger)))
	t.Cleanup(srv.Close)

	return &harness{
		store: store,
		srv:   srv,
		wsURL: "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws",
	}
}

// dial opens a connection and completes HELLO.
func (h *harness) dial(t *testing.T, userID string, identity []byte) *testClient {
	t.Helper()

	conn, _, err := websocket.DefaultDialer.Dial(h.wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	c := &testClient{t: t, conn: conn}
	var w writer
	w.str(userID)
	w.blob(identity)
	c.send(typeHello, w.bytes())

	if msgType, _ := c.recv(); msgType != typeHelloOK {
		t.Fatalf("expected hello ok, got %#x", msgType)
	}
	return c
}

// dialRaw opens a connection without sending HELLO.
func (h *harness) dialRaw(t *testing.T) *testClient {
	t.Helper()

	conn, _, err := websocket.DefaultDialer.Dial(h.wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &testClient{t: t, conn: conn}
}

type testClient struct {
	t    *testing.T
	conn *websocket.Conn
}

func (c *testClient) send(msgType byte, payload []byte) {
	c.t.Helper()
	env, err := frame(msgType, payload)
	if err != nil {
		c.t.Fatalf("frame: %v", err)
	}
	if err := c.conn.WriteMessage(websocket.BinaryMessage, env); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

func (c *testClient) recv() (byte, []byte) {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, data, err := c.conn.ReadMessage()
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	msgType, payload, err := parseEnvelope(data)
	if err != nil {
		c.t.Fatalf("parse envelope: %v", err)
	}
	return msgType, payload
}

// recvType reads until a message of the wanted type arrives.
func (c *testClient) recvType(want byte) []byte {
	c.t.Helper()
	for i := 0; i < 8; i++ {
		msgType, payload := c.recv()
		if msgType == want {
			return payload
		}
	}
	c.t.Fatalf("never received type %#x", want)
	return nil
}

func (c *testClient) expectType(want byte) []byte {
	c.t.Helper()
	msgType, payload := c.recv()
	if msgType != want {
		c.t.Fatalf("type = %#x, want %#x (payload %q)", msgType, want, payload)
	}
	return payload
}

func identity(seed byte) []byte {
	b := make([]byte, 64)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return b
}

// ---- Envelope ----------------------------------------------------------

func TestEnvelopeRoundTrip(t *testing.T) {
	payload := []byte("hello veil")
	env, err := frame(typeSend, payload)
	if err != nil {
		t.Fatalf("frame: %v", err)
	}
	msgType, got, err := parseEnvelope(env)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if msgType != typeSend {
		t.Fatalf("type = %#x, want %#x", msgType, typeSend)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestEnvelopeRejectsMalformed(t *testing.T) {
	if _, _, err := parseEnvelope([]byte{1, 2}); err == nil {
		t.Fatal("short frame accepted")
	}

	env, _ := frame(typeSend, []byte("abc"))
	if _, _, err := parseEnvelope(env[:len(env)-1]); err == nil {
		t.Fatal("truncated frame accepted")
	}

	bad := append([]byte{}, env...)
	bad[0] = 9
	if _, _, err := parseEnvelope(bad); err == nil {
		t.Fatal("wrong version accepted")
	}
}

// ---- Field codec -------------------------------------------------------

func TestFieldCodecRoundTrip(t *testing.T) {
	var w writer
	w.u32(0xDEADBEEF)
	w.str("alice")
	w.blob([]byte{1, 2, 3})

	r := reader{buf: w.bytes()}
	v, err := r.u32()
	if err != nil || v != 0xDEADBEEF {
		t.Fatalf("u32 = %#x, %v", v, err)
	}
	s, err := r.str()
	if err != nil || s != "alice" {
		t.Fatalf("str = %q, %v", s, err)
	}
	b, err := r.blob()
	if err != nil || !bytes.Equal(b, []byte{1, 2, 3}) {
		t.Fatalf("blob = %v, %v", b, err)
	}
	if !r.done() {
		t.Fatal("reader not exhausted")
	}
}

func TestFieldCodecRejectsTruncation(t *testing.T) {
	var w writer
	w.str("alice")
	r := reader{buf: w.bytes()[:3]}
	if _, err := r.str(); err == nil {
		t.Fatal("truncated string accepted")
	}
}

// ---- Handshake ---------------------------------------------------------

func TestHelloBindsIdentity(t *testing.T) {
	h := newHarness(t)
	h.dial(t, "alice", identity(1))

	// Same user id, different identity: must be refused.
	c := h.dialRaw(t)
	var w writer
	w.str("alice")
	w.blob(identity(99))
	c.send(typeHello, w.bytes())

	payload := c.expectType(typeError)
	if !strings.Contains(string(payload), "identity") {
		t.Fatalf("unexpected error payload: %q", payload)
	}
}

func TestHelloRejectsShortIdentity(t *testing.T) {
	h := newHarness(t)
	c := h.dialRaw(t)

	var w writer
	w.str("alice")
	w.blob([]byte{1, 2, 3})
	c.send(typeHello, w.bytes())

	c.expectType(typeError)
}

func TestHelloRequiredBeforeSend(t *testing.T) {
	h := newHarness(t)
	c := h.dialRaw(t)

	var w writer
	w.str("bob")
	w.blob([]byte("hi"))
	c.send(typeSend, w.bytes())

	payload := c.expectType(typeError)
	if !strings.Contains(string(payload), "HELLO") {
		t.Fatalf("unexpected payload: %q", payload)
	}
}

// ---- Prekeys -----------------------------------------------------------

func TestPreKeyPublishAndFetch(t *testing.T) {
	h := newHarness(t)
	bob := h.dial(t, "bob", identity(2))
	alice := h.dial(t, "alice", identity(3))

	// Two one-time entries, in the client's own encoding:
	//   [4] count, then per entry [4] id | [32] public
	var set writer
	set.u32(2)
	set.u32(0x1001)
	set.raw(bytes.Repeat([]byte{0x22}, 32))
	set.u32(0x1002)
	set.raw(bytes.Repeat([]byte{0x33}, 32))

	var w writer
	w.u32(7)
	w.blob(bytes.Repeat([]byte{0xAA}, 32))
	w.blob(bytes.Repeat([]byte{0xBB}, 64))
	w.blob(set.bytes())
	bob.send(typePublishPreKeys, w.bytes())

	// The publish is processed on the reader goroutine, so poll for it.
	waitFor(t, 2*time.Second, func() bool {
		pk, err := h.store.PreKeys("bob")
		return err == nil && pk != nil
	})

	var q writer
	q.str("bob")
	alice.send(typeGetBundle, q.bytes())

	payload := alice.recvType(typeBundle)
	r := reader{buf: payload}

	gotUser, err := r.str()
	if err != nil || gotUser != "bob" {
		t.Fatalf("user = %q, %v", gotUser, err)
	}
	id, _ := r.blob()
	if !bytes.Equal(id, identity(2)) {
		t.Fatal("identity mismatch in bundle")
	}
	signedID, _ := r.u32()
	if signedID != 7 {
		t.Fatalf("signed id = %d, want 7", signedID)
	}
	signedPub, _ := r.blob()
	if !bytes.Equal(signedPub, bytes.Repeat([]byte{0xAA}, 32)) {
		t.Fatal("signed prekey mismatch")
	}

	_, _ = r.blob() // signature
	otID, _ := r.u32()
	if otID != 0x1001 {
		t.Fatalf("one-time id = %#x, want the first entry", otID)
	}
	otPub, _ := r.blob()
	if !bytes.Equal(otPub, bytes.Repeat([]byte{0x22}, 32)) {
		t.Fatal("one-time prekey mismatch")
	}

	// A second fetch must hand out the next one-time prekey, never the same
	// one twice.
	alice.send(typeGetBundle, q.bytes())
	payload = alice.recvType(typeBundle)
	r = reader{buf: payload}
	_, _ = r.str()
	_, _ = r.blob()
	_, _ = r.u32()
	_, _ = r.blob()
	_, _ = r.blob()
	otID2, _ := r.u32()
	if otID2 != 0x1002 {
		t.Fatalf("second fetch got one-time id %#x, want 0x1002", otID2)
	}

	// And a third fetch must succeed with no one-time prekey at all.
	alice.send(typeGetBundle, q.bytes())
	payload = alice.recvType(typeBundle)
	r = reader{buf: payload}
	_, _ = r.str()
	_, _ = r.blob()
	_, _ = r.u32()
	_, _ = r.blob()
	_, _ = r.blob()
	otID3, _ := r.u32()
	if otID3 != 0 {
		t.Fatalf("third fetch got one-time id %#x, want 0", otID3)
	}
}

func TestBundleMissing(t *testing.T) {
	h := newHarness(t)
	alice := h.dial(t, "alice", identity(4))

	var w writer
	w.str("nobody")
	alice.send(typeGetBundle, w.bytes())

	alice.expectType(typeError)
}

// ---- Delivery ----------------------------------------------------------

func TestDeliverOnline(t *testing.T) {
	h := newHarness(t)
	alice := h.dial(t, "alice", identity(10))
	bob := h.dial(t, "bob", identity(11))

	var w writer
	w.str("bob")
	w.blob([]byte("ciphertext-for-bob"))
	alice.send(typeSend, w.bytes())

	payload := bob.recvType(typeDeliver)
	r := reader{buf: payload}
	id, err := r.u32()
	if err != nil || id != 0 {
		t.Fatalf("outbox id = %d, %v (want 0 for a live delivery)", id, err)
	}
	sender, err := r.str()
	if err != nil || sender != "alice" {
		t.Fatalf("sender = %q, %v", sender, err)
	}
	body, _ := r.blob()
	if string(body) != "ciphertext-for-bob" {
		t.Fatalf("body = %q", body)
	}
}

func TestDeliverOfflineThenFlush(t *testing.T) {
	h := newHarness(t)
	alice := h.dial(t, "alice", identity(20))

	// Bob is not connected, so the message is queued.
	var w writer
	w.str("bob")
	w.blob([]byte("queued"))
	alice.send(typeSend, w.bytes())

	waitFor(t, 2*time.Second, func() bool {
		n, err := h.store.PendingCount()
		return err == nil && n == 1
	})

	// Bob connects and must receive the backlog without asking.
	bob := h.dial(t, "bob", identity(21))

	payload := bob.recvType(typeDeliver)
	r := reader{buf: payload}
	if _, err := r.u32(); err != nil { // outbox id
		t.Fatalf("id: %v", err)
	}
	sender, _ := r.str()
	if sender != "alice" {
		t.Fatalf("sender = %q", sender)
	}
	body, _ := r.blob()
	if string(body) != "queued" {
		t.Fatalf("body = %q", body)
	}
}

func TestAckDrainsOutbox(t *testing.T) {
	h := newHarness(t)
	alice := h.dial(t, "alice", identity(30))

	var w writer
	w.str("bob")
	w.blob([]byte("one"))
	alice.send(typeSend, w.bytes())

	waitFor(t, 2*time.Second, func() bool {
		n, err := h.store.PendingCount()
		return err == nil && n == 1
	})

	bob := h.dial(t, "bob", identity(31))
	bob.recvType(typeDeliver)

	var a writer
	a.u32(1) // acknowledge everything up to id 1
	bob.send(typeAck, a.bytes())

	waitFor(t, 2*time.Second, func() bool {
		n, err := h.store.PendingCount()
		return err == nil && n == 0
	})
}

func TestSelfSendRejected(t *testing.T) {
	h := newHarness(t)
	alice := h.dial(t, "alice", identity(40))

	var w writer
	w.str("alice")
	w.blob([]byte("echo"))
	alice.send(typeSend, w.bytes())

	alice.expectType(typeError)
}

func TestUnknownTypeRejected(t *testing.T) {
	h := newHarness(t)
	alice := h.dial(t, "alice", identity(50))

	alice.send(0x7F, []byte("nope"))
	alice.expectType(typeError)
}

// ---- Store -------------------------------------------------------------

func TestOutboxOrdering(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/order.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	for i := 0; i < 5; i++ {
		if err := store.Enqueue("bob", "alice", []byte{byte(i)}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	got, err := store.Drain("bob", 0, 100)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("drained %d, want 5", len(got))
	}
	for i, m := range got {
		if m.Payload[0] != byte(i) {
			t.Fatalf("message %d has payload %d", i, m.Payload[0])
		}
	}

	// Draining after the third id must return only the remainder.
	rest, err := store.Drain("bob", got[2].ID, 100)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(rest) != 2 {
		t.Fatalf("drained %d after cursor, want 2", len(rest))
	}
}

func TestAcknowledgeIsScopedToRecipient(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/ack.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	_ = store.Enqueue("bob", "alice", []byte("b1"))
	_ = store.Enqueue("carol", "alice", []byte("c1"))

	if err := store.Acknowledge("bob", 100); err != nil {
		t.Fatalf("ack: %v", err)
	}

	if n, _ := store.PendingCount(); n != 1 {
		t.Fatalf("pending = %d, want 1 (carol's message must survive)", n)
	}
}

// ---- Health ------------------------------------------------------------

func TestHealthEndpoint(t *testing.T) {
	h := newHarness(t)

	resp, err := http.Get(h.srv.URL + "/health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// ---- Helpers -----------------------------------------------------------

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
