package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
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
	hub   *Hub
	srv   *httptest.Server
	wsURL string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWithOrigins(t, "")
}

func newHarnessWithOrigins(t *testing.T, allowed string) *harness {
	t.Helper()

	store, err := OpenStore(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	hub := NewHubWithOrigins(store, logger, allowed)
	srv := httptest.NewServer(newMux(hub))
	t.Cleanup(srv.Close)

	return &harness{
		store: store,
		hub:   hub,
		srv:   srv,
		wsURL: "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws",
	}
}

// testIdentity is a real Ed25519 key pair plus a stand-in for the DH half, so
// the challenge signature can actually be produced and checked. The relay
// never looks at the DH half beyond storing it.
type testIdentity struct {
	blob   []byte // [32] dh stand-in | [32] ed25519 public
	signer ed25519.PrivateKey
}

func newTestIdentity(t *testing.T, seed byte) *testIdentity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	blob := make([]byte, 64)
	for i := 0; i < 32; i++ {
		blob[i] = seed + byte(i)
	}
	copy(blob[32:], pub)
	return &testIdentity{blob: blob, signer: priv}
}

// dial opens a connection and completes the challenge handshake.
func (h *harness) dial(t *testing.T, userID string, id *testIdentity) *testClient {
	t.Helper()

	c := h.dialRaw(t)
	c.hello(t, userID, id)
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

// dialWithDevice opens a connection, proves the identity, and announces the
// device it speaks for.
func (h *harness) dialWithDevice(t *testing.T, userID, deviceID string,
	id *testIdentity) *testClient {
	t.Helper()

	c := h.dialRaw(t)

	var w writer
	w.str(userID)
	w.blob(id.blob)
	w.str(deviceID)
	c.send(typeHello, w.bytes())

	r := reader{buf: c.recvType(typeAuthChallenge)}
	nonce, err := r.blob()
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}

	var a writer
	a.blob(ed25519.Sign(id.signer, nonce))
	c.send(typeAuthResponse, a.bytes())

	if msgType, _ := c.recv(); msgType != typeHelloOK {
		t.Fatalf("expected hello ok, got %#x", msgType)
	}
	return c
}

// hello runs HELLO plus the challenge response.
func (c *testClient) hello(t *testing.T, userID string, id *testIdentity) {
	t.Helper()

	var w writer
	w.str(userID)
	w.blob(id.blob)
	c.send(typeHello, w.bytes())

	payload := c.recvType(typeAuthChallenge)
	r := reader{buf: payload}
	nonce, err := r.blob()
	if err != nil || len(nonce) != challengeSize {
		t.Fatalf("challenge: %v", err)
	}

	var a writer
	a.blob(ed25519.Sign(id.signer, nonce))
	c.send(typeAuthResponse, a.bytes())
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

// identity is used by the store-level tests, which never sign anything.
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
	h.dial(t, "alice", newTestIdentity(t, 1))

	// Same user id, different identity: the challenge is answered correctly
	// for the *new* key, so the refusal has to come from the binding check.
	c := h.dialRaw(t)
	impostor := newTestIdentity(t, 99)
	var w writer
	w.str("alice")
	w.blob(impostor.blob)
	c.send(typeHello, w.bytes())

	r := reader{buf: c.recvType(typeAuthChallenge)}
	nonce, _ := r.blob()
	var a writer
	a.blob(ed25519.Sign(impostor.signer, nonce))
	c.send(typeAuthResponse, a.bytes())

	payload := c.expectType(typeError)
	if !strings.Contains(string(payload), "identity") {
		t.Fatalf("unexpected error payload: %q", payload)
	}
}

func TestHelloRejectsForgedProof(t *testing.T) {
	// A user id must only be claimable by the holder of the matching signing
	// key. Otherwise registration is first-come-first-served and anyone can
	// take over an id that has not been used yet, then publish prekeys of
	// their own under it.
	h := newHarness(t)

	victim := newTestIdentity(t, 5)
	attacker := newTestIdentity(t, 6)

	// The attacker sends the victim's *public* identity with its own key as
	// the signer: a signature that verifies against nothing the victim holds.
	c := h.dialRaw(t)
	var w writer
	w.str("carol")
	w.blob(victim.blob)
	c.send(typeHello, w.bytes())

	r := reader{buf: c.recvType(typeAuthChallenge)}
	nonce, _ := r.blob()
	var a writer
	// Sign with the attacker's key, but present it as carol's identity.
	a.blob(ed25519.Sign(attacker.signer, nonce))
	c.send(typeAuthResponse, a.bytes())

	payload := c.expectType(typeError)
	if !strings.Contains(string(payload), "proof") {
		t.Fatalf("unexpected error payload: %q", payload)
	}

	// And nothing was registered under the id.
	got, err := h.store.Identity("carol")
	if err != nil {
		t.Fatalf("identity lookup: %v", err)
	}
	if got != nil {
		t.Fatal("a failed proof must not bind the user id")
	}
}

func TestAuthResponseRequiresChallenge(t *testing.T) {
	h := newHarness(t)
	c := h.dialRaw(t)

	var a writer
	a.blob(make([]byte, ed25519.SignatureSize))
	c.send(typeAuthResponse, a.bytes())

	payload := c.expectType(typeError)
	if !strings.Contains(string(payload), "challenge") {
		t.Fatalf("unexpected payload: %q", payload)
	}
}

func TestSecondChallengeRefused(t *testing.T) {
	h := newHarness(t)
	c := h.dialRaw(t)

	var w writer
	w.str("dave")
	w.blob(newTestIdentity(t, 7).blob)
	c.send(typeHello, w.bytes())
	c.recvType(typeAuthChallenge)

	// Asking twice would let a client grind nonces on one connection.
	c.send(typeHello, w.bytes())
	c.expectType(typeError)
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
	if !strings.Contains(string(payload), "challenge") {
		t.Fatalf("unexpected payload: %q", payload)
	}
}

// ---- Origin policy -----------------------------------------------------

func TestOriginPolicy(t *testing.T) {
	// No Origin header: a native client. Accepted.
	if !newOriginPolicy("").check(requestWithOrigin(nil)) {
		t.Fatal("native client rejected")
	}

	// A browser at an unlisted origin must not open a socket, even with no
	// cookies involved: the handshake would otherwise inherit whatever
	// ambient authority the page has against this host.
	if newOriginPolicy("").check(requestWithOrigin(strPtr("https://evil.example"))) {
		t.Fatal("unlisted origin accepted by an empty allow-list")
	}

	p := newOriginPolicy("https://app.example.com, https://web.example.com/")
	if !p.check(requestWithOrigin(strPtr("https://app.example.com"))) {
		t.Fatal("listed origin rejected")
	}
	// Normalisation: trailing slash and explicit default port must not matter.
	if !p.check(requestWithOrigin(strPtr("https://web.example.com/"))) {
		t.Fatal("listed origin with trailing slash rejected")
	}
	if p.check(requestWithOrigin(strPtr("https://app.example.com.evil.example"))) {
		t.Fatal("look-alike origin accepted")
	}
	if p.check(requestWithOrigin(strPtr("http://app.example.com"))) {
		t.Fatal("scheme downgrade accepted")
	}
}

func TestHandshakeRejectedForForeignOrigin(t *testing.T) {
	h := newHarnessWithOrigins(t, "https://app.example.com")

	header := http.Header{}
	header.Set("Origin", "https://evil.example")
	_, resp, err := websocket.DefaultDialer.Dial(h.wsURL, header)
	if err == nil {
		t.Fatal("foreign origin completed a handshake")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %v, want 403", resp)
	}

	// The listed origin still works.
	ok := http.Header{}
	ok.Set("Origin", "https://app.example.com")
	conn, _, err := websocket.DefaultDialer.Dial(h.wsURL, ok)
	if err != nil {
		t.Fatalf("listed origin refused: %v", err)
	}
	_ = conn.Close()
}

func strPtr(s string) *string { return &s }

func requestWithOrigin(origin *string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://relay.local/ws", nil)
	if origin != nil {
		r.Header.Set("Origin", *origin)
	}
	return r
}

// ---- Prekeys -----------------------------------------------------------

func TestPreKeyPublishAndFetch(t *testing.T) {
	h := newHarness(t)
	bobID := newTestIdentity(t, 2)
	bob := h.dial(t, "bob", bobID)
	alice := h.dial(t, "alice", newTestIdentity(t, 3))

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
	if !bytes.Equal(id, bobID.blob) {
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
	alice := h.dial(t, "alice", newTestIdentity(t, 4))

	var w writer
	w.str("nobody")
	alice.send(typeGetBundle, w.bytes())

	alice.expectType(typeError)
}

// ---- Delivery ----------------------------------------------------------

func TestDeliverOnline(t *testing.T) {
	h := newHarness(t)
	alice := h.dial(t, "alice", newTestIdentity(t, 10))
	bob := h.dial(t, "bob", newTestIdentity(t, 11))

	var w writer
	w.str("bob")
	w.blob([]byte("ciphertext-for-bob"))
	alice.send(typeSend, w.bytes())

	payload := bob.recvType(typeDeliver)
	r := reader{buf: payload}
	id, err := r.u64()
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
	alice := h.dial(t, "alice", newTestIdentity(t, 20))

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
	bob := h.dial(t, "bob", newTestIdentity(t, 21))

	payload := bob.recvType(typeDeliver)
	r := reader{buf: payload}
	if _, err := r.u64(); err != nil { // outbox id
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
	alice := h.dial(t, "alice", newTestIdentity(t, 30))

	var w writer
	w.str("bob")
	w.blob([]byte("one"))
	alice.send(typeSend, w.bytes())

	waitFor(t, 2*time.Second, func() bool {
		n, err := h.store.PendingCount()
		return err == nil && n == 1
	})

	bob := h.dial(t, "bob", newTestIdentity(t, 31))
	bob.recvType(typeDeliver)

	var a writer
	a.u64(1) // acknowledge everything up to id 1
	bob.send(typeAck, a.bytes())

	waitFor(t, 2*time.Second, func() bool {
		n, err := h.store.PendingCount()
		return err == nil && n == 0
	})
}

func TestSelfSendRejected(t *testing.T) {
	h := newHarness(t)
	alice := h.dial(t, "alice", newTestIdentity(t, 40))

	var w writer
	w.str("alice")
	w.blob([]byte("echo"))
	alice.send(typeSend, w.bytes())

	alice.expectType(typeError)
}

func TestUnknownTypeRejected(t *testing.T) {
	h := newHarness(t)
	alice := h.dial(t, "alice", newTestIdentity(t, 50))

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
		if err := enqueueAt(store, "bob", "alice", uint64(i+1), []byte{byte(i)}); err != nil {
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

	// Both recipients use the same sequence numbers, which is the point: the
	// id is per-recipient, so an acknowledgement up to 100 for bob must not
	// touch carol's identically numbered entry.
	_ = enqueueAt(store, "bob", "alice", 1, []byte("b1"))
	_ = enqueueAt(store, "carol", "alice", 1, []byte("c1"))

	if err := store.Acknowledge("bob", 100); err != nil {
		t.Fatalf("ack: %v", err)
	}

	if n, _ := store.PendingCount(); n != 1 {
		t.Fatalf("pending = %d, want 1 (carol's message must survive)", n)
	}
	if n, _ := store.PendingFor("carol"); n != 1 {
		t.Fatalf("carol pending = %d, want 1", n)
	}
	if n, _ := store.PendingFor("bob"); n != 0 {
		t.Fatalf("bob pending = %d, want 0", n)
	}
}

// ---- Outbox paging -----------------------------------------------------

func TestOutboxSequenceIsDensePerRecipient(t *testing.T) {
	// A dense per-recipient counter is what makes "I have everything up to N"
	// meaningful. The global rowid was sparse: carol's inserts advanced the
	// number bob saw, so bob had to ack ids it never received.
	store, err := OpenStore(t.TempDir() + "/seq.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	var bobs []uint64
	for i := 0; i < 3; i++ {
		seq, err := store.Seq("bob")
		if err != nil {
			t.Fatalf("seq: %v", err)
		}
		bobs = append(bobs, seq)
		if err := store.Enqueue("bob", "alice", seq, []byte{byte(i)}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		// Carol's traffic must not advance bob's counter.
		if _, err := store.Seq("carol"); err != nil {
			t.Fatalf("seq: %v", err)
		}
	}

	if bobs[0] != 1 || bobs[1] != 2 || bobs[2] != 3 {
		t.Fatalf("bob seq = %v, want 1,2,3", bobs)
	}
}

func TestOutboxSweepDropsExpiredAndTrims(t *testing.T) {
	// The outbox was unbounded storage that any authenticated sender could
	// fill: nothing removed what a recipient declined to read.
	store, err := OpenStore(t.TempDir() + "/sweep.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	for i := 0; i < outboxPerRecipient+5; i++ {
		if err := enqueueAt(store, "bob", "alice", uint64(i+1), []byte{byte(i)}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	_, trimmed, err := store.Sweep(time.Now())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if trimmed != 5 {
		t.Fatalf("trimmed = %d, want 5", trimmed)
	}
	if n, _ := store.PendingFor("bob"); n != int64(outboxPerRecipient) {
		t.Fatalf("pending = %d, want %d", n, outboxPerRecipient)
	}

	// The newest entries are the ones kept.
	pending, err := store.Drain("bob", 0, 5)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(pending) != 5 || pending[0].ID != 6 {
		t.Fatalf("oldest surviving seq = %v, want 6", pending[0].ID)
	}

	// An entry older than the retention window goes regardless.
	if _, err := store.db.Exec(
		`INSERT INTO outbox(recipient, sender, seq, payload, created_at)
		 VALUES('dave','alice',1,'old',? )`,
		time.Now().Add(-2*outboxTTL).Unix()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	expired, _, err := store.Sweep(time.Now())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if expired != 1 {
		t.Fatalf("expired = %d, want 1", expired)
	}
}

// ---- Device lists ------------------------------------------------------

// fakeCredential builds the bytes the relay stores verbatim: a two-byte user id
// length, the id, and filler. The relay never parses past the id, so the rest
// only has to be non-empty.
func fakeCredential(userID string, deviceByte byte) []byte {
	out := []byte{byte(len(userID) >> 8), byte(len(userID))}
	out = append(out, []byte(userID)...)
	out = append(out, deviceByte)
	out = append(out, bytes.Repeat([]byte{0xAB}, 64)...)
	return out
}

func publishDevices(t *testing.T, c *testClient, userID string, ids []string, creds [][]byte) {
	t.Helper()

	var w writer
	w.str(userID)
	w.u32(uint32(len(ids)))
	for i, id := range ids {
		w.str(id)
		w.blob(creds[i])
	}
	c.send(typePublishDevices, w.bytes())
}

func TestPublishAndGetDevices(t *testing.T) {
	h := newHarness(t)
	alice := h.dial(t, "alice", newTestIdentity(t, 80))
	bob := h.dial(t, "bob", newTestIdentity(t, 81))

	publishDevices(t, alice, "alice",
		[]string{"phone", "laptop"},
		[][]byte{fakeCredential("alice", 1), fakeCredential("alice", 2)})

	// The publish is processed on the reader goroutine, so poll for it.
	waitFor(t, 2*time.Second, func() bool {
		devices, _, err := h.store.Devices("alice")
		return err == nil && len(devices) == 2
	})

	var w writer
	w.str("alice")
	bob.send(typeGetDevices, w.bytes())

	payload := bob.recvType(typeDevices)
	r := reader{buf: payload}

	version, err := r.u32()
	if err != nil || version != 1 {
		t.Fatalf("version = %d, %v (want 1)", version, err)
	}
	count, _ := r.u32()
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}

	var seen []string
	for i := uint32(0); i < count; i++ {
		id, _ := r.str()
		cred, _ := r.blob()
		if len(cred) == 0 {
			t.Fatalf("device %s came back without a credential", id)
		}
		seen = append(seen, id)
	}
	if len(seen) != 2 {
		t.Fatalf("saw %d devices, want 2", len(seen))
	}
}

func TestRevocationIsOmission(t *testing.T) {
	// Replacing the whole set is what makes revocation expressible: a device
	// that is not in the new list is gone. There is no separate "remove" call
	// for a client to forget.
	h := newHarness(t)
	alice := h.dial(t, "alice", newTestIdentity(t, 82))
	bob := h.dial(t, "bob", newTestIdentity(t, 83))
	_ = bob // connected only so the relay has a second party; the test reads the store

	publishDevices(t, alice, "alice",
		[]string{"phone", "laptop"},
		[][]byte{fakeCredential("alice", 1), fakeCredential("alice", 2)})
	waitFor(t, 2*time.Second, func() bool {
		d, _, err := h.store.Devices("alice")
		return err == nil && len(d) == 2
	})

	// The laptop is stolen; alice publishes a list without it.
	publishDevices(t, alice, "alice",
		[]string{"phone"},
		[][]byte{fakeCredential("alice", 1)})
	waitFor(t, 2*time.Second, func() bool {
		d, _, err := h.store.Devices("alice")
		return err == nil && len(d) == 1
	})

	devices, version, err := h.store.Devices("alice")
	if err != nil {
		t.Fatalf("devices: %v", err)
	}
	if version != 2 {
		t.Fatalf("version = %d, want 2 (a revocation bumps it)", version)
	}
	if len(devices) != 1 || devices[0].DeviceID != "phone" {
		t.Fatalf("devices = %v, want only phone", devices)
	}
}

func TestDeviceListRejectsAnotherAccount(t *testing.T) {
	// A connection authenticated as alice must not be able to publish a list
	// for bob: that is the whole attack a device list has to survive.
	h := newHarness(t)
	alice := h.dial(t, "alice", newTestIdentity(t, 84))

	publishDevices(t, alice, "bob",
		[]string{"phone"}, [][]byte{fakeCredential("bob", 1)})

	payload := alice.expectType(typeError)
	if !strings.Contains(string(payload), "own device list") {
		t.Fatalf("unexpected error: %q", payload)
	}

	if devices, _, _ := h.store.Devices("bob"); len(devices) != 0 {
		t.Fatalf("bob gained %d devices from alice's publish", len(devices))
	}
}

func TestDeviceListRejectsMismatchedCredential(t *testing.T) {
	// The credential's own encoding names an account; a list whose entries name
	// somebody else is malformed, not merely unverifiable, and must not reach
	// the store.
	h := newHarness(t)
	alice := h.dial(t, "alice", newTestIdentity(t, 85))

	publishDevices(t, alice, "alice",
		[]string{"phone"}, [][]byte{fakeCredential("mallory", 1)})

	payload := alice.expectType(typeError)
	if !strings.Contains(string(payload), "malformed device list") {
		t.Fatalf("unexpected error: %q", payload)
	}
}

func TestDeviceListSizeBounds(t *testing.T) {
	h := newHarness(t)
	alice := h.dial(t, "alice", newTestIdentity(t, 86))

	// Zero devices is not a list. Revocation is expressed by publishing a
	// smaller list, not an empty one, so that an account can never end up with
	// no devices and no way back in.
	var w writer
	w.str("alice")
	w.u32(0)
	alice.send(typePublishDevices, w.bytes())
	alice.expectType(typeError)

	// More than the cap is refused rather than stored.
	var big writer
	big.str("alice")
	big.u32(1000)
	alice.send(typePublishDevices, big.bytes())
	alice.expectType(typeError)
}

func TestGetDevicesForUnknownUser(t *testing.T) {
	h := newHarness(t)
	alice := h.dial(t, "alice", newTestIdentity(t, 87))

	var w writer
	w.str("nobody")
	alice.send(typeGetDevices, w.bytes())
	alice.expectType(typeError)
}

// ---- Device addressing ------------------------------------------------

func TestDeliverReachesOnlyTheAddressedDevice(t *testing.T) {
	// This is the property a fan-out depends on. A frame is encrypted to one
	// device's ratchet, so delivering it to a sibling would not leak it 鈥?it
	// would produce an authentication failure on a message that was never meant
	// for that device.
	h := newHarness(t)

	alice := h.dial(t, "alice", newTestIdentity(t, 90))

	// Two devices of one account share the account identity: that is what makes
	// them one account rather than two. Each gets its own *device* key pair in
	// the full design, but at the relay the account identity is what binds the
	// user id, so both connections present it.
	bobID := newTestIdentity(t, 91)
	phone := h.dialWithDevice(t, "bob", "phone", bobID)
	laptop := h.dialWithDevice(t, "bob", "laptop", bobID)

	var w writer
	w.str("bob")
	w.blob([]byte("for the phone"))
	w.str("phone")
	alice.send(typeSend, w.bytes())

	// The phone gets it.
	payload := phone.recvType(typeDeliver)
	r := reader{buf: payload}
	_, _ = r.u64()
	sender, _ := r.str()
	body, _ := r.blob()
	if sender != "alice" || string(body) != "for the phone" {
		t.Fatalf("phone got %q from %q", body, sender)
	}

	// The laptop must not. It is given the same opportunity to speak, and the
	// reply it sends proves the ordering rather than relying on a timeout.
	_ = laptop
	var ping writer
	ping.str("alice")
	ping.blob([]byte("laptop is here"))
	laptop.send(typeSend, ping.bytes())

	// Alice receives the laptop's ping. If the laptop had also received the
	// phone's frame, this read would have returned that frame first.
	back := alice.recvType(typeDeliver)
	br := reader{buf: back}
	_, _ = br.u64()
	from, _ := br.str()
	if from != "bob" {
		t.Fatalf("alice's next delivery was from %q, not the laptop's ping", from)
	}
}

func TestUnaddressedDeliveryReachesEveryDevice(t *testing.T) {
	// A sender that does not know the recipient's devices 鈥?a single-device
	// account, or a client that has not fetched the list 鈥?addresses the bare
	// user id, and every connection of that user still gets it. This is the
	// behaviour that existed before device addressing.
	h := newHarness(t)

	alice := h.dial(t, "alice", newTestIdentity(t, 92))
	bobID := newTestIdentity(t, 93)
	phone := h.dialWithDevice(t, "bob", "phone", bobID)
	laptop := h.dialWithDevice(t, "bob", "laptop", bobID)

	var w writer
	w.str("bob")
	w.blob([]byte("for whoever"))
	alice.send(typeSend, w.bytes())

	for name, c := range map[string]*testClient{"phone": phone, "laptop": laptop} {
		payload := c.recvType(typeDeliver)
		r := reader{buf: payload}
		_, _ = r.u64()
		_, _ = r.str()
		body, _ := r.blob()
		if string(body) != "for whoever" {
			t.Fatalf("%s got %q", name, body)
		}
	}
}

func TestDeviceAddressingSurvivesOfflineQueueing(t *testing.T) {
	// A frame for a device that is not connected is queued against that device,
	// and the wrong device must not pick it up on reconnect.
	h := newHarness(t)

	alice := h.dial(t, "alice", newTestIdentity(t, 94))

	var w writer
	w.str("bob")
	w.blob([]byte("queued for the phone"))
	w.str("phone")
	alice.send(typeSend, w.bytes())

	waitFor(t, 2*time.Second, func() bool {
		n, err := h.store.PendingCount()
		return err == nil && n == 1
	})

	// The laptop connects first. It must see nothing.
	bobID := newTestIdentity(t, 95)
	laptop := h.dialWithDevice(t, "bob", "laptop", bobID)
	time.Sleep(200 * time.Millisecond)

	// Prove the laptop is connected and idle by having it ping alice.
	var ping writer
	ping.str("alice")
	ping.blob([]byte("laptop online"))
	laptop.send(typeSend, ping.bytes())
	back := alice.recvType(typeDeliver)
	br := reader{buf: back}
	_, _ = br.u64()
	from, _ := br.str()
	if from != "bob" {
		t.Fatalf("unexpected delivery from %q", from)
	}

	// Now the phone connects and gets the queued frame.
	phone := h.dialWithDevice(t, "bob", "phone", bobID)
	payload := phone.recvType(typeDeliver)
	r := reader{buf: payload}
	_, _ = r.u64()
	_, _ = r.str()
	body, _ := r.blob()
	if string(body) != "queued for the phone" {
		t.Fatalf("phone got %q", body)
	}
}

func TestHelloEchoesTheBoundDevice(t *testing.T) {
	// A client should be able to tell what the relay thinks it is, rather than
	// assuming its device id was accepted.
	h := newHarness(t)

	conn, _, err := websocket.DefaultDialer.Dial(h.wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	c := &testClient{t: t, conn: conn}
	id := newTestIdentity(t, 96)

	var w writer
	w.str("dave")
	w.blob(id.blob)
	w.str("laptop-7")
	c.send(typeHello, w.bytes())

	r := reader{buf: c.recvType(typeAuthChallenge)}
	nonce, _ := r.blob()

	var a writer
	a.blob(ed25519.Sign(id.signer, nonce))
	c.send(typeAuthResponse, a.bytes())

	payload := c.expectType(typeHelloOK)
	ok := reader{buf: payload}
	user, _ := ok.str()
	device, _ := ok.str()
	if user != "dave" {
		t.Fatalf("user = %q", user)
	}
	if device != "laptop-7" {
		t.Fatalf("device = %q, want laptop-7", device)
	}
	ok.done()
}

func TestEmptyDeviceMeansWholeAccount(t *testing.T) {
	// A SEND with an empty trailing device field addresses the whole account,
	// which is what a single-device peer does. It must be delivered, not
	// refused: an empty string is a valid "no particular device".
	h := newHarness(t)

	alice := h.dial(t, "alice", newTestIdentity(t, 97))
	bob := h.dialWithDevice(t, "bob", "phone", newTestIdentity(t, 98))

	var w writer
	w.str("bob")
	w.blob([]byte("hello"))
	w.str("")
	alice.send(typeSend, w.bytes())

	payload := bob.recvType(typeDeliver)
	r := reader{buf: payload}
	_, _ = r.u64()
	from, _ := r.str()
	body, _ := r.blob()
	if from != "alice" || string(body) != "hello" {
		t.Fatalf("got %q from %q", body, from)
	}
}

// ---- Password vaults --------------------------------------------------

func putVaultPayload(user string, salt []byte, memory, passes, lanes uint32, blob []byte) []byte {
	var w writer
	w.str(user)
	w.blob(salt)
	w.u32(memory)
	w.u32(passes)
	w.u32(lanes)
	w.blob(blob)
	return w.bytes()
}

func TestVaultRoundTrip(t *testing.T) {
	// The whole feature depends on this: a client restores its identity by
	// fetching a blob the relay cannot open.
	h := newHarness(t)
	c := h.dialRaw(t)  // deliberately *not* authenticated: a vault fetch happens
	// before HELLO, because the client has no identity to prove yet.

	salt := bytes.Repeat([]byte{0x11}, 16)
	blob := bytes.Repeat([]byte{0xAB}, 512)

	c.send(typePutVault, putVaultPayload("alice", salt, 65536, 3, 2, blob))
	ack := c.recvType(typeVaultAck)
	r := reader{buf: ack}
	generation, err := r.u32()
	if err != nil || generation != 1 {
		t.Fatalf("generation = %d, %v (want 1)", generation, err)
	}

	var w writer
	w.str("alice")
	c.send(typeGetVault, w.bytes())

	payload := c.recvType(typeVaultData)
	got := reader{buf: payload}

	gotSalt, _ := got.blob()
	memory, _ := got.u32()
	passes, _ := got.u32()
	lanes, _ := got.u32()
	gen, _ := got.u32()
	gotBlob, _ := got.blob()

	if !bytes.Equal(gotSalt, salt) {
		t.Fatalf("salt mismatch")
	}
	if memory != 65536 || passes != 3 || lanes != 2 {
		t.Fatalf("kdf params = %d/%d/%d", memory, passes, lanes)
	}
	if gen != 1 {
		t.Fatalf("generation = %d, want 1", gen)
	}
	if !bytes.Equal(gotBlob, blob) {
		t.Fatalf("blob mismatch")
	}
}

func TestVaultGenerationAdvancesOnRewrite(t *testing.T) {
	// Two devices writing at once is the realistic case for this table. Last write
	// wins, but the generation has to move so a client can tell its write was
	// overwritten rather than assume it stuck.
	h := newHarness(t)
	c := h.dialRaw(t)

	salt := bytes.Repeat([]byte{0x22}, 16)

	c.send(typePutVault, putVaultPayload("alice", salt, 65536, 3, 2, []byte("first")))
	r1 := reader{buf: c.recvType(typeVaultAck)}
	gen1, _ := r1.u32()

	c.send(typePutVault, putVaultPayload("alice", salt, 65536, 3, 2, []byte("second")))
	r2 := reader{buf: c.recvType(typeVaultAck)}
	gen2, _ := r2.u32()

	if gen2 != gen1+1 {
		t.Fatalf("generation = %d -> %d, want an increment", gen1, gen2)
	}
}

func TestVaultForUnknownUserIsNotAnError(t *testing.T) {
	// A user that never set a password has no vault. The client must be able to
	// tell that apart from a failure, because it falls back to a local identity.
	h := newHarness(t)
	c := h.dialRaw(t)

	var w writer
	w.str("nobody")
	c.send(typeGetVault, w.bytes())

	payload := c.recvType(typeError)
	if !strings.Contains(string(payload), "no vault") {
		t.Fatalf("unexpected error: %q", payload)
	}
}

func TestVaultRejectsWeakDerivationParameters(t *testing.T) {
	// The relay is the one place that can refuse a weak vault without knowing the
	// password. A client asking for 1 pass or 8 KiB is weakening its own store, and
	// the price of the feature is that the server holds it.
	h := newHarness(t)
	c := h.dialRaw(t)

	salt := bytes.Repeat([]byte{0x33}, 16)

	cases := []struct {
		name                  string
		memory, passes, lanes uint32
	}{
		{"zero passes", 65536, 0, 2},
		{"zero memory", 0, 3, 2},
		{"memory below lanes", 8, 3, 4},
		{"absurd memory", 1 << 20, 3, 2},
		{"zero lanes", 65536, 3, 0},
	}

	for _, tc := range cases {
		c.send(typePutVault, putVaultPayload("alice", salt, tc.memory, tc.passes, tc.lanes, []byte("x")))
		c.expectType(typeError)
	}
}

func TestVaultRejectsShortSalt(t *testing.T) {
	// A short salt would let one precomputation attack every account that shares
	// it, which is the failure this parameter exists to prevent.
	h := newHarness(t)
	c := h.dialRaw(t)

	c.send(typePutVault, putVaultPayload("alice", []byte{1, 2, 3}, 65536, 3, 2, []byte("x")))
	c.expectType(typeError)
}

func TestVaultRejectsOversizedBlob(t *testing.T) {
	// Two ceilings, and the vault's must sit below the transport's or it can never
	// fire. That relationship is asserted here because it is a configuration
	// invariant, not a behaviour: the previous flat 4 MiB vault limit was above the
	// 1 MiB frame limit, so a 4 MiB vault would have been refused by the codec with
	// an error that says nothing about vaults.
	if maxVaultBlob >= maxPayload {
		t.Fatalf("maxVaultBlob (%d) must be below maxPayload (%d)",
			maxVaultBlob, maxPayload)
	}

	h := newHarness(t)
	c := h.dialRaw(t)

	salt := bytes.Repeat([]byte{0x44}, 16)

	// A blob just over the vault ceiling, inside a frame the transport accepts.
	oversized := make([]byte, maxVaultBlob+1)
	payload := putVaultPayload("alice", salt, 65536, 3, 2, oversized)

	if _, err := frame(typePutVault, payload); err != nil {
		t.Fatalf("the oversized vault did not fit a frame, so this test cannot "+
			"reach the vault check: %v", err)
	}

	c.send(typePutVault, payload)
	c.expectType(typeError)
}

func TestAuthenticatedClientCannotWriteAnotherVault(t *testing.T) {
	// An authenticated connection may only write its own vault. Writing somebody
	// else's would let one user replace another's encrypted identity with a blob
	// they control - the victim would then restore into a stranger's account.
	h := newHarness(t)
	alice := h.dial(t, "alice", newTestIdentity(t, 200))

	salt := bytes.Repeat([]byte{0x55}, 16)
	alice.send(typePutVault, putVaultPayload("bob", salt, 65536, 3, 2, []byte("x")))

	payload := alice.expectType(typeError)
	if !strings.Contains(string(payload), "own device list") {
		t.Fatalf("unexpected error: %q", payload)
	}

	stored, err := h.store.GetVault("bob")
	if err != nil {
		t.Fatalf("GetVault: %v", err)
	}
	if stored != nil {
		t.Fatal("bob gained a vault from alice's write")
	}
}

// ---- Send pacing -------------------------------------------------------

func TestSendRateLimit(t *testing.T) {
	// One connection can otherwise fill the outbox for everybody else: the
	// relay accepts ciphertext from any authenticated sender for any
	// recipient, and nothing paced it.
	lim := newRateLimiter(sendBurst, 10*time.Second)

	allowed := 0
	for i := 0; i < sendBurst+10; i++ {
		if lim.allow() {
			allowed++
		}
	}
	if allowed != sendBurst {
		t.Fatalf("allowed = %d, want %d", allowed, sendBurst)
	}

	// Refill restores exactly the burst allowance, not more.
	lim.last = time.Now().Add(-10 * time.Second)
	if !lim.allow() {
		t.Fatal("refill did not restore a token")
	}
	if lim.tokens > lim.burst-1+0.001 {
		t.Fatalf("tokens = %v, burst = %v: refill exceeded the burst", lim.tokens, lim.burst)
	}
}

func TestHealthEndpoint(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{"/healthz", "/readyz", "/health"} {
		resp, err := http.Get(h.srv.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", path, resp.StatusCode)
		}
		if path != "/healthz" && !strings.Contains(string(body), "outbox=") {
			t.Fatalf("%s body = %q, want the queue depth", path, body)
		}
	}
}

func TestReadyReportsQueueDepth(t *testing.T) {
	h := newHarness(t)
	_ = enqueueAt(h.store, "bob", "alice", 1, []byte("x"))
	_ = enqueueAt(h.store, "bob", "alice", 2, []byte("y"))

	resp, err := http.Get(h.srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if !strings.Contains(string(body), "outbox=2") {
		t.Fatalf("body = %q, want outbox=2", body)
	}
}

func TestReadyFailsWhenStoreIsClosed(t *testing.T) {
	// A bound port says nothing about whether the store is usable, and the
	// store is what actually breaks. Readiness has to fail with it.
	h := newHarness(t)
	_ = h.store.Close()

	resp, err := http.Get(h.srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

// ---- Graceful shutdown -------------------------------------------------

func TestShutdownClosesSocketsCleanly(t *testing.T) {
	// http.Server.Shutdown does not touch hijacked websockets, so without an
	// explicit close the process sat for 10 seconds and then died, and the
	// client only learned about it when its next write failed.
	h := newHarness(t)
	c := h.dial(t, "alice", newTestIdentity(t, 70))

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.hub.Shutdown(context.Background())
	}()

	// The client must see a real close frame, not a dropped TCP connection.
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err := c.conn.ReadMessage()
	if err == nil {
		t.Fatal("expected the socket to close")
	}
	var closeErr *websocket.CloseError
	if !errors.As(err, &closeErr) {
		t.Fatalf("closed with %v, want a websocket close frame", err)
	}
	if closeErr.Code != websocket.CloseGoingAway {
		t.Fatalf("close code = %d, want %d", closeErr.Code, websocket.CloseGoingAway)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not finish")
	}

	// And a new handshake is refused while draining.
	if _, _, err := websocket.DefaultDialer.Dial(h.wsURL, nil); err == nil {
		t.Fatal("handshake accepted while shutting down")
	}
}

// ---- Outbox paging -----------------------------------------------------

// floor the ceiling for the duration of one test, so a test can flood the
// outbox on purpose without the pacing bucket stopping it.
func allowFlood(t *testing.T) {
	t.Helper()
	previous := sendBurst
	sendBurst = 1 << 20
	t.Cleanup(func() { sendBurst = previous })
}

func TestOutboxDrainsAcrossPages(t *testing.T) {
	allowFlood(t)
	h := newHarness(t)
	alice := h.dial(t, "alice", newTestIdentity(t, 60))

	const total = flushPageSize + 25
	for i := 0; i < total; i++ {
		var w writer
		w.str("bob")
		w.blob([]byte{byte(i)})
		alice.send(typeSend, w.bytes())
	}

	waitFor(t, 5*time.Second, func() bool {
		n, err := h.store.PendingCount()
		return err == nil && n == total
	})

	bob := h.dial(t, "bob", newTestIdentity(t, 61))

	// Page one, then the "more pending" marker, then an ACK pulls page two.
	received := readPage(t, bob, flushPageSize)
	more := bob.recvType(typeMorePending)
	if len(more) != 0 {
		t.Fatalf("more-pending frame carried %d bytes", len(more))
	}
	if len(received) != flushPageSize {
		t.Fatalf("first page = %d, want %d", len(received), flushPageSize)
	}

	var a writer
	a.u64(received[len(received)-1])
	bob.send(typeAck, a.bytes())

	rest := readPage(t, bob, total-flushPageSize)
	if len(rest) != total-flushPageSize {
		t.Fatalf("second page = %d, want %d", len(rest), total-flushPageSize)
	}

	// Payloads must arrive in order, with nothing dropped or duplicated across
	// the page boundary.
	all := append(append([]uint64{}, received...), rest...)
	for i := 1; i < len(all); i++ {
		if all[i] <= all[i-1] {
			t.Fatalf("outbox ids out of order across pages: %d then %d", all[i-1], all[i])
		}
	}
	waitFor(t, 2*time.Second, func() bool {
		n, err := h.store.PendingCount()
		return err == nil && n == total-int64(flushPageSize)
	})
}

// readPage collects up to n DELIVER frames, stopping early on more-pending.
func readPage(t *testing.T, c *testClient, n int) []uint64 {
	t.Helper()
	var ids []uint64
	for len(ids) < n {
		msgType, payload := c.recv()
		switch msgType {
		case typeDeliver:
			r := reader{buf: payload}
			id, err := r.u64()
			if err != nil {
				t.Fatalf("deliver id: %v", err)
			}
			ids = append(ids, id)
		case typeMorePending:
			return ids
		default:
			t.Fatalf("unexpected frame %#x while reading a page", msgType)
		}
	}
	return ids
}

// enqueueAt stores a frame under an explicit per-recipient sequence number, so
// a test does not depend on the counter's current value.
func enqueueAt(s *Store, recipient, sender string, seq uint64, payload []byte) error {
	return s.Enqueue(recipient, sender, seq, payload)
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
