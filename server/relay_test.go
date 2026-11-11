package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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
	srv := httptest.NewServer(newMux(NewHubWithOrigins(store, logger, allowed)))
	t.Cleanup(srv.Close)

	return &harness{
		store: store,
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
	a.u32(1) // acknowledge everything up to id 1
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

// ---- Outbox paging -----------------------------------------------------

func TestOutboxDrainsAcrossPages(t *testing.T) {
	// A backlog larger than one page used to strand everything past the first
	// page until the next reconnect, with the client showing an empty
	// conversation and no hint that more was waiting.
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
	a.u32(uint32(received[len(received)-1]))
	bob.send(typeAck, a.bytes())

	rest := readPage(t, bob, total-flushPageSize)
	if len(rest) != total-flushPageSize {
		t.Fatalf("second page = %d, want %d", len(rest), total-flushPageSize)
	}

	// Payloads must arrive in order, with nothing dropped or duplicated across
	// the page boundary.
	all := append(append([]uint32{}, received...), rest...)
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
func readPage(t *testing.T, c *testClient, n int) []uint32 {
	t.Helper()
	var ids []uint32
	for len(ids) < n {
		msgType, payload := c.recv()
		switch msgType {
		case typeDeliver:
			r := reader{buf: payload}
			id, err := r.u32()
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
