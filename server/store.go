package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Outbox retention and pacing.
//
// None of these existed: the outbox grew forever, and one connection could
// push frames into it as fast as the socket allowed. A relay that accepts
// ciphertext from anyone for anyone will be used as cheap storage unless it
// says no somewhere.
const (
	// Entries older than this are dropped on the next sweep. A week is long
	// enough for a phone that was off, short enough that the disk stays
	// bounded without operator attention.
	outboxTTL = 7 * 24 * time.Hour

	// Per-recipient ceiling. When it is reached the oldest entries go first:
	// the peer is clearly not reading, and keeping the newest is what makes
	// the queue useful when it does come back.
	outboxPerRecipient = 2000

	// Send pacing per connection.
	//
	// A var rather than a const so a test can raise the allowance for the
	// duration of one case instead of the production ceiling carrying a
	// test-only escape hatch.
	sendBurstDefault = 30
	sendRefill       = 10 * time.Second
)

var sendBurst = sendBurstDefault

// Store keeps exactly the three things the relay can act on: who published
// which public prekeys, which ciphertext is waiting for whom, and the
// per-recipient sequence of the outbox. It never sees a private key or a
// plaintext message.
type Store struct {
	db *sql.DB
}

func OpenStore(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer; a small pool keeps readers from blocking the
	// writer while staying well inside the file lock.
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS accounts (
    user_id     TEXT PRIMARY KEY,
    identity    BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS prekeys (
    user_id     TEXT PRIMARY KEY,
    signed_id   INTEGER NOT NULL,
    signed_pub  BLOB NOT NULL,
    signature   BLOB NOT NULL,
    one_time    BLOB NOT NULL,
    updated_at  INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES accounts(user_id)
);

CREATE TABLE IF NOT EXISTS outbox (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient   TEXT NOT NULL,
    -- The device this frame is encrypted to. Empty means "whatever device
    -- collects it", which is what a single-device account still uses.
    device_id   TEXT NOT NULL DEFAULT '',
    sender      TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    payload     BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);

-- The id the client sees and acknowledges is (recipient, seq), a dense
-- per-recipient counter. It used to be the global rowid truncated to u32:
-- AUTOINCREMENT counts across *all* recipients, so the wire value was sparse,
-- overflowed at 2^32, and an acknowledgement after the wrap could delete a
-- different recipient's entry.
CREATE UNIQUE INDEX IF NOT EXISTS outbox_recipient_seq ON outbox(recipient, seq);
CREATE INDEX IF NOT EXISTS outbox_age ON outbox(created_at);

-- Per-recipient sequence. A separate row per recipient keeps the counter dense
-- even after entries are deleted, so a client can say "I have everything up to
-- N" without gaps.
CREATE TABLE IF NOT EXISTS outbox_seq (
    recipient   TEXT PRIMARY KEY,
    last_seq    INTEGER NOT NULL
);

-- Device lists.
--
-- The relay stores each credential blob verbatim and does not parse it. The
-- signatures inside are checked by the client that downloads the list, against
-- the account key it already pins. Storing an opaque blob is what keeps "the
-- relay cannot invent a device" true rather than aspirational: it has nothing
-- to sign with.
--
-- The version is monotonic per user and deliberately lives outside the signed
-- credentials. The account signs which devices exist; the relay only counts.
CREATE TABLE IF NOT EXISTS devices (
    user_id     TEXT NOT NULL,
    device_id   TEXT NOT NULL,
    credential  BLOB NOT NULL,
    added_at    INTEGER NOT NULL,
    PRIMARY KEY (user_id, device_id)
);

CREATE TABLE IF NOT EXISTS device_lists (
    user_id     TEXT PRIMARY KEY,
    version     INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);
`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	// Databases created before the seq column existed get it added and seeded
	// from the rowid. The old ids were globally increasing, so per recipient
	// they are still strictly increasing - not dense, but a valid ordering,
	// which is all an acknowledgement needs.
	return s.ensureSeqColumn()
}

func (s *Store) ensureSeqColumn() error {
	rows, err := s.db.Query(`PRAGMA table_info(outbox)`)
	if err != nil {
		return err
	}
	hasSeq := false
	hasDevice := false
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		switch name {
		case "seq":
			hasSeq = true
		case "device_id":
			hasDevice = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// The device column arrived with device addressing. Existing rows get an
	// empty value, which means "any device of that recipient" — the behaviour
	// they had before, so an upgraded relay still delivers an old backlog.
	if !hasDevice {
		if _, err := s.db.Exec(
			`ALTER TABLE outbox ADD COLUMN device_id TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}

	if hasSeq {
		return nil
	}

	if _, err := s.db.Exec(`ALTER TABLE outbox ADD COLUMN seq INTEGER NOT NULL DEFAULT 0`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE outbox SET seq = id WHERE seq = 0`); err != nil {
		return err
	}
	// Seed the counters so new inserts continue after the highest seeded value.
	_, err = s.db.Exec(`
INSERT INTO outbox_seq(recipient, last_seq)
SELECT recipient, MAX(seq) FROM outbox GROUP BY recipient
ON CONFLICT(recipient) DO UPDATE SET last_seq = MAX(last_seq, excluded.last_seq)`)
	return err
}

// EnsureAccount binds a user id to an identity key.
//
// The binding is one-way: once a user id has an identity, a different identity
// is rejected. Without that, anyone could take over an existing id by
// announcing a new key.
func (s *Store) EnsureAccount(userID string, identity []byte) (bool, error) {
	var existing []byte
	err := s.db.QueryRow(`SELECT identity FROM accounts WHERE user_id = ?`, userID).
		Scan(&existing)
	switch {
	case err == sql.ErrNoRows:
		_, err = s.db.Exec(
			`INSERT INTO accounts(user_id, identity, created_at) VALUES(?,?,strftime('%s','now'))`,
			userID, identity)
		return err == nil, err
	case err != nil:
		return false, err
	}
	return string(existing) == string(identity), nil
}

func (s *Store) Identity(userID string) ([]byte, error) {
	var b []byte
	err := s.db.QueryRow(`SELECT identity FROM accounts WHERE user_id = ?`, userID).Scan(&b)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return b, err
}

type preKeyRow struct {
	SignedID  uint32
	SignedPub []byte
	Signature []byte
	OneTime   []byte // opaque to the relay: the client's own encoding
}

func (s *Store) PublishPreKeys(userID string, pk preKeyRow) error {
	_, err := s.db.Exec(`
INSERT INTO prekeys(user_id, signed_id, signed_pub, signature, one_time, updated_at)
VALUES(?,?,?,?,?,strftime('%s','now'))
ON CONFLICT(user_id) DO UPDATE SET
    signed_id  = excluded.signed_id,
    signed_pub = excluded.signed_pub,
    signature  = excluded.signature,
    one_time   = excluded.one_time,
    updated_at = excluded.updated_at`,
		userID, pk.SignedID, pk.SignedPub, pk.Signature, pk.OneTime)
	return err
}

func (s *Store) PreKeys(userID string) (*preKeyRow, error) {
	row := s.db.QueryRow(
		`SELECT signed_id, signed_pub, signature, one_time FROM prekeys WHERE user_id = ?`,
		userID)
	var pk preKeyRow
	var id uint32
	if err := row.Scan(&id, &pk.SignedPub, &pk.Signature, &pk.OneTime); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	pk.SignedID = id
	return &pk, nil
}

// ReplaceOneTime rewrites the remaining one-time prekeys after one is handed
// out. Kept separate from PublishPreKeys so the signed half never moves.
func (s *Store) ReplaceOneTime(userID string, remaining []byte) error {
	_, err := s.db.Exec(`UPDATE prekeys SET one_time = ? WHERE user_id = ?`, remaining, userID)
	return err
}

type storedMessage struct {
	// The per-recipient sequence number, not the SQLite rowid.
	//
	// The wire carried the rowid as a u32. AUTOINCREMENT is global, so it
	// overflows at 2^32 across *all* recipients - and the client echoed the
	// same u32 back in an acknowledgement, so the day it wrapped, an ACK could
	// delete somebody else's entry. A per-recipient counter is scoped to the
	// recipient it belongs to, and 2^64 is not reachable by accident.
	ID      uint64
	Sender  string
	Payload []byte
}

// Seq returns the next dense sequence number for one recipient.
func (s *Store) Seq(recipient string) (uint64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var last int64
	err = tx.QueryRow(`SELECT last_seq FROM outbox_seq WHERE recipient = ?`, recipient).Scan(&last)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}

	next := last + 1
	if _, err := tx.Exec(`
INSERT INTO outbox_seq(recipient, last_seq) VALUES(?,?)
ON CONFLICT(recipient) DO UPDATE SET last_seq = excluded.last_seq`,
		recipient, next); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return uint64(next), nil
}

// Enqueue stores a frame for a recipient that is not connected, under an
// explicit per-recipient sequence number so the id the client sees is the one
// it will acknowledge.
//
// `deviceID` scopes the frame to one device; empty leaves it collectable by any
// connection of that recipient.
func (s *Store) Enqueue(recipient, sender string, seq uint64, payload []byte) error {
	return s.EnqueueDevice(recipient, "", sender, seq, payload)
}

// EnqueueDevice is Enqueue with an explicit target device.
func (s *Store) EnqueueDevice(recipient, deviceID, sender string, seq uint64, payload []byte) error {
	_, err := s.db.Exec(
		`INSERT INTO outbox(recipient, device_id, sender, seq, payload, created_at)
		 VALUES(?,?,?,?,?,strftime('%s','now'))`,
		recipient, deviceID, sender, int64(seq), payload)
	return err
}

// Drain returns everything queued for recipient with seq greater than afterSeq.
//
// `deviceID` restricts the page to frames addressed to that device plus frames
// addressed to nobody, which is what a single-device account stores. A frame
// addressed to a different device is *not* returned: it is encrypted to that
// device's ratchet and would fail to decrypt here.
func (s *Store) Drain(recipient string, afterSeq uint64, limit int) ([]storedMessage, error) {
	return s.DrainForDevice(recipient, "", afterSeq, limit)
}

// DrainForDevice is Drain with an explicit device filter.
func (s *Store) DrainForDevice(recipient, deviceID string, afterSeq uint64, limit int) ([]storedMessage, error) {
	var rows *sql.Rows
	var err error

	if deviceID == "" {
		rows, err = s.db.Query(
			`SELECT seq, sender, payload FROM outbox
			 WHERE recipient = ? AND seq > ? ORDER BY seq LIMIT ?`,
			recipient, int64(afterSeq), limit)
	} else {
		rows, err = s.db.Query(
			`SELECT seq, sender, payload FROM outbox
			 WHERE recipient = ? AND (device_id = ? OR device_id = '')
			   AND seq > ? ORDER BY seq LIMIT ?`,
			recipient, deviceID, int64(afterSeq), limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []storedMessage
	for rows.Next() {
		var m storedMessage
		var seq int64
		if err := rows.Scan(&seq, &m.Sender, &m.Payload); err != nil {
			return nil, err
		}
		m.ID = uint64(seq)
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---- Device lists ------------------------------------------------------
//
// A device list is a set of opaque, account-signed credential blobs plus a
// version counter the relay owns. The relay never parses a credential: it
// cannot verify the signature (it has no account key) and it has no reason to,
// because the client verifies every entry against the key it already pins.
//
// What the relay *does* enforce is monotonicity. Without it, a relay that had
// been compromised, or one that simply replayed an old response, could hand a
// peer a list from before a device was removed - and the peer would start a
// session with a device the user had disowned.

// PublishDevices replaces a user's device set and bumps the version.
//
// Returns the new version. Replacing the whole set rather than diffing is what
// makes revocation expressible as omission: a device that is not in the new list
// is gone, and there is no separate "remove" operation to forget to call.
func (s *Store) PublishDevices(userID string, credentials [][]byte, deviceIDs []string) (uint32, error) {
	if len(credentials) != len(deviceIDs) {
		return 0, fmt.Errorf("devices: %d credentials for %d ids", len(credentials), len(deviceIDs))
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var current uint32
	err = tx.QueryRow(`SELECT version FROM device_lists WHERE user_id = ?`, userID).Scan(&current)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	next := current + 1

	if _, err := tx.Exec(`
INSERT INTO device_lists(user_id, version, updated_at)
VALUES(?,?,strftime('%s','now'))
ON CONFLICT(user_id) DO UPDATE SET
    version    = excluded.version,
    updated_at = excluded.updated_at`, userID, next); err != nil {
		return 0, err
	}

	if _, err := tx.Exec(`DELETE FROM devices WHERE user_id = ?`, userID); err != nil {
		return 0, err
	}

	for i, credential := range credentials {
		if _, err := tx.Exec(
			`INSERT INTO devices(user_id, device_id, credential, added_at)
			 VALUES(?,?,?,strftime('%s','now'))`,
			userID, deviceIDs[i], credential); err != nil {
			return 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}

type deviceRow struct {
	DeviceID   string
	Credential []byte
}

// Devices returns a user's current device list and its version.
func (s *Store) Devices(userID string) ([]deviceRow, uint32, error) {
	var version uint32
	err := s.db.QueryRow(`SELECT version FROM device_lists WHERE user_id = ?`, userID).
		Scan(&version)
	if err == sql.ErrNoRows {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Query(
		`SELECT device_id, credential FROM devices WHERE user_id = ? ORDER BY device_id`,
		userID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []deviceRow
	for rows.Next() {
		var d deviceRow
		if err := rows.Scan(&d.DeviceID, &d.Credential); err != nil {
			return nil, 0, err
		}
		out = append(out, d)
	}
	return out, version, rows.Err()
}

// SeedDefaultDevice gives an account that predates device lists a list of one.
//
// The credential is the account identity vouching for itself, which is exactly
// what a first device produces. That is why this migration needs no special
// case in the client: an upgraded relay serves an upgraded account in the shape
// the new code already understands.
func (s *Store) SeedDefaultDevice(userID string, deviceID string, credential []byte) error {
	var exists int
	if err := s.db.QueryRow(`SELECT 1 FROM device_lists WHERE user_id = ?`, userID).
		Scan(&exists); err != nil {
		if err != sql.ErrNoRows {
			return err
		}
	} else {
		return nil
	}

	_, err := s.PublishDevices(userID, [][]byte{credential}, []string{deviceID})
	return err
}

// Acknowledge drops everything this recipient has up to and including upTo.
//
// Scoped to the recipient on purpose: the wire id used to be a global rowid, so
// an acknowledgement could match a row belonging to somebody else.
func (s *Store) Acknowledge(recipient string, upTo uint64) error {
	_, err := s.db.Exec(`DELETE FROM outbox WHERE recipient = ? AND seq <= ?`,
		recipient, int64(upTo))
	return err
}

// PendingCount is used by the readiness endpoint to report queue depth.
func (s *Store) PendingCount() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM outbox`).Scan(&n)
	return n, err
}

// PendingFor reports how many entries are waiting for one recipient.
func (s *Store) PendingFor(recipient string) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM outbox WHERE recipient = ?`, recipient).Scan(&n)
	return n, err
}

// Sweep drops expired entries and trims each recipient back to the ceiling.
//
// Without this the outbox was unbounded storage anyone could fill: the relay
// accepts ciphertext from any authenticated sender for any recipient, and
// nothing ever removed what the recipient declined to read.
func (s *Store) Sweep(now time.Time) (expired int64, trimmed int64, err error) {
	cutoff := now.Add(-outboxTTL).Unix()

	res, err := s.db.Exec(`DELETE FROM outbox WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, 0, err
	}
	expired, _ = res.RowsAffected()

	rows, err := s.db.Query(
		`SELECT recipient FROM outbox GROUP BY recipient HAVING COUNT(*) > ?`,
		outboxPerRecipient)
	if err != nil {
		return expired, 0, err
	}
	var over []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			rows.Close()
			return expired, 0, err
		}
		over = append(over, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return expired, 0, err
	}

	for _, recipient := range over {
		// Keep the newest N: the peer is clearly not reading, and the recent
		// entries are the ones worth having when it comes back.
		r, err := s.db.Exec(
			`DELETE FROM outbox
			 WHERE recipient = ?
			   AND seq < (SELECT seq FROM outbox WHERE recipient = ?
			              ORDER BY seq DESC LIMIT 1 OFFSET ?)`,
			recipient, recipient, outboxPerRecipient-1)
		if err != nil {
			return expired, trimmed, err
		}
		n, _ := r.RowsAffected()
		trimmed += n
	}
	return expired, trimmed, nil
}
