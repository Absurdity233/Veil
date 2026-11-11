package main

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

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
    sender      TEXT NOT NULL,
    payload     BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS outbox_recipient ON outbox(recipient, id);
`
	_, err := s.db.Exec(schema)
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

func (s *Store) Enqueue(recipient, sender string, payload []byte) error {
	_, err := s.db.Exec(
		`INSERT INTO outbox(recipient, sender, payload, created_at)
		 VALUES(?,?,?,strftime('%s','now'))`,
		recipient, sender, payload)
	return err
}

type storedMessage struct {
	ID      int64
	Sender  string
	Payload []byte
}

// Drain returns everything queued for recipient with id greater than afterID.
func (s *Store) Drain(recipient string, afterID int64, limit int) ([]storedMessage, error) {
	rows, err := s.db.Query(
		`SELECT id, sender, payload FROM outbox
		 WHERE recipient = ? AND id > ? ORDER BY id LIMIT ?`,
		recipient, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []storedMessage
	for rows.Next() {
		var m storedMessage
		if err := rows.Scan(&m.ID, &m.Sender, &m.Payload); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) Acknowledge(recipient string, upTo int64) error {
	_, err := s.db.Exec(`DELETE FROM outbox WHERE recipient = ? AND id <= ?`, recipient, upTo)
	return err
}

// PendingCount is used by the health endpoint to report queue depth.
func (s *Store) PendingCount() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM outbox`).Scan(&n)
	return n, err
}
