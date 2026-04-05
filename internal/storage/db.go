package storage

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

func Open(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=foreign_keys(1)&_pragma=journal_mode(wal)")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Single writer for SQLite
	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	return db, nil
}

// OpenMemory opens an in-memory SQLite database for testing.
func OpenMemory() (*sql.DB, error) {
	db, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("opening in-memory database: %w", err)
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

func Migrate(db *sql.DB) error {
	_, err := db.Exec(schema)
	if err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}

	// Run column migrations for existing databases.
	// ALTER TABLE ADD COLUMN is a no-op if the column already exists in SQLite
	// when we ignore the "duplicate column" error.
	columnMigrations := []string{
		`ALTER TABLE authorizations ADD COLUMN metadata_constraints TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE authorizations ADD COLUMN confirmation_tier TEXT NOT NULL DEFAULT 'autonomous'`,
		`ALTER TABLE signing_keys ADD COLUMN sign_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE signing_keys ADD COLUMN last_used_at TEXT`,
		`ALTER TABLE authorizations ADD COLUMN require_signature BOOLEAN NOT NULL DEFAULT 0`,
		`ALTER TABLE pending_signatures ADD COLUMN approval_token TEXT`,
		`ALTER TABLE pending_signatures ADD COLUMN signing_session_id TEXT`,
		`ALTER TABLE pending_signatures ADD COLUMN signature TEXT`,
	}
	for _, m := range columnMigrations {
		_, err := db.Exec(m)
		if err != nil && !isColumnExistsError(err) {
			return fmt.Errorf("running column migration: %w", err)
		}
	}

	return nil
}

func isColumnExistsError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "duplicate column") || strings.Contains(msg, "already exists")
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
	user_id    TEXT PRIMARY KEY,
	created_at TEXT NOT NULL DEFAULT (datetime('now')),
	status     TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS user_keys (
	ssh_fingerprint TEXT PRIMARY KEY,
	user_id         TEXT NOT NULL REFERENCES users(user_id),
	public_key      TEXT NOT NULL,
	label           TEXT NOT NULL DEFAULT '',
	added_at        TEXT NOT NULL DEFAULT (datetime('now')),
	revoked_at      TEXT
);

CREATE TABLE IF NOT EXISTS signing_keys (
	key_id                TEXT PRIMARY KEY,
	owner_id              TEXT NOT NULL REFERENCES users(user_id),
	public_key            TEXT NOT NULL,
	private_key_encrypted BLOB NOT NULL,
	dek_encrypted         BLOB NOT NULL,
	created_at            TEXT NOT NULL DEFAULT (datetime('now')),
	revoked_at            TEXT
);

CREATE TABLE IF NOT EXISTS authorizations (
	token_id              TEXT PRIMARY KEY,
	signing_key_id        TEXT NOT NULL REFERENCES signing_keys(key_id),
	granted_by            TEXT NOT NULL REFERENCES users(user_id),
	scopes                TEXT NOT NULL DEFAULT '[]',
	constraints           TEXT NOT NULL DEFAULT '{}',
	metadata_constraints  TEXT NOT NULL DEFAULT '[]',
	confirmation_tier     TEXT NOT NULL DEFAULT 'autonomous',
	hard_rules            TEXT NOT NULL DEFAULT '[]',
	soft_rules            TEXT NOT NULL DEFAULT '[]',
	expires_at            TEXT,
	revoked_at            TEXT,
	created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pending_signatures (
	id              TEXT PRIMARY KEY,
	signing_key_id  TEXT NOT NULL REFERENCES signing_keys(key_id),
	auth_token_id   TEXT NOT NULL REFERENCES authorizations(token_id),
	requester_id    TEXT NOT NULL REFERENCES users(user_id),
	doc_type        TEXT NOT NULL,
	payload_hash    TEXT NOT NULL,
	metadata        TEXT,
	status          TEXT NOT NULL DEFAULT 'pending',
	created_at      TEXT NOT NULL DEFAULT (datetime('now')),
	resolved_at     TEXT,
	resolved_by     TEXT
);

CREATE TABLE IF NOT EXISTS negotiation_offers (
	id              TEXT PRIMARY KEY,
	negotiation_id  TEXT NOT NULL,
	round           INTEGER NOT NULL,
	from_party      TEXT NOT NULL,
	offer_type      TEXT NOT NULL,
	metadata        TEXT NOT NULL DEFAULT '{}',
	previous_tx     INTEGER NOT NULL DEFAULT 0,
	audit_tx_id     INTEGER NOT NULL DEFAULT 0,
	user_id         TEXT NOT NULL REFERENCES users(user_id),
	created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_negotiation_offers_neg_id ON negotiation_offers(negotiation_id, round);

CREATE TABLE IF NOT EXISTS evidence_envelopes (
	pending_id  TEXT PRIMARY KEY REFERENCES pending_signatures(id),
	data        BLOB NOT NULL,
	hash        TEXT NOT NULL,
	created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
`
