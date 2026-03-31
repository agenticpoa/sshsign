package storage

import (
	"database/sql"
	"fmt"

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
	return nil
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
	token_id       TEXT PRIMARY KEY,
	signing_key_id TEXT NOT NULL REFERENCES signing_keys(key_id),
	granted_by     TEXT NOT NULL REFERENCES users(user_id),
	scopes         TEXT NOT NULL DEFAULT '[]',
	constraints    TEXT NOT NULL DEFAULT '{}',
	hard_rules     TEXT NOT NULL DEFAULT '[]',
	soft_rules     TEXT NOT NULL DEFAULT '[]',
	expires_at     TEXT,
	revoked_at     TEXT,
	created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
`
