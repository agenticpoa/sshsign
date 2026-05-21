package storage

import (
	"context"
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

// migration represents one ordered schema change. New columns/tables
// land as a new entry at the end of [migrations]; the up SQL runs
// exactly once per database, gated by the schema_migrations table.
type migration struct {
	version int
	name    string
	up      string
}

// migrations is the ordered history of schema changes. Earlier entries
// must never be edited after release — that would mutate the schema
// silently on long-running databases. Append new versions instead.
//
// v1 carries the current full schema as a single block (CREATE TABLE
// IF NOT EXISTS for every table). Legacy DBs are baselined into v1 on
// first run after this code lands so the loop of opportunistic
// ALTER-TABLE-ADD-COLUMN calls can retire.
var migrations = []migration{
	{version: 1, name: "initial_schema", up: schemaV1},
}

// Migrate brings the database up to the latest known schema version.
// Safe to call on fresh, legacy (pre-versioning), and already-migrated
// databases — see baselineIfLegacy for how existing column-migration
// DBs roll forward without re-running the ALTERs.
func Migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at TEXT NOT NULL DEFAULT (datetime('now'))
	)`); err != nil {
		return fmt.Errorf("creating schema_migrations: %w", err)
	}

	if err := baselineIfLegacy(ctx, db); err != nil {
		return fmt.Errorf("baselining legacy schema: %w", err)
	}

	applied, err := loadAppliedVersions(ctx, db)
	if err != nil {
		return fmt.Errorf("loading applied versions: %w", err)
	}

	for _, m := range migrations {
		if applied[m.version] {
			continue
		}
		if err := runMigration(ctx, db, m); err != nil {
			return err
		}
	}
	return nil
}

func runMigration(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx for v%d (%s): %w", m.version, m.name, err)
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx, m.up); err != nil {
		return fmt.Errorf("running migration v%d (%s): %w", m.version, m.name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name) VALUES (?, ?)`,
		m.version, m.name,
	); err != nil {
		return fmt.Errorf("recording migration v%d: %w", m.version, err)
	}
	return tx.Commit()
}

func loadAppliedVersions(ctx context.Context, db *sql.DB) (map[int]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

// baselineIfLegacy detects a pre-versioning database — one created by
// the old opportunistic ALTER-TABLE-on-every-startup scheme — and
// records every known migration as applied without re-running it. The
// signal is "schema_migrations is empty but the users table already
// exists." Fresh databases have neither, and roll through the normal
// migration path. Already-versioned databases have applied rows and
// skip this entirely.
func baselineIfLegacy(ctx context.Context, db *sql.DB) error {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	var name string
	err := db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name='users'`,
	).Scan(&name)
	if err == sql.ErrNoRows {
		return nil // fresh database, let migrations run from v1
	}
	if err != nil {
		return err
	}

	// Legacy DB. Mark every known migration applied so we don't try to
	// re-create tables or re-add columns that the old loop already put
	// in place.
	for _, m := range migrations {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, name) VALUES (?, ?)`,
			m.version, m.name,
		); err != nil {
			return fmt.Errorf("baselining v%d: %w", m.version, err)
		}
	}
	return nil
}

// schemaV1 is the current full schema as of the migration-versioning
// switch. New tables and columns live here for fresh databases; for
// long-running databases, additive changes go in as new migration
// entries appended to [migrations].
const schemaV1 = `
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
	revoked_at            TEXT,
	sign_count            INTEGER NOT NULL DEFAULT 0,
	last_used_at          TEXT,
	kek_algo              TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS authorizations (
	token_id              TEXT PRIMARY KEY,
	signing_key_id        TEXT NOT NULL REFERENCES signing_keys(key_id),
	granted_by            TEXT NOT NULL REFERENCES users(user_id),
	scopes                TEXT NOT NULL DEFAULT '[]',
	constraints           TEXT NOT NULL DEFAULT '{}',
	metadata_constraints  TEXT NOT NULL DEFAULT '[]',
	confirmation_tier     TEXT NOT NULL DEFAULT 'autonomous',
	require_signature     BOOLEAN NOT NULL DEFAULT 0,
	hard_rules            TEXT NOT NULL DEFAULT '[]',
	soft_rules            TEXT NOT NULL DEFAULT '[]',
	expires_at            TEXT,
	revoked_at            TEXT,
	created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pending_signatures (
	id                  TEXT PRIMARY KEY,
	signing_key_id      TEXT NOT NULL REFERENCES signing_keys(key_id),
	auth_token_id       TEXT NOT NULL REFERENCES authorizations(token_id),
	requester_id        TEXT NOT NULL REFERENCES users(user_id),
	doc_type            TEXT NOT NULL,
	payload_hash        TEXT NOT NULL,
	metadata            TEXT,
	status              TEXT NOT NULL DEFAULT 'pending',
	approval_token      TEXT,
	signing_session_id  TEXT,
	signature           TEXT,
	pending_mac         BLOB,
	created_at          TEXT NOT NULL DEFAULT (datetime('now')),
	resolved_at         TEXT,
	resolved_by         TEXT
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

CREATE TABLE IF NOT EXISTS signing_sessions (
	session_id         TEXT PRIMARY KEY,
	session_code       TEXT NOT NULL UNIQUE,
	created_by         TEXT NOT NULL REFERENCES users(user_id),
	created_at         TEXT NOT NULL DEFAULT (datetime('now')),
	expires_at         TEXT NOT NULL,
	status             TEXT NOT NULL DEFAULT 'open',
	canceled_by        TEXT REFERENCES users(user_id),
	completed_at       TEXT,
	finalized_by       TEXT REFERENCES users(user_id),
	executed_artifact  TEXT,
	metadata_public    TEXT NOT NULL DEFAULT '{}',
	metadata_member    TEXT NOT NULL DEFAULT '{}',
	view_token         TEXT,
	group_chat_id      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_signing_sessions_code ON signing_sessions(session_code);
CREATE INDEX IF NOT EXISTS idx_signing_sessions_status_expires ON signing_sessions(status, expires_at);

CREATE TABLE IF NOT EXISTS signing_session_members (
	session_id            TEXT NOT NULL REFERENCES signing_sessions(session_id),
	user_id               TEXT NOT NULL REFERENCES users(user_id),
	role                  TEXT NOT NULL,
	apoa_pubkey_pem       TEXT NOT NULL,
	party_did             TEXT NOT NULL DEFAULT '',
	joined_at             TEXT NOT NULL DEFAULT (datetime('now')),
	founder_resumed_at    INTEGER,
	founder_streaming_at  INTEGER,
	bot_handle            TEXT,
	telegram_user_id      TEXT,
	PRIMARY KEY (session_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_session_members_user ON signing_session_members(user_id);

CREATE TABLE IF NOT EXISTS signing_session_leases (
	session_id   TEXT NOT NULL REFERENCES signing_sessions(session_id),
	role         TEXT NOT NULL,
	action       TEXT NOT NULL,
	owner_id     TEXT NOT NULL REFERENCES users(user_id),
	holder       TEXT NOT NULL,
	generation   INTEGER NOT NULL DEFAULT 1,
	acquired_at  TEXT NOT NULL,
	expires_at   TEXT NOT NULL,
	PRIMARY KEY (session_id, role, action)
);

CREATE INDEX IF NOT EXISTS idx_session_leases_expires ON signing_session_leases(expires_at);

CREATE TABLE IF NOT EXISTS signing_session_deliveries (
	session_id    TEXT NOT NULL REFERENCES signing_sessions(session_id),
	delivery_key  TEXT NOT NULL,
	target        TEXT NOT NULL DEFAULT '',
	message_id    TEXT NOT NULL DEFAULT '',
	delivered_by  TEXT NOT NULL REFERENCES users(user_id),
	delivered_at  TEXT NOT NULL,
	PRIMARY KEY (session_id, delivery_key)
);

CREATE INDEX IF NOT EXISTS idx_session_deliveries_session ON signing_session_deliveries(session_id);

CREATE TABLE IF NOT EXISTS signing_session_audit (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id  TEXT NOT NULL REFERENCES signing_sessions(session_id),
	event_type  TEXT NOT NULL,
	actor_id    TEXT NOT NULL REFERENCES users(user_id),
	details     TEXT NOT NULL DEFAULT '{}',
	created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_session_audit_session ON signing_session_audit(session_id, created_at);

CREATE TABLE IF NOT EXISTS server_config (
	id          INTEGER PRIMARY KEY CHECK (id = 1),
	kek_salt    BLOB NOT NULL,
	created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
`
