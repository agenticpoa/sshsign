package storage_test

import (
	"context"
	"testing"

	"github.com/agenticpoa/sshsign/internal/storage"
)

func testDB(t *testing.T) *storage.TestDB {
	t.Helper()
	tdb, err := storage.NewTestDB()
	if err != nil {
		t.Fatalf("opening test database: %v", err)
	}
	t.Cleanup(func() { tdb.Close() })
	return tdb
}

func TestMigrateCreatesTablesIdempotent(t *testing.T) {
	db, err := storage.OpenMemory()
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer db.Close()

	// Run migrate twice, should not error
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatalf("first migration: %v", err)
	}
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatalf("second migration: %v", err)
	}

	// schema_migrations should record v1 exactly once.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 1`).Scan(&n); err != nil {
		t.Fatalf("querying schema_migrations: %v", err)
	}
	if n != 1 {
		t.Errorf("expected exactly 1 row for v1, got %d", n)
	}
}

func TestMigrateBaselinesLegacyDatabase(t *testing.T) {
	// Simulate a database created by the previous ad-hoc migration
	// scheme: all tables present, no schema_migrations table. Migrate
	// should mark every known version applied without re-running any
	// migration body (which would fail with "table already exists").
	db, err := storage.OpenMemory()
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer db.Close()

	// Stand up only the `users` table — the signal that there's
	// already data here. baselineIfLegacy uses this as its trigger.
	if _, err := db.Exec(`CREATE TABLE users (
		user_id TEXT PRIMARY KEY,
		created_at TEXT NOT NULL DEFAULT (datetime('now')),
		status TEXT NOT NULL DEFAULT 'active'
	)`); err != nil {
		t.Fatalf("seeding legacy users table: %v", err)
	}

	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatalf("baselining: %v", err)
	}

	// v1 must be marked applied without having created any new tables
	// (CREATE TABLE IF NOT EXISTS would be a no-op anyway, but the
	// point is we recorded the baseline so future migrations append).
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 1`).Scan(&n); err != nil {
		t.Fatalf("querying schema_migrations: %v", err)
	}
	if n != 1 {
		t.Errorf("expected legacy DB to be baselined at v1, got %d rows", n)
	}
}

func TestMigrateRunsFreshSchema(t *testing.T) {
	// Fresh DB has no tables and no schema_migrations row. Migrate
	// should apply v1 (which creates everything) and record it.
	db, err := storage.OpenMemory()
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer db.Close()

	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrating fresh DB: %v", err)
	}

	// Sanity check: a representative table from v1 exists.
	var name string
	if err := db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='signing_keys'`,
	).Scan(&name); err != nil {
		t.Errorf("signing_keys table not created by v1: %v", err)
	}
}
