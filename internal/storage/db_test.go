package storage_test

import (
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
	if err := storage.Migrate(db); err != nil {
		t.Fatalf("first migration: %v", err)
	}
	if err := storage.Migrate(db); err != nil {
		t.Fatalf("second migration: %v", err)
	}
}
