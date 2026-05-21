package storage

import (
	"context"
	"database/sql"
)

// TestDB wraps a sql.DB for testing with a migrated in-memory database.
type TestDB struct {
	*sql.DB
}

func NewTestDB() (*TestDB, error) {
	db, err := OpenMemory()
	if err != nil {
		return nil, err
	}
	if err := Migrate(context.Background(), db); err != nil {
		db.Close()
		return nil, err
	}
	return &TestDB{DB: db}, nil
}
