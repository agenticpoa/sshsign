package storage

import "database/sql"

// TestDB wraps a sql.DB for testing with a migrated in-memory database.
type TestDB struct {
	*sql.DB
}

func NewTestDB() (*TestDB, error) {
	db, err := OpenMemory()
	if err != nil {
		return nil, err
	}
	if err := Migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &TestDB{DB: db}, nil
}
