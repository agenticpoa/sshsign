package storage

import (
	"database/sql"
	"fmt"
	"time"
)

// SaveEvidenceEnvelope stores a sealed evidence envelope for a pending signature.
func SaveEvidenceEnvelope(db *sql.DB, pendingID string, data []byte, hash string) error {
	_, err := db.Exec(
		`INSERT INTO evidence_envelopes (pending_id, data, hash) VALUES (?, ?, ?)`,
		pendingID, data, hash,
	)
	if err != nil {
		return fmt.Errorf("inserting evidence envelope: %w", err)
	}
	return nil
}

// GetEvidenceEnvelope retrieves a sealed evidence envelope by pending ID.
func GetEvidenceEnvelope(db *sql.DB, pendingID string) (*EvidenceEnvelope, error) {
	row := db.QueryRow(
		`SELECT pending_id, data, hash, created_at FROM evidence_envelopes WHERE pending_id = ?`,
		pendingID,
	)

	var env EvidenceEnvelope
	var createdAt string

	err := row.Scan(&env.PendingID, &env.Data, &env.Hash, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scanning evidence envelope: %w", err)
	}

	env.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	return &env, nil
}
