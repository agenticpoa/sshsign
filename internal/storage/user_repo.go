package storage

import (
	"database/sql"
	"fmt"
	"time"
)

// FindUserByFingerprint looks up a user by their SSH key fingerprint.
// Returns nil, nil, nil if no matching key is found.
func FindUserByFingerprint(db *sql.DB, fingerprint string) (*User, *UserKey, error) {
	row := db.QueryRow(`
		SELECT u.user_id, u.created_at, u.status,
		       uk.ssh_fingerprint, uk.user_id, uk.public_key, uk.label, uk.added_at, uk.revoked_at
		FROM user_keys uk
		JOIN users u ON u.user_id = uk.user_id
		WHERE uk.ssh_fingerprint = ?
	`, fingerprint)

	var user User
	var key UserKey
	var createdAt, addedAt string
	var revokedAt *string

	err := row.Scan(
		&user.UserID, &createdAt, &user.Status,
		&key.SSHFingerprint, &key.UserID, &key.PublicKey, &key.Label, &addedAt, &revokedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("querying user by fingerprint: %w", err)
	}

	user.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	key.AddedAt, _ = time.Parse("2006-01-02 15:04:05", addedAt)
	if revokedAt != nil {
		t, _ := time.Parse("2006-01-02 15:04:05", *revokedAt)
		key.RevokedAt = &t
	}

	return &user, &key, nil
}

// CreateUser creates a new user and links the given SSH key to them.
func CreateUser(db *sql.DB, fingerprint, publicKey string) (*User, *UserKey, error) {
	userID := NewUserID()

	tx, err := db.Begin()
	if err != nil {
		return nil, nil, fmt.Errorf("starting transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`INSERT INTO users (user_id) VALUES (?)`, userID); err != nil {
		return nil, nil, fmt.Errorf("inserting user: %w", err)
	}

	if _, err := tx.Exec(
		`INSERT INTO user_keys (ssh_fingerprint, user_id, public_key) VALUES (?, ?, ?)`,
		fingerprint, userID, publicKey,
	); err != nil {
		return nil, nil, fmt.Errorf("inserting user key: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("committing transaction: %w", err)
	}

	return FindUserByFingerprint(db, fingerprint)
}

// LinkKey adds a new SSH key to an existing user.
func LinkKey(db *sql.DB, userID, fingerprint, publicKey, label string) (*UserKey, error) {
	_, err := db.Exec(
		`INSERT INTO user_keys (ssh_fingerprint, user_id, public_key, label) VALUES (?, ?, ?, ?)`,
		fingerprint, userID, publicKey, label,
	)
	if err != nil {
		return nil, fmt.Errorf("linking key: %w", err)
	}

	return &UserKey{
		SSHFingerprint: fingerprint,
		UserID:         userID,
		PublicKey:      publicKey,
		Label:          label,
		AddedAt:        time.Now(),
	}, nil
}

// ListUserKeys returns all SSH keys linked to a user.
func ListUserKeys(db *sql.DB, userID string) ([]UserKey, error) {
	rows, err := db.Query(
		`SELECT ssh_fingerprint, user_id, public_key, label, added_at, revoked_at
		 FROM user_keys WHERE user_id = ? ORDER BY added_at`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying user keys: %w", err)
	}
	defer rows.Close()

	var keys []UserKey
	for rows.Next() {
		var k UserKey
		var addedAt string
		var revokedAt *string
		if err := rows.Scan(&k.SSHFingerprint, &k.UserID, &k.PublicKey, &k.Label, &addedAt, &revokedAt); err != nil {
			return nil, fmt.Errorf("scanning user key: %w", err)
		}
		k.AddedAt, _ = time.Parse("2006-01-02 15:04:05", addedAt)
		if revokedAt != nil {
			t, _ := time.Parse("2006-01-02 15:04:05", *revokedAt)
			k.RevokedAt = &t
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}
