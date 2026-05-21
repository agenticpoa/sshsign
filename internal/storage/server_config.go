package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
)

// kekSaltBytes is the length of the random salt fed to Argon2id when
// deriving the server's current KEK. 32 bytes is well above the 16-byte
// minimum enforced in crypto.DeriveKEKArgon2id and gives generous margin.
const kekSaltBytes = 32

// GetOrCreateKEKSalt returns the persisted KEK salt, generating and
// inserting a fresh one on first call. Subsequent calls return the same
// bytes so the Argon2id KEK is reproducible across server restarts.
//
// The salt is stored next to the wrapped DEKs in the same database;
// backup/restore must move them together or every signing key is lost.
func GetOrCreateKEKSalt(ctx context.Context, db *sql.DB) ([]byte, error) {
	var salt []byte
	err := db.QueryRowContext(ctx, `SELECT kek_salt FROM server_config WHERE id = 1`).Scan(&salt)
	if err == nil {
		if len(salt) < 16 {
			return nil, fmt.Errorf("stored KEK salt is too short (%d bytes)", len(salt))
		}
		return salt, nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("reading kek salt: %w", err)
	}

	fresh := make([]byte, kekSaltBytes)
	if _, err := rand.Read(fresh); err != nil {
		return nil, fmt.Errorf("generating kek salt: %w", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO server_config (id, kek_salt) VALUES (1, ?)`, fresh); err != nil {
		return nil, fmt.Errorf("persisting kek salt: %w", err)
	}
	return fresh, nil
}
