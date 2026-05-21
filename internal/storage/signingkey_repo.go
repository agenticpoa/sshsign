package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// CreateSigningKey stores a new signing key with its encrypted private key and DEK.
func CreateSigningKey(ctx context.Context, db *sql.DB, ownerID, publicKey string, encPrivKey, encDEK []byte, kekAlgo string) (*SigningKey, error) {
	keyID := NewKeyID()

	_, err := db.ExecContext(ctx,
		`INSERT INTO signing_keys (key_id, owner_id, public_key, private_key_encrypted, dek_encrypted, kek_algo)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		keyID, ownerID, publicKey, encPrivKey, encDEK, kekAlgo,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting signing key: %w", err)
	}

	return GetSigningKey(ctx, db, keyID)
}

// CreateSigningKeyWithID stores a new signing key using a pre-generated key ID.
func CreateSigningKeyWithID(ctx context.Context, db *sql.DB, keyID, ownerID, publicKey string, encPrivKey, encDEK []byte, kekAlgo string) (*SigningKey, error) {
	_, err := db.ExecContext(ctx,
		`INSERT INTO signing_keys (key_id, owner_id, public_key, private_key_encrypted, dek_encrypted, kek_algo)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		keyID, ownerID, publicKey, encPrivKey, encDEK, kekAlgo,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting signing key: %w", err)
	}

	return GetSigningKey(ctx, db, keyID)
}

// GetSigningKey retrieves a signing key by its ID.
func GetSigningKey(ctx context.Context, db *sql.DB, keyID string) (*SigningKey, error) {
	row := db.QueryRowContext(ctx,
		`SELECT key_id, owner_id, public_key, private_key_encrypted, dek_encrypted, created_at, revoked_at, sign_count, last_used_at, kek_algo
		 FROM signing_keys WHERE key_id = ?`,
		keyID,
	)

	sk, err := scanSigningKey(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying signing key: %w", err)
	}
	return sk, nil
}

// ListSigningKeys returns all signing keys owned by a user.
func ListSigningKeys(ctx context.Context, db *sql.DB, ownerID string) ([]SigningKey, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT key_id, owner_id, public_key, private_key_encrypted, dek_encrypted, created_at, revoked_at, sign_count, last_used_at, kek_algo
		 FROM signing_keys WHERE owner_id = ? ORDER BY created_at`,
		ownerID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying signing keys: %w", err)
	}
	defer rows.Close()

	var keys []SigningKey
	for rows.Next() {
		sk, err := scanSigningKey(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning signing key: %w", err)
		}
		keys = append(keys, *sk)
	}
	return keys, rows.Err()
}

type signingKeyScannable interface {
	Scan(dest ...any) error
}

func scanSigningKey(s signingKeyScannable) (*SigningKey, error) {
	var sk SigningKey
	var createdAt string
	var revokedAt, lastUsedAt *string

	err := s.Scan(&sk.KeyID, &sk.OwnerID, &sk.PublicKey, &sk.PrivateKeyEncrypted, &sk.DEKEncrypted, &createdAt, &revokedAt, &sk.SignCount, &lastUsedAt, &sk.KEKAlgo)
	if err != nil {
		return nil, err
	}

	sk.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	if revokedAt != nil {
		t, _ := time.Parse("2006-01-02 15:04:05", *revokedAt)
		sk.RevokedAt = &t
	}
	if lastUsedAt != nil {
		t, _ := time.Parse("2006-01-02 15:04:05", *lastUsedAt)
		sk.LastUsedAt = &t
	}

	return &sk, nil
}

// RecordKeyUsage increments the sign count and updates the last used timestamp.
func RecordKeyUsage(ctx context.Context, db *sql.DB, keyID string) {
	db.ExecContext(ctx,
		`UPDATE signing_keys SET sign_count = sign_count + 1, last_used_at = datetime('now') WHERE key_id = ?`,
		keyID,
	)
}

// RevokeSigningKey marks a signing key as revoked.
func RevokeSigningKey(ctx context.Context, db *sql.DB, keyID string) error {
	result, err := db.ExecContext(ctx,
		`UPDATE signing_keys SET revoked_at = datetime('now') WHERE key_id = ? AND revoked_at IS NULL`,
		keyID,
	)
	if err != nil {
		return fmt.Errorf("revoking signing key: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("signing key %s not found or already revoked", keyID)
	}
	return nil
}
