package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// CreateAuthorization creates a new authorization token for a signing key.
func CreateAuthorization(db *sql.DB, signingKeyID, grantedBy string, scopes []string, constraints map[string][]string, hardRules, softRules []string, expiresAt *time.Time) (*Authorization, error) {
	return CreateAuthorizationFull(db, signingKeyID, grantedBy, scopes, constraints, nil, "", false, hardRules, softRules, expiresAt)
}

// CreateAuthorizationFull creates an authorization with all fields including metadata constraints and confirmation tier.
func CreateAuthorizationFull(db *sql.DB, signingKeyID, grantedBy string, scopes []string, constraints map[string][]string, metadataConstraints []MetadataConstraint, confirmationTier string, requireSignature bool, hardRules, softRules []string, expiresAt *time.Time) (*Authorization, error) {
	tokenID := NewTokenID()

	if confirmationTier == "" {
		confirmationTier = "autonomous"
	}

	scopesJSON, _ := json.Marshal(scopes)
	constraintsJSON, _ := json.Marshal(constraints)
	metadataConstraintsJSON, _ := json.Marshal(metadataConstraints)
	hardRulesJSON, _ := json.Marshal(hardRules)
	softRulesJSON, _ := json.Marshal(softRules)

	var expiresAtStr *string
	if expiresAt != nil {
		s := expiresAt.Format("2006-01-02 15:04:05")
		expiresAtStr = &s
	}

	_, err := db.Exec(
		`INSERT INTO authorizations (token_id, signing_key_id, granted_by, scopes, constraints, metadata_constraints, confirmation_tier, require_signature, hard_rules, soft_rules, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		tokenID, signingKeyID, grantedBy,
		string(scopesJSON), string(constraintsJSON), string(metadataConstraintsJSON), confirmationTier, requireSignature,
		string(hardRulesJSON), string(softRulesJSON),
		expiresAtStr,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting authorization: %w", err)
	}

	return GetAuthorization(db, tokenID)
}

// GetAuthorization retrieves an authorization by its token ID.
func GetAuthorization(db *sql.DB, tokenID string) (*Authorization, error) {
	row := db.QueryRow(
		`SELECT token_id, signing_key_id, granted_by, scopes, constraints, metadata_constraints, confirmation_tier, require_signature, hard_rules, soft_rules, expires_at, revoked_at, created_at
		 FROM authorizations WHERE token_id = ?`,
		tokenID,
	)
	return scanAuthorization(row)
}

// FindAuthorizationsForKey returns all active (non-revoked, non-expired) authorizations for a signing key.
func FindAuthorizationsForKey(db *sql.DB, signingKeyID string) ([]Authorization, error) {
	rows, err := db.Query(
		`SELECT token_id, signing_key_id, granted_by, scopes, constraints, metadata_constraints, confirmation_tier, require_signature, hard_rules, soft_rules, expires_at, revoked_at, created_at
		 FROM authorizations
		 WHERE signing_key_id = ? AND revoked_at IS NULL
		 ORDER BY created_at`,
		signingKeyID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying authorizations: %w", err)
	}
	defer rows.Close()

	var auths []Authorization
	for rows.Next() {
		auth, err := scanAuthorizationRow(rows)
		if err != nil {
			return nil, err
		}
		auths = append(auths, *auth)
	}
	return auths, rows.Err()
}

// RevokeAuthorization marks an authorization as revoked.
func RevokeAuthorization(db *sql.DB, tokenID string) error {
	result, err := db.Exec(
		`UPDATE authorizations SET revoked_at = datetime('now') WHERE token_id = ? AND revoked_at IS NULL`,
		tokenID,
	)
	if err != nil {
		return fmt.Errorf("revoking authorization: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("authorization %s not found or already revoked", tokenID)
	}
	return nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanAuthorizationFields(s scannable) (*Authorization, error) {
	var auth Authorization
	var scopesJSON, constraintsJSON, metadataConstraintsJSON, hardRulesJSON, softRulesJSON string
	var createdAt string
	var expiresAt, revokedAt *string

	err := s.Scan(
		&auth.TokenID, &auth.SigningKeyID, &auth.GrantedBy,
		&scopesJSON, &constraintsJSON, &metadataConstraintsJSON, &auth.ConfirmationTier, &auth.RequireSignature,
		&hardRulesJSON, &softRulesJSON,
		&expiresAt, &revokedAt, &createdAt,
	)
	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(scopesJSON), &auth.Scopes)
	json.Unmarshal([]byte(constraintsJSON), &auth.Constraints)
	json.Unmarshal([]byte(metadataConstraintsJSON), &auth.MetadataConstraints)
	json.Unmarshal([]byte(hardRulesJSON), &auth.HardRules)
	json.Unmarshal([]byte(softRulesJSON), &auth.SoftRules)

	auth.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	if expiresAt != nil {
		t, _ := time.Parse("2006-01-02 15:04:05", *expiresAt)
		auth.ExpiresAt = &t
	}
	if revokedAt != nil {
		t, _ := time.Parse("2006-01-02 15:04:05", *revokedAt)
		auth.RevokedAt = &t
	}

	return &auth, nil
}

func scanAuthorization(row *sql.Row) (*Authorization, error) {
	auth, err := scanAuthorizationFields(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scanning authorization: %w", err)
	}
	return auth, nil
}

func scanAuthorizationRow(rows *sql.Rows) (*Authorization, error) {
	auth, err := scanAuthorizationFields(rows)
	if err != nil {
		return nil, fmt.Errorf("scanning authorization row: %w", err)
	}
	return auth, nil
}
