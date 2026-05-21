package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// CreatePendingSignature inserts a new pending signature request. The
// caller supplies pendingMAC; it must be the HMAC over the signing
// intent fields (see crypto.KEKRing.ComputePendingMAC). Required for
// cosign rows; pass nil only for purely autonomous flows that never go
// through human approval.
func CreatePendingSignature(ctx context.Context, db *sql.DB, signingKeyID, authTokenID, requesterID, docType, payloadHash, metadata, approvalToken, signingSessionID string, pendingMAC []byte) (*PendingSignature, error) {
	id := NewPendingID()

	var tokenPtr, sessionPtr *string
	if approvalToken != "" {
		tokenPtr = &approvalToken
	}
	if signingSessionID != "" {
		sessionPtr = &signingSessionID
	}

	_, err := db.ExecContext(ctx,
		`INSERT INTO pending_signatures (id, signing_key_id, auth_token_id, requester_id, doc_type, payload_hash, metadata, approval_token, signing_session_id, pending_mac)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, signingKeyID, authTokenID, requesterID, docType, payloadHash, metadata, tokenPtr, sessionPtr, pendingMAC,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting pending signature: %w", err)
	}

	return GetPendingSignature(ctx, db, id)
}

// GetPendingSignature retrieves a pending signature by ID.
func GetPendingSignature(ctx context.Context, db *sql.DB, id string) (*PendingSignature, error) {
	row := db.QueryRowContext(ctx,
		`SELECT id, signing_key_id, auth_token_id, requester_id, doc_type, payload_hash, metadata, status, approval_token, signing_session_id, signature, pending_mac, created_at, resolved_at, resolved_by
		 FROM pending_signatures WHERE id = ?`, id,
	)
	return scanPendingRow(row)
}

func scanPendingRow(s interface{ Scan(...any) error }) (*PendingSignature, error) {
	var ps PendingSignature
	var metadata, approvalToken, signingSessionID, signature *string
	var pendingMAC []byte
	var createdAt string
	var resolvedAt, resolvedBy *string

	err := s.Scan(
		&ps.ID, &ps.SigningKeyID, &ps.AuthTokenID, &ps.RequesterID,
		&ps.DocType, &ps.PayloadHash, &metadata, &ps.Status,
		&approvalToken, &signingSessionID, &signature, &pendingMAC,
		&createdAt, &resolvedAt, &resolvedBy,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scanning pending signature: %w", err)
	}

	if metadata != nil {
		ps.Metadata = *metadata
	}
	if approvalToken != nil {
		ps.ApprovalToken = *approvalToken
	}
	if signingSessionID != nil {
		ps.SigningSessionID = *signingSessionID
	}
	if signature != nil {
		ps.Signature = *signature
	}
	ps.PendingMAC = pendingMAC
	ps.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	if resolvedAt != nil {
		t, _ := time.Parse("2006-01-02 15:04:05", *resolvedAt)
		ps.ResolvedAt = &t
	}
	if resolvedBy != nil {
		ps.ResolvedBy = *resolvedBy
	}

	return &ps, nil
}

// ListPendingSignatures returns all pending signatures for the principal (authorization granter).
// The principal is the user who created the authorization, identified by the granted_by field.
func ListPendingSignatures(ctx context.Context, db *sql.DB, principalID string) ([]PendingSignature, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT ps.id, ps.signing_key_id, ps.auth_token_id, ps.requester_id, ps.doc_type, ps.payload_hash, ps.metadata, ps.status, ps.approval_token, ps.signing_session_id, ps.signature, ps.pending_mac, ps.created_at, ps.resolved_at, ps.resolved_by
		 FROM pending_signatures ps
		 JOIN authorizations a ON ps.auth_token_id = a.token_id
		 WHERE a.granted_by = ? AND ps.status = 'pending'
		 ORDER BY ps.created_at`,
		principalID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying pending signatures: %w", err)
	}
	defer rows.Close()

	var results []PendingSignature
	for rows.Next() {
		ps, err := scanPendingRow(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, *ps)
	}
	return results, rows.Err()
}

// ListSessionPendings returns all pending signatures for a signing session.
func ListSessionPendings(ctx context.Context, db *sql.DB, sessionID string) ([]PendingSignature, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, signing_key_id, auth_token_id, requester_id, doc_type, payload_hash, metadata, status, approval_token, signing_session_id, signature, pending_mac, created_at, resolved_at, resolved_by
		 FROM pending_signatures WHERE signing_session_id = ?
		 ORDER BY created_at`, sessionID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying session pendings: %w", err)
	}
	defer rows.Close()

	var results []PendingSignature
	for rows.Next() {
		ps, err := scanPendingRow(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, *ps)
	}
	return results, rows.Err()
}

// ResolvePendingSignature marks a pending signature as approved or denied.
// If sig is non-empty, it is persisted so callers can retrieve it later.
func ResolvePendingSignature(ctx context.Context, db *sql.DB, id, status, resolvedBy, sig string) error {
	var sigPtr *string
	if sig != "" {
		sigPtr = &sig
	}
	result, err := db.ExecContext(ctx,
		`UPDATE pending_signatures SET status = ?, resolved_at = datetime('now'), resolved_by = ?, signature = ?
		 WHERE id = ? AND status = 'pending'`,
		status, resolvedBy, sigPtr, id,
	)
	if err != nil {
		return fmt.Errorf("resolving pending signature: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("pending signature %s not found or already resolved", id)
	}
	return nil
}
