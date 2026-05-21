package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// CreateNegotiationOffer logs a new offer in a negotiation chain.
func CreateNegotiationOffer(ctx context.Context, db *sql.DB, negotiationID string, round int, fromParty, offerType, metadata string, previousTx, auditTxID uint64, userID string) (*NegotiationOffer, error) {
	id := NewOfferID()

	_, err := db.ExecContext(ctx,
		`INSERT INTO negotiation_offers (id, negotiation_id, round, from_party, offer_type, metadata, previous_tx, audit_tx_id, user_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, negotiationID, round, fromParty, offerType, metadata, previousTx, auditTxID, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting negotiation offer: %w", err)
	}

	return GetNegotiationOffer(ctx, db, id)
}

// GetNegotiationOffer retrieves an offer by its ID.
func GetNegotiationOffer(ctx context.Context, db *sql.DB, id string) (*NegotiationOffer, error) {
	row := db.QueryRowContext(ctx,
		`SELECT id, negotiation_id, round, from_party, offer_type, metadata, previous_tx, audit_tx_id, user_id, created_at
		 FROM negotiation_offers WHERE id = ?`, id,
	)

	var o NegotiationOffer
	var createdAt string
	err := row.Scan(&o.ID, &o.NegotiationID, &o.Round, &o.FromParty, &o.OfferType, &o.Metadata, &o.PreviousTx, &o.AuditTxID, &o.UserID, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scanning negotiation offer: %w", err)
	}
	o.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	return &o, nil
}

// ListNegotiationOffers returns all offers for a negotiation, ordered by round.
func ListNegotiationOffers(ctx context.Context, db *sql.DB, negotiationID string) ([]NegotiationOffer, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, negotiation_id, round, from_party, offer_type, metadata, previous_tx, audit_tx_id, user_id, created_at
		 FROM negotiation_offers WHERE negotiation_id = ?
		 ORDER BY round, created_at`, negotiationID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying negotiation offers: %w", err)
	}
	defer rows.Close()

	var offers []NegotiationOffer
	for rows.Next() {
		var o NegotiationOffer
		var createdAt string
		err := rows.Scan(&o.ID, &o.NegotiationID, &o.Round, &o.FromParty, &o.OfferType, &o.Metadata, &o.PreviousTx, &o.AuditTxID, &o.UserID, &createdAt)
		if err != nil {
			return nil, fmt.Errorf("scanning negotiation offer row: %w", err)
		}
		o.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		offers = append(offers, o)
	}
	return offers, rows.Err()
}

// GetLastOffer returns the most recent offer in a negotiation, or nil if none exist.
func GetLastOffer(ctx context.Context, db *sql.DB, negotiationID string) (*NegotiationOffer, error) {
	row := db.QueryRowContext(ctx,
		`SELECT id, negotiation_id, round, from_party, offer_type, metadata, previous_tx, audit_tx_id, user_id, created_at
		 FROM negotiation_offers WHERE negotiation_id = ?
		 ORDER BY round DESC, created_at DESC LIMIT 1`, negotiationID,
	)

	var o NegotiationOffer
	var createdAt string
	err := row.Scan(&o.ID, &o.NegotiationID, &o.Round, &o.FromParty, &o.OfferType, &o.Metadata, &o.PreviousTx, &o.AuditTxID, &o.UserID, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying last offer: %w", err)
	}
	o.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	return &o, nil
}

// FindOfferByAuditTx checks if an offer with the given audit_tx_id exists.
func FindOfferByAuditTx(ctx context.Context, db *sql.DB, auditTxID uint64) (*NegotiationOffer, error) {
	row := db.QueryRowContext(ctx,
		`SELECT id, negotiation_id, round, from_party, offer_type, metadata, previous_tx, audit_tx_id, user_id, created_at
		 FROM negotiation_offers WHERE audit_tx_id = ?`, auditTxID,
	)

	var o NegotiationOffer
	var createdAt string
	err := row.Scan(&o.ID, &o.NegotiationID, &o.Round, &o.FromParty, &o.OfferType, &o.Metadata, &o.PreviousTx, &o.AuditTxID, &o.UserID, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scanning negotiation offer: %w", err)
	}
	o.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	return &o, nil
}
