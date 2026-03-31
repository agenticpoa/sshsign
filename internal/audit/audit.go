package audit

import (
	"encoding/json"
	"fmt"
	"time"
)

// Entry represents an immutable audit log entry.
type Entry struct {
	TxID               uint64    `json:"tx_id"`
	Timestamp          time.Time `json:"timestamp"`
	UserID             string    `json:"user_id"`
	SigningKeyID       string    `json:"signing_key_id"`
	ActionType         string    `json:"action_type"`
	PayloadHash        string    `json:"payload_hash"`
	AuthorizationToken string    `json:"authorization_token_id"`
	ScopesChecked      []string  `json:"scopes_checked,omitempty"`
	RulesEvaluated     []string  `json:"rules_evaluated,omitempty"`
	Result             string    `json:"result"` // "SIGNED" | "DENIED" | "REVOKED"
	DenialReason       string    `json:"denial_reason,omitempty"`
	Signature          string    `json:"signature,omitempty"`
}

// Logger defines the interface for the immutable audit log.
// The primary implementation uses immudb. A memory-based implementation
// is provided for testing.
type Logger interface {
	// Log writes an audit entry and returns the transaction ID.
	// This is synchronous: if the log is unavailable, it returns an error
	// and the signing operation must fail.
	Log(entry Entry) (uint64, error)

	// Get retrieves an audit entry by its key (action_type:tx_id).
	Get(key string) (*Entry, error)

	// Verify checks that an audit entry hasn't been tampered with.
	Verify(key string) (bool, error)

	// Healthy returns true if the audit log backend is reachable.
	Healthy() bool

	// Close releases resources.
	Close() error
}

// EntryKey generates the immudb key for an audit entry.
func EntryKey(actionType string, txID uint64) string {
	return fmt.Sprintf("audit:%s:%d", actionType, txID)
}

// MarshalEntry serializes an audit entry to JSON for storage.
func MarshalEntry(e Entry) ([]byte, error) {
	return json.Marshal(e)
}

// UnmarshalEntry deserializes an audit entry from JSON.
func UnmarshalEntry(data []byte) (*Entry, error) {
	var e Entry
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	return &e, nil
}
