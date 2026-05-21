package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

// ChainKeyInfo is the HKDF info string for deriving an audit-chain HMAC
// key from a server secret. Versioned so a key rotation is a single
// constant edit; existing chains would fail verification afterward.
const ChainKeyInfo = "sshsign-audit-chain-v1"

// DeriveChainKey returns the HMAC-SHA256 key that should be threaded
// into MemoryLogger so the chain survives restarts under the same
// server secret. Derived via HKDF-Expand from the caller's existing
// key material (e.g., the current KEK) so we don't introduce a new
// secret to manage.
func DeriveChainKey(material []byte) []byte {
	out := make([]byte, 32)
	h := hkdf.Expand(sha256.New, material, []byte(ChainKeyInfo))
	_, _ = io.ReadFull(h, out)
	return out
}

// computeEntryHash returns HMAC-SHA256 of the entry's canonical JSON
// form (with EntryHash blanked) keyed by chainKey. Used by both the
// writer (to fill EntryHash on insert) and the verifier (to recompute
// and constant-time-compare on read).
func computeEntryHash(chainKey []byte, e Entry) (string, error) {
	e.EntryHash = ""
	canonical, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("marshaling for chain hash: %w", err)
	}
	mac := hmac.New(sha256.New, chainKey)
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Entry represents an immutable audit log entry.
//
// PrevHash and EntryHash form a hash chain: each entry's EntryHash is
// HMAC-SHA256 over the entry's canonical JSON (with EntryHash blanked)
// keyed by the logger's chain key. Modifying or deleting any entry
// breaks every chain pointer that follows it. See [MemoryLogger.VerifyChain].
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
	PrevHash           string    `json:"prev_hash,omitempty"`  // hex EntryHash of the previous entry, "" at genesis
	EntryHash          string    `json:"entry_hash,omitempty"` // hex HMAC of this entry's canonical form
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

	// VerifyChain walks every committed entry and rejects the first
	// integrity break. For the memory logger this walks the HMAC
	// chain in TxID order; for immudb it relies on the backend's
	// signed Merkle root and verifies every entry's inclusion. nil
	// means the whole log is consistent.
	VerifyChain() error

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
