package storage

import (
	"encoding/json"
	"time"
)

type User struct {
	UserID    string
	CreatedAt time.Time
	Status    string // "active" | "suspended"
}

type UserKey struct {
	SSHFingerprint string
	UserID         string
	PublicKey      string // ssh-ed25519 AAAA...
	Label          string
	AddedAt        time.Time
	RevokedAt      *time.Time
}

type SigningKey struct {
	KeyID               string
	OwnerID             string
	PublicKey           string // ssh-ed25519 AAAA...
	PrivateKeyEncrypted []byte
	DEKEncrypted        []byte
	CreatedAt           time.Time
	RevokedAt           *time.Time
	SignCount           int
	LastUsedAt          *time.Time
}

// MetadataConstraint defines a typed constraint on a metadata field.
// Used to validate request metadata against authorization boundaries.
type MetadataConstraint struct {
	Type     string   `json:"type"`               // "range", "minimum", "maximum", "enum", "required_bool"
	Field    string   `json:"field"`               // metadata field name
	Min      *float64 `json:"min,omitempty"`       // for range, minimum
	Max      *float64 `json:"max,omitempty"`       // for range, maximum
	Allowed  []string `json:"allowed,omitempty"`   // for enum
	Required *bool    `json:"required,omitempty"`   // for required_bool
}

type Authorization struct {
	TokenID             string
	SigningKeyID        string
	GrantedBy           string               // user_id of who created this (always key owner in v1)
	Scopes              []string             // e.g. ["git-commit"]
	Constraints         map[string][]string  // e.g. {"repos": ["github.com/user/*"]}
	MetadataConstraints []MetadataConstraint // typed constraints on metadata fields
	ConfirmationTier    string               // "autonomous" (default) or "cosign"
	HardRules           []string             // e.g. ["never sign to main branch"]
	SoftRules           []string             // e.g. ["alert if >10 sigs/hour"]
	ExpiresAt           *time.Time
	RevokedAt           *time.Time
	CreatedAt           time.Time
}

// PendingSignature represents a signature request held for co-sign approval.
type PendingSignature struct {
	ID           string
	SigningKeyID string
	AuthTokenID  string
	RequesterID  string
	DocType      string
	PayloadHash  string
	Metadata     string // JSON string
	Status       string // "pending", "approved", "denied"
	CreatedAt    time.Time
	ResolvedAt   *time.Time
	ResolvedBy   string
}

// NegotiationOffer represents a single offer in a negotiation chain.
type NegotiationOffer struct {
	ID            string
	NegotiationID string
	Round         int
	FromParty     string
	OfferType     string // "offer", "counter", "accept", "reject"
	Metadata      string // JSON string
	PreviousTx    uint64
	AuditTxID     uint64
	UserID        string
	CreatedAt     time.Time
}

// ScopesJSON returns scopes as a JSON string for storage.
func (a *Authorization) ScopesJSON() string {
	b, _ := json.Marshal(a.Scopes)
	return string(b)
}

// ConstraintsJSON returns constraints as a JSON string for storage.
func (a *Authorization) ConstraintsJSON() string {
	b, _ := json.Marshal(a.Constraints)
	return string(b)
}

// MetadataConstraintsJSON returns metadata constraints as a JSON string for storage.
func (a *Authorization) MetadataConstraintsJSON() string {
	b, _ := json.Marshal(a.MetadataConstraints)
	return string(b)
}

// HardRulesJSON returns hard rules as a JSON string for storage.
func (a *Authorization) HardRulesJSON() string {
	b, _ := json.Marshal(a.HardRules)
	return string(b)
}

// SoftRulesJSON returns soft rules as a JSON string for storage.
func (a *Authorization) SoftRulesJSON() string {
	b, _ := json.Marshal(a.SoftRules)
	return string(b)
}
