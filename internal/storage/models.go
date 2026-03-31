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
}

type Authorization struct {
	TokenID      string
	SigningKeyID string
	GrantedBy    string   // user_id of who created this (always key owner in v1)
	Scopes       []string // e.g. ["git-commit"]
	Constraints  map[string][]string // e.g. {"repos": ["github.com/user/*"]}
	HardRules    []string // e.g. ["never sign to main branch"]
	SoftRules    []string // e.g. ["alert if >10 sigs/hour"]
	ExpiresAt    *time.Time
	RevokedAt    *time.Time
	CreatedAt    time.Time
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
