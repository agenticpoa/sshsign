package sessions

import (
	"errors"
	"time"
)

// Status values for a signing session. Immutable transitions — once a
// session reaches a terminal state (completed, canceled, rescinded,
// expired) it cannot transition again. Enforced at the repo layer;
// any path that writes without going through the repo can bypass, so
// keep all session writes funneled through SessionRepo.
type Status string

const (
	StatusOpen                Status = "open"
	StatusJoined              Status = "joined"
	StatusCompleted           Status = "completed"
	StatusCanceled            Status = "canceled"
	StatusRescindedAfterSign  Status = "rescinded_after_sign"
	StatusExpired             Status = "expired"
)

// IsTerminal returns true if the session has reached a final state and
// cannot transition further.
func (s Status) IsTerminal() bool {
	switch s {
	case StatusCompleted, StatusCanceled, StatusRescindedAfterSign, StatusExpired:
		return true
	}
	return false
}

// Errors returned by repo operations; callers should unwrap with errors.Is.
var (
	ErrNotFound       = errors.New("session not found")
	ErrCodeNotFound   = errors.New("session code not found")
	ErrAlreadyJoined  = errors.New("session already has a member in that role")
	ErrNotMember      = errors.New("caller is not a member of this session")
	ErrNotCreator     = errors.New("only the session creator may perform this action")
	ErrTerminal       = errors.New("session is in a terminal state")
	ErrExpired        = errors.New("session has expired")
	ErrCodeCollision  = errors.New("session_code collision after retries")
	ErrRateLimit      = errors.New("rate limit exceeded")
	ErrInvalidStatus  = errors.New("invalid status transition")
)

// Session is the first-class record describing a multi-party signing
// coordination. Use-case-agnostic — consumers stuff use-case-specific
// JSON into MetadataPublic and MetadataMember.
type Session struct {
	SessionID         string
	SessionCode       string
	CreatedBy         string // user_id of creator
	CreatedAt         time.Time
	ExpiresAt         time.Time
	Status            Status
	CanceledBy        string // user_id; empty unless status=canceled/rescinded
	CompletedAt       time.Time
	FinalizedBy       string // user_id; empty unless status=completed
	ExecutedArtifact  string // URI to signed artifact; empty unless status=completed
	MetadataPublic    string // visible to anyone with the session_code
	MetadataMember    string // visible ONLY to members
	ViewToken         string // shareable read-only audit token; empty until issued
}

// Member represents one party in a session.
type Member struct {
	SessionID      string
	UserID         string
	Role           string
	APOAPubkeyPEM  string
	PartyDID       string // optional APOA-layer identifier; empty if consumer doesn't use DIDs
	JoinedAt       time.Time
}

// AuditEvent is one entry in a session's append-only transition log.
type AuditEvent struct {
	ID         int64
	SessionID  string
	EventType  string
	ActorID    string
	Details    string // JSON blob
	CreatedAt  time.Time
}

// Per-DID rate limits. Tuned for the demo / early production use case:
// low enough to prevent code-space enumeration, high enough that no
// legitimate user hits them. Exposed as constants so ops can tune via
// recompile if needed; env-var tunables can come later.
const (
	MaxOpenSessionsPerUser    = 50
	MaxGetSessionCallsPerHour = 1000
	MaxCodeGenerationRetries  = 10
)
