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
	StatusOpen               Status = "open"
	StatusJoined             Status = "joined"
	StatusCompleted          Status = "completed"
	StatusCanceled           Status = "canceled"
	StatusRescindedAfterSign Status = "rescinded_after_sign"
	StatusExpired            Status = "expired"
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
	ErrNotFound      = errors.New("session not found")
	ErrCodeNotFound  = errors.New("session code not found")
	ErrAlreadyJoined = errors.New("session already has a member in that role")
	ErrNotMember     = errors.New("caller is not a member of this session")
	ErrNotCreator    = errors.New("only the session creator may perform this action")
	ErrTerminal      = errors.New("session is in a terminal state")
	ErrExpired       = errors.New("session has expired")
	ErrCodeCollision = errors.New("session_code collision after retries")
	ErrRateLimit     = errors.New("rate limit exceeded")
	ErrInvalidStatus = errors.New("invalid status transition")
	// ErrGroupAlreadyBound is returned by BindGroup when the session is
	// already bound to a different group_chat_id. Write-once semantics:
	// callers must cancel the session and start a new one if they want
	// to re-bind, so a leaked bind can never be silently overwritten.
	ErrGroupAlreadyBound = errors.New("session is already bound to a different group")
	// ErrFieldNotWritable is returned by UpdateSessionMemberField when
	// the requested field is not in the P7-5 whitelist. Server-side
	// defense against future whitelist expansions that might land in
	// clients but not here.
	ErrFieldNotWritable    = errors.New("field not writable via update-session-member")
	ErrLeaseHeld           = errors.New("lease is held by another holder")
	ErrLeaseNotHeld        = errors.New("lease is not held")
	ErrLeaseHolderMismatch = errors.New("lease holder mismatch")
	ErrLeaseExpired        = errors.New("lease expired")
	ErrInvalidLeaseAction  = errors.New("invalid lease action")
	ErrInvalidLeaseTTL     = errors.New("invalid lease ttl")
)

// Session is the first-class record describing a multi-party signing
// coordination. Use-case-agnostic — consumers stuff use-case-specific
// JSON into MetadataPublic and MetadataMember.
type Session struct {
	SessionID        string
	SessionCode      string
	CreatedBy        string // user_id of creator
	CreatedAt        time.Time
	ExpiresAt        time.Time
	Status           Status
	CanceledBy       string // user_id; empty unless status=canceled/rescinded
	CompletedAt      time.Time
	FinalizedBy      string // user_id; empty unless status=completed
	ExecutedArtifact string // URI to signed artifact; empty unless status=completed
	MetadataPublic   string // visible to anyone with the session_code
	MetadataMember   string // visible ONLY to members
	ViewToken        string // shareable read-only audit token; empty until issued
	GroupChatID      int64  // Telegram group chat_id (or equivalent); 0 = unbound
}

// Member represents one party in a session.
type Member struct {
	SessionID     string
	UserID        string
	Role          string
	APOAPubkeyPEM string
	PartyDID      string // optional APOA-layer identifier; empty if consumer doesn't use DIDs
	JoinedAt      time.Time
	// P7-5 durable founder-wait fields. Nil = not set yet. Founder
	// sets FounderResumedAt when a cron-triggered scan reattaches to
	// a waiting session; FounderStreamingAt once the stream is
	// actually running (investor's gate signal).
	FounderResumedAt   *int64
	FounderStreamingAt *int64
	// Inverted-invitation: each member's own Telegram bot handle.
	// Self-written by the member's own bot at create / join time.
	// Empty until the member writes it. Read by the OTHER side to
	// compose attribution-correct UI (rejection redirects, post-join
	// create-group card, investor waiting card).
	BotHandle string
	// TelegramUserID is the member's own Telegram DM/user id. It is
	// member-self-written and lets stateless recovery rebuild local
	// workflow pointers after OpenClaw reaps or loses local files.
	TelegramUserID string
}

// AuditEvent is one entry in a session's append-only transition log.
type AuditEvent struct {
	ID        int64
	SessionID string
	EventType string
	ActorID   string
	Details   string // JSON blob
	CreatedAt time.Time
}

// Lease is a short-lived exclusive claim on one session action. Generation
// is a fencing token: stale workers from older generations must fail
// check/refresh before performing irreversible side effects.
type Lease struct {
	SessionID  string
	Role       string
	Action     string
	OwnerID    string
	Holder     string
	Generation int64
	AcquiredAt time.Time
	ExpiresAt  time.Time
}

// Delivery is a durable idempotency claim for an external side effect,
// such as posting one Telegram card into a group. The first member to
// claim (session_id, key) owns that delivery; later callers receive the
// existing row and must not repeat the side effect.
type Delivery struct {
	SessionID   string
	Key         string
	Target      string
	MessageID   string
	DeliveredBy string
	DeliveredAt time.Time
}

// LeaseHeldError exposes the current holder on an ErrLeaseHeld conflict
// without requiring clients to parse an error string.
type LeaseHeldError struct {
	Holder    string
	ExpiresAt time.Time
}

func (e *LeaseHeldError) Error() string {
	return ErrLeaseHeld.Error()
}

func (e *LeaseHeldError) Unwrap() error {
	return ErrLeaseHeld
}

type AcquireLeaseParams struct {
	SessionID   string
	ActorUserID string
	Role        string
	Action      string
	Holder      string
	TTL         time.Duration
}

// Per-DID rate limits. Tuned for the demo / early production use case:
// low enough to prevent code-space enumeration, high enough that no
// legitimate user hits them. Exposed as constants so ops can tune via
// recompile if needed; env-var tunables can come later.
const (
	MaxOpenSessionsPerUser    = 10
	MaxGetSessionCallsPerHour = 1000
	MaxCodeGenerationRetries  = 10
	DefaultLeaseTTL           = 120 * time.Second
	MinLeaseTTL               = 15 * time.Second
	MaxLeaseTTL               = 300 * time.Second
)
