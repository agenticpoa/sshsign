package sessions

import (
	cryptoRand "crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Repo is the only supported way to read/write signing_sessions. All
// state transitions are gated here; no ad-hoc SQL from callers.
type Repo struct {
	db *sql.DB

	// Injectable for tests — default is time.Now.
	now func() time.Time
}

// NewRepo returns a Repo backed by the given db.
func NewRepo(db *sql.DB) *Repo {
	return &Repo{db: db, now: time.Now}
}

// CreateParams groups arguments for creating a new session.
type CreateParams struct {
	SessionID        string        // caller supplies — typically reuses an existing neg_XXX id
	CreatorUserID    string        // resolved sshsign user id (SSH auth truth)
	CreatorRole      string        // free-form; consumer-specific (founder/investor/party_1/…)
	CreatorAPOAPub   string        // PEM-encoded APOA pubkey
	CreatorPartyDID  string        // optional — empty string if consumer doesn't use DIDs
	TTL              time.Duration // time until session expires; defaults to 24h if zero
	MetadataPublic   string        // visible to anyone with the code; defaults to "{}"
	MetadataMember   string        // visible only to members; defaults to "{}"
}

// Create inserts a new session + the creator's member row in one
// transaction. Generates a unique session_code with retry-on-collision.
// Enforces the open-sessions-per-user rate limit.
func (r *Repo) Create(p CreateParams) (*Session, error) {
	if p.SessionID == "" {
		return nil, errors.New("session_id required")
	}
	if p.CreatorUserID == "" {
		return nil, errors.New("creator user_id required")
	}
	if p.CreatorRole == "" {
		return nil, errors.New("creator role required")
	}
	if p.CreatorAPOAPub == "" {
		return nil, errors.New("creator APOA pubkey required")
	}
	if p.TTL <= 0 {
		p.TTL = 24 * time.Hour
	}
	if p.MetadataPublic == "" {
		p.MetadataPublic = "{}"
	}
	if p.MetadataMember == "" {
		p.MetadataMember = "{}"
	}

	// Rate limit: how many open sessions does this user already have?
	var openCount int
	err := r.db.QueryRow(
		`SELECT COUNT(*) FROM signing_sessions
		 WHERE created_by = ? AND status = 'open'`,
		p.CreatorUserID,
	).Scan(&openCount)
	if err != nil {
		return nil, fmt.Errorf("counting open sessions: %w", err)
	}
	if openCount >= MaxOpenSessionsPerUser {
		return nil, fmt.Errorf("%w: %d open sessions (max %d)",
			ErrRateLimit, openCount, MaxOpenSessionsPerUser)
	}

	now := r.now().UTC()
	expiresAt := now.Add(p.TTL)

	tx, err := r.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Generate a session_code; retry on UNIQUE collision.
	var code string
	for attempt := 0; attempt < MaxCodeGenerationRetries; attempt++ {
		code, err = GenerateCode()
		if err != nil {
			return nil, fmt.Errorf("generate code: %w", err)
		}
		_, err = tx.Exec(
			`INSERT INTO signing_sessions
			   (session_id, session_code, created_by, created_at, expires_at,
			    status, metadata_public, metadata_member)
			 VALUES (?, ?, ?, ?, ?, 'open', ?, ?)`,
			p.SessionID, code, p.CreatorUserID,
			now.Format(time.RFC3339Nano), expiresAt.Format(time.RFC3339Nano),
			p.MetadataPublic, p.MetadataMember,
		)
		if err == nil {
			break
		}
		if isUniqueConflict(err, "session_code") {
			continue // retry with fresh code
		}
		if isUniqueConflict(err, "session_id") {
			return nil, fmt.Errorf("session_id %q already exists", p.SessionID)
		}
		return nil, fmt.Errorf("insert session: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCodeCollision, err)
	}

	_, err = tx.Exec(
		`INSERT INTO signing_session_members
		   (session_id, user_id, role, apoa_pubkey_pem, party_did, joined_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		p.SessionID, p.CreatorUserID, p.CreatorRole,
		p.CreatorAPOAPub, p.CreatorPartyDID, now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, fmt.Errorf("insert creator member: %w", err)
	}

	if err := writeAudit(tx, p.SessionID, "created", p.CreatorUserID, ""); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return &Session{
		SessionID:      p.SessionID,
		SessionCode:    code,
		CreatedBy:      p.CreatorUserID,
		CreatedAt:      now,
		ExpiresAt:      expiresAt,
		Status:         StatusOpen,
		MetadataPublic: p.MetadataPublic,
		MetadataMember: p.MetadataMember,
	}, nil
}

// JoinParams — inputs for Join.
type JoinParams struct {
	SessionCode    string
	UserID         string
	Role           string
	APOAPubkeyPEM  string
	PartyDID       string
}

// Join adds a member to an existing session, transitioning status to
// 'joined' if it was 'open'. Rejects if the session is terminal,
// expired, or already has a member in the same role.
func (r *Repo) Join(p JoinParams) (*Session, error) {
	if p.SessionCode == "" || p.UserID == "" || p.Role == "" || p.APOAPubkeyPEM == "" {
		return nil, errors.New("session_code, user_id, role, apoa_pubkey required")
	}

	tx, err := r.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	sess, err := getByCodeTx(tx, p.SessionCode)
	if err != nil {
		return nil, err
	}

	if sess.Status.IsTerminal() {
		return nil, fmt.Errorf("%w: %s", ErrTerminal, sess.Status)
	}
	if r.now().After(sess.ExpiresAt) {
		// Opportunistic expiration: mark the session expired on the way out
		_ = markExpiredTx(tx, sess.SessionID, r.now())
		_ = tx.Commit()
		return nil, ErrExpired
	}

	// Role-slot check: reject if someone else already claimed this role.
	var existingID string
	err = tx.QueryRow(
		`SELECT user_id FROM signing_session_members
		 WHERE session_id = ? AND role = ?`,
		sess.SessionID, p.Role,
	).Scan(&existingID)
	if err == nil {
		if existingID == p.UserID {
			// Idempotent rejoin by same user — return current state.
			return r.getByIDTx(tx, sess.SessionID)
		}
		return nil, fmt.Errorf("%w: role %q", ErrAlreadyJoined, p.Role)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("role slot check: %w", err)
	}

	joinedAt := r.now().UTC()
	_, err = tx.Exec(
		`INSERT INTO signing_session_members
		   (session_id, user_id, role, apoa_pubkey_pem, party_did, joined_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sess.SessionID, p.UserID, p.Role, p.APOAPubkeyPEM, p.PartyDID,
		joinedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, fmt.Errorf("insert member: %w", err)
	}

	// Transition open → joined on first non-creator join.
	if sess.Status == StatusOpen {
		_, err = tx.Exec(
			`UPDATE signing_sessions SET status = 'joined' WHERE session_id = ?`,
			sess.SessionID,
		)
		if err != nil {
			return nil, fmt.Errorf("update status: %w", err)
		}
	}

	if err := writeAudit(tx, sess.SessionID, "joined", p.UserID,
		fmt.Sprintf(`{"role":%q}`, p.Role)); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return r.GetByID(sess.SessionID)
}

// GetByCode fetches by session_code (for prospective joiners).
func (r *Repo) GetByCode(code string) (*Session, error) {
	tx, err := r.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	sess, err := getByCodeTx(tx, code)
	if err != nil {
		return nil, err
	}
	return sess, tx.Commit()
}

// GetByID fetches by session_id.
func (r *Repo) GetByID(id string) (*Session, error) {
	tx, err := r.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	sess, err := r.getByIDTx(tx, id)
	if err != nil {
		return nil, err
	}
	return sess, tx.Commit()
}

// ──────────────────────────────────────────────────────────────
// Rate limiter for get-session (in-memory sliding window per user).
// ──────────────────────────────────────────────────────────────

// GetSessionRateLimiter tracks per-user get-session call counts in a
// sliding 1-hour window. Shared across all Repo instances via the
// server's SessionContext. Kept separate from Repo so it can be
// composed at the handler layer (the repo itself doesn't know about
// callers — it just reads the DB).
type GetSessionRateLimiter struct {
	mu      sync.Mutex
	windows map[string]*userWindow
	limit   int
	period  time.Duration

	// Injectable for tests.
	now func() time.Time
}

type userWindow struct {
	timestamps []time.Time
}

// NewGetSessionRateLimiter returns a limiter capped at
// MaxGetSessionCallsPerHour per user over a 1-hour sliding window.
func NewGetSessionRateLimiter() *GetSessionRateLimiter {
	return &GetSessionRateLimiter{
		windows: make(map[string]*userWindow),
		limit:   MaxGetSessionCallsPerHour,
		period:  time.Hour,
		now:     time.Now,
	}
}

// Allow returns nil if the user is under quota; otherwise ErrRateLimit.
// Records the current call so repeated callers get incrementally rejected.
func (l *GetSessionRateLimiter) Allow(userID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	cutoff := now.Add(-l.period)

	w, ok := l.windows[userID]
	if !ok {
		w = &userWindow{}
		l.windows[userID] = w
	}

	// Drop expired timestamps from the head of the window.
	i := 0
	for ; i < len(w.timestamps); i++ {
		if !w.timestamps[i].Before(cutoff) {
			break
		}
	}
	if i > 0 {
		w.timestamps = w.timestamps[i:]
	}

	if len(w.timestamps) >= l.limit {
		return fmt.Errorf("%w: %d get-session calls in the past %s (max %d)",
			ErrRateLimit, len(w.timestamps), l.period, l.limit)
	}
	w.timestamps = append(w.timestamps, now)
	return nil
}

// Members returns all members of a session.
func (r *Repo) Members(sessionID string) ([]Member, error) {
	rows, err := r.db.Query(
		`SELECT session_id, user_id, role, apoa_pubkey_pem, party_did, joined_at,
		        founder_resumed_at, founder_streaming_at
		 FROM signing_session_members WHERE session_id = ? ORDER BY joined_at`,
		sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Member
	for rows.Next() {
		var m Member
		var joinedAt string
		var resumedAt, streamingAt sql.NullInt64
		if err := rows.Scan(&m.SessionID, &m.UserID, &m.Role, &m.APOAPubkeyPEM,
			&m.PartyDID, &joinedAt, &resumedAt, &streamingAt); err != nil {
			return nil, err
		}
		m.JoinedAt, _ = time.Parse(time.RFC3339Nano, joinedAt)
		if resumedAt.Valid {
			v := resumedAt.Int64
			m.FounderResumedAt = &v
		}
		if streamingAt.Valid {
			v := streamingAt.Int64
			m.FounderStreamingAt = &v
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// updatableMemberFields is the whitelist of columns writable via
// UpdateSessionMemberField. Introduced for P7-5 durable founder-wait.
// New fields land here intentionally; defaulting to closed means the
// RPC can never be coerced into touching anything else (session-id,
// role, joined_at, pubkey, etc.).
var updatableMemberFields = map[string]bool{
	"founder_resumed_at":   true,
	"founder_streaming_at": true,
}

// UpdateSessionMemberField sets a whitelisted integer column on the
// caller's own member row. Creator-only — the founder is always the
// creator, and P7-5's semantics are founder-only. Non-whitelisted
// fields return ErrFieldNotWritable; any attempt to update another
// member's row is silently a no-op since the WHERE clause binds to
// actorUserID.
//
// Terminal sessions accept updates silently (idempotent after
// completion); callers shouldn't be pinging update_session_member on
// a terminal session in practice, but guarding against it here would
// prevent the scan turn from recording its dedup attempt cleanly.
func (r *Repo) UpdateSessionMemberField(
	sessionID, actorUserID, field string, value int64,
) error {
	if !updatableMemberFields[field] {
		return fmt.Errorf("%w: %q", ErrFieldNotWritable, field)
	}

	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	sess, err := r.getByIDTx(tx, sessionID)
	if err != nil {
		return err
	}
	if sess.CreatedBy != actorUserID {
		return ErrNotCreator
	}

	// Field name is validated by the whitelist above, so string
	// concatenation into the SQL is safe here (not user-controlled).
	res, err := tx.Exec(
		`UPDATE signing_session_members
		 SET `+field+` = ?
		 WHERE session_id = ? AND user_id = ?`,
		value, sessionID, actorUserID,
	)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		// Session exists and caller is creator, but no member row —
		// sshsign's create-session always inserts the creator as a
		// member, so this can only happen if someone deleted the
		// row out of band. Surface it rather than silently no-op.
		return fmt.Errorf("%w: creator has no member row", ErrNotMember)
	}

	details := fmt.Sprintf(`{"field":%q,"value":%d}`, field, value)
	if err := writeAudit(tx, sessionID, "member_field_updated", actorUserID, details); err != nil {
		return err
	}

	return tx.Commit()
}

// IsMember returns true if userID is a member of the session.
func (r *Repo) IsMember(sessionID, userID string) (bool, error) {
	var exists int
	err := r.db.QueryRow(
		`SELECT 1 FROM signing_session_members WHERE session_id = ? AND user_id = ?`,
		sessionID, userID,
	).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// Cancel transitions a session to 'canceled' (pre-agreement) or
// 'rescinded_after_sign' (post-first-signature). The caller decides
// which state semantically applies — this method trusts the caller
// to pass the right target status. Callers pass either StatusCanceled
// or StatusRescindedAfterSign.
func (r *Repo) Cancel(sessionID, actorUserID string, target Status) (*Session, error) {
	if target != StatusCanceled && target != StatusRescindedAfterSign {
		return nil, fmt.Errorf("%w: %s", ErrInvalidStatus, target)
	}

	tx, err := r.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	sess, err := r.getByIDTx(tx, sessionID)
	if err != nil {
		return nil, err
	}
	if sess.Status.IsTerminal() {
		return nil, fmt.Errorf("%w: already %s", ErrTerminal, sess.Status)
	}

	var isMember int
	err = tx.QueryRow(
		`SELECT 1 FROM signing_session_members
		 WHERE session_id = ? AND user_id = ?`,
		sessionID, actorUserID,
	).Scan(&isMember)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotMember
	}
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(
		`UPDATE signing_sessions SET status = ?, canceled_by = ? WHERE session_id = ?`,
		string(target), actorUserID, sessionID,
	)
	if err != nil {
		return nil, err
	}

	eventType := "canceled"
	if target == StatusRescindedAfterSign {
		eventType = "rescinded_after_sign"
	}
	if err := writeAudit(tx, sessionID, eventType, actorUserID, ""); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.GetByID(sessionID)
}

// BindGroup associates a session with a chat venue (e.g. a Telegram group
// chat_id). Write-once: the first non-zero bind wins, subsequent calls with
// the SAME value are a no-op, calls with a DIFFERENT value return
// ErrGroupAlreadyBound. Any session member may bind. Write is rejected if
// the session is already in a terminal state.
//
// The chosen value is opaque to sshsign — consumers pick the integer
// semantics that fit their venue (Telegram group chat_ids are negative;
// Slack would use a channel numeric id; a future consumer could use any
// int64). sshsign just records and serves it back.
func (r *Repo) BindGroup(sessionID, actorUserID string, groupChatID int64) (*Session, error) {
	if groupChatID == 0 {
		return nil, errors.New("group_chat_id must be non-zero")
	}

	tx, err := r.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	sess, err := r.getByIDTx(tx, sessionID)
	if err != nil {
		return nil, err
	}
	if sess.Status.IsTerminal() {
		return nil, fmt.Errorf("%w: %s", ErrTerminal, sess.Status)
	}

	var isMember int
	err = tx.QueryRow(
		`SELECT 1 FROM signing_session_members
		 WHERE session_id = ? AND user_id = ?`,
		sessionID, actorUserID,
	).Scan(&isMember)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotMember
	}
	if err != nil {
		return nil, err
	}

	// Write-once semantics: existing bind with same value is idempotent
	// no-op; existing bind with different value is a conflict.
	if sess.GroupChatID != 0 {
		if sess.GroupChatID == groupChatID {
			return sess, tx.Commit()
		}
		return nil, ErrGroupAlreadyBound
	}

	_, err = tx.Exec(
		`UPDATE signing_sessions SET group_chat_id = ? WHERE session_id = ?`,
		groupChatID, sessionID,
	)
	if err != nil {
		return nil, err
	}

	if err := writeAudit(tx, sessionID, "group_bound", actorUserID,
		fmt.Sprintf(`{"group_chat_id":%d}`, groupChatID)); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.GetByID(sessionID)
}

// Complete transitions a session to 'completed'. Creator-only.
// Idempotent: calling twice with the same args returns the current
// state without changing anything.
func (r *Repo) Complete(sessionID, actorUserID, executedArtifact string) (*Session, error) {
	if executedArtifact == "" {
		return nil, errors.New("executed_artifact required")
	}

	tx, err := r.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	sess, err := r.getByIDTx(tx, sessionID)
	if err != nil {
		return nil, err
	}

	if sess.Status == StatusCompleted {
		// Idempotent no-op if the same artifact is being re-recorded.
		if sess.ExecutedArtifact == executedArtifact && sess.FinalizedBy == actorUserID {
			return sess, tx.Commit()
		}
		return nil, fmt.Errorf("%w: already completed", ErrTerminal)
	}
	if sess.Status.IsTerminal() {
		return nil, fmt.Errorf("%w: %s", ErrTerminal, sess.Status)
	}
	if sess.CreatedBy != actorUserID {
		return nil, ErrNotCreator
	}

	now := r.now().UTC().Format(time.RFC3339Nano)

	// Issue a fresh view_token at completion time so the creator can
	// immediately share the audit URL. Regenerable later via
	// IssueViewToken if the token is leaked.
	viewToken, err := generateViewToken()
	if err != nil {
		return nil, fmt.Errorf("generate view token: %w", err)
	}

	_, err = tx.Exec(
		`UPDATE signing_sessions
		 SET status = 'completed', completed_at = ?, finalized_by = ?,
		     executed_artifact = ?, view_token = ?
		 WHERE session_id = ?`,
		now, actorUserID, executedArtifact, viewToken, sessionID,
	)
	if err != nil {
		return nil, err
	}

	if err := writeAudit(tx, sessionID, "completed", actorUserID,
		fmt.Sprintf(`{"artifact":%q}`, executedArtifact)); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.GetByID(sessionID)
}

// IssueViewToken rotates the shareable audit view_token. Creator-only.
// Returns the new token in the returned Session.ViewToken field. The
// previous token stops working immediately — useful if a token was
// leaked or shared with someone who shouldn't have access anymore.
func (r *Repo) IssueViewToken(sessionID, actorUserID string) (*Session, error) {
	tx, err := r.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	sess, err := r.getByIDTx(tx, sessionID)
	if err != nil {
		return nil, err
	}
	if sess.CreatedBy != actorUserID {
		return nil, ErrNotCreator
	}
	if sess.Status != StatusCompleted {
		// Pre-completion sessions don't need audit URLs; restrict to
		// completed to avoid accidental exposure of in-progress state.
		return nil, fmt.Errorf("%w: view tokens are only issued after completion", ErrInvalidStatus)
	}

	token, err := generateViewToken()
	if err != nil {
		return nil, fmt.Errorf("generate view token: %w", err)
	}

	_, err = tx.Exec(
		`UPDATE signing_sessions SET view_token = ? WHERE session_id = ?`,
		token, sessionID,
	)
	if err != nil {
		return nil, err
	}
	if err := writeAudit(tx, sessionID, "view_token_rotated", actorUserID, ""); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.GetByID(sessionID)
}

// GetByViewToken fetches a session for public audit rendering. The
// session_id AND the view_token must match — prevents enumeration of
// session IDs to discover tokens. Returns ErrNotFound on mismatch (don't
// leak whether the session exists but the token is wrong).
func (r *Repo) GetByViewToken(sessionID, viewToken string) (*Session, error) {
	if sessionID == "" || viewToken == "" {
		return nil, ErrNotFound
	}
	tx, err := r.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	sess, err := r.getByIDTx(tx, sessionID)
	if err != nil {
		return nil, err
	}
	// Constant-time compare would be strictly more principled, but the
	// attacker's leverage here is limited: tokens are high-entropy and
	// rate-limited at the HTTP layer. Standard comparison is fine.
	if sess.ViewToken == "" || sess.ViewToken != viewToken {
		return nil, ErrNotFound
	}
	return sess, tx.Commit()
}

// generateViewToken returns a URL-safe random string (22 chars,
// ~128 bits of entropy).
func generateViewToken() (string, error) {
	// 16 random bytes → base64 URL encoded = 22 chars.
	buf := make([]byte, 16)
	if _, err := cryptoRand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Audit returns the append-only transition log for a session.
func (r *Repo) Audit(sessionID string) ([]AuditEvent, error) {
	rows, err := r.db.Query(
		`SELECT id, session_id, event_type, actor_id, details, created_at
		 FROM signing_session_audit WHERE session_id = ? ORDER BY id`,
		sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var createdAt string
		if err := rows.Scan(&e.ID, &e.SessionID, &e.EventType, &e.ActorID,
			&e.Details, &createdAt); err != nil {
			return nil, err
		}
		e.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ──────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────

func (r *Repo) getByIDTx(tx *sql.Tx, id string) (*Session, error) {
	return scanSessionRow(tx.QueryRow(
		sessionSelectColumns+` FROM signing_sessions WHERE session_id = ?`, id))
}

func getByCodeTx(tx *sql.Tx, code string) (*Session, error) {
	sess, err := scanSessionRow(tx.QueryRow(
		sessionSelectColumns+` FROM signing_sessions WHERE session_code = ?`, code))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrCodeNotFound
	}
	return sess, err
}

const sessionSelectColumns = `SELECT session_id, session_code, created_by, created_at, expires_at,
       status, COALESCE(canceled_by, ''), COALESCE(completed_at, ''),
       COALESCE(finalized_by, ''), COALESCE(executed_artifact, ''),
       metadata_public, metadata_member, COALESCE(view_token, ''),
       COALESCE(group_chat_id, 0)`

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanSessionRow(row rowScanner) (*Session, error) {
	var s Session
	var createdAt, expiresAt, completedAt string
	var status string
	err := row.Scan(
		&s.SessionID, &s.SessionCode, &s.CreatedBy,
		&createdAt, &expiresAt, &status,
		&s.CanceledBy, &completedAt, &s.FinalizedBy, &s.ExecutedArtifact,
		&s.MetadataPublic, &s.MetadataMember, &s.ViewToken,
		&s.GroupChatID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	s.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expiresAt)
	if completedAt != "" {
		s.CompletedAt, _ = time.Parse(time.RFC3339Nano, completedAt)
	}
	s.Status = Status(status)
	return &s, nil
}

func markExpiredTx(tx *sql.Tx, sessionID string, now time.Time) error {
	_, err := tx.Exec(
		`UPDATE signing_sessions SET status = 'expired' WHERE session_id = ? AND status = 'open'`,
		sessionID,
	)
	if err != nil {
		return err
	}
	return writeAudit(tx, sessionID, "expired", "system", "")
}

func writeAudit(tx *sql.Tx, sessionID, eventType, actorID, details string) error {
	if details == "" {
		details = "{}"
	}
	_, err := tx.Exec(
		`INSERT INTO signing_session_audit (session_id, event_type, actor_id, details)
		 VALUES (?, ?, ?, ?)`,
		sessionID, eventType, actorID, details,
	)
	if err != nil {
		return fmt.Errorf("write audit: %w", err)
	}
	return nil
}

func isUniqueConflict(err error, col string) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE") && strings.Contains(msg, col)
}
