package server

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"

	"github.com/agenticpoa/sshsign/internal/audit"
	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/ratelimit"
	"github.com/agenticpoa/sshsign/internal/sessions"
	"github.com/agenticpoa/sshsign/internal/storage"
)

// SessionContext holds everything a session needs to operate.
type SessionContext struct {
	DB                    *sql.DB
	KEK                   *apoacrypto.KEKRing
	User                  *storage.User
	UserKey               *storage.UserKey
	IsNewUser             bool
	RateLimits            *ServerRateLimits
	GetSessionRateLimiter ratelimit.Limiter
	Audit                 audit.Logger
	HTTPDomain            string // domain for web approval URLs
}

// EnsureUser finds or creates a user for the connecting SSH key.
func EnsureUser(ctx context.Context, db *sql.DB, fingerprint, publicKey string) (*storage.User, *storage.UserKey, bool, error) {
	user, key, err := storage.FindUserByFingerprint(ctx, db, fingerprint)
	if err != nil {
		return nil, nil, false, err
	}

	if user != nil {
		return user, key, false, nil
	}

	user, key, err = storage.CreateUser(ctx, db, fingerprint, publicKey)
	if err != nil {
		return nil, nil, false, err
	}

	return user, key, true, nil
}

// CommandHandler handles non-interactive (programmatic) SSH sessions.
func CommandHandler(sess ssh.Session, sc *SessionContext) {
	cmd := sess.Command()
	if len(cmd) == 0 {
		wish.Println(sess, "sshsign - SSH signing service for AI agents")
		wish.Printf(sess, "User: %s\n", sc.User.UserID)
		wish.Printf(sess, "SSH key: %s\n", sc.UserKey.SSHFingerprint)
		wish.Println(sess, "")
		wish.Println(sess, "Connect with an interactive terminal for the full UI.")
		wish.Println(sess, "Or use commands: sign, verify, keys, create-key, get-envelope, revoke")
		return
	}

	switch cmd[0] {
	case "sign":
		handleSign(sess, sc, cmd[1:])
	case "verify":
		handleVerify(sess, sc, cmd[1:])
	case "keys":
		handleKeys(sess, sc)
	case "create-key":
		handleCreateKey(sess, sc, cmd[1:])
	case "get-envelope":
		handleGetEnvelope(sess, sc, cmd[1:])
	case "revoke":
		handleRevoke(sess, sc, cmd[1:])
	case "pending":
		handlePending(sess, sc)
	case "approve":
		handleApprove(sess, sc, cmd[1:])
	case "deny":
		handleDeny(sess, sc, cmd[1:])
	case "session":
		handleSession(sess, sc, cmd[1:])
	case "log-offer":
		handleLogOffer(sess, sc, cmd[1:])
	case "history":
		handleHistory(sess, sc, cmd[1:])
	case "create-session":
		handleCreateSession(sess, sc, cmd[1:])
	case "join-session":
		handleJoinSession(sess, sc, cmd[1:])
	case "get-session":
		handleGetSession(sess, sc, cmd[1:])
	case "cancel-session":
		handleCancelSession(sess, sc, cmd[1:])
	case "complete-session":
		handleCompleteSession(sess, sc, cmd[1:])
	case "audit-session":
		handleAuditSession(sess, sc, cmd[1:])
	case "bind-group":
		handleBindGroup(sess, sc, cmd[1:])
	case "update-session-member":
		handleUpdateSessionMember(sess, sc, cmd[1:])
	case "acquire-lease":
		handleAcquireLease(sess, sc, cmd[1:])
	case "refresh-lease":
		handleRefreshLease(sess, sc, cmd[1:])
	case "check-lease":
		handleCheckLease(sess, sc, cmd[1:])
	case "release-lease":
		handleReleaseLease(sess, sc, cmd[1:])
	case "claim-delivery":
		handleClaimDelivery(sess, sc, cmd[1:])
	case "get-delivery":
		handleGetDelivery(sess, sc, cmd[1:])
	case "list-deliveries":
		handleListDeliveries(sess, sc, cmd[1:])
	default:
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("unknown command '%s'", cmd[0])})
	}
}

// SessionHandler returns a middleware that sets up the session context.
// For PTY sessions, it passes through to the next handler (bubbletea).
// For non-PTY sessions, it handles commands directly.
func SessionHandler(db *sql.DB, kek *apoacrypto.KEKRing, rl *ServerRateLimits, auditLog audit.Logger, httpDomain string) func(next ssh.Handler) ssh.Handler {
	// Long-lived, shared across all SSH connections — per-user counters
	// live inside the limiter and are keyed by sshsign user_id.
	getSessionLimiter := ratelimit.NewSlidingWindow(sessions.MaxGetSessionCallsPerHour, time.Hour)

	return func(next ssh.Handler) ssh.Handler {
		return func(sess ssh.Session) {
			fingerprint := FingerprintFromContext(sess.Context())
			publicKey := PublicKeyFromContext(sess.Context())

			if fingerprint == "" {
				wish.Fatalln(sess, "no SSH key provided")
				return
			}

			user, userKey, isNew, err := EnsureUser(sess.Context(), db, fingerprint, publicKey)
			if err != nil {
				log.Printf("error ensuring user for %s: %v", fingerprint, err)
				wish.Fatalln(sess, "internal error")
				return
			}

			sc := &SessionContext{
				DB:                    db,
				KEK:                   kek,
				User:                  user,
				UserKey:               userKey,
				IsNewUser:             isNew,
				RateLimits:            rl,
				GetSessionRateLimiter: getSessionLimiter,
				Audit:                 auditLog,
				HTTPDomain:            httpDomain,
			}

			// Store session context for the TUI to access
			sess.Context().SetValue(ctxSessionContext, sc)

			_, _, isPTY := sess.Pty()
			if !isPTY {
				CommandHandler(sess, sc)
				return
			}

			// PTY session: pass to bubbletea middleware
			next(sess)
		}
	}
}

const ctxSessionContext contextKey = "session_context"

func SessionContextFromContext(ctx ssh.Context) *SessionContext {
	v, _ := ctx.Value(ctxSessionContext).(*SessionContext)
	return v
}
