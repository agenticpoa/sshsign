package server

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"

	"github.com/agenticpoa/sshsign/internal/audit"
	"github.com/agenticpoa/sshsign/internal/storage"
)

// SessionContext holds everything a session needs to operate.
type SessionContext struct {
	DB         *sql.DB
	KEK        []byte
	User       *storage.User
	UserKey    *storage.UserKey
	IsNewUser  bool
	RateLimits *ServerRateLimits
	Audit      audit.Logger
}

// EnsureUser finds or creates a user for the connecting SSH key.
func EnsureUser(db *sql.DB, fingerprint, publicKey string) (*storage.User, *storage.UserKey, bool, error) {
	user, key, err := storage.FindUserByFingerprint(db, fingerprint)
	if err != nil {
		return nil, nil, false, err
	}

	if user != nil {
		return user, key, false, nil
	}

	user, key, err = storage.CreateUser(db, fingerprint, publicKey)
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
		wish.Println(sess, "Or use commands: sign, verify, keys, revoke")
		return
	}

	switch cmd[0] {
	case "sign":
		handleSign(sess, sc, cmd[1:])
	case "verify":
		handleVerify(sess, sc, cmd[1:])
	case "keys":
		handleKeys(sess, sc)
	case "revoke":
		handleRevoke(sess, sc, cmd[1:])
	default:
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("unknown command '%s'", cmd[0])})
	}
}

// SessionHandler returns a middleware that sets up the session context.
// For PTY sessions, it passes through to the next handler (bubbletea).
// For non-PTY sessions, it handles commands directly.
func SessionHandler(db *sql.DB, kek []byte, rl *ServerRateLimits, auditLog audit.Logger) func(next ssh.Handler) ssh.Handler {
	return func(next ssh.Handler) ssh.Handler {
		return func(sess ssh.Session) {
			fingerprint := FingerprintFromContext(sess.Context())
			publicKey := PublicKeyFromContext(sess.Context())

			if fingerprint == "" {
				wish.Fatalln(sess, "no SSH key provided")
				return
			}

			user, userKey, isNew, err := EnsureUser(db, fingerprint, publicKey)
			if err != nil {
				log.Printf("error ensuring user for %s: %v", fingerprint, err)
				wish.Fatalln(sess, "internal error")
				return
			}

			sc := &SessionContext{
				DB:         db,
				KEK:        kek,
				User:       user,
				UserKey:    userKey,
				IsNewUser:  isNew,
				RateLimits: rl,
				Audit:      auditLog,
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
