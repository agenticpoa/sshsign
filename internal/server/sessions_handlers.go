package server

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/ssh"

	"github.com/agenticpoa/sshsign/internal/sessions"
)

// Wire format for SSH-CLI responses. All handlers return JSON.

type sessionView struct {
	SessionID        string            `json:"session_id"`
	SessionCode      string            `json:"session_code"`
	CreatedBy        string            `json:"created_by"`
	CreatedAt        string            `json:"created_at"`
	ExpiresAt        string            `json:"expires_at"`
	Status           string            `json:"status"`
	CanceledBy       string            `json:"canceled_by,omitempty"`
	CompletedAt      string            `json:"completed_at,omitempty"`
	FinalizedBy      string            `json:"finalized_by,omitempty"`
	ExecutedArtifact string            `json:"executed_artifact,omitempty"`
	MetadataPublic   string            `json:"metadata_public"`
	MetadataMember   string            `json:"metadata_member,omitempty"` // omitted for non-members
	Members          []memberView      `json:"members,omitempty"`         // omitted for non-members
}

type memberView struct {
	Role          string `json:"role"`
	UserID        string `json:"user_id"`
	PartyDID      string `json:"party_did,omitempty"`
	APOAPubkeyPEM string `json:"apoa_pubkey_pem"`
	JoinedAt      string `json:"joined_at"`
}

type auditEventView struct {
	EventType string `json:"event_type"`
	ActorID   string `json:"actor_id"`
	Details   string `json:"details"`
	CreatedAt string `json:"created_at"`
}

// marshalSession shapes the wire response. When `includeMember` is true,
// metadata_member and the full members list are included (caller is a
// session member). Otherwise only public fields are exposed.
func marshalSession(sess *sessions.Session, members []sessions.Member, includeMember bool) sessionView {
	v := sessionView{
		SessionID:        sess.SessionID,
		SessionCode:      sess.SessionCode,
		CreatedBy:        sess.CreatedBy,
		CreatedAt:        sess.CreatedAt.Format(time.RFC3339),
		ExpiresAt:        sess.ExpiresAt.Format(time.RFC3339),
		Status:           string(sess.Status),
		CanceledBy:       sess.CanceledBy,
		FinalizedBy:      sess.FinalizedBy,
		ExecutedArtifact: sess.ExecutedArtifact,
		MetadataPublic:   sess.MetadataPublic,
	}
	if !sess.CompletedAt.IsZero() {
		v.CompletedAt = sess.CompletedAt.Format(time.RFC3339)
	}
	if includeMember {
		v.MetadataMember = sess.MetadataMember
		v.Members = make([]memberView, 0, len(members))
		for _, m := range members {
			v.Members = append(v.Members, memberView{
				Role:          m.Role,
				UserID:        m.UserID,
				PartyDID:      m.PartyDID,
				APOAPubkeyPEM: m.APOAPubkeyPEM,
				JoinedAt:      m.JoinedAt.Format(time.RFC3339),
			})
		}
	}
	return v
}

// handleCreateSession: `create-session --session-id ID --role ROLE
// --apoa-pubkey PEM [--party-did DID] [--metadata-public JSON]
// [--metadata-member JSON] [--ttl 86400]`
func handleCreateSession(sess ssh.Session, sc *SessionContext, args []string) {
	flags, err := parseSessionFlags(args)
	if err != nil {
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}
	if flags["session-id"] == "" || flags["role"] == "" || flags["apoa-pubkey"] == "" {
		writeJSON(sess, errorResponse{Error: "session-id, role, apoa-pubkey are required"})
		return
	}

	ttl := 24 * time.Hour
	if raw := flags["ttl"]; raw != "" {
		secs, perr := time.ParseDuration(raw + "s")
		if perr != nil {
			writeJSON(sess, errorResponse{Error: fmt.Sprintf("invalid --ttl: %v", perr)})
			return
		}
		ttl = secs
	}

	repo := sessions.NewRepo(sc.DB)
	created, err := repo.Create(sessions.CreateParams{
		SessionID:       flags["session-id"],
		CreatorUserID:   sc.User.UserID,
		CreatorRole:     flags["role"],
		CreatorAPOAPub:  flags["apoa-pubkey"],
		CreatorPartyDID: flags["party-did"],
		TTL:             ttl,
		MetadataPublic:  flags["metadata-public"],
		MetadataMember:  flags["metadata-member"],
	})
	if err != nil {
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}

	members, _ := repo.Members(created.SessionID)
	writeJSON(sess, marshalSession(created, members, true))
}

// handleJoinSession: `join-session --session-code CODE --role ROLE
// --apoa-pubkey PEM [--party-did DID]`
func handleJoinSession(sess ssh.Session, sc *SessionContext, args []string) {
	flags, err := parseSessionFlags(args)
	if err != nil {
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}
	if flags["session-code"] == "" || flags["role"] == "" || flags["apoa-pubkey"] == "" {
		writeJSON(sess, errorResponse{Error: "session-code, role, apoa-pubkey are required"})
		return
	}

	repo := sessions.NewRepo(sc.DB)
	joined, err := repo.Join(sessions.JoinParams{
		SessionCode:   flags["session-code"],
		UserID:        sc.User.UserID,
		Role:          flags["role"],
		APOAPubkeyPEM: flags["apoa-pubkey"],
		PartyDID:      flags["party-did"],
	})
	if err != nil {
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}

	members, _ := repo.Members(joined.SessionID)
	writeJSON(sess, marshalSession(joined, members, true))
}

// handleGetSession: `get-session (--session-code CODE | --session-id ID)`
// Returns the session record. Membership-gated metadata_member + members
// list appear only if the caller is a member of the session.
// Rate-limited per-user (sliding 1-hour window) to prevent code-space
// enumeration.
func handleGetSession(sess ssh.Session, sc *SessionContext, args []string) {
	flags, err := parseSessionFlags(args)
	if err != nil {
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}

	// Rate limit before touching the DB — cheap check, blocks attackers
	// from amortizing fixed DB latency while iterating codes.
	if sc.GetSessionRateLimiter != nil {
		if err := sc.GetSessionRateLimiter.Allow(sc.User.UserID); err != nil {
			writeJSON(sess, errorResponse{Error: err.Error()})
			return
		}
	}

	repo := sessions.NewRepo(sc.DB)
	var s *sessions.Session
	switch {
	case flags["session-code"] != "":
		s, err = repo.GetByCode(flags["session-code"])
	case flags["session-id"] != "":
		s, err = repo.GetByID(flags["session-id"])
	default:
		writeJSON(sess, errorResponse{Error: "one of --session-code or --session-id required"})
		return
	}
	if err != nil {
		if errors.Is(err, sessions.ErrNotFound) || errors.Is(err, sessions.ErrCodeNotFound) {
			writeJSON(sess, errorResponse{Error: "session not found"})
			return
		}
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}

	isMember, _ := repo.IsMember(s.SessionID, sc.User.UserID)
	var members []sessions.Member
	if isMember {
		members, _ = repo.Members(s.SessionID)
	}
	writeJSON(sess, marshalSession(s, members, isMember))
}

// handleCancelSession: `cancel-session --session-id ID [--rescind]`.
// `--rescind` produces the rescinded_after_sign state (caller signals the
// session had progressed past the signing step before cancellation).
func handleCancelSession(sess ssh.Session, sc *SessionContext, args []string) {
	flags, err := parseSessionFlags(args)
	if err != nil {
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}
	if flags["session-id"] == "" {
		writeJSON(sess, errorResponse{Error: "--session-id required"})
		return
	}
	target := sessions.StatusCanceled
	if flags["rescind"] == "true" {
		target = sessions.StatusRescindedAfterSign
	}

	repo := sessions.NewRepo(sc.DB)
	after, err := repo.Cancel(flags["session-id"], sc.User.UserID, target)
	if err != nil {
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}
	members, _ := repo.Members(after.SessionID)
	writeJSON(sess, marshalSession(after, members, true))
}

// handleCompleteSession: `complete-session --session-id ID
// --executed-artifact URI`. Creator-only; idempotent.
func handleCompleteSession(sess ssh.Session, sc *SessionContext, args []string) {
	flags, err := parseSessionFlags(args)
	if err != nil {
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}
	if flags["session-id"] == "" || flags["executed-artifact"] == "" {
		writeJSON(sess, errorResponse{Error: "session-id and executed-artifact are required"})
		return
	}

	repo := sessions.NewRepo(sc.DB)
	after, err := repo.Complete(flags["session-id"], sc.User.UserID, flags["executed-artifact"])
	if err != nil {
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}
	members, _ := repo.Members(after.SessionID)
	writeJSON(sess, marshalSession(after, members, true))
}

// handleAuditSession: `audit-session --session-id ID`. Returns the
// append-only transition log. Members only.
func handleAuditSession(sess ssh.Session, sc *SessionContext, args []string) {
	flags, err := parseSessionFlags(args)
	if err != nil {
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}
	if flags["session-id"] == "" {
		writeJSON(sess, errorResponse{Error: "--session-id required"})
		return
	}

	repo := sessions.NewRepo(sc.DB)
	isMember, _ := repo.IsMember(flags["session-id"], sc.User.UserID)
	if !isMember {
		writeJSON(sess, errorResponse{Error: "not a member of this session"})
		return
	}

	events, err := repo.Audit(flags["session-id"])
	if err != nil {
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}

	out := make([]auditEventView, 0, len(events))
	for _, e := range events {
		out = append(out, auditEventView{
			EventType: e.EventType,
			ActorID:   e.ActorID,
			Details:   e.Details,
			CreatedAt: e.CreatedAt.Format(time.RFC3339),
		})
	}
	writeJSON(sess, out)
}

// parseSessionFlags is a minimal --key value flag parser. Supports
// `--key value` and boolean `--flag` (treated as "--flag=true"). Returns
// a map with hyphen-prefix stripped. Mirrors the convention used by
// sign/verify/etc. in commands.go; kept local to sessions for isolation.
//
// Multi-line PEM values: SSH splits argv on whitespace including newlines,
// so an "-----BEGIN PUBLIC KEY-----\n<base64>\n-----END PUBLIC KEY-----"
// arrives as several separate args. When we detect an arg that starts
// with "-----BEGIN", we rejoin subsequent non-flag args with newlines
// until we see the matching "-----END" line. Mirrors the same concession
// parseJSONArg (commands.go) makes for JSON arguments with spaces.
func parseSessionFlags(args []string) (map[string]string, error) {
	// isFlag — a real "--foo" flag, NOT a PEM delimiter like "-----BEGIN"
	// that also happens to start with "--". The discriminator: real flags
	// have a letter or digit right after the two dashes; PEM markers have
	// another dash.
	isFlag := func(s string) bool {
		return len(s) > 2 && s[:2] == "--" && s[2] != '-'
	}

	out := make(map[string]string)
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !isFlag(a) {
			return nil, fmt.Errorf("unexpected argument: %q", a)
		}
		key := a[2:]
		// Boolean flag (next arg is another flag or end of list)
		if i+1 >= len(args) || isFlag(args[i+1]) {
			out[key] = "true"
			continue
		}
		val := args[i+1]
		i++

		if strings.HasPrefix(val, "-----BEGIN") {
			// Keep joining until a real `--flag` appears or args are
			// exhausted. PEM end markers themselves are split across
			// multiple args ("-----END", "PUBLIC", "KEY-----") so
			// short-circuiting on "-----END" leaves tail args dangling
			// and trips the outer loop's bare-arg check.
			parts := []string{val}
			for i+1 < len(args) {
				if isFlag(args[i+1]) {
					break
				}
				parts = append(parts, args[i+1])
				i++
			}
			val = strings.Join(parts, "\n")
		}
		out[key] = val
	}
	return out, nil
}
