package server

import (
	"encoding/base64"
	"encoding/json"
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
	GroupChatID      int64             `json:"group_chat_id,omitempty"`   // 0 = unbound
}

type memberView struct {
	Role          string `json:"role"`
	UserID        string `json:"user_id"`
	PartyDID      string `json:"party_did,omitempty"`
	APOAPubkeyPEM string `json:"apoa_pubkey_pem"`
	JoinedAt      string `json:"joined_at"`
	// P7-5 durable founder-wait timestamps. omitempty so unset stays
	// absent from the wire — Python consumer treats absent and null
	// identically (m.get(...) is None either way). Pointer-to-int64
	// preserves the SQL NULL distinction at the layer below.
	FounderResumedAt   *int64 `json:"founder_resumed_at,omitempty"`
	FounderStreamingAt *int64 `json:"founder_streaming_at,omitempty"`
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
		GroupChatID:      sess.GroupChatID,
	}
	if !sess.CompletedAt.IsZero() {
		v.CompletedAt = sess.CompletedAt.Format(time.RFC3339)
	}
	if includeMember {
		v.MetadataMember = sess.MetadataMember
		v.Members = make([]memberView, 0, len(members))
		for _, m := range members {
			v.Members = append(v.Members, memberView{
				Role:               m.Role,
				UserID:             m.UserID,
				PartyDID:           m.PartyDID,
				APOAPubkeyPEM:      m.APOAPubkeyPEM,
				JoinedAt:           m.JoinedAt.Format(time.RFC3339),
				FounderResumedAt:   m.FounderResumedAt,
				FounderStreamingAt: m.FounderStreamingAt,
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

// handleUpdateSessionMember: P7-5 RPC that lets the session creator
// set whitelisted integer fields on their own member row. Today's
// whitelist is {founder_resumed_at, founder_streaming_at}; the repo
// layer owns enforcement via ErrFieldNotWritable, so this handler
// just parses flags and delegates.
//
//   update-session-member --session-id ID --field NAME --value INT
func handleUpdateSessionMember(sess ssh.Session, sc *SessionContext, args []string) {
	flags, err := parseSessionFlags(args)
	if err != nil {
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}
	if flags["session-id"] == "" || flags["field"] == "" || flags["value"] == "" {
		writeJSON(sess, errorResponse{Error: "session-id, field, and value are required"})
		return
	}

	var value int64
	if _, perr := fmt.Sscan(flags["value"], &value); perr != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("value must be an integer: %v", perr)})
		return
	}

	repo := sessions.NewRepo(sc.DB)
	if err := repo.UpdateSessionMemberField(
		flags["session-id"], sc.User.UserID, flags["field"], value,
	); err != nil {
		if errors.Is(err, sessions.ErrFieldNotWritable) {
			writeJSON(sess, errorResponse{Error: "field_not_writable"})
			return
		}
		if errors.Is(err, sessions.ErrNotCreator) {
			writeJSON(sess, errorResponse{Error: "only the session creator may update members"})
			return
		}
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}
	writeJSON(sess, map[string]bool{"ok": true})
}

// handleBindGroup: `bind-group --session-id ID --group-chat-id INT`.
// Write-once: first non-zero bind wins. Any session member may bind.
// Idempotent on a re-bind with the same chat_id.
func handleBindGroup(sess ssh.Session, sc *SessionContext, args []string) {
	flags, err := parseSessionFlags(args)
	if err != nil {
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}
	if flags["session-id"] == "" || flags["group-chat-id"] == "" {
		writeJSON(sess, errorResponse{Error: "session-id and group-chat-id are required"})
		return
	}

	var chatID int64
	if _, perr := fmt.Sscan(flags["group-chat-id"], &chatID); perr != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("group-chat-id must be an integer: %v", perr)})
		return
	}

	repo := sessions.NewRepo(sc.DB)
	after, err := repo.BindGroup(flags["session-id"], sc.User.UserID, chatID)
	if err != nil {
		if errors.Is(err, sessions.ErrGroupAlreadyBound) {
			writeJSON(sess, errorResponse{Error: "group_already_bound"})
			return
		}
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}
	members, _ := repo.Members(after.SessionID)
	writeJSON(sess, marshalSession(after, members, true))
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
// joinPEMParts reconstructs a canonical PEM block from SSH-argv fragments.
// A marker line ("-----BEGIN PUBLIC KEY-----") arrives as three parts:
// the leading "-----BEGIN", a word like "PUBLIC" that has no dashes,
// and "KEY-----". The rule: a marker line starts at an arg containing
// "-----" and ends at the *next* arg that contains "-----"; any word
// fragments between are part of the same line. Args outside marker
// runs are base64 data, one arg per line.
func joinPEMParts(parts []string) string {
	var lines []string
	i := 0
	for i < len(parts) {
		if !strings.Contains(parts[i], "-----") {
			lines = append(lines, parts[i])
			i++
			continue
		}
		// Marker-line run: scan forward until we find the matching
		// "-----" arg that closes this header/footer.
		j := i + 1
		for j < len(parts) && !strings.Contains(parts[j], "-----") {
			j++
		}
		if j < len(parts) {
			lines = append(lines, strings.Join(parts[i:j+1], " "))
			i = j + 1
		} else {
			// Unclosed marker — emit what we have; downstream PEM
			// decode will fail with a clearer error than argv noise.
			lines = append(lines, strings.Join(parts[i:], " "))
			i = len(parts)
		}
	}
	return strings.Join(lines, "\n")
}

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
			// Reconstruct canonical PEM: header/footer lines are single
			// lines with space-separated tokens (`-----BEGIN PUBLIC
			// KEY-----`); base64 data is its own line. Detect marker-line
			// fragments by presence of "-----" and group adjacent ones
			// together with spaces. Go's pem.Decode rejects the naive
			// newline-join because `-----BEGIN\nPUBLIC\nKEY-----` is not
			// a valid PEM header.
			val = joinPEMParts(parts)
		} else if strings.HasPrefix(val, "{") || strings.HasPrefix(val, "[") {
			// JSON value with spaces — SSH splits `{"a":1, "b":2}` on
			// whitespace, so we rejoin until either the value parses
			// as valid JSON or a real flag appears. Same accommodation
			// parseJSONArg (commands.go) makes for legacy commands; also
			// tolerate SSH stripping inner double quotes (so
			// `{"use_case":"safe"}` may arrive as `{use_case:safe}`).
			for !json.Valid([]byte(val)) && !json.Valid([]byte(fixBareJSONKeys(val))) &&
				i+1 < len(args) && !isFlag(args[i+1]) {
				val += " " + args[i+1]
				i++
			}
			if !json.Valid([]byte(val)) {
				// Last-ditch: try bare-keys repair so the value at least
				// parses downstream. If neither works, pass through and
				// let the handler's JSON-unmarshal surface the error.
				if fixed := fixBareJSONKeys(val); json.Valid([]byte(fixed)) {
					val = fixed
				}
			}
		}
		out[key] = val
	}

	// P8-2: resolve base64-encoded metadata flags. SSH argv strips inner
	// double quotes and the fixBareJSONKeys repair only covers bare keys,
	// not bare string values — so JSON like `{"firm":"Blue Fund"}` gets
	// mangled into `{firm:Blue Fund}` and fails to parse. The `-b64` suffix
	// is the escape hatch: value is URL-safe base64 of the JSON text, which
	// is a whitespace-free alphabet that SSH transports opaquely.
	if err := resolveB64Metadata(out, "metadata-public"); err != nil {
		return nil, err
	}
	if err := resolveB64Metadata(out, "metadata-member"); err != nil {
		return nil, err
	}
	return out, nil
}

// resolveB64Metadata decodes `<key>-b64` (URL-safe base64 JSON) into `<key>`.
// Fails if both the plain and b64 forms are set. Fails if the base64 is
// unparseable. Does not validate that the decoded text is JSON — that's
// the storage layer's job; handlers store the string verbatim.
func resolveB64Metadata(flags map[string]string, key string) error {
	b64Key := key + "-b64"
	encoded, ok := flags[b64Key]
	if !ok {
		return nil
	}
	if _, both := flags[key]; both {
		return fmt.Errorf("cannot set both --%s and --%s", key, b64Key)
	}
	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		// Try standard encoding as a forgiving fallback — clients that
		// forget to swap + for - shouldn't get a cryptic error.
		decoded, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("invalid base64 for --%s: %v", b64Key, err)
		}
	}
	flags[key] = string(decoded)
	delete(flags, b64Key)
	return nil
}
