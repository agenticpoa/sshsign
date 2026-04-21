package web

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/agenticpoa/sshsign/internal/sessions"
)

// handleAuditView serves the public, shareable audit view for a completed
// signing session. The URL carries a single-use-capable view_token issued
// on session completion; anyone with the token can see the agreed terms,
// party fingerprints, signatures, and lifecycle timeline.
//
// Deliberately does NOT expose:
//   - Either party's APOA-authorized ranges (would leak negotiating
//     position asymmetrically)
//   - Offer-level history (that's the "my-audit" view, members only)
//   - Pre-completion session state (view_tokens are only issued on
//     transition to `completed`, so in-progress sessions can't be
//     audit-viewed — prevents accidental exposure of in-flight state)
//
// Response format:
//   - Default: HTML report suitable for sharing with lawyers, cap-table
//     software, auditors
//   - ?format=json: machine-readable JSON (same content, different wrapper)
func (s *Server) handleAuditView(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("sessionID")
	viewToken := r.URL.Query().Get("token")

	if sessionID == "" || viewToken == "" {
		http.Error(w, "missing session id or token", http.StatusBadRequest)
		return
	}

	repo := sessions.NewRepo(s.db)
	sess, err := repo.GetByViewToken(sessionID, viewToken)
	if err != nil {
		// Return 404 for both missing session and wrong token — don't
		// leak whether the session exists.
		http.NotFound(w, r)
		return
	}

	// Only completed sessions have audit views worth showing. In theory
	// a view_token could only be issued on completion (enforced at
	// IssueViewToken), but guard here too.
	if sess.Status != sessions.StatusCompleted {
		http.NotFound(w, r)
		return
	}

	members, err := repo.Members(sess.SessionID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	auditEvents, err := repo.Audit(sess.SessionID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	view := buildPublicAuditView(sess, members, auditEvents)

	if strings.EqualFold(r.URL.Query().Get("format"), "json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(view)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := publicAuditTemplate.Execute(w, view); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// publicAuditView is the wire-safe (no ranges, no offers) payload for
// the shareable audit page.
type publicAuditView struct {
	SessionID        string
	SessionCode      string
	Status           string
	CreatedAt        string
	CompletedAt      string
	ExecutedArtifact string
	MetadataPublic   string // opaque JSON from the consumer
	Parties          []publicPartyView
	Timeline         []publicTimelineEvent
}

type publicPartyView struct {
	Role           string
	UserID         string // sshsign user_id; durable, safe to expose
	PartyDID       string // optional APOA DID
	PubkeyFingerprint string // hash of APOA pubkey PEM (NOT the pubkey itself)
	JoinedAt       string
}

type publicTimelineEvent struct {
	EventType string
	ActorID   string
	CreatedAt string
	Details   string
}

func buildPublicAuditView(sess *sessions.Session, members []sessions.Member, events []sessions.AuditEvent) publicAuditView {
	v := publicAuditView{
		SessionID:        sess.SessionID,
		SessionCode:      sess.SessionCode,
		Status:           string(sess.Status),
		CreatedAt:        sess.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		ExecutedArtifact: sess.ExecutedArtifact,
		MetadataPublic:   sess.MetadataPublic,
	}
	if !sess.CompletedAt.IsZero() {
		v.CompletedAt = sess.CompletedAt.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	for _, m := range members {
		v.Parties = append(v.Parties, publicPartyView{
			Role:              m.Role,
			UserID:            m.UserID,
			PartyDID:          m.PartyDID,
			PubkeyFingerprint: fingerprint(m.APOAPubkeyPEM),
			JoinedAt:          m.JoinedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		})
	}
	for _, e := range events {
		v.Timeline = append(v.Timeline, publicTimelineEvent{
			EventType: e.EventType,
			ActorID:   e.ActorID,
			CreatedAt: e.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
			Details:   e.Details,
		})
	}
	return v
}

// fingerprint returns a short, deterministic hash of a PEM-encoded key
// for public display. NOT the key itself — the whole point of the public
// audit view is that viewers can verify integrity without seeing the
// underlying keys.
func fingerprint(pem string) string {
	pem = strings.TrimSpace(pem)
	if pem == "" {
		return ""
	}
	// SHA-256 hex, first 16 chars. Good enough for visual identification;
	// anyone verifying against a known pubkey can compute the full hash.
	return fmt.Sprintf("sha256:%s", sha256Hex(pem)[:16])
}

// Separate function so we can stub it in tests if needed.
var sha256Hex = func(s string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum(nil))
}

var publicAuditTemplate = template.Must(template.New("public_audit").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Signing session {{.SessionID}} — audit</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; max-width: 780px; margin: 2rem auto; padding: 0 1rem; color: #222; }
  h1 { font-size: 1.4rem; margin-bottom: 0.25rem; }
  .subtle { color: #666; font-size: 0.9rem; }
  .status { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 4px; font-size: 0.85rem; font-weight: 600; }
  .status-completed { background: #d4edda; color: #155724; }
  .card { border: 1px solid #e0e0e0; border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0; background: #fafbfc; }
  .card h2 { font-size: 1.05rem; margin-top: 0; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th, td { text-align: left; padding: 0.4rem 0.5rem; border-bottom: 1px solid #eee; }
  th { font-weight: 600; color: #555; }
  code { background: #f0f0f0; padding: 0.1rem 0.35rem; border-radius: 3px; font-size: 0.85rem; }
  .footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #e0e0e0; color: #888; font-size: 0.85rem; }
</style>
</head>
<body>
<h1>Signing session audit</h1>
<p class="subtle">
  Session <code>{{.SessionID}}</code> · code <code>{{.SessionCode}}</code> ·
  <span class="status status-{{.Status}}">{{.Status}}</span>
</p>

<div class="card">
  <h2>Overview</h2>
  <table>
    <tr><th>Started</th><td>{{.CreatedAt}}</td></tr>
    <tr><th>Completed</th><td>{{.CompletedAt}}</td></tr>
    <tr><th>Executed artifact</th><td><code>{{.ExecutedArtifact}}</code></td></tr>
    {{if .MetadataPublic}}<tr><th>Use case</th><td><code>{{.MetadataPublic}}</code></td></tr>{{end}}
  </table>
</div>

<div class="card">
  <h2>Parties</h2>
  <table>
    <tr><th>Role</th><th>User</th><th>DID</th><th>APOA pubkey fingerprint</th><th>Joined</th></tr>
    {{range .Parties}}
    <tr>
      <td>{{.Role}}</td>
      <td><code>{{.UserID}}</code></td>
      <td>{{if .PartyDID}}<code>{{.PartyDID}}</code>{{else}}—{{end}}</td>
      <td><code>{{.PubkeyFingerprint}}</code></td>
      <td>{{.JoinedAt}}</td>
    </tr>
    {{end}}
  </table>
  <p class="subtle">Fingerprints are SHA-256 hashes of the APOA public keys. The keys themselves are not exposed. Each party retains a private audit view showing their own authorized bounds.</p>
</div>

<div class="card">
  <h2>Timeline</h2>
  <table>
    <tr><th>When</th><th>Event</th><th>Actor</th></tr>
    {{range .Timeline}}
    <tr>
      <td>{{.CreatedAt}}</td>
      <td><code>{{.EventType}}</code></td>
      <td><code>{{.ActorID}}</code></td>
    </tr>
    {{end}}
  </table>
</div>

<div class="footer">
  This audit is signed cryptographically through sshsign. To verify a
  PDF against this session, run: <code>ssh sshsign.dev verify --session {{.SessionID}}</code>.
  Authorized ranges for each party are not exposed here — they remain
  private to each signer and visible only in their own my-audit view.
</div>
</body>
</html>
`))
