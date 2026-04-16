package tui

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/agenticpoa/sshsign/internal/audit"
	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/signing"
	"github.com/agenticpoa/sshsign/internal/storage"
)

type pendingView int

const (
	pendingViewList pendingView = iota
	pendingViewDetail
)

type pendingApprovalsModel struct {
	db       *sql.DB
	user     *storage.User
	pendings []storage.PendingSignature
	cursor   int
	view     pendingView
	status   string
	isError  bool

	// Approval confirmation state
	confirmAction string // "approve" or "deny"
}

func newPendingApprovalsModel(db *sql.DB, user *storage.User) pendingApprovalsModel {
	m := pendingApprovalsModel{db: db, user: user}
	m.refresh()
	return m
}

func (p *pendingApprovalsModel) refresh() {
	pendings, _ := storage.ListPendingSignatures(p.db, p.user.UserID)
	p.pendings = pendings
	if p.cursor >= len(pendings) && len(pendings) > 0 {
		p.cursor = len(pendings) - 1
	}
}

func (m Model) updatePendingApprovals(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.pending.view {
	case pendingViewDetail:
		return m.updatePendingDetail(msg)
	default:
		return m.updatePendingList(msg)
	}
}

func (m Model) updatePendingList(msg tea.Msg) (tea.Model, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	switch km.String() {
	case "esc", "q":
		m.screen = screenWelcome
		return m, nil
	case "up", "k":
		if m.pending.cursor > 0 {
			m.pending.cursor--
		}
	case "down", "j":
		if m.pending.cursor < len(m.pending.pendings)-1 {
			m.pending.cursor++
		}
	case "r":
		m.pending.refresh()
		m.pending.status = "Refreshed"
		m.pending.isError = false
	case "enter":
		if len(m.pending.pendings) > 0 {
			m.pending.view = pendingViewDetail
			m.pending.status = ""
			m.pending.confirmAction = ""
		}
	}
	return m, nil
}

func (m Model) updatePendingDetail(msg tea.Msg) (tea.Model, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	// Handle confirmation state
	if m.pending.confirmAction != "" {
		switch km.String() {
		case "y":
			return m.executeApprovalAction()
		case "n", "esc":
			m.pending.confirmAction = ""
			m.pending.status = ""
			return m, nil
		}
		return m, nil
	}

	switch km.String() {
	case "esc":
		m.pending.view = pendingViewList
		m.pending.status = ""
		m.pending.refresh()
		return m, nil
	case "a":
		ps := m.pending.pendings[m.pending.cursor]
		auth, _ := storage.GetAuthorization(m.db, ps.AuthTokenID)
		if auth != nil && auth.RequireSignature {
			m.pending.status = "This approval requires a handwritten signature. Open the URL above in your browser."
			m.pending.isError = true
			return m, nil
		}
		m.pending.confirmAction = "approve"
		m.pending.status = ""
	case "d":
		m.pending.confirmAction = "deny"
		m.pending.status = ""
	}
	return m, nil
}

func (m Model) executeApprovalAction() (tea.Model, tea.Cmd) {
	ps := m.pending.pendings[m.pending.cursor]
	action := m.pending.confirmAction
	m.pending.confirmAction = ""

	if action == "deny" {
		if err := storage.ResolvePendingSignature(m.db, ps.ID, "denied", m.user.UserID, ""); err != nil {
			m.pending.status = fmt.Sprintf("Error: %v", err)
			m.pending.isError = true
			return m, nil
		}
		if m.auditLogger != nil {
			m.auditLogger.Log(audit.Entry{
				UserID:             m.user.UserID,
				SigningKeyID:       ps.SigningKeyID,
				ActionType:         ps.DocType,
				PayloadHash:        ps.PayloadHash,
				AuthorizationToken: ps.AuthTokenID,
				Result:             "DENIED",
				DenialReason:       "denied by principal via TUI",
			})
		}
		m.pending.status = fmt.Sprintf("Denied %s", ps.ID)
		m.pending.isError = false
		m.pending.view = pendingViewList
		m.pending.refresh()
		return m, nil
	}

	// Approve: re-validate and sign
	auth, err := storage.GetAuthorization(m.db, ps.AuthTokenID)
	if err != nil || auth == nil {
		m.pending.status = "Authorization not found"
		m.pending.isError = true
		return m, nil
	}
	if auth.RevokedAt != nil {
		m.pending.status = "Authorization has been revoked"
		m.pending.isError = true
		return m, nil
	}
	if auth.ExpiresAt != nil && time.Now().After(*auth.ExpiresAt) {
		m.pending.status = "Authorization has expired"
		m.pending.isError = true
		return m, nil
	}

	sk, err := storage.GetSigningKey(m.db, ps.SigningKeyID)
	if err != nil || sk == nil {
		m.pending.status = "Signing key not found"
		m.pending.isError = true
		return m, nil
	}
	if sk.RevokedAt != nil {
		m.pending.status = "Signing key has been revoked"
		m.pending.isError = true
		return m, nil
	}

	if m.auditLogger != nil && !m.auditLogger.Healthy() {
		m.pending.status = "Audit log unavailable: signing denied for safety"
		m.pending.isError = true
		return m, nil
	}

	dek, err := apoacrypto.UnwrapDEK(sk.DEKEncrypted, m.kek)
	if err != nil {
		m.pending.status = "Key decryption failed"
		m.pending.isError = true
		return m, nil
	}
	defer apoacrypto.ZeroBytes(dek)

	privKey, err := apoacrypto.DecryptPrivateKey(sk.PrivateKeyEncrypted, dek)
	if err != nil {
		m.pending.status = "Key decryption failed"
		m.pending.isError = true
		return m, nil
	}
	defer apoacrypto.ZeroBytes(privKey)

	sig, err := signing.Sign(privKey, []byte(ps.PayloadHash), ps.DocType)
	if err != nil {
		m.pending.status = fmt.Sprintf("Signing failed: %v", err)
		m.pending.isError = true
		return m, nil
	}

	if err := storage.ResolvePendingSignature(m.db, ps.ID, "approved", m.user.UserID, string(sig)); err != nil {
		m.pending.status = fmt.Sprintf("Error: %v", err)
		m.pending.isError = true
		return m, nil
	}

	if m.auditLogger != nil {
		m.auditLogger.Log(audit.Entry{
			UserID:             m.user.UserID,
			SigningKeyID:       sk.KeyID,
			ActionType:         ps.DocType,
			PayloadHash:        ps.PayloadHash,
			AuthorizationToken: ps.AuthTokenID,
			Result:             "SIGNED",
			Signature:          string(sig),
		})
	}
	storage.RecordKeyUsage(m.db, sk.KeyID)

	m.pending.status = fmt.Sprintf("Approved %s", ps.ID)
	m.pending.isError = false
	m.pending.view = pendingViewList
	m.pending.refresh()
	return m, nil
}

func (m Model) viewPendingApprovals() string {
	if m.pending.view == pendingViewDetail {
		return m.viewPendingDetail()
	}
	return m.viewPendingList()
}

func (m Model) viewPendingList() string {
	var b strings.Builder

	b.WriteString(m.s.Title.Render("Pending Approvals"))
	b.WriteString("\n\n")

	if len(m.pending.pendings) == 0 {
		b.WriteString(m.s.Dim.Render("  No pending approvals."))
		b.WriteString("\n")
	} else {
		for i, ps := range m.pending.pendings {
			cursor := "  "
			style := m.s.Normal
			if i == m.pending.cursor {
				cursor = "> "
				style = m.s.Selected
			}

			scope := formatScope(ps.DocType)
			age := time.Since(ps.CreatedAt).Round(time.Minute)
			ageStr := formatAge(age)

			b.WriteString(style.Render(fmt.Sprintf("%s%s", cursor, scope)))
			b.WriteString("  ")
			b.WriteString(m.s.Dim.Render(fmt.Sprintf("from %s, %s ago", ps.RequesterID, ageStr)))
			b.WriteString("\n")

			if i == m.pending.cursor {
				auth, _ := storage.GetAuthorization(m.db, ps.AuthTokenID)
				if auth != nil && auth.RequireSignature {
					b.WriteString(m.s.Dim.Render("      requires handwritten signature (browser)"))
					b.WriteString("\n")
				}
			}
		}
	}

	if m.pending.status != "" {
		b.WriteString("\n")
		if m.pending.isError {
			b.WriteString(m.s.Error.Render("  " + m.pending.status))
		} else {
			b.WriteString(m.s.Success.Render("  " + m.pending.status))
		}
	}

	b.WriteString("\n\n")
	hints := []hint{{"j/k", "navigate", hintNav}}
	if len(m.pending.pendings) > 0 {
		hints = append(hints, hint{"enter", "view", hintAction})
	}
	hints = append(hints, hint{"r", "refresh", hintAction}, hint{"esc", "back", hintNav})
	b.WriteString(m.buildHints(hints))

	return m.s.Border.Render(b.String())
}

func (m Model) viewPendingDetail() string {
	var b strings.Builder
	ps := m.pending.pendings[m.pending.cursor]
	auth, _ := storage.GetAuthorization(m.db, ps.AuthTokenID)

	b.WriteString(m.s.Title.Render(formatScope(ps.DocType)))
	b.WriteString("\n\n")

	b.WriteString(m.s.InfoLabel.Render("  Pending    "))
	b.WriteString(m.s.Info.Render(ps.ID))
	b.WriteString("\n")
	b.WriteString(m.s.InfoLabel.Render("  Requester  "))
	b.WriteString(m.s.Info.Render(ps.RequesterID))
	b.WriteString("\n")
	b.WriteString(m.s.InfoLabel.Render("  Key        "))
	b.WriteString(m.s.Info.Render(ps.SigningKeyID))
	b.WriteString("\n")
	b.WriteString(m.s.InfoLabel.Render("  Submitted  "))
	b.WriteString(m.s.Info.Render(ps.CreatedAt.Format("Jan 2, 2006 15:04 UTC")))
	b.WriteString("\n\n")

	if ps.Metadata != "" {
		b.WriteString(m.s.InfoLabel.Render("  Metadata"))
		b.WriteString("\n")
		b.WriteString(m.s.Dim.Render("  " + ps.Metadata))
		b.WriteString("\n\n")
	}

	if auth != nil && auth.RequireSignature {
		b.WriteString(m.s.Error.Render("  ⚠ Requires handwritten signature"))
		b.WriteString("\n")
		b.WriteString(m.s.Dim.Render("  Open this URL in your browser:"))
		b.WriteString("\n")
		if ps.ApprovalToken != "" {
			url := fmt.Sprintf("https://sshsign.dev/approve/%s?token=%s", ps.ID, ps.ApprovalToken)
			b.WriteString(m.s.Info.Render("  " + url))
		} else {
			b.WriteString(m.s.Dim.Render("  (no approval token recorded for this pending)"))
		}
		b.WriteString("\n\n")
	}

	if m.pending.confirmAction == "approve" {
		b.WriteString(m.s.Error.Render("  ESIGN Disclosure"))
		b.WriteString("\n\n")
		b.WriteString(m.s.Dim.Render("  By approving, you confirm: (1) you have reviewed the terms,"))
		b.WriteString("\n")
		b.WriteString(m.s.Dim.Render("  (2) your approval is legally binding as an electronic signature"))
		b.WriteString("\n")
		b.WriteString(m.s.Dim.Render("  under the ESIGN Act (15 U.S.C. 7001), and (3) a tamper-evident"))
		b.WriteString("\n")
		b.WriteString(m.s.Dim.Render("  record will be created."))
		b.WriteString("\n\n")
		b.WriteString(m.s.Selected.Render("  Approve this signature? (y/n)"))
		b.WriteString("\n")
	} else if m.pending.confirmAction == "deny" {
		b.WriteString(m.s.Selected.Render("  Deny this signature? (y/n)"))
		b.WriteString("\n")
	}

	if m.pending.status != "" {
		b.WriteString("\n")
		if m.pending.isError {
			b.WriteString(m.s.Error.Render("  " + m.pending.status))
		} else {
			b.WriteString(m.s.Success.Render("  " + m.pending.status))
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")
	var hints []hint
	if m.pending.confirmAction != "" {
		hints = []hint{
			{"y", "confirm", hintAction},
			{"n", "cancel", hintNav},
		}
	} else {
		hints = []hint{
			{"a", "approve", hintAction},
			{"d", "deny", hintDanger},
			{"esc", "back", hintNav},
		}
	}
	b.WriteString(m.buildHints(hints))

	return m.s.Border.Render(b.String())
}

func formatScope(scope string) string {
	switch scope {
	case "safe-agreement":
		return "SAFE Agreement"
	case "nda":
		return "NDA"
	case "git-commit":
		return "Git Commit"
	default:
		return scope
	}
}

func formatAge(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
