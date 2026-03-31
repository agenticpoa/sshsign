package tui

import (
	"database/sql"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/agenticpoa/sshsign/internal/storage"
)

// auditLogModel displays signing activity from the signing_keys and authorizations tables.
// In Phase 3, this will be backed by immudb. For now, it shows key/auth activity from SQLite.
type auditLogModel struct {
	entries []auditDisplayEntry
	cursor  int
	offset  int
	db      *sql.DB
	user    *storage.User
}

type auditDisplayEntry struct {
	KeyID     string
	Action    string // "created", "revoked"
	Timestamp string
	Detail    string
}

func newAuditLogModel(db *sql.DB, user *storage.User) auditLogModel {
	var entries []auditDisplayEntry

	keys, _ := storage.ListSigningKeys(db, user.UserID)
	for _, k := range keys {
		entries = append(entries, auditDisplayEntry{
			KeyID:     k.KeyID,
			Action:    "key created",
			Timestamp: k.CreatedAt.Format("2006-01-02 15:04"),
			Detail:    truncate(k.PublicKey, 40),
		})
		if k.RevokedAt != nil {
			entries = append(entries, auditDisplayEntry{
				KeyID:     k.KeyID,
				Action:    "key revoked",
				Timestamp: k.RevokedAt.Format("2006-01-02 15:04"),
			})
		}

		auths, _ := storage.FindAuthorizationsForKey(db, k.KeyID)
		for _, a := range auths {
			entries = append(entries, auditDisplayEntry{
				KeyID:     k.KeyID,
				Action:    "auth created",
				Timestamp: a.CreatedAt.Format("2006-01-02 15:04"),
				Detail:    fmt.Sprintf("%s scopes=%v", a.TokenID, a.Scopes),
			})
		}
	}

	// Reverse so newest is first
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	return auditLogModel{
		entries: entries,
		db:      db,
		user:    user,
	}
}

func (m Model) updateAuditLog(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "esc", "q":
			m.screen = screenWelcome
			return m, nil
		case "up", "k":
			if m.auditLog.cursor > 0 {
				m.auditLog.cursor--
			}
		case "down", "j":
			if m.auditLog.cursor < len(m.auditLog.entries)-1 {
				m.auditLog.cursor++
			}
		}
	}
	return m, nil
}

func (m Model) viewAuditLog() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Audit Log"))
	b.WriteString("\n\n")

	if len(m.auditLog.entries) == 0 {
		b.WriteString(dimStyle.Render("  No activity yet."))
	} else {
		// Show up to 15 entries
		maxVisible := 15
		start := 0
		if m.auditLog.cursor >= maxVisible {
			start = m.auditLog.cursor - maxVisible + 1
		}
		end := start + maxVisible
		if end > len(m.auditLog.entries) {
			end = len(m.auditLog.entries)
		}

		for i := start; i < end; i++ {
			entry := m.auditLog.entries[i]
			cursor := "  "
			style := normalStyle
			if i == m.auditLog.cursor {
				cursor = "> "
				style = selectedStyle
			}

			actionStyle := dimStyle
			if strings.Contains(entry.Action, "revoked") {
				actionStyle = errorStyle
			}

			line := fmt.Sprintf("%s %s %s", entry.Timestamp, actionStyle.Render(entry.Action), entry.KeyID)
			b.WriteString(style.Render(cursor + line))
			b.WriteString("\n")

			if i == m.auditLog.cursor && entry.Detail != "" {
				b.WriteString(dimStyle.Render("    " + entry.Detail))
				b.WriteString("\n")
			}
		}

		if len(m.auditLog.entries) > maxVisible {
			b.WriteString("\n")
			b.WriteString(dimStyle.Render(fmt.Sprintf("  Showing %d-%d of %d entries", start+1, end, len(m.auditLog.entries))))
		}
	}

	b.WriteString("\n\n")
	b.WriteString(buildHints([]hint{
		{"j/k", "scroll", hintNav},
		{"esc", "back", hintNav},
	}))

	return borderStyle.Render(b.String())
}
