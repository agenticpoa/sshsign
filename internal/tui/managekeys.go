package tui

import (
	"database/sql"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/agenticpoa/sshsign/internal/storage"
)

type manageKeysView int

const (
	viewKeyList manageKeysView = iota
	viewKeyDetail
)

type manageKeysModel struct {
	keys       []storage.SigningKey
	cursor     int
	status     string
	isError    bool
	db         *sql.DB
	user       *storage.User
	view       manageKeysView
	auths      []storage.Authorization
	authCursor int
}

func newManageKeysModel(db *sql.DB, user *storage.User) manageKeysModel {
	keys, _ := storage.ListSigningKeys(db, user.UserID)
	return manageKeysModel{
		keys: keys,
		db:   db,
		user: user,
		view: viewKeyList,
	}
}

func (mk *manageKeysModel) refreshKeys() {
	mk.keys, _ = storage.ListSigningKeys(mk.db, mk.user.UserID)
}

func (mk *manageKeysModel) refreshAuths() {
	if mk.cursor < len(mk.keys) {
		mk.auths, _ = storage.FindAuthorizationsForKey(mk.db, mk.keys[mk.cursor].KeyID)
	}
}

func (m Model) updateManageKeys(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.manageKeys.view {
	case viewKeyList:
		return m.updateKeyList(msg)
	case viewKeyDetail:
		return m.updateKeyDetail(msg)
	}
	return m, nil
}

func (m Model) updateKeyList(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "esc", "q":
			m.screen = screenWelcome
			return m, nil
		case "up", "k":
			if m.manageKeys.cursor > 0 {
				m.manageKeys.cursor--
			}
		case "down", "j":
			if m.manageKeys.cursor < len(m.manageKeys.keys)-1 {
				m.manageKeys.cursor++
			}
		case "enter":
			if len(m.manageKeys.keys) > 0 {
				m.manageKeys.view = viewKeyDetail
				m.manageKeys.authCursor = 0
				m.manageKeys.status = ""
				m.manageKeys.refreshAuths()
			}
		case "r":
			if len(m.manageKeys.keys) > 0 {
				key := m.manageKeys.keys[m.manageKeys.cursor]
				if key.RevokedAt != nil {
					m.manageKeys.status = "Key already revoked"
					m.manageKeys.isError = true
				} else if err := storage.RevokeSigningKey(m.manageKeys.db, key.KeyID); err != nil {
					m.manageKeys.status = fmt.Sprintf("Error: %v", err)
					m.manageKeys.isError = true
				} else {
					m.manageKeys.status = fmt.Sprintf("Revoked %s", key.KeyID)
					m.manageKeys.isError = false
					m.manageKeys.refreshKeys()
				}
			}
		}
	}
	return m, nil
}

func (m Model) updateKeyDetail(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "esc":
			m.manageKeys.view = viewKeyList
			m.manageKeys.status = ""
			return m, nil
		case "up", "k":
			if m.manageKeys.authCursor > 0 {
				m.manageKeys.authCursor--
			}
		case "down", "j":
			if m.manageKeys.authCursor < len(m.manageKeys.auths)-1 {
				m.manageKeys.authCursor++
			}
		case "a":
			// Add authorization to existing key
			key := m.manageKeys.keys[m.manageKeys.cursor]
			m.authSetup = newAuthSetupModelForExistingKey(m.db, m.user, key.KeyID)
			m.screen = screenAuthSetup
			return m, nil
		case "r":
			if len(m.manageKeys.auths) > 0 {
				auth := m.manageKeys.auths[m.manageKeys.authCursor]
				if err := storage.RevokeAuthorization(m.manageKeys.db, auth.TokenID); err != nil {
					m.manageKeys.status = fmt.Sprintf("Error: %v", err)
					m.manageKeys.isError = true
				} else {
					m.manageKeys.status = fmt.Sprintf("Revoked %s", auth.TokenID)
					m.manageKeys.isError = false
					m.manageKeys.refreshAuths()
					if m.manageKeys.authCursor >= len(m.manageKeys.auths) && m.manageKeys.authCursor > 0 {
						m.manageKeys.authCursor--
					}
				}
			}
		}
	}
	return m, nil
}

func (m Model) viewManageKeys() string {
	switch m.manageKeys.view {
	case viewKeyDetail:
		return m.viewKeyDetail()
	default:
		return m.viewKeyList()
	}
}

func (m Model) viewKeyList() string {
	var b strings.Builder

	b.WriteString(m.s.Title.Render("Manage Keys"))
	b.WriteString("\n\n")

	if len(m.manageKeys.keys) == 0 {
		b.WriteString(m.s.Dim.Render("  No signing keys yet."))
	} else {
		for i, key := range m.manageKeys.keys {
			cursor := "  "
			style := m.s.Normal
			if i == m.manageKeys.cursor {
				cursor = "> "
				style = m.s.Selected
			}

			status := m.s.Success.Render("active")
			if key.RevokedAt != nil {
				status = m.s.Error.Render("revoked")
			}

			// Count authorizations
			auths, _ := storage.FindAuthorizationsForKey(m.db, key.KeyID)
			authCount := len(auths)
			authLabel := fmt.Sprintf("%d auth", authCount)
			if authCount != 1 {
				authLabel += "s"
			}

			line := fmt.Sprintf("%s  [%s]  %s", key.KeyID, status, m.s.Dim.Render(authLabel))
			b.WriteString(style.Render(cursor) + line)
			b.WriteString("\n")
		}
	}

	if m.manageKeys.status != "" {
		b.WriteString("\n")
		if m.manageKeys.isError {
			b.WriteString(m.s.Error.Render("  " + m.manageKeys.status))
		} else {
			b.WriteString(m.s.Success.Render("  " + m.manageKeys.status))
		}
	}

	b.WriteString("\n\n")
	b.WriteString(m.buildHints([]hint{
		{"enter", "manage", hintAction},
		{"r", "revoke key", hintDanger},
		{"esc", "back", hintNav},
	}))

	return m.s.Border.Render(b.String())
}

func (m Model) viewKeyDetail() string {
	var b strings.Builder

	key := m.manageKeys.keys[m.manageKeys.cursor]

	b.WriteString(m.s.Title.Render("Key"))
	b.WriteString("  ")
	b.WriteString(m.s.Info.Render(key.KeyID))

	status := m.s.Success.Render("active")
	if key.RevokedAt != nil {
		status = m.s.Error.Render("revoked")
	}
	b.WriteString("  ")
	b.WriteString(status)
	b.WriteString("\n\n")

	b.WriteString(m.s.InfoLabel.Render("  Public   "))
	b.WriteString(m.s.Dim.Render(truncate(key.PublicKey, 45)))
	b.WriteString("\n")
	b.WriteString(m.s.InfoLabel.Render("  Created  "))
	b.WriteString(m.s.Dim.Render(key.CreatedAt.Format("2006-01-02 15:04")))
	b.WriteString("\n\n")

	if len(m.manageKeys.auths) == 0 {
		b.WriteString(m.s.Dim.Render("  No authorizations. This key cannot sign anything."))
		b.WriteString("\n")
	} else {
		b.WriteString(m.s.Info.Render("  Authorizations:"))
		b.WriteString("\n\n")

		for i, auth := range m.manageKeys.auths {
			cursor := "  "
			style := m.s.Normal
			if i == m.manageKeys.authCursor {
				cursor = "> "
				style = m.s.Selected
			}

			scopes := strings.Join(auth.Scopes, ", ")
			b.WriteString(style.Render(fmt.Sprintf("%s%s", cursor, auth.TokenID)))
			b.WriteString("  ")
			b.WriteString(m.s.Dim.Render(scopes))
			b.WriteString("\n")

			if i == m.manageKeys.authCursor {
				// Show details for selected auth
				if len(auth.Constraints) > 0 {
					for k, v := range auth.Constraints {
						b.WriteString(m.s.Dim.Render(fmt.Sprintf("      %s: %s", k, strings.Join(v, ", "))))
						b.WriteString("\n")
					}
				}
				if len(auth.HardRules) > 0 {
					b.WriteString(m.s.Dim.Render(fmt.Sprintf("      rules: %s", strings.Join(auth.HardRules, ", "))))
					b.WriteString("\n")
				}
				if auth.ExpiresAt != nil {
					b.WriteString(m.s.Dim.Render(fmt.Sprintf("      expires: %s", auth.ExpiresAt.Format("2006-01-02"))))
					b.WriteString("\n")
				}
			}
		}
	}

	if m.manageKeys.status != "" {
		b.WriteString("\n")
		if m.manageKeys.isError {
			b.WriteString(m.s.Error.Render("  " + m.manageKeys.status))
		} else {
			b.WriteString(m.s.Success.Render("  " + m.manageKeys.status))
		}
	}

	b.WriteString("\n\n")
	b.WriteString(m.buildHints([]hint{
		{"a", "add auth", hintAction},
		{"r", "revoke auth", hintDanger},
		{"esc", "back", hintNav},
	}))

	return m.s.Border.Render(b.String())
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
