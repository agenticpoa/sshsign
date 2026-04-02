package tui

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	gossh "golang.org/x/crypto/ssh"

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
	confirmRevoke bool // waiting for y/n confirmation
}

func newManageKeysModel(db *sql.DB, user *storage.User) manageKeysModel {
	keys, _ := storage.ListSigningKeys(db, user.UserID)
	sortKeysActiveFirst(keys)
	return manageKeysModel{
		keys: keys,
		db:   db,
		user: user,
		view: viewKeyList,
	}
}

func (mk *manageKeysModel) refreshKeys() {
	mk.keys, _ = storage.ListSigningKeys(mk.db, mk.user.UserID)
	sortKeysActiveFirst(mk.keys)
}

// sortKeysActiveFirst sorts keys so active keys come before revoked ones,
// preserving creation order within each group.
func sortKeysActiveFirst(keys []storage.SigningKey) {
	sort.SliceStable(keys, func(i, j int) bool {
		iRevoked := keys[i].RevokedAt != nil
		jRevoked := keys[j].RevokedAt != nil
		if iRevoked != jRevoked {
			return !iRevoked // active (not revoked) comes first
		}
		return false // preserve original order within group
	})
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
				} else {
					m.manageKeys.confirmRevoke = true
					m.manageKeys.status = fmt.Sprintf("Revoke key %s? (y/n)", key.KeyID)
					m.manageKeys.isError = false
				}
			}
		case "y":
			if m.manageKeys.confirmRevoke {
				key := m.manageKeys.keys[m.manageKeys.cursor]
				if err := storage.RevokeSigningKey(m.manageKeys.db, key.KeyID); err != nil {
					m.manageKeys.status = fmt.Sprintf("Error: %v", err)
					m.manageKeys.isError = true
				} else {
					m.manageKeys.status = fmt.Sprintf("Revoked %s", key.KeyID)
					m.manageKeys.isError = false
					m.manageKeys.refreshKeys()
				}
				m.manageKeys.confirmRevoke = false
			}
		case "n":
			if m.manageKeys.confirmRevoke {
				m.manageKeys.confirmRevoke = false
				m.manageKeys.status = ""
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
			m.authSetup = newAuthSetupModelForExistingKey(m.db, m.user, key.KeyID, m.r)
			m.screen = screenAuthSetup
			return m, nil
		case "e":
			// Edit: duplicate selected auth with pre-filled values, auto-revoke old on confirm
			if len(m.manageKeys.auths) > 0 {
				key := m.manageKeys.keys[m.manageKeys.cursor]
				auth := m.manageKeys.auths[m.manageKeys.authCursor]
				m.authSetup = newAuthSetupFromExisting(m.db, m.user, key.KeyID, &auth, m.r)
				m.screen = screenAuthSetup
				return m, nil
			}
		case "r":
			if len(m.manageKeys.auths) > 0 {
				auth := m.manageKeys.auths[m.manageKeys.authCursor]
				m.manageKeys.confirmRevoke = true
				m.manageKeys.status = fmt.Sprintf("Revoke authorization %s? (y/n)", auth.TokenID)
				m.manageKeys.isError = false
			}
		case "y":
			if m.manageKeys.confirmRevoke {
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
				m.manageKeys.confirmRevoke = false
			}
		case "n":
			if m.manageKeys.confirmRevoke {
				m.manageKeys.confirmRevoke = false
				m.manageKeys.status = ""
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

// scopeSummary returns a human-readable label for an authorization's scope.
func scopeSummary(auths []storage.Authorization) string {
	if len(auths) == 0 {
		return "no auth"
	}
	seen := map[string]bool{}
	var labels []string
	for _, a := range auths {
		for _, s := range a.Scopes {
			if seen[s] {
				continue
			}
			seen[s] = true
			// Map scope IDs to friendly names
			switch s {
			case "git-commit":
				labels = append(labels, "Git")
			case "safe-agreement":
				labels = append(labels, "SAFE")
			case "nda":
				labels = append(labels, "NDA")
			case "*":
				labels = append(labels, "all")
			default:
				labels = append(labels, s)
			}
		}
	}
	return strings.Join(labels, ", ")
}

// tierBadge returns a short label for the confirmation tier.
func tierBadge(auths []storage.Authorization) string {
	for _, a := range auths {
		if a.ConfirmationTier == "cosign" {
			return "cosign"
		}
	}
	return ""
}

func (m Model) viewKeyList() string {
	var b strings.Builder

	b.WriteString(m.s.Title.Render("Manage Keys"))
	b.WriteString("\n\n")

	if len(m.manageKeys.keys) == 0 {
		b.WriteString(m.s.Dim.Render("  No signing keys yet."))
	} else {
		// Split into active and revoked
		var activeIdxs, revokedIdxs []int
		for i, key := range m.manageKeys.keys {
			if key.RevokedAt != nil {
				revokedIdxs = append(revokedIdxs, i)
			} else {
				activeIdxs = append(activeIdxs, i)
			}
		}

		if len(activeIdxs) > 0 {
			b.WriteString(m.s.Info.Render("  Active Keys"))
			b.WriteString("\n\n")
			for _, i := range activeIdxs {
				m.renderKeyRow(&b, i)
			}
		}

		if len(revokedIdxs) > 0 {
			if len(activeIdxs) > 0 {
				b.WriteString("\n")
				b.WriteString(m.s.Divider.Render("  " + strings.Repeat("─", 40)))
				b.WriteString("\n\n")
			}
			b.WriteString(m.s.Dim.Render("  Revoked Keys"))
			b.WriteString("\n\n")
			for _, i := range revokedIdxs {
				m.renderKeyRow(&b, i)
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
		{"enter", "manage", hintAction},
		{"r", "revoke key", hintDanger},
		{"esc", "back", hintNav},
	}))

	return m.s.Border.Render(b.String())
}

func (m Model) renderKeyRow(b *strings.Builder, i int) {
	key := m.manageKeys.keys[i]
	cursor := "  "
	style := m.s.Normal
	if i == m.manageKeys.cursor {
		cursor = "> "
		style = m.s.Selected
	}

	auths, _ := storage.FindAuthorizationsForKey(m.db, key.KeyID)
	scopeLabel := scopeSummary(auths)
	tier := tierBadge(auths)
	authCount := len(auths)
	authLabel := fmt.Sprintf("%d auth", authCount)
	if authCount != 1 {
		authLabel += "s"
	}

	// Line 1: key ID, scope, auth count, tier
	line := fmt.Sprintf("%s  %s  %s", key.KeyID, m.s.Info.Render(scopeLabel), m.s.Dim.Render(authLabel))
	if tier != "" {
		line += "  " + m.s.Dim.Render("["+tier+"]")
	}
	if key.RevokedAt != nil {
		line += "  " + m.s.Error.Render("revoked")
	}
	b.WriteString(style.Render(cursor) + line)
	b.WriteString("\n")

	// Details (selected only): fingerprint, dates on separate lines
	if i == m.manageKeys.cursor {
		fp := keyFingerprint(key.PublicKey)
		b.WriteString(m.s.Dim.Render(fmt.Sprintf("      %s", fp)))
		b.WriteString("\n")
		b.WriteString(m.s.Dim.Render(fmt.Sprintf("      created %s", key.CreatedAt.Format("Jan 2, 2006 15:04"))))
		b.WriteString("\n")
		if key.RevokedAt != nil {
			b.WriteString(m.s.Dim.Render(fmt.Sprintf("      revoked %s", key.RevokedAt.Format("Jan 2, 2006 15:04"))))
			b.WriteString("\n")
		}
	}
}

func keyFingerprint(pubKeyStr string) string {
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(pubKeyStr))
	if err != nil {
		return "unknown"
	}
	return gossh.FingerprintSHA256(pub)
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

	b.WriteString(m.s.InfoLabel.Render("  Fingerprint  "))
	b.WriteString(m.s.Dim.Render(keyFingerprint(key.PublicKey)))
	b.WriteString("\n")
	b.WriteString(m.s.InfoLabel.Render("  Created      "))
	b.WriteString(m.s.Dim.Render(key.CreatedAt.Format("Jan 2, 2006 15:04")))
	b.WriteString("\n")
	if key.RevokedAt != nil {
		b.WriteString(m.s.InfoLabel.Render("  Revoked      "))
		b.WriteString(m.s.Error.Render(key.RevokedAt.Format("Jan 2, 2006 15:04")))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	if len(m.manageKeys.auths) == 0 {
		b.WriteString(m.s.Dim.Render("  No authorizations. This key cannot sign anything."))
		b.WriteString("\n")
	} else {
		b.WriteString(m.s.Info.Render("  Authorizations:"))
		b.WriteString("\n\n")

		for i, a := range m.manageKeys.auths {
			cursor := "  "
			style := m.s.Normal
			if i == m.manageKeys.authCursor {
				cursor = "> "
				style = m.s.Selected
			}

			// Scope with friendly name
			scopeLabel := scopeSummary([]storage.Authorization{a})
			b.WriteString(style.Render(fmt.Sprintf("%s%s", cursor, a.TokenID)))
			b.WriteString("  ")
			b.WriteString(m.s.Info.Render(scopeLabel))
			if a.ConfirmationTier == "cosign" {
				b.WriteString("  ")
				b.WriteString(m.s.Dim.Render("[cosign]"))
			}
			b.WriteString("\n")

			if i == m.manageKeys.authCursor {
				// Repo constraints
				if len(a.Constraints) > 0 {
					for k, v := range a.Constraints {
						b.WriteString(m.s.Dim.Render(fmt.Sprintf("      %s: %s", k, strings.Join(v, ", "))))
						b.WriteString("\n")
					}
				}

				// Metadata constraints
				if len(a.MetadataConstraints) > 0 {
					for _, mc := range a.MetadataConstraints {
						b.WriteString(m.s.Dim.Render(fmt.Sprintf("      %s: %s", mc.Field, formatMetadataConstraint(mc))))
						b.WriteString("\n")
					}
				}

				// Rules
				if len(a.HardRules) > 0 {
					b.WriteString(m.s.Dim.Render(fmt.Sprintf("      rules: %s", strings.Join(a.HardRules, ", "))))
					b.WriteString("\n")
				}

				// Expiry
				if a.ExpiresAt != nil {
					b.WriteString(m.s.Dim.Render(fmt.Sprintf("      expires: %s", a.ExpiresAt.Format("Jan 2, 2006 15:04"))))
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
	hints := []hint{
		{"a", "add auth", hintAction},
	}
	if len(m.manageKeys.auths) > 0 {
		hints = append(hints, hint{"e", "edit auth", hintAction})
		hints = append(hints, hint{"r", "revoke auth", hintDanger})
	}
	hints = append(hints, hint{"esc", "back", hintNav})
	b.WriteString(m.buildHints(hints))

	return m.s.Border.Render(b.String())
}

func formatMetadataConstraint(mc storage.MetadataConstraint) string {
	switch mc.Type {
	case "range":
		minS, maxS := "?", "?"
		if mc.Min != nil {
			minS = formatNumber(*mc.Min)
		}
		if mc.Max != nil {
			maxS = formatNumber(*mc.Max)
		}
		return fmt.Sprintf("range %s - %s", minS, maxS)
	case "minimum":
		if mc.Min != nil {
			return fmt.Sprintf("min %s", formatNumber(*mc.Min))
		}
		return "min ?"
	case "maximum":
		if mc.Max != nil {
			return fmt.Sprintf("max %s", formatNumber(*mc.Max))
		}
		return "max ?"
	case "enum":
		return fmt.Sprintf("allow [%s]", strings.Join(mc.Allowed, ", "))
	case "required_bool":
		if mc.Required != nil && *mc.Required {
			return "required true"
		}
		return "required false"
	}
	return mc.Type
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
