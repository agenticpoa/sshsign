package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/storage"
)

type welcomeMenuItem int

const (
	menuCreateKey welcomeMenuItem = iota
	menuManageKeys
	menuAuthSetup
	menuAuditLog
	menuLinkKey
	menuExit
)

type welcomeModel struct {
	user      *storage.User
	userKey   *storage.UserKey
	isNewUser bool
	cursor    int
	items     []welcomeMenuItem
	status    string
	isError   bool
}

func newWelcomeModel(user *storage.User, userKey *storage.UserKey, isNewUser bool) welcomeModel {
	var items []welcomeMenuItem
	if isNewUser {
		items = []welcomeMenuItem{menuCreateKey, menuLinkKey, menuExit}
	} else {
		items = []welcomeMenuItem{menuCreateKey, menuManageKeys, menuAuditLog, menuLinkKey, menuExit}
	}
	return welcomeModel{
		user:      user,
		userKey:   userKey,
		isNewUser: isNewUser,
		items:     items,
	}
}

func menuLabel(item welcomeMenuItem) string {
	switch item {
	case menuCreateKey:
		return "New signing key"
	case menuManageKeys:
		return "Manage keys"
	case menuAuthSetup:
		return "Add authorization"
	case menuAuditLog:
		return "Audit log"
	case menuLinkKey:
		return "Link SSH key"
	case menuExit:
		return "Exit"
	default:
		return ""
	}
}

func (m Model) updateWelcome(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case statusMsg:
		m.welcome.status = msg.message
		m.welcome.isError = msg.isError
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.welcome.cursor > 0 {
				m.welcome.cursor--
			}
		case "down", "j":
			if m.welcome.cursor < len(m.welcome.items)-1 {
				m.welcome.cursor++
			}
		case "enter":
			switch m.welcome.items[m.welcome.cursor] {
			case menuCreateKey:
				return m.handleCreateKey()
			case menuManageKeys:
				m.manageKeys = newManageKeysModel(m.db, m.user)
				m.screen = screenManageKeys
				return m, nil
			case menuAuthSetup:
				m.authSetup = newAuthSetupModel(m.db, m.user, m.r)
				m.screen = screenAuthSetup
				return m, nil
			case menuAuditLog:
				m.auditLog = newAuditLogModel(m.db, m.user)
				m.screen = screenAuditLog
				return m, nil
			case menuLinkKey:
				m.screen = screenLinkKey
				m.linkKey = newLinkKeyModel(m.r)
				return m, m.linkKey.input.Focus()
			case menuExit:
				return m, tea.Quit
			}
		case "q":
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m Model) handleCreateKey() (tea.Model, tea.Cmd) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		m.welcome.status = fmt.Sprintf("Error generating key: %v", err)
		m.welcome.isError = true
		return m, nil
	}

	pubSSH, err := crypto.MarshalPublicKeySSH(pub)
	if err != nil {
		m.welcome.status = fmt.Sprintf("Error marshaling key: %v", err)
		m.welcome.isError = true
		return m, nil
	}

	dek, err := crypto.GenerateDEK()
	if err != nil {
		m.welcome.status = fmt.Sprintf("Error generating DEK: %v", err)
		m.welcome.isError = true
		return m, nil
	}
	defer crypto.ZeroBytes(dek)

	encPrivKey, err := crypto.EncryptPrivateKey(priv, dek)
	if err != nil {
		m.welcome.status = fmt.Sprintf("Error encrypting key: %v", err)
		m.welcome.isError = true
		return m, nil
	}
	crypto.ZeroBytes(priv)

	wrappedDEK, err := crypto.WrapDEK(dek, m.kek)
	if err != nil {
		m.welcome.status = fmt.Sprintf("Error wrapping DEK: %v", err)
		m.welcome.isError = true
		return m, nil
	}

	keyID := storage.NewKeyID()
	m.authSetup = newAuthSetupModelForPendingKey(m.db, m.user, keyID, pubSSH, encPrivKey, wrappedDEK, m.r)
	m.screen = screenAuthSetup
	return m, nil
}

func (m Model) viewWelcome() string {
	var b strings.Builder
	s := m.s

	b.WriteString("\n")
	b.WriteString(s.LogoPrompt.Render(" /\\   ") + s.Title.Render("          _"))
	b.WriteString("\n")
	b.WriteString(s.LogoPrompt.Render(" \\ \\  ") + s.Title.Render("  ___ ___| |__  ___(_) __ _ _ __"))
	b.WriteString("\n")
	b.WriteString(s.LogoPrompt.Render("  > > ") + s.Title.Render(" / __/ __| '_ \\/ __| |/ _` | '_ \\"))
	b.WriteString("\n")
	b.WriteString(s.LogoPrompt.Render(" / /  ") + s.Title.Render(" \\__ \\__ \\ | | \\__ \\ | (_| | | | |"))
	b.WriteString("\n")
	b.WriteString(s.LogoPrompt.Render(" \\/   ") + s.Title.Render(" |___/___/_| |_|___/_|\\__, |_| |_|"))
	b.WriteString("\n")
	b.WriteString(s.LogoPrompt.Render("      ") + s.Title.Render("                      |___/"))
	b.WriteString("\n\n")

	if m.user != nil {
		b.WriteString(s.InfoLabel.Render("  User    "))
		b.WriteString(s.Info.Render(m.user.UserID))
		b.WriteString("\n")
		if m.userKey != nil {
			fp := m.userKey.SSHFingerprint
			if len(fp) > 40 {
				fp = fp[:40] + "..."
			}
			b.WriteString(s.InfoLabel.Render("  Key     "))
			b.WriteString(s.Info.Render(fp))
			b.WriteString("\n")
		}
		if !m.isNewUser && m.db != nil {
			keys, _ := storage.ListSigningKeys(m.db, m.user.UserID)
			active, revoked := 0, 0
			for _, k := range keys {
				if k.RevokedAt != nil {
					revoked++
				} else {
					active++
				}
			}
			b.WriteString(s.InfoLabel.Render("  Signs   "))
			b.WriteString(s.Info.Render(fmt.Sprintf("%d active, %d revoked", active, revoked)))
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")

	for i, item := range m.welcome.items {
		cursor := "  "
		style := s.Normal
		if item == menuExit {
			style = s.Exit
		}
		if i == m.welcome.cursor {
			cursor = "> "
			style = s.Selected
		}
		b.WriteString(style.Render(cursor + menuLabel(item)))
		b.WriteString("\n")
	}

	if m.welcome.status != "" {
		b.WriteString("\n")
		if m.welcome.isError {
			b.WriteString(s.Error.Render("  " + m.welcome.status))
		} else {
			b.WriteString(s.Success.Render("  " + m.welcome.status))
		}
	}

	b.WriteString("\n")
	b.WriteString(m.buildHints([]hint{
		{"j/k", "navigate", hintNav},
		{"enter", "select", hintAction},
		{"q", "quit", hintNav},
	}))

	return s.Border.Render(b.String())
}
