package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	gossh "golang.org/x/crypto/ssh"

	"github.com/agenticpoa/sshsign/internal/storage"
)

type linkKeyField int

const (
	fieldPublicKey linkKeyField = iota
	fieldLabel
)

type linkKeyModel struct {
	input      textinput.Model
	labelInput textinput.Model
	focus      linkKeyField
	err        string
	done       bool
}

func newLinkKeyModel() linkKeyModel {
	input := newStaticCursorInput()
	input.Placeholder = "ssh-ed25519 AAAA..."
	input.CharLimit = 1024
	input.Width = 60

	label := newStaticCursorInput()
	label.Placeholder = "work laptop"
	label.CharLimit = 64
	label.Width = 40

	return linkKeyModel{
		input:      input,
		labelInput: label,
		focus:      fieldPublicKey,
	}
}

func (m Model) updateLinkKey(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			m.screen = screenWelcome
			return m, nil
		case "tab":
			if m.linkKey.focus == fieldPublicKey {
				m.linkKey.focus = fieldLabel
				m.linkKey.input.Blur()
				return m, m.linkKey.labelInput.Focus()
			}
			m.linkKey.focus = fieldPublicKey
			m.linkKey.labelInput.Blur()
			return m, m.linkKey.input.Focus()
		case "enter":
			if m.linkKey.focus == fieldPublicKey {
				m.linkKey.focus = fieldLabel
				m.linkKey.input.Blur()
				return m, m.linkKey.labelInput.Focus()
			}
			return m.handleLinkKey()
		}
	}

	var cmd tea.Cmd
	if m.linkKey.focus == fieldPublicKey {
		m.linkKey.input, cmd = m.linkKey.input.Update(msg)
	} else {
		m.linkKey.labelInput, cmd = m.linkKey.labelInput.Update(msg)
	}
	return m, cmd
}

func (m Model) handleLinkKey() (tea.Model, tea.Cmd) {
	pubKeyStr := strings.TrimSpace(m.linkKey.input.Value())
	label := strings.TrimSpace(m.linkKey.labelInput.Value())

	if pubKeyStr == "" {
		m.linkKey.err = "Public key is required"
		return m, nil
	}

	pubKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(pubKeyStr))
	if err != nil {
		m.linkKey.err = "Invalid SSH public key format"
		return m, nil
	}

	fingerprint := gossh.FingerprintSHA256(pubKey)

	_, err = storage.LinkKey(m.db, m.user.UserID, fingerprint, pubKeyStr, label)
	if err != nil {
		m.linkKey.err = fmt.Sprintf("Failed to link key: %v", err)
		return m, nil
	}

	m.screen = screenWelcome
	m.welcome.status = fmt.Sprintf("Linked SSH key: %s", fingerprint)
	m.welcome.isError = false
	return m, nil
}

func (m Model) viewLinkKey() string {
	var b strings.Builder
	s := m.s

	b.WriteString(s.Title.Render("Link SSH Key"))
	b.WriteString("\n\n")

	if m.user != nil {
		b.WriteString(s.Info.Render(fmt.Sprintf("  Current identity: %s", m.user.UserID)))
		b.WriteString("\n\n")
	}

	b.WriteString(s.Info.Render("  Paste the public key to link:"))
	b.WriteString("\n")
	b.WriteString("  " + m.linkKey.input.View())
	b.WriteString("\n\n")

	b.WriteString(s.Info.Render("  Label:"))
	b.WriteString("\n")
	b.WriteString("  " + m.linkKey.labelInput.View())

	if m.linkKey.err != "" {
		b.WriteString("\n\n")
		b.WriteString(s.Error.Render("  " + m.linkKey.err))
	}

	b.WriteString("\n\n")
	b.WriteString(m.buildHints([]hint{
		{"tab", "switch field", hintNav},
		{"enter", "submit", hintAction},
		{"esc", "cancel", hintNav},
	}))

	return s.Border.Render(b.String())
}
