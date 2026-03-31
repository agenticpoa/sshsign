package tui

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/agenticpoa/sshsign/internal/auth"
	"github.com/agenticpoa/sshsign/internal/storage"
)

type authSetupStep int

const (
	stepSelectKey authSetupStep = iota
	stepRepoConstraint
	stepSelectRules
	stepExpiry
	stepConfirm
)

type authSetupModel struct {
	db      *sql.DB
	user    *storage.User
	keys    []storage.SigningKey
	cursor  int
	step    authSetupStep
	status  string
	isError bool

	selectedKeyID string
	repoInput     textinput.Model
	rules         []ruleOption
	ruleCursor    int
	expiryDays    int
	fromWizard    bool // true when entered via "New signing key"
}

type ruleOption struct {
	def     auth.RuleDefinition
	checked bool
}

func newAuthSetupModel(db *sql.DB, user *storage.User) authSetupModel {
	keys, _ := storage.ListSigningKeys(db, user.UserID)

	var active []storage.SigningKey
	for _, k := range keys {
		if k.RevokedAt == nil {
			active = append(active, k)
		}
	}

	return authSetupModel{
		db:         db,
		user:       user,
		keys:       active,
		step:       stepSelectKey,
		repoInput:  newRepoInput(),
		rules:      newRuleOptions(),
		expiryDays: 30,
	}
}

// newAuthSetupModelForKey is used when creating a new key (wizard flow).
func newAuthSetupModelForKey(db *sql.DB, user *storage.User, keyID string) authSetupModel {
	m := newAuthSetupModel(db, user)
	m.selectedKeyID = keyID
	m.step = stepRepoConstraint
	m.fromWizard = true
	m.repoInput.Focus()
	return m
}

// newAuthSetupModelForExistingKey is used when adding auth from Manage Keys.
func newAuthSetupModelForExistingKey(db *sql.DB, user *storage.User, keyID string) authSetupModel {
	m := newAuthSetupModel(db, user)
	m.selectedKeyID = keyID
	m.step = stepRepoConstraint
	m.fromWizard = false
	m.repoInput.Focus()
	return m
}

func newRepoInput() textinput.Model {
	input := textinput.New()
	input.Placeholder = "github.com/user/* (leave empty to skip)"
	input.Width = 50
	return input
}

func newRuleOptions() []ruleOption {
	var rules []ruleOption
	for _, def := range auth.PredefinedRules {
		rules = append(rules, ruleOption{def: def})
	}
	return rules
}

// wizardStepCount returns the total number of wizard steps (excluding key select when fromWizard)
func (m authSetupModel) wizardStepCount() int {
	if m.fromWizard {
		return 4 // repo, rules, expiry, confirm
	}
	return 5 // key, repo, rules, expiry, confirm
}

func (m authSetupModel) wizardStepNum() int {
	step := int(m.step)
	if m.fromWizard {
		// stepRepoConstraint=1 becomes 1, stepSelectRules=2 becomes 2, etc.
		return step
	}
	return step + 1
}

func (m Model) updateAuthSetup(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "esc" {
			if m.authSetup.step == stepSelectKey || (m.authSetup.fromWizard && m.authSetup.step == stepRepoConstraint) {
				m.screen = screenWelcome
				return m, nil
			}
			m.authSetup.step--
			return m, nil
		}
	}

	switch m.authSetup.step {
	case stepSelectKey:
		return m.updateAuthSelectKey(msg)
	case stepRepoConstraint:
		return m.updateAuthRepo(msg)
	case stepSelectRules:
		return m.updateAuthRules(msg)
	case stepExpiry:
		return m.updateAuthExpiry(msg)
	case stepConfirm:
		return m.updateAuthConfirm(msg)
	}

	return m, nil
}

func (m Model) updateAuthSelectKey(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "up", "k":
			if m.authSetup.cursor > 0 {
				m.authSetup.cursor--
			}
		case "down", "j":
			if m.authSetup.cursor < len(m.authSetup.keys)-1 {
				m.authSetup.cursor++
			}
		case "enter":
			if len(m.authSetup.keys) > 0 {
				m.authSetup.selectedKeyID = m.authSetup.keys[m.authSetup.cursor].KeyID
				m.authSetup.step = stepRepoConstraint
				return m, m.authSetup.repoInput.Focus()
			}
		}
	}
	return m, nil
}

func (m Model) updateAuthRepo(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok && km.String() == "enter" {
		m.authSetup.repoInput.Blur()
		m.authSetup.step = stepSelectRules
		return m, nil
	}
	var cmd tea.Cmd
	m.authSetup.repoInput, cmd = m.authSetup.repoInput.Update(msg)
	return m, cmd
}

func (m Model) updateAuthRules(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "up", "k":
			if m.authSetup.ruleCursor > 0 {
				m.authSetup.ruleCursor--
			}
		case "down", "j":
			if m.authSetup.ruleCursor < len(m.authSetup.rules)-1 {
				m.authSetup.ruleCursor++
			}
		case " ":
			m.authSetup.rules[m.authSetup.ruleCursor].checked = !m.authSetup.rules[m.authSetup.ruleCursor].checked
		case "enter":
			m.authSetup.step = stepExpiry
		}
	}
	return m, nil
}

func (m Model) updateAuthExpiry(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "up", "k":
			if m.authSetup.expiryDays < 365 {
				m.authSetup.expiryDays++
			}
		case "down", "j":
			if m.authSetup.expiryDays > 1 {
				m.authSetup.expiryDays--
			}
		case "enter":
			m.authSetup.step = stepConfirm
		}
	}
	return m, nil
}

func (m Model) updateAuthConfirm(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "y", "enter":
			return m.handleCreateAuth()
		case "n", "esc":
			m.screen = screenWelcome
			return m, nil
		}
	}
	return m, nil
}

func (m Model) handleCreateAuth() (tea.Model, tea.Cmd) {
	scopes := []string{"git-commit"}

	var constraints map[string][]string
	repo := strings.TrimSpace(m.authSetup.repoInput.Value())
	if repo != "" {
		constraints = map[string][]string{"repo": {repo}}
	}

	var hardRules, softRules []string
	for _, r := range m.authSetup.rules {
		if !r.checked {
			continue
		}
		switch r.def.Kind {
		case "hard":
			hardRules = append(hardRules, r.def.ID)
		case "soft":
			softRules = append(softRules, r.def.ID)
		}
	}

	expires := time.Now().AddDate(0, 0, m.authSetup.expiryDays)

	_, err := storage.CreateAuthorization(
		m.authSetup.db, m.authSetup.selectedKeyID, m.authSetup.user.UserID,
		scopes, constraints, hardRules, softRules, &expires,
	)
	if err != nil {
		m.authSetup.status = fmt.Sprintf("Error: %v", err)
		m.authSetup.isError = true
		return m, nil
	}

	if m.authSetup.fromWizard {
		m.screen = screenWelcome
		m.welcome.status = fmt.Sprintf("Key %s is ready to sign (expires in %d days)", m.authSetup.selectedKeyID, m.authSetup.expiryDays)
	} else {
		// Return to key detail view
		m.screen = screenManageKeys
		m.manageKeys.view = viewKeyDetail
		m.manageKeys.status = fmt.Sprintf("Added authorization (expires in %d days)", m.authSetup.expiryDays)
		m.manageKeys.isError = false
		m.manageKeys.refreshAuths()
	}
	m.welcome.isError = false
	return m, nil
}

func (m Model) viewAuthSetup() string {
	var b strings.Builder

	// Header: adapt based on context
	if m.authSetup.fromWizard {
		b.WriteString(m.s.Success.Render(fmt.Sprintf("  New signing key: %s", m.authSetup.selectedKeyID)))
	} else {
		b.WriteString(m.s.Title.Render("  Update Key"))
		b.WriteString("  ")
		b.WriteString(m.s.Dim.Render(m.authSetup.selectedKeyID))
	}
	b.WriteString("\n\n")

	stepNum := m.authSetup.wizardStepNum()
	totalSteps := m.authSetup.wizardStepCount()

	switch m.authSetup.step {
	case stepSelectKey:
		b.WriteString(m.s.Title.Render(fmt.Sprintf("  Step %d/%d", stepNum, totalSteps)))
		b.WriteString("  ")
		b.WriteString(m.s.Info.Render("Select a signing key"))
		b.WriteString("\n\n")

		if len(m.authSetup.keys) == 0 {
			b.WriteString(m.s.Dim.Render("  No active signing keys. Create one first."))
		} else {
			for i, key := range m.authSetup.keys {
				cursor := "  "
				style := m.s.Normal
				if i == m.authSetup.cursor {
					cursor = "> "
					style = m.s.Selected
				}
				b.WriteString(style.Render(fmt.Sprintf("%s%s", cursor, key.KeyID)))
				b.WriteString("\n")
			}
		}

	case stepRepoConstraint:
		b.WriteString(m.s.Title.Render(fmt.Sprintf("  Step %d/%d", stepNum, totalSteps)))
		b.WriteString("  ")
		b.WriteString(m.s.Info.Render("Repository constraint"))
		b.WriteString("\n\n")

		b.WriteString(m.s.Dim.Render("  Limit which repos this key can sign for."))
		b.WriteString("\n")
		b.WriteString(m.s.Dim.Render("  Use wildcards like github.com/user/*"))
		b.WriteString("\n")
		b.WriteString(m.s.Dim.Render("  Leave empty to allow all repos."))
		b.WriteString("\n\n")

		b.WriteString("  " + m.authSetup.repoInput.View())

	case stepSelectRules:
		b.WriteString(m.s.Title.Render(fmt.Sprintf("  Step %d/%d", stepNum, totalSteps)))
		b.WriteString("  ")
		b.WriteString(m.s.Info.Render("Signing rules"))
		b.WriteString("\n\n")

		b.WriteString(m.s.Dim.Render("  Select rules to enforce. Hard rules block signing."))
		b.WriteString("\n\n")

		for i, r := range m.authSetup.rules {
			cursor := "  "
			style := m.s.Normal
			if i == m.authSetup.ruleCursor {
				cursor = "> "
				style = m.s.Selected
			}

			check := "[ ]"
			if r.checked {
				check = "[x]"
			}

			b.WriteString(style.Render(fmt.Sprintf("%s%s %s", cursor, check, r.def.Label)))
			b.WriteString("\n")

			if i == m.authSetup.ruleCursor {
				b.WriteString(m.s.Dim.Render(fmt.Sprintf("      %s", r.def.Description)))
				b.WriteString("\n")
			}
		}

	case stepExpiry:
		b.WriteString(m.s.Title.Render(fmt.Sprintf("  Step %d/%d", stepNum, totalSteps)))
		b.WriteString("  ")
		b.WriteString(m.s.Info.Render("Expiration"))
		b.WriteString("\n\n")

		b.WriteString(m.s.Dim.Render("  How long should this authorization last?"))
		b.WriteString("\n\n")

		b.WriteString(m.s.Info.Render(fmt.Sprintf("  %d days", m.authSetup.expiryDays)))
		b.WriteString("\n")

	case stepConfirm:
		b.WriteString(m.s.Title.Render(fmt.Sprintf("  Step %d/%d", stepNum, totalSteps)))
		b.WriteString("  ")
		if m.authSetup.fromWizard {
			b.WriteString(m.s.Info.Render("Review and activate key"))
		} else {
			b.WriteString(m.s.Info.Render("Review and update key"))
		}
		b.WriteString("\n\n")

		b.WriteString(m.s.InfoLabel.Render("  Key      "))
		b.WriteString(m.s.Info.Render(m.authSetup.selectedKeyID))
		b.WriteString("\n")
		b.WriteString(m.s.InfoLabel.Render("  Scope    "))
		b.WriteString(m.s.Info.Render("git-commit"))
		b.WriteString("\n")

		repo := strings.TrimSpace(m.authSetup.repoInput.Value())
		if repo != "" {
			b.WriteString(m.s.InfoLabel.Render("  Repo     "))
			b.WriteString(m.s.Info.Render(repo))
		} else {
			b.WriteString(m.s.InfoLabel.Render("  Repo     "))
			b.WriteString(m.s.Dim.Render("any"))
		}
		b.WriteString("\n")

		var selected []string
		for _, r := range m.authSetup.rules {
			if r.checked {
				selected = append(selected, r.def.Label)
			}
		}
		if len(selected) > 0 {
			b.WriteString(m.s.InfoLabel.Render("  Rules    "))
			b.WriteString(m.s.Info.Render(selected[0]))
			b.WriteString("\n")
			for _, s := range selected[1:] {
				b.WriteString(m.s.InfoLabel.Render("           "))
				b.WriteString(m.s.Info.Render(s))
				b.WriteString("\n")
			}
		} else {
			b.WriteString(m.s.InfoLabel.Render("  Rules    "))
			b.WriteString(m.s.Dim.Render("none"))
			b.WriteString("\n")
		}

		b.WriteString(m.s.InfoLabel.Render("  Expires  "))
		b.WriteString(m.s.Info.Render(fmt.Sprintf("%d days", m.authSetup.expiryDays)))
		b.WriteString("\n\n")

		if m.authSetup.fromWizard {
			b.WriteString(m.s.Selected.Render("  Activate key? (y/n)"))
		} else {
			b.WriteString(m.s.Selected.Render("  Update key? (y/n)"))
		}
	}

	if m.authSetup.status != "" {
		b.WriteString("\n\n")
		if m.authSetup.isError {
			b.WriteString(m.s.Error.Render("  " + m.authSetup.status))
		} else {
			b.WriteString(m.s.Success.Render("  " + m.authSetup.status))
		}
	}

	b.WriteString("\n\n")
	switch m.authSetup.step {
	case stepSelectRules:
		b.WriteString(m.buildHints([]hint{
			{"space", "toggle", hintAction},
			{"j/k", "navigate", hintNav},
			{"enter", "next", hintAction},
			{"esc", "back", hintNav},
		}))
	case stepExpiry:
		b.WriteString(m.buildHints([]hint{
			{"j/k", "adjust", hintNav},
			{"enter", "next", hintAction},
			{"esc", "back", hintNav},
		}))
	default:
		b.WriteString(m.buildHints([]hint{
			{"enter", "next", hintAction},
			{"esc", "back", hintNav},
		}))
	}

	return m.s.Border.Render(b.String())
}
