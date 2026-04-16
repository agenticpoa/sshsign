package tui

import (
	"database/sql"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/agenticpoa/sshsign/internal/audit"
	"github.com/agenticpoa/sshsign/internal/storage"
)

type screen int

const (
	screenWelcome screen = iota
	screenLinkKey
	screenManageKeys
	screenAuthSetup
	screenAuditLog
	screenPendingApprovals
)

type Model struct {
	db          *sql.DB
	kek         []byte
	auditLogger audit.Logger
	user        *storage.User
	userKey     *storage.UserKey
	isNewUser   bool
	screen      screen
	width       int
	height      int
	r           *lipgloss.Renderer
	s           Styles

	// Sub-models
	linkKey    linkKeyModel
	welcome    welcomeModel
	manageKeys manageKeysModel
	authSetup  authSetupModel
	auditLog   auditLogModel
	pending    pendingApprovalsModel
}

func NewModel(db *sql.DB, kek []byte, user *storage.User, userKey *storage.UserKey, isNewUser bool) Model {
	return NewModelWithRenderer(db, kek, nil, user, userKey, isNewUser, lipgloss.DefaultRenderer())
}

func NewModelWithRenderer(db *sql.DB, kek []byte, auditLogger audit.Logger, user *storage.User, userKey *storage.UserKey, isNewUser bool, r *lipgloss.Renderer) Model {
	return Model{
		db:          db,
		kek:         kek,
		auditLogger: auditLogger,
		user:        user,
		userKey:     userKey,
		isNewUser:   isNewUser,
		screen:      screenWelcome,
		r:           r,
		s:           NewStyles(r),
		welcome:     newWelcomeModel(user, userKey, isNewUser),
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}

	switch m.screen {
	case screenWelcome:
		return m.updateWelcome(msg)
	case screenLinkKey:
		return m.updateLinkKey(msg)
	case screenManageKeys:
		return m.updateManageKeys(msg)
	case screenAuthSetup:
		return m.updateAuthSetup(msg)
	case screenAuditLog:
		return m.updateAuditLog(msg)
	case screenPendingApprovals:
		return m.updatePendingApprovals(msg)
	}

	return m, nil
}

func (m Model) View() string {
	switch m.screen {
	case screenWelcome:
		return m.viewWelcome()
	case screenLinkKey:
		return m.viewLinkKey()
	case screenManageKeys:
		return m.viewManageKeys()
	case screenAuthSetup:
		return m.viewAuthSetup()
	case screenAuditLog:
		return m.viewAuditLog()
	case screenPendingApprovals:
		return m.viewPendingApprovals()
	default:
		return "Unknown screen"
	}
}

type navigateMsg struct {
	screen screen
}

type statusMsg struct {
	message string
	isError bool
}
