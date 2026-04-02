package tui

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/agenticpoa/sshsign/internal/auth"
	"github.com/agenticpoa/sshsign/internal/storage"
)

type authSetupStep int

const (
	stepSelectKey       authSetupStep = iota
	stepSelectTemplate
	stepCustomScope
	stepRepoConstraint
	stepSelectRules
	stepEditConstraints
	stepAddConstraint
	stepConfirmationTier
	stepExpiry
	stepConfirm
)

type authSetupModel struct {
	db       *sql.DB
	user     *storage.User
	renderer *lipgloss.Renderer
	keys     []storage.SigningKey
	cursor   int
	step     authSetupStep
	status   string
	isError  bool

	selectedKeyID string
	repoInput     textinput.Model
	rules         []ruleOption
	ruleCursor    int
	expiryDays    int
	fromWizard       bool
	replacingTokenID string // if editing, the old auth to revoke on confirm

	// Pending key material - held in memory until confirm
	pendingPubSSH     string
	pendingEncPriv    []byte
	pendingWrappedDEK []byte

	// Template state
	selectedTemplate *authTemplate
	templateCursor   int

	// Custom scope
	scopeInput textinput.Model

	// Metadata constraints
	constraints       []editableConstraint
	constraintCursor  int
	editingConstraint bool // inline editing mode

	// Confirmation tier
	confirmationTier string
	tierCursor       int

	// Custom constraint builder
	addSubStep       addConstraintStep
	newTypeCursor    int
	newFieldInput    textinput.Model
	newMinInput      textinput.Model
	newMaxInput      textinput.Model
	newAllowedInput  textinput.Model
	newRequiredValue bool
}

type addConstraintStep int

const (
	addStepList addConstraintStep = iota
	addStepType
	addStepField
	addStepValues
)

type editableConstraint struct {
	tmpl     constraintTemplate
	min      *float64
	max      *float64
	allowed  []string
	required *bool
	// Inline edit inputs
	minInput     textinput.Model
	maxInput     textinput.Model
	allowedInput textinput.Model
	// Enum selection state
	enumOptions    []enumOption // toggleable options
	enumCursor     int
	enumAddingNew  bool // typing a custom value
	enumNewInput   textinput.Model
}

type enumOption struct {
	value   string
	checked bool
}

type ruleOption struct {
	def     auth.RuleDefinition
	checked bool
}

func newEditableConstraint(ct constraintTemplate, r *lipgloss.Renderer) editableConstraint {
	ec := editableConstraint{
		tmpl:     ct,
		min:      ct.DefaultMin,
		max:      ct.DefaultMax,
		allowed:  ct.Allowed,
		required: ct.Required,
	}
	ec.minInput = newStaticCursorInput(r)
	ec.minInput.Width = 20
	if ct.DefaultMin != nil {
		ec.minInput.SetValue(formatNumber(*ct.DefaultMin))
	}
	ec.maxInput = newStaticCursorInput(r)
	ec.maxInput.Width = 20
	if ct.DefaultMax != nil {
		ec.maxInput.SetValue(formatNumber(*ct.DefaultMax))
	}
	ec.allowedInput = newStaticCursorInput(r)
	ec.allowedInput.Width = 40
	ec.allowedInput.Placeholder = "comma-separated values"
	if len(ct.Allowed) > 0 {
		ec.allowedInput.SetValue(strings.Join(ct.Allowed, ", "))
	}
	// Initialize enum options (all checked by default)
	for _, v := range ct.Allowed {
		ec.enumOptions = append(ec.enumOptions, enumOption{value: v, checked: true})
	}
	ec.enumNewInput = newStaticCursorInput(r)
	ec.enumNewInput.Placeholder = "new value"
	ec.enumNewInput.Width = 30
	return ec
}

func checkedEnumValues(opts []enumOption) []string {
	var vals []string
	for _, opt := range opts {
		if opt.checked {
			vals = append(vals, opt.value)
		}
	}
	return vals
}

func formatNumber(f float64) string {
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func newAuthSetupModel(db *sql.DB, user *storage.User, r *lipgloss.Renderer) authSetupModel {
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
		renderer:   r,
		keys:       active,
		step:       stepSelectKey,
		repoInput:  newRepoInput(r),
		rules:      newRuleOptions(),
		expiryDays: 30,
		scopeInput: newScopeInput(r),
	}
}

func newAuthSetupModelForKey(db *sql.DB, user *storage.User, keyID string, r *lipgloss.Renderer) authSetupModel {
	m := newAuthSetupModel(db, user, r)
	m.selectedKeyID = keyID
	m.step = stepSelectTemplate
	m.fromWizard = true
	return m
}

func newAuthSetupModelForPendingKey(db *sql.DB, user *storage.User, keyID, pubSSH string, encPriv, wrappedDEK []byte, r *lipgloss.Renderer) authSetupModel {
	m := newAuthSetupModel(db, user, r)
	m.selectedKeyID = keyID
	m.step = stepSelectTemplate
	m.fromWizard = true
	m.pendingPubSSH = pubSSH
	m.pendingEncPriv = encPriv
	m.pendingWrappedDEK = wrappedDEK
	return m
}

func newAuthSetupModelForExistingKey(db *sql.DB, user *storage.User, keyID string, r *lipgloss.Renderer) authSetupModel {
	m := newAuthSetupModel(db, user, r)
	m.selectedKeyID = keyID
	m.step = stepSelectTemplate
	m.fromWizard = false
	return m
}

// newAuthSetupFromExisting creates an auth setup pre-filled from an existing authorization.
// On confirm, the old authorization is auto-revoked (edit = revoke old + create new).
func newAuthSetupFromExisting(db *sql.DB, user *storage.User, keyID string, existing *storage.Authorization, r *lipgloss.Renderer) authSetupModel {
	m := newAuthSetupModel(db, user, r)
	m.selectedKeyID = keyID
	m.fromWizard = false
	m.replacingTokenID = existing.TokenID

	// Find matching template by scope
	scope := ""
	if len(existing.Scopes) > 0 {
		scope = existing.Scopes[0]
	}
	for i := range authTemplates {
		if authTemplates[i].Scope == scope {
			m.selectTemplate(&authTemplates[i])
			break
		}
	}
	// If no template matched, use custom
	if m.selectedTemplate == nil {
		custom := authTemplates[len(authTemplates)-1] // "custom" is last
		m.selectTemplate(&custom)
		m.scopeInput.SetValue(scope)
	}

	// Pre-fill confirmation tier
	m.confirmationTier = existing.ConfirmationTier
	if existing.ConfirmationTier == "cosign" {
		m.tierCursor = 1
	} else {
		m.tierCursor = 0
	}

	// Pre-fill repo constraint
	if repos, ok := existing.Constraints["repo"]; ok && len(repos) > 0 {
		m.repoInput.SetValue(repos[0])
	}

	// Pre-fill rules
	ruleSet := map[string]bool{}
	for _, r := range existing.HardRules {
		ruleSet[r] = true
	}
	for _, r := range existing.SoftRules {
		ruleSet[r] = true
	}
	for i := range m.rules {
		m.rules[i].checked = ruleSet[m.rules[i].def.ID]
	}

	// Pre-fill metadata constraints (override template defaults)
	if len(existing.MetadataConstraints) > 0 {
		m.constraints = nil
		for _, mc := range existing.MetadataConstraints {
			ct := constraintTemplate{
				Field:      mc.Field,
				Label:      mc.Field,
				Type:       mc.Type,
				DefaultMin: mc.Min,
				DefaultMax: mc.Max,
				Allowed:    mc.Allowed,
				Required:   mc.Required,
			}
			// Try to find a friendly label from the template
			if m.selectedTemplate != nil {
				for _, tc := range m.selectedTemplate.Constraints {
					if tc.Field == mc.Field {
						ct.Label = tc.Label
						break
					}
				}
			}
			m.constraints = append(m.constraints, newEditableConstraint(ct, m.renderer))
		}
	}

	// Pre-fill expiry
	if existing.ExpiresAt != nil {
		days := int(existing.ExpiresAt.Sub(existing.CreatedAt).Hours() / 24)
		if days > 0 && days <= 365 {
			m.expiryDays = days
		}
	}

	// Skip template selection, go straight to the first content step
	steps := m.applicableSteps()
	// Find the step after stepSelectTemplate
	for i, s := range steps {
		if s == stepSelectTemplate && i+1 < len(steps) {
			m.step = steps[i+1]
			break
		}
	}

	return m
}

// newStaticCursorInput creates a textinput with a visible cursor over SSH.
// Uses the session renderer so ANSI escapes are emitted correctly
// (the default renderer is bound to the server's stdout, which has no TTY
// when running as a daemon, causing all styles to be stripped).
func newStaticCursorInput(r *lipgloss.Renderer) textinput.Model {
	input := textinput.New()
	input.Cursor.SetMode(cursor.CursorStatic)
	input.Cursor.Style = r.NewStyle().Reverse(true)
	input.Cursor.TextStyle = r.NewStyle()
	return input
}

// isNumericRune returns true if the rune is valid in a numeric value.
func isNumericRune(r rune) bool {
	return (r >= '0' && r <= '9') || r == '.' || r == '-'
}

// filterNumericMsg returns nil if the key message contains non-numeric runes,
// preventing them from reaching the textinput's Update.
func filterNumericMsg(msg tea.Msg) tea.Msg {
	if keyMsg, ok := msg.(tea.KeyMsg); ok && keyMsg.Type == tea.KeyRunes {
		for _, r := range keyMsg.Runes {
			if !isNumericRune(r) {
				return nil
			}
		}
	}
	return msg
}

func newRepoInput(r *lipgloss.Renderer) textinput.Model {
	input := newStaticCursorInput(r)
	input.Placeholder = "github.com/user/* (leave empty to skip)"
	input.Width = 50
	return input
}

func newScopeInput(r *lipgloss.Renderer) textinput.Model {
	input := newStaticCursorInput(r)
	input.Placeholder = "e.g. api-request, purchase-agreement"
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

// applicableSteps returns the ordered list of steps for the current template.
func (m authSetupModel) applicableSteps() []authSetupStep {
	var steps []authSetupStep

	if !m.fromWizard && m.selectedKeyID == "" {
		steps = append(steps, stepSelectKey)
	}

	steps = append(steps, stepSelectTemplate)

	if m.selectedTemplate != nil {
		if m.selectedTemplate.ID == "custom" {
			steps = append(steps, stepCustomScope)
		}
		if m.selectedTemplate.ShowRepoConstraint {
			steps = append(steps, stepRepoConstraint)
		}
		if m.selectedTemplate.ShowRules {
			steps = append(steps, stepSelectRules)
		}
		if len(m.selectedTemplate.Constraints) > 0 {
			steps = append(steps, stepEditConstraints)
		}
		if m.selectedTemplate.ID == "custom" {
			steps = append(steps, stepAddConstraint)
		}
		if m.selectedTemplate.ShowTierPicker {
			steps = append(steps, stepConfirmationTier)
		}
	}

	steps = append(steps, stepExpiry, stepConfirm)
	return steps
}

func (m *authSetupModel) nextStep() {
	steps := m.applicableSteps()
	for i, s := range steps {
		if s == m.step && i+1 < len(steps) {
			m.step = steps[i+1]
			return
		}
	}
}

func (m *authSetupModel) prevStep() {
	steps := m.applicableSteps()
	for i, s := range steps {
		if s == m.step && i > 0 {
			m.step = steps[i-1]
			return
		}
	}
}

func (m authSetupModel) isFirstStep() bool {
	steps := m.applicableSteps()
	return len(steps) > 0 && m.step == steps[0]
}

func (m authSetupModel) wizardStepCount() int {
	return len(m.applicableSteps())
}

func (m authSetupModel) wizardStepNum() int {
	steps := m.applicableSteps()
	for i, s := range steps {
		if s == m.step {
			return i + 1
		}
	}
	return 1
}

// selectTemplate initializes state from a template selection.
func (m *authSetupModel) selectTemplate(tmpl *authTemplate) {
	m.selectedTemplate = tmpl
	m.confirmationTier = tmpl.ConfirmationTier
	if tmpl.ConfirmationTier == "cosign" {
		m.tierCursor = 1
	} else {
		m.tierCursor = 0
	}

	m.constraints = nil
	for _, ct := range tmpl.Constraints {
		m.constraints = append(m.constraints, newEditableConstraint(ct, m.renderer))
	}
	m.constraintCursor = 0
	m.editingConstraint = false
}

// --- Update handlers ---

func (m Model) updateAuthSetup(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "esc" {
			// If editing a constraint inline, cancel the edit
			if m.authSetup.step == stepEditConstraints && m.authSetup.editingConstraint {
				m.authSetup.editingConstraint = false
				return m, nil
			}
			// If in add constraint sub-flow, go back within it
			if m.authSetup.step == stepAddConstraint && m.authSetup.addSubStep > addStepList {
				m.authSetup.addSubStep--
				return m, nil
			}
			if m.authSetup.isFirstStep() {
				m.screen = screenWelcome
				return m, nil
			}
			m.authSetup.prevStep()
			return m, m.focusCurrentStep()
		}
	}

	switch m.authSetup.step {
	case stepSelectKey:
		return m.updateAuthSelectKey(msg)
	case stepSelectTemplate:
		return m.updateAuthSelectTemplate(msg)
	case stepCustomScope:
		return m.updateAuthCustomScope(msg)
	case stepRepoConstraint:
		return m.updateAuthRepo(msg)
	case stepSelectRules:
		return m.updateAuthRules(msg)
	case stepEditConstraints:
		return m.updateAuthEditConstraints(msg)
	case stepAddConstraint:
		return m.updateAuthAddConstraint(msg)
	case stepConfirmationTier:
		return m.updateAuthTier(msg)
	case stepExpiry:
		return m.updateAuthExpiry(msg)
	case stepConfirm:
		return m.updateAuthConfirm(msg)
	}

	return m, nil
}

func (m Model) focusCurrentStep() tea.Cmd {
	switch m.authSetup.step {
	case stepRepoConstraint:
		return m.authSetup.repoInput.Focus()
	case stepCustomScope:
		return m.authSetup.scopeInput.Focus()
	}
	return nil
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
				m.authSetup.nextStep()
				return m, nil
			}
		}
	}
	return m, nil
}

func (m Model) updateAuthSelectTemplate(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "up", "k":
			if m.authSetup.templateCursor > 0 {
				m.authSetup.templateCursor--
			}
		case "down", "j":
			if m.authSetup.templateCursor < len(authTemplates)-1 {
				m.authSetup.templateCursor++
			}
		case "enter":
			tmpl := authTemplates[m.authSetup.templateCursor]
			m.authSetup.selectTemplate(&tmpl)
			m.authSetup.nextStep()
			return m, m.focusCurrentStep()
		}
	}
	return m, nil
}

func (m Model) updateAuthCustomScope(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok && km.String() == "enter" {
		scope := strings.TrimSpace(m.authSetup.scopeInput.Value())
		if scope == "" {
			m.authSetup.status = "Scope is required"
			m.authSetup.isError = true
			return m, nil
		}
		m.authSetup.status = ""
		m.authSetup.scopeInput.Blur()
		m.authSetup.nextStep()
		return m, nil
	}
	var cmd tea.Cmd
	m.authSetup.scopeInput, cmd = m.authSetup.scopeInput.Update(msg)
	return m, cmd
}

func (m Model) updateAuthRepo(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok && km.String() == "enter" {
		m.authSetup.repoInput.Blur()
		m.authSetup.nextStep()
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
			m.authSetup.nextStep()
		}
	}
	return m, nil
}

func (m Model) updateAuthEditConstraints(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.authSetup.editingConstraint {
		return m.updateAuthEditConstraintInline(msg)
	}

	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "up", "k":
			if m.authSetup.constraintCursor > 0 {
				m.authSetup.constraintCursor--
			}
		case "down", "j":
			if m.authSetup.constraintCursor < len(m.authSetup.constraints)-1 {
				m.authSetup.constraintCursor++
			}
		case "enter":
			if len(m.authSetup.constraints) == 0 {
				m.authSetup.nextStep()
				return m, nil
			}
			ec := &m.authSetup.constraints[m.authSetup.constraintCursor]
			if ec.tmpl.Type == "required_bool" {
				// Toggle directly
				if ec.required == nil {
					ec.required = boolptr(true)
				} else {
					*ec.required = !*ec.required
				}
				return m, nil
			}
			// Enter edit mode
			m.authSetup.editingConstraint = true
			if ec.tmpl.Type == "enum" {
				ec.enumCursor = 0
				ec.enumAddingNew = false
				return m, nil
			}
			cmd := ec.minInput.Focus()
			return m, cmd
		case "n":
			// "next" shortcut to advance without editing
			m.authSetup.nextStep()
			return m, nil
		case " ":
			// Toggle required_bool with space
			if len(m.authSetup.constraints) > 0 {
				ec := &m.authSetup.constraints[m.authSetup.constraintCursor]
				if ec.tmpl.Type == "required_bool" {
					if ec.required == nil {
						ec.required = boolptr(true)
					} else {
						*ec.required = !*ec.required
					}
				}
			}
		}
	}
	return m, nil
}

func (m Model) updateAuthEditConstraintInline(msg tea.Msg) (tea.Model, tea.Cmd) {
	ec := &m.authSetup.constraints[m.authSetup.constraintCursor]

	if ec.tmpl.Type == "enum" {
		return m.updateEnumEdit(msg)
	}

	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "enter":
			if minStr := ec.minInput.Value(); minStr != "" {
				if v, err := strconv.ParseFloat(minStr, 64); err == nil {
					ec.min = &v
				}
			}
			if maxStr := ec.maxInput.Value(); maxStr != "" {
				if v, err := strconv.ParseFloat(maxStr, 64); err == nil {
					ec.max = &v
				}
			}
			ec.minInput.Blur()
			ec.maxInput.Blur()
			m.authSetup.editingConstraint = false
			return m, nil
		case "tab":
			if ec.tmpl.Type == "range" {
				var cmd tea.Cmd
				if ec.minInput.Focused() {
					ec.minInput.Blur()
					cmd = ec.maxInput.Focus()
				} else {
					ec.maxInput.Blur()
					cmd = ec.minInput.Focus()
				}
				return m, cmd
			}
		}
	}

	filtered := filterNumericMsg(msg)
	if filtered == nil {
		return m, nil
	}
	var cmd tea.Cmd
	switch {
	case ec.minInput.Focused():
		ec.minInput, cmd = ec.minInput.Update(filtered)
	case ec.maxInput.Focused():
		ec.maxInput, cmd = ec.maxInput.Update(filtered)
	}
	return m, cmd
}

func (m Model) updateEnumEdit(msg tea.Msg) (tea.Model, tea.Cmd) {
	ec := &m.authSetup.constraints[m.authSetup.constraintCursor]

	// If typing a new custom value
	if ec.enumAddingNew {
		if km, ok := msg.(tea.KeyMsg); ok {
			switch km.String() {
			case "enter":
				val := strings.TrimSpace(ec.enumNewInput.Value())
				if val != "" {
					ec.enumOptions = append(ec.enumOptions, enumOption{value: val, checked: true})
					ec.allowed = checkedEnumValues(ec.enumOptions)
					ec.enumNewInput.SetValue("")
				}
				ec.enumAddingNew = false
				ec.enumNewInput.Blur()
				return m, nil
			case "esc":
				ec.enumAddingNew = false
				ec.enumNewInput.Blur()
				return m, nil
			}
		}
		var cmd tea.Cmd
		ec.enumNewInput, cmd = ec.enumNewInput.Update(msg)
		return m, cmd
	}

	if km, ok := msg.(tea.KeyMsg); ok {
		// +1 for the "Add custom value..." row
		maxIdx := len(ec.enumOptions)
		switch km.String() {
		case "up", "k":
			if ec.enumCursor > 0 {
				ec.enumCursor--
			}
		case "down", "j":
			if ec.enumCursor < maxIdx {
				ec.enumCursor++
			}
		case " ":
			if ec.enumCursor < len(ec.enumOptions) {
				ec.enumOptions[ec.enumCursor].checked = !ec.enumOptions[ec.enumCursor].checked
				ec.allowed = checkedEnumValues(ec.enumOptions)
			}
		case "enter":
			if ec.enumCursor == len(ec.enumOptions) {
				// "Add custom value" selected
				ec.enumAddingNew = true
				ec.enumNewInput.SetValue("")
				cmd := ec.enumNewInput.Focus()
				return m, cmd
			}
			// Save: collect checked values and exit edit mode
			ec.allowed = checkedEnumValues(ec.enumOptions)
			m.authSetup.editingConstraint = false
			return m, nil
		case "x":
			// Delete unchecked option under cursor
			if ec.enumCursor < len(ec.enumOptions) && !ec.enumOptions[ec.enumCursor].checked {
				ec.enumOptions = append(ec.enumOptions[:ec.enumCursor], ec.enumOptions[ec.enumCursor+1:]...)
				if ec.enumCursor >= len(ec.enumOptions) && ec.enumCursor > 0 {
					ec.enumCursor--
				}
			}
		}
	}
	return m, nil
}

func (m Model) updateAuthAddConstraint(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.authSetup.addSubStep {
	case addStepList:
		return m.updateAddConstraintList(msg)
	case addStepType:
		return m.updateAddConstraintType(msg)
	case addStepField:
		return m.updateAddConstraintField(msg)
	case addStepValues:
		return m.updateAddConstraintValues(msg)
	}
	return m, nil
}

var constraintTypeLabels = []string{"range", "minimum", "maximum", "enum", "required_bool"}

func (m Model) updateAddConstraintList(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "a":
			// Start adding a new constraint
			m.authSetup.addSubStep = addStepType
			m.authSetup.newTypeCursor = 0
			return m, nil
		case "enter", "n", "d":
			// Done adding constraints
			m.authSetup.nextStep()
			return m, nil
		}
	}
	return m, nil
}

func (m Model) updateAddConstraintType(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "up", "k":
			if m.authSetup.newTypeCursor > 0 {
				m.authSetup.newTypeCursor--
			}
		case "down", "j":
			if m.authSetup.newTypeCursor < len(constraintTypeLabels)-1 {
				m.authSetup.newTypeCursor++
			}
		case "enter":
			m.authSetup.addSubStep = addStepField
			m.authSetup.newFieldInput = newStaticCursorInput(m.r)
			m.authSetup.newFieldInput.Placeholder = "field name (e.g. valuation_cap)"
			m.authSetup.newFieldInput.Width = 40
			cmd := m.authSetup.newFieldInput.Focus()
			return m, cmd
		}
	}
	return m, nil
}

func (m Model) updateAddConstraintField(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok && km.String() == "enter" {
		field := strings.TrimSpace(m.authSetup.newFieldInput.Value())
		if field == "" {
			return m, nil
		}
		m.authSetup.newFieldInput.Blur()

		selectedType := constraintTypeLabels[m.authSetup.newTypeCursor]

		// required_bool doesn't need value input
		if selectedType == "required_bool" {
			ct := constraintTemplate{
				Field:    field,
				Label:    field,
				Type:     "required_bool",
				Required: boolptr(true),
			}
			m.authSetup.constraints = append(m.authSetup.constraints, newEditableConstraint(ct, m.r))
			m.authSetup.addSubStep = addStepList
			return m, nil
		}

		// Set up value inputs
		m.authSetup.addSubStep = addStepValues
		m.authSetup.newMinInput = newStaticCursorInput(m.r)
		m.authSetup.newMinInput.Width = 20
		m.authSetup.newMaxInput = newStaticCursorInput(m.r)
		m.authSetup.newMaxInput.Width = 20
		m.authSetup.newAllowedInput = newStaticCursorInput(m.r)
		m.authSetup.newAllowedInput.Width = 40
		m.authSetup.newAllowedInput.Placeholder = "comma-separated values"

		var cmd tea.Cmd
		switch selectedType {
		case "range":
			m.authSetup.newMinInput.Placeholder = "minimum"
			m.authSetup.newMaxInput.Placeholder = "maximum"
			cmd = m.authSetup.newMinInput.Focus()
		case "minimum":
			m.authSetup.newMinInput.Placeholder = "minimum value"
			cmd = m.authSetup.newMinInput.Focus()
		case "maximum":
			m.authSetup.newMaxInput.Placeholder = "maximum value"
			cmd = m.authSetup.newMaxInput.Focus()
		case "enum":
			cmd = m.authSetup.newAllowedInput.Focus()
		}

		return m, cmd
	}
	var cmd tea.Cmd
	m.authSetup.newFieldInput, cmd = m.authSetup.newFieldInput.Update(msg)
	return m, cmd
}

func (m Model) updateAddConstraintValues(msg tea.Msg) (tea.Model, tea.Cmd) {
	selectedType := constraintTypeLabels[m.authSetup.newTypeCursor]
	field := strings.TrimSpace(m.authSetup.newFieldInput.Value())

	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "enter":
			ct := constraintTemplate{Field: field, Label: field, Type: selectedType}

			switch selectedType {
			case "range":
				if v, err := strconv.ParseFloat(m.authSetup.newMinInput.Value(), 64); err == nil {
					ct.DefaultMin = &v
				}
				if v, err := strconv.ParseFloat(m.authSetup.newMaxInput.Value(), 64); err == nil {
					ct.DefaultMax = &v
				}
			case "minimum":
				if v, err := strconv.ParseFloat(m.authSetup.newMinInput.Value(), 64); err == nil {
					ct.DefaultMin = &v
				}
			case "maximum":
				if v, err := strconv.ParseFloat(m.authSetup.newMaxInput.Value(), 64); err == nil {
					ct.DefaultMax = &v
				}
			case "enum":
				parts := strings.Split(m.authSetup.newAllowedInput.Value(), ",")
				for _, p := range parts {
					if t := strings.TrimSpace(p); t != "" {
						ct.Allowed = append(ct.Allowed, t)
					}
				}
			}

			m.authSetup.constraints = append(m.authSetup.constraints, newEditableConstraint(ct, m.r))
			m.authSetup.addSubStep = addStepList
			return m, nil
		case "tab":
			if selectedType == "range" {
				var cmd tea.Cmd
				if m.authSetup.newMinInput.Focused() {
					m.authSetup.newMinInput.Blur()
					cmd = m.authSetup.newMaxInput.Focus()
				} else {
					m.authSetup.newMaxInput.Blur()
					cmd = m.authSetup.newMinInput.Focus()
				}
				return m, cmd
			}
		}
	}

	var cmd tea.Cmd
	switch selectedType {
	case "range":
		filtered := filterNumericMsg(msg)
		if filtered == nil {
			return m, nil
		}
		if m.authSetup.newMinInput.Focused() {
			m.authSetup.newMinInput, cmd = m.authSetup.newMinInput.Update(filtered)
		} else {
			m.authSetup.newMaxInput, cmd = m.authSetup.newMaxInput.Update(filtered)
		}
	case "minimum":
		filtered := filterNumericMsg(msg)
		if filtered == nil {
			return m, nil
		}
		m.authSetup.newMinInput, cmd = m.authSetup.newMinInput.Update(filtered)
	case "maximum":
		filtered := filterNumericMsg(msg)
		if filtered == nil {
			return m, nil
		}
		m.authSetup.newMaxInput, cmd = m.authSetup.newMaxInput.Update(filtered)
	case "enum":
		m.authSetup.newAllowedInput, cmd = m.authSetup.newAllowedInput.Update(msg)
	}
	return m, cmd
}

func (m Model) updateAuthTier(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "up", "k":
			if m.authSetup.tierCursor > 0 {
				m.authSetup.tierCursor--
			}
		case "down", "j":
			if m.authSetup.tierCursor < 1 {
				m.authSetup.tierCursor++
			}
		case "enter":
			if m.authSetup.tierCursor == 0 {
				m.authSetup.confirmationTier = "autonomous"
			} else {
				m.authSetup.confirmationTier = "cosign"
			}
			m.authSetup.nextStep()
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
			m.authSetup.nextStep()
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
	tmpl := m.authSetup.selectedTemplate

	// Determine scope
	scope := tmpl.Scope
	if tmpl.ID == "custom" {
		scope = strings.TrimSpace(m.authSetup.scopeInput.Value())
	}
	scopes := []string{scope}

	// Repo constraints (git-commit only)
	var constraints map[string][]string
	if tmpl.ShowRepoConstraint {
		repo := strings.TrimSpace(m.authSetup.repoInput.Value())
		if repo != "" {
			constraints = map[string][]string{"repo": {repo}}
		}
	}

	// Convert editable constraints to storage model
	var metaConstraints []storage.MetadataConstraint
	for _, ec := range m.authSetup.constraints {
		metaConstraints = append(metaConstraints, storage.MetadataConstraint{
			Type:     ec.tmpl.Type,
			Field:    ec.tmpl.Field,
			Min:      ec.min,
			Max:      ec.max,
			Allowed:  ec.allowed,
			Required: ec.required,
		})
	}

	// Hard/soft rules (git-commit only)
	var hardRules, softRules []string
	if tmpl.ShowRules {
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
	}

	// Persist pending key if this is a new key from the wizard
	if m.authSetup.pendingPubSSH != "" {
		_, err := storage.CreateSigningKeyWithID(
			m.authSetup.db, m.authSetup.selectedKeyID, m.authSetup.user.UserID,
			m.authSetup.pendingPubSSH, m.authSetup.pendingEncPriv, m.authSetup.pendingWrappedDEK,
		)
		if err != nil {
			m.authSetup.status = fmt.Sprintf("Error storing key: %v", err)
			m.authSetup.isError = true
			return m, nil
		}
		m.authSetup.pendingPubSSH = ""
		m.authSetup.pendingEncPriv = nil
		m.authSetup.pendingWrappedDEK = nil
	}

	expires := time.Now().AddDate(0, 0, m.authSetup.expiryDays)

	_, err := storage.CreateAuthorizationFull(
		m.authSetup.db, m.authSetup.selectedKeyID, m.authSetup.user.UserID,
		scopes, constraints, metaConstraints, m.authSetup.confirmationTier, false,
		hardRules, softRules, &expires,
	)
	if err != nil {
		m.authSetup.status = fmt.Sprintf("Error: %v", err)
		m.authSetup.isError = true
		return m, nil
	}

	// If editing an existing auth, revoke the old one
	if m.authSetup.replacingTokenID != "" {
		storage.RevokeAuthorization(m.authSetup.db, m.authSetup.replacingTokenID)
	}

	if m.authSetup.fromWizard {
		m.screen = screenWelcome
		m.welcome.status = fmt.Sprintf("Key %s is ready to sign (expires in %d days)", m.authSetup.selectedKeyID, m.authSetup.expiryDays)
	} else {
		m.screen = screenManageKeys
		m.manageKeys.view = viewKeyDetail
		if m.authSetup.replacingTokenID != "" {
			m.manageKeys.status = fmt.Sprintf("Updated authorization (expires in %d days)", m.authSetup.expiryDays)
		} else {
			m.manageKeys.status = fmt.Sprintf("Added authorization (expires in %d days)", m.authSetup.expiryDays)
		}
		m.manageKeys.isError = false
		m.manageKeys.refreshAuths()
	}
	m.welcome.isError = false
	return m, nil
}

// --- View handlers ---

func (m Model) viewAuthSetup() string {
	var b strings.Builder

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
		m.viewStepSelectKey(&b, stepNum, totalSteps)
	case stepSelectTemplate:
		m.viewStepSelectTemplate(&b, stepNum, totalSteps)
	case stepCustomScope:
		m.viewStepCustomScope(&b, stepNum, totalSteps)
	case stepRepoConstraint:
		m.viewStepRepoConstraint(&b, stepNum, totalSteps)
	case stepSelectRules:
		m.viewStepSelectRules(&b, stepNum, totalSteps)
	case stepEditConstraints:
		m.viewStepEditConstraints(&b, stepNum, totalSteps)
	case stepAddConstraint:
		m.viewStepAddConstraint(&b, stepNum, totalSteps)
	case stepConfirmationTier:
		m.viewStepTier(&b, stepNum, totalSteps)
	case stepExpiry:
		m.viewStepExpiry(&b, stepNum, totalSteps)
	case stepConfirm:
		m.viewStepConfirm(&b, stepNum, totalSteps)
	}

	if m.authSetup.status != "" {
		b.WriteString("\n\n")
		if m.authSetup.isError {
			b.WriteString(m.s.Error.Render("  " + m.authSetup.status))
		} else {
			b.WriteString(m.s.Success.Render("  " + m.authSetup.status))
		}
	}

	return m.s.Border.Render(b.String())
}

func (m Model) viewStepSelectKey(b *strings.Builder, step, total int) {
	b.WriteString(m.s.Title.Render(fmt.Sprintf("  Step %d/%d", step, total)))
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

	b.WriteString("\n\n")
	b.WriteString(m.buildHints([]hint{
		{"enter", "next", hintAction},
		{"esc", "back", hintNav},
	}))
}

func (m Model) viewStepSelectTemplate(b *strings.Builder, step, total int) {
	b.WriteString(m.s.Title.Render(fmt.Sprintf("  Step %d/%d", step, total)))
	b.WriteString("  ")
	b.WriteString(m.s.Info.Render("What will this key sign?"))
	b.WriteString("\n\n")

	for i, tmpl := range authTemplates {
		cursor := "  "
		style := m.s.Normal
		if i == m.authSetup.templateCursor {
			cursor = "> "
			style = m.s.Selected
		}
		b.WriteString(style.Render(fmt.Sprintf("%s%s", cursor, tmpl.Label)))
		b.WriteString("\n")

		if i == m.authSetup.templateCursor {
			b.WriteString(m.s.Dim.Render(fmt.Sprintf("      %s", tmpl.Description)))
			b.WriteString("\n")
		}
	}

	b.WriteString("\n\n")
	b.WriteString(m.buildHints([]hint{
		{"j/k", "navigate", hintNav},
		{"enter", "select", hintAction},
		{"esc", "back", hintNav},
	}))
}

func (m Model) viewStepCustomScope(b *strings.Builder, step, total int) {
	b.WriteString(m.s.Title.Render(fmt.Sprintf("  Step %d/%d", step, total)))
	b.WriteString("  ")
	b.WriteString(m.s.Info.Render("Scope"))
	b.WriteString("\n\n")

	b.WriteString(m.s.Dim.Render("  Enter the scope identifier for this authorization."))
	b.WriteString("\n\n")
	b.WriteString("  " + m.authSetup.scopeInput.View())

	b.WriteString("\n\n")
	b.WriteString(m.buildHints([]hint{
		{"enter", "next", hintAction},
		{"esc", "back", hintNav},
	}))
}

func (m Model) viewStepRepoConstraint(b *strings.Builder, step, total int) {
	b.WriteString(m.s.Title.Render(fmt.Sprintf("  Step %d/%d", step, total)))
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

	b.WriteString("\n\n")
	b.WriteString(m.buildHints([]hint{
		{"enter", "next", hintAction},
		{"esc", "back", hintNav},
	}))
}

func (m Model) viewStepSelectRules(b *strings.Builder, step, total int) {
	b.WriteString(m.s.Title.Render(fmt.Sprintf("  Step %d/%d", step, total)))
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

	b.WriteString("\n\n")
	b.WriteString(m.buildHints([]hint{
		{"space", "toggle", hintAction},
		{"j/k", "navigate", hintNav},
		{"enter", "next", hintAction},
		{"esc", "back", hintNav},
	}))
}

func (m Model) viewStepEditConstraints(b *strings.Builder, step, total int) {
	b.WriteString(m.s.Title.Render(fmt.Sprintf("  Step %d/%d", step, total)))
	b.WriteString("  ")
	b.WriteString(m.s.Info.Render("Review constraints"))
	b.WriteString("\n\n")

	b.WriteString(m.s.Dim.Render("  Adjust the pre-filled constraint boundaries."))
	b.WriteString("\n")
	b.WriteString(m.s.Dim.Render("  These define what the agent is allowed to sign, not what it will sign."))
	b.WriteString("\n\n")

	for i, ec := range m.authSetup.constraints {
		cursor := "  "
		style := m.s.Normal
		if i == m.authSetup.constraintCursor {
			cursor = "> "
			style = m.s.Selected
		}

		label := ec.tmpl.Label
		valueStr := formatConstraintValue(ec)

		b.WriteString(style.Render(fmt.Sprintf("%s%-20s %s", cursor, label, valueStr)))
		b.WriteString("\n")

		// Show inline edit inputs when editing this constraint
		if i == m.authSetup.constraintCursor && m.authSetup.editingConstraint {
			switch ec.tmpl.Type {
			case "range":
				b.WriteString(m.s.Dim.Render("      Min: "))
				b.WriteString(ec.minInput.View())
				b.WriteString("\n")
				b.WriteString(m.s.Dim.Render("      Max: "))
				b.WriteString(ec.maxInput.View())
				b.WriteString("\n")
			case "minimum":
				b.WriteString(m.s.Dim.Render("      Min: "))
				b.WriteString(ec.minInput.View())
				b.WriteString("\n")
			case "maximum":
				b.WriteString(m.s.Dim.Render("      Max: "))
				b.WriteString(ec.maxInput.View())
				b.WriteString("\n")
			case "enum":
				for ei, opt := range ec.enumOptions {
					check := "[ ]"
					if opt.checked {
						check = "[x]"
					}
					style := m.s.Dim
					cursor := "      "
					if ei == ec.enumCursor {
						style = m.s.Selected
						cursor = "    > "
					}
					b.WriteString(style.Render(fmt.Sprintf("%s%s %s", cursor, check, opt.value)))
					b.WriteString("\n")
				}
				// "Add custom value" row
				addStyle := m.s.Dim
				addCursor := "      "
				if ec.enumCursor == len(ec.enumOptions) {
					addStyle = m.s.Selected
					addCursor = "    > "
				}
				if ec.enumAddingNew {
					b.WriteString(addStyle.Render(addCursor + "+ "))
					b.WriteString(ec.enumNewInput.View())
				} else {
					b.WriteString(addStyle.Render(addCursor + "+ Add custom value..."))
				}
				b.WriteString("\n")
			}
		}
	}

	b.WriteString("\n\n")
	if m.authSetup.editingConstraint {
		ec := m.authSetup.constraints[m.authSetup.constraintCursor]
		if ec.tmpl.Type == "enum" && ec.enumAddingNew {
			b.WriteString(m.buildHints([]hint{
				{"enter", "add", hintAction},
				{"esc", "cancel", hintNav},
			}))
		} else if ec.tmpl.Type == "enum" {
			b.WriteString(m.buildHints([]hint{
				{"space", "toggle", hintAction},
				{"j/k", "navigate", hintNav},
				{"enter", "save / add custom", hintAction},
				{"x", "remove", hintDanger},
				{"esc", "cancel", hintNav},
			}))
		} else {
			b.WriteString(m.buildHints([]hint{
				{"tab", "switch field", hintNav},
				{"enter", "save", hintAction},
				{"esc", "cancel", hintNav},
			}))
		}
	} else {
		hints := []hint{
			{"j/k", "navigate", hintNav},
			{"enter", "edit", hintAction},
		}
		for _, ec := range m.authSetup.constraints {
			if ec.tmpl.Type == "required_bool" {
				hints = append(hints, hint{"space", "toggle", hintAction})
				break
			}
		}
		hints = append(hints, hint{"n", "next", hintAction}, hint{"esc", "back", hintNav})
		b.WriteString(m.buildHints(hints))
	}
}

func formatConstraintValue(ec editableConstraint) string {
	switch ec.tmpl.Type {
	case "range":
		minS, maxS := "?", "?"
		if ec.min != nil {
			minS = formatNumber(*ec.min)
		}
		if ec.max != nil {
			maxS = formatNumber(*ec.max)
		}
		return fmt.Sprintf("range  %s - %s", minS, maxS)
	case "minimum":
		if ec.min != nil {
			return fmt.Sprintf("min    %s", formatNumber(*ec.min))
		}
		return "min    ?"
	case "maximum":
		if ec.max != nil {
			return fmt.Sprintf("max    %s", formatNumber(*ec.max))
		}
		return "max    ?"
	case "enum":
		return fmt.Sprintf("allow  [%s]", strings.Join(ec.allowed, ", "))
	case "required_bool":
		if ec.required != nil && *ec.required {
			return "required  true"
		}
		return "required  false"
	}
	return ""
}

func (m Model) viewStepAddConstraint(b *strings.Builder, step, total int) {
	b.WriteString(m.s.Title.Render(fmt.Sprintf("  Step %d/%d", step, total)))
	b.WriteString("  ")
	b.WriteString(m.s.Info.Render("Add constraints"))
	b.WriteString("\n\n")

	// Show existing constraints
	if len(m.authSetup.constraints) > 0 {
		for _, ec := range m.authSetup.constraints {
			b.WriteString(m.s.Info.Render(fmt.Sprintf("  %-20s %s", ec.tmpl.Label, formatConstraintValue(ec))))
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	switch m.authSetup.addSubStep {
	case addStepList:
		if len(m.authSetup.constraints) == 0 {
			b.WriteString(m.s.Dim.Render("  No constraints yet. Press 'a' to add one."))
		} else {
			b.WriteString(m.s.Dim.Render("  Press 'a' to add another, or enter to continue."))
		}
		b.WriteString("\n\n")
		b.WriteString(m.buildHints([]hint{
			{"a", "add constraint", hintAction},
			{"enter", "next", hintAction},
			{"esc", "back", hintNav},
		}))

	case addStepType:
		b.WriteString(m.s.Dim.Render("  Select constraint type:"))
		b.WriteString("\n\n")
		for i, label := range constraintTypeLabels {
			cursor := "  "
			style := m.s.Normal
			if i == m.authSetup.newTypeCursor {
				cursor = "> "
				style = m.s.Selected
			}
			b.WriteString(style.Render(fmt.Sprintf("%s%s", cursor, label)))
			b.WriteString("\n")
		}
		b.WriteString("\n\n")
		b.WriteString(m.buildHints([]hint{
			{"j/k", "navigate", hintNav},
			{"enter", "select", hintAction},
			{"esc", "back", hintNav},
		}))

	case addStepField:
		b.WriteString(m.s.Dim.Render(fmt.Sprintf("  Type: %s", constraintTypeLabels[m.authSetup.newTypeCursor])))
		b.WriteString("\n\n")
		b.WriteString(m.s.Dim.Render("  Field name:"))
		b.WriteString("\n")
		b.WriteString("  " + m.authSetup.newFieldInput.View())
		b.WriteString("\n\n")
		b.WriteString(m.buildHints([]hint{
			{"enter", "next", hintAction},
			{"esc", "back", hintNav},
		}))

	case addStepValues:
		selectedType := constraintTypeLabels[m.authSetup.newTypeCursor]
		field := strings.TrimSpace(m.authSetup.newFieldInput.Value())
		b.WriteString(m.s.Dim.Render(fmt.Sprintf("  Type: %s  Field: %s", selectedType, field)))
		b.WriteString("\n\n")

		switch selectedType {
		case "range":
			b.WriteString(m.s.Dim.Render("  Min: "))
			b.WriteString(m.authSetup.newMinInput.View())
			b.WriteString("\n")
			b.WriteString(m.s.Dim.Render("  Max: "))
			b.WriteString(m.authSetup.newMaxInput.View())
			b.WriteString("\n")
		case "minimum":
			b.WriteString(m.s.Dim.Render("  Min: "))
			b.WriteString(m.authSetup.newMinInput.View())
			b.WriteString("\n")
		case "maximum":
			b.WriteString(m.s.Dim.Render("  Max: "))
			b.WriteString(m.authSetup.newMaxInput.View())
			b.WriteString("\n")
		case "enum":
			b.WriteString(m.s.Dim.Render("  Allowed values:"))
			b.WriteString("\n  ")
			b.WriteString(m.authSetup.newAllowedInput.View())
			b.WriteString("\n")
		}
		b.WriteString("\n")

		hints := []hint{{"enter", "add", hintAction}, {"esc", "back", hintNav}}
		if selectedType == "range" {
			hints = append([]hint{{"tab", "switch field", hintNav}}, hints...)
		}
		b.WriteString(m.buildHints(hints))
	}
}

func (m Model) viewStepTier(b *strings.Builder, step, total int) {
	b.WriteString(m.s.Title.Render(fmt.Sprintf("  Step %d/%d", step, total)))
	b.WriteString("  ")
	b.WriteString(m.s.Info.Render("Confirmation tier"))
	b.WriteString("\n\n")

	tiers := []struct {
		label string
		desc  string
	}{
		{"Autonomous", "Signatures proceed without additional approval"},
		{"Co-sign", "Each signature requires human approval before completing"},
	}

	for i, t := range tiers {
		cursor := "  "
		style := m.s.Normal
		if i == m.authSetup.tierCursor {
			cursor = "> "
			style = m.s.Selected
		}
		b.WriteString(style.Render(fmt.Sprintf("%s%s", cursor, t.label)))
		b.WriteString("\n")
		if i == m.authSetup.tierCursor {
			b.WriteString(m.s.Dim.Render(fmt.Sprintf("      %s", t.desc)))
			b.WriteString("\n")
		}
	}

	b.WriteString("\n\n")
	b.WriteString(m.buildHints([]hint{
		{"j/k", "navigate", hintNav},
		{"enter", "select", hintAction},
		{"esc", "back", hintNav},
	}))
}

func (m Model) viewStepExpiry(b *strings.Builder, step, total int) {
	b.WriteString(m.s.Title.Render(fmt.Sprintf("  Step %d/%d", step, total)))
	b.WriteString("  ")
	b.WriteString(m.s.Info.Render("Expiration"))
	b.WriteString("\n\n")

	b.WriteString(m.s.Dim.Render("  How long should this authorization last?"))
	b.WriteString("\n\n")

	b.WriteString(m.s.Info.Render(fmt.Sprintf("  %d days", m.authSetup.expiryDays)))
	b.WriteString("\n")

	b.WriteString("\n\n")
	b.WriteString(m.buildHints([]hint{
		{"j/k", "adjust", hintNav},
		{"enter", "next", hintAction},
		{"esc", "back", hintNav},
	}))
}

func (m Model) viewStepConfirm(b *strings.Builder, step, total int) {
	b.WriteString(m.s.Title.Render(fmt.Sprintf("  Step %d/%d", step, total)))
	b.WriteString("  ")
	if m.authSetup.fromWizard {
		b.WriteString(m.s.Info.Render("Review and activate key"))
	} else {
		b.WriteString(m.s.Info.Render("Review and update key"))
	}
	b.WriteString("\n\n")

	tmpl := m.authSetup.selectedTemplate

	// Key
	b.WriteString(m.s.InfoLabel.Render("  Key       "))
	b.WriteString(m.s.Info.Render(m.authSetup.selectedKeyID))
	b.WriteString("\n")

	// Template
	b.WriteString(m.s.InfoLabel.Render("  Template  "))
	b.WriteString(m.s.Info.Render(tmpl.Label))
	b.WriteString("\n")

	// Scope
	scope := tmpl.Scope
	if tmpl.ID == "custom" {
		scope = strings.TrimSpace(m.authSetup.scopeInput.Value())
	}
	b.WriteString(m.s.InfoLabel.Render("  Scope     "))
	b.WriteString(m.s.Info.Render(scope))
	b.WriteString("\n")

	// Tier
	b.WriteString(m.s.InfoLabel.Render("  Tier      "))
	b.WriteString(m.s.Info.Render(m.authSetup.confirmationTier))
	b.WriteString("\n")

	// Repo (git-commit only)
	if tmpl.ShowRepoConstraint {
		repo := strings.TrimSpace(m.authSetup.repoInput.Value())
		b.WriteString(m.s.InfoLabel.Render("  Repo      "))
		if repo != "" {
			b.WriteString(m.s.Info.Render(repo))
		} else {
			b.WriteString(m.s.Dim.Render("any"))
		}
		b.WriteString("\n")
	}

	// Rules (git-commit only)
	if tmpl.ShowRules {
		var selected []string
		for _, r := range m.authSetup.rules {
			if r.checked {
				selected = append(selected, r.def.Label)
			}
		}
		if len(selected) > 0 {
			b.WriteString(m.s.InfoLabel.Render("  Rules     "))
			b.WriteString(m.s.Info.Render(selected[0]))
			b.WriteString("\n")
			for _, s := range selected[1:] {
				b.WriteString(m.s.InfoLabel.Render("            "))
				b.WriteString(m.s.Info.Render(s))
				b.WriteString("\n")
			}
		} else {
			b.WriteString(m.s.InfoLabel.Render("  Rules     "))
			b.WriteString(m.s.Dim.Render("none"))
			b.WriteString("\n")
		}
	}

	// Metadata constraints
	if len(m.authSetup.constraints) > 0 {
		b.WriteString("\n")
		b.WriteString(m.s.InfoLabel.Render("  Constraints"))
		b.WriteString("\n")
		for _, ec := range m.authSetup.constraints {
			b.WriteString(m.s.Info.Render(fmt.Sprintf("    %-18s %s", ec.tmpl.Label, formatConstraintValue(ec))))
			b.WriteString("\n")
		}
	}

	// Expiry
	b.WriteString(m.s.InfoLabel.Render("\n  Expires   "))
	b.WriteString(m.s.Info.Render(fmt.Sprintf("%d days", m.authSetup.expiryDays)))
	b.WriteString("\n\n")

	if m.authSetup.replacingTokenID != "" {
		b.WriteString(m.s.Dim.Render(fmt.Sprintf("  Replaces: %s (will be revoked)", m.authSetup.replacingTokenID)))
		b.WriteString("\n\n")
		b.WriteString(m.s.Selected.Render("  Save changes? (y/n)"))
	} else if m.authSetup.fromWizard {
		b.WriteString(m.s.Selected.Render("  Activate key? (y/n)"))
	} else {
		b.WriteString(m.s.Selected.Render("  Add authorization? (y/n)"))
	}

	b.WriteString("\n\n")
	b.WriteString(m.buildHints([]hint{
		{"y", "confirm", hintAction},
		{"n", "cancel", hintNav},
		{"esc", "back", hintNav},
	}))
}
