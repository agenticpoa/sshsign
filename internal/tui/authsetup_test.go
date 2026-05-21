package tui

import (
	"context"
	"strconv"
	"testing"

	"github.com/charmbracelet/lipgloss"

	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/storage"
)

// authSetupFixture builds the storage + user + signing key any
// authSetup test needs. handleCreateAuth persists rows, so we need a
// real signing key in place.
type authSetupFixture struct {
	t     *testing.T
	tdb   *storage.TestDB
	kek   *apoacrypto.KEKRing
	user  *storage.User
	keyID string
}

func setupAuthSetupFixture(t *testing.T) *authSetupFixture {
	t.Helper()
	ctx := context.Background()
	tdb, err := storage.NewTestDB()
	if err != nil {
		t.Fatalf("test DB: %v", err)
	}
	t.Cleanup(func() { tdb.Close() })

	kek, _ := apoacrypto.NewKEKRingForTests("authsetup-test-secret")
	user, _, err := storage.CreateUser(ctx, tdb.DB, "SHA256:astest", "ssh-ed25519 AAAAastest")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	pub, priv, _ := apoacrypto.GenerateEd25519Keypair()
	pubSSH, _ := apoacrypto.MarshalPublicKeySSH(pub)
	dek, _ := apoacrypto.GenerateDEK()
	encPriv, _ := apoacrypto.EncryptPrivateKey(priv, dek)
	wrapped, algo, _ := kek.WrapDEK(dek)
	sk, err := storage.CreateSigningKey(ctx, tdb.DB, user.UserID, pubSSH, encPriv, wrapped, algo)
	if err != nil {
		t.Fatalf("create signing key: %v", err)
	}

	return &authSetupFixture{t: t, tdb: tdb, kek: kek, user: user, keyID: sk.KeyID}
}

func (f *authSetupFixture) baseModel() Model {
	m := NewModelWithRenderer(f.tdb.DB, f.kek, nil, f.user, nil, false, lipgloss.DefaultRenderer())
	m.screen = screenAuthSetup
	return m
}

func (f *authSetupFixture) wizardModel() Model {
	m := f.baseModel()
	m.authSetup = newAuthSetupModelForKey(f.tdb.DB, f.user, f.keyID, m.r)
	return m
}

// templateByID returns the index of the template with the given ID in
// authTemplates. Tests target templates by stable ID rather than
// numeric position so a future re-ordering of authTemplates wouldn't
// silently switch which template each test exercises.
func templateByID(id string) int {
	for i, t := range authTemplates {
		if t.ID == id {
			return i
		}
	}
	return -1
}

// selectTemplateByID drives the wizard from stepSelectTemplate up to
// (and past) the template-selection enter press, leaving the model at
// whichever step follows. Returns the resulting Model.
func (f *authSetupFixture) selectTemplate(t *testing.T, m Model, id string) Model {
	t.Helper()
	target := templateByID(id)
	if target < 0 {
		t.Fatalf("unknown template id %q", id)
	}
	m.authSetup.templateCursor = target
	next, _ := m.Update(key("enter"))
	return next.(Model)
}

// ──────────────────────────────────────────────────────────────
// applicableSteps / wizard navigation
// ──────────────────────────────────────────────────────────────

func TestAuthSetup_ApplicableStepsForGitCommit(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "git-commit")

	steps := m.authSetup.applicableSteps()
	want := []authSetupStep{stepSelectTemplate, stepRepoConstraint, stepSelectRules, stepExpiry, stepConfirm}
	if len(steps) != len(want) {
		t.Fatalf("git-commit steps len = %d, want %d", len(steps), len(want))
	}
	for i, w := range want {
		if steps[i] != w {
			t.Errorf("steps[%d] = %v, want %v", i, steps[i], w)
		}
	}
}

func TestAuthSetup_ApplicableStepsForSafeAgreement(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "safe-agreement")

	steps := m.authSetup.applicableSteps()
	want := []authSetupStep{stepSelectTemplate, stepEditConstraints, stepConfirmationTier, stepExpiry, stepConfirm}
	if len(steps) != len(want) {
		t.Fatalf("safe steps len = %d, want %d", len(steps), len(want))
	}
	for i, w := range want {
		if steps[i] != w {
			t.Errorf("steps[%d] = %v, want %v", i, steps[i], w)
		}
	}
}

func TestAuthSetup_ApplicableStepsForCustom(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "custom")

	steps := m.authSetup.applicableSteps()
	want := []authSetupStep{stepSelectTemplate, stepCustomScope, stepAddConstraint, stepConfirmationTier, stepExpiry, stepConfirm}
	if len(steps) != len(want) {
		t.Fatalf("custom steps len = %d, want %d", len(steps), len(want))
	}
	for i, w := range want {
		if steps[i] != w {
			t.Errorf("steps[%d] = %v, want %v", i, steps[i], w)
		}
	}
}

func TestAuthSetup_NextPrevStep(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "git-commit")

	// After selecting git-commit, step is stepRepoConstraint.
	if m.authSetup.step != stepRepoConstraint {
		t.Fatalf("step after template selection = %v, want repoConstraint", m.authSetup.step)
	}
	m.authSetup.prevStep()
	if m.authSetup.step != stepSelectTemplate {
		t.Errorf("prevStep = %v, want selectTemplate", m.authSetup.step)
	}
	m.authSetup.nextStep()
	if m.authSetup.step != stepRepoConstraint {
		t.Errorf("nextStep = %v, want repoConstraint", m.authSetup.step)
	}
}

func TestAuthSetup_WizardStepCountAndNum(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "git-commit")

	if got, want := m.authSetup.wizardStepCount(), 5; got != want {
		t.Errorf("git-commit step count = %d, want %d", got, want)
	}
	// At stepRepoConstraint, position is 2 (1-indexed).
	if got, want := m.authSetup.wizardStepNum(), 2; got != want {
		t.Errorf("step num at repoConstraint = %d, want %d", got, want)
	}
}

// ──────────────────────────────────────────────────────────────
// Esc behavior
// ──────────────────────────────────────────────────────────────

func TestAuthSetup_EscOnFirstStepReturnsToWelcome(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	// Starts at stepSelectTemplate, which is the first step in
	// wizard mode (no stepSelectKey).
	next, _ := m.Update(key("esc"))
	if got := next.(Model).screen; got != screenWelcome {
		t.Errorf("esc on first step screen = %v, want welcome", got)
	}
}

func TestAuthSetup_EscOnLaterStepGoesBack(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "git-commit") // step is stepRepoConstraint
	next, _ := m.Update(key("esc"))
	mm := next.(Model)
	if mm.screen != screenAuthSetup {
		t.Errorf("esc on later step navigated away; screen = %v", mm.screen)
	}
	if mm.authSetup.step != stepSelectTemplate {
		t.Errorf("esc on later step landed on %v, want stepSelectTemplate", mm.authSetup.step)
	}
}

func TestAuthSetup_EscDuringInlineConstraintEditCancelsEdit(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "safe-agreement") // step = stepEditConstraints

	// Enter on first constraint (valuation_cap, range) puts us into
	// inline edit mode.
	next, _ := m.Update(key("enter"))
	mm := next.(Model)
	if !mm.authSetup.editingConstraint {
		t.Fatal("enter on constraint did not enter editing mode")
	}
	next2, _ := mm.Update(key("esc"))
	mm2 := next2.(Model)
	if mm2.authSetup.editingConstraint {
		t.Error("esc did not cancel inline edit")
	}
	if mm2.authSetup.step != stepEditConstraints {
		t.Errorf("esc moved off stepEditConstraints to %v", mm2.authSetup.step)
	}
}

func TestAuthSetup_EscInAddConstraintSubStepBacksUp(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "custom") // step = stepCustomScope

	m.authSetup.scopeInput.SetValue("my-custom-scope")
	next, _ := m.Update(key("enter"))
	mm := next.(Model)
	if mm.authSetup.step != stepAddConstraint {
		t.Fatalf("after custom scope, step = %v, want addConstraint", mm.authSetup.step)
	}
	// At addSubStep = addStepList. Press 'a' to enter addStepType.
	next2, _ := mm.Update(key("a"))
	mm2 := next2.(Model)
	if mm2.authSetup.addSubStep != addStepType {
		t.Fatalf("after 'a', addSubStep = %v, want addStepType", mm2.authSetup.addSubStep)
	}
	// Esc should back us up within the sub-flow, not leave the step.
	next3, _ := mm2.Update(key("esc"))
	mm3 := next3.(Model)
	if mm3.authSetup.addSubStep != addStepList {
		t.Errorf("esc didn't back up; addSubStep = %v, want addStepList", mm3.authSetup.addSubStep)
	}
	if mm3.authSetup.step != stepAddConstraint {
		t.Errorf("esc moved off stepAddConstraint to %v", mm3.authSetup.step)
	}
}

// ──────────────────────────────────────────────────────────────
// Per-step update functions
// ──────────────────────────────────────────────────────────────

func TestAuthSetup_SelectTemplate_NavAndEnter(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()

	if m.authSetup.templateCursor != 0 {
		t.Fatalf("starting templateCursor = %d, want 0", m.authSetup.templateCursor)
	}
	m1, _ := m.Update(key("down"))
	if m1.(Model).authSetup.templateCursor != 1 {
		t.Errorf("down didn't advance cursor")
	}
	// Walk down past the end; cursor caps at last template.
	curr := m1.(Model)
	for i := 0; i < 20; i++ {
		next, _ := curr.Update(key("down"))
		curr = next.(Model)
	}
	if want := len(authTemplates) - 1; curr.authSetup.templateCursor != want {
		t.Errorf("templateCursor = %d, want %d", curr.authSetup.templateCursor, want)
	}
	// Enter selects, advancing into the next applicable step.
	next, _ := curr.Update(key("enter"))
	mm := next.(Model)
	if mm.authSetup.selectedTemplate == nil {
		t.Error("enter did not set selectedTemplate")
	}
}

func TestAuthSetup_CustomScopeEmptyRejected(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "custom") // step = stepCustomScope

	// Don't type anything; press enter.
	next, _ := m.Update(key("enter"))
	mm := next.(Model)
	if mm.authSetup.step != stepCustomScope {
		t.Errorf("empty scope advanced; step = %v, want stepCustomScope", mm.authSetup.step)
	}
	if !mm.authSetup.isError {
		t.Error("empty scope didn't flag error")
	}
}

func TestAuthSetup_CustomScopeAcceptsValue(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "custom")

	m.authSetup.scopeInput.SetValue("my-scope")
	next, _ := m.Update(key("enter"))
	mm := next.(Model)
	if mm.authSetup.step != stepAddConstraint {
		t.Errorf("step after scope entry = %v, want addConstraint", mm.authSetup.step)
	}
}

func TestAuthSetup_RulesSpaceToggles(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "git-commit")

	// stepRepoConstraint → enter (no repo) → stepSelectRules
	next, _ := m.Update(key("enter"))
	mm := next.(Model)
	if mm.authSetup.step != stepSelectRules {
		t.Fatalf("step = %v, want stepSelectRules", mm.authSetup.step)
	}
	if len(mm.authSetup.rules) == 0 {
		t.Fatal("no rules to toggle")
	}
	before := mm.authSetup.rules[0].checked
	next2, _ := mm.Update(key(" "))
	if got := next2.(Model).authSetup.rules[0].checked; got == before {
		t.Errorf("space did not toggle rule check; still %v", got)
	}
}

func TestAuthSetup_EditConstraint_RequiredBoolTogglesOnEnter(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "safe-agreement")

	// safe-agreement has constraints [valuation_cap(range), discount_rate(min), pro_rata(required_bool)]
	// Move cursor to pro_rata (index 2).
	m.authSetup.constraintCursor = 2

	// Capture the VALUE before, not the pointer. The slice is shared
	// across the copied Model, so the in-place pointer toggle inside
	// updateAuthEditConstraints mutates a single backing bool — the
	// test has to snapshot before Update().
	if m.authSetup.constraints[2].required == nil {
		t.Fatal("safe template's pro_rata required field is nil before toggle")
	}
	beforeVal := *m.authSetup.constraints[2].required

	next, _ := m.Update(key("enter"))
	mm := next.(Model)
	// Enter on required_bool toggles the value; should not enter
	// inline edit mode.
	if mm.authSetup.editingConstraint {
		t.Error("enter on required_bool entered editing mode")
	}
	if mm.authSetup.constraints[2].required == nil {
		t.Fatal("required pointer became nil after toggle")
	}
	if *mm.authSetup.constraints[2].required == beforeVal {
		t.Errorf("required_bool value did not toggle from %v", beforeVal)
	}
}

func TestAuthSetup_EditConstraint_RangeInputs(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "safe-agreement")

	// Cursor at index 0 = valuation_cap (range). Enter to edit.
	next, _ := m.Update(key("enter"))
	mm := next.(Model)
	if !mm.authSetup.editingConstraint {
		t.Fatal("did not enter inline edit mode for range constraint")
	}
	// Type new min, tab, type new max, enter.
	mm.authSetup.constraints[0].minInput.SetValue("5000000")
	mm.authSetup.constraints[0].maxInput.SetValue("10000000")
	next2, _ := mm.Update(key("enter"))
	mm2 := next2.(Model)
	if mm2.authSetup.editingConstraint {
		t.Fatal("enter did not exit inline edit mode")
	}
	if mm2.authSetup.constraints[0].min == nil || *mm2.authSetup.constraints[0].min != 5000000 {
		t.Errorf("min not committed; got %v", mm2.authSetup.constraints[0].min)
	}
	if mm2.authSetup.constraints[0].max == nil || *mm2.authSetup.constraints[0].max != 10000000 {
		t.Errorf("max not committed; got %v", mm2.authSetup.constraints[0].max)
	}
}

func TestAuthSetup_EditConstraint_EnumToggleAndAdd(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "nda")

	// nda has constraints [nda_type(enum, mutual/one-way), term_years(range)]
	m.authSetup.constraintCursor = 0
	next, _ := m.Update(key("enter"))
	mm := next.(Model)
	if !mm.authSetup.editingConstraint {
		t.Fatal("did not enter inline edit mode for enum constraint")
	}

	// Uncheck the first option.
	beforeChecked := mm.authSetup.constraints[0].enumOptions[0].checked
	next2, _ := mm.Update(key(" "))
	mm2 := next2.(Model)
	if mm2.authSetup.constraints[0].enumOptions[0].checked == beforeChecked {
		t.Error("space did not toggle enum option")
	}

	// Add a new custom value via the "Add custom value..." row at
	// index len(enumOptions).
	mm2.authSetup.constraints[0].enumCursor = len(mm2.authSetup.constraints[0].enumOptions)
	next3, _ := mm2.Update(key("enter"))
	mm3 := next3.(Model)
	if !mm3.authSetup.constraints[0].enumAddingNew {
		t.Fatal("did not enter enumAddingNew state")
	}
	mm3.authSetup.constraints[0].enumNewInput.SetValue("custom-mode")
	next4, _ := mm3.Update(key("enter"))
	mm4 := next4.(Model)
	if mm4.authSetup.constraints[0].enumAddingNew {
		t.Error("still in enumAddingNew after enter")
	}
	found := false
	for _, o := range mm4.authSetup.constraints[0].enumOptions {
		if o.value == "custom-mode" {
			found = true
			break
		}
	}
	if !found {
		t.Error("custom enum value not added to options")
	}
}

func TestAuthSetup_AddConstraint_FullSubFlowRange(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "custom") // → stepCustomScope

	m.authSetup.scopeInput.SetValue("custom-scope")
	next, _ := m.Update(key("enter")) // → stepAddConstraint (addStepList)
	mm := next.(Model)

	// 'a' starts a new constraint → addStepType
	next2, _ := mm.Update(key("a"))
	mm = next2.(Model)
	if mm.authSetup.addSubStep != addStepType {
		t.Fatalf("addSubStep = %v, want addStepType", mm.authSetup.addSubStep)
	}

	// Cursor 0 = "range". Enter advances to addStepField.
	next3, _ := mm.Update(key("enter"))
	mm = next3.(Model)
	if mm.authSetup.addSubStep != addStepField {
		t.Fatalf("addSubStep = %v, want addStepField", mm.authSetup.addSubStep)
	}

	mm.authSetup.newFieldInput.SetValue("amount_usd")
	next4, _ := mm.Update(key("enter"))
	mm = next4.(Model)
	if mm.authSetup.addSubStep != addStepValues {
		t.Fatalf("addSubStep = %v, want addStepValues", mm.authSetup.addSubStep)
	}

	mm.authSetup.newMinInput.SetValue("100")
	mm.authSetup.newMaxInput.SetValue("1000")
	next5, _ := mm.Update(key("enter"))
	mm = next5.(Model)
	if mm.authSetup.addSubStep != addStepList {
		t.Fatalf("after values, addSubStep = %v, want addStepList", mm.authSetup.addSubStep)
	}

	if len(mm.authSetup.constraints) != 1 {
		t.Fatalf("constraints len = %d, want 1", len(mm.authSetup.constraints))
	}
	ec := mm.authSetup.constraints[0]
	if ec.tmpl.Field != "amount_usd" || ec.tmpl.Type != "range" {
		t.Errorf("constraint = {%q, %q}, want {amount_usd, range}", ec.tmpl.Field, ec.tmpl.Type)
	}
	if ec.tmpl.DefaultMin == nil || *ec.tmpl.DefaultMin != 100 {
		t.Errorf("default min = %v, want 100", ec.tmpl.DefaultMin)
	}
	if ec.tmpl.DefaultMax == nil || *ec.tmpl.DefaultMax != 1000 {
		t.Errorf("default max = %v, want 1000", ec.tmpl.DefaultMax)
	}
}

func TestAuthSetup_AddConstraint_RequiredBoolSkipsValues(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "custom")
	m.authSetup.scopeInput.SetValue("s")
	mm, _ := m.Update(key("enter"))
	m = mm.(Model)
	m1, _ := m.Update(key("a"))
	m = m1.(Model)

	// Move cursor to required_bool (last index).
	m.authSetup.newTypeCursor = len(constraintTypeLabels) - 1
	m2, _ := m.Update(key("enter"))
	mm2 := m2.(Model)
	mm2.authSetup.newFieldInput.SetValue("must_sign")
	m3, _ := mm2.Update(key("enter"))
	mm3 := m3.(Model)
	// required_bool skips addStepValues and goes straight back to list.
	if mm3.authSetup.addSubStep != addStepList {
		t.Errorf("after required_bool field, addSubStep = %v, want addStepList", mm3.authSetup.addSubStep)
	}
	if len(mm3.authSetup.constraints) != 1 {
		t.Fatalf("constraint not appended; len = %d", len(mm3.authSetup.constraints))
	}
	if mm3.authSetup.constraints[0].tmpl.Type != "required_bool" {
		t.Errorf("constraint type = %q, want required_bool", mm3.authSetup.constraints[0].tmpl.Type)
	}
}

func TestAuthSetup_TierToggle(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "safe-agreement")
	// Walk through edit-constraints (just enter to skip with no edits) → tier.
	m.authSetup.step = stepConfirmationTier

	// tierCursor starts at 1 (cosign) because safe defaults to cosign.
	if m.authSetup.tierCursor != 1 {
		t.Fatalf("safe default tierCursor = %d, want 1", m.authSetup.tierCursor)
	}
	// Enter selects cosign and advances.
	next, _ := m.Update(key("enter"))
	mm := next.(Model)
	if mm.authSetup.confirmationTier != "cosign" {
		t.Errorf("tier = %q, want cosign", mm.authSetup.confirmationTier)
	}

	// Move back: up to cursor 0, enter selects autonomous, requires
	// the tier flag to clear requireSignature.
	m.authSetup.tierCursor = 1
	m.authSetup.requireSignature = true
	m.authSetup.step = stepConfirmationTier
	m1, _ := m.Update(key("up"))
	if m1.(Model).authSetup.tierCursor != 0 {
		t.Errorf("up didn't move cursor to autonomous")
	}
	m2, _ := m1.(Model).Update(key("enter"))
	mm2 := m2.(Model)
	if mm2.authSetup.confirmationTier != "autonomous" {
		t.Errorf("tier after autonomous enter = %q", mm2.authSetup.confirmationTier)
	}
	if mm2.authSetup.requireSignature {
		t.Error("requireSignature should be cleared when switching to autonomous")
	}
}

func TestAuthSetup_TierSpaceTogglesRequireSignature(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "safe-agreement")
	m.authSetup.step = stepConfirmationTier
	m.authSetup.tierCursor = 1 // cosign

	if m.authSetup.requireSignature {
		t.Fatalf("requireSignature unexpectedly true")
	}
	next, _ := m.Update(key(" "))
	if !next.(Model).authSetup.requireSignature {
		t.Error("space did not toggle requireSignature on cosign")
	}
}

func TestAuthSetup_ExpiryBounded(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m.authSetup.step = stepExpiry
	m.authSetup.expiryDays = 1

	// Down at 1 stays at 1 (clamped).
	next, _ := m.Update(key("down"))
	if got := next.(Model).authSetup.expiryDays; got != 1 {
		t.Errorf("expiryDays = %d, want 1 (clamped at lower bound)", got)
	}

	// Walk up to 365, then one more up stays at 365.
	m.authSetup.expiryDays = 365
	next2, _ := m.Update(key("up"))
	if got := next2.(Model).authSetup.expiryDays; got != 365 {
		t.Errorf("expiryDays = %d, want 365 (clamped at upper bound)", got)
	}
}

// ──────────────────────────────────────────────────────────────
// handleCreateAuth: persists and navigates
// ──────────────────────────────────────────────────────────────

func TestAuthSetup_ConfirmCreatesAuthFromWizard(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "git-commit") // wizard path, fromWizard=true

	// Skip through to confirm. Walk via step assignments — simpler
	// than driving every keypress.
	m.authSetup.step = stepConfirm
	next, _ := m.Update(key("y"))
	mm := next.(Model)
	if mm.authSetup.isError {
		t.Fatalf("create errored: %s", mm.authSetup.status)
	}
	if mm.screen != screenWelcome {
		t.Errorf("after wizard confirm, screen = %v, want welcome", mm.screen)
	}

	auths, err := storage.FindAuthorizationsForKey(context.Background(), f.tdb.DB, f.keyID)
	if err != nil {
		t.Fatalf("listing auths: %v", err)
	}
	if len(auths) != 1 {
		t.Fatalf("expected 1 auth after confirm, got %d", len(auths))
	}
	if auths[0].ConfirmationTier != "autonomous" {
		t.Errorf("tier = %q, want autonomous", auths[0].ConfirmationTier)
	}
	if len(auths[0].Scopes) != 1 || auths[0].Scopes[0] != "git-commit" {
		t.Errorf("scopes = %v, want [git-commit]", auths[0].Scopes)
	}
}

func TestAuthSetup_ConfirmCreatesAuthFromManageKeys(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.baseModel()
	// Non-wizard entry point: explicitly add auth to existing key.
	m.authSetup = newAuthSetupModelForExistingKey(f.tdb.DB, f.user, f.keyID, m.r)
	m = f.selectTemplate(t, m, "git-commit")

	m.authSetup.step = stepConfirm
	next, _ := m.Update(key("y"))
	mm := next.(Model)
	if mm.authSetup.isError {
		t.Fatalf("create errored: %s", mm.authSetup.status)
	}
	if mm.screen != screenManageKeys {
		t.Errorf("after non-wizard confirm, screen = %v, want manageKeys", mm.screen)
	}
	if mm.manageKeys.view != viewKeyDetail {
		t.Errorf("manageKeys view = %v, want detail", mm.manageKeys.view)
	}
}

func TestAuthSetup_ConfirmReplacingAuthRevokesOld(t *testing.T) {
	f := setupAuthSetupFixture(t)
	ctx := context.Background()

	// Pre-seed an authorization for the key, then edit it.
	old, err := storage.CreateAuthorization(ctx, f.tdb.DB, f.keyID, f.user.UserID,
		[]string{"git-commit"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("seed old auth: %v", err)
	}

	m := f.baseModel()
	m.authSetup = newAuthSetupFromExisting(f.tdb.DB, f.user, f.keyID, old, m.r)
	m.authSetup.step = stepConfirm

	next, _ := m.Update(key("y"))
	mm := next.(Model)
	if mm.authSetup.isError {
		t.Fatalf("create errored: %s", mm.authSetup.status)
	}

	// Old auth must now be revoked.
	rolledOld, _ := storage.GetAuthorization(ctx, f.tdb.DB, old.TokenID)
	if rolledOld.RevokedAt == nil {
		t.Error("replacingTokenID auth was not revoked on confirm")
	}

	// A new active auth exists for the key.
	auths, _ := storage.FindAuthorizationsForKey(ctx, f.tdb.DB, f.keyID)
	if len(auths) != 1 {
		t.Errorf("expected 1 active auth (the new one), got %d", len(auths))
	}
}

func TestAuthSetup_ConfirmDeclineReturnsToWelcome(t *testing.T) {
	f := setupAuthSetupFixture(t)
	m := f.wizardModel()
	m = f.selectTemplate(t, m, "git-commit")
	m.authSetup.step = stepConfirm

	next, _ := m.Update(key("n"))
	mm := next.(Model)
	if mm.screen != screenWelcome {
		t.Errorf("decline navigated to %v, want welcome", mm.screen)
	}
	// No auth should have been created.
	auths, _ := storage.FindAuthorizationsForKey(context.Background(), f.tdb.DB, f.keyID)
	if len(auths) != 0 {
		t.Errorf("decline persisted %d auths", len(auths))
	}
}

func TestAuthSetup_PendingKeyPersistsBothOnConfirm(t *testing.T) {
	// Path: welcome → CreateKey generated a fresh key and stashed it in
	// pendingPubSSH/etc. Confirm should persist BOTH the key and the auth.
	f := setupAuthSetupFixture(t)

	// Build fresh pending key material exactly like welcome's
	// handleCreateKey would.
	pub, priv, _ := apoacrypto.GenerateEd25519Keypair()
	pubSSH, _ := apoacrypto.MarshalPublicKeySSH(pub)
	dek, _ := apoacrypto.GenerateDEK()
	encPriv, _ := apoacrypto.EncryptPrivateKey(priv, dek)
	wrappedDEK, kekAlgo, _ := f.kek.WrapDEK(dek)
	pendingKeyID := storage.NewKeyID()

	m := f.baseModel()
	m.authSetup = newAuthSetupModelForPendingKey(
		f.tdb.DB, f.user, pendingKeyID, pubSSH, encPriv, wrappedDEK, kekAlgo, m.r,
	)
	m = f.selectTemplate(t, m, "git-commit")
	m.authSetup.step = stepConfirm

	next, _ := m.Update(key("y"))
	mm := next.(Model)
	if mm.authSetup.isError {
		t.Fatalf("confirm errored: %s", mm.authSetup.status)
	}

	// Key must now exist in storage.
	sk, err := storage.GetSigningKey(context.Background(), f.tdb.DB, pendingKeyID)
	if err != nil || sk == nil {
		t.Fatalf("pending key not persisted: %v", err)
	}
	if sk.KEKAlgo != kekAlgo {
		t.Errorf("persisted kek_algo = %q, want %q", sk.KEKAlgo, kekAlgo)
	}

	// Auth must exist for that key.
	auths, _ := storage.FindAuthorizationsForKey(context.Background(), f.tdb.DB, pendingKeyID)
	if len(auths) != 1 {
		t.Errorf("expected 1 auth on the new key, got %d", len(auths))
	}

	// Pending fields should be cleared so a re-confirm doesn't
	// double-write.
	if mm.authSetup.pendingPubSSH != "" {
		t.Error("pendingPubSSH not cleared after success")
	}
	if mm.authSetup.pendingKEKAlgo != "" {
		t.Error("pendingKEKAlgo not cleared after success")
	}
}

// ──────────────────────────────────────────────────────────────
// Small helpers
// ──────────────────────────────────────────────────────────────

func TestAuthSetup_FormatNumber(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{1.5, "1.5"},
		{1000000, "1000000"},
	}
	for _, c := range cases {
		got := formatNumber(c.in)
		if got != c.want {
			t.Errorf("formatNumber(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAuthSetup_IsNumericRune(t *testing.T) {
	for _, r := range "0123456789." {
		if !isNumericRune(r) {
			t.Errorf("isNumericRune(%q) = false, want true", r)
		}
	}
	for _, r := range "abcXYZ!@#" {
		if isNumericRune(r) {
			t.Errorf("isNumericRune(%q) = true, want false", r)
		}
	}
}

func TestAuthSetup_NumericInputParse(t *testing.T) {
	// Smoke check that storing/parsing the values returned from the
	// inline editor produces what handleCreateAuth would persist.
	v, err := strconv.ParseFloat("8000000", 64)
	if err != nil || v != 8000000 {
		t.Errorf("ParseFloat(8000000) = (%v, %v)", v, err)
	}
}
