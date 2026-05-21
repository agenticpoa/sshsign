package tui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/agenticpoa/sshsign/internal/audit"
	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/storage"
)

// pendingFixture is the standard setup the TUI pending tests need:
// a test DB, a user, a signing key wrapped under a test KEK ring, an
// autonomous authorization (so approve doesn't need a web envelope),
// and one pending signature waiting for approval.
type pendingFixture struct {
	t        *testing.T
	tdb      *storage.TestDB
	kek      *apoacrypto.KEKRing
	user     *storage.User
	keyID    string
	authID   string
	pending  *storage.PendingSignature
	audit    *audit.MemoryLogger
}

func setupPendingFixture(t *testing.T) *pendingFixture {
	t.Helper()
	ctx := context.Background()

	tdb, err := storage.NewTestDB()
	if err != nil {
		t.Fatalf("test DB: %v", err)
	}
	t.Cleanup(func() { tdb.Close() })

	kek, err := apoacrypto.NewKEKRingForTests("tui-test-secret")
	if err != nil {
		t.Fatalf("KEK ring: %v", err)
	}

	user, _, err := storage.CreateUser(ctx, tdb.DB, "SHA256:tuitest", "ssh-ed25519 AAAAtuitest")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Build a real signing key wrapped under the test ring so the
	// approve flow can actually unwrap and sign.
	pub, priv, _ := apoacrypto.GenerateEd25519Keypair()
	pubSSH, _ := apoacrypto.MarshalPublicKeySSH(pub)
	dek, _ := apoacrypto.GenerateDEK()
	encPriv, _ := apoacrypto.EncryptPrivateKey(priv, dek)
	wrappedDEK, kekAlgo, _ := kek.WrapDEK(dek)

	sk, err := storage.CreateSigningKey(ctx, tdb.DB, user.UserID, pubSSH, encPriv, wrappedDEK, kekAlgo)
	if err != nil {
		t.Fatalf("create signing key: %v", err)
	}

	// Autonomous tier with a one-day expiry. No require_signature, so
	// the TUI approve path doesn't need a web evidence envelope.
	auth, err := storage.CreateAuthorizationFull(ctx, tdb.DB, sk.KeyID, user.UserID,
		[]string{"safe-agreement"}, nil, nil, "cosign", false, nil, nil, nil)
	if err != nil {
		t.Fatalf("create auth: %v", err)
	}

	// MAC must be present even though the TUI flow doesn't verify it
	// — storage requires non-empty for cosign rows in spirit, but
	// existing pending creation accepts nil too. Use a real MAC so
	// the row mirrors production shape.
	mac := kek.ComputePendingMAC(apoacrypto.PendingBinding{
		SigningKeyID: sk.KeyID, AuthTokenID: auth.TokenID, RequesterID: user.UserID,
		DocType: "safe-agreement", PayloadHash: "sha256:tuipayload",
		Metadata: `{}`,
	})
	ps, err := storage.CreatePendingSignature(ctx, tdb.DB, sk.KeyID, auth.TokenID, user.UserID,
		"safe-agreement", "sha256:tuipayload", `{}`,
		apoacrypto.HashApprovalToken("tuitoken"), "", mac)
	if err != nil {
		t.Fatalf("create pending: %v", err)
	}

	return &pendingFixture{
		t: t, tdb: tdb, kek: kek, user: user,
		keyID: sk.KeyID, authID: auth.TokenID, pending: ps,
		audit: audit.NewMemoryLogger(),
	}
}

// model builds a TUI Model on the screenPendingApprovals screen with
// the pending list refreshed from storage. Convenience for the tests
// below to avoid repeating the same wiring.
func (f *pendingFixture) model() Model {
	m := NewModelWithRenderer(f.tdb.DB, f.kek, f.audit, f.user, nil, false, lipgloss.DefaultRenderer())
	m.screen = screenPendingApprovals
	m.pending = newPendingApprovalsModel(f.tdb.DB, f.user)
	return m
}

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

func TestPending_LoadsFromStorage(t *testing.T) {
	f := setupPendingFixture(t)
	m := f.model()

	if len(m.pending.pendings) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(m.pending.pendings))
	}
	if m.pending.pendings[0].ID != f.pending.ID {
		t.Errorf("loaded pending id = %q, want %q", m.pending.pendings[0].ID, f.pending.ID)
	}
}

func TestPending_EnterMovesToDetail(t *testing.T) {
	f := setupPendingFixture(t)
	m := f.model()

	next, _ := m.Update(key("enter"))
	mm := next.(Model)
	if mm.pending.view != pendingViewDetail {
		t.Errorf("view = %v, want detail", mm.pending.view)
	}
}

func TestPending_EscFromListReturnsToWelcome(t *testing.T) {
	f := setupPendingFixture(t)
	m := f.model()

	next, _ := m.Update(key("esc"))
	mm := next.(Model)
	if mm.screen != screenWelcome {
		t.Errorf("screen = %v, want welcome", mm.screen)
	}
}

func TestPending_DenyFlowResolvesAndLogs(t *testing.T) {
	f := setupPendingFixture(t)
	m := f.model()

	// Enter detail → press 'd' → confirm with 'y'.
	m1, _ := m.Update(key("enter"))
	m2, _ := m1.(Model).Update(key("d"))
	if got := m2.(Model).pending.confirmAction; got != "deny" {
		t.Fatalf("confirmAction = %q, want deny", got)
	}
	m3, _ := m2.(Model).Update(key("y"))
	mm := m3.(Model)

	if mm.pending.isError {
		t.Errorf("unexpected error after deny: %s", mm.pending.status)
	}

	ps, err := storage.GetPendingSignature(context.Background(), f.tdb.DB, f.pending.ID)
	if err != nil {
		t.Fatalf("getting pending: %v", err)
	}
	if ps.Status != "denied" {
		t.Errorf("status = %q, want denied", ps.Status)
	}

	// Audit log should carry the denial.
	found := false
	for _, e := range f.audit.Entries() {
		if e.Result == "DENIED" && e.SigningKeyID == f.keyID {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DENIED audit entry from TUI deny path")
	}
}

func TestPending_ConfirmCancelClearsAction(t *testing.T) {
	f := setupPendingFixture(t)
	m := f.model()

	m1, _ := m.Update(key("enter"))
	m2, _ := m1.(Model).Update(key("a"))
	if m2.(Model).pending.confirmAction != "approve" {
		t.Fatalf("expected confirmAction = approve")
	}
	m3, _ := m2.(Model).Update(key("n"))
	if got := m3.(Model).pending.confirmAction; got != "" {
		t.Errorf("after 'n' cancel, confirmAction = %q, want empty", got)
	}
}

func TestPending_ApproveFlowSigns(t *testing.T) {
	f := setupPendingFixture(t)
	m := f.model()

	// Enter detail → press 'a' → confirm with 'y'.
	m1, _ := m.Update(key("enter"))
	m2, _ := m1.(Model).Update(key("a"))
	m3, _ := m2.(Model).Update(key("y"))
	mm := m3.(Model)

	if mm.pending.isError {
		t.Fatalf("approve failed: %s", mm.pending.status)
	}

	ps, err := storage.GetPendingSignature(context.Background(), f.tdb.DB, f.pending.ID)
	if err != nil {
		t.Fatalf("getting pending: %v", err)
	}
	if ps.Status != "approved" {
		t.Errorf("status = %q, want approved", ps.Status)
	}
	if ps.Signature == "" {
		t.Error("expected non-empty signature after approve")
	}

	// Audit log should carry the SIGNED entry.
	found := false
	for _, e := range f.audit.Entries() {
		if e.Result == "SIGNED" && e.SigningKeyID == f.keyID {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SIGNED audit entry from TUI approve path")
	}
}

func TestPending_RefreshKey(t *testing.T) {
	f := setupPendingFixture(t)
	m := f.model()

	// Resolve the pending out-of-band, then press 'r' — the list
	// should empty (only "pending" status rows are listed).
	_ = storage.ResolvePendingSignature(context.Background(), f.tdb.DB, f.pending.ID, "denied", f.user.UserID, "")

	next, _ := m.Update(key("r"))
	mm := next.(Model)
	if len(mm.pending.pendings) != 0 {
		t.Errorf("after refresh, pendings = %d, want 0", len(mm.pending.pendings))
	}
	if !strings.Contains(mm.pending.status, "Refreshed") {
		t.Errorf("status = %q, want to contain Refreshed", mm.pending.status)
	}
}
