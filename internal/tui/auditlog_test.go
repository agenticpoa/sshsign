package tui

import (
	"context"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/storage"
)

func setupAuditLogFixture(t *testing.T) (*storage.TestDB, *apoacrypto.KEKRing, *storage.User) {
	t.Helper()
	tdb, err := storage.NewTestDB()
	if err != nil {
		t.Fatalf("test DB: %v", err)
	}
	t.Cleanup(func() { tdb.Close() })

	kek, _ := apoacrypto.NewKEKRingForTests("audit-test-secret")
	user, _, err := storage.CreateUser(context.Background(), tdb.DB, "SHA256:audittest", "ssh-ed25519 AAAAaudittest")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	return tdb, kek, user
}

// auditMakeKey creates a signing key, optionally revoking it and
// adding an authorization. Returns the new key ID.
func auditMakeKey(t *testing.T, tdb *storage.TestDB, kek *apoacrypto.KEKRing, userID string, revoke, withAuth bool) string {
	t.Helper()
	ctx := context.Background()
	pub, priv, _ := apoacrypto.GenerateEd25519Keypair()
	pubSSH, _ := apoacrypto.MarshalPublicKeySSH(pub)
	dek, _ := apoacrypto.GenerateDEK()
	encPriv, _ := apoacrypto.EncryptPrivateKey(priv, dek)
	wrapped, algo, _ := kek.WrapDEK(dek)
	sk, err := storage.CreateSigningKey(ctx, tdb.DB, userID, pubSSH, encPriv, wrapped, algo)
	if err != nil {
		t.Fatalf("create signing key: %v", err)
	}
	if withAuth {
		if _, err := storage.CreateAuthorization(ctx, tdb.DB, sk.KeyID, userID,
			[]string{"safe-agreement"}, nil, nil, nil, nil); err != nil {
			t.Fatalf("create auth: %v", err)
		}
	}
	if revoke {
		if err := storage.RevokeSigningKey(ctx, tdb.DB, sk.KeyID); err != nil {
			t.Fatalf("revoke: %v", err)
		}
	}
	return sk.KeyID
}

func TestAuditLog_EmptyForUserWithNoKeys(t *testing.T) {
	tdb, _, user := setupAuditLogFixture(t)
	m := newAuditLogModel(tdb.DB, user)
	if len(m.entries) != 0 {
		t.Errorf("expected 0 entries for user with no activity, got %d", len(m.entries))
	}
}

func TestAuditLog_RecordsKeyCreation(t *testing.T) {
	tdb, kek, user := setupAuditLogFixture(t)
	keyID := auditMakeKey(t, tdb, kek, user.UserID, false, false)

	m := newAuditLogModel(tdb.DB, user)
	if len(m.entries) != 1 {
		t.Fatalf("expected 1 entry for one created key, got %d", len(m.entries))
	}
	if m.entries[0].Action != "key created" {
		t.Errorf("action = %q, want \"key created\"", m.entries[0].Action)
	}
	if m.entries[0].KeyID != keyID {
		t.Errorf("KeyID = %q, want %q", m.entries[0].KeyID, keyID)
	}
}

func TestAuditLog_RecordsRevocation(t *testing.T) {
	tdb, kek, user := setupAuditLogFixture(t)
	keyID := auditMakeKey(t, tdb, kek, user.UserID, true, false)

	m := newAuditLogModel(tdb.DB, user)
	if len(m.entries) != 2 {
		t.Fatalf("expected 2 entries (created + revoked), got %d", len(m.entries))
	}
	// Entries are reversed (newest first), so revocation should be index 0.
	if m.entries[0].Action != "key revoked" {
		t.Errorf("first entry action = %q, want \"key revoked\"", m.entries[0].Action)
	}
	if m.entries[1].Action != "key created" {
		t.Errorf("second entry action = %q, want \"key created\"", m.entries[1].Action)
	}
	for _, e := range m.entries {
		if e.KeyID != keyID {
			t.Errorf("KeyID = %q, want %q", e.KeyID, keyID)
		}
	}
}

func TestAuditLog_RecordsAuthCreation(t *testing.T) {
	tdb, kek, user := setupAuditLogFixture(t)
	_ = auditMakeKey(t, tdb, kek, user.UserID, false, true)

	m := newAuditLogModel(tdb.DB, user)
	if len(m.entries) != 2 {
		t.Fatalf("expected 2 entries (key + auth created), got %d", len(m.entries))
	}
	foundAuth := false
	foundKey := false
	for _, e := range m.entries {
		if e.Action == "auth created" {
			foundAuth = true
			if !strings.Contains(e.Detail, "safe-agreement") {
				t.Errorf("auth detail = %q, want scope name", e.Detail)
			}
		}
		if e.Action == "key created" {
			foundKey = true
		}
	}
	if !foundAuth {
		t.Error("no 'auth created' entry produced")
	}
	if !foundKey {
		t.Error("no 'key created' entry produced")
	}
}

func TestAuditLog_NewestFirst(t *testing.T) {
	tdb, kek, user := setupAuditLogFixture(t)
	auditMakeKey(t, tdb, kek, user.UserID, false, false)
	auditMakeKey(t, tdb, kek, user.UserID, false, false)
	auditMakeKey(t, tdb, kek, user.UserID, false, false)

	m := newAuditLogModel(tdb.DB, user)
	if len(m.entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(m.entries))
	}
	// We can't rely on sub-second timestamp differences in SQLite to
	// distinguish 3 rapid CreateSigningKey calls, so the assertion
	// here is structural: the slice was reversed (entries[0] is the
	// last inserted from the storage-ordered list, regardless of the
	// indistinguishable timestamps). We verify the reversal hook ran
	// by checking the list isn't simply in insertion order — which
	// requires a sentinel: insert a 4th key and confirm it lands at
	// index 0.
	last := auditMakeKey(t, tdb, kek, user.UserID, false, false)
	m2 := newAuditLogModel(tdb.DB, user)
	if m2.entries[0].KeyID != last {
		t.Errorf("expected most-recent key %q first, got %q", last, m2.entries[0].KeyID)
	}
}

func TestAuditLog_CursorNavigationBounded(t *testing.T) {
	tdb, kek, user := setupAuditLogFixture(t)
	auditMakeKey(t, tdb, kek, user.UserID, false, false)
	auditMakeKey(t, tdb, kek, user.UserID, false, false)
	auditMakeKey(t, tdb, kek, user.UserID, false, false)

	m := NewModelWithRenderer(tdb.DB, kek, nil, user, nil, false, lipgloss.DefaultRenderer())
	m.screen = screenAuditLog
	m.auditLog = newAuditLogModel(tdb.DB, user)

	if m.auditLog.cursor != 0 {
		t.Fatalf("starting cursor = %d, want 0", m.auditLog.cursor)
	}
	// Up at top stays at 0.
	m1, _ := m.Update(key("up"))
	if got := m1.(Model).auditLog.cursor; got != 0 {
		t.Errorf("up at cursor 0 = %d, want 0", got)
	}
	// Walk down past the end; cursor caps at last index.
	curr := m1.(Model)
	for i := 0; i < 50; i++ {
		next, _ := curr.Update(key("down"))
		curr = next.(Model)
	}
	if want := len(curr.auditLog.entries) - 1; curr.auditLog.cursor != want {
		t.Errorf("cursor after many downs = %d, want %d", curr.auditLog.cursor, want)
	}
}

func TestAuditLog_EscReturnsToWelcome(t *testing.T) {
	tdb, kek, user := setupAuditLogFixture(t)
	m := NewModelWithRenderer(tdb.DB, kek, nil, user, nil, false, lipgloss.DefaultRenderer())
	m.screen = screenAuditLog
	m.auditLog = newAuditLogModel(tdb.DB, user)

	next, _ := m.Update(key("esc"))
	if got := next.(Model).screen; got != screenWelcome {
		t.Errorf("screen after esc = %v, want welcome", got)
	}
}
