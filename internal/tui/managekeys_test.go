package tui

import (
	"context"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"

	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/storage"
)

// manageKeysFixture stands up the minimum schema needed to drive the
// manage-keys flow: a user with several signing keys (active and
// revoked) and at least one authorization on the first key. The keys
// are sortable by created_at so order assertions are stable.
type manageKeysFixture struct {
	t          *testing.T
	tdb        *storage.TestDB
	kek        *apoacrypto.KEKRing
	user       *storage.User
	activeKey  string
	revokedKey string
	authID     string
}

func setupManageKeysFixture(t *testing.T) *manageKeysFixture {
	t.Helper()
	ctx := context.Background()

	tdb, err := storage.NewTestDB()
	if err != nil {
		t.Fatalf("test DB: %v", err)
	}
	t.Cleanup(func() { tdb.Close() })

	kek, err := apoacrypto.NewKEKRingForTests("mk-test-secret")
	if err != nil {
		t.Fatalf("KEK ring: %v", err)
	}

	user, _, err := storage.CreateUser(ctx, tdb.DB, "SHA256:mktest", "ssh-ed25519 AAAAmktest")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Two keys: one currently active, one revoked. Stable wrapping so
	// the rows look like production. Revoked one created first to
	// confirm the sort puts active-first regardless of created_at.
	mkKey := func(label string, revoked bool) string {
		pub, priv, _ := apoacrypto.GenerateEd25519Keypair()
		pubSSH, _ := apoacrypto.MarshalPublicKeySSH(pub)
		dek, _ := apoacrypto.GenerateDEK()
		encPriv, _ := apoacrypto.EncryptPrivateKey(priv, dek)
		wrapped, algo, _ := kek.WrapDEK(dek)
		sk, err := storage.CreateSigningKey(ctx, tdb.DB, user.UserID, pubSSH, encPriv, wrapped, algo)
		if err != nil {
			t.Fatalf("create %s key: %v", label, err)
		}
		if revoked {
			if err := storage.RevokeSigningKey(ctx, tdb.DB, sk.KeyID); err != nil {
				t.Fatalf("revoke %s key: %v", label, err)
			}
		}
		return sk.KeyID
	}

	// Insert revoked first; the active-first sort puts the live key
	// at index 0 regardless of created_at, which is what the tests
	// below assume.
	revoked := mkKey("revoked", true)
	active := mkKey("active", false)

	expires := time.Now().AddDate(0, 0, 30)
	auth, err := storage.CreateAuthorization(ctx, tdb.DB, active, user.UserID,
		[]string{"safe-agreement"}, nil, nil, nil, &expires)
	if err != nil {
		t.Fatalf("create auth: %v", err)
	}

	return &manageKeysFixture{
		t: t, tdb: tdb, kek: kek, user: user,
		activeKey: active, revokedKey: revoked, authID: auth.TokenID,
	}
}

func (f *manageKeysFixture) model() Model {
	m := NewModelWithRenderer(f.tdb.DB, f.kek, nil, f.user, nil, false, lipgloss.DefaultRenderer())
	m.screen = screenManageKeys
	m.manageKeys = newManageKeysModel(f.tdb.DB, f.user)
	return m
}

func TestManageKeys_SortsActiveBeforeRevoked(t *testing.T) {
	f := setupManageKeysFixture(t)
	m := f.model()

	if len(m.manageKeys.keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(m.manageKeys.keys))
	}
	if m.manageKeys.keys[0].KeyID != f.activeKey {
		t.Errorf("first key = %q, want active key %q", m.manageKeys.keys[0].KeyID, f.activeKey)
	}
	if m.manageKeys.keys[1].KeyID != f.revokedKey {
		t.Errorf("second key = %q, want revoked key %q", m.manageKeys.keys[1].KeyID, f.revokedKey)
	}
}

func TestManageKeys_EnterShowsDetailWithAuths(t *testing.T) {
	f := setupManageKeysFixture(t)
	m := f.model()

	// Cursor is at index 0 (active key) by construction.
	next, _ := m.Update(key("enter"))
	mm := next.(Model)
	if mm.manageKeys.view != viewKeyDetail {
		t.Errorf("view = %v, want detail", mm.manageKeys.view)
	}
	if len(mm.manageKeys.auths) != 1 {
		t.Fatalf("expected 1 auth on detail load, got %d", len(mm.manageKeys.auths))
	}
	if mm.manageKeys.auths[0].TokenID != f.authID {
		t.Errorf("loaded auth %q, want %q", mm.manageKeys.auths[0].TokenID, f.authID)
	}
}

func TestManageKeys_RevokeKeyHappyPath(t *testing.T) {
	f := setupManageKeysFixture(t)
	m := f.model()

	// Press 'r' on active key, then 'y' to confirm.
	m1, _ := m.Update(key("r"))
	if !m1.(Model).manageKeys.confirmRevoke {
		t.Fatal("'r' did not enter confirm-revoke state")
	}
	m2, _ := m1.(Model).Update(key("y"))
	mm := m2.(Model)
	if mm.manageKeys.confirmRevoke {
		t.Error("confirmRevoke still set after 'y'")
	}
	if mm.manageKeys.isError {
		t.Errorf("revoke flagged error: %s", mm.manageKeys.status)
	}

	sk, err := storage.GetSigningKey(context.Background(), f.tdb.DB, f.activeKey)
	if err != nil {
		t.Fatalf("getting key: %v", err)
	}
	if sk.RevokedAt == nil {
		t.Error("key not revoked in DB after 'y' confirm")
	}
}

func TestManageKeys_RevokeCancel(t *testing.T) {
	f := setupManageKeysFixture(t)
	m := f.model()

	m1, _ := m.Update(key("r"))
	m2, _ := m1.(Model).Update(key("n"))
	mm := m2.(Model)
	if mm.manageKeys.confirmRevoke {
		t.Error("confirmRevoke still set after 'n'")
	}

	// Key must still be active.
	sk, _ := storage.GetSigningKey(context.Background(), f.tdb.DB, f.activeKey)
	if sk.RevokedAt != nil {
		t.Error("key was revoked despite 'n' cancel")
	}
}

func TestManageKeys_RevokingAlreadyRevokedKeyIsError(t *testing.T) {
	f := setupManageKeysFixture(t)
	m := f.model()

	// Move cursor down to the revoked key (index 1).
	m1, _ := m.Update(key("down"))
	m2, _ := m1.(Model).Update(key("r"))
	mm := m2.(Model)

	if mm.manageKeys.confirmRevoke {
		t.Error("'r' on revoked key should not enter confirm state")
	}
	if !mm.manageKeys.isError {
		t.Error("'r' on revoked key should flag error")
	}
}

func TestManageKeys_DetailRevokeAuth(t *testing.T) {
	f := setupManageKeysFixture(t)
	m := f.model()

	// enter detail → press 'r' to start auth revoke → 'y' to confirm
	m1, _ := m.Update(key("enter"))
	m2, _ := m1.(Model).Update(key("r"))
	if !m2.(Model).manageKeys.confirmRevoke {
		t.Fatal("'r' in detail did not enter confirm-revoke state")
	}
	m3, _ := m2.(Model).Update(key("y"))
	mm := m3.(Model)
	if mm.manageKeys.isError {
		t.Errorf("revoke failed: %s", mm.manageKeys.status)
	}

	// Auth must be revoked in storage; FindAuthorizationsForKey
	// filters out revoked rows, so the list on the model should be
	// empty after refresh.
	if len(mm.manageKeys.auths) != 0 {
		t.Errorf("auth list len = %d, want 0 after revoke", len(mm.manageKeys.auths))
	}
}

func TestManageKeys_DetailEscapesToListAndRefreshes(t *testing.T) {
	f := setupManageKeysFixture(t)
	m := f.model()

	m1, _ := m.Update(key("enter"))
	m2, _ := m1.(Model).Update(key("esc"))
	mm := m2.(Model)
	if mm.manageKeys.view != viewKeyList {
		t.Errorf("view after esc = %v, want list", mm.manageKeys.view)
	}
}

func TestManageKeys_AddAuthOpensAuthSetup(t *testing.T) {
	f := setupManageKeysFixture(t)
	m := f.model()

	m1, _ := m.Update(key("enter"))
	m2, _ := m1.(Model).Update(key("a"))
	mm := m2.(Model)
	if mm.screen != screenAuthSetup {
		t.Errorf("screen after 'a' = %v, want authSetup", mm.screen)
	}
	if mm.authSetup.selectedKeyID != f.activeKey {
		t.Errorf("authSetup selectedKeyID = %q, want %q", mm.authSetup.selectedKeyID, f.activeKey)
	}
}

func TestManageKeys_EscFromListReturnsToWelcome(t *testing.T) {
	f := setupManageKeysFixture(t)
	m := f.model()

	next, _ := m.Update(key("esc"))
	if next.(Model).screen != screenWelcome {
		t.Errorf("screen after esc from list = %v, want welcome", next.(Model).screen)
	}
}

func TestSortKeysActiveFirst_NoActiveKeys(t *testing.T) {
	// Edge: list of all-revoked keys still sorts (by created_at desc).
	older := time.Now().Add(-2 * time.Hour)
	newer := time.Now().Add(-1 * time.Hour)
	revoked := time.Now()
	keys := []storage.SigningKey{
		{KeyID: "ak_older", RevokedAt: &revoked, CreatedAt: older},
		{KeyID: "ak_newer", RevokedAt: &revoked, CreatedAt: newer},
	}
	sortKeysActiveFirst(keys)
	if keys[0].KeyID != "ak_newer" {
		t.Errorf("expected newer revoked key first, got %q", keys[0].KeyID)
	}
}
