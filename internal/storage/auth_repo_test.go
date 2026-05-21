package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/agenticpoa/sshsign/internal/storage"
)

func setupUserAndKey(t *testing.T, tdb *storage.TestDB) (*storage.User, *storage.SigningKey) {
	t.Helper()
	user, _, err := storage.CreateUser(context.Background(), tdb.DB, "SHA256:authtest", "ssh-ed25519 AAAAauthtest")
	if err != nil {
		t.Fatalf("creating user: %v", err)
	}
	sk, err := storage.CreateSigningKey(context.Background(), tdb.DB, user.UserID, "ssh-ed25519 AAAAsig", []byte("enc"), []byte("dek"), "")
	if err != nil {
		t.Fatalf("creating signing key: %v", err)
	}
	return user, sk
}

func TestCreateAndGetAuthorization(t *testing.T) {
	tdb := testDB(t)
	user, sk := setupUserAndKey(t, tdb)

	expires := time.Now().Add(30 * 24 * time.Hour)
	auth, err := storage.CreateAuthorization(
		context.Background(),
		tdb.DB, sk.KeyID, user.UserID,
		[]string{"git-commit"},
		map[string][]string{"repo": {"github.com/user/*"}},
		[]string{"never sign to main branch"},
		[]string{"alert if >10 sigs/hour"},
		&expires,
	)
	if err != nil {
		t.Fatalf("creating authorization: %v", err)
	}

	if auth.TokenID == "" {
		t.Error("token ID should not be empty")
	}
	if auth.SigningKeyID != sk.KeyID {
		t.Errorf("signing key ID = %q, want %q", auth.SigningKeyID, sk.KeyID)
	}
	if len(auth.Scopes) != 1 || auth.Scopes[0] != "git-commit" {
		t.Errorf("scopes = %v, want [git-commit]", auth.Scopes)
	}
	if len(auth.Constraints["repo"]) != 1 {
		t.Errorf("constraints repo = %v, want 1 pattern", auth.Constraints["repo"])
	}
	if len(auth.HardRules) != 1 {
		t.Errorf("hard rules = %v, want 1 rule", auth.HardRules)
	}
	if auth.ExpiresAt == nil {
		t.Error("expires_at should not be nil")
	}

	// Get by ID
	found, err := storage.GetAuthorization(context.Background(), tdb.DB, auth.TokenID)
	if err != nil {
		t.Fatalf("getting authorization: %v", err)
	}
	if found.TokenID != auth.TokenID {
		t.Errorf("found token ID = %q, want %q", found.TokenID, auth.TokenID)
	}
}

func TestFindAuthorizationsForKey(t *testing.T) {
	tdb := testDB(t)
	user, sk := setupUserAndKey(t, tdb)

	_, err := storage.CreateAuthorization(context.Background(), tdb.DB, sk.KeyID, user.UserID,
		[]string{"git-commit"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("creating first auth: %v", err)
	}

	_, err = storage.CreateAuthorization(context.Background(), tdb.DB, sk.KeyID, user.UserID,
		[]string{"api-request"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("creating second auth: %v", err)
	}

	auths, err := storage.FindAuthorizationsForKey(context.Background(), tdb.DB, sk.KeyID)
	if err != nil {
		t.Fatalf("finding authorizations: %v", err)
	}
	if len(auths) != 2 {
		t.Errorf("expected 2 authorizations, got %d", len(auths))
	}
}

func TestFindAuthorizationsForKey_ExcludesExpired(t *testing.T) {
	tdb := testDB(t)
	user, sk := setupUserAndKey(t, tdb)

	// Active (no expiry)
	_, err := storage.CreateAuthorization(context.Background(), tdb.DB, sk.KeyID, user.UserID,
		[]string{"alpha"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("creating active auth: %v", err)
	}

	// Active (future expiry)
	future := time.Now().Add(24 * time.Hour)
	_, err = storage.CreateAuthorization(context.Background(), tdb.DB, sk.KeyID, user.UserID,
		[]string{"beta"}, nil, nil, nil, &future)
	if err != nil {
		t.Fatalf("creating future-expiry auth: %v", err)
	}

	// Expired
	past := time.Now().Add(-1 * time.Hour)
	_, err = storage.CreateAuthorization(context.Background(), tdb.DB, sk.KeyID, user.UserID,
		[]string{"gamma"}, nil, nil, nil, &past)
	if err != nil {
		t.Fatalf("creating expired auth: %v", err)
	}

	auths, err := storage.FindAuthorizationsForKey(context.Background(), tdb.DB, sk.KeyID)
	if err != nil {
		t.Fatalf("finding authorizations: %v", err)
	}
	if len(auths) != 2 {
		t.Fatalf("expected 2 active authorizations, got %d", len(auths))
	}
	for _, a := range auths {
		for _, s := range a.Scopes {
			if s == "gamma" {
				t.Error("expired authorization was returned")
			}
		}
	}
}

func TestRevokeAuthorization(t *testing.T) {
	tdb := testDB(t)
	user, sk := setupUserAndKey(t, tdb)

	auth, err := storage.CreateAuthorization(context.Background(), tdb.DB, sk.KeyID, user.UserID,
		[]string{"git-commit"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("creating auth: %v", err)
	}

	if err := storage.RevokeAuthorization(context.Background(), tdb.DB, auth.TokenID); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	// Should not appear in active authorizations
	auths, err := storage.FindAuthorizationsForKey(context.Background(), tdb.DB, sk.KeyID)
	if err != nil {
		t.Fatalf("finding authorizations: %v", err)
	}
	if len(auths) != 0 {
		t.Errorf("expected 0 active authorizations after revocation, got %d", len(auths))
	}

	// But should still be gettable by ID (with revoked_at set)
	found, err := storage.GetAuthorization(context.Background(), tdb.DB, auth.TokenID)
	if err != nil {
		t.Fatalf("getting revoked auth: %v", err)
	}
	if found.RevokedAt == nil {
		t.Error("revoked_at should not be nil")
	}
}
