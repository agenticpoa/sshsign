package storage_test

import (
	"testing"

	"github.com/agenticpoa/sshsign/internal/storage"
)

func TestCreateUserAndFind(t *testing.T) {
	tdb := testDB(t)

	user, key, err := storage.CreateUser(tdb.DB, "SHA256:abc123", "ssh-ed25519 AAAAC3test")
	if err != nil {
		t.Fatalf("creating user: %v", err)
	}

	if user.UserID == "" {
		t.Error("user ID should not be empty")
	}
	if user.Status != "active" {
		t.Errorf("status = %q, want 'active'", user.Status)
	}
	if key.SSHFingerprint != "SHA256:abc123" {
		t.Errorf("fingerprint = %q, want 'SHA256:abc123'", key.SSHFingerprint)
	}

	// Find by fingerprint
	foundUser, foundKey, err := storage.FindUserByFingerprint(tdb.DB, "SHA256:abc123")
	if err != nil {
		t.Fatalf("finding user: %v", err)
	}
	if foundUser.UserID != user.UserID {
		t.Errorf("found user ID = %q, want %q", foundUser.UserID, user.UserID)
	}
	if foundKey.PublicKey != "ssh-ed25519 AAAAC3test" {
		t.Errorf("found public key = %q, want 'ssh-ed25519 AAAAC3test'", foundKey.PublicKey)
	}
}

func TestFindNonexistentUser(t *testing.T) {
	tdb := testDB(t)

	user, key, err := storage.FindUserByFingerprint(tdb.DB, "SHA256:nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil || key != nil {
		t.Error("expected nil results for nonexistent user")
	}
}

func TestLinkKeyToExistingUser(t *testing.T) {
	tdb := testDB(t)

	user, _, err := storage.CreateUser(tdb.DB, "SHA256:first", "ssh-ed25519 AAAAfirst")
	if err != nil {
		t.Fatalf("creating user: %v", err)
	}

	_, err = storage.LinkKey(tdb.DB, user.UserID, "SHA256:second", "ssh-ed25519 AAAAsecond", "work laptop")
	if err != nil {
		t.Fatalf("linking key: %v", err)
	}

	// Find by second key should return same user
	foundUser, foundKey, err := storage.FindUserByFingerprint(tdb.DB, "SHA256:second")
	if err != nil {
		t.Fatalf("finding user by second key: %v", err)
	}
	if foundUser.UserID != user.UserID {
		t.Errorf("user ID = %q, want %q (same user)", foundUser.UserID, user.UserID)
	}
	if foundKey.Label != "work laptop" {
		t.Errorf("label = %q, want 'work laptop'", foundKey.Label)
	}
}

func TestLinkDuplicateFingerprint(t *testing.T) {
	tdb := testDB(t)

	user, _, err := storage.CreateUser(tdb.DB, "SHA256:dup", "ssh-ed25519 AAAAdup")
	if err != nil {
		t.Fatalf("creating user: %v", err)
	}

	// Linking same fingerprint again should fail
	_, err = storage.LinkKey(tdb.DB, user.UserID, "SHA256:dup", "ssh-ed25519 AAAAdup", "duplicate")
	if err == nil {
		t.Error("expected error when linking duplicate fingerprint")
	}
}

func TestListUserKeys(t *testing.T) {
	tdb := testDB(t)

	user, _, err := storage.CreateUser(tdb.DB, "SHA256:k1", "ssh-ed25519 AAAAk1")
	if err != nil {
		t.Fatalf("creating user: %v", err)
	}

	_, err = storage.LinkKey(tdb.DB, user.UserID, "SHA256:k2", "ssh-ed25519 AAAAk2", "second key")
	if err != nil {
		t.Fatalf("linking key: %v", err)
	}

	keys, err := storage.ListUserKeys(tdb.DB, user.UserID)
	if err != nil {
		t.Fatalf("listing keys: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}
