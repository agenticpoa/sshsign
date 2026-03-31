package storage_test

import (
	"testing"

	"github.com/agenticpoa/sshsign/internal/storage"
)

func TestCreateAndGetSigningKey(t *testing.T) {
	tdb := testDB(t)

	user, _, err := storage.CreateUser(tdb.DB, "SHA256:owner", "ssh-ed25519 AAAAowner")
	if err != nil {
		t.Fatalf("creating user: %v", err)
	}

	encPrivKey := []byte("encrypted-private-key-data")
	encDEK := []byte("encrypted-dek-data")

	sk, err := storage.CreateSigningKey(tdb.DB, user.UserID, "ssh-ed25519 AAAAsigning", encPrivKey, encDEK)
	if err != nil {
		t.Fatalf("creating signing key: %v", err)
	}

	if sk.KeyID == "" {
		t.Error("key ID should not be empty")
	}
	if sk.OwnerID != user.UserID {
		t.Errorf("owner ID = %q, want %q", sk.OwnerID, user.UserID)
	}
	if sk.PublicKey != "ssh-ed25519 AAAAsigning" {
		t.Errorf("public key = %q, want 'ssh-ed25519 AAAAsigning'", sk.PublicKey)
	}

	// Retrieve by ID
	found, err := storage.GetSigningKey(tdb.DB, sk.KeyID)
	if err != nil {
		t.Fatalf("getting signing key: %v", err)
	}
	if found.KeyID != sk.KeyID {
		t.Errorf("found key ID = %q, want %q", found.KeyID, sk.KeyID)
	}
	if string(found.PrivateKeyEncrypted) != string(encPrivKey) {
		t.Error("encrypted private key data does not match")
	}
	if string(found.DEKEncrypted) != string(encDEK) {
		t.Error("encrypted DEK data does not match")
	}
}

func TestListSigningKeys(t *testing.T) {
	tdb := testDB(t)

	user, _, err := storage.CreateUser(tdb.DB, "SHA256:lister", "ssh-ed25519 AAAAlister")
	if err != nil {
		t.Fatalf("creating user: %v", err)
	}

	_, err = storage.CreateSigningKey(tdb.DB, user.UserID, "ssh-ed25519 AAAA1", []byte("enc1"), []byte("dek1"))
	if err != nil {
		t.Fatalf("creating first key: %v", err)
	}

	_, err = storage.CreateSigningKey(tdb.DB, user.UserID, "ssh-ed25519 AAAA2", []byte("enc2"), []byte("dek2"))
	if err != nil {
		t.Fatalf("creating second key: %v", err)
	}

	keys, err := storage.ListSigningKeys(tdb.DB, user.UserID)
	if err != nil {
		t.Fatalf("listing keys: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 signing keys, got %d", len(keys))
	}
}

func TestGetNonexistentSigningKey(t *testing.T) {
	tdb := testDB(t)

	sk, err := storage.GetSigningKey(tdb.DB, "ak_nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sk != nil {
		t.Error("expected nil for nonexistent signing key")
	}
}

func TestRevokeSigningKey(t *testing.T) {
	tdb := testDB(t)

	user, _, err := storage.CreateUser(tdb.DB, "SHA256:revoker", "ssh-ed25519 AAAArevoker")
	if err != nil {
		t.Fatalf("creating user: %v", err)
	}

	sk, err := storage.CreateSigningKey(tdb.DB, user.UserID, "ssh-ed25519 AAAArevoke", []byte("enc"), []byte("dek"))
	if err != nil {
		t.Fatalf("creating signing key: %v", err)
	}

	if err := storage.RevokeSigningKey(tdb.DB, sk.KeyID); err != nil {
		t.Fatalf("revoking key: %v", err)
	}

	found, err := storage.GetSigningKey(tdb.DB, sk.KeyID)
	if err != nil {
		t.Fatalf("getting revoked key: %v", err)
	}
	if found.RevokedAt == nil {
		t.Error("revoked_at should not be nil after revocation")
	}

	// Revoking again should fail
	if err := storage.RevokeSigningKey(tdb.DB, sk.KeyID); err == nil {
		t.Error("expected error when revoking already-revoked key")
	}
}
