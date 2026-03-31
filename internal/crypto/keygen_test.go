package crypto_test

import (
	"strings"
	"testing"

	"github.com/agenticpoa/sshsign/internal/crypto"
)

func TestGenerateEd25519Keypair(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(pub) != 32 {
		t.Errorf("public key length = %d, want 32", len(pub))
	}
	if len(priv) != 64 {
		t.Errorf("private key length = %d, want 64", len(priv))
	}
}

func TestGenerateEd25519Keypair_Unique(t *testing.T) {
	pub1, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pub2, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(pub1) == string(pub2) {
		t.Error("two generated keys should be different")
	}
}

func TestMarshalPublicKeySSH(t *testing.T) {
	pub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sshKey, err := crypto.MarshalPublicKeySSH(pub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(sshKey, "ssh-ed25519 ") {
		t.Errorf("SSH key should start with 'ssh-ed25519 ', got: %s", sshKey[:20])
	}
}

func TestFingerprintSHA256(t *testing.T) {
	pub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fp, err := crypto.FingerprintSHA256(pub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("fingerprint should start with 'SHA256:', got: %s", fp)
	}
}
