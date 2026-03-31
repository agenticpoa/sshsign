package signing_test

import (
	"strings"
	"testing"

	"github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/signing"
)

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	pubSSH, err := crypto.MarshalPublicKeySSH(pub)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	payload := []byte("hello world")
	sig, err := signing.Sign(priv, payload, "git")
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	if err := signing.Verify(sig, payload, pubSSH, "git"); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestVerifyWithWrongKey(t *testing.T) {
	_, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	// Sign with key A
	payload := []byte("hello world")
	sig, err := signing.Sign(priv, payload, "git")
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Verify with key B
	pub2, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("generating second keypair: %v", err)
	}
	pubSSH2, err := crypto.MarshalPublicKeySSH(pub2)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	if err := signing.Verify(sig, payload, pubSSH2, "git"); err == nil {
		t.Error("expected verification to fail with wrong key")
	}
}

func TestVerifyCorruptedSignature(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	pubSSH, err := crypto.MarshalPublicKeySSH(pub)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	payload := []byte("hello world")
	sig, err := signing.Sign(priv, payload, "git")
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Corrupt the signature by modifying a byte in the base64 body
	corrupted := make([]byte, len(sig))
	copy(corrupted, sig)
	// Find a position in the middle of the base64 content and flip it
	mid := len(corrupted) / 2
	corrupted[mid] ^= 0xff

	if err := signing.Verify(corrupted, payload, pubSSH, "git"); err == nil {
		t.Error("expected verification to fail with corrupted signature")
	}
}

func TestSignatureFormat(t *testing.T) {
	_, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	sig, err := signing.Sign(priv, []byte("test"), "git")
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	sigStr := string(sig)
	if !strings.Contains(sigStr, "-----BEGIN SSH SIGNATURE-----") {
		t.Error("signature should contain BEGIN SSH SIGNATURE header")
	}
	if !strings.Contains(sigStr, "-----END SSH SIGNATURE-----") {
		t.Error("signature should contain END SSH SIGNATURE footer")
	}
}

func TestGitNamespaceCrossProtection(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	pubSSH, err := crypto.MarshalPublicKeySSH(pub)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	payload := []byte("test data")

	// Sign with "git" namespace
	sig, err := signing.Sign(priv, payload, "git")
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Verify with "git" namespace should succeed
	if err := signing.Verify(sig, payload, pubSSH, "git"); err != nil {
		t.Fatalf("same-namespace verification failed: %v", err)
	}

	// Verify with "file" namespace should fail
	if err := signing.Verify(sig, payload, pubSSH, "file"); err == nil {
		t.Error("cross-namespace verification should fail")
	}
}
