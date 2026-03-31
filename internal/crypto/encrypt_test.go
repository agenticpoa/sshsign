package crypto_test

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/agenticpoa/sshsign/internal/crypto"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	_, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("generating DEK: %v", err)
	}

	encrypted, err := crypto.EncryptPrivateKey(priv, dek)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	decrypted, err := crypto.DecryptPrivateKey(encrypted, dek)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}

	if !bytes.Equal(priv, decrypted) {
		t.Error("decrypted key does not match original")
	}
}

func TestDEKWrapUnwrapRoundTrip(t *testing.T) {
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("generating DEK: %v", err)
	}

	kek, err := crypto.DeriveKEK("test-secret")
	if err != nil {
		t.Fatalf("deriving KEK: %v", err)
	}

	wrapped, err := crypto.WrapDEK(dek, kek)
	if err != nil {
		t.Fatalf("wrapping DEK: %v", err)
	}

	unwrapped, err := crypto.UnwrapDEK(wrapped, kek)
	if err != nil {
		t.Fatalf("unwrapping DEK: %v", err)
	}

	if !bytes.Equal(dek, unwrapped) {
		t.Error("unwrapped DEK does not match original")
	}
}

func TestFullEnvelopeRoundTrip(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	// Encrypt the private key
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("generating DEK: %v", err)
	}

	encPrivKey, err := crypto.EncryptPrivateKey(priv, dek)
	if err != nil {
		t.Fatalf("encrypting private key: %v", err)
	}

	kek, err := crypto.DeriveKEK("test-secret")
	if err != nil {
		t.Fatalf("deriving KEK: %v", err)
	}

	wrappedDEK, err := crypto.WrapDEK(dek, kek)
	if err != nil {
		t.Fatalf("wrapping DEK: %v", err)
	}

	// Zero the originals to prove we can recover from storage
	crypto.ZeroBytes(dek)
	crypto.ZeroBytes(priv)

	// Recover: unwrap DEK, decrypt private key, sign, verify
	recoveredDEK, err := crypto.UnwrapDEK(wrappedDEK, kek)
	if err != nil {
		t.Fatalf("unwrapping DEK: %v", err)
	}

	recoveredPriv, err := crypto.DecryptPrivateKey(encPrivKey, recoveredDEK)
	if err != nil {
		t.Fatalf("decrypting private key: %v", err)
	}

	message := []byte("test message")
	sig := ed25519.Sign(recoveredPriv, message)
	if !ed25519.Verify(pub, message, sig) {
		t.Error("signature verification failed with recovered key")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	_, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("generating DEK: %v", err)
	}

	encrypted, err := crypto.EncryptPrivateKey(priv, dek)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	wrongDEK, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("generating wrong DEK: %v", err)
	}

	_, err = crypto.DecryptPrivateKey(encrypted, wrongDEK)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}

func TestDecryptCorruptedData(t *testing.T) {
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("generating DEK: %v", err)
	}

	// Too short
	_, err = crypto.DecryptPrivateKey([]byte("short"), dek)
	if err == nil {
		t.Error("expected error for too-short data")
	}

	// Corrupted ciphertext
	_, priv, _ := crypto.GenerateEd25519Keypair()
	encrypted, _ := crypto.EncryptPrivateKey(priv, dek)
	encrypted[len(encrypted)-1] ^= 0xff // flip last byte
	_, err = crypto.DecryptPrivateKey(encrypted, dek)
	if err == nil {
		t.Error("expected error for corrupted ciphertext")
	}
}

func TestZeroBytes(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	crypto.ZeroBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte %d = %d, want 0", i, b)
		}
	}
}

func TestDeriveKEK_EmptySecret(t *testing.T) {
	_, err := crypto.DeriveKEK("")
	if err == nil {
		t.Error("expected error for empty secret")
	}
}
