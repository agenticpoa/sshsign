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

func TestApprovalTokenHashAndVerify(t *testing.T) {
	raw := "8a3f0b6f2cd14a..fakeRawToken"

	stored := crypto.HashApprovalToken(raw)
	if stored == raw {
		t.Fatal("HashApprovalToken returned raw token; must hash")
	}
	if stored == "" {
		t.Fatal("HashApprovalToken returned empty for non-empty input")
	}

	if !crypto.VerifyApprovalToken(stored, raw) {
		t.Error("VerifyApprovalToken rejected correct token against stored hash")
	}
	if crypto.VerifyApprovalToken(stored, raw+"x") {
		t.Error("VerifyApprovalToken accepted wrong token")
	}
	if crypto.VerifyApprovalToken(stored, "") {
		t.Error("VerifyApprovalToken accepted empty presented token")
	}
	if crypto.VerifyApprovalToken("", raw) {
		t.Error("VerifyApprovalToken accepted empty stored verifier")
	}
}

func TestApprovalTokenLegacyRawAccepted(t *testing.T) {
	// Rows created before the hashing migration store the raw token
	// directly. VerifyApprovalToken must still accept them so in-flight
	// pendings are not bricked.
	raw := "legacyRawToken"
	if !crypto.VerifyApprovalToken(raw, raw) {
		t.Error("VerifyApprovalToken rejected legacy raw match")
	}
	if crypto.VerifyApprovalToken(raw, "different") {
		t.Error("VerifyApprovalToken accepted legacy raw mismatch")
	}
}

func TestHashApprovalTokenEmpty(t *testing.T) {
	if got := crypto.HashApprovalToken(""); got != "" {
		t.Errorf("HashApprovalToken(\"\") = %q, want empty", got)
	}
}

func TestKEKRing_WrapTagsCurrentAlgo(t *testing.T) {
	ring, err := crypto.NewKEKRingForTests("test-secret")
	if err != nil {
		t.Fatalf("building ring: %v", err)
	}
	dek, _ := crypto.GenerateDEK()
	defer crypto.ZeroBytes(dek)

	wrapped, algo, err := ring.WrapDEK(dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if algo != crypto.KEKAlgoArgon2id {
		t.Errorf("algo = %q, want %q", algo, crypto.KEKAlgoArgon2id)
	}
	unwrapped, err := ring.UnwrapDEK(wrapped, algo)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if string(unwrapped) != string(dek) {
		t.Error("round-trip mismatch")
	}
}

func TestKEKRing_UnwrapsLegacyRows(t *testing.T) {
	// A pre-migration row was wrapped with the SHA-256-derived KEK and
	// stored with kek_algo = "". A real (Argon2id) ring must still be
	// able to decrypt it via the legacy key in the ring.
	legacyKEK, err := crypto.DeriveKEK("test-secret-thats-32-chars-long!!")
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	dek, _ := crypto.GenerateDEK()
	legacyWrapped, err := crypto.WrapDEK(dek, legacyKEK)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	ring, err := crypto.NewKEKRing("test-secret-thats-32-chars-long!!", salt)
	if err != nil {
		t.Fatalf("NewKEKRing: %v", err)
	}

	got, err := ring.UnwrapDEK(legacyWrapped, crypto.KEKAlgoLegacy)
	if err != nil {
		t.Fatalf("UnwrapDEK legacy row: %v", err)
	}
	if string(got) != string(dek) {
		t.Error("legacy DEK did not round-trip through ring")
	}
}

func TestKEKRing_RejectsUnknownAlgo(t *testing.T) {
	ring, _ := crypto.NewKEKRingForTests("test-secret")
	if _, err := ring.UnwrapDEK([]byte("anything"), "not-an-algo"); err == nil {
		t.Error("expected error for unknown KEK algo")
	}
}

func TestDeriveKEKArgon2id_RejectsShortSalt(t *testing.T) {
	if _, err := crypto.DeriveKEKArgon2id("secret", []byte("tooshort")); err == nil {
		t.Error("expected error for short salt")
	}
}

func TestKEKRing_CloseRendersUnwrapInert(t *testing.T) {
	// After Close, the ring's keys are all zeros. Encrypting a DEK
	// with the now-zeroed current key and then trying to decrypt with
	// the still-live key from a sibling ring should fail — proving
	// the slot in memory really was wiped.
	ring, err := crypto.NewKEKRingForTests("test-secret")
	if err != nil {
		t.Fatalf("building ring: %v", err)
	}
	dek, _ := crypto.GenerateDEK()
	wrapped, _, err := ring.WrapDEK(dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	// Sibling ring (same secret) — unwraps fine before Close.
	sibling, _ := crypto.NewKEKRingForTests("test-secret")
	if _, err := sibling.UnwrapDEK(wrapped, crypto.KEKAlgoArgon2id); err != nil {
		t.Fatalf("sanity unwrap before close: %v", err)
	}

	ring.Close()
	// After Close, the same ring can no longer wrap usefully — the
	// resulting ciphertext would decrypt with a zeroed key, which the
	// sibling ring doesn't share.
	wrappedAfterClose, _, err := ring.WrapDEK(dek)
	if err != nil {
		// AES with a zero key technically still produces ciphertext;
		// the wrap call doesn't fail. What we care about is that the
		// sibling — which holds the real key — can't decrypt it.
		t.Logf("WrapDEK after Close: %v (acceptable)", err)
	} else if _, err := sibling.UnwrapDEK(wrappedAfterClose, crypto.KEKAlgoArgon2id); err == nil {
		t.Error("sibling unwrapped post-Close ciphertext; ring keys not actually zeroed")
	}
}

func TestPendingMAC_RoundTrip(t *testing.T) {
	ring, err := crypto.NewKEKRingForTests("test-secret")
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	b := crypto.PendingBinding{
		SigningKeyID: "ak_1", AuthTokenID: "at_1", RequesterID: "u_1",
		DocType: "safe-agreement", PayloadHash: "sha256:abc",
		Metadata: `{"valuation_cap":10000000}`,
	}
	mac := ring.ComputePendingMAC(b)
	if !ring.VerifyPendingMAC(b, mac) {
		t.Error("round-trip verify failed")
	}
}

func TestPendingMAC_DetectsFieldTamper(t *testing.T) {
	ring, _ := crypto.NewKEKRingForTests("test-secret")
	orig := crypto.PendingBinding{
		SigningKeyID: "ak_1", AuthTokenID: "at_1", RequesterID: "u_1",
		DocType: "safe-agreement", PayloadHash: "sha256:abc",
		Metadata: `{"valuation_cap":10000000}`,
	}
	mac := ring.ComputePendingMAC(orig)

	cases := []struct {
		name   string
		mutate func(*crypto.PendingBinding)
	}{
		{"payload_hash swapped", func(b *crypto.PendingBinding) { b.PayloadHash = "sha256:xyz" }},
		{"metadata swapped", func(b *crypto.PendingBinding) { b.Metadata = `{"valuation_cap":100000000}` }},
		{"signing_key swapped", func(b *crypto.PendingBinding) { b.SigningKeyID = "ak_evil" }},
		{"auth_token swapped", func(b *crypto.PendingBinding) { b.AuthTokenID = "at_evil" }},
		{"requester swapped", func(b *crypto.PendingBinding) { b.RequesterID = "u_evil" }},
		{"doc_type swapped", func(b *crypto.PendingBinding) { b.DocType = "loan-agreement" }},
	}
	for _, tc := range cases {
		tampered := orig
		tc.mutate(&tampered)
		if ring.VerifyPendingMAC(tampered, mac) {
			t.Errorf("%s: verify succeeded against tampered binding", tc.name)
		}
	}
}

func TestPendingMAC_RejectsEmpty(t *testing.T) {
	ring, _ := crypto.NewKEKRingForTests("test-secret")
	b := crypto.PendingBinding{SigningKeyID: "ak_1", PayloadHash: "sha256:abc"}
	if ring.VerifyPendingMAC(b, nil) {
		t.Error("verify accepted nil MAC")
	}
	if ring.VerifyPendingMAC(b, []byte{}) {
		t.Error("verify accepted empty MAC")
	}
}

func TestPendingMAC_LengthPrefixingPreventsConcatenationCollision(t *testing.T) {
	// {"foo", "barbaz"} must not collide with {"foobar", "baz"}. Without
	// length-prefixing, naive concatenation would produce the same input
	// to HMAC for both.
	ring, _ := crypto.NewKEKRingForTests("test-secret")
	a := ring.ComputePendingMAC(crypto.PendingBinding{
		SigningKeyID: "foo", AuthTokenID: "barbaz",
	})
	b := ring.ComputePendingMAC(crypto.PendingBinding{
		SigningKeyID: "foobar", AuthTokenID: "baz",
	})
	if string(a) == string(b) {
		t.Error("MAC collision across field boundaries — canonical encoding broken")
	}
}

func TestPendingMAC_StableAcrossRingsWithSameSecret(t *testing.T) {
	// Two rings derived from the same secret+salt must produce the same
	// MAC — otherwise restarts would invalidate every in-flight pending.
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	r1, _ := crypto.NewKEKRing("test-secret-thats-32-chars-long!!", salt)
	r2, _ := crypto.NewKEKRing("test-secret-thats-32-chars-long!!", salt)
	b := crypto.PendingBinding{
		SigningKeyID: "ak_1", PayloadHash: "sha256:abc",
	}
	if string(r1.ComputePendingMAC(b)) != string(r2.ComputePendingMAC(b)) {
		t.Error("MAC differs across rings with identical secret+salt")
	}
}

