package evidence

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestSealAndOpen(t *testing.T) {
	env := &Envelope{
		Version:        1,
		PendingID:      "pnd_abc123",
		PayloadHash:    "sha256:deadbeef",
		Scope:          "safe-agreement",
		Metadata:       `{"valuation_cap": 14000000}`,
		SignerID:       "u_xyz",
		SignerIP:       "203.0.113.42",
		SignatureImage: base64.StdEncoding.EncodeToString([]byte("fake-png-data")),
		ImageHash:      HashImage([]byte("fake-png-data")),
		CapturedAt:     time.Date(2026, 4, 2, 18, 30, 0, 0, time.UTC),
	}

	sealed, err := Seal(env)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if sealed.Hash == "" {
		t.Fatal("expected non-empty hash")
	}
	if len(sealed.Data) == 0 {
		t.Fatal("expected non-empty data")
	}

	// Verify the hash is correct
	h := sha256.Sum256(sealed.Data)
	expectedHash := hex.EncodeToString(h[:])
	if sealed.Hash != expectedHash {
		t.Fatalf("hash mismatch: sealed.Hash=%s, computed=%s", sealed.Hash, expectedHash)
	}

	// Open with correct hash
	opened, err := Open(sealed.Data, sealed.Hash)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if opened.PendingID != env.PendingID {
		t.Errorf("PendingID: got %s, want %s", opened.PendingID, env.PendingID)
	}
	if opened.PayloadHash != env.PayloadHash {
		t.Errorf("PayloadHash: got %s, want %s", opened.PayloadHash, env.PayloadHash)
	}
	if opened.SignerID != env.SignerID {
		t.Errorf("SignerID: got %s, want %s", opened.SignerID, env.SignerID)
	}
	if opened.SignatureImage != env.SignatureImage {
		t.Errorf("SignatureImage mismatch")
	}
	if opened.ImageHash != env.ImageHash {
		t.Errorf("ImageHash: got %s, want %s", opened.ImageHash, env.ImageHash)
	}
}

func TestOpenRejectsTamperedData(t *testing.T) {
	env := &Envelope{
		Version:        1,
		PendingID:      "pnd_abc123",
		PayloadHash:    "sha256:deadbeef",
		Scope:          "safe-agreement",
		SignerID:       "u_xyz",
		SignerIP:       "127.0.0.1",
		SignatureImage: "dGVzdA==",
		ImageHash:      HashImage([]byte("test")),
		CapturedAt:     time.Now(),
	}

	sealed, err := Seal(env)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Tamper with the data
	tampered := make([]byte, len(sealed.Data))
	copy(tampered, sealed.Data)
	tampered[len(tampered)-5] = '!'

	_, err = Open(tampered, sealed.Hash)
	if err == nil {
		t.Fatal("expected error for tampered data")
	}
}

func TestOpenRejectsWrongHash(t *testing.T) {
	env := &Envelope{
		Version:     1,
		PendingID:   "pnd_abc123",
		PayloadHash: "sha256:deadbeef",
		Scope:       "nda",
		SignerID:    "u_xyz",
		SignerIP:    "127.0.0.1",
		SignatureImage: "dGVzdA==",
		ImageHash:   HashImage([]byte("test")),
		CapturedAt:  time.Now(),
	}

	sealed, err := Seal(env)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	_, err = Open(sealed.Data, "wrong_hash")
	if err == nil {
		t.Fatal("expected error for wrong hash")
	}
}

func TestSealDeterministic(t *testing.T) {
	ts := time.Date(2026, 4, 2, 18, 30, 0, 0, time.UTC)
	env := &Envelope{
		Version:        1,
		PendingID:      "pnd_abc123",
		PayloadHash:    "sha256:deadbeef",
		Scope:          "safe-agreement",
		SignerID:       "u_xyz",
		SignerIP:       "127.0.0.1",
		SignatureImage: "dGVzdA==",
		ImageHash:      "abc123",
		CapturedAt:     ts,
	}

	sealed1, _ := Seal(env)
	sealed2, _ := Seal(env)

	if sealed1.Hash != sealed2.Hash {
		t.Fatalf("Seal is not deterministic: %s != %s", sealed1.Hash, sealed2.Hash)
	}
}

func TestHashImage(t *testing.T) {
	data := []byte("png-image-bytes")
	h := sha256.Sum256(data)
	expected := hex.EncodeToString(h[:])

	got := HashImage(data)
	if got != expected {
		t.Fatalf("HashImage: got %s, want %s", got, expected)
	}
}

func TestCompositePayload(t *testing.T) {
	result := CompositePayload("payload123", "envelope456")
	if result != "payload123|envelope456" {
		t.Fatalf("got %s", result)
	}
}

func TestSealProducesValidJSON(t *testing.T) {
	env := &Envelope{
		Version:        1,
		PendingID:      "pnd_test",
		PayloadHash:    "sha256:abc",
		Scope:          "safe-agreement",
		SignerID:       "u_test",
		SignerIP:       "10.0.0.1",
		SignatureImage: "dGVzdA==",
		ImageHash:      HashImage([]byte("test")),
		CapturedAt:     time.Now().UTC(),
	}

	sealed, err := Seal(env)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if !json.Valid(sealed.Data) {
		t.Fatal("sealed data is not valid JSON")
	}
}
