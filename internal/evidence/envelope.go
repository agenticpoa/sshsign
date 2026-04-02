package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Envelope is a sealed artifact binding a handwritten signature image
// to the document it approves. The image lives inside and nowhere else.
type Envelope struct {
	Version        int       `json:"version"`
	PendingID      string    `json:"pending_id"`
	PayloadHash    string    `json:"payload_hash"`
	Scope          string    `json:"scope"`
	Metadata       string    `json:"metadata,omitempty"`
	SignerID       string    `json:"signer_id"`
	SignerIP       string    `json:"signer_ip"`
	SignatureImage string    `json:"signature_image"` // base64 PNG
	ImageHash      string    `json:"image_hash"`      // SHA256 of raw PNG bytes
	CapturedAt     time.Time `json:"captured_at"`
}

// SealedEnvelope is the output of Seal: the canonical JSON bytes and their hash.
type SealedEnvelope struct {
	Data []byte // canonical JSON
	Hash string // SHA256 hex of Data
}

// Seal serializes the envelope to canonical JSON and computes its SHA256 hash.
func Seal(env *Envelope) (*SealedEnvelope, error) {
	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshaling envelope: %w", err)
	}

	h := sha256.Sum256(data)
	return &SealedEnvelope{
		Data: data,
		Hash: hex.EncodeToString(h[:]),
	}, nil
}

// Open deserializes a sealed envelope and verifies its hash.
func Open(data []byte, expectedHash string) (*Envelope, error) {
	h := sha256.Sum256(data)
	got := hex.EncodeToString(h[:])
	if got != expectedHash {
		return nil, fmt.Errorf("envelope hash mismatch: expected %s, got %s", expectedHash, got)
	}

	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("unmarshaling envelope: %w", err)
	}
	return &env, nil
}

// HashImage computes the SHA256 hex digest of raw image bytes.
func HashImage(imageBytes []byte) string {
	h := sha256.Sum256(imageBytes)
	return hex.EncodeToString(h[:])
}

// CompositePayload builds the string that the cryptographic signature covers
// when an evidence envelope is involved: "payload_hash|envelope_hash".
func CompositePayload(payloadHash, envelopeHash string) string {
	return payloadHash + "|" + envelopeHash
}
