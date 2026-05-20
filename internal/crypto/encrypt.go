package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// KEK algorithm tags persisted on every signing_keys row so a server can
// decrypt DEKs produced under either the original SHA-256 derivation
// (KEKAlgoLegacy) or the current Argon2id derivation (KEKAlgoArgon2id).
const (
	KEKAlgoLegacy   = ""
	KEKAlgoArgon2id = "argon2id"
)

// Argon2id parameters tuned for once-per-startup KEK derivation on a
// modest server. 64 MiB / 3 passes is roughly 300–700 ms on commodity
// hardware — costly enough to make brute-force impractical against a
// stolen DB without making startup feel broken.
const (
	argon2Time    uint32 = 3
	argon2Memory  uint32 = 64 * 1024 // KiB
	argon2Threads uint8  = 4
	argon2KeyLen  uint32 = 32
)

// DeriveKEK derives a 32-byte key encryption key from a server secret
// using the legacy SHA-256 derivation. Retained so DEKs wrapped under
// the original scheme remain decryptable. New wraps go through KEKRing
// and pick KEKAlgoArgon2id.
func DeriveKEK(secret string) ([]byte, error) {
	if secret == "" {
		return nil, fmt.Errorf("KEK secret cannot be empty")
	}
	hash := sha256.Sum256([]byte(secret))
	return hash[:], nil
}

// DeriveKEKArgon2id derives a 32-byte KEK from the server secret and a
// per-server random salt using Argon2id. The salt must be persisted
// alongside the wrapped DEKs (see storage.GetOrCreateKEKSalt) so the
// same KEK is reproducible across restarts.
func DeriveKEKArgon2id(secret string, salt []byte) ([]byte, error) {
	if secret == "" {
		return nil, fmt.Errorf("KEK secret cannot be empty")
	}
	if len(salt) < 16 {
		return nil, fmt.Errorf("KEK salt must be at least 16 bytes, got %d", len(salt))
	}
	return argon2.IDKey([]byte(secret), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen), nil
}

// KEKRing holds the KEKs needed to decrypt every signing_keys row the
// server might encounter. The current entry is used for all new wraps;
// the legacy entry is only consulted to decrypt rows written before the
// Argon2id migration. Both keys are kept in memory for the process
// lifetime — zero them via ZeroBytes if the ring is ever discarded.
//
// The ring also carries the HMAC key that binds pending_signatures rows
// to their immutable fields (see ComputePendingMAC). Putting it here
// keeps every server-secret-derived value behind one constructor.
type KEKRing struct {
	legacy      []byte
	current     []byte
	currentAlgo string
	macKey      []byte // HMAC-SHA256 key for pending-row binding
}

// NewKEKRingForTests builds a ring suitable for unit and integration
// tests. The current and legacy keys are both the SHA-256 derivation,
// skipping the ~300 ms Argon2id cost. New wraps still get tagged with
// KEKAlgoArgon2id so the per-row algo plumbing is exercised end-to-end;
// only the brute-force resistance is dropped. Not for production.
func NewKEKRingForTests(secret string) (*KEKRing, error) {
	kek, err := DeriveKEK(secret)
	if err != nil {
		return nil, err
	}
	return &KEKRing{
		legacy:      kek,
		current:     kek,
		currentAlgo: KEKAlgoArgon2id,
		macKey:      derivePendingMACKey(kek),
	}, nil
}

// NewKEKRing builds a KEKRing from the server's KEK secret and a stored
// salt. Both the legacy (SHA-256) and current (Argon2id) keys are
// derived so any historical DEK in the DB can still be unwrapped.
func NewKEKRing(secret string, salt []byte) (*KEKRing, error) {
	legacy, err := DeriveKEK(secret)
	if err != nil {
		return nil, fmt.Errorf("deriving legacy KEK: %w", err)
	}
	current, err := DeriveKEKArgon2id(secret, salt)
	if err != nil {
		return nil, fmt.Errorf("deriving argon2id KEK: %w", err)
	}
	return &KEKRing{
		legacy:      legacy,
		current:     current,
		currentAlgo: KEKAlgoArgon2id,
		macKey:      derivePendingMACKey(current),
	}, nil
}

// WrapDEK encrypts dek with the current KEK and returns the wrapped
// bytes alongside the algorithm tag to persist with the row.
func (r *KEKRing) WrapDEK(dek []byte) ([]byte, string, error) {
	wrapped, err := WrapDEK(dek, r.current)
	if err != nil {
		return nil, "", err
	}
	return wrapped, r.currentAlgo, nil
}

// UnwrapDEK decrypts wrapped using the KEK that matches the row's algo
// tag. Empty tag or "v1-sha256" routes to the legacy SHA-256-derived
// KEK; "argon2id" routes to the current Argon2id-derived KEK.
func (r *KEKRing) UnwrapDEK(wrapped []byte, algo string) ([]byte, error) {
	kek, err := r.kekFor(algo)
	if err != nil {
		return nil, err
	}
	return UnwrapDEK(wrapped, kek)
}

// CurrentAlgo returns the algorithm tag new rows should be tagged with.
func (r *KEKRing) CurrentAlgo() string {
	return r.currentAlgo
}

// CurrentKEKMaterial returns a copy of the current KEK for use as input
// to HKDF derivations outside this package (e.g., audit chain keys).
// Returning a copy prevents callers from mutating the ring's internal
// key by accident.
func (r *KEKRing) CurrentKEKMaterial() []byte {
	out := make([]byte, len(r.current))
	copy(out, r.current)
	return out
}

func (r *KEKRing) kekFor(algo string) ([]byte, error) {
	switch algo {
	case KEKAlgoLegacy:
		return r.legacy, nil
	case KEKAlgoArgon2id:
		return r.current, nil
	default:
		return nil, fmt.Errorf("unknown KEK algorithm %q", algo)
	}
}

// PendingBinding holds the fields a cosign approval signs over. Every
// value that shapes signing intent — which key signs, which auth
// authorizes, who requested, what document type, the payload hash, and
// the request metadata — is included so any tamper between sign-request
// and approval is detected.
type PendingBinding struct {
	SigningKeyID string
	AuthTokenID  string
	RequesterID  string
	DocType      string
	PayloadHash  string
	Metadata     string
}

// pendingMACInfo is the HKDF info string for deriving the pending-row
// HMAC key. Bumping the version suffix rotates every binding at once;
// existing pendings would fail verification on the next approve.
const pendingMACInfo = "sshsign-pending-mac-v1"

func derivePendingMACKey(currentKEK []byte) []byte {
	out := make([]byte, 32)
	h := hkdf.Expand(sha256.New, currentKEK, []byte(pendingMACInfo))
	_, _ = io.ReadFull(h, out)
	return out
}

func (b PendingBinding) canonical() []byte {
	// Length-prefix every field so encoded boundaries are unambiguous —
	// {"foo", "barbaz"} can't collide with {"foobar", "baz"}.
	fields := []string{b.SigningKeyID, b.AuthTokenID, b.RequesterID, b.DocType, b.PayloadHash, b.Metadata}
	total := 0
	for _, f := range fields {
		total += 4 + len(f)
	}
	out := make([]byte, 0, total)
	var lenBuf [4]byte
	for _, f := range fields {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(f)))
		out = append(out, lenBuf[:]...)
		out = append(out, f...)
	}
	return out
}

// ComputePendingMAC returns the HMAC-SHA256 of the binding's canonical
// encoding under the ring's pending MAC key. Persist alongside the row
// at sign time; recompute on approve and compare with VerifyPendingMAC.
func (r *KEKRing) ComputePendingMAC(b PendingBinding) []byte {
	h := hmac.New(sha256.New, r.macKey)
	h.Write(b.canonical())
	return h.Sum(nil)
}

// VerifyPendingMAC returns true iff mac was produced by ComputePendingMAC
// for the same binding under this ring. Empty mac is rejected so a row
// whose pending_mac column was zeroed cannot be silently downgraded to
// "no integrity check."
func (r *KEKRing) VerifyPendingMAC(b PendingBinding, mac []byte) bool {
	if len(mac) == 0 {
		return false
	}
	expected := r.ComputePendingMAC(b)
	return subtle.ConstantTimeCompare(expected, mac) == 1
}

// GenerateDEK generates a random 32-byte data encryption key.
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("generating DEK: %w", err)
	}
	return dek, nil
}

// EncryptPrivateKey encrypts an ed25519 private key with a DEK using AES-256-GCM.
// Returns nonce || ciphertext.
func EncryptPrivateKey(privKey ed25519.PrivateKey, dek []byte) ([]byte, error) {
	return encryptAESGCM([]byte(privKey), dek)
}

// DecryptPrivateKey decrypts an ed25519 private key encrypted with EncryptPrivateKey.
func DecryptPrivateKey(encrypted []byte, dek []byte) (ed25519.PrivateKey, error) {
	plaintext, err := decryptAESGCM(encrypted, dek)
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(plaintext), nil
}

// WrapDEK encrypts a DEK with the KEK using AES-256-GCM.
func WrapDEK(dek []byte, kek []byte) ([]byte, error) {
	return encryptAESGCM(dek, kek)
}

// UnwrapDEK decrypts a DEK that was encrypted with WrapDEK.
func UnwrapDEK(wrappedDEK []byte, kek []byte) ([]byte, error) {
	return decryptAESGCM(wrappedDEK, kek)
}

// ZeroBytes zeroes a byte slice to clear sensitive data from memory.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// hashedApprovalTokenPrefix tags a stored approval-token hash so it can be
// distinguished from legacy plaintext tokens still present in older rows.
const hashedApprovalTokenPrefix = "$sha256$"

// HashApprovalToken returns the verifier to persist in place of a raw
// approval token. The raw token must only ever live in the response URL
// returned to the signer at sign time; the DB stores this hash so DB
// compromise alone does not yield forgeable approvals.
func HashApprovalToken(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hashedApprovalTokenPrefix + hex.EncodeToString(sum[:])
}

// VerifyApprovalToken returns true when the presented (raw) token matches
// the value stored at request time. New rows store [[HashApprovalToken]]
// output; legacy rows (pre-hashing) hold the raw token and are accepted
// via direct constant-time compare so in-flight approvals are not bricked
// by the migration.
func VerifyApprovalToken(stored, presented string) bool {
	if stored == "" || presented == "" {
		return false
	}
	if strings.HasPrefix(stored, hashedApprovalTokenPrefix) {
		return subtle.ConstantTimeCompare([]byte(stored), []byte(HashApprovalToken(presented))) == 1
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) == 1
}

func encryptAESGCM(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// nonce is prepended to ciphertext
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptAESGCM(encrypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short: expected at least %d bytes, got %d", nonceSize, len(encrypted))
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}
