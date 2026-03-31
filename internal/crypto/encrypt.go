package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// DeriveKEK derives a 32-byte key encryption key from a server secret.
// v1 uses SHA-256 for simplicity. v2 should use a cloud KMS.
func DeriveKEK(secret string) ([]byte, error) {
	if secret == "" {
		return nil, fmt.Errorf("KEK secret cannot be empty")
	}
	hash := sha256.Sum256([]byte(secret))
	return hash[:], nil
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
