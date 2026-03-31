package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func GenerateEd25519Keypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating ed25519 keypair: %w", err)
	}
	return pub, priv, nil
}

// MarshalPublicKeySSH converts an ed25519 public key to the "ssh-ed25519 AAAA..." format.
func MarshalPublicKeySSH(pub ed25519.PublicKey) (string, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("creating ssh public key: %w", err)
	}
	// MarshalAuthorizedKey returns "type base64\n", trim the trailing newline
	authorized := ssh.MarshalAuthorizedKey(sshPub)
	return string(authorized[:len(authorized)-1]), nil
}

// FingerprintSHA256 returns the SHA256 fingerprint of an ed25519 public key.
func FingerprintSHA256(pub ed25519.PublicKey) (string, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("creating ssh public key: %w", err)
	}
	return ssh.FingerprintSHA256(sshPub), nil
}
