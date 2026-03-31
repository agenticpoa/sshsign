package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/42wim/sshsig"
	"golang.org/x/crypto/ssh"
)

// Sign produces a PEM-armored SSH signature (SSHSIG format) compatible with
// ssh-keygen -Y verify and git's gpg.ssh.program integration.
func Sign(privKey ed25519.PrivateKey, payload []byte, namespace string) ([]byte, error) {
	pemBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		return nil, fmt.Errorf("marshaling private key to PEM: %w", err)
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	sig, err := sshsig.Sign(pemBytes, bytes.NewReader(payload), namespace)
	if err != nil {
		return nil, fmt.Errorf("signing payload: %w", err)
	}

	return sig, nil
}

// Verify checks a PEM-armored SSH signature against a payload and public key.
// publicKeySSH should be in authorized_keys format: "ssh-ed25519 AAAA..."
func Verify(armoredSig []byte, payload []byte, publicKeySSH string, namespace string) error {
	return sshsig.Verify(
		bytes.NewReader(payload),
		armoredSig,
		[]byte(publicKeySSH),
		namespace,
	)
}

// SignReader produces a PEM-armored SSH signature reading the payload from a reader.
func SignReader(privKey ed25519.PrivateKey, payload io.Reader, namespace string) ([]byte, error) {
	pemBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		return nil, fmt.Errorf("marshaling private key to PEM: %w", err)
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	sig, err := sshsig.Sign(pemBytes, payload, namespace)
	if err != nil {
		return nil, fmt.Errorf("signing payload: %w", err)
	}

	return sig, nil
}
