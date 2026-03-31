package signing_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/signing"
)

// TestSSHKeygenVerifiesOurSignature is the critical spike test:
// it proves that signatures produced by our signing engine are accepted
// by ssh-keygen -Y verify, which is what git uses under the hood.
func TestSSHKeygenVerifiesOurSignature(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available, skipping spike test")
	}

	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	pubSSH, err := crypto.MarshalPublicKeySSH(pub)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	payload := []byte("test commit data\n")

	sig, err := signing.Sign(priv, payload, "git")
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Write temp files for ssh-keygen
	dir := t.TempDir()

	sigFile := filepath.Join(dir, "signature.sig")
	if err := os.WriteFile(sigFile, sig, 0600); err != nil {
		t.Fatalf("writing signature file: %v", err)
	}

	payloadFile := filepath.Join(dir, "payload")
	if err := os.WriteFile(payloadFile, payload, 0600); err != nil {
		t.Fatalf("writing payload file: %v", err)
	}

	// allowed_signers format: <principal> <key-type> <base64-key>
	allowedSigners := "test@test " + pubSSH + "\n"
	allowedSignersFile := filepath.Join(dir, "allowed_signers")
	if err := os.WriteFile(allowedSignersFile, []byte(allowedSigners), 0600); err != nil {
		t.Fatalf("writing allowed_signers file: %v", err)
	}

	// ssh-keygen -Y verify -f allowed_signers -I test@test -n git -s sig_file < payload
	cmd := exec.Command("ssh-keygen",
		"-Y", "verify",
		"-f", allowedSignersFile,
		"-I", "test@test",
		"-n", "git",
		"-s", sigFile,
	)
	cmd.Stdin, err = os.Open(payloadFile)
	if err != nil {
		t.Fatalf("opening payload for stdin: %v", err)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -Y verify failed: %v\noutput: %s", err, string(output))
	}

	t.Logf("ssh-keygen output: %s", string(output))
}
