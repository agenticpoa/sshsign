package server_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/storage"
	gossh "golang.org/x/crypto/ssh"
)

// sshClientWithStdin connects and sends data on stdin, useful for sign/verify commands.
func sshClientWithStdin(t *testing.T, addr string, signer gossh.Signer, command string, stdin []byte) (string, error) {
	t.Helper()

	config := &gossh.ClientConfig{
		User: "test",
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(signer),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := gossh.Dial("tcp", addr, config)
	if err != nil {
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	session.Stdin = bytes.NewReader(stdin)

	var stdout bytes.Buffer
	session.Stdout = &stdout

	err = session.Run(command)
	return stdout.String(), err
}

// setupUserWithSigningKeyAndAuth creates a user, a signing key, and an authorization.
// Returns the user, signing key ID, and SSH signer for connecting.
func setupUserWithSigningKeyAndAuth(t *testing.T, ts *testServer, scopes []string, constraints map[string][]string, hardRules, softRules []string) (gossh.Signer, string, string) {
	t.Helper()

	signer, pub := generateTestSSHKey(t)

	// Connect to create the user
	sshClient(t, ts.addr, signer, "")

	sshPub, _ := gossh.NewPublicKey(pub)
	fingerprint := gossh.FingerprintSHA256(sshPub)

	user, _, err := storage.FindUserByFingerprint(ts.db.DB, fingerprint)
	if err != nil || user == nil {
		t.Fatalf("finding user: %v", err)
	}

	// Create a signing key
	edPub, edPriv, err := apoacrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("generating ed25519 keypair: %v", err)
	}

	pubSSH, err := apoacrypto.MarshalPublicKeySSH(edPub)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	dek, err := apoacrypto.GenerateDEK()
	if err != nil {
		t.Fatalf("generating DEK: %v", err)
	}

	encPrivKey, err := apoacrypto.EncryptPrivateKey(edPriv, dek)
	if err != nil {
		t.Fatalf("encrypting private key: %v", err)
	}

	wrappedDEK, err := apoacrypto.WrapDEK(dek, ts.kek)
	if err != nil {
		t.Fatalf("wrapping DEK: %v", err)
	}

	sk, err := storage.CreateSigningKey(ts.db.DB, user.UserID, pubSSH, encPrivKey, wrappedDEK)
	if err != nil {
		t.Fatalf("creating signing key: %v", err)
	}

	// Create authorization
	_, err = storage.CreateAuthorization(ts.db.DB, sk.KeyID, user.UserID,
		scopes, constraints, hardRules, softRules, nil)
	if err != nil {
		t.Fatalf("creating authorization: %v", err)
	}

	return signer, user.UserID, sk.KeyID
}

func TestSignAndVerifyEndToEnd(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithSigningKeyAndAuth(t, ts,
		[]string{"git-commit"},
		map[string][]string{"repo": {"github.com/user/*"}},
		nil, nil,
	)

	payload := []byte("tree abc123\nparent def456\nauthor Test <test@test.com>\n\ntest commit\n")

	// Sign
	signCmd := "sign --type git-commit --key-id " + keyID + " --repo github.com/user/myrepo"
	output, err := sshClientWithStdin(t, ts.addr, signer, signCmd, payload)
	if err != nil {
		t.Logf("sign output: %s", output)
		t.Fatalf("sign command failed: %v", err)
	}

	var signResp struct {
		Signature string `json:"signature"`
		KeyID     string `json:"key_id"`
		TokenID   string `json:"token_id"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal([]byte(output), &signResp); err != nil {
		t.Fatalf("parsing sign response: %v\nraw output: %s", err, output)
	}
	if signResp.Error != "" {
		t.Fatalf("sign returned error: %s", signResp.Error)
	}
	if signResp.Signature == "" {
		t.Fatal("expected non-empty signature")
	}
	if !strings.Contains(signResp.Signature, "BEGIN SSH SIGNATURE") {
		t.Error("signature should be PEM-armored SSH signature")
	}

	t.Logf("signed with key %s, token %s", signResp.KeyID, signResp.TokenID)
}

func TestSignDeniedWrongScope(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithSigningKeyAndAuth(t, ts,
		[]string{"api-request"}, // only api-request, not git-commit
		nil, nil, nil,
	)

	payload := []byte("test data")
	signCmd := "sign --type git-commit --key-id " + keyID
	output, _ := sshClientWithStdin(t, ts.addr, signer, signCmd, payload)

	var resp struct{ Error string }
	json.Unmarshal([]byte(output), &resp)
	if !strings.Contains(resp.Error, "denied") {
		t.Errorf("expected denial for wrong scope, got: %s", resp.Error)
	}
}

func TestSignDeniedConstraintViolation(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithSigningKeyAndAuth(t, ts,
		[]string{"git-commit"},
		map[string][]string{"repo": {"github.com/user/*"}},
		nil, nil,
	)

	payload := []byte("test data")
	// Repo doesn't match constraint
	signCmd := "sign --type git-commit --key-id " + keyID + " --repo github.com/other/repo"
	output, _ := sshClientWithStdin(t, ts.addr, signer, signCmd, payload)

	var resp struct{ Error string }
	json.Unmarshal([]byte(output), &resp)
	if !strings.Contains(resp.Error, "denied") {
		t.Errorf("expected denial for constraint violation, got: %s", resp.Error)
	}
}

func TestSignDeniedHardRule(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithSigningKeyAndAuth(t, ts,
		[]string{"git-commit"},
		map[string][]string{"repo": {"github.com/user/*"}},
		[]string{"never sign to main branch"},
		nil,
	)

	payload := []byte("test commit data")
	signCmd := "sign --type git-commit --key-id " + keyID + " --repo github.com/user/myrepo --branch main"
	output, _ := sshClientWithStdin(t, ts.addr, signer, signCmd, payload)

	var resp struct{ Error string }
	json.Unmarshal([]byte(output), &resp)
	if !strings.Contains(resp.Error, "hard rule") {
		t.Errorf("expected hard rule denial, got: %s", resp.Error)
	}
}

func TestSignDeniedExpiredAuth(t *testing.T) {
	ts := setupTestServer(t)

	signer, pub := generateTestSSHKey(t)
	sshClient(t, ts.addr, signer, "")

	sshPub, _ := gossh.NewPublicKey(pub)
	fingerprint := gossh.FingerprintSHA256(sshPub)
	user, _, _ := storage.FindUserByFingerprint(ts.db.DB, fingerprint)

	edPub, edPriv, _ := apoacrypto.GenerateEd25519Keypair()
	pubSSH, _ := apoacrypto.MarshalPublicKeySSH(edPub)
	dek, _ := apoacrypto.GenerateDEK()
	encPrivKey, _ := apoacrypto.EncryptPrivateKey(edPriv, dek)
	wrappedDEK, _ := apoacrypto.WrapDEK(dek, ts.kek)

	sk, _ := storage.CreateSigningKey(ts.db.DB, user.UserID, pubSSH, encPrivKey, wrappedDEK)

	// Create expired authorization
	expired := time.Now().Add(-1 * time.Hour)
	storage.CreateAuthorization(ts.db.DB, sk.KeyID, user.UserID,
		[]string{"git-commit"}, nil, nil, nil, &expired)

	payload := []byte("test data")
	signCmd := "sign --type git-commit --key-id " + sk.KeyID
	output, _ := sshClientWithStdin(t, ts.addr, signer, signCmd, payload)

	var resp struct{ Error string }
	json.Unmarshal([]byte(output), &resp)
	if !strings.Contains(resp.Error, "denied") {
		t.Errorf("expected denial for expired auth, got: %s", resp.Error)
	}
}

func TestSignDeniedRevokedKey(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithSigningKeyAndAuth(t, ts,
		[]string{"git-commit"}, nil, nil, nil,
	)

	// Revoke the key
	storage.RevokeSigningKey(ts.db.DB, keyID)

	payload := []byte("test data")
	signCmd := "sign --type git-commit --key-id " + keyID
	output, _ := sshClientWithStdin(t, ts.addr, signer, signCmd, payload)

	var resp struct{ Error string }
	json.Unmarshal([]byte(output), &resp)
	if resp.Error == "" {
		t.Error("expected error for revoked key")
	}
}

func TestKeysCommand(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, _ := setupUserWithSigningKeyAndAuth(t, ts,
		[]string{"git-commit"}, nil, nil, nil,
	)

	output, err := sshClient(t, ts.addr, signer, "keys")
	if err != nil {
		t.Logf("keys output: %s", output)
	}

	var keys []struct {
		KeyID     string  `json:"key_id"`
		PublicKey string  `json:"public_key"`
		RevokedAt *string `json:"revoked_at"`
	}
	if err := json.Unmarshal([]byte(output), &keys); err != nil {
		t.Fatalf("parsing keys response: %v\nraw: %s", err, output)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}
	if keys[0].KeyID == "" {
		t.Error("key_id should not be empty")
	}
}

func TestRevokeCommand(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithSigningKeyAndAuth(t, ts,
		[]string{"git-commit"}, nil, nil, nil,
	)

	output, err := sshClient(t, ts.addr, signer, "revoke --key-id "+keyID)
	if err != nil {
		t.Logf("revoke output: %s", output)
	}

	var resp struct {
		Status string `json:"status"`
		KeyID  string `json:"key_id"`
	}
	if err := json.Unmarshal([]byte(output), &resp); err != nil {
		t.Fatalf("parsing revoke response: %v\nraw: %s", err, output)
	}
	if resp.Status != "revoked" {
		t.Errorf("expected status 'revoked', got %q", resp.Status)
	}

	// Signing should now fail
	payload := []byte("test data")
	signOutput, _ := sshClientWithStdin(t, ts.addr, signer, "sign --type git-commit --key-id "+keyID, payload)
	var signResp struct{ Error string }
	json.Unmarshal([]byte(signOutput), &signResp)
	if signResp.Error == "" {
		t.Error("expected error when signing with revoked key")
	}
}

func TestSignEmptyPayload(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithSigningKeyAndAuth(t, ts,
		[]string{"git-commit"}, nil, nil, nil,
	)

	output, _ := sshClientWithStdin(t, ts.addr, signer, "sign --type git-commit --key-id "+keyID, nil)

	var resp struct{ Error string }
	json.Unmarshal([]byte(output), &resp)
	if resp.Error == "" {
		t.Error("expected error for empty payload")
	}
}

func TestSignNoSigningKeys(t *testing.T) {
	ts := setupTestServer(t)

	signer, _ := generateTestSSHKey(t)
	sshClient(t, ts.addr, signer, "") // create user but no signing key

	payload := []byte("test data")
	output, _ := sshClientWithStdin(t, ts.addr, signer, "sign --type git-commit", payload)

	var resp struct{ Error string }
	json.Unmarshal([]byte(output), &resp)
	if !strings.Contains(resp.Error, "no active signing keys") {
		t.Errorf("expected 'no active signing keys' error, got: %s", resp.Error)
	}
}
