package server_test

import (
	"encoding/json"
	"strings"
	"testing"

	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/storage"
	gossh "golang.org/x/crypto/ssh"
)

// setupUserWithCosignAuth creates a user with a signing key and a cosign-tier authorization.
// Returns the SSH signer, user ID, and signing key ID.
func setupUserWithCosignAuth(t *testing.T, ts *testServer, scopes []string, metadataConstraints []storage.MetadataConstraint) (gossh.Signer, string, string) {
	t.Helper()

	signer, pub := generateTestSSHKey(t)
	sshClient(t, ts.addr, signer, "")

	sshPub, _ := gossh.NewPublicKey(pub)
	fingerprint := gossh.FingerprintSHA256(sshPub)
	user, _, err := storage.FindUserByFingerprint(ts.db.DB, fingerprint)
	if err != nil || user == nil {
		t.Fatalf("finding user: %v", err)
	}

	edPub, edPriv, _ := apoacrypto.GenerateEd25519Keypair()
	pubSSH, _ := apoacrypto.MarshalPublicKeySSH(edPub)
	dek, _ := apoacrypto.GenerateDEK()
	encPrivKey, _ := apoacrypto.EncryptPrivateKey(edPriv, dek)
	wrappedDEK, _ := apoacrypto.WrapDEK(dek, ts.kek)

	sk, err := storage.CreateSigningKey(ts.db.DB, user.UserID, pubSSH, encPrivKey, wrappedDEK)
	if err != nil {
		t.Fatalf("creating signing key: %v", err)
	}

	_, err = storage.CreateAuthorizationFull(ts.db.DB, sk.KeyID, user.UserID,
		scopes, nil, metadataConstraints, "cosign", nil, nil, nil)
	if err != nil {
		t.Fatalf("creating cosign authorization: %v", err)
	}

	return signer, user.UserID, sk.KeyID
}

func TestCosignFlow_ReturnesPending(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithCosignAuth(t, ts, []string{"safe-agreement"}, nil)

	payload := []byte("test document content")
	signCmd := "sign --type safe-agreement --key-id " + keyID
	output, err := sshClientWithStdin(t, ts.addr, signer, signCmd, payload)
	if err != nil {
		t.Logf("sign output: %s", output)
	}

	var resp struct {
		Status    string `json:"status"`
		PendingID string `json:"pending_id"`
	}
	if err := json.Unmarshal([]byte(output), &resp); err != nil {
		t.Fatalf("parsing response: %v\nraw: %s", err, output)
	}

	if resp.Status != "pending_cosign" {
		t.Errorf("expected status 'pending_cosign', got %q", resp.Status)
	}
	if !strings.HasPrefix(resp.PendingID, "pnd_") {
		t.Errorf("expected pending ID with pnd_ prefix, got %q", resp.PendingID)
	}
}

func TestCosignFlow_ApproveProducesSignature(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithCosignAuth(t, ts, []string{"safe-agreement"}, nil)

	// Submit sign request (goes to pending)
	payload := []byte("test document content")
	signCmd := "sign --type safe-agreement --key-id " + keyID
	signOutput, _ := sshClientWithStdin(t, ts.addr, signer, signCmd, payload)

	var pendingResp struct {
		PendingID string `json:"pending_id"`
	}
	json.Unmarshal([]byte(signOutput), &pendingResp)

	// Check pending list
	pendingOutput, _ := sshClient(t, ts.addr, signer, "pending")
	var pendingList []struct {
		ID string `json:"id"`
	}
	json.Unmarshal([]byte(pendingOutput), &pendingList)
	if len(pendingList) != 1 {
		t.Fatalf("expected 1 pending signature, got %d", len(pendingList))
	}

	// Approve
	approveOutput, _ := sshClient(t, ts.addr, signer, "approve --id "+pendingResp.PendingID)

	var approveResp struct {
		Signature string `json:"signature"`
		KeyID     string `json:"key_id"`
		TokenID   string `json:"token_id"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal([]byte(approveOutput), &approveResp); err != nil {
		t.Fatalf("parsing approve response: %v\nraw: %s", err, approveOutput)
	}

	if approveResp.Error != "" {
		t.Fatalf("approve returned error: %s", approveResp.Error)
	}
	if approveResp.Signature == "" {
		t.Fatal("expected non-empty signature after approval")
	}
	if !strings.Contains(approveResp.Signature, "BEGIN SSH SIGNATURE") {
		t.Error("signature should be PEM-armored SSH signature")
	}
}

func TestCosignFlow_DenyIsLogged(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithCosignAuth(t, ts, []string{"safe-agreement"}, nil)

	payload := []byte("test document")
	signCmd := "sign --type safe-agreement --key-id " + keyID
	signOutput, _ := sshClientWithStdin(t, ts.addr, signer, signCmd, payload)

	var pendingResp struct {
		PendingID string `json:"pending_id"`
	}
	json.Unmarshal([]byte(signOutput), &pendingResp)

	// Deny
	denyOutput, _ := sshClient(t, ts.addr, signer, "deny --id "+pendingResp.PendingID)

	var denyResp struct {
		Status    string `json:"status"`
		PendingID string `json:"pending_id"`
	}
	json.Unmarshal([]byte(denyOutput), &denyResp)

	if denyResp.Status != "denied" {
		t.Errorf("expected status 'denied', got %q", denyResp.Status)
	}

	// Verify denial is in audit log
	entries := ts.auditLog.Entries()
	found := false
	for _, e := range entries {
		if e.Result == "DENIED" && e.DenialReason == "co-sign denied by principal" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected denial audit entry not found")
	}
}

func TestCosignFlow_ApproveAfterKeyRevoke(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithCosignAuth(t, ts, []string{"safe-agreement"}, nil)

	// Submit sign request
	payload := []byte("test document")
	signCmd := "sign --type safe-agreement --key-id " + keyID
	signOutput, _ := sshClientWithStdin(t, ts.addr, signer, signCmd, payload)

	var pendingResp struct {
		PendingID string `json:"pending_id"`
	}
	json.Unmarshal([]byte(signOutput), &pendingResp)

	// Revoke the signing key
	storage.RevokeSigningKey(ts.db.DB, keyID)

	// Try to approve - should fail
	approveOutput, _ := sshClient(t, ts.addr, signer, "approve --id "+pendingResp.PendingID)

	var resp struct {
		Error string `json:"error"`
	}
	json.Unmarshal([]byte(approveOutput), &resp)

	if !strings.Contains(resp.Error, "revoked") {
		t.Errorf("expected revoked error, got: %s", resp.Error)
	}
}

func TestCosignFlow_ApproveByWrongUser(t *testing.T) {
	ts := setupTestServer(t)

	// User A creates the cosign auth and submits
	signerA, _, keyID := setupUserWithCosignAuth(t, ts, []string{"safe-agreement"}, nil)

	payload := []byte("test document")
	signCmd := "sign --type safe-agreement --key-id " + keyID
	signOutput, _ := sshClientWithStdin(t, ts.addr, signerA, signCmd, payload)

	var pendingResp struct {
		PendingID string `json:"pending_id"`
	}
	json.Unmarshal([]byte(signOutput), &pendingResp)

	// User B tries to approve
	signerB, _ := generateTestSSHKey(t)
	sshClient(t, ts.addr, signerB, "") // create user B

	approveOutput, _ := sshClient(t, ts.addr, signerB, "approve --id "+pendingResp.PendingID)

	var resp struct {
		Error string `json:"error"`
	}
	json.Unmarshal([]byte(approveOutput), &resp)

	if !strings.Contains(resp.Error, "principal") {
		t.Errorf("expected principal error, got: %s", resp.Error)
	}
}
