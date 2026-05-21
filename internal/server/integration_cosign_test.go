package server_test

import (
	"context"
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
	user, _, err := storage.FindUserByFingerprint(context.Background(), ts.db.DB, fingerprint)
	if err != nil || user == nil {
		t.Fatalf("finding user: %v", err)
	}

	edPub, edPriv, _ := apoacrypto.GenerateEd25519Keypair()
	pubSSH, _ := apoacrypto.MarshalPublicKeySSH(edPub)
	dek, _ := apoacrypto.GenerateDEK()
	encPrivKey, _ := apoacrypto.EncryptPrivateKey(edPriv, dek)
	wrappedDEK, kekAlgo, _ := ts.kek.WrapDEK(dek)

	sk, err := storage.CreateSigningKey(context.Background(), ts.db.DB, user.UserID, pubSSH, encPrivKey, wrappedDEK, kekAlgo)
	if err != nil {
		t.Fatalf("creating signing key: %v", err)
	}

	_, err = storage.CreateAuthorizationFull(context.Background(), ts.db.DB, sk.KeyID, user.UserID,
		scopes, nil, metadataConstraints, "cosign", false, nil, nil, nil)
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
	mustUnmarshal(t, signOutput, &pendingResp)

	// Check pending list
	pendingOutput, _ := sshClient(t, ts.addr, signer, "pending")
	var pendingList []struct {
		ID string `json:"id"`
	}
	mustUnmarshal(t, pendingOutput, &pendingList)
	if len(pendingList) != 1 {
		t.Fatalf("expected 1 pending signature, got %d", len(pendingList))
	}

	// Approve (--confirm acknowledges ESIGN disclosure)
	approveOutput, _ := sshClient(t, ts.addr, signer, "approve --id "+pendingResp.PendingID+" --confirm")

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

func TestCosignFlow_RejectsTamperedPayloadHash(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithCosignAuth(t, ts, []string{"safe-agreement"}, nil)

	// Submit a sign request whose payload SHOULD bind to "good payload".
	signCmd := "sign --type safe-agreement --key-id " + keyID
	signOutput, _ := sshClientWithStdin(t, ts.addr, signer, signCmd, []byte("good payload"))

	var pendingResp struct {
		PendingID string `json:"pending_id"`
	}
	if err := json.Unmarshal([]byte(signOutput), &pendingResp); err != nil {
		t.Fatalf("parse sign output: %v\nraw: %s", err, signOutput)
	}

	// Simulate a DB tamper: swap the payload_hash on the pending row.
	// MAC was computed over the original hash, so verification must fail.
	_, err := ts.db.DB.Exec(
		`UPDATE pending_signatures SET payload_hash = ? WHERE id = ?`,
		"sha256:attacker-substituted-payload", pendingResp.PendingID,
	)
	if err != nil {
		t.Fatalf("tampering payload_hash: %v", err)
	}

	approveOutput, _ := sshClient(t, ts.addr, signer, "approve --id "+pendingResp.PendingID+" --confirm")
	var approveResp struct {
		Signature string `json:"signature"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal([]byte(approveOutput), &approveResp); err != nil {
		t.Fatalf("parse approve output: %v\nraw: %s", err, approveOutput)
	}
	if approveResp.Signature != "" {
		t.Fatal("approve produced a signature against a tampered payload_hash")
	}
	if !strings.Contains(approveResp.Error, "integrity check failed") {
		t.Errorf("expected integrity error, got: %q", approveResp.Error)
	}

	// Tamper attempt must be recorded in the audit log.
	found := false
	for _, e := range ts.auditLog.Entries() {
		if e.Result == "DENIED" && strings.Contains(e.DenialReason, "MAC mismatch") {
			found = true
			break
		}
	}
	if !found {
		t.Error("MAC mismatch was not recorded in the audit log")
	}
}

func TestCosignFlow_RejectsRowWithoutMAC(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithCosignAuth(t, ts, []string{"safe-agreement"}, nil)

	signCmd := "sign --type safe-agreement --key-id " + keyID
	signOutput, _ := sshClientWithStdin(t, ts.addr, signer, signCmd, []byte("legacy payload"))

	var pendingResp struct {
		PendingID string `json:"pending_id"`
	}
	mustUnmarshal(t, signOutput, &pendingResp)

	// Simulate a pre-migration row: clear the MAC. Approve must refuse
	// rather than silently downgrade to "no integrity check."
	if _, err := ts.db.DB.Exec(
		`UPDATE pending_signatures SET pending_mac = NULL WHERE id = ?`,
		pendingResp.PendingID,
	); err != nil {
		t.Fatalf("clearing MAC: %v", err)
	}

	approveOutput, _ := sshClient(t, ts.addr, signer, "approve --id "+pendingResp.PendingID+" --confirm")
	var approveResp struct {
		Signature string `json:"signature"`
		Error     string `json:"error"`
	}
	mustUnmarshal(t, approveOutput, &approveResp)
	if approveResp.Signature != "" {
		t.Fatal("approve produced a signature against a row with no MAC")
	}
	if !strings.Contains(approveResp.Error, "integrity check failed") {
		t.Errorf("expected integrity error, got: %q", approveResp.Error)
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
	mustUnmarshal(t, signOutput, &pendingResp)

	// Deny
	denyOutput, _ := sshClient(t, ts.addr, signer, "deny --id "+pendingResp.PendingID)

	var denyResp struct {
		Status    string `json:"status"`
		PendingID string `json:"pending_id"`
	}
	mustUnmarshal(t, denyOutput, &denyResp)

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
	mustUnmarshal(t, signOutput, &pendingResp)

	// Revoke the signing key
	storage.RevokeSigningKey(context.Background(), ts.db.DB, keyID)

	// Try to approve - should fail (key was revoked)
	approveOutput, _ := sshClient(t, ts.addr, signer, "approve --id "+pendingResp.PendingID+" --confirm")

	var resp struct {
		Error string `json:"error"`
	}
	mustUnmarshal(t, approveOutput, &resp)

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
	mustUnmarshal(t, signOutput, &pendingResp)

	// User B tries to approve
	signerB, _ := generateTestSSHKey(t)
	sshClient(t, ts.addr, signerB, "") // create user B

	approveOutput, _ := sshClient(t, ts.addr, signerB, "approve --id "+pendingResp.PendingID+" --confirm")

	var resp struct {
		Error string `json:"error"`
	}
	mustUnmarshal(t, approveOutput, &resp)

	if !strings.Contains(resp.Error, "principal") {
		t.Errorf("expected principal error, got: %s", resp.Error)
	}
}
