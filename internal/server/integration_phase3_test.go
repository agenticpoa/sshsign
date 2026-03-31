package server_test

import (
	"encoding/json"
	"testing"
)

func TestAuditEntryOnSign(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithSigningKeyAndAuth(t, ts,
		[]string{"git-commit"},
		map[string][]string{"repo": {"github.com/user/*"}},
		nil, nil,
	)

	before := ts.auditLog.Count()

	payload := []byte("test commit for audit")
	signCmd := "sign --type git-commit --key-id " + keyID + " --repo github.com/user/myrepo"
	output, err := sshClientWithStdin(t, ts.addr, signer, signCmd, payload)
	if err != nil {
		t.Logf("sign output: %s", output)
	}

	var signResp struct {
		AuditTxID uint64 `json:"audit_tx_id"`
		Error     string `json:"error"`
	}
	json.Unmarshal([]byte(output), &signResp)
	if signResp.Error != "" {
		t.Fatalf("sign returned error: %s", signResp.Error)
	}
	if signResp.AuditTxID == 0 {
		t.Error("expected non-zero audit tx ID")
	}

	after := ts.auditLog.Count()
	if after != before+1 {
		t.Errorf("expected 1 new audit entry, got %d", after-before)
	}

	// Verify the audit entry has correct fields
	entries := ts.auditLog.Entries()
	found := false
	for _, e := range entries {
		if e.TxID == signResp.AuditTxID {
			found = true
			if e.Result != "SIGNED" {
				t.Errorf("audit result = %q, want SIGNED", e.Result)
			}
			if e.ActionType != "git-commit" {
				t.Errorf("audit action_type = %q, want git-commit", e.ActionType)
			}
			if e.SigningKeyID != keyID {
				t.Errorf("audit signing_key_id = %q, want %s", e.SigningKeyID, keyID)
			}
			if e.PayloadHash == "" {
				t.Error("audit payload_hash should not be empty")
			}
			if e.Signature == "" {
				t.Error("audit signature should not be empty for SIGNED entries")
			}
		}
	}
	if !found {
		t.Errorf("audit entry with tx_id %d not found", signResp.AuditTxID)
	}
}

func TestAuditEntryOnDenial(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithSigningKeyAndAuth(t, ts,
		[]string{"git-commit"},
		map[string][]string{"repo": {"github.com/user/*"}},
		[]string{"never sign to main branch"},
		nil,
	)

	before := ts.auditLog.Count()

	payload := []byte("test commit denied")
	signCmd := "sign --type git-commit --key-id " + keyID + " --repo github.com/user/myrepo --branch main"
	sshClientWithStdin(t, ts.addr, signer, signCmd, payload)

	after := ts.auditLog.Count()
	if after != before+1 {
		t.Errorf("expected 1 new audit entry for denial, got %d", after-before)
	}

	entries := ts.auditLog.Entries()
	var denials int
	for _, e := range entries {
		if e.Result == "DENIED" {
			denials++
			if e.DenialReason == "" {
				t.Error("denial reason should not be empty")
			}
		}
	}
	if denials == 0 {
		t.Error("expected at least one DENIED audit entry")
	}
}

func TestAuditEntryOnRevoke(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithSigningKeyAndAuth(t, ts,
		[]string{"git-commit"}, nil, nil, nil,
	)

	before := ts.auditLog.Count()

	sshClient(t, ts.addr, signer, "revoke --key-id "+keyID)

	after := ts.auditLog.Count()
	if after != before+1 {
		t.Errorf("expected 1 new audit entry for revoke, got %d", after-before)
	}

	entries := ts.auditLog.Entries()
	var revokes int
	for _, e := range entries {
		if e.Result == "REVOKED" {
			revokes++
			if e.SigningKeyID != keyID {
				t.Errorf("revoke audit key_id = %q, want %s", e.SigningKeyID, keyID)
			}
		}
	}
	if revokes == 0 {
		t.Error("expected at least one REVOKED audit entry")
	}
}

func TestSignFailsWhenAuditUnhealthy(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithSigningKeyAndAuth(t, ts,
		[]string{"git-commit"}, nil, nil, nil,
	)

	// Make audit logger unhealthy
	ts.auditLog.SetHealthy(false)

	payload := []byte("test data")
	signCmd := "sign --type git-commit --key-id " + keyID
	output, _ := sshClientWithStdin(t, ts.addr, signer, signCmd, payload)

	var resp struct{ Error string }
	json.Unmarshal([]byte(output), &resp)
	if resp.Error == "" {
		t.Error("expected error when audit log is unhealthy")
	}
	t.Logf("unhealthy audit response: %s", resp.Error)

	// Restore health and verify signing works again
	ts.auditLog.SetHealthy(true)

	output2, _ := sshClientWithStdin(t, ts.addr, signer, signCmd, payload)
	var resp2 struct {
		Signature string `json:"signature"`
		Error     string `json:"error"`
	}
	json.Unmarshal([]byte(output2), &resp2)
	if resp2.Error != "" {
		t.Errorf("expected signing to work after audit recovery, got: %s", resp2.Error)
	}
	if resp2.Signature == "" {
		t.Error("expected signature after audit recovery")
	}
}

func TestAuditNoGapsUnderLoad(t *testing.T) {
	ts := setupTestServer(t)

	signer, _, keyID := setupUserWithSigningKeyAndAuth(t, ts,
		[]string{"git-commit"}, nil, nil, nil,
	)

	// Send 10 sequential sign requests (within rate limit burst of 10)
	for i := range 10 {
		payload := []byte("commit " + string(rune('A'+i)))
		signCmd := "sign --type git-commit --key-id " + keyID
		output, _ := sshClientWithStdin(t, ts.addr, signer, signCmd, payload)

		var resp struct{ Error string }
		json.Unmarshal([]byte(output), &resp)
		if resp.Error != "" {
			t.Fatalf("sign %d failed: %s", i, resp.Error)
		}
	}

	count := ts.auditLog.Count()
	if count != 10 {
		t.Errorf("expected 10 audit entries, got %d (gaps detected)", count)
	}
}
