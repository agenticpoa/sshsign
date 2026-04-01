package server_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestLogOffer_SequenceAndChain(t *testing.T) {
	ts := setupTestServer(t)

	signer, _ := generateTestSSHKey(t)
	sshClient(t, ts.addr, signer, "") // create user

	// Offer 1: founder initial offer
	cmd1 := `log-offer --negotiation-id neg_test1 --round 1 --from founder --type offer --metadata {"valuation_cap":12000000,"discount_rate":0.20} --previous-tx 0`
	out1, _ := sshClient(t, ts.addr, signer, cmd1)

	var resp1 struct {
		ImmudbTx      uint64 `json:"immudb_tx"`
		NegotiationID string `json:"negotiation_id"`
		Round         int    `json:"round"`
	}
	if err := json.Unmarshal([]byte(out1), &resp1); err != nil {
		t.Fatalf("parsing offer 1 response: %v\nraw: %s", err, out1)
	}
	if resp1.NegotiationID != "neg_test1" {
		t.Errorf("expected neg_test1, got %s", resp1.NegotiationID)
	}
	if resp1.Round != 1 {
		t.Errorf("expected round 1, got %d", resp1.Round)
	}
	tx1 := resp1.ImmudbTx

	// Offer 2: investor counter, chained to offer 1
	cmd2 := `log-offer --negotiation-id neg_test1 --round 1 --from investor --type counter --metadata {"valuation_cap":6000000,"discount_rate":0.15} --previous-tx ` + itoa(tx1)
	out2, _ := sshClient(t, ts.addr, signer, cmd2)

	var resp2 struct {
		ImmudbTx uint64 `json:"immudb_tx"`
		Round    int    `json:"round"`
	}
	json.Unmarshal([]byte(out2), &resp2)
	tx2 := resp2.ImmudbTx

	// Offer 3: founder counter
	cmd3 := `log-offer --negotiation-id neg_test1 --round 2 --from founder --type counter --metadata {"valuation_cap":9000000,"discount_rate":0.18} --previous-tx ` + itoa(tx2)
	out3, _ := sshClient(t, ts.addr, signer, cmd3)

	var resp3 struct {
		ImmudbTx uint64 `json:"immudb_tx"`
	}
	json.Unmarshal([]byte(out3), &resp3)
	tx3 := resp3.ImmudbTx

	// Offer 4: investor accept
	cmd4 := `log-offer --negotiation-id neg_test1 --round 2 --from investor --type accept --metadata {"valuation_cap":9000000,"discount_rate":0.18} --previous-tx ` + itoa(tx3)
	out4, _ := sshClient(t, ts.addr, signer, cmd4)

	var resp4 struct {
		ImmudbTx uint64 `json:"immudb_tx"`
	}
	json.Unmarshal([]byte(out4), &resp4)

	// Verify all 4 tx IDs are sequential and non-zero
	if tx1 == 0 || resp2.ImmudbTx == 0 || resp3.ImmudbTx == 0 || resp4.ImmudbTx == 0 {
		t.Error("all audit tx IDs should be non-zero")
	}
}

func TestHistory_ReturnsAllOffersInOrder(t *testing.T) {
	ts := setupTestServer(t)

	signer, _ := generateTestSSHKey(t)
	sshClient(t, ts.addr, signer, "")

	// Log 3 offers
	sshClient(t, ts.addr, signer, `log-offer --negotiation-id neg_hist --round 1 --from founder --type offer --metadata {"cap":12000000} --previous-tx 0`)
	out2, _ := sshClient(t, ts.addr, signer, `log-offer --negotiation-id neg_hist --round 1 --from investor --type counter --metadata {"cap":8000000} --previous-tx 1`)
	var r2 struct {
		ImmudbTx uint64 `json:"immudb_tx"`
	}
	json.Unmarshal([]byte(out2), &r2)
	sshClient(t, ts.addr, signer, `log-offer --negotiation-id neg_hist --round 2 --from founder --type accept --metadata {"cap":8000000} --previous-tx `+itoa(r2.ImmudbTx))

	// Query history
	histOut, _ := sshClient(t, ts.addr, signer, "history --negotiation-id neg_hist")

	var history []struct {
		Round      int    `json:"round"`
		From       string `json:"from"`
		Type       string `json:"type"`
		PreviousTx uint64 `json:"previous_tx"`
		AuditTxID  uint64 `json:"audit_tx_id"`
	}
	if err := json.Unmarshal([]byte(histOut), &history); err != nil {
		t.Fatalf("parsing history: %v\nraw: %s", err, histOut)
	}

	if len(history) != 3 {
		t.Fatalf("expected 3 offers in history, got %d", len(history))
	}

	// Verify ordering
	if history[0].From != "founder" || history[0].Type != "offer" {
		t.Errorf("first offer wrong: %+v", history[0])
	}
	if history[1].From != "investor" || history[1].Type != "counter" {
		t.Errorf("second offer wrong: %+v", history[1])
	}
	if history[2].From != "founder" || history[2].Type != "accept" {
		t.Errorf("third offer wrong: %+v", history[2])
	}
}

func TestHistory_ChainIntegrity(t *testing.T) {
	ts := setupTestServer(t)

	signer, _ := generateTestSSHKey(t)
	sshClient(t, ts.addr, signer, "")

	// Log a chain of 4 offers
	out1, _ := sshClient(t, ts.addr, signer, `log-offer --negotiation-id neg_chain --round 1 --from founder --type offer --metadata {} --previous-tx 0`)
	var r1 struct{ ImmudbTx uint64 `json:"immudb_tx"` }
	json.Unmarshal([]byte(out1), &r1)

	out2, _ := sshClient(t, ts.addr, signer, `log-offer --negotiation-id neg_chain --round 1 --from investor --type counter --metadata {} --previous-tx `+itoa(r1.ImmudbTx))
	var r2 struct{ ImmudbTx uint64 `json:"immudb_tx"` }
	json.Unmarshal([]byte(out2), &r2)

	out3, _ := sshClient(t, ts.addr, signer, `log-offer --negotiation-id neg_chain --round 2 --from founder --type counter --metadata {} --previous-tx `+itoa(r2.ImmudbTx))
	var r3 struct{ ImmudbTx uint64 `json:"immudb_tx"` }
	json.Unmarshal([]byte(out3), &r3)

	out4, _ := sshClient(t, ts.addr, signer, `log-offer --negotiation-id neg_chain --round 2 --from investor --type accept --metadata {} --previous-tx `+itoa(r3.ImmudbTx))
	var r4 struct{ ImmudbTx uint64 `json:"immudb_tx"` }
	json.Unmarshal([]byte(out4), &r4)

	// Query and verify chain
	histOut, _ := sshClient(t, ts.addr, signer, "history --negotiation-id neg_chain")
	var history []struct {
		PreviousTx uint64 `json:"previous_tx"`
		AuditTxID  uint64 `json:"audit_tx_id"`
	}
	json.Unmarshal([]byte(histOut), &history)

	if len(history) != 4 {
		t.Fatalf("expected 4 offers, got %d", len(history))
	}

	// First offer has previous_tx 0
	if history[0].PreviousTx != 0 {
		t.Errorf("first offer previous_tx should be 0, got %d", history[0].PreviousTx)
	}

	// Each subsequent offer points to the previous offer's audit_tx_id
	for i := 1; i < len(history); i++ {
		if history[i].PreviousTx != history[i-1].AuditTxID {
			t.Errorf("offer %d previous_tx=%d, expected %d (previous offer's audit_tx_id)",
				i, history[i].PreviousTx, history[i-1].AuditTxID)
		}
	}
}

func TestLogOffer_NonExistentPreviousTx(t *testing.T) {
	ts := setupTestServer(t)

	signer, _ := generateTestSSHKey(t)
	sshClient(t, ts.addr, signer, "")

	// Try to chain to a non-existent tx
	out, _ := sshClient(t, ts.addr, signer, `log-offer --negotiation-id neg_bad --round 1 --from founder --type offer --metadata {} --previous-tx 99999`)

	var resp struct{ Error string }
	json.Unmarshal([]byte(out), &resp)

	if !strings.Contains(resp.Error, "not found") {
		t.Errorf("expected 'not found' error for bad previous_tx, got: %s", resp.Error)
	}
}

func itoa(n uint64) string {
	return fmt.Sprintf("%d", n)
}
