package audit_test

import (
	"testing"

	"github.com/agenticpoa/sshsign/internal/audit"
)

func TestMemoryLogger_LogAndGet(t *testing.T) {
	l := audit.NewMemoryLogger()

	txID, err := l.Log(audit.Entry{
		UserID:       "u_test",
		SigningKeyID: "ak_test",
		ActionType:   "git-commit",
		PayloadHash:  "abc123",
		Result:       "SIGNED",
	})
	if err != nil {
		t.Fatalf("logging: %v", err)
	}
	if txID == 0 {
		t.Error("tx ID should not be 0")
	}

	key := audit.EntryKey("git-commit", txID)
	entry, err := l.Get(key)
	if err != nil {
		t.Fatalf("getting entry: %v", err)
	}
	if entry.UserID != "u_test" {
		t.Errorf("user_id = %q, want u_test", entry.UserID)
	}
	if entry.Result != "SIGNED" {
		t.Errorf("result = %q, want SIGNED", entry.Result)
	}
	if entry.TxID != txID {
		t.Errorf("tx_id = %d, want %d", entry.TxID, txID)
	}
}

func TestMemoryLogger_Verify(t *testing.T) {
	l := audit.NewMemoryLogger()

	txID, _ := l.Log(audit.Entry{
		ActionType: "git-commit",
		Result:     "SIGNED",
	})

	key := audit.EntryKey("git-commit", txID)
	valid, err := l.Verify(key)
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}
	if !valid {
		t.Error("expected valid verification")
	}

	// Nonexistent key should fail
	_, err = l.Verify("audit:git-commit:999999")
	if err == nil {
		t.Error("expected error for nonexistent entry")
	}
}

func TestMemoryLogger_Healthy(t *testing.T) {
	l := audit.NewMemoryLogger()

	if !l.Healthy() {
		t.Error("expected healthy on init")
	}

	l.SetHealthy(false)
	if l.Healthy() {
		t.Error("expected unhealthy after SetHealthy(false)")
	}

	// Logging should fail when unhealthy
	_, err := l.Log(audit.Entry{ActionType: "test", Result: "SIGNED"})
	if err == nil {
		t.Error("expected error when logging to unhealthy logger")
	}

	l.SetHealthy(true)
	if !l.Healthy() {
		t.Error("expected healthy after SetHealthy(true)")
	}
}

func TestMemoryLogger_DenialEntry(t *testing.T) {
	l := audit.NewMemoryLogger()

	txID, err := l.Log(audit.Entry{
		UserID:       "u_test",
		SigningKeyID: "ak_test",
		ActionType:   "git-commit",
		Result:       "DENIED",
		DenialReason: "hard rule: never sign to main branch",
	})
	if err != nil {
		t.Fatalf("logging denial: %v", err)
	}

	key := audit.EntryKey("git-commit", txID)
	entry, err := l.Get(key)
	if err != nil {
		t.Fatalf("getting entry: %v", err)
	}
	if entry.Result != "DENIED" {
		t.Errorf("result = %q, want DENIED", entry.Result)
	}
	if entry.DenialReason == "" {
		t.Error("denial reason should not be empty")
	}
}

func TestMemoryLogger_Count(t *testing.T) {
	l := audit.NewMemoryLogger()

	for i := range 5 {
		_, err := l.Log(audit.Entry{
			ActionType: "git-commit",
			Result:     "SIGNED",
			PayloadHash: string(rune('a' + i)),
		})
		if err != nil {
			t.Fatalf("logging entry %d: %v", i, err)
		}
	}

	if l.Count() != 5 {
		t.Errorf("count = %d, want 5", l.Count())
	}
}

func TestMemoryLogger_SequentialTxIDs(t *testing.T) {
	l := audit.NewMemoryLogger()

	tx1, _ := l.Log(audit.Entry{ActionType: "git-commit", Result: "SIGNED"})
	tx2, _ := l.Log(audit.Entry{ActionType: "git-commit", Result: "SIGNED"})
	tx3, _ := l.Log(audit.Entry{ActionType: "git-commit", Result: "DENIED"})

	if tx2 != tx1+1 || tx3 != tx2+1 {
		t.Errorf("tx IDs should be sequential: %d, %d, %d", tx1, tx2, tx3)
	}
}
