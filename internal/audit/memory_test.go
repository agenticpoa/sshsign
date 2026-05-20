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

func TestMemoryLogger_ChainVerifies(t *testing.T) {
	l := audit.NewMemoryLogger()
	for i := 0; i < 5; i++ {
		_, err := l.Log(audit.Entry{
			ActionType:  "git-commit",
			Result:      "SIGNED",
			PayloadHash: string(rune('a' + i)),
		})
		if err != nil {
			t.Fatalf("logging entry %d: %v", i, err)
		}
	}
	if err := l.VerifyChain(); err != nil {
		t.Errorf("VerifyChain on untampered log: %v", err)
	}
}

func TestMemoryLogger_ChainDetectsModifiedEntry(t *testing.T) {
	l := audit.NewMemoryLogger()
	tx, _ := l.Log(audit.Entry{
		ActionType: "git-commit", Result: "SIGNED", PayloadHash: "real",
	})
	_, _ = l.Log(audit.Entry{ActionType: "git-commit", Result: "SIGNED", PayloadHash: "b"})

	// Tamper with the first entry's payload_hash by writing back a
	// modified marshaled blob. The recomputed EntryHash will no longer
	// match what's stored.
	key := audit.EntryKey("git-commit", tx)
	got, err := l.Get(key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got.PayloadHash = "tampered"
	data, _ := audit.MarshalEntry(*got)
	audit.RewriteEntryForTest(l, key, data)

	if err := l.VerifyChain(); err == nil {
		t.Error("VerifyChain accepted a modified entry")
	}
}

func TestMemoryLogger_ChainDetectsDeletedEntry(t *testing.T) {
	l := audit.NewMemoryLogger()
	_, _ = l.Log(audit.Entry{ActionType: "git-commit", Result: "SIGNED", PayloadHash: "a"})
	tx2, _ := l.Log(audit.Entry{ActionType: "git-commit", Result: "SIGNED", PayloadHash: "b"})
	_, _ = l.Log(audit.Entry{ActionType: "git-commit", Result: "SIGNED", PayloadHash: "c"})

	audit.DeleteEntryForTest(l, audit.EntryKey("git-commit", tx2))

	if err := l.VerifyChain(); err == nil {
		t.Error("VerifyChain accepted a chain with a missing entry")
	}
}

func TestMemoryLogger_VerifySingleEntryDetectsTamper(t *testing.T) {
	l := audit.NewMemoryLogger()
	tx, _ := l.Log(audit.Entry{
		ActionType: "git-commit", Result: "SIGNED", PayloadHash: "real",
	})
	key := audit.EntryKey("git-commit", tx)

	ok, err := l.Verify(key)
	if err != nil {
		t.Fatalf("verify clean: %v", err)
	}
	if !ok {
		t.Fatal("clean entry should verify")
	}

	got, _ := l.Get(key)
	got.Result = "DENIED"
	data, _ := audit.MarshalEntry(*got)
	audit.RewriteEntryForTest(l, key, data)

	ok, _ = l.Verify(key)
	if ok {
		t.Error("Verify accepted a tampered entry")
	}
}

func TestMemoryLogger_ChainSurvivesRestartWithSameKey(t *testing.T) {
	// Two loggers built with the same chain key produce verifiable
	// chains across the boundary — proving the chain ties to the key
	// material, not to a per-instance random value.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	l1 := audit.NewMemoryLoggerWithChainKey(key)
	tx, _ := l1.Log(audit.Entry{ActionType: "git-commit", Result: "SIGNED", PayloadHash: "x"})

	// Reconstruct a second logger with the same key; re-verifying the
	// first logger's entry uses the same HMAC, so it must succeed.
	l2 := audit.NewMemoryLoggerWithChainKey(key)
	entry, err := l1.Get(audit.EntryKey("git-commit", tx))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	// Stuff the entry into l2 at its original key so VerifyChain has
	// something to walk.
	data, _ := audit.MarshalEntry(*entry)
	audit.RewriteEntryForTest(l2, audit.EntryKey("git-commit", tx), data)
	audit.BumpTxSeqForTest(l2, tx)

	if err := l2.VerifyChain(); err != nil {
		t.Errorf("VerifyChain across logger boundary failed: %v", err)
	}
}
