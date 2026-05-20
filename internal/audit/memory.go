package audit

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// MemoryLogger is an in-memory audit logger for testing and development.
// It provides the same interface as ImmuDBLogger but stores entries in
// memory and hashes them into a chain so tamper is detectable via
// [MemoryLogger.VerifyChain]. ImmuDBLogger gets tamper evidence from
// immudb's signed Merkle root instead and does not chain.
type MemoryLogger struct {
	mu       sync.RWMutex
	entries  map[string][]byte
	txSeq    atomic.Uint64
	healthy  atomic.Bool
	chainKey []byte
	tipHash  string // hex EntryHash of the most-recent committed entry; "" at genesis
}

// NewMemoryLogger returns an in-memory logger with a random per-instance
// chain key. The key is not persisted, so VerifyChain only works within
// the same process lifetime. For production-style chains that survive
// restarts, use NewMemoryLoggerWithChainKey with a deterministic key
// (e.g., DeriveChainKey from a stable server secret).
func NewMemoryLogger() *MemoryLogger {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// crypto/rand failing on a server is fatal; we don't return an
		// error here because NewMemoryLogger has never returned one and
		// all callsites would have to change. The audit log going down
		// is the right escalation if the OS entropy pool is broken.
		panic(fmt.Sprintf("audit: random chain key: %v", err))
	}
	return newMemoryLoggerWithKey(key)
}

// NewMemoryLoggerWithChainKey returns a logger keyed by chainKey. Use
// this when the chain must verify across process restarts — derive the
// key from a stable server secret (DeriveChainKey).
func NewMemoryLoggerWithChainKey(chainKey []byte) *MemoryLogger {
	if len(chainKey) == 0 {
		panic("audit: NewMemoryLoggerWithChainKey requires a non-empty key")
	}
	cp := make([]byte, len(chainKey))
	copy(cp, chainKey)
	return newMemoryLoggerWithKey(cp)
}

func newMemoryLoggerWithKey(chainKey []byte) *MemoryLogger {
	l := &MemoryLogger{
		entries:  make(map[string][]byte),
		chainKey: chainKey,
	}
	l.healthy.Store(true)
	return l
}

func (l *MemoryLogger) Log(entry Entry) (uint64, error) {
	if !l.healthy.Load() {
		return 0, fmt.Errorf("audit logger is unhealthy")
	}

	entry.Timestamp = time.Now()
	txID := l.txSeq.Add(1)
	entry.TxID = txID

	// Hold the lock for read-tip / compute / write-entry / update-tip
	// so concurrent Log() calls produce a well-defined chain.
	l.mu.Lock()
	defer l.mu.Unlock()

	entry.PrevHash = l.tipHash
	hash, err := computeEntryHash(l.chainKey, entry)
	if err != nil {
		return 0, err
	}
	entry.EntryHash = hash

	data, err := MarshalEntry(entry)
	if err != nil {
		return 0, fmt.Errorf("marshaling audit entry: %w", err)
	}

	key := EntryKey(entry.ActionType, txID)
	l.entries[key] = data
	l.tipHash = hash

	return txID, nil
}

func (l *MemoryLogger) Get(key string) (*Entry, error) {
	l.mu.RLock()
	data, ok := l.entries[key]
	l.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("audit entry not found: %s", key)
	}

	return UnmarshalEntry(data)
}

func (l *MemoryLogger) Verify(key string) (bool, error) {
	l.mu.RLock()
	data, ok := l.entries[key]
	l.mu.RUnlock()

	if !ok {
		return false, fmt.Errorf("audit entry not found: %s", key)
	}

	stored, err := UnmarshalEntry(data)
	if err != nil {
		return false, fmt.Errorf("unmarshaling entry: %w", err)
	}
	want, err := computeEntryHash(l.chainKey, *stored)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(stored.EntryHash), []byte(want)) == 1, nil
}

// VerifyChain walks every committed entry in TxID order and rejects
// the first break in the hash chain. Returns nil iff every entry's
// EntryHash matches HMAC(chainKey, canonical(entry)) and each entry's
// PrevHash equals the previous entry's EntryHash. Genesis is signaled
// by an empty PrevHash on the lowest-TxID entry.
func (l *MemoryLogger) VerifyChain() error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	type indexed struct {
		txID uint64
		raw  []byte
	}
	all := make([]indexed, 0, len(l.entries))
	for _, raw := range l.entries {
		e, err := UnmarshalEntry(raw)
		if err != nil {
			return fmt.Errorf("unmarshaling stored entry: %w", err)
		}
		all = append(all, indexed{e.TxID, raw})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].txID < all[j].txID })

	prev := ""
	for _, it := range all {
		e, err := UnmarshalEntry(it.raw)
		if err != nil {
			return fmt.Errorf("unmarshaling entry tx=%d: %w", it.txID, err)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("chain break at tx=%d: prev_hash=%q want=%q", e.TxID, e.PrevHash, prev)
		}
		want, err := computeEntryHash(l.chainKey, *e)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(e.EntryHash), []byte(want)) != 1 {
			return fmt.Errorf("entry_hash mismatch at tx=%d", e.TxID)
		}
		prev = e.EntryHash
	}
	return nil
}

// RewriteEntryForTest replaces an entry's stored bytes. Test-only —
// used to simulate a tamper attack so VerifyChain has something to
// catch. Lives on the exported surface because audit_test is a
// separate package.
func RewriteEntryForTest(l *MemoryLogger, key string, data []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries[key] = data
}

// DeleteEntryForTest removes an entry. Test-only.
func DeleteEntryForTest(l *MemoryLogger, key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// BumpTxSeqForTest fast-forwards the internal tx counter to id when a
// test reconstructs a logger from a previous instance's entries.
// Test-only.
func BumpTxSeqForTest(l *MemoryLogger, id uint64) {
	for l.txSeq.Load() < id {
		l.txSeq.Add(1)
	}
}

func (l *MemoryLogger) Healthy() bool {
	return l.healthy.Load()
}

func (l *MemoryLogger) Close() error {
	return nil
}

// SetHealthy allows tests to simulate immudb being up or down.
func (l *MemoryLogger) SetHealthy(healthy bool) {
	l.healthy.Store(healthy)
}

// Entries returns all logged entries for test assertions.
func (l *MemoryLogger) Entries() []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var result []Entry
	for _, data := range l.entries {
		e, err := UnmarshalEntry(data)
		if err == nil {
			result = append(result, *e)
		}
	}
	return result
}

// Count returns the number of logged entries.
func (l *MemoryLogger) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}
