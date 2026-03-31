package audit

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// MemoryLogger is an in-memory audit logger for testing and development.
// It provides the same interface as ImmuDBLogger but stores entries in memory.
type MemoryLogger struct {
	mu      sync.RWMutex
	entries map[string][]byte
	txSeq   atomic.Uint64
	healthy atomic.Bool
}

func NewMemoryLogger() *MemoryLogger {
	l := &MemoryLogger{
		entries: make(map[string][]byte),
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

	data, err := MarshalEntry(entry)
	if err != nil {
		return 0, fmt.Errorf("marshaling audit entry: %w", err)
	}

	key := EntryKey(entry.ActionType, txID)

	l.mu.Lock()
	l.entries[key] = data
	l.mu.Unlock()

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
	_, ok := l.entries[key]
	l.mu.RUnlock()

	if !ok {
		return false, fmt.Errorf("audit entry not found: %s", key)
	}

	// In-memory logger always verifies (no tamper possible)
	return true, nil
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
