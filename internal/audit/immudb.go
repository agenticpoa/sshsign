package audit

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	immudb "github.com/codenotary/immudb/pkg/client"
)

// ImmuDBLogger is the production audit logger backed by immudb.
type ImmuDBLogger struct {
	client  immudb.ImmuClient
	healthy atomic.Bool
	mu      sync.Mutex
	txSeq   atomic.Uint64
}

// ImmuDBConfig holds connection parameters for immudb.
type ImmuDBConfig struct {
	Address  string // e.g. "127.0.0.1"
	Port     int    // e.g. 3322
	Username string // e.g. "immudb"
	Password string // e.g. "immudb"
	Database string // e.g. "defaultdb"
}

// NewImmuDBLogger connects to immudb and returns a Logger implementation.
func NewImmuDBLogger(cfg ImmuDBConfig) (*ImmuDBLogger, error) {
	opts := immudb.DefaultOptions().
		WithAddress(cfg.Address).
		WithPort(cfg.Port).
		WithHeartBeatFrequency(1 * time.Minute)

	client := immudb.NewClient().WithOptions(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := client.OpenSession(ctx, []byte(cfg.Username), []byte(cfg.Password), cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("opening immudb session: %w", err)
	}

	l := &ImmuDBLogger{client: client}
	l.healthy.Store(true)

	go l.healthCheckLoop()

	return l, nil
}

func (l *ImmuDBLogger) Log(entry Entry) (uint64, error) {
	if !l.healthy.Load() {
		return 0, fmt.Errorf("immudb is unhealthy: audit logging unavailable")
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
	defer l.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hdr, err := l.client.VerifiedSet(ctx, []byte(key), data)
	if err != nil {
		l.healthy.Store(false)
		return 0, fmt.Errorf("writing to immudb: %w", err)
	}

	return hdr.Id, nil
}

func (l *ImmuDBLogger) Get(key string) (*Entry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	entry, err := l.client.VerifiedGet(ctx, []byte(key))
	if err != nil {
		return nil, fmt.Errorf("reading from immudb: %w", err)
	}

	return UnmarshalEntry(entry.Value)
}

func (l *ImmuDBLogger) Verify(key string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := l.client.VerifiedGet(ctx, []byte(key))
	if err != nil {
		return false, fmt.Errorf("verification failed: %w", err)
	}

	return true, nil
}

func (l *ImmuDBLogger) Healthy() bool {
	return l.healthy.Load()
}

func (l *ImmuDBLogger) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return l.client.CloseSession(ctx)
}

func (l *ImmuDBLogger) healthCheckLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := l.client.HealthCheck(ctx)
		cancel()

		wasHealthy := l.healthy.Load()
		l.healthy.Store(err == nil)

		if wasHealthy && err != nil {
			fmt.Printf("immudb health check failed: %v\n", err)
		} else if !wasHealthy && err == nil {
			fmt.Println("immudb health check recovered")
		}
	}
}
