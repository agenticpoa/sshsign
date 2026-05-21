// Package ratelimit provides per-key rate-limiting primitives shared
// across packages. The Limiter interface lets callers stay agnostic to
// the underlying algorithm; pick TokenBucket for bursty traffic that
// should average out over time, or SlidingWindow for honest "max N
// requests per period" semantics that can't be gamed with bursts.
package ratelimit

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ErrRateLimit is the sentinel returned by Limiter.Allow when a request
// is rejected. Callers compare with errors.Is so wrappers carrying
// extra context still match.
var ErrRateLimit = errors.New("rate limit exceeded")

// Limiter rejects requests for a given key when usage exceeds policy.
// Returning an error rather than a bool lets implementations report
// the cause (current window count, retry-after hints, etc.) without
// breaking the call site.
type Limiter interface {
	Allow(key string) error
}

// ──────────────────────────────────────────────────────────────
// Token bucket
// ──────────────────────────────────────────────────────────────

// TokenBucket is a per-key token-bucket limiter backed by
// golang.org/x/time/rate. Suited to traffic patterns where short
// bursts are expected and an average rate is the real cap.
type TokenBucket struct {
	mu       sync.Mutex
	limiters map[string]*tokenBucketEntry
	rate     rate.Limit
	burst    int
	now      func() time.Time
}

type tokenBucketEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewTokenBucket builds a token-bucket limiter at rps requests per
// second with the given burst capacity. A background goroutine evicts
// per-key state that has been idle for two hours so memory doesn't
// grow unbounded under churning keys.
func NewTokenBucket(rps float64, burst int) *TokenBucket {
	tb := &TokenBucket{
		limiters: make(map[string]*tokenBucketEntry),
		rate:     rate.Limit(rps),
		burst:    burst,
		now:      time.Now,
	}
	go tb.cleanupLoop()
	return tb
}

// Allow returns nil if key is under quota, ErrRateLimit otherwise.
func (tb *TokenBucket) Allow(key string) error {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	entry, ok := tb.limiters[key]
	if !ok {
		entry = &tokenBucketEntry{
			limiter: rate.NewLimiter(tb.rate, tb.burst),
		}
		tb.limiters[key] = entry
	}
	entry.lastSeen = tb.now()

	if !entry.limiter.Allow() {
		return fmt.Errorf("%w: token bucket exhausted for key", ErrRateLimit)
	}
	return nil
}

func (tb *TokenBucket) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		tb.mu.Lock()
		cutoff := tb.now().Add(-2 * time.Hour)
		for key, entry := range tb.limiters {
			if entry.lastSeen.Before(cutoff) {
				delete(tb.limiters, key)
			}
		}
		tb.mu.Unlock()
	}
}

// ──────────────────────────────────────────────────────────────
// Sliding window
// ──────────────────────────────────────────────────────────────

// SlidingWindow counts calls in a moving time window and rejects once
// the window is full. Honest "max N requests per period" semantics —
// no burst escape hatch like the token bucket has.
type SlidingWindow struct {
	mu      sync.Mutex
	windows map[string]*slidingWindowEntry
	limit   int
	period  time.Duration

	// Injectable for tests.
	now func() time.Time
}

type slidingWindowEntry struct {
	timestamps []time.Time
}

// NewSlidingWindow returns a limiter capped at limit calls per period
// per key. Window is fully sliding — every recorded timestamp older
// than period is forgotten on the next Allow for that key.
func NewSlidingWindow(limit int, period time.Duration) *SlidingWindow {
	return &SlidingWindow{
		windows: make(map[string]*slidingWindowEntry),
		limit:   limit,
		period:  period,
		now:     time.Now,
	}
}

// Allow returns nil if key is under quota; otherwise an error wrapping
// ErrRateLimit with the current count and window size for diagnostics.
// Records the current call so repeated callers get incrementally rejected.
func (l *SlidingWindow) Allow(key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	cutoff := now.Add(-l.period)

	w, ok := l.windows[key]
	if !ok {
		w = &slidingWindowEntry{}
		l.windows[key] = w
	}

	// Drop expired timestamps from the head of the window.
	i := 0
	for ; i < len(w.timestamps); i++ {
		if !w.timestamps[i].Before(cutoff) {
			break
		}
	}
	if i > 0 {
		w.timestamps = w.timestamps[i:]
	}

	if len(w.timestamps) >= l.limit {
		return fmt.Errorf("%w: %d calls in the past %s (max %d)",
			ErrRateLimit, len(w.timestamps), l.period, l.limit)
	}
	w.timestamps = append(w.timestamps, now)
	return nil
}

// SetClockForTesting installs a deterministic clock. Test-only.
func (l *SlidingWindow) SetClockForTesting(now func() time.Time) {
	l.now = now
}
