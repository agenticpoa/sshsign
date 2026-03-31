package server

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter provides per-key rate limiting with automatic cleanup of stale entries.
type RateLimiter struct {
	mu       sync.RWMutex
	limiters map[string]*limiterEntry
	rate     rate.Limit
	burst    int
}

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewRateLimiter(rps float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*limiterEntry),
		rate:     rate.Limit(rps),
		burst:    burst,
	}

	// Cleanup stale entries every hour
	go rl.cleanup()

	return rl
}

// Allow checks if the given key is within its rate limit.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, ok := rl.limiters[key]
	if !ok {
		entry = &limiterEntry{
			limiter:  rate.NewLimiter(rl.rate, rl.burst),
			lastSeen: time.Now(),
		}
		rl.limiters[key] = entry
	}
	entry.lastSeen = time.Now()

	return entry.limiter.Allow()
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-2 * time.Hour)
		for key, entry := range rl.limiters {
			if entry.lastSeen.Before(cutoff) {
				delete(rl.limiters, key)
			}
		}
		rl.mu.Unlock()
	}
}

// ServerRateLimits holds the rate limiters for different server-level limits.
type ServerRateLimits struct {
	// Per-IP connection rate limiting (10 connections/min)
	Connections *RateLimiter
	// Per-IP auth failure rate limiting (5 failures/min)
	AuthFailures *RateLimiter
	// Per-key signing rate limiting (100/hour = ~0.028/sec)
	SigningRequests *RateLimiter
}

func NewServerRateLimits() *ServerRateLimits {
	return &ServerRateLimits{
		Connections:    NewRateLimiter(10.0/60.0, 10),     // 10/min, burst 10
		AuthFailures:   NewRateLimiter(5.0/60.0, 5),       // 5/min, burst 5
		SigningRequests: NewRateLimiter(100.0/3600.0, 10),  // 100/hour, burst 10
	}
}
