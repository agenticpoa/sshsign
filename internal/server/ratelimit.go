package server

import (
	"github.com/agenticpoa/sshsign/internal/ratelimit"
)

// ServerRateLimits bundles the rate limiters the SSH server applies
// across handlers. All entries satisfy ratelimit.Limiter so handlers
// can call Allow(key) uniformly and treat any non-nil return as a
// reject — see ratelimit.ErrRateLimit.
type ServerRateLimits struct {
	// Per-IP connection rate limiting (10 connections/min)
	Connections ratelimit.Limiter
	// Per-IP auth failure rate limiting (5 failures/min)
	AuthFailures ratelimit.Limiter
	// Per-key signing rate limiting (100/hour, burst 10)
	SigningRequests ratelimit.Limiter
	// Per-key provisioning/session/offer limits for hosted demo safety.
	KeyCreation     ratelimit.Limiter
	SessionMutation ratelimit.Limiter
	OfferMutation   ratelimit.Limiter
}

func NewServerRateLimits() *ServerRateLimits {
	return &ServerRateLimits{
		Connections:     ratelimit.NewTokenBucket(10.0/60.0, 10),    // 10/min, burst 10
		AuthFailures:    ratelimit.NewTokenBucket(5.0/60.0, 5),      // 5/min, burst 5
		SigningRequests: ratelimit.NewTokenBucket(100.0/3600.0, 10), // 100/hour, burst 10
		KeyCreation:     ratelimit.NewTokenBucket(40.0/3600.0, 8),   // 40/hour, burst 8
		SessionMutation: ratelimit.NewTokenBucket(120.0/3600.0, 12), // 120/hour, burst 12
		OfferMutation:   ratelimit.NewTokenBucket(240.0/3600.0, 20), // 240/hour, burst 20
	}
}
