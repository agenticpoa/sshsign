package ratelimit_test

import (
	"errors"
	"testing"
	"time"

	"github.com/agenticpoa/sshsign/internal/ratelimit"
)

func TestTokenBucket_AllowsUnderBurst(t *testing.T) {
	tb := ratelimit.NewTokenBucket(1.0, 5) // 1/sec, burst 5
	for i := 0; i < 5; i++ {
		if err := tb.Allow("alice"); err != nil {
			t.Fatalf("call %d: expected allowed, got %v", i, err)
		}
	}
}

func TestTokenBucket_RejectsOverBurst(t *testing.T) {
	tb := ratelimit.NewTokenBucket(1.0/3600.0, 3) // 1/hour, burst 3
	for i := 0; i < 3; i++ {
		_ = tb.Allow("alice")
	}
	err := tb.Allow("alice")
	if !errors.Is(err, ratelimit.ErrRateLimit) {
		t.Errorf("err = %v, want ErrRateLimit", err)
	}
}

func TestTokenBucket_PerKeyIsolation(t *testing.T) {
	tb := ratelimit.NewTokenBucket(1.0/3600.0, 2)
	for i := 0; i < 2; i++ {
		_ = tb.Allow("alice")
	}
	if !errors.Is(tb.Allow("alice"), ratelimit.ErrRateLimit) {
		t.Fatal("expected alice to be limited")
	}
	if err := tb.Allow("bob"); err != nil {
		t.Errorf("bob should be allowed independently, got %v", err)
	}
}

func TestSlidingWindow_AllowsUnderLimit(t *testing.T) {
	l := ratelimit.NewSlidingWindow(10, time.Hour)
	for i := 0; i < 10; i++ {
		if err := l.Allow("alice"); err != nil {
			t.Fatalf("call %d: expected nil, got %v", i, err)
		}
	}
}

func TestSlidingWindow_RejectsOverLimit(t *testing.T) {
	l := ratelimit.NewSlidingWindow(5, time.Hour)
	for i := 0; i < 5; i++ {
		_ = l.Allow("alice")
	}
	if !errors.Is(l.Allow("alice"), ratelimit.ErrRateLimit) {
		t.Error("expected ErrRateLimit on 6th call")
	}
}

func TestSlidingWindow_PerKeyIsolation(t *testing.T) {
	l := ratelimit.NewSlidingWindow(3, time.Hour)
	for i := 0; i < 3; i++ {
		_ = l.Allow("alice")
	}
	if err := l.Allow("bob"); err != nil {
		t.Errorf("bob should be allowed, got %v", err)
	}
	if !errors.Is(l.Allow("alice"), ratelimit.ErrRateLimit) {
		t.Error("alice should still be limited")
	}
}

func TestSlidingWindow_DropsExpiredTimestamps(t *testing.T) {
	l := ratelimit.NewSlidingWindow(3, time.Hour)
	base := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
	l.SetClockForTesting(func() time.Time { return base })

	for i := 0; i < 3; i++ {
		_ = l.Allow("alice")
	}
	if !errors.Is(l.Allow("alice"), ratelimit.ErrRateLimit) {
		t.Fatal("expected limit at t=0")
	}

	// Advance past the window.
	l.SetClockForTesting(func() time.Time { return base.Add(time.Hour + time.Second) })
	if err := l.Allow("alice"); err != nil {
		t.Errorf("after window expiry, expected allowed; got %v", err)
	}
}

func TestSlidingWindow_PartialWindowExpiry(t *testing.T) {
	l := ratelimit.NewSlidingWindow(10, time.Hour)
	base := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
	l.SetClockForTesting(func() time.Time { return base })

	// Fill half the quota at t=0.
	for i := 0; i < 5; i++ {
		_ = l.Allow("alice")
	}
	// Fill the other half at t=30min.
	l.SetClockForTesting(func() time.Time { return base.Add(30 * time.Minute) })
	for i := 0; i < 5; i++ {
		_ = l.Allow("alice")
	}
	if !errors.Is(l.Allow("alice"), ratelimit.ErrRateLimit) {
		t.Fatal("expected limit when window is full")
	}

	// Advance to t=61min — first batch expires, second batch survives.
	l.SetClockForTesting(func() time.Time { return base.Add(61 * time.Minute) })
	if err := l.Allow("alice"); err != nil {
		t.Errorf("half the window should have expired; got %v", err)
	}
}

func TestLimiterInterface_Satisfied(t *testing.T) {
	// Compile-time assertion that both implementations satisfy Limiter.
	var _ ratelimit.Limiter = ratelimit.NewTokenBucket(1.0, 1)
	var _ ratelimit.Limiter = ratelimit.NewSlidingWindow(1, time.Hour)
}
