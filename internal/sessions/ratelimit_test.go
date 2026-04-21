package sessions

import (
	"errors"
	"testing"
	"time"
)

func newFixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestGetSessionRateLimiter_AllowsUnderLimit(t *testing.T) {
	l := NewGetSessionRateLimiter()
	for i := 0; i < MaxGetSessionCallsPerHour; i++ {
		if err := l.Allow("alice"); err != nil {
			t.Fatalf("call %d: expected nil, got %v", i, err)
		}
	}
}

func TestGetSessionRateLimiter_RejectsOverLimit(t *testing.T) {
	l := NewGetSessionRateLimiter()
	for i := 0; i < MaxGetSessionCallsPerHour; i++ {
		_ = l.Allow("alice")
	}
	err := l.Allow("alice")
	if !errors.Is(err, ErrRateLimit) {
		t.Errorf("err = %v, want ErrRateLimit", err)
	}
}

func TestGetSessionRateLimiter_PerUserIsolation(t *testing.T) {
	l := NewGetSessionRateLimiter()
	for i := 0; i < MaxGetSessionCallsPerHour; i++ {
		_ = l.Allow("alice")
	}
	// Alice is over, but Bob still has full quota.
	if err := l.Allow("bob"); err != nil {
		t.Errorf("bob should be allowed, got: %v", err)
	}
	if !errors.Is(l.Allow("alice"), ErrRateLimit) {
		t.Error("alice should still be blocked")
	}
}

func TestGetSessionRateLimiter_SlidingWindowDropsExpired(t *testing.T) {
	l := NewGetSessionRateLimiter()
	base := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
	l.now = newFixedClock(base)

	// Fill the window.
	for i := 0; i < MaxGetSessionCallsPerHour; i++ {
		_ = l.Allow("alice")
	}
	if !errors.Is(l.Allow("alice"), ErrRateLimit) {
		t.Fatal("expected limit at t=0")
	}

	// Advance past the window; old timestamps should expire.
	l.now = newFixedClock(base.Add(time.Hour + time.Second))
	if err := l.Allow("alice"); err != nil {
		t.Errorf("after window expiry, expected allowed; got %v", err)
	}
}

func TestGetSessionRateLimiter_PartialWindowExpiry(t *testing.T) {
	l := NewGetSessionRateLimiter()
	base := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
	l.now = newFixedClock(base)

	// Fill half the quota.
	half := MaxGetSessionCallsPerHour / 2
	for i := 0; i < half; i++ {
		_ = l.Allow("alice")
	}

	// Advance 30 min, fill the other half.
	l.now = newFixedClock(base.Add(30 * time.Minute))
	for i := 0; i < MaxGetSessionCallsPerHour-half; i++ {
		_ = l.Allow("alice")
	}
	if !errors.Is(l.Allow("alice"), ErrRateLimit) {
		t.Fatal("expected limit when window is full")
	}

	// Advance another 31 min — first-half timestamps expire.
	l.now = newFixedClock(base.Add(61 * time.Minute))
	if err := l.Allow("alice"); err != nil {
		t.Errorf("half the window should have expired; got %v", err)
	}
}
