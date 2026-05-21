package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// noopHandler is a handler that always returns 200 OK; used as the
// inner handler when exercising middleware in isolation.
var noopHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestRateLimit_AllowsUpToCap(t *testing.T) {
	h := rateLimit(noopHandler)
	for i := 0; i < 30; i++ {
		req := httptest.NewRequest("GET", "/approve/x", nil)
		req.RemoteAddr = "1.2.3.4:5678"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d/30: got %d, want 200", i+1, w.Code)
		}
	}
}

func TestRateLimit_RejectsOverCap(t *testing.T) {
	h := rateLimit(noopHandler)
	for i := 0; i < 30; i++ {
		req := httptest.NewRequest("GET", "/approve/x", nil)
		req.RemoteAddr = "1.2.3.4:5678"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
	}
	// 31st request must be rejected.
	req := httptest.NewRequest("GET", "/approve/x", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("31st request: got %d, want 429", w.Code)
	}
}

func TestRateLimit_PerIPIsolation(t *testing.T) {
	h := rateLimit(noopHandler)
	// Fill alice's quota.
	for i := 0; i < 30; i++ {
		req := httptest.NewRequest("GET", "/approve/x", nil)
		req.RemoteAddr = "10.0.0.1:1111"
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	// alice is over.
	req := httptest.NewRequest("GET", "/approve/x", nil)
	req.RemoteAddr = "10.0.0.1:1111"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("alice should be limited, got %d", w.Code)
	}

	// bob from a different IP still has full quota.
	req = httptest.NewRequest("GET", "/approve/x", nil)
	req.RemoteAddr = "10.0.0.2:2222"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("bob should be allowed, got %d", w.Code)
	}
}

func TestRateLimit_HealthBypass(t *testing.T) {
	h := rateLimit(noopHandler)
	// Hammer /health well past the limit — none should be rejected.
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest("GET", "/health", nil)
		req.RemoteAddr = "1.2.3.4:5678"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("health check %d: got %d, want 200", i+1, w.Code)
		}
	}
}

func TestRateLimit_HonorsXForwardedFor(t *testing.T) {
	// Two clients sharing one proxy IP but with distinct XFF headers
	// should not interfere with each other.
	h := rateLimit(noopHandler)
	for i := 0; i < 30; i++ {
		req := httptest.NewRequest("GET", "/approve/x", nil)
		req.RemoteAddr = "127.0.0.1:1234" // proxy
		req.Header.Set("X-Forwarded-For", "203.0.113.1")
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	// 203.0.113.1 is at the cap.
	req := httptest.NewRequest("GET", "/approve/x", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("203.0.113.1 should be limited, got %d", w.Code)
	}

	// 203.0.113.2 from same proxy is still allowed.
	req = httptest.NewRequest("GET", "/approve/x", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.2")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("203.0.113.2 should be independent, got %d", w.Code)
	}
}
