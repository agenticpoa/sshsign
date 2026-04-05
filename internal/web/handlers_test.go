package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/storage"
)

func newTestDB(t *testing.T) *storage.TestDB {
	t.Helper()
	tdb, err := storage.NewTestDB()
	if err != nil {
		t.Fatalf("opening test database: %v", err)
	}
	t.Cleanup(func() { tdb.Close() })
	return tdb
}

func setupTest(t *testing.T) (*Server, *storage.PendingSignature) {
	t.Helper()
	tdb := newTestDB(t)

	kek, _ := crypto.DeriveKEK("test-secret")
	srv := New(":0", tdb.DB, kek)

	// Create user, key, auth, pending
	user, _, _ := storage.CreateUser(tdb.DB, "SHA256:testfp", "ssh-ed25519 testkey")
	pub, priv, _ := crypto.GenerateEd25519Keypair()
	pubSSH, _ := crypto.MarshalPublicKeySSH(pub)
	dek, _ := crypto.GenerateDEK()
	encPriv, _ := crypto.EncryptPrivateKey(priv, dek)
	wrappedDEK, _ := crypto.WrapDEK(dek, kek)
	sk, _ := storage.CreateSigningKey(tdb.DB, user.UserID, pubSSH, encPriv, wrappedDEK)

	auth, _ := storage.CreateAuthorizationFull(tdb.DB, sk.KeyID, user.UserID,
		[]string{"safe-agreement"}, nil, nil, "cosign", true, nil, nil, nil)

	ps, _ := storage.CreatePendingSignature(tdb.DB, sk.KeyID, auth.TokenID, user.UserID,
		"safe-agreement", "sha256:deadbeef", `{"valuation_cap": 10000000}`, "testtoken123", "")

	return srv, ps
}

func TestGetApproval_InvalidPendingID(t *testing.T) {
	tdb := newTestDB(t)
	srv := New(":0", tdb.DB, []byte("k"))

	req := httptest.NewRequest("GET", "/approve/invalid!id?token=abc", nil)
	req.SetPathValue("pendingID", "invalid!id")
	w := httptest.NewRecorder()
	srv.handleGetApproval(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestGetApproval_NotFound(t *testing.T) {
	tdb := newTestDB(t)
	srv := New(":0", tdb.DB, []byte("k"))

	req := httptest.NewRequest("GET", "/approve/pnd_000000000000?token=abc", nil)
	req.SetPathValue("pendingID", "pnd_000000000000")
	w := httptest.NewRecorder()
	srv.handleGetApproval(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestGetApproval_WrongToken(t *testing.T) {
	srv, ps := setupTest(t)

	req := httptest.NewRequest("GET", "/approve/"+ps.ID+"?token=wrong", nil)
	req.SetPathValue("pendingID", ps.ID)
	w := httptest.NewRecorder()
	srv.handleGetApproval(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestGetApproval_ValidToken(t *testing.T) {
	srv, ps := setupTest(t)

	req := httptest.NewRequest("GET", "/approve/"+ps.ID+"?token=testtoken123", nil)
	req.SetPathValue("pendingID", ps.ID)
	w := httptest.NewRecorder()
	srv.handleGetApproval(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Review &amp; Sign") {
		t.Error("expected approval page HTML")
	}
}

func TestGetApproval_AlreadyResolved(t *testing.T) {
	srv, ps := setupTest(t)
	storage.ResolvePendingSignature(srv.db, ps.ID, "approved", "u_test", "")

	req := httptest.NewRequest("GET", "/approve/"+ps.ID+"?token=testtoken123", nil)
	req.SetPathValue("pendingID", ps.ID)
	w := httptest.NewRecorder()
	srv.handleGetApproval(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "already been") {
		t.Error("expected already-done page")
	}
}

func TestPostApproval_WrongToken(t *testing.T) {
	srv, ps := setupTest(t)

	body := `{"signature_image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="}`
	req := httptest.NewRequest("POST", "/approve/"+ps.ID+"?token=wrong", strings.NewReader(body))
	req.SetPathValue("pendingID", ps.ID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handlePostApproval(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestPostApproval_EmptyImage(t *testing.T) {
	srv, ps := setupTest(t)

	body := `{"signature_image": ""}`
	req := httptest.NewRequest("POST", "/approve/"+ps.ID+"?token=testtoken123", strings.NewReader(body))
	req.SetPathValue("pendingID", ps.ID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handlePostApproval(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestPostApproval_InvalidPNG(t *testing.T) {
	srv, ps := setupTest(t)

	// "notapng" base64 encoded
	body := `{"signature_image": "data:image/png;base64,bm90YXBuZw=="}`
	req := httptest.NewRequest("POST", "/approve/"+ps.ID+"?token=testtoken123", strings.NewReader(body))
	req.SetPathValue("pendingID", ps.ID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handlePostApproval(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid PNG, got %d", w.Code)
	}
}

func TestPostApproval_AlreadyResolved(t *testing.T) {
	srv, ps := setupTest(t)
	storage.ResolvePendingSignature(srv.db, ps.ID, "denied", "someone", "")

	body := `{"signature_image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="}`
	req := httptest.NewRequest("POST", "/approve/"+ps.ID+"?token=testtoken123", strings.NewReader(body))
	req.SetPathValue("pendingID", ps.ID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handlePostApproval(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", w.Code)
	}
}

func TestPostApproval_SQLInjection(t *testing.T) {
	tdb := newTestDB(t)
	srv := New(":0", tdb.DB, []byte("k"))

	req := httptest.NewRequest("POST", "/approve/test", strings.NewReader("{}"))
	req.SetPathValue("pendingID", "pnd_x'; DROP TABLE")
	w := httptest.NewRecorder()
	srv.handlePostApproval(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	checks := map[string]string{
		"Content-Security-Policy": "default-src 'self'",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
	}
	for header, expected := range checks {
		if got := w.Header().Get(header); !strings.Contains(got, expected) {
			t.Errorf("%s: expected to contain %q, got %q", header, expected, got)
		}
	}
}

func TestGetApproval_XSSEscaping(t *testing.T) {
	tdb := newTestDB(t)
	kek, _ := crypto.DeriveKEK("test-secret")
	srv := New(":0", tdb.DB, kek)

	user, _, _ := storage.CreateUser(tdb.DB, "SHA256:xssfp", "ssh-ed25519 xsskey")
	pub, priv, _ := crypto.GenerateEd25519Keypair()
	pubSSH, _ := crypto.MarshalPublicKeySSH(pub)
	dek, _ := crypto.GenerateDEK()
	encPriv, _ := crypto.EncryptPrivateKey(priv, dek)
	wrappedDEK, _ := crypto.WrapDEK(dek, kek)
	sk, _ := storage.CreateSigningKey(tdb.DB, user.UserID, pubSSH, encPriv, wrappedDEK)
	auth, _ := storage.CreateAuthorizationFull(tdb.DB, sk.KeyID, user.UserID,
		[]string{"safe"}, nil, nil, "cosign", true, nil, nil, nil)

	xss := `{"<script>alert(1)</script>": "xss"}`
	ps, _ := storage.CreatePendingSignature(tdb.DB, sk.KeyID, auth.TokenID, user.UserID,
		"safe", "sha256:test", xss, "xsstoken", "")

	req := httptest.NewRequest("GET", "/approve/"+ps.ID+"?token=xsstoken", nil)
	req.SetPathValue("pendingID", ps.ID)
	w := httptest.NewRecorder()
	srv.handleGetApproval(w, req)

	if strings.Contains(w.Body.String(), "<script>alert(1)</script>") {
		t.Error("XSS not escaped")
	}
}

func TestFormatTermValue(t *testing.T) {
	tests := []struct {
		field, expected string
		value           any
	}{
		{"valuation_cap", "$10,000,000", float64(10000000)},
		{"discount_rate", "20%", float64(0.2)},
		{"pro_rata", "Yes", true},
		{"mfn", "No", false},
		{"term_years", "5", float64(5)},
	}
	for _, tt := range tests {
		if got := formatTermValue(tt.field, tt.value); got != tt.expected {
			t.Errorf("formatTermValue(%q, %v) = %q, want %q", tt.field, tt.value, got, tt.expected)
		}
	}
}

func TestFormatFieldLabel(t *testing.T) {
	tests := []struct{ field, expected string }{
		{"mfn", "Most Favored Nation"},
		{"pro_rata", "Pro-Rata Rights"},
		{"valuation_cap", "Valuation Cap"},
	}
	for _, tt := range tests {
		if got := formatFieldLabel(tt.field); got != tt.expected {
			t.Errorf("formatFieldLabel(%q) = %q, want %q", tt.field, got, tt.expected)
		}
	}
}

func TestFormatIntWithCommas(t *testing.T) {
	tests := []struct {
		n        int64
		expected string
	}{
		{0, "0"},
		{100, "100"},
		{1000, "1,000"},
		{10000000, "10,000,000"},
	}
	for _, tt := range tests {
		if got := formatIntWithCommas(tt.n); got != tt.expected {
			t.Errorf("formatIntWithCommas(%d) = %q, want %q", tt.n, got, tt.expected)
		}
	}
}

func TestClientIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	if got := clientIP(req); got != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", got)
	}

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "10.0.0.1:12345"
	if got := clientIP(req2); got != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", got)
	}
}

func init() {
	_ = json.Marshal // suppress unused import
}
