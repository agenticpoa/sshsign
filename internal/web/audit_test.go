package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agenticpoa/sshsign/internal/sessions"
	"github.com/agenticpoa/sshsign/internal/storage"
)

func newAuditTestSession(t *testing.T) (*Server, *sessions.Session) {
	t.Helper()
	tdb, err := storage.NewTestDB()
	if err != nil {
		t.Fatalf("NewTestDB: %v", err)
	}
	t.Cleanup(func() { tdb.Close() })

	for _, uid := range []string{"alice", "bob"} {
		if _, err := tdb.Exec(`INSERT INTO users (user_id) VALUES (?)`, uid); err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}

	repo := sessions.NewRepo(tdb.DB)
	created, err := repo.Create(sessions.CreateParams{
		SessionID:      "neg_auditor",
		CreatorUserID:  "alice",
		CreatorRole:    "founder",
		CreatorAPOAPub: "-----BEGIN APOA-----\nFOUNDERKEY\n-----END APOA-----\n",
		MetadataPublic: `{"use_case":"safe","version":1}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Join(sessions.JoinParams{
		SessionCode: created.SessionCode, UserID: "bob", Role: "investor",
		APOAPubkeyPEM: "-----BEGIN APOA-----\nINVESTORKEY\n-----END APOA-----\n",
	}); err != nil {
		t.Fatal(err)
	}
	completed, err := repo.Complete(created.SessionID, "alice", "sshsign://artifact/final.pdf")
	if err != nil {
		t.Fatal(err)
	}

	srv := &Server{db: tdb.DB}
	return srv, completed
}

func TestAuditView_ValidTokenReturnsHTML(t *testing.T) {
	srv, sess := newAuditTestSession(t)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /audit/{sessionID}", srv.handleAuditView)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/audit/" + sess.SessionID + "?token=" + sess.ViewToken)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	// Required fields visible
	for _, want := range []string{
		"neg_auditor",
		"sshsign://artifact/final.pdf",
		"founder",
		"investor",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	// Must NOT leak raw PEM pubkeys
	if strings.Contains(body, "INVESTORKEY") || strings.Contains(body, "FOUNDERKEY") {
		t.Error("body leaked raw APOA pubkey")
	}
	// Fingerprints should be present instead
	if !strings.Contains(body, "sha256:") {
		t.Error("body missing pubkey fingerprints")
	}
}

func TestAuditView_JSONFormat(t *testing.T) {
	srv, sess := newAuditTestSession(t)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /audit/{sessionID}", srv.handleAuditView)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/audit/" + sess.SessionID + "?token=" + sess.ViewToken + "&format=json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var payload map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["SessionID"] != sess.SessionID {
		t.Errorf("SessionID = %v, want %v", payload["SessionID"], sess.SessionID)
	}
	parties, _ := payload["Parties"].([]interface{})
	if len(parties) != 2 {
		t.Errorf("parties len = %d, want 2", len(parties))
	}
}

func TestAuditView_MissingTokenIsBadRequest(t *testing.T) {
	srv, sess := newAuditTestSession(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /audit/{sessionID}", srv.handleAuditView)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/audit/" + sess.SessionID)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAuditView_WrongTokenIs404(t *testing.T) {
	srv, sess := newAuditTestSession(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /audit/{sessionID}", srv.handleAuditView)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/audit/" + sess.SessionID + "?token=wrong")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAuditView_UnknownSessionIs404(t *testing.T) {
	srv, sess := newAuditTestSession(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /audit/{sessionID}", srv.handleAuditView)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/audit/neg_nonexistent?token=" + sess.ViewToken)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAuditView_NonCompletedSessionNotServed(t *testing.T) {
	// Create a session that is NOT completed — it should not have a view_token,
	// so the audit URL should 404 even if someone guesses a blank token.
	tdb, _ := storage.NewTestDB()
	t.Cleanup(func() { tdb.Close() })
	_, _ = tdb.Exec(`INSERT INTO users (user_id) VALUES ('alice')`)

	repo := sessions.NewRepo(tdb.DB)
	sess, _ := repo.Create(sessions.CreateParams{
		SessionID:      "neg_inprogress",
		CreatorUserID:  "alice",
		CreatorRole:    "founder",
		CreatorAPOAPub: "X",
	})

	srv := &Server{db: tdb.DB}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /audit/{sessionID}", srv.handleAuditView)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Try with a fake token.
	resp, _ := http.Get(ts.URL + "/audit/" + sess.SessionID + "?token=anything")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (no view_token on non-completed session)", resp.StatusCode)
	}
}
