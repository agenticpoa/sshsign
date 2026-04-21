package sessions

import (
	"errors"
	"testing"
)

func TestComplete_IssuesViewToken(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	after, err := r.Complete(sess.SessionID, "alice", "artifact://x")
	if err != nil {
		t.Fatal(err)
	}
	if after.ViewToken == "" {
		t.Error("expected view_token to be issued on completion")
	}
	if len(after.ViewToken) < 16 {
		t.Errorf("view_token too short (%d chars): %q", len(after.ViewToken), after.ViewToken)
	}
}

func TestGetByViewToken_ValidTokenReturnsSession(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	after, _ := r.Complete(sess.SessionID, "alice", "artifact://x")

	got, err := r.GetByViewToken(after.SessionID, after.ViewToken)
	if err != nil {
		t.Fatalf("GetByViewToken: %v", err)
	}
	if got.SessionID != after.SessionID {
		t.Errorf("got session_id %q, want %q", got.SessionID, after.SessionID)
	}
}

func TestGetByViewToken_WrongTokenRejected(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	after, _ := r.Complete(sess.SessionID, "alice", "artifact://x")

	_, err := r.GetByViewToken(after.SessionID, "wrong-token")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound (to avoid leaking existence)", err)
	}
}

func TestGetByViewToken_EmptyTokenRejected(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	_, _ = r.Complete(sess.SessionID, "alice", "artifact://x")

	_, err := r.GetByViewToken(sess.SessionID, "")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestIssueViewToken_RotatesToken(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	after, _ := r.Complete(sess.SessionID, "alice", "artifact://x")
	original := after.ViewToken

	rotated, err := r.IssueViewToken(after.SessionID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.ViewToken == original {
		t.Error("expected new token, got the same one back")
	}

	// Old token should no longer work.
	_, err = r.GetByViewToken(after.SessionID, original)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("old token still works after rotation: %v", err)
	}
	// New token should work.
	_, err = r.GetByViewToken(after.SessionID, rotated.ViewToken)
	if err != nil {
		t.Errorf("new token rejected: %v", err)
	}
}

func TestIssueViewToken_CreatorOnly(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	_, _ = r.Join(JoinParams{
		SessionCode: sess.SessionCode, UserID: "bob",
		Role: "investor", APOAPubkeyPEM: "X",
	})
	_, _ = r.Complete(sess.SessionID, "alice", "artifact://x")

	_, err := r.IssueViewToken(sess.SessionID, "bob")
	if !errors.Is(err, ErrNotCreator) {
		t.Errorf("err = %v, want ErrNotCreator", err)
	}
}

func TestIssueViewToken_OnlyOnCompletedSessions(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	_, err := r.IssueViewToken(sess.SessionID, "alice")
	if !errors.Is(err, ErrInvalidStatus) {
		t.Errorf("err = %v, want ErrInvalidStatus", err)
	}
}
