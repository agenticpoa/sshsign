package sessions

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/agenticpoa/sshsign/internal/storage"
)

// Each test uses a fresh in-memory DB with the standard migrations
// applied. A few fixture users are seeded so FK constraints pass.

func newTestRepo(t *testing.T) (*Repo, *sql.DB, func()) {
	t.Helper()
	tdb, err := storage.NewTestDB()
	if err != nil {
		t.Fatalf("NewTestDB: %v", err)
	}
	seedUsers(t, tdb.DB, "alice", "bob", "charlie", "system")
	r := NewRepo(tdb.DB)
	return r, tdb.DB, func() { tdb.Close() }
}

func seedUsers(t *testing.T, db *sql.DB, ids ...string) {
	t.Helper()
	for _, id := range ids {
		_, err := db.Exec(`INSERT INTO users (user_id) VALUES (?)`, id)
		if err != nil {
			t.Fatalf("seed user %q: %v", id, err)
		}
	}
}

func baseCreate(creator string) CreateParams {
	return CreateParams{
		SessionID:       "neg_" + creator,
		CreatorUserID:   creator,
		CreatorRole:     "founder",
		CreatorAPOAPub:  "-----BEGIN APOA-----\nFAKE\n-----END APOA-----\n",
		CreatorPartyDID: "did:apoa:" + creator,
	}
}

// ─── Create ───────────────────────────────────────────────────────

func TestCreate_WritesSessionAndCreatorMember(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()

	sess, err := r.Create(baseCreate("alice"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sess.Status != StatusOpen {
		t.Errorf("status = %q, want open", sess.Status)
	}
	if sess.SessionCode == "" || sess.SessionCode[:4] != "INV-" {
		t.Errorf("session_code = %q, want INV-… prefix", sess.SessionCode)
	}
	if sess.MetadataPublic != "{}" {
		t.Errorf("metadata_public default = %q, want {}", sess.MetadataPublic)
	}

	members, err := r.Members(sess.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 {
		t.Fatalf("members = %d, want 1", len(members))
	}
	if members[0].UserID != "alice" || members[0].Role != "founder" {
		t.Errorf("member[0] = %+v, want alice/founder", members[0])
	}
	if members[0].PartyDID != "did:apoa:alice" {
		t.Errorf("party_did not stored: %q", members[0].PartyDID)
	}
}

func TestCreate_DefaultTTLIs24h(t *testing.T) {
	fixedNow := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	r.now = func() time.Time { return fixedNow }

	sess, err := r.Create(baseCreate("alice"))
	if err != nil {
		t.Fatal(err)
	}
	if want := fixedNow.Add(24 * time.Hour); !sess.ExpiresAt.Equal(want) {
		t.Errorf("expires_at = %v, want %v", sess.ExpiresAt, want)
	}
}

func TestCreate_RequiredFields(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()

	cases := []struct {
		name string
		mut  func(*CreateParams)
	}{
		{"missing session_id", func(p *CreateParams) { p.SessionID = "" }},
		{"missing creator", func(p *CreateParams) { p.CreatorUserID = "" }},
		{"missing role", func(p *CreateParams) { p.CreatorRole = "" }},
		{"missing pubkey", func(p *CreateParams) { p.CreatorAPOAPub = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := baseCreate("alice")
			tc.mut(&p)
			if _, err := r.Create(p); err == nil {
				t.Errorf("expected error")
			}
		})
	}
}

func TestCreate_DuplicateSessionIDRejected(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	if _, err := r.Create(baseCreate("alice")); err != nil {
		t.Fatal(err)
	}
	_, err := r.Create(baseCreate("alice"))
	if err == nil {
		t.Error("expected second create to fail on duplicate session_id")
	}
}

func TestCreate_RateLimitedByOpenSessionsPerUser(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()

	// Seed up to the limit.
	for i := 0; i < MaxOpenSessionsPerUser; i++ {
		p := baseCreate("alice")
		p.SessionID = fmt.Sprintf("neg_alice_%d", i)
		if _, err := r.Create(p); err != nil {
			t.Fatalf("create #%d: %v", i, err)
		}
	}

	p := baseCreate("alice")
	p.SessionID = "neg_alice_overflow"
	_, err := r.Create(p)
	if !errors.Is(err, ErrRateLimit) {
		t.Errorf("err = %v, want ErrRateLimit", err)
	}
}

func TestCreate_TerminalSessionsDoNotCountAgainstLimit(t *testing.T) {
	r, db, cleanup := newTestRepo(t)
	defer cleanup()

	for i := 0; i < MaxOpenSessionsPerUser; i++ {
		p := baseCreate("alice")
		p.SessionID = fmt.Sprintf("neg_alice_%d", i)
		if _, err := r.Create(p); err != nil {
			t.Fatal(err)
		}
	}
	// Force one to canceled — the slot should free up.
	_, err := db.Exec(
		`UPDATE signing_sessions SET status = 'canceled' WHERE session_id = ?`,
		"neg_alice_0",
	)
	if err != nil {
		t.Fatal(err)
	}
	p := baseCreate("alice")
	p.SessionID = "neg_alice_new"
	if _, err := r.Create(p); err != nil {
		t.Errorf("expected success after canceling one, got: %v", err)
	}
}

func TestCreate_WritesAuditEntry(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	events, err := r.Audit(sess.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].EventType != "created" || events[0].ActorID != "alice" {
		t.Errorf("audit = %+v", events)
	}
}

// ─── Join ─────────────────────────────────────────────────────────

func TestJoin_TransitionsStatusToJoined(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))

	after, err := r.Join(JoinParams{
		SessionCode:   sess.SessionCode,
		UserID:        "bob",
		Role:          "investor",
		APOAPubkeyPEM: "-----BEGIN APOA-----\nBOB\n-----END APOA-----\n",
		PartyDID:      "did:apoa:bob",
	})
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != StatusJoined {
		t.Errorf("status = %q, want joined", after.Status)
	}
	members, _ := r.Members(sess.SessionID)
	if len(members) != 2 {
		t.Fatalf("members = %d, want 2", len(members))
	}
}

func TestJoin_RoleCollisionRejected(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))

	_, err := r.Join(JoinParams{
		SessionCode:   sess.SessionCode,
		UserID:        "bob",
		Role:          "founder", // same as creator
		APOAPubkeyPEM: "BOB",
	})
	if !errors.Is(err, ErrAlreadyJoined) {
		t.Errorf("err = %v, want ErrAlreadyJoined", err)
	}
}

func TestJoin_SameUserIsIdempotent(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))

	p := JoinParams{
		SessionCode: sess.SessionCode, UserID: "bob", Role: "investor",
		APOAPubkeyPEM: "BOB",
	}
	if _, err := r.Join(p); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Join(p); err != nil {
		t.Errorf("idempotent rejoin should succeed, got: %v", err)
	}
}

func TestJoin_TerminalSessionRejected(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	if _, err := r.Cancel(sess.SessionID, "alice", StatusCanceled); err != nil {
		t.Fatal(err)
	}
	_, err := r.Join(JoinParams{
		SessionCode: sess.SessionCode, UserID: "bob", Role: "investor",
		APOAPubkeyPEM: "BOB",
	})
	if !errors.Is(err, ErrTerminal) {
		t.Errorf("err = %v, want ErrTerminal", err)
	}
}

func TestJoin_ExpiredSessionRejected(t *testing.T) {
	clock := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	r.now = func() time.Time { return clock }

	sess, _ := r.Create(baseCreate("alice"))
	// Jump time past expiry
	r.now = func() time.Time { return sess.ExpiresAt.Add(time.Minute) }

	_, err := r.Join(JoinParams{
		SessionCode: sess.SessionCode, UserID: "bob", Role: "investor",
		APOAPubkeyPEM: "BOB",
	})
	if !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
	// Status should be transitioned to expired as a side effect.
	latest, _ := r.GetByID(sess.SessionID)
	if latest.Status != StatusExpired {
		t.Errorf("status after expired join attempt = %q, want expired", latest.Status)
	}
}

func TestJoin_UnknownCodeReturnsCodeNotFound(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	_, err := r.Join(JoinParams{
		SessionCode: "INV-NOPEE", UserID: "bob", Role: "investor", APOAPubkeyPEM: "X",
	})
	if !errors.Is(err, ErrCodeNotFound) {
		t.Errorf("err = %v, want ErrCodeNotFound", err)
	}
}

// ─── Cancel / Complete ────────────────────────────────────────────

func TestCancel_AnyMemberMayCancel(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	_, _ = r.Join(JoinParams{SessionCode: sess.SessionCode, UserID: "bob",
		Role: "investor", APOAPubkeyPEM: "X"})

	// Investor cancels — should succeed even though they're not creator.
	after, err := r.Cancel(sess.SessionID, "bob", StatusCanceled)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != StatusCanceled || after.CanceledBy != "bob" {
		t.Errorf("cancel state = %+v", after)
	}
}

func TestCancel_NonMemberRejected(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	_, err := r.Cancel(sess.SessionID, "charlie", StatusCanceled)
	if !errors.Is(err, ErrNotMember) {
		t.Errorf("err = %v, want ErrNotMember", err)
	}
}

func TestCancel_RescindedAfterSignIsDistinctStatus(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	after, err := r.Cancel(sess.SessionID, "alice", StatusRescindedAfterSign)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != StatusRescindedAfterSign {
		t.Errorf("status = %q, want rescinded_after_sign", after.Status)
	}
}

func TestCancel_TerminalSessionRejected(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	if _, err := r.Cancel(sess.SessionID, "alice", StatusCanceled); err != nil {
		t.Fatal(err)
	}
	_, err := r.Cancel(sess.SessionID, "alice", StatusCanceled)
	if !errors.Is(err, ErrTerminal) {
		t.Errorf("err = %v, want ErrTerminal", err)
	}
}

func TestComplete_CreatorOnly(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	_, _ = r.Join(JoinParams{SessionCode: sess.SessionCode, UserID: "bob",
		Role: "investor", APOAPubkeyPEM: "X"})

	_, err := r.Complete(sess.SessionID, "bob", "sshsign://artifact/123")
	if !errors.Is(err, ErrNotCreator) {
		t.Errorf("err = %v, want ErrNotCreator", err)
	}
	after, err := r.Complete(sess.SessionID, "alice", "sshsign://artifact/123")
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != StatusCompleted {
		t.Errorf("status = %q, want completed", after.Status)
	}
	if after.FinalizedBy != "alice" || after.ExecutedArtifact != "sshsign://artifact/123" {
		t.Errorf("state = %+v", after)
	}
}

func TestComplete_IdempotentForSameArtifact(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	artifact := "sshsign://artifact/42"
	if _, err := r.Complete(sess.SessionID, "alice", artifact); err != nil {
		t.Fatal(err)
	}
	// Second call with same args should succeed silently.
	if _, err := r.Complete(sess.SessionID, "alice", artifact); err != nil {
		t.Errorf("idempotent second complete failed: %v", err)
	}
	// Different artifact should fail (immutability).
	_, err := r.Complete(sess.SessionID, "alice", "different")
	if !errors.Is(err, ErrTerminal) {
		t.Errorf("err = %v, want ErrTerminal", err)
	}
}

func TestComplete_RequiresExecutedArtifact(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	_, err := r.Complete(sess.SessionID, "alice", "")
	if err == nil {
		t.Error("expected error for empty executed_artifact")
	}
}

// ─── Gets ─────────────────────────────────────────────────────────

func TestGetByCode_UnknownCode(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	_, err := r.GetByCode("INV-NOPEE")
	if !errors.Is(err, ErrCodeNotFound) {
		t.Errorf("err = %v, want ErrCodeNotFound", err)
	}
}

func TestGetByID_UnknownID(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	_, err := r.GetByID("neg_missing")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestIsMember(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))

	ok, _ := r.IsMember(sess.SessionID, "alice")
	if !ok {
		t.Error("alice should be member")
	}
	ok, _ = r.IsMember(sess.SessionID, "charlie")
	if ok {
		t.Error("charlie should not be member")
	}
}

// ─── BindGroup ────────────────────────────────────────────────────

func TestBindGroup_FirstBindSucceedsAndPersists(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))

	after, err := r.BindGroup(sess.SessionID, "alice", -1001234567890)
	if err != nil {
		t.Fatalf("BindGroup: %v", err)
	}
	if after.GroupChatID != -1001234567890 {
		t.Errorf("GroupChatID = %d, want -1001234567890", after.GroupChatID)
	}

	// Re-read via GetByID to confirm persistence.
	reloaded, _ := r.GetByID(sess.SessionID)
	if reloaded.GroupChatID != -1001234567890 {
		t.Errorf("reloaded GroupChatID = %d, want persisted value", reloaded.GroupChatID)
	}
}

func TestBindGroup_SameValueIsNoOp(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	_, _ = r.BindGroup(sess.SessionID, "alice", -1001)

	// Second bind with same value should not error (idempotent).
	after, err := r.BindGroup(sess.SessionID, "alice", -1001)
	if err != nil {
		t.Fatalf("idempotent rebind: %v", err)
	}
	if after.GroupChatID != -1001 {
		t.Errorf("GroupChatID = %d, want -1001", after.GroupChatID)
	}

	// Audit should only record ONE group_bound event.
	events, _ := r.Audit(sess.SessionID)
	count := 0
	for _, e := range events {
		if e.EventType == "group_bound" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("group_bound events = %d, want 1", count)
	}
}

func TestBindGroup_DifferentValueReturnsConflict(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	_, _ = r.BindGroup(sess.SessionID, "alice", -1001)

	_, err := r.BindGroup(sess.SessionID, "alice", -2002)
	if !errors.Is(err, ErrGroupAlreadyBound) {
		t.Errorf("err = %v, want ErrGroupAlreadyBound", err)
	}

	// Original value must still be intact.
	reloaded, _ := r.GetByID(sess.SessionID)
	if reloaded.GroupChatID != -1001 {
		t.Errorf("GroupChatID = %d, want -1001 (unchanged)", reloaded.GroupChatID)
	}
}

func TestBindGroup_NonMemberRejected(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))

	_, err := r.BindGroup(sess.SessionID, "charlie", -1001)
	if !errors.Is(err, ErrNotMember) {
		t.Errorf("err = %v, want ErrNotMember", err)
	}
}

func TestBindGroup_AnyMemberMayBind(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	_, _ = r.Join(JoinParams{
		SessionCode: sess.SessionCode, UserID: "bob",
		Role: "investor", APOAPubkeyPEM: "BOB",
	})

	// Investor (non-creator) binds — should succeed.
	after, err := r.BindGroup(sess.SessionID, "bob", -3003)
	if err != nil {
		t.Fatalf("investor bind: %v", err)
	}
	if after.GroupChatID != -3003 {
		t.Errorf("GroupChatID = %d, want -3003", after.GroupChatID)
	}
}

func TestBindGroup_TerminalSessionRejected(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	_, _ = r.Cancel(sess.SessionID, "alice", StatusCanceled)

	_, err := r.BindGroup(sess.SessionID, "alice", -1001)
	if !errors.Is(err, ErrTerminal) {
		t.Errorf("err = %v, want ErrTerminal", err)
	}
}

func TestBindGroup_ZeroValueRejected(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))

	_, err := r.BindGroup(sess.SessionID, "alice", 0)
	if err == nil {
		t.Error("expected error for zero group_chat_id")
	}
}

func TestBindGroup_WritesAuditEntry(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	_, _ = r.BindGroup(sess.SessionID, "alice", -7777)

	events, _ := r.Audit(sess.SessionID)
	var bind *AuditEvent
	for i := range events {
		if events[i].EventType == "group_bound" {
			bind = &events[i]
			break
		}
	}
	if bind == nil {
		t.Fatal("no group_bound audit event")
	}
	if bind.ActorID != "alice" {
		t.Errorf("actor = %q, want alice", bind.ActorID)
	}
	if !contains(bind.Details, "-7777") {
		t.Errorf("details = %q, should contain -7777", bind.Details)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ─── Audit ────────────────────────────────────────────────────────

func TestAudit_RecordsFullLifecycle(t *testing.T) {
	r, _, cleanup := newTestRepo(t)
	defer cleanup()
	sess, _ := r.Create(baseCreate("alice"))
	_, _ = r.Join(JoinParams{SessionCode: sess.SessionCode, UserID: "bob",
		Role: "investor", APOAPubkeyPEM: "X"})
	_, _ = r.Complete(sess.SessionID, "alice", "artifact://final")

	events, err := r.Audit(sess.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3", len(events))
	}
	want := []string{"created", "joined", "completed"}
	for i, w := range want {
		if events[i].EventType != w {
			t.Errorf("events[%d] = %q, want %q", i, events[i].EventType, w)
		}
	}
}
