package tui

import (
	"context"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/storage"
)

// linkKeyFixture: user with the SSH key they signed in with, ready to
// add a second key via the linkkey flow.
type linkKeyFixture struct {
	t    *testing.T
	tdb  *storage.TestDB
	user *storage.User
}

func setupLinkKeyFixture(t *testing.T) *linkKeyFixture {
	t.Helper()
	ctx := context.Background()

	tdb, err := storage.NewTestDB()
	if err != nil {
		t.Fatalf("test DB: %v", err)
	}
	t.Cleanup(func() { tdb.Close() })

	user, _, err := storage.CreateUser(ctx, tdb.DB, "SHA256:lktest", "ssh-ed25519 AAAAlktest")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	return &linkKeyFixture{t: t, tdb: tdb, user: user}
}

func (f *linkKeyFixture) model() Model {
	kek, _ := apoacrypto.NewKEKRingForTests("lk-test-secret")
	m := NewModelWithRenderer(f.tdb.DB, kek, nil, f.user, nil, false, lipgloss.DefaultRenderer())
	m.screen = screenLinkKey
	m.linkKey = newLinkKeyModel(m.r)
	return m
}

// validPubKey is a real ed25519 public key in the OpenSSH authorized-keys
// format. Generated once and reused so tests don't pay keygen cost.
const validPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK7+B2fjLLZWqzeGmYR2vDJ7T8FaMqDDxLDeP9xj7hfH"

func TestLinkKey_EmptyPubKeyShowsError(t *testing.T) {
	f := setupLinkKeyFixture(t)
	m := f.model()
	// Focus is on pubkey field (default), with empty value. Tab to
	// label, then enter to submit.
	m1, _ := m.Update(key("tab"))
	m2, _ := m1.(Model).Update(key("enter"))
	mm := m2.(Model)
	if mm.linkKey.err == "" {
		t.Error("expected error on empty public key submission")
	}
	if mm.screen != screenLinkKey {
		t.Errorf("screen = %v, want still on linkKey screen", mm.screen)
	}
}

func TestLinkKey_InvalidPubKeyShowsError(t *testing.T) {
	f := setupLinkKeyFixture(t)
	m := f.model()
	m.linkKey.input.SetValue("not a real ssh key")
	m1, _ := m.Update(key("tab"))
	m2, _ := m1.(Model).Update(key("enter"))
	mm := m2.(Model)
	if mm.linkKey.err == "" {
		t.Error("expected error on invalid public key")
	}
	if mm.screen != screenLinkKey {
		t.Errorf("screen = %v, want still on linkKey screen", mm.screen)
	}

	// No key should have been linked.
	keys, _ := storage.ListUserKeys(context.Background(), f.tdb.DB, f.user.UserID)
	if len(keys) != 1 {
		t.Errorf("expected 1 user key (the original), got %d", len(keys))
	}
}

func TestLinkKey_HappyPath(t *testing.T) {
	f := setupLinkKeyFixture(t)
	m := f.model()
	m.linkKey.input.SetValue(validPubKey)
	m.linkKey.labelInput.SetValue("work laptop")
	m1, _ := m.Update(key("tab"))
	m2, _ := m1.(Model).Update(key("enter"))
	mm := m2.(Model)

	if mm.linkKey.err != "" {
		t.Fatalf("unexpected error: %s", mm.linkKey.err)
	}
	if mm.screen != screenWelcome {
		t.Errorf("screen = %v, want welcome (auto-navigate on success)", mm.screen)
	}

	keys, err := storage.ListUserKeys(context.Background(), f.tdb.DB, f.user.UserID)
	if err != nil {
		t.Fatalf("listing user keys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys after link, got %d", len(keys))
	}
	// The new key should carry the label.
	var newKey *storage.UserKey
	for i, k := range keys {
		if k.Label == "work laptop" {
			newKey = &keys[i]
			break
		}
	}
	if newKey == nil {
		t.Fatal("new key with label 'work laptop' not found")
	}
	if newKey.PublicKey != validPubKey {
		t.Errorf("stored pubkey = %q, want %q", newKey.PublicKey, validPubKey)
	}
}

func TestLinkKey_TabSwitchesFocus(t *testing.T) {
	f := setupLinkKeyFixture(t)
	m := f.model()
	if m.linkKey.focus != fieldPublicKey {
		t.Fatalf("starting focus = %v, want fieldPublicKey", m.linkKey.focus)
	}
	m1, _ := m.Update(key("tab"))
	if got := m1.(Model).linkKey.focus; got != fieldLabel {
		t.Errorf("focus after tab = %v, want fieldLabel", got)
	}
	m2, _ := m1.(Model).Update(key("tab"))
	if got := m2.(Model).linkKey.focus; got != fieldPublicKey {
		t.Errorf("focus after second tab = %v, want fieldPublicKey", got)
	}
}

func TestLinkKey_EnterOnPubKeyAdvancesField(t *testing.T) {
	// Enter on the public-key field should NOT submit; it should
	// advance focus to the label field so the user can type a label
	// before committing.
	f := setupLinkKeyFixture(t)
	m := f.model()
	m.linkKey.input.SetValue(validPubKey)

	m1, _ := m.Update(key("enter"))
	mm := m1.(Model)
	if mm.linkKey.focus != fieldLabel {
		t.Errorf("focus after enter on pubkey = %v, want fieldLabel", mm.linkKey.focus)
	}
	if mm.screen != screenLinkKey {
		t.Errorf("enter on pubkey field navigated to %v, want stay on linkKey", mm.screen)
	}
	// Key must NOT have been linked yet.
	keys, _ := storage.ListUserKeys(context.Background(), f.tdb.DB, f.user.UserID)
	if len(keys) != 1 {
		t.Errorf("key was linked prematurely; user has %d keys, want 1", len(keys))
	}
}

func TestLinkKey_EscapeReturnsToWelcome(t *testing.T) {
	f := setupLinkKeyFixture(t)
	m := f.model()
	m.linkKey.input.SetValue(validPubKey)

	m1, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if got := m1.(Model).screen; got != screenWelcome {
		t.Errorf("screen after esc = %v, want welcome", got)
	}

	// Esc must not have committed the pending input.
	keys, _ := storage.ListUserKeys(context.Background(), f.tdb.DB, f.user.UserID)
	if len(keys) != 1 {
		t.Errorf("esc committed input; user has %d keys, want 1", len(keys))
	}
}
