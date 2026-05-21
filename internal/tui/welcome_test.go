package tui

import (
	"context"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/storage"
)

func setupWelcomeFixture(t *testing.T) (*storage.TestDB, *apoacrypto.KEKRing, *storage.User) {
	t.Helper()
	tdb, err := storage.NewTestDB()
	if err != nil {
		t.Fatalf("test DB: %v", err)
	}
	t.Cleanup(func() { tdb.Close() })

	kek, err := apoacrypto.NewKEKRingForTests("welcome-test-secret")
	if err != nil {
		t.Fatalf("KEK ring: %v", err)
	}

	user, _, err := storage.CreateUser(context.Background(), tdb.DB, "SHA256:welcomeTest", "ssh-ed25519 AAAAwelcometest")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	return tdb, kek, user
}

func makeWelcomeModel(tdb *storage.TestDB, kek *apoacrypto.KEKRing, user *storage.User, isNew bool) Model {
	return NewModelWithRenderer(tdb.DB, kek, nil, user, nil, isNew, lipgloss.DefaultRenderer())
}

func TestWelcome_NewUserMenuIsSubset(t *testing.T) {
	tdb, kek, user := setupWelcomeFixture(t)
	m := makeWelcomeModel(tdb, kek, user, true)

	items := m.welcome.items
	if len(items) != 3 {
		t.Fatalf("new-user menu len = %d, want 3", len(items))
	}
	wanted := []welcomeMenuItem{menuCreateKey, menuLinkKey, menuExit}
	for i, want := range wanted {
		if items[i] != want {
			t.Errorf("items[%d] = %v, want %v", i, items[i], want)
		}
	}
}

func TestWelcome_ReturningUserMenuIsFull(t *testing.T) {
	tdb, kek, user := setupWelcomeFixture(t)
	m := makeWelcomeModel(tdb, kek, user, false)

	wanted := []welcomeMenuItem{
		menuCreateKey, menuManageKeys, menuPendingApprovals,
		menuAuditLog, menuLinkKey, menuExit,
	}
	if len(m.welcome.items) != len(wanted) {
		t.Fatalf("returning-user menu len = %d, want %d", len(m.welcome.items), len(wanted))
	}
	for i, w := range wanted {
		if m.welcome.items[i] != w {
			t.Errorf("items[%d] = %v, want %v", i, m.welcome.items[i], w)
		}
	}
}

func TestWelcome_CursorNavigation(t *testing.T) {
	tdb, kek, user := setupWelcomeFixture(t)
	m := makeWelcomeModel(tdb, kek, user, false)

	m1, _ := m.Update(key("down"))
	if got := m1.(Model).welcome.cursor; got != 1 {
		t.Errorf("cursor after down = %d, want 1", got)
	}
	m2, _ := m1.(Model).Update(key("down"))
	m3, _ := m2.(Model).Update(key("up"))
	if got := m3.(Model).welcome.cursor; got != 1 {
		t.Errorf("cursor after down/down/up = %d, want 1", got)
	}

	// Cursor can't go below 0 from index 0.
	m4 := makeWelcomeModel(tdb, kek, user, false)
	m5, _ := m4.Update(key("up"))
	if got := m5.(Model).welcome.cursor; got != 0 {
		t.Errorf("cursor up from 0 = %d, want 0", got)
	}

	// Cursor can't go past last item.
	m6 := makeWelcomeModel(tdb, kek, user, false)
	for i := 0; i < 20; i++ {
		next, _ := m6.Update(key("down"))
		m6 = next.(Model)
	}
	if want := len(m6.welcome.items) - 1; m6.welcome.cursor != want {
		t.Errorf("cursor after many downs = %d, want %d", m6.welcome.cursor, want)
	}
}

// menuIndex returns the cursor position for a given menu item, given
// the model's items slice. Test helper so tests can target items by
// semantic name rather than fragile numeric index.
func menuIndex(items []welcomeMenuItem, target welcomeMenuItem) int {
	for i, it := range items {
		if it == target {
			return i
		}
	}
	return -1
}

func TestWelcome_EnterManageKeys(t *testing.T) {
	tdb, kek, user := setupWelcomeFixture(t)
	m := makeWelcomeModel(tdb, kek, user, false)
	m.welcome.cursor = menuIndex(m.welcome.items, menuManageKeys)

	next, _ := m.Update(key("enter"))
	if got := next.(Model).screen; got != screenManageKeys {
		t.Errorf("screen = %v, want manageKeys", got)
	}
}

func TestWelcome_EnterPendingApprovals(t *testing.T) {
	tdb, kek, user := setupWelcomeFixture(t)
	m := makeWelcomeModel(tdb, kek, user, false)
	m.welcome.cursor = menuIndex(m.welcome.items, menuPendingApprovals)

	next, _ := m.Update(key("enter"))
	if got := next.(Model).screen; got != screenPendingApprovals {
		t.Errorf("screen = %v, want pendingApprovals", got)
	}
}

func TestWelcome_EnterAuditLog(t *testing.T) {
	tdb, kek, user := setupWelcomeFixture(t)
	m := makeWelcomeModel(tdb, kek, user, false)
	m.welcome.cursor = menuIndex(m.welcome.items, menuAuditLog)

	next, _ := m.Update(key("enter"))
	if got := next.(Model).screen; got != screenAuditLog {
		t.Errorf("screen = %v, want auditLog", got)
	}
}

func TestWelcome_EnterLinkKey(t *testing.T) {
	tdb, kek, user := setupWelcomeFixture(t)
	m := makeWelcomeModel(tdb, kek, user, false)
	m.welcome.cursor = menuIndex(m.welcome.items, menuLinkKey)

	next, _ := m.Update(key("enter"))
	if got := next.(Model).screen; got != screenLinkKey {
		t.Errorf("screen = %v, want linkKey", got)
	}
}

func TestWelcome_EnterCreateKeyGoesToAuthSetupWithPending(t *testing.T) {
	tdb, kek, user := setupWelcomeFixture(t)
	m := makeWelcomeModel(tdb, kek, user, true) // new user
	m.welcome.cursor = menuIndex(m.welcome.items, menuCreateKey)

	next, _ := m.Update(key("enter"))
	mm := next.(Model)
	if mm.screen != screenAuthSetup {
		t.Fatalf("screen = %v, want authSetup", mm.screen)
	}
	// authSetup must have received the pending key material so the
	// subsequent confirm can persist the key in a single transaction.
	if mm.authSetup.pendingPubSSH == "" {
		t.Error("authSetup.pendingPubSSH is empty; CreateKey didn't pass the key material through")
	}
	if mm.authSetup.pendingKEKAlgo == "" {
		t.Error("authSetup.pendingKEKAlgo is empty; algo tag not forwarded")
	}
	if mm.authSetup.selectedKeyID == "" {
		t.Error("authSetup.selectedKeyID is empty")
	}
}

func TestWelcome_QuitKey(t *testing.T) {
	tdb, kek, user := setupWelcomeFixture(t)
	m := makeWelcomeModel(tdb, kek, user, false)

	_, cmd := m.Update(key("q"))
	if cmd == nil {
		t.Fatal("'q' produced no command; expected tea.Quit")
	}
	// tea.Quit is the func value returned by tea.Quit; the cmd it
	// returns is what we get from Update. We can't directly compare
	// function pointers reliably across Go versions, so invoke it and
	// inspect the message.
	msg := cmd()
	if _, ok := msg.(tea.QuitMsg); !ok {
		t.Errorf("'q' cmd returned %T, want tea.QuitMsg", msg)
	}
}

func TestWelcome_EnterExit(t *testing.T) {
	tdb, kek, user := setupWelcomeFixture(t)
	m := makeWelcomeModel(tdb, kek, user, false)
	m.welcome.cursor = menuIndex(m.welcome.items, menuExit)

	_, cmd := m.Update(key("enter"))
	if cmd == nil {
		t.Fatal("Exit enter produced no command; expected tea.Quit")
	}
	msg := cmd()
	if _, ok := msg.(tea.QuitMsg); !ok {
		t.Errorf("Exit cmd returned %T, want tea.QuitMsg", msg)
	}
}

func TestWelcome_StatusMsgUpdatesStatus(t *testing.T) {
	tdb, kek, user := setupWelcomeFixture(t)
	m := makeWelcomeModel(tdb, kek, user, false)

	next, _ := m.Update(statusMsg{message: "all good", isError: false})
	if got := next.(Model).welcome.status; got != "all good" {
		t.Errorf("welcome.status = %q, want \"all good\"", got)
	}

	next2, _ := next.(Model).Update(statusMsg{message: "boom", isError: true})
	mm := next2.(Model)
	if mm.welcome.status != "boom" || !mm.welcome.isError {
		t.Errorf("error statusMsg not applied: status=%q isError=%v", mm.welcome.status, mm.welcome.isError)
	}
}
