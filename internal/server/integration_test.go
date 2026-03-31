package server_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/agenticpoa/sshsign/internal/audit"
	"github.com/agenticpoa/sshsign/internal/config"
	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/server"
	"github.com/agenticpoa/sshsign/internal/storage"
	gossh "golang.org/x/crypto/ssh"
)

type testServer struct {
	addr     string
	db       *storage.TestDB
	kek      []byte
	auditLog *audit.MemoryLogger
}

func setupTestServer(t *testing.T) *testServer {
	t.Helper()

	db, err := storage.NewTestDB()
	if err != nil {
		t.Fatalf("creating test db: %v", err)
	}

	kek, err := apoacrypto.DeriveKEK("test-secret")
	if err != nil {
		t.Fatalf("deriving KEK: %v", err)
	}

	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	auditLog := audit.NewMemoryLogger()
	hostKeyPath := t.TempDir() + "/host_key"

	cfg := config.Config{
		ListenAddr:  addr,
		DBPath:      ":memory:",
		HostKeyPath: hostKeyPath,
		KEKSecret:   "test-secret",
	}

	srv, err := server.New(cfg, db.DB, kek, auditLog)
	if err != nil {
		t.Fatalf("creating server: %v", err)
	}

	go func() {
		srv.ListenAndServe()
	}()

	// Wait for server to be ready
	for i := range 50 {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if i == 49 {
			t.Fatalf("server did not start within timeout")
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Cleanup(func() {
		srv.Close()
		db.Close()
	})

	return &testServer{addr: addr, db: db, kek: kek, auditLog: auditLog}
}

func generateTestSSHKey(t *testing.T) (gossh.Signer, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	return signer, pub
}

func sshClient(t *testing.T, addr string, signer gossh.Signer, command string) (string, error) {
	t.Helper()

	config := &gossh.ClientConfig{
		User: "test",
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(signer),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := gossh.Dial("tcp", addr, config)
	if err != nil {
		return "", fmt.Errorf("dialing: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("creating session: %w", err)
	}
	defer session.Close()

	if command != "" {
		output, err := session.CombinedOutput(command)
		return string(output), err
	}

	// Non-interactive, no command: server sends welcome and closes
	output, err := session.CombinedOutput("")
	return string(output), err
}

func TestSSHConnectionCreatesUser(t *testing.T) {
	ts := setupTestServer(t)
	signer, pub := generateTestSSHKey(t)

	_, err := sshClient(t, ts.addr, signer, "")
	if err != nil {
		// Non-zero exit is OK for non-interactive sessions
		t.Logf("ssh command returned error (expected for non-PTY): %v", err)
	}

	// Check that user was created
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("creating ssh public key: %v", err)
	}
	fingerprint := gossh.FingerprintSHA256(sshPub)

	user, key, err := storage.FindUserByFingerprint(ts.db.DB, fingerprint)
	if err != nil {
		t.Fatalf("finding user: %v", err)
	}
	if user == nil {
		t.Fatal("expected user to be created on first connection")
	}
	if key == nil {
		t.Fatal("expected user key to be created on first connection")
	}
	if user.Status != "active" {
		t.Errorf("user status = %q, want 'active'", user.Status)
	}
	if key.SSHFingerprint != fingerprint {
		t.Errorf("key fingerprint = %q, want %q", key.SSHFingerprint, fingerprint)
	}

	t.Logf("created user %s with fingerprint %s", user.UserID, fingerprint)
}

func TestSecondConnectionSameUser(t *testing.T) {
	ts := setupTestServer(t)
	signer, pub := generateTestSSHKey(t)

	// First connection
	sshClient(t, ts.addr, signer, "")

	// Second connection with same key
	sshClient(t, ts.addr, signer, "")

	sshPub, _ := gossh.NewPublicKey(pub)
	fingerprint := gossh.FingerprintSHA256(sshPub)

	user, _, err := storage.FindUserByFingerprint(ts.db.DB, fingerprint)
	if err != nil {
		t.Fatalf("finding user: %v", err)
	}
	if user == nil {
		t.Fatal("expected user to exist")
	}

	// Should still only have one user key
	keys, err := storage.ListUserKeys(ts.db.DB, user.UserID)
	if err != nil {
		t.Fatalf("listing keys: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 user key after two connections with same key, got %d", len(keys))
	}
}

func TestUnknownKeyHandledGracefully(t *testing.T) {
	ts := setupTestServer(t)

	// Connect with a completely new key
	signer, _ := generateTestSSHKey(t)

	output, err := sshClient(t, ts.addr, signer, "")
	if err != nil {
		t.Logf("ssh returned error (expected): %v", err)
	}

	// Should not panic or crash, should get a welcome message
	t.Logf("output: %s", output)
}

func TestProgrammaticUnknownCommand(t *testing.T) {
	ts := setupTestServer(t)
	signer, _ := generateTestSSHKey(t)

	output, _ := sshClient(t, ts.addr, signer, "foobar")
	if output == "" {
		t.Error("expected error output for unknown command")
	}
	t.Logf("unknown command output: %s", output)
}
