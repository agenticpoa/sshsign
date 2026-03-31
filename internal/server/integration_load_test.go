package server_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

func TestConcurrentSSHConnections(t *testing.T) {
	ts := setupTestServer(t)

	const numClients = 10
	var wg sync.WaitGroup
	var successes, failures atomic.Int32

	start := time.Now()

	for i := range numClients {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			signer, _ := generateTestSSHKey(t)

			config := &gossh.ClientConfig{
				User:            "test",
				Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
				HostKeyCallback: gossh.InsecureIgnoreHostKey(),
				Timeout:         10 * time.Second,
			}

			client, err := gossh.Dial("tcp", ts.addr, config)
			if err != nil {
				failures.Add(1)
				t.Logf("client %d: dial failed: %v", id, err)
				return
			}
			defer client.Close()

			session, err := client.NewSession()
			if err != nil {
				failures.Add(1)
				t.Logf("client %d: session failed: %v", id, err)
				return
			}
			defer session.Close()

			output, err := session.CombinedOutput("")
			if err != nil {
				// Non-zero exit is expected for non-PTY
				t.Logf("client %d: command returned: %v", id, err)
			}

			if len(output) > 0 {
				successes.Add(1)
			} else {
				failures.Add(1)
				t.Logf("client %d: empty output", id)
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("completed %d connections in %s (%d successes, %d failures)",
		numClients, elapsed, successes.Load(), failures.Load())

	if successes.Load() < int32(numClients) {
		t.Errorf("expected %d successful connections, got %d", numClients, successes.Load())
	}

	// Verify all 10 users were created
	var count int
	err := ts.db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		t.Fatalf("counting users: %v", err)
	}
	if count != numClients {
		t.Errorf("expected %d users created, got %d", numClients, count)
	}

	t.Logf("server handled %d concurrent connections, %d users created", numClients, count)
}

func TestConcurrentSignRequests(t *testing.T) {
	ts := setupTestServer(t)

	// Set up a user with a signing key and auth
	signer, _, keyID := setupUserWithSigningKeyAndAuth(t, ts,
		[]string{"git-commit"}, nil, nil, nil,
	)

	const numRequests = 8 // Stay within rate limit burst
	var wg sync.WaitGroup
	var successes, failures atomic.Int32

	start := time.Now()

	for i := range numRequests {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			payload := []byte(fmt.Sprintf("concurrent commit %d", id))
			cmd := "sign --type git-commit --key-id " + keyID
			output, err := sshClientWithStdin(t, ts.addr, signer, cmd, payload)
			if err != nil {
				t.Logf("request %d: %v", id, err)
			}

			if len(output) > 0 && !contains(output, "error") {
				successes.Add(1)
			} else {
				failures.Add(1)
				t.Logf("request %d output: %s", id, output)
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("completed %d sign requests in %s (%d successes, %d failures)",
		numRequests, elapsed, successes.Load(), failures.Load())

	if successes.Load() < int32(numRequests) {
		t.Errorf("expected %d successful signs, got %d", numRequests, successes.Load())
	}

	// Verify audit entries
	auditCount := ts.auditLog.Count()
	if auditCount < int(numRequests) {
		t.Errorf("expected at least %d audit entries, got %d", numRequests, auditCount)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
