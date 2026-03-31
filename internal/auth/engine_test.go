package auth_test

import (
	"testing"
	"time"

	"github.com/agenticpoa/sshsign/internal/auth"
	"github.com/agenticpoa/sshsign/internal/storage"
)

func baseAuth() storage.Authorization {
	return storage.Authorization{
		TokenID:      "tok_test",
		SigningKeyID: "ak_test",
		GrantedBy:    "u_test",
		Scopes:       []string{"git-commit"},
		Constraints:  map[string][]string{"repo": {"github.com/user/*"}},
		HardRules:    []string{"never sign to main branch"},
		SoftRules:    []string{"alert if >10 sigs/hour"},
		CreatedAt:    time.Now(),
	}
}

func TestAuthorize_AllowedBasic(t *testing.T) {
	a := baseAuth()
	req := auth.SignRequest{
		ActionType: "git-commit",
		Metadata:   map[string]string{"repo": "github.com/user/myrepo", "branch": "feature-x"},
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if !d.Allowed {
		t.Fatalf("expected allowed, got denied: %s", d.DenialReason)
	}
	if d.TokenID != "tok_test" {
		t.Errorf("token ID = %q, want tok_test", d.TokenID)
	}
}

func TestAuthorize_ScopeMismatch(t *testing.T) {
	a := baseAuth()
	req := auth.SignRequest{
		ActionType: "api-request",
		Metadata:   map[string]string{"repo": "github.com/user/myrepo"},
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if d.Allowed {
		t.Fatal("expected denied for wrong scope")
	}
}

func TestAuthorize_ConstraintDenied(t *testing.T) {
	a := baseAuth()
	req := auth.SignRequest{
		ActionType: "git-commit",
		Metadata:   map[string]string{"repo": "github.com/other/repo", "branch": "dev"},
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if d.Allowed {
		t.Fatalf("expected denied for constraint violation, got allowed")
	}
	if d.DenialReason == "" {
		t.Error("denial reason should not be empty")
	}
}

func TestAuthorize_ConstraintAllowed_Wildcard(t *testing.T) {
	a := baseAuth()
	a.Constraints = map[string][]string{"repo": {"github.com/user/*"}}
	req := auth.SignRequest{
		ActionType: "git-commit",
		Metadata:   map[string]string{"repo": "github.com/user/any-repo", "branch": "dev"},
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if !d.Allowed {
		t.Fatalf("expected allowed for wildcard match, got denied: %s", d.DenialReason)
	}
}

func TestAuthorize_HardRuleViolation(t *testing.T) {
	a := baseAuth()
	req := auth.SignRequest{
		ActionType: "git-commit",
		Metadata:   map[string]string{"repo": "github.com/user/myrepo", "branch": "main"},
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if d.Allowed {
		t.Fatal("expected denied for hard rule violation (main branch)")
	}
	if d.DenialReason == "" {
		t.Error("denial reason should not be empty")
	}
}

func TestAuthorize_SoftRuleWarning(t *testing.T) {
	a := baseAuth()
	// Soft rules are currently logged but we test the structure is populated
	req := auth.SignRequest{
		ActionType: "git-commit",
		Metadata:   map[string]string{"repo": "github.com/user/myrepo", "branch": "dev"},
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if !d.Allowed {
		t.Fatalf("expected allowed, got denied: %s", d.DenialReason)
	}
	// Soft rules don't trigger for this request since it's a rate-based rule
	// Just verify the structure works
}

func TestAuthorize_Expired(t *testing.T) {
	a := baseAuth()
	pastTime := time.Now().Add(-24 * time.Hour)
	a.ExpiresAt = &pastTime

	req := auth.SignRequest{
		ActionType: "git-commit",
		Metadata:   map[string]string{"repo": "github.com/user/myrepo", "branch": "dev"},
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if d.Allowed {
		t.Fatal("expected denied for expired authorization")
	}
}

func TestAuthorize_NotYetExpired(t *testing.T) {
	a := baseAuth()
	futureTime := time.Now().Add(24 * time.Hour)
	a.ExpiresAt = &futureTime

	req := auth.SignRequest{
		ActionType: "git-commit",
		Metadata:   map[string]string{"repo": "github.com/user/myrepo", "branch": "dev"},
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if !d.Allowed {
		t.Fatalf("expected allowed for non-expired auth, got denied: %s", d.DenialReason)
	}
}

func TestAuthorize_Revoked(t *testing.T) {
	a := baseAuth()
	revokedTime := time.Now().Add(-1 * time.Hour)
	a.RevokedAt = &revokedTime

	req := auth.SignRequest{
		ActionType: "git-commit",
		Metadata:   map[string]string{"repo": "github.com/user/myrepo", "branch": "dev"},
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if d.Allowed {
		t.Fatal("expected denied for revoked authorization")
	}
}

func TestAuthorize_NoAuthorizations(t *testing.T) {
	req := auth.SignRequest{
		ActionType: "git-commit",
		Metadata:   map[string]string{},
	}

	d := auth.Authorize(nil, req, time.Now())
	if d.Allowed {
		t.Fatal("expected denied when no authorizations exist")
	}
}

func TestAuthorize_WildcardScope(t *testing.T) {
	a := baseAuth()
	a.Scopes = []string{"*"}
	a.Constraints = nil

	req := auth.SignRequest{
		ActionType: "anything",
		Metadata:   map[string]string{},
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if !d.Allowed {
		t.Fatalf("expected allowed for wildcard scope, got denied: %s", d.DenialReason)
	}
}

func TestAuthorize_MultipleAuthsFallthrough(t *testing.T) {
	// First auth only allows api-request, second allows git-commit
	a1 := baseAuth()
	a1.TokenID = "tok_1"
	a1.Scopes = []string{"api-request"}

	a2 := baseAuth()
	a2.TokenID = "tok_2"
	a2.Scopes = []string{"git-commit"}

	req := auth.SignRequest{
		ActionType: "git-commit",
		Metadata:   map[string]string{"repo": "github.com/user/myrepo", "branch": "dev"},
	}

	d := auth.Authorize([]storage.Authorization{a1, a2}, req, time.Now())
	if !d.Allowed {
		t.Fatalf("expected allowed via second auth, got denied: %s", d.DenialReason)
	}
	if d.TokenID != "tok_2" {
		t.Errorf("expected tok_2, got %s", d.TokenID)
	}
}

func TestAuthorize_MasterBranchHardRule(t *testing.T) {
	a := baseAuth()
	a.HardRules = []string{"never sign to master branch"}

	req := auth.SignRequest{
		ActionType: "git-commit",
		Metadata:   map[string]string{"repo": "github.com/user/myrepo", "branch": "master"},
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if d.Allowed {
		t.Fatal("expected denied for master branch hard rule")
	}
}

func TestAuthorize_StructuredRuleIDs(t *testing.T) {
	tests := []struct {
		name     string
		rule     string
		metadata map[string]string
		denied   bool
	}{
		{"no-main-branch blocks main", "no-main-branch", map[string]string{"repo": "github.com/user/x", "branch": "main"}, true},
		{"no-main-branch allows dev", "no-main-branch", map[string]string{"repo": "github.com/user/x", "branch": "dev"}, false},
		{"no-master-branch blocks master", "no-master-branch", map[string]string{"repo": "github.com/user/x", "branch": "master"}, true},
		{"no-master-branch allows main", "no-master-branch", map[string]string{"repo": "github.com/user/x", "branch": "main"}, false},
		{"no-force-push blocks force push", "no-force-push", map[string]string{"repo": "github.com/user/x", "force_push": "true"}, true},
		{"no-force-push allows normal", "no-force-push", map[string]string{"repo": "github.com/user/x"}, false},
		{"no-merge-commits blocks merge", "no-merge-commits", map[string]string{"repo": "github.com/user/x", "commit_type": "merge"}, true},
		{"no-merge-commits allows normal", "no-merge-commits", map[string]string{"repo": "github.com/user/x", "commit_type": "regular"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := baseAuth()
			a.HardRules = []string{tt.rule}
			a.Constraints = nil // don't interfere with constraint checks

			req := auth.SignRequest{
				ActionType: "git-commit",
				Metadata:   tt.metadata,
			}

			d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
			if tt.denied && d.Allowed {
				t.Errorf("expected denied, got allowed")
			}
			if !tt.denied && !d.Allowed {
				t.Errorf("expected allowed, got denied: %s", d.DenialReason)
			}
		})
	}
}
