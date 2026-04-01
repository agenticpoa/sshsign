package auth

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/agenticpoa/sshsign/internal/storage"
)

// Decision represents the result of an authorization check.
type Decision struct {
	Allowed          bool
	TokenID          string
	ConfirmationTier string // "autonomous" or "cosign"
	DenialReason     string
	SoftWarnings     []string // soft rule violations (logged but allowed)
	ScopesChecked    []string
	RulesChecked     []string
}

// SignRequest holds the parameters for a signing authorization check.
type SignRequest struct {
	ActionType      string            // e.g. "git-commit", "safe-agreement"
	Metadata        map[string]string // e.g. {"repo": "github.com/user/repo", "branch": "main"}
	RequestMetadata json.RawMessage   // typed metadata JSON for constraint validation
}

// Authorize checks whether a signing key is authorized to perform the requested action.
// It evaluates all active authorizations for the key and returns a decision.
func Authorize(auths []storage.Authorization, req SignRequest, now time.Time) Decision {
	if len(auths) == 0 {
		return Decision{
			Allowed:      false,
			DenialReason: "no active authorizations for this signing key",
		}
	}

	var lastDenial Decision
	for _, auth := range auths {
		decision := evaluateAuth(auth, req, now)
		if decision.Allowed {
			return decision
		}
		// Keep the most specific denial (prefer rule/constraint denials over scope mismatches)
		if lastDenial.DenialReason == "" || decision.TokenID != "" {
			lastDenial = decision
		}
	}

	return lastDenial
}

func evaluateAuth(auth storage.Authorization, req SignRequest, now time.Time) Decision {
	d := Decision{
		TokenID:          auth.TokenID,
		ConfirmationTier: auth.ConfirmationTier,
	}

	// Check expiration
	if auth.ExpiresAt != nil && now.After(*auth.ExpiresAt) {
		d.DenialReason = "authorization expired"
		return d
	}

	// Check revocation
	if auth.RevokedAt != nil {
		d.DenialReason = "authorization revoked"
		return d
	}

	// Check scopes
	d.ScopesChecked = auth.Scopes
	if !scopeMatches(auth.Scopes, req.ActionType) {
		d.DenialReason = fmt.Sprintf("action type %q not in authorized scopes %v", req.ActionType, auth.Scopes)
		return d
	}

	// Check constraints (glob-pattern based)
	if reason := checkConstraints(auth.Constraints, req.Metadata); reason != "" {
		d.DenialReason = reason
		return d
	}

	// Check typed metadata constraints (range, minimum, maximum, enum, required_bool)
	if reason := checkMetadataConstraints(auth.MetadataConstraints, req.RequestMetadata); reason != "" {
		d.DenialReason = reason
		return d
	}

	// Check hard rules (deny if violated)
	d.RulesChecked = append(auth.HardRules, auth.SoftRules...)
	if reason := checkHardRules(auth.HardRules, req); reason != "" {
		d.DenialReason = "hard rule: " + reason
		return d
	}

	// Check soft rules (warn but allow)
	d.SoftWarnings = checkSoftRules(auth.SoftRules, req)

	d.Allowed = true
	return d
}

func scopeMatches(scopes []string, actionType string) bool {
	for _, scope := range scopes {
		if scope == actionType || scope == "*" {
			return true
		}
	}
	return false
}

func checkConstraints(constraints map[string][]string, metadata map[string]string) string {
	for key, patterns := range constraints {
		value, ok := metadata[key]
		if !ok {
			// If constraint is defined but metadata doesn't have the key,
			// that's a constraint violation (unknown context)
			return fmt.Sprintf("constraint %q requires metadata key %q", key, key)
		}

		if !matchesAny(value, patterns) {
			return fmt.Sprintf("constraint violation: %q=%q does not match allowed patterns %v", key, value, patterns)
		}
	}
	return ""
}

// matchesAny checks if a value matches any of the given glob patterns.
func matchesAny(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, value); matched {
			return true
		}
		// Also support ** prefix matching for paths like "github.com/user/*"
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			if strings.HasPrefix(value, prefix+"/") || value == prefix {
				return true
			}
		}
	}
	return false
}

func checkHardRules(rules []string, req SignRequest) string {
	for _, rule := range rules {
		if violated, reason := evaluateRule(rule, req); violated {
			return reason
		}
	}
	return ""
}

func checkSoftRules(rules []string, req SignRequest) []string {
	var warnings []string
	for _, rule := range rules {
		if violated, reason := evaluateRule(rule, req); violated {
			warnings = append(warnings, reason)
		}
	}
	return warnings
}

// RuleDefinition describes a predefined, enforceable rule.
type RuleDefinition struct {
	ID          string // stored in DB, e.g. "no-main-branch"
	Label       string // displayed in TUI
	Description string // help text
	Kind        string // "hard" or "soft"
}

// PredefinedRules are the rules available in the TUI picker.
// Every rule here has a matching evaluator in evaluateRule.
var PredefinedRules = []RuleDefinition{
	{ID: "no-main-branch", Label: "Block signing to main branch", Description: "Deny commits targeting the main branch", Kind: "hard"},
	{ID: "no-force-push", Label: "Block force-push commits", Description: "Deny commits with force-push metadata", Kind: "hard"},
	{ID: "no-merge-commits", Label: "Block merge commits", Description: "Deny merge commits (only fast-forward)", Kind: "hard"},
}

// evaluateRule checks a structured rule ID against a request.
func evaluateRule(rule string, req SignRequest) (bool, string) {
	branch := req.Metadata["branch"]
	commitType := req.Metadata["commit_type"]

	switch rule {
	case "no-main-branch":
		if branch == "main" {
			return true, fmt.Sprintf("rule %q violated: branch is %q", rule, branch)
		}
	case "no-master-branch":
		if branch == "master" {
			return true, fmt.Sprintf("rule %q violated: branch is %q", rule, branch)
		}
	case "no-force-push":
		if req.Metadata["force_push"] == "true" {
			return true, fmt.Sprintf("rule %q violated: force push detected", rule)
		}
	case "no-merge-commits":
		if commitType == "merge" {
			return true, fmt.Sprintf("rule %q violated: merge commit detected", rule)
		}
	case "alert-high-frequency":
		// Soft rule: rate-based alerting is checked at the server level,
		// but we flag it here so it shows in audit logs
		return false, ""
	default:
		// Legacy natural-language rules: best-effort matching for backwards compat
		normalized := strings.ToLower(strings.TrimSpace(rule))
		if strings.Contains(normalized, "never sign to") {
			for _, forbidden := range []string{"main", "master"} {
				if strings.Contains(normalized, forbidden) && branch == forbidden {
					return true, fmt.Sprintf("rule %q violated: branch is %q", rule, branch)
				}
			}
		}
	}

	return false, ""
}
