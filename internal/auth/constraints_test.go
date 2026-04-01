package auth_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/agenticpoa/sshsign/internal/auth"
	"github.com/agenticpoa/sshsign/internal/storage"
)

func f64(v float64) *float64 { return &v }
func boolp(v bool) *bool     { return &v }

func safeAuth() storage.Authorization {
	return storage.Authorization{
		TokenID:      "tok_safe",
		SigningKeyID: "ak_test",
		GrantedBy:    "u_test",
		Scopes:       []string{"safe-agreement"},
		ConfirmationTier: "autonomous",
		MetadataConstraints: []storage.MetadataConstraint{
			{Type: "range", Field: "valuation_cap", Min: f64(8000000), Max: f64(12000000)},
			{Type: "minimum", Field: "discount_rate", Min: f64(0.20)},
			{Type: "required_bool", Field: "pro_rata", Required: boolp(true)},
		},
		CreatedAt: time.Now(),
	}
}

func TestMetadataConstraints_AllPass(t *testing.T) {
	a := safeAuth()
	req := auth.SignRequest{
		ActionType:      "safe-agreement",
		RequestMetadata: json.RawMessage(`{"valuation_cap":10000000,"discount_rate":0.25,"pro_rata":true}`),
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if !d.Allowed {
		t.Fatalf("expected allowed, got denied: %s", d.DenialReason)
	}
}

func TestMetadataConstraints_BelowMinimum(t *testing.T) {
	a := safeAuth()
	req := auth.SignRequest{
		ActionType:      "safe-agreement",
		RequestMetadata: json.RawMessage(`{"valuation_cap":10000000,"discount_rate":0.10,"pro_rata":true}`),
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if d.Allowed {
		t.Fatal("expected denied for discount_rate below minimum")
	}
	if d.DenialReason == "" {
		t.Error("denial reason should not be empty")
	}
}

func TestMetadataConstraints_AboveMaximum(t *testing.T) {
	a := storage.Authorization{
		TokenID:      "tok_max",
		SigningKeyID: "ak_test",
		GrantedBy:    "u_test",
		Scopes:       []string{"safe-agreement"},
		MetadataConstraints: []storage.MetadataConstraint{
			{Type: "maximum", Field: "penalty", Max: f64(500000)},
		},
		CreatedAt: time.Now(),
	}

	req := auth.SignRequest{
		ActionType:      "safe-agreement",
		RequestMetadata: json.RawMessage(`{"penalty":750000}`),
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if d.Allowed {
		t.Fatal("expected denied for penalty above maximum")
	}
}

func TestMetadataConstraints_OutsideRange(t *testing.T) {
	a := safeAuth()

	// Below range
	req := auth.SignRequest{
		ActionType:      "safe-agreement",
		RequestMetadata: json.RawMessage(`{"valuation_cap":5000000,"discount_rate":0.25,"pro_rata":true}`),
	}
	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if d.Allowed {
		t.Fatal("expected denied for valuation_cap below range")
	}

	// Above range
	req2 := auth.SignRequest{
		ActionType:      "safe-agreement",
		RequestMetadata: json.RawMessage(`{"valuation_cap":15000000,"discount_rate":0.25,"pro_rata":true}`),
	}
	d2 := auth.Authorize([]storage.Authorization{a}, req2, time.Now())
	if d2.Allowed {
		t.Fatal("expected denied for valuation_cap above range")
	}
}

func TestMetadataConstraints_RequiredBoolFalse(t *testing.T) {
	a := safeAuth()
	req := auth.SignRequest{
		ActionType:      "safe-agreement",
		RequestMetadata: json.RawMessage(`{"valuation_cap":10000000,"discount_rate":0.25,"pro_rata":false}`),
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if d.Allowed {
		t.Fatal("expected denied for pro_rata set to false")
	}
}

func TestMetadataConstraints_EnumNotInSet(t *testing.T) {
	a := storage.Authorization{
		TokenID:      "tok_enum",
		SigningKeyID: "ak_test",
		GrantedBy:    "u_test",
		Scopes:       []string{"nda"},
		MetadataConstraints: []storage.MetadataConstraint{
			{Type: "enum", Field: "nda_type", Allowed: []string{"mutual", "one-way"}},
		},
		CreatedAt: time.Now(),
	}

	req := auth.SignRequest{
		ActionType:      "nda",
		RequestMetadata: json.RawMessage(`{"nda_type":"bilateral"}`),
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if d.Allowed {
		t.Fatal("expected denied for enum value not in allowed set")
	}
}

func TestMetadataConstraints_EnumAllowed(t *testing.T) {
	a := storage.Authorization{
		TokenID:      "tok_enum",
		SigningKeyID: "ak_test",
		GrantedBy:    "u_test",
		Scopes:       []string{"nda"},
		MetadataConstraints: []storage.MetadataConstraint{
			{Type: "enum", Field: "nda_type", Allowed: []string{"mutual", "one-way"}},
		},
		CreatedAt: time.Now(),
	}

	req := auth.SignRequest{
		ActionType:      "nda",
		RequestMetadata: json.RawMessage(`{"nda_type":"mutual"}`),
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if !d.Allowed {
		t.Fatalf("expected allowed, got denied: %s", d.DenialReason)
	}
}

func TestMetadataConstraints_NoMetadataWhenConstraintsExist(t *testing.T) {
	a := safeAuth()
	req := auth.SignRequest{
		ActionType: "safe-agreement",
		// no RequestMetadata
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if d.Allowed {
		t.Fatal("expected denied when constraints exist but no metadata provided")
	}
}

func TestMetadataConstraints_ExtraFieldsAllowed(t *testing.T) {
	a := safeAuth()
	req := auth.SignRequest{
		ActionType:      "safe-agreement",
		RequestMetadata: json.RawMessage(`{"valuation_cap":10000000,"discount_rate":0.25,"pro_rata":true,"mfn":false,"extra_field":"whatever"}`),
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if !d.Allowed {
		t.Fatalf("expected allowed with extra fields, got denied: %s", d.DenialReason)
	}
}

func TestMetadataConstraints_BoundaryValues(t *testing.T) {
	a := safeAuth()

	// Exact minimum of range should pass
	req := auth.SignRequest{
		ActionType:      "safe-agreement",
		RequestMetadata: json.RawMessage(`{"valuation_cap":8000000,"discount_rate":0.20,"pro_rata":true}`),
	}
	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if !d.Allowed {
		t.Fatalf("expected allowed at exact minimum boundary, got denied: %s", d.DenialReason)
	}

	// Exact maximum of range should pass
	req2 := auth.SignRequest{
		ActionType:      "safe-agreement",
		RequestMetadata: json.RawMessage(`{"valuation_cap":12000000,"discount_rate":0.20,"pro_rata":true}`),
	}
	d2 := auth.Authorize([]storage.Authorization{a}, req2, time.Now())
	if !d2.Allowed {
		t.Fatalf("expected allowed at exact maximum boundary, got denied: %s", d2.DenialReason)
	}
}

func TestMetadataConstraints_NoConstraintsNoMetadata(t *testing.T) {
	a := storage.Authorization{
		TokenID:      "tok_noconst",
		SigningKeyID: "ak_test",
		GrantedBy:    "u_test",
		Scopes:       []string{"*"},
		CreatedAt:    time.Now(),
	}

	req := auth.SignRequest{
		ActionType: "anything",
	}

	d := auth.Authorize([]storage.Authorization{a}, req, time.Now())
	if !d.Allowed {
		t.Fatalf("expected allowed with no constraints, got denied: %s", d.DenialReason)
	}
}
