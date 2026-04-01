package tui

// authTemplate defines a pre-configured authorization setup template.
type authTemplate struct {
	ID               string
	Label            string // display name in picker
	Description      string // one-liner
	Scope            string // pre-filled scope (empty for custom)
	ConfirmationTier string // default tier: "autonomous" or "cosign"
	Constraints      []constraintTemplate
	ShowRepoConstraint bool
	ShowRules          bool
	ShowTierPicker     bool
}

// constraintTemplate defines a pre-configured metadata constraint with defaults.
type constraintTemplate struct {
	Field      string   // metadata field name
	Label      string   // display name
	Type       string   // range, minimum, maximum, enum, required_bool
	DefaultMin *float64 // for range, minimum
	DefaultMax *float64 // for range, maximum
	Allowed    []string // for enum
	Required   *bool    // for required_bool
}

func f64ptr(v float64) *float64 { return &v }
func boolptr(v bool) *bool      { return &v }

var authTemplates = []authTemplate{
	{
		ID:                 "git-commit",
		Label:              "Git commit signing",
		Description:        "Sign git commits with repo and branch rules",
		Scope:              "git-commit",
		ConfirmationTier:   "autonomous",
		ShowRepoConstraint: true,
		ShowRules:          true,
		ShowTierPicker:     false,
	},
	{
		ID:               "safe-agreement",
		Label:            "SAFE agreement",
		Description:      "Sign SAFE investment agreements (requires co-sign)",
		Scope:            "safe-agreement",
		ConfirmationTier: "cosign",
		ShowTierPicker:   true,
		Constraints: []constraintTemplate{
			{Field: "valuation_cap", Label: "Valuation Cap ($)", Type: "range", DefaultMin: f64ptr(100000), DefaultMax: f64ptr(50000000)},
			{Field: "discount_rate", Label: "Discount Rate", Type: "minimum", DefaultMin: f64ptr(0)},
			{Field: "pro_rata", Label: "Pro-Rata Rights", Type: "required_bool", Required: boolptr(true)},
		},
	},
	{
		ID:               "nda",
		Label:            "NDA signing",
		Description:      "Sign non-disclosure agreements",
		Scope:            "nda",
		ConfirmationTier: "autonomous",
		ShowTierPicker:   true,
		Constraints: []constraintTemplate{
			{Field: "nda_type", Label: "NDA Type", Type: "enum", Allowed: []string{"mutual", "one-way"}},
			{Field: "term_years", Label: "Term (years)", Type: "range", DefaultMin: f64ptr(1), DefaultMax: f64ptr(10)},
		},
	},
	{
		ID:               "custom",
		Label:            "Custom",
		Description:      "Define scope and constraints manually",
		Scope:            "",
		ConfirmationTier: "autonomous",
		ShowTierPicker:   true,
	},
}
