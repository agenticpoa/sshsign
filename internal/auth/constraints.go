package auth

import (
	"encoding/json"
	"fmt"

	"github.com/agenticpoa/sshsign/internal/storage"
)

// checkMetadataConstraints validates request metadata against typed constraints.
// Returns empty string if all constraints pass, or a denial reason.
func checkMetadataConstraints(constraints []storage.MetadataConstraint, rawMetadata json.RawMessage) string {
	if len(constraints) == 0 {
		return ""
	}

	// Constraints exist but no metadata provided
	if len(rawMetadata) == 0 {
		return "metadata required: authorization has constraints but no metadata was provided"
	}

	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(rawMetadata, &metadata); err != nil {
		return fmt.Sprintf("invalid metadata JSON: %v", err)
	}

	for _, c := range constraints {
		fieldRaw, ok := metadata[c.Field]
		if !ok {
			return fmt.Sprintf("constraint violation: required metadata field %q not provided", c.Field)
		}

		if reason := validateConstraint(c, fieldRaw); reason != "" {
			return reason
		}
	}

	return ""
}

func validateConstraint(c storage.MetadataConstraint, fieldRaw json.RawMessage) string {
	switch c.Type {
	case "range":
		return validateRange(c, fieldRaw)
	case "minimum":
		return validateMinimum(c, fieldRaw)
	case "maximum":
		return validateMaximum(c, fieldRaw)
	case "enum":
		return validateEnum(c, fieldRaw)
	case "required_bool":
		return validateRequiredBool(c, fieldRaw)
	default:
		return fmt.Sprintf("unknown constraint type %q for field %q", c.Type, c.Field)
	}
}

func validateRange(c storage.MetadataConstraint, fieldRaw json.RawMessage) string {
	var val float64
	if err := json.Unmarshal(fieldRaw, &val); err != nil {
		return fmt.Sprintf("constraint violation: field %q must be a number, got %s", c.Field, string(fieldRaw))
	}
	if c.Min != nil && val < *c.Min {
		return fmt.Sprintf("constraint violation: field %q value %v is below minimum %v", c.Field, val, *c.Min)
	}
	if c.Max != nil && val > *c.Max {
		return fmt.Sprintf("constraint violation: field %q value %v exceeds maximum %v", c.Field, val, *c.Max)
	}
	return ""
}

func validateMinimum(c storage.MetadataConstraint, fieldRaw json.RawMessage) string {
	var val float64
	if err := json.Unmarshal(fieldRaw, &val); err != nil {
		return fmt.Sprintf("constraint violation: field %q must be a number, got %s", c.Field, string(fieldRaw))
	}
	if c.Min != nil && val < *c.Min {
		return fmt.Sprintf("constraint violation: field %q value %v is below minimum %v", c.Field, val, *c.Min)
	}
	return ""
}

func validateMaximum(c storage.MetadataConstraint, fieldRaw json.RawMessage) string {
	var val float64
	if err := json.Unmarshal(fieldRaw, &val); err != nil {
		return fmt.Sprintf("constraint violation: field %q must be a number, got %s", c.Field, string(fieldRaw))
	}
	if c.Max != nil && val > *c.Max {
		return fmt.Sprintf("constraint violation: field %q value %v exceeds maximum %v", c.Field, val, *c.Max)
	}
	return ""
}

func validateEnum(c storage.MetadataConstraint, fieldRaw json.RawMessage) string {
	var val string
	if err := json.Unmarshal(fieldRaw, &val); err != nil {
		return fmt.Sprintf("constraint violation: field %q must be a string, got %s", c.Field, string(fieldRaw))
	}
	for _, allowed := range c.Allowed {
		if val == allowed {
			return ""
		}
	}
	return fmt.Sprintf("constraint violation: field %q value %q not in allowed set %v", c.Field, val, c.Allowed)
}

func validateRequiredBool(c storage.MetadataConstraint, fieldRaw json.RawMessage) string {
	var val bool
	if err := json.Unmarshal(fieldRaw, &val); err != nil {
		return fmt.Sprintf("constraint violation: field %q must be a boolean, got %s", c.Field, string(fieldRaw))
	}
	if c.Required != nil && *c.Required && !val {
		return fmt.Sprintf("constraint violation: field %q must be true", c.Field)
	}
	return ""
}
