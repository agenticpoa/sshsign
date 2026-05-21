package server

import (
	"encoding/base64"
	"testing"
)

func TestDecodeB64JSON_URLSafe(t *testing.T) {
	original := `{"firm":"Blue Fund","amount":1000000}`
	encoded := base64.URLEncoding.EncodeToString([]byte(original))

	got, err := decodeB64JSON(encoded)
	if err != nil {
		t.Fatalf("decode URL-safe base64: %v", err)
	}
	if got != original {
		t.Errorf("decoded = %q, want %q", got, original)
	}
}

func TestDecodeB64JSON_StandardFallback(t *testing.T) {
	// Standard base64 alphabet uses + and / where URL-safe uses - and _.
	// A payload that includes those characters in its encoded form
	// would fail URL-safe decoding but should fall back to standard.
	original := `{"q":"a+b/c"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(original))

	got, err := decodeB64JSON(encoded)
	if err != nil {
		t.Fatalf("decode standard base64 fallback: %v", err)
	}
	if got != original {
		t.Errorf("decoded = %q, want %q", got, original)
	}
}

func TestDecodeB64JSON_InvalidInputErrors(t *testing.T) {
	cases := []string{
		"not base64 at all!",
		"%%%",
		"abc==xyz==",
	}
	for _, in := range cases {
		if _, err := decodeB64JSON(in); err == nil {
			t.Errorf("expected error decoding %q, got nil", in)
		}
	}
}

func TestDecodeB64JSON_HandlesValuesWithSpaces(t *testing.T) {
	// The whole point of the b64 escape hatch: a JSON string value
	// containing a space (which SSH argv would split into multiple
	// tokens) round-trips cleanly when base64-encoded.
	original := `{"company_name":"Acme Holdings Inc"}`
	encoded := base64.URLEncoding.EncodeToString([]byte(original))

	got, err := decodeB64JSON(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != original {
		t.Errorf("decoded = %q, want %q", got, original)
	}
}

func TestParseJSONArg_BareKeysRepaired(t *testing.T) {
	// SSH strips inner double quotes; parseJSONArg should repair the
	// bare-key form back to valid JSON.
	args := []string{"{key:1,nested:2}"}
	i := 0
	got := parseJSONArg(args, &i)
	want := `{"key":1,"nested":2}`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseJSONArg_RejoinsSpaceSplitTokens(t *testing.T) {
	// If JSON had spaces, SSH would split it; parseJSONArg rejoins
	// adjacent non-flag tokens. The result still needs the bare-key
	// repair to become valid JSON.
	args := []string{`{key:`, `"value`, `with`, `spaces"}`}
	i := 0
	got := parseJSONArg(args, &i)
	// idx should have advanced past the rejoined tokens.
	if i != 3 {
		t.Errorf("idx = %d after rejoin, want 3", i)
	}
	want := `{"key": "value with spaces"}`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseJSONArg_StopsAtFlagBoundary(t *testing.T) {
	// Rejoin must NOT consume the next flag.
	args := []string{`{a:1}`, `--next-flag`, `value`}
	i := 0
	_ = parseJSONArg(args, &i)
	if i != 0 {
		t.Errorf("idx = %d, want 0 (flag boundary)", i)
	}
}

func TestIsFlag(t *testing.T) {
	cases := map[string]bool{
		"--scope":      true,
		"--metadata":   true,
		"--":           true,
		"-x":           false,
		"value":        false,
		"a":            false,
		"":             false,
		"{a:1}":        false,
	}
	for in, want := range cases {
		if got := isFlag(in); got != want {
			t.Errorf("isFlag(%q) = %v, want %v", in, got, want)
		}
	}
}
