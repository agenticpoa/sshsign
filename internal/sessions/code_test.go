package sessions

import (
	"strings"
	"testing"
)

func TestGenerateCode(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		code, err := GenerateCode()
		if err != nil {
			t.Fatalf("GenerateCode: %v", err)
		}
		if !strings.HasPrefix(code, "INV-") {
			t.Errorf("code %q missing INV- prefix", code)
		}
		// Total length = len("INV-") + 5
		if len(code) != len("INV-")+codeLength {
			t.Errorf("code %q length %d, want %d", code, len(code), len("INV-")+codeLength)
		}
		body := strings.TrimPrefix(code, "INV-")
		for _, r := range body {
			if !strings.ContainsRune(codeAlphabet, r) {
				t.Errorf("code %q contains char outside alphabet: %q", code, r)
			}
		}
		// Collision across 1000 samples = a smell test, not a guarantee
		if seen[code] {
			t.Logf("collision at %dth sample: %q", i, code)
		}
		seen[code] = true
	}
}

func TestAlphabetExcludesConfusables(t *testing.T) {
	for _, c := range []string{"0", "1", "I", "L", "O", "U", "V"} {
		if strings.Contains(codeAlphabet, c) {
			t.Errorf("alphabet contains confusable character %q", c)
		}
	}
}
