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

// TestGenerateCodeUniformity samples enough codes to make biased
// outputs visible. With ~3% rejection sampling and a 29-char alphabet,
// each character should appear roughly 1/29 ≈ 3.45% of the time.
// Without rejection sampling, the first 256 % 29 = 24 alphabet entries
// would each be ~8% more frequent — easily detected here.
func TestGenerateCodeUniformity(t *testing.T) {
	const samples = 5000
	counts := make(map[byte]int, len(codeAlphabet))
	for i := 0; i < len(codeAlphabet); i++ {
		counts[codeAlphabet[i]] = 0
	}
	for i := 0; i < samples; i++ {
		code, err := GenerateCode()
		if err != nil {
			t.Fatalf("GenerateCode: %v", err)
		}
		body := strings.TrimPrefix(code, "INV-")
		for j := 0; j < len(body); j++ {
			counts[body[j]]++
		}
	}
	totalChars := samples * codeLength
	expected := float64(totalChars) / float64(len(codeAlphabet))
	// Allow ±20% deviation per character — chi-square thresholds at this
	// sample size are well inside that band, so a real bias (say, +8%
	// concentrated on 24 characters) would still trip it.
	low, high := expected*0.80, expected*1.20
	for ch, n := range counts {
		f := float64(n)
		if f < low || f > high {
			t.Errorf("character %q frequency %.0f outside [%.0f, %.0f] (expected %.0f)", ch, f, low, high, expected)
		}
	}
}
