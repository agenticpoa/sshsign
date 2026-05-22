package server

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// fuzzTimeout caps the per-call duration of every code path we hit
// from the fuzzers. The targets here are nominally fast (regex
// substitution, base64 decode); anything that takes longer than 100ms
// on a 1KB input is almost certainly catastrophic backtracking or a
// pathological rejoin loop and should fail the test.
const fuzzTimeout = 100 * time.Millisecond

// runWithDeadline invokes fn and fails t with a "timeout" message if
// fn doesn't return inside fuzzTimeout. Useful for asserting bounded
// runtime under fuzzed inputs without requiring fn to accept a ctx.
func runWithDeadline(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(fuzzTimeout):
		t.Fatal("operation exceeded deadline; possible infinite loop or catastrophic backtracking")
	}
}

// FuzzParseJSONArg explores parseJSONArg with arbitrary inputs. The
// invariants we assert on every output:
//   - never panics
//   - idx never advances past len(args)
//   - returned string is either valid JSON OR a string the caller will
//     hand to json.Unmarshal (which will report a clean error)
//   - completes inside fuzzTimeout — guards against catastrophic
//     regex backtracking in fixBareJSONKeys
func FuzzParseJSONArg(f *testing.F) {
	// Seed corpus drawn from the unit tests and the real SSH-mangled
	// forms we know about from production.
	seeds := []string{
		`{"key":1}`,
		`{key:1}`,
		`{key:1,nested:2}`,
		`{"foo":"bar with spaces"}`,
		`{foo:"bar with spaces"}`,
		``,
		`{`,
		`}`,
		`{{{{`,
		`{a:`,
		`{"a":}`,
		`{"a":1`,
		`{"alpha":"beta"}`,
		`{"a":"x"}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		// Construct a small argv slice the way the real flag loops do.
		// The interesting case is the rejoin path, so include both a
		// single-arg and a space-split form.
		single := []string{raw}
		split := strings.Fields(raw)
		if len(split) == 0 {
			split = []string{""}
		}

		runWithDeadline(t, func() {
			i := 0
			_ = parseJSONArg(single, &i)
			if i < 0 || i >= len(single) {
				if i != 0 { // single-arg, idx should remain 0
					t.Errorf("single-arg idx advanced past bounds: i=%d len=%d", i, len(single))
				}
			}
		})

		runWithDeadline(t, func() {
			i := 0
			_ = parseJSONArg(split, &i)
			if i < 0 || i >= len(split) {
				t.Errorf("split-arg idx out of bounds: i=%d len=%d", i, len(split))
			}
		})
	})
}

// FuzzFixBareJSONKeys focuses on the regex substitution alone. The
// regex repairs `{foo:` to `{"foo":` — under fuzz we mainly care
// that it terminates quickly on adversarial input. Catastrophic
// backtracking in a regex used on attacker-controlled SSH argv would
// be a denial-of-service vector.
func FuzzFixBareJSONKeys(f *testing.F) {
	seeds := []string{
		`{foo:1}`,
		`{`,
		``,
		strings.Repeat("{", 1000),                // many openings
		strings.Repeat(",a:", 200),               // many bare-key candidates
		strings.Repeat("a", 5000),                // long non-matching text
		`{a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_:1}`, // long bare key
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		runWithDeadline(t, func() {
			_ = fixBareJSONKeys(raw)
		})
	})
}

// FuzzDecodeB64JSON checks the base64 decode helper. The invariants:
//   - never panics
//   - on success, the returned string is the byte-exact decoding
//     (length matches base64 length math)
//   - on failure, returns a non-nil error and an empty string
func FuzzDecodeB64JSON(f *testing.F) {
	seeds := []string{
		base64.URLEncoding.EncodeToString([]byte(`{"a":1}`)),
		base64.StdEncoding.EncodeToString([]byte(`{"firm":"Blue Fund"}`)),
		``,
		`not base64`,
		`%%%`,
		`====`,
		`AAAA`,
		`abc==xyz==`,
		strings.Repeat("A", 10000),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, encoded string) {
		runWithDeadline(t, func() {
			got, err := decodeB64JSON(encoded)
			if err != nil {
				if got != "" {
					t.Errorf("err=%v but got=%q (want empty on error)", err, got)
				}
				return
			}
			// On success, the bytes returned must be exactly the
			// base64 decoding of the input under one of the two
			// alphabets the helper tries.
			urlDecoded, urlErr := base64.URLEncoding.DecodeString(encoded)
			stdDecoded, stdErr := base64.StdEncoding.DecodeString(encoded)
			matchesURL := urlErr == nil && string(urlDecoded) == got
			matchesStd := stdErr == nil && string(stdDecoded) == got
			if !matchesURL && !matchesStd {
				t.Errorf("returned %q matches neither URL-safe nor standard decoding", got)
			}
		})
	})
}

// FuzzIsFlag is trivial but cheap; included so the fuzz corpus
// builds at least one entry that exercises the boundary check used
// by the rejoin loop in parseJSONArg.
func FuzzIsFlag(f *testing.F) {
	for _, s := range []string{"--scope", "--", "-x", "value", "", "a", "{a:1}"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := isFlag(s)
		want := len(s) >= 2 && s[0] == '-' && s[1] == '-'
		if got != want {
			t.Errorf("isFlag(%q) = %v, want %v", s, got, want)
		}
	})
}

// Sanity unit test: the fuzzers above pass round-trip JSON through
// parseJSONArg. Documents the invariant we care about even when the
// fuzz harness isn't running.
func TestParseJSONArg_ValidJSONRoundTrips(t *testing.T) {
	cases := []string{
		`{"a":1}`,
		`{"nested":{"x":"y"}}`,
		`[1,2,3]`,
		`true`,
		`null`,
		`"a string"`,
	}
	for _, in := range cases {
		args := []string{in}
		i := 0
		got := parseJSONArg(args, &i)
		if !json.Valid([]byte(got)) {
			t.Errorf("parseJSONArg(%q) = %q, want valid JSON", in, got)
		}
	}
}
