package server

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/agenticpoa/sshsign/internal/sessions"
)

func TestParseSessionFlags_SimpleKV(t *testing.T) {
	out, err := parseSessionFlags([]string{
		"--session-id", "neg_1",
		"--role", "founder",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out["session-id"] != "neg_1" || out["role"] != "founder" {
		t.Fatalf("unexpected: %#v", out)
	}
}

func TestParseSessionFlags_BooleanFlag(t *testing.T) {
	out, err := parseSessionFlags([]string{
		"--rescind",
		"--session-id", "neg_1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out["rescind"] != "true" {
		t.Fatalf("expected rescind=true, got %q", out["rescind"])
	}
	if out["session-id"] != "neg_1" {
		t.Fatalf("session-id mismatch: %q", out["session-id"])
	}
}

func TestParseSessionFlags_MultiLinePEMRejoined(t *testing.T) {
	// SSH splits the single remote command line on whitespace (including
	// newlines), so a client passing --apoa-pubkey "$(cat pub.pem)"
	// arrives here as multiple separate args. The parser must stitch them
	// back together with newlines through the trailing -----END marker.
	args := []string{
		"--session-id", "neg_1",
		"--role", "founder",
		"--apoa-pubkey",
		"-----BEGIN",
		"PUBLIC",
		"KEY-----",
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKEY",
		"-----END",
		"PUBLIC",
		"KEY-----",
	}
	out, err := parseSessionFlags(args)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	got := out["apoa-pubkey"]
	// Canonical PEM: single-line header + base64 data + single-line footer
	if !strings.HasPrefix(got, "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("expected canonical PEM header, got: %q", got)
	}
	if !strings.HasSuffix(got, "-----END PUBLIC KEY-----") {
		t.Fatalf("expected canonical PEM footer, got: %q", got)
	}
	if out["session-id"] != "neg_1" || out["role"] != "founder" {
		t.Fatalf("sibling flags mangled: %#v", out)
	}
}

func TestParseSessionFlags_PEMIsGoParseable(t *testing.T) {
	// End-to-end validation: the rejoined PEM must decode cleanly with
	// Go's pem package, otherwise signature-verify paths blow up.
	args := []string{
		"--apoa-pubkey",
		"-----BEGIN",
		"PUBLIC",
		"KEY-----",
		"MCowBQYDK2VwAyEAcdSPrRI/ac1w5FdQHFZxoE5asT18DNckUwkRMIrMKmU=",
		"-----END",
		"PUBLIC",
		"KEY-----",
	}
	out, err := parseSessionFlags(args)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	block, _ := pem.Decode([]byte(out["apoa-pubkey"]))
	if block == nil {
		t.Fatalf("pem.Decode failed on: %q", out["apoa-pubkey"])
	}
	if block.Type != "PUBLIC KEY" {
		t.Fatalf("expected type PUBLIC KEY, got %q", block.Type)
	}
}

func TestParseSessionFlags_PEMFollowedByAnotherFlag(t *testing.T) {
	// After the -----END line closes the PEM, the next "--" flag must still
	// parse as its own flag (not get swallowed into the PEM block).
	args := []string{
		"--apoa-pubkey",
		"-----BEGIN",
		"PUBLIC",
		"KEY-----",
		"abc",
		"-----END",
		"PUBLIC",
		"KEY-----",
		"--role", "investor",
	}
	out, err := parseSessionFlags(args)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out["role"] != "investor" {
		t.Fatalf("role lost: %#v", out)
	}
}

func TestParseSessionFlags_FlagBreaksMidPEM(t *testing.T) {
	// If an input is malformed (a flag sneaks into the PEM before END is
	// seen), the parser should stop joining and process the flag normally.
	// This avoids infinite-join runaway on pathological input.
	args := []string{
		"--apoa-pubkey",
		"-----BEGIN",
		"PUBLIC",
		"KEY-----",
		"--role", "investor",
	}
	out, err := parseSessionFlags(args)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out["role"] != "investor" {
		t.Fatalf("role must still parse: %#v", out)
	}
	if !strings.Contains(out["apoa-pubkey"], "PUBLIC") {
		t.Fatalf("partial PEM not captured: %#v", out)
	}
}

func TestParseSessionFlags_RejectsBareArg(t *testing.T) {
	_, err := parseSessionFlags([]string{"session-id", "neg_1"})
	if err == nil {
		t.Fatalf("expected error for bare arg")
	}
}

func TestParseSessionFlags_JSONWithSpaces(t *testing.T) {
	// SSH splits `{"use_case":"safe", "version":1}` on the comma-space,
	// so the value arrives as multiple args. The parser must rejoin
	// until JSON is valid.
	args := []string{
		"--metadata-public",
		`{"use_case":"safe",`, `"version":1,`, `"company_name":"APOA`, `Inc"}`,
		"--role", "founder",
	}
	out, err := parseSessionFlags(args)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out["role"] != "founder" {
		t.Fatalf("role lost after JSON rejoin: %#v", out)
	}
	md := out["metadata-public"]
	if !strings.Contains(md, "APOA Inc") {
		t.Fatalf("JSON not rejoined properly: %q", md)
	}
}

// P8-2: `--metadata-*-b64` flags carry base64-encoded JSON so string
// values with spaces or inner quotes survive SSH argv without needing
// the fragile bare-value repair path.

func TestParseSessionFlags_MetadataPublicB64Decoded(t *testing.T) {
	raw := `{"use_case":"safe","version":1,"company_name":"Blue Fund"}`
	encoded := base64.URLEncoding.EncodeToString([]byte(raw))
	out, err := parseSessionFlags([]string{
		"--role", "founder",
		"--metadata-public-b64", encoded,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out["metadata-public"] != raw {
		t.Fatalf("expected %q, got %q", raw, out["metadata-public"])
	}
	if _, ok := out["metadata-public-b64"]; ok {
		t.Fatalf("b64 key should be consumed, got: %#v", out)
	}
}

func TestParseSessionFlags_MetadataMemberB64Decoded(t *testing.T) {
	raw := `{"investor_firm":"Blue Fund","investor_name":"Alex Chen"}`
	encoded := base64.URLEncoding.EncodeToString([]byte(raw))
	out, err := parseSessionFlags([]string{
		"--metadata-member-b64", encoded,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out["metadata-member"] != raw {
		t.Fatalf("got %q", out["metadata-member"])
	}
}

func TestParseSessionFlags_B64FallsBackToStdEncoding(t *testing.T) {
	// Client that forgets to swap + for - still works.
	raw := `{"k":"a+b/c"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	out, err := parseSessionFlags([]string{"--metadata-public-b64", encoded})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out["metadata-public"] != raw {
		t.Fatalf("got %q", out["metadata-public"])
	}
}

func TestParseSessionFlags_B64RejectsInvalid(t *testing.T) {
	_, err := parseSessionFlags([]string{"--metadata-public-b64", "!!!not-b64!!!"})
	if err == nil {
		t.Fatalf("expected error on invalid base64")
	}
	if !strings.Contains(err.Error(), "invalid base64") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseSessionFlags_B64AndPlainConflict(t *testing.T) {
	// Clients must pick one form; supporting both silently would make
	// precedence ambiguous (does b64 win? plain win?).
	encoded := base64.URLEncoding.EncodeToString([]byte(`{"a":1}`))
	_, err := parseSessionFlags([]string{
		"--metadata-public", `{"a":1}`,
		"--metadata-public-b64", encoded,
	})
	if err == nil {
		t.Fatalf("expected error on double-set")
	}
	if !strings.Contains(err.Error(), "cannot set both") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseSessionFlags_B64PreservesInnerQuotesAcrossArgv(t *testing.T) {
	// Regression fixture for the actual bug: a string value with a space
	// that would have been mangled by the legacy repair path is bit-perfect
	// after base64 round-trip.
	raw := `{"investor_firm":"Blue Fund","investor_name":"Alex Chen"}`
	encoded := base64.URLEncoding.EncodeToString([]byte(raw))
	out, err := parseSessionFlags([]string{"--metadata-member-b64", encoded})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// Must NOT have suffered quote-stripping.
	if !strings.Contains(out["metadata-member"], `"Blue Fund"`) {
		t.Fatalf("inner quotes lost: %q", out["metadata-member"])
	}
}

func TestParseSessionFlags_BareKeysWithValuesPassedThrough(t *testing.T) {
	// Pathological case where SSH strips ALL inner quotes and there's
	// nothing to rejoin (`{use_case:safe}` is malformed JSON we cannot
	// repair: bare value `safe` has no context). Parser passes it
	// through unchanged; the session handler's downstream JSON decode
	// surfaces a clearer error to the user than an argv complaint.
	args := []string{
		"--metadata-public", "{use_case:safe}",
		"--role", "founder",
	}
	out, err := parseSessionFlags(args)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out["role"] != "founder" {
		t.Fatalf("role lost: %#v", out)
	}
	// Pass-through, unchanged.
	if out["metadata-public"] != "{use_case:safe}" {
		t.Fatalf("expected pass-through, got: %q", out["metadata-public"])
	}
}

// P7-5 regression: marshalSession must serialize founder_resumed_at +
// founder_streaming_at when set on a Member. They were initially missed
// (added to the DB schema + Member struct + repo SELECT, but not to the
// wire-format memberView), causing the investor's Python poll to never
// see streaming_at and time out at 180s instead of detecting the live
// founder. Caught during the first live dry-run on INV-6Z4K7.
func TestMarshalSession_IncludesFounderResumedAndStreamingTimestamps(t *testing.T) {
	resumedAt := int64(1714000000)
	streamingAt := int64(1714000005)

	sess := &sessions.Session{
		SessionID:   "neg_1",
		SessionCode: "INV-X",
		CreatedBy:   "alice",
		Status:      "joined",
	}
	members := []sessions.Member{
		{
			Role:               "founder",
			UserID:             "alice",
			FounderResumedAt:   &resumedAt,
			FounderStreamingAt: &streamingAt,
		},
		{Role: "investor", UserID: "bob"}, // both fields nil → omitempty
	}

	v := marshalSession(sess, members, true)
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(out)
	if !strings.Contains(body, `"founder_resumed_at":1714000000`) {
		t.Errorf("founder_resumed_at missing from wire format: %s", body)
	}
	if !strings.Contains(body, `"founder_streaming_at":1714000005`) {
		t.Errorf("founder_streaming_at missing from wire format: %s", body)
	}
	// Investor row has nil pointers → keys must be omitted.
	if strings.Contains(body, `"role":"investor",.*"founder_resumed_at"`) {
		t.Errorf("nil pointer should be omitted, not zero-serialized: %s", body)
	}
}
