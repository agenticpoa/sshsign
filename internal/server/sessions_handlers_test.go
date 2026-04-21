package server

import (
	"encoding/pem"
	"strings"
	"testing"
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
