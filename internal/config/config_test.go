package config_test

import (
	"strings"
	"testing"

	"github.com/agenticpoa/sshsign/internal/config"
)

const validSecret = "abcdefghijklmnopqrstuvwxyz012345" // exactly 32 chars

// envVars are the keys Load reads. Cleared via t.Setenv on every test
// so values from the developer's shell don't leak in and make the
// table tests inconsistent.
var envVars = []string{
	"SSHSIGN_LISTEN_ADDR",
	"SSHSIGN_DB_PATH",
	"SSHSIGN_HOST_KEY_PATH",
	"SSHSIGN_KEK_SECRET",
	"SSHSIGN_HTTP_DOMAIN",
	"SSHSIGN_HTTP_ADDR",
	"SSHSIGN_TLS_CERT",
	"SSHSIGN_TLS_KEY",
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range envVars {
		t.Setenv(k, "")
	}
}

func TestLoad_RequiresKEKSecret(t *testing.T) {
	clearEnv(t)
	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error when SSHSIGN_KEK_SECRET is empty")
	}
	if !strings.Contains(err.Error(), "SSHSIGN_KEK_SECRET") {
		t.Errorf("error should mention the env var, got: %v", err)
	}
}

func TestLoad_RejectsShortSecret(t *testing.T) {
	clearEnv(t)
	t.Setenv("SSHSIGN_KEK_SECRET", "tooshort")
	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for 8-char secret")
	}
	if !strings.Contains(err.Error(), "32 characters") {
		t.Errorf("error should mention the 32-char minimum, got: %v", err)
	}
}

func TestLoad_AcceptsExactly32Chars(t *testing.T) {
	clearEnv(t)
	t.Setenv("SSHSIGN_KEK_SECRET", validSecret)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load failed for 32-char secret: %v", err)
	}
	if cfg.KEKSecret != validSecret {
		t.Errorf("KEKSecret = %q, want %q", cfg.KEKSecret, validSecret)
	}
}

func TestLoad_AppliesDefaults(t *testing.T) {
	clearEnv(t)
	t.Setenv("SSHSIGN_KEK_SECRET", validSecret)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cases := map[string]string{
		"ListenAddr":  ":2222",
		"DBPath":      "./sshsign.db",
		"HostKeyPath": "./host_key",
		"HTTPDomain":  "sshsign.dev",
		"HTTPAddr":    ":8443",
	}
	got := map[string]string{
		"ListenAddr":  cfg.ListenAddr,
		"DBPath":      cfg.DBPath,
		"HostKeyPath": cfg.HostKeyPath,
		"HTTPDomain":  cfg.HTTPDomain,
		"HTTPAddr":    cfg.HTTPAddr,
	}
	for field, want := range cases {
		if got[field] != want {
			t.Errorf("%s default = %q, want %q", field, got[field], want)
		}
	}
}

func TestLoad_EnvOverridesDefaults(t *testing.T) {
	clearEnv(t)
	t.Setenv("SSHSIGN_KEK_SECRET", validSecret)
	t.Setenv("SSHSIGN_LISTEN_ADDR", ":2200")
	t.Setenv("SSHSIGN_DB_PATH", "/var/lib/sshsign/db")
	t.Setenv("SSHSIGN_HOST_KEY_PATH", "/etc/sshsign/host_key")
	t.Setenv("SSHSIGN_HTTP_DOMAIN", "sign.example.com")
	t.Setenv("SSHSIGN_HTTP_ADDR", ":443")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":2200" {
		t.Errorf("ListenAddr = %q, want :2200", cfg.ListenAddr)
	}
	if cfg.DBPath != "/var/lib/sshsign/db" {
		t.Errorf("DBPath = %q", cfg.DBPath)
	}
	if cfg.HostKeyPath != "/etc/sshsign/host_key" {
		t.Errorf("HostKeyPath = %q", cfg.HostKeyPath)
	}
	if cfg.HTTPDomain != "sign.example.com" {
		t.Errorf("HTTPDomain = %q", cfg.HTTPDomain)
	}
	if cfg.HTTPAddr != ":443" {
		t.Errorf("HTTPAddr = %q", cfg.HTTPAddr)
	}
}

func TestLoad_TLSPathsOptional(t *testing.T) {
	clearEnv(t)
	t.Setenv("SSHSIGN_KEK_SECRET", validSecret)

	// Without TLS env set, the paths are empty (HTTP-only mode).
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.TLSCert != "" || cfg.TLSKey != "" {
		t.Errorf("expected empty TLS paths by default, got cert=%q key=%q", cfg.TLSCert, cfg.TLSKey)
	}

	// With TLS env set, both surface.
	t.Setenv("SSHSIGN_TLS_CERT", "/etc/ssl/sshsign.crt")
	t.Setenv("SSHSIGN_TLS_KEY", "/etc/ssl/sshsign.key")
	cfg, err = config.Load()
	if err != nil {
		t.Fatalf("Load with TLS: %v", err)
	}
	if cfg.TLSCert != "/etc/ssl/sshsign.crt" {
		t.Errorf("TLSCert = %q", cfg.TLSCert)
	}
	if cfg.TLSKey != "/etc/ssl/sshsign.key" {
		t.Errorf("TLSKey = %q", cfg.TLSKey)
	}
}
