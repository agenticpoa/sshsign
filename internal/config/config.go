package config

import (
	"fmt"
	"os"
)

type Config struct {
	ListenAddr  string
	DBPath      string
	HostKeyPath string
	KEKSecret   string
	HTTPDomain  string // domain for web approval URLs (e.g. "sshsign.dev")
}

func Load() (Config, error) {
	cfg := Config{
		ListenAddr:  envOrDefault("SSHSIGN_LISTEN_ADDR", ":2222"),
		DBPath:      envOrDefault("SSHSIGN_DB_PATH", "./sshsign.db"),
		HostKeyPath: envOrDefault("SSHSIGN_HOST_KEY_PATH", "./host_key"),
		KEKSecret:   os.Getenv("SSHSIGN_KEK_SECRET"),
		HTTPDomain:  envOrDefault("SSHSIGN_HTTP_DOMAIN", "sshsign.dev"),
	}

	if cfg.KEKSecret == "" {
		return Config{}, fmt.Errorf("SSHSIGN_KEK_SECRET environment variable is required")
	}

	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
