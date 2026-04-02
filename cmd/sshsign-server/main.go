package main

import (
	"log"
	"os"
	"strconv"

	"github.com/agenticpoa/sshsign/internal/audit"
	"github.com/agenticpoa/sshsign/internal/config"
	"github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/server"
	"github.com/agenticpoa/sshsign/internal/storage"
	"github.com/agenticpoa/sshsign/internal/web"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	db, err := storage.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("opening database: %v", err)
	}
	defer db.Close()

	if err := storage.Migrate(db); err != nil {
		log.Fatalf("running migrations: %v", err)
	}

	kek, err := crypto.DeriveKEK(cfg.KEKSecret)
	if err != nil {
		log.Fatalf("deriving KEK: %v", err)
	}

	// Set up audit logger: immudb if configured, otherwise in-memory
	var auditLog audit.Logger
	if addr := os.Getenv("SSHSIGN_IMMUDB_ADDRESS"); addr != "" {
		port := 3322
		if p := os.Getenv("SSHSIGN_IMMUDB_PORT"); p != "" {
			port, _ = strconv.Atoi(p)
		}
		username := envOrDefault("SSHSIGN_IMMUDB_USERNAME", "immudb")
		password := envOrDefault("SSHSIGN_IMMUDB_PASSWORD", "immudb")
		database := envOrDefault("SSHSIGN_IMMUDB_DATABASE", "defaultdb")

		immuLogger, err := audit.NewImmuDBLogger(audit.ImmuDBConfig{
			Address:  addr,
			Port:     port,
			Username: username,
			Password: password,
			Database: database,
		})
		if err != nil {
			log.Fatalf("connecting to immudb: %v", err)
		}
		defer immuLogger.Close()
		auditLog = immuLogger
		log.Printf("audit logging to immudb at %s:%d", addr, port)
	} else {
		auditLog = audit.NewMemoryLogger()
		log.Println("audit logging to memory (set SSHSIGN_IMMUDB_ADDRESS for production)")
	}

	srv, err := server.New(cfg, db, kek, auditLog)
	if err != nil {
		log.Fatalf("creating server: %v", err)
	}

	// Start HTTP server for web approval flow
	httpSrv := web.New(cfg.HTTPAddr, db, kek)
	go func() {
		var err error
		if cfg.TLSCert != "" && cfg.TLSKey != "" {
			err = httpSrv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && err.Error() != "http: Server closed" {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	if err := server.Run(srv); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
