package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

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

	if err := storage.Migrate(context.Background(), db); err != nil {
		log.Fatalf("running migrations: %v", err)
	}

	salt, err := storage.GetOrCreateKEKSalt(context.Background(), db)
	if err != nil {
		log.Fatalf("loading KEK salt: %v", err)
	}
	kek, err := crypto.NewKEKRing(cfg.KEKSecret, salt)
	if err != nil {
		log.Fatalf("building KEK ring: %v", err)
	}

	// Set up audit logger: immudb if configured, otherwise in-memory.
	// The in-memory logger gets a chain key derived from the KEK so
	// VerifyChain survives restarts under the same server secret.
	// ImmuDB has its own tamper-evidence via Merkle proofs, so the
	// chain key only matters for the memory logger.
	auditChainKey := audit.DeriveChainKey(kek.CurrentKEKMaterial())
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
		defer func() { _ = immuLogger.Close() }()
		auditLog = immuLogger
		log.Printf("audit logging to immudb at %s:%d", addr, port)
	} else {
		auditLog = audit.NewMemoryLoggerWithChainKey(auditChainKey)
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
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	runErr := server.Run(srv)

	// server.Run drained on SIGINT/SIGTERM. Give the HTTP server the
	// same chance to finish in-flight approvals instead of dropping
	// their TCP connections; without this the goroutine above would
	// outlive the process briefly and any active cosign request would
	// see a connection reset.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}

	// Zero the ring's key material so a post-mortem core dump never
	// contains live KEKs. Done after HTTP shutdown so any in-flight
	// approval that needed to unwrap a DEK has already finished.
	kek.Close()

	if runErr != nil {
		log.Fatalf("server error: %v", runErr)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
