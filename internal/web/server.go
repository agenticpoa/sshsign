package web

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"time"
)

// Server holds the HTTP server and its dependencies.
type Server struct {
	db         *sql.DB
	kek        []byte
	httpServer *http.Server
}

// New creates an HTTP server for the web approval flow.
func New(addr string, db *sql.DB, kek []byte) *Server {
	s := &Server{db: db, kek: kek}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /approve/{pendingID}", s.handleGetApproval)
	mux.HandleFunc("POST /approve/{pendingID}", s.handlePostApproval)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      securityHeaders(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	log.Printf("starting HTTP server on %s", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

// ListenAndServeTLS starts the HTTPS server.
func (s *Server) ListenAndServeTLS(certFile, keyFile string) error {
	log.Printf("starting HTTPS server on %s", s.httpServer.Addr)
	return s.httpServer.ListenAndServeTLS(certFile, keyFile)
}

// Shutdown gracefully shuts down the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
