package server

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os/signal"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	"github.com/charmbracelet/wish/bubbletea"

	"github.com/agenticpoa/sshsign/internal/audit"
	"github.com/agenticpoa/sshsign/internal/config"
	appTUI "github.com/agenticpoa/sshsign/internal/tui"
)

func New(cfg config.Config, db *sql.DB, kek []byte, auditLog audit.Logger) (*ssh.Server, error) {
	rl := NewServerRateLimits()

	srv, err := wish.NewServer(
		wish.WithAddress(cfg.ListenAddr),
		wish.WithHostKeyPath(cfg.HostKeyPath),
		wish.WithPublicKeyAuth(PublicKeyHandler()),
		wish.WithMiddleware(
			// Bubbletea middleware runs for PTY sessions
			bubbletea.Middleware(tuiHandler(db, kek)),
			// Session handler runs first: user lookup/create, command routing
			SessionHandler(db, kek, rl, auditLog),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating SSH server: %w", err)
	}

	return srv, nil
}

func tuiHandler(db *sql.DB, kek []byte) bubbletea.Handler {
	return func(sess ssh.Session) (tea.Model, []tea.ProgramOption) {
		sc := SessionContextFromContext(sess.Context())
		if sc == nil {
			// Shouldn't happen, but handle gracefully
			return appTUI.NewModel(db, kek, nil, nil, true), []tea.ProgramOption{tea.WithAltScreen()}
		}

		model := appTUI.NewModel(db, kek, sc.User, sc.UserKey, sc.IsNewUser)
		return model, []tea.ProgramOption{tea.WithAltScreen()}
	}
}

func Run(srv *ssh.Server) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("starting SSH server on %s", srv.Addr)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case <-ctx.Done():
		log.Println("shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
