package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"emailstore/internal/auth"
	"emailstore/internal/config"
	"emailstore/internal/db"
	"emailstore/internal/email"
	"emailstore/internal/handler"
	imappoller "emailstore/internal/imap"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.SetPrefix("emailstore ")

	cfg := config.Load()

	// Fail fast if required configuration is missing or invalid.
	if cfg.Port == "" {
		log.Fatal("startup: PORT must not be empty")
	}
	if cfg.DataDir == "" {
		log.Fatal("startup: DATA_DIR must not be empty")
	}

	log.Printf("starting: bind=%s:%s data=%s", cfg.Host, cfg.Port, cfg.DataDir)

	// Ensure all required directories exist before any further startup work.
	if err := cfg.EnsureDirs(); err != nil {
		log.Fatalf("startup: create data dirs: %v", err)
	}

	sqldb, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("startup: open db: %v", err)
	}
	defer func() {
		if err := sqldb.Close(); err != nil {
			log.Printf("shutdown: db close: %v", err)
		}
	}()

	// Load and parse all templates once at startup. Any missing or malformed
	// template is a fatal error — better to fail immediately than serve errors.
	tmpl, err := loadTemplates()
	if err != nil {
		log.Fatalf("startup: load templates: %v", err)
	}

	// Ensure the inbox category always exists — permanent fallback for
	// uncategorised emails; must survive upgrades and fresh installs.
	if _, err := sqldb.Exec(
		`INSERT OR IGNORE INTO categories (name, slug, color) VALUES ('Inbox', 'inbox', '#6366f1')`,
	); err != nil {
		log.Printf("startup: ensure inbox category: %v", err)
	}

	h := handler.New(sqldb, tmpl, cfg.AttachDir)

	// Root context — cancelled on shutdown signal to stop all background goroutines.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Background: IMAP poller — respects ctx for clean shutdown.
	imappoller.StartPoller(ctx, sqldb, cfg.AttachDir)

	// Background: session pruner — runs hourly, exits when ctx is cancelled.
	// Panics are recovered so a pruner failure cannot affect the HTTP server.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("session pruner: panic recovered: %v", r)
			}
		}()
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Printf("session pruner: stopping")
				return
			case <-t.C:
				if err := auth.PruneExpiredSessions(sqldb); err != nil {
					log.Printf("session pruner: %v", err)
				}
			}
		}
	}()

	srv := &http.Server{
		Addr:         cfg.Host + ":" + cfg.Port,
		Handler:      h.Routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Buffered channel so the signal sender is never blocked.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("listening on http://%s:%s", cfg.Host, cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	// Block until SIGINT or SIGTERM.
	sig := <-quit
	log.Printf("received signal %s — shutting down", sig)

	// Cancel context first — stops poller and session pruner immediately.
	cancel()

	// Give in-flight HTTP requests 10 s to complete before forcing close.
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Printf("shutdown: http server: %v", err)
	}

	log.Printf("shutdown: complete")
}

// loadTemplates parses all HTML templates once at startup.
// Relative glob patterns are safe here because the working directory is set
// by the caller (Docker WORKDIR /app, or the repo root for local dev).
func loadTemplates() (*template.Template, error) {
	funcMap := template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"not": func(v any) bool {
			if v == nil {
				return true
			}
			switch val := v.(type) {
			case bool:
				return !val
			case string:
				return val == ""
			case int:
				return val == 0
			case []*email.Email:
				return len(val) == 0
			default:
				return false
			}
		},
		"formatBytes": func(n int64) string {
			switch {
			case n >= 1024*1024:
				return fmt.Sprintf("%.1f MB", float64(n)/1024/1024)
			case n >= 1024:
				return fmt.Sprintf("%.0f KB", float64(n)/1024)
			default:
				return fmt.Sprintf("%d B", n)
			}
		},
	}

	tmpl := template.New("").Funcs(funcMap)
	for _, pattern := range []string{"templates/*.html", "templates/settings/*.html"} {
		if _, err := tmpl.ParseGlob(pattern); err != nil {
			return nil, fmt.Errorf("parse %s: %w", pattern, err)
		}
	}
	return tmpl, nil
}
