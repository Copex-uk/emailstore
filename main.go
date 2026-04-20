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
	cfg := config.Load()

	if err := cfg.EnsureDirs(); err != nil {
		log.Fatalf("create data dirs: %v", err)
	}

	sqldb, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer sqldb.Close()

	tmpl, err := loadTemplates()
	if err != nil {
		log.Fatalf("load templates: %v", err)
	}

	// Ensure the inbox category always exists — it is the permanent fallback
	// for uncategorised emails and must never be absent, even after upgrades.
	sqldb.Exec(
		`INSERT OR IGNORE INTO categories (name, slug, color) VALUES ('Inbox', 'inbox', '#6366f1')`,
	)

	h := handler.New(sqldb, tmpl, cfg.AttachDir)

	// Root context — cancelled on shutdown signal
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start IMAP poller with context for clean shutdown
	imappoller.StartPoller(ctx, sqldb, cfg.AttachDir)

	// Prune expired sessions every hour
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				auth.PruneExpiredSessions(sqldb)
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

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("emailstore listening on http://%s:%s", cfg.Host, cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	<-quit
	log.Println("shutting down...")

	// Cancel context — stops poller and session pruner
	cancel()

	// Give HTTP server 10s to drain
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
	log.Println("stopped")
}

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

	patterns := []string{
		"templates/*.html",
		"templates/settings/*.html",
	}
	for _, p := range patterns {
		if _, err := tmpl.ParseGlob(p); err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
	}
	return tmpl, nil
}
