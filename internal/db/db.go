package db

import (
	"database/sql"
	"fmt"
	"log"

	_ "modernc.org/sqlite"
)

func Open(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath+"?_journal=WAL&_timeout=5000&_fk=true")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	for i, stmt := range migrations {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("migration %d: %w", i, err)
		}
	}
	log.Println("db: migrations applied")
	return nil
}

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS settings (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`,

	`CREATE TABLE IF NOT EXISTS sessions (
		id         TEXT PRIMARY KEY,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	)`,

	`CREATE TABLE IF NOT EXISTS allowed_senders (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		email      TEXT NOT NULL UNIQUE,
		name       TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL DEFAULT (unixepoch())
	)`,

	`CREATE TABLE IF NOT EXISTS categories (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		name       TEXT NOT NULL UNIQUE,
		slug       TEXT NOT NULL UNIQUE,
		color      TEXT NOT NULL DEFAULT '#6366f1',
		created_at INTEGER NOT NULL DEFAULT (unixepoch())
	)`,

	`CREATE TABLE IF NOT EXISTS category_rules (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		category_id INTEGER NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
		pattern     TEXT NOT NULL,
		created_at  INTEGER NOT NULL DEFAULT (unixepoch())
	)`,

	`CREATE TABLE IF NOT EXISTS emails (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		message_id   TEXT NOT NULL UNIQUE,
		category_id  INTEGER REFERENCES categories(id) ON DELETE SET NULL,
		sender_email TEXT NOT NULL,
		sender_name  TEXT NOT NULL DEFAULT '',
		subject      TEXT NOT NULL DEFAULT '',
		body_text    TEXT NOT NULL DEFAULT '',
		body_html    TEXT NOT NULL DEFAULT '',
		received_at  INTEGER NOT NULL,
		read         INTEGER NOT NULL DEFAULT 0,
		created_at   INTEGER NOT NULL DEFAULT (unixepoch())
	)`,

	`CREATE INDEX IF NOT EXISTS idx_emails_category  ON emails(category_id)`,
	`CREATE INDEX IF NOT EXISTS idx_emails_received  ON emails(received_at DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_emails_sender    ON emails(sender_email)`,

	`CREATE TABLE IF NOT EXISTS attachments (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		email_id   INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
		filename   TEXT NOT NULL,
		mime_type  TEXT NOT NULL,
		size       INTEGER NOT NULL,
		stored_path TEXT NOT NULL,
		created_at INTEGER NOT NULL DEFAULT (unixepoch())
	)`,

	`CREATE INDEX IF NOT EXISTS idx_attachments_email ON attachments(email_id)`,

	`INSERT INTO categories (name, slug, color)
		SELECT * FROM (VALUES
			('Inbox',    'inbox',    '#6366f1'),
			('Work',     'work',     '#0ea5e9'),
			('Personal', 'personal', '#22c55e'),
			('Finance',  'finance',  '#f59e0b'),
			('Other',    'other',    '#94a3b8')
		) WHERE (SELECT COUNT(*) FROM categories) = 0`,

	// Assign any existing uncategorised emails to the inbox category.
	// This runs on every startup but only affects emails with NULL category_id.
	`UPDATE emails SET category_id = (
		SELECT id FROM categories WHERE slug = 'inbox' LIMIT 1
	) WHERE category_id IS NULL
	  AND (SELECT id FROM categories WHERE slug = 'inbox' LIMIT 1) IS NOT NULL`,
}
