package db

import (
	"database/sql"
	"fmt"
)

const (
	KeyPasswordHash   = "password_hash"
	KeyIMAPHost       = "imap_host"
	KeyIMAPPort       = "imap_port"
	KeyIMAPUser       = "imap_user"
	KeyIMAPPassword   = "imap_password"
	KeyIMAPTLS        = "imap_tls"
	KeyIMAPStartTLS   = "imap_starttls"
	KeyIMAPDebug      = "imap_debug"
	KeyPollInterval   = "poll_interval_mins"
	KeySessionTimeout = "session_timeout_mins"
	KeySetupDone      = "setup_done"
	KeyMaxAttachBytes = "max_attach_bytes"

	// Security policy keys
	KeySecurityMode           = "security_mode"
	KeySecurityRequireToken   = "security_require_token"
	KeySecurityTokenLocation  = "security_token_location"
	KeySecurityTokens         = "security_tokens"
	KeySecurityMaxEmailMB     = "security_max_email_mb"
	KeySecurityMaxAttachments = "security_max_attachments"
	KeySecurityMaxAttachMB    = "security_max_attach_mb"
)

// SettingGet returns the value for key, or ("", nil) if the key does not exist.
func SettingGet(db *sql.DB, key string) (string, error) {
	var val string
	err := db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&val)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return val, err
}

// SettingSet inserts or updates a single setting key/value pair.
func SettingSet(db *sql.DB, key, value string) error {
	_, err := db.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("setting set %q: %w", key, err)
	}
	return nil
}

// SettingGetAll returns all key/value pairs from the settings table.
func SettingGetAll(db *sql.DB) (map[string]string, error) {
	rows, err := db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, fmt.Errorf("setting get all: %w", err)
	}
	defer rows.Close()
	m := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("setting get all scan: %w", err)
		}
		m[k] = v
	}
	return m, rows.Err()
}
