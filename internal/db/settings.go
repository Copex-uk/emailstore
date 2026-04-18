package db

import (
	"database/sql"
	"errors"
)

func SettingGet(db *sql.DB, key string) (string, error) {
	var val string
	err := db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&val)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return val, err
}

func SettingSet(db *sql.DB, key, value string) error {
	_, err := db.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	return err
}

func SettingGetAll(db *sql.DB) (map[string]string, error) {
	rows, err := db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

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
	KeySecurityMode          = "security_mode"
	KeySecurityRequireToken  = "security_require_token"
	KeySecurityTokenLocation = "security_token_location"
	KeySecurityTokens        = "security_tokens"
	KeySecurityMaxEmailMB    = "security_max_email_mb"
	KeySecurityMaxAttachments= "security_max_attachments"
	KeySecurityMaxAttachMB   = "security_max_attach_mb"
)
