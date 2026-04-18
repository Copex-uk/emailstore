// Package security implements a configurable policy engine for email validation.
// It enforces zero-trust principles: reject everything unless explicitly permitted.
package security

import (
	"database/sql"
	"strconv"

	"emailstore/internal/db"
)

// Mode controls how strictly the security policy is enforced.
type Mode string

const (
	// ModeStrict requires both an authorised sender AND a valid token. Default.
	ModeStrict Mode = "strict"
	// ModeBalanced requires either an authorised sender OR a valid token.
	ModeBalanced Mode = "balanced"
	// ModeRelaxed requires only an authorised sender.
	ModeRelaxed Mode = "relaxed"
)

// TokenLocation controls where the auth token is extracted from.
type TokenLocation string

const (
	TokenInSubject TokenLocation = "subject" // [ES:token] in subject line
	TokenInHeader  TokenLocation = "header"  // X-EmailStore-Auth header
)

// Limits defines resource constraints applied to every accepted email.
type Limits struct {
	MaxEmailSizeMB      int64 // total email size
	MaxAttachments      int   // maximum number of attachments
	MaxAttachSizeMB     int64 // per-attachment size limit
}

// Policy is the fully resolved security policy loaded from the database.
type Policy struct {
	Mode          Mode
	TokenRequired bool
	TokenLocation TokenLocation
	Tokens        []string // valid token values
	Limits        Limits
	OnReject      string // "delete" (only supported action currently)
}

// DefaultPolicy returns the strictest safe defaults.
// These apply when the database has no security settings configured.
func DefaultPolicy() *Policy {
	return &Policy{
		Mode:          ModeStrict,
		TokenRequired: true,
		TokenLocation: TokenInSubject,
		Tokens:        nil, // no tokens → strict mode rejects everything
		Limits: Limits{
			MaxEmailSizeMB:  10,
			MaxAttachments:  5,
			MaxAttachSizeMB: 5,
		},
		OnReject: "delete",
	}
}

// LoadPolicy reads the security policy from the database settings.
func LoadPolicy(sqldb *sql.DB) *Policy {
	p := DefaultPolicy()

	if mode, _ := db.SettingGet(sqldb, db.KeySecurityMode); mode != "" {
		switch Mode(mode) {
		case ModeStrict, ModeBalanced, ModeRelaxed:
			p.Mode = Mode(mode)
		}
	}

	if v, _ := db.SettingGet(sqldb, db.KeySecurityRequireToken); v != "" {
		p.TokenRequired = v == "1"
	}

	if loc, _ := db.SettingGet(sqldb, db.KeySecurityTokenLocation); loc != "" {
		switch TokenLocation(loc) {
		case TokenInSubject, TokenInHeader:
			p.TokenLocation = TokenLocation(loc)
		}
	}

	if tokens, _ := db.SettingGet(sqldb, db.KeySecurityTokens); tokens != "" {
		p.Tokens = splitTokens(tokens)
	}

	if v, _ := db.SettingGet(sqldb, db.KeySecurityMaxEmailMB); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			p.Limits.MaxEmailSizeMB = n
		}
	}
	if v, _ := db.SettingGet(sqldb, db.KeySecurityMaxAttachments); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			p.Limits.MaxAttachments = n
		}
	}
	if v, _ := db.SettingGet(sqldb, db.KeySecurityMaxAttachMB); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			p.Limits.MaxAttachSizeMB = n
		}
	}

	return p
}

// splitTokens splits a comma-separated token list and trims whitespace.
func splitTokens(raw string) []string {
	var tokens []string
	for _, t := range splitComma(raw) {
		if t != "" {
			tokens = append(tokens, t)
		}
	}
	return tokens
}

func splitComma(s string) []string {
	var parts []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			parts = append(parts, trim(cur))
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if t := trim(cur); t != "" {
		parts = append(parts, t)
	}
	return parts
}

func trim(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
