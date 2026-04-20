package handler

import (
	"net/http"
	"strconv"

	"emailstore/internal/auth"
	"emailstore/internal/db"
	"emailstore/internal/email"
)

func (h *Handler) settingsIndex(w http.ResponseWriter, r *http.Request) {
	csrf := auth.NewCSRFToken(w)
	h.render(w, "settings/index.html", map[string]any{"CSRF": csrf})
}

// ── Security ──────────────────────────────────────────────────────────────

func (h *Handler) settingsSecurityGet(w http.ResponseWriter, r *http.Request) {
	timeout, _ := db.SettingGet(h.DB, db.KeySessionTimeout)
	csrf := auth.NewCSRFToken(w)
	h.render(w, "settings/security.html", map[string]any{
		"SessionTimeout": timeout,
		"CSRF":           csrf,
	})
}

func (h *Handler) settingsSecurityPost(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	csrf := auth.NewCSRFToken(w)

	newPassword := r.FormValue("new_password")
	if newPassword != "" {
		confirm := r.FormValue("confirm_password")
		current := r.FormValue("current_password")
		hash, _ := db.SettingGet(h.DB, db.KeyPasswordHash)
		if !auth.CheckPassword(hash, current) {
			h.render(w, "settings/security.html", map[string]any{
				"Error": "Current password is incorrect",
				"CSRF":  csrf,
			})
			return
		}
		if len(newPassword) < 8 {
			h.render(w, "settings/security.html", map[string]any{
				"Error": "Password must be at least 8 characters",
				"CSRF":  csrf,
			})
			return
		}
		if newPassword != confirm {
			h.render(w, "settings/security.html", map[string]any{
				"Error": "Passwords do not match",
				"CSRF":  csrf,
			})
			return
		}
		newHash, err := auth.HashPassword(newPassword)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		db.SettingSet(h.DB, db.KeyPasswordHash, newHash)
	}

	if t := r.FormValue("session_timeout"); t != "" {
		if n, err := strconv.Atoi(t); err == nil && n > 0 {
			db.SettingSet(h.DB, db.KeySessionTimeout, strconv.Itoa(n))
		}
	}

	h.render(w, "settings/security.html", map[string]any{
		"Success":        "Settings saved",
		"SessionTimeout": r.FormValue("session_timeout"),
		"CSRF":           csrf,
	})
}

// ── Mailbox ───────────────────────────────────────────────────────────────

func (h *Handler) settingsMailboxGet(w http.ResponseWriter, r *http.Request) {
	s, _ := db.SettingGetAll(h.DB)
	csrf := auth.NewCSRFToken(w)

	mode := "plain"
	if s[db.KeyIMAPTLS] == "1" {
		mode = "tls"
	} else if s[db.KeyIMAPStartTLS] == "1" {
		mode = "starttls"
	}

	pollError := r.URL.Query().Get("poll_error")

	h.render(w, "settings/mailbox.html", map[string]any{
		"Host":         s[db.KeyIMAPHost],
		"Port":         s[db.KeyIMAPPort],
		"User":         s[db.KeyIMAPUser],
		"Mode":         mode,
		"PollInterval": s[db.KeyPollInterval],
		"Debug":        s[db.KeyIMAPDebug] == "1",
		"Error":        pollError,
		"CSRF":         csrf,
	})
}

func (h *Handler) settingsMailboxPost(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	db.SettingSet(h.DB, db.KeyIMAPHost, r.FormValue("host"))
	db.SettingSet(h.DB, db.KeyIMAPPort, r.FormValue("port"))
	db.SettingSet(h.DB, db.KeyIMAPUser, r.FormValue("user"))
	if p := r.FormValue("password"); p != "" {
		db.SettingSet(h.DB, db.KeyIMAPPassword, p)
	}

	// Connection mode — mutually exclusive radio buttons
	mode := r.FormValue("mode")
	db.SettingSet(h.DB, db.KeyIMAPTLS, boolStr(mode == "tls"))
	db.SettingSet(h.DB, db.KeyIMAPStartTLS, boolStr(mode == "starttls"))
	db.SettingSet(h.DB, db.KeyIMAPDebug, boolStr(r.FormValue("debug") == "on"))

	if interval := r.FormValue("poll_interval"); interval != "" {
		db.SettingSet(h.DB, db.KeyPollInterval, interval)
	}

	csrf := auth.NewCSRFToken(w)
	h.render(w, "settings/mailbox.html", map[string]any{
		"Host":         r.FormValue("host"),
		"Port":         r.FormValue("port"),
		"User":         r.FormValue("user"),
		"Mode":         mode,
		"PollInterval": r.FormValue("poll_interval"),
		"Debug":        r.FormValue("debug") == "on",
		"Success":      "Mailbox settings saved",
		"CSRF":         csrf,
	})
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// ── Allowed senders ───────────────────────────────────────────────────────

func (h *Handler) settingsSendersGet(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query(
		`SELECT id, email, name FROM allowed_senders ORDER BY email`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type Sender struct {
		ID    int64
		Email string
		Name  string
	}
	var senders []Sender
	for rows.Next() {
		var s Sender
		if err := rows.Scan(&s.ID, &s.Email, &s.Name); err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		senders = append(senders, s)
	}
	csrf := auth.NewCSRFToken(w)
	h.render(w, "settings/senders.html", map[string]any{
		"Senders": senders,
		"CSRF":    csrf,
	})
}

func (h *Handler) settingsSendersPost(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	emailAddr := r.FormValue("email")
	name := r.FormValue("name")
	if emailAddr != "" {
		h.DB.Exec(
			`INSERT OR IGNORE INTO allowed_senders (email, name) VALUES (?, ?)`,
			emailAddr, name,
		)
	}
	http.Redirect(w, r, "/settings/senders", http.StatusSeeOther)
}

func (h *Handler) settingsSendersDelete(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id := r.FormValue("id")
	if id != "" {
		h.DB.Exec(`DELETE FROM allowed_senders WHERE id = ?`, id)
	}
	http.Redirect(w, r, "/settings/senders", http.StatusSeeOther)
}

// ── Categories ────────────────────────────────────────────────────────────

func (h *Handler) settingsCategoriesGet(w http.ResponseWriter, r *http.Request) {
	cats, _ := email.ListCategories(h.DB)
	csrf := auth.NewCSRFToken(w)
	h.render(w, "settings/categories.html", map[string]any{
		"Categories": cats,
		"CSRF":       csrf,
	})
}

func (h *Handler) settingsCategoriesPost(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	action := r.FormValue("action")
	switch action {
	case "add":
		name := r.FormValue("name")
		color := r.FormValue("color")
		if color == "" {
			color = "#6366f1"
		}
		if name != "" {
			slug := toSlug(name)
			h.DB.Exec(
				`INSERT OR IGNORE INTO categories (name, slug, color) VALUES (?, ?, ?)`,
				name, slug, color,
			)
		}
	case "delete":
		id := r.FormValue("id")
		if id != "" {
			// Protect the inbox category — it is the fallback for uncategorised emails
			// and must always exist. Silently ignore the request if the user tries to delete it.
			var slug string
			h.DB.QueryRow(`SELECT slug FROM categories WHERE id = ?`, id).Scan(&slug)
			if slug == "inbox" {
				break
			}
			h.DB.Exec(`DELETE FROM categories WHERE id = ?`, id)
		}
	case "add_rule":
		catID := r.FormValue("category_id")
		pattern := r.FormValue("pattern")
		if catID != "" && pattern != "" {
			h.DB.Exec(
				`INSERT INTO category_rules (category_id, pattern) VALUES (?, ?)`,
				catID, pattern,
			)
		}
	case "delete_rule":
		ruleID := r.FormValue("rule_id")
		if ruleID != "" {
			h.DB.Exec(`DELETE FROM category_rules WHERE id = ?`, ruleID)
		}
	}
	http.Redirect(w, r, "/settings/categories", http.StatusSeeOther)
}

// ── General ───────────────────────────────────────────────────────────────

func (h *Handler) settingsGeneralGet(w http.ResponseWriter, r *http.Request) {
	maxBytes, _ := db.SettingGet(h.DB, db.KeyMaxAttachBytes)
	csrf := auth.NewCSRFToken(w)
	h.render(w, "settings/general.html", map[string]any{
		"MaxAttachMB": bytesToMB(maxBytes),
		"CSRF":        csrf,
	})
}

func (h *Handler) settingsGeneralPost(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if mb := r.FormValue("max_attach_mb"); mb != "" {
		if n, err := strconv.ParseInt(mb, 10, 64); err == nil && n > 0 {
			db.SettingSet(h.DB, db.KeyMaxAttachBytes, strconv.FormatInt(n*1024*1024, 10))
		}
	}
	csrf := auth.NewCSRFToken(w)
	h.render(w, "settings/general.html", map[string]any{
		"MaxAttachMB": r.FormValue("max_attach_mb"),
		"Success":     "Settings saved",
		"CSRF":        csrf,
	})
}

func toSlug(s string) string {
	slug := ""
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			slug += string(c)
		case c >= 'A' && c <= 'Z':
			slug += string(rune(c + 32))
		case c == ' ' || c == '-' || c == '_':
			slug += "-"
		}
	}
	return slug
}

func bytesToMB(s string) string {
	if s == "" {
		return "25"
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return "25"
	}
	return strconv.FormatInt(n/1024/1024, 10)
}

// ── Security policy ───────────────────────────────────────────────────────

func (h *Handler) settingsPolicyGet(w http.ResponseWriter, r *http.Request) {
	s, _ := db.SettingGetAll(h.DB)
	csrf := auth.NewCSRFToken(w)

	mode := s[db.KeySecurityMode]
	tokens := s[db.KeySecurityTokens]
	requireToken := s[db.KeySecurityRequireToken] == "1"

	// Warn if strict/balanced mode is set with token required but no tokens configured —
	// this will reject every email.
	var warn string
	if requireToken && tokens == "" && (mode == "strict" || mode == "balanced") {
		warn = "Token authentication is required but no tokens are configured. All emails will be rejected until you add at least one token, or switch to Relaxed mode."
	}

	h.render(w, "settings/policy.html", map[string]any{
		"Mode":           mode,
		"RequireToken":   requireToken,
		"TokenLocation":  s[db.KeySecurityTokenLocation],
		"Tokens":         tokens,
		"MaxEmailMB":     s[db.KeySecurityMaxEmailMB],
		"MaxAttachments": s[db.KeySecurityMaxAttachments],
		"MaxAttachMB":    s[db.KeySecurityMaxAttachMB],
		"Warning":        warn,
		"CSRF":           csrf,
	})
}

func (h *Handler) settingsPolicyPost(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	mode := r.FormValue("mode")
	if mode != "strict" && mode != "balanced" && mode != "relaxed" {
		mode = "strict"
	}
	db.SettingSet(h.DB, db.KeySecurityMode, mode)
	db.SettingSet(h.DB, db.KeySecurityRequireToken, boolStr(r.FormValue("require_token") == "on"))
	loc := r.FormValue("token_location")
	if loc != "subject" && loc != "header" {
		loc = "subject"
	}
	db.SettingSet(h.DB, db.KeySecurityTokenLocation, loc)
	db.SettingSet(h.DB, db.KeySecurityTokens, r.FormValue("tokens"))
	if v := r.FormValue("max_email_mb"); v != "" {
		db.SettingSet(h.DB, db.KeySecurityMaxEmailMB, v)
	}
	if v := r.FormValue("max_attachments"); v != "" {
		db.SettingSet(h.DB, db.KeySecurityMaxAttachments, v)
	}
	if v := r.FormValue("max_attach_mb"); v != "" {
		db.SettingSet(h.DB, db.KeySecurityMaxAttachMB, v)
	}
	csrf := auth.NewCSRFToken(w)
	h.render(w, "settings/policy.html", map[string]any{
		"Mode":           mode,
		"RequireToken":   r.FormValue("require_token") == "on",
		"TokenLocation":  loc,
		"Tokens":         r.FormValue("tokens"),
		"MaxEmailMB":     r.FormValue("max_email_mb"),
		"MaxAttachments": r.FormValue("max_attachments"),
		"MaxAttachMB":    r.FormValue("max_attach_mb"),
		"Success":        "Security policy saved",
		"CSRF":           csrf,
	})
}
