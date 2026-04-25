package handler

import (
	"log"
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
		if err := db.SettingSet(h.DB, db.KeyPasswordHash, newHash); err != nil {
			log.Printf("settings: save password hash: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	if t := r.FormValue("session_timeout"); t != "" {
		if n, err := strconv.Atoi(t); err == nil && n > 0 {
			if err := db.SettingSet(h.DB, db.KeySessionTimeout, strconv.Itoa(n)); err != nil {
				log.Printf("settings: save session timeout: %v", err)
			}
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
	s, err := db.SettingGetAll(h.DB)
	if err != nil {
		log.Printf("settings mailbox: load settings: %v", err)
		s = map[string]string{}
	}
	csrf := auth.NewCSRFToken(w)

	mode := "plain"
	if s[db.KeyIMAPTLS] == "1" {
		mode = "tls"
	} else if s[db.KeyIMAPStartTLS] == "1" {
		mode = "starttls"
	}

	h.render(w, "settings/mailbox.html", map[string]any{
		"Host":         s[db.KeyIMAPHost],
		"Port":         s[db.KeyIMAPPort],
		"User":         s[db.KeyIMAPUser],
		"Mode":         mode,
		"PollInterval": s[db.KeyPollInterval],
		"Debug":        s[db.KeyIMAPDebug] == "1",
		"Error":        r.URL.Query().Get("poll_error"),
		"CSRF":         csrf,
	})
}

func (h *Handler) settingsMailboxPost(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	setOrLog := func(key, val string) {
		if err := db.SettingSet(h.DB, key, val); err != nil {
			log.Printf("settings mailbox: set %s: %v", key, err)
		}
	}
	setOrLog(db.KeyIMAPHost, r.FormValue("host"))
	setOrLog(db.KeyIMAPPort, r.FormValue("port"))
	setOrLog(db.KeyIMAPUser, r.FormValue("user"))
	if p := r.FormValue("password"); p != "" {
		setOrLog(db.KeyIMAPPassword, p)
	}
	mode := r.FormValue("mode")
	setOrLog(db.KeyIMAPTLS, boolStr(mode == "tls"))
	setOrLog(db.KeyIMAPStartTLS, boolStr(mode == "starttls"))
	setOrLog(db.KeyIMAPDebug, boolStr(r.FormValue("debug") == "on"))
	if interval := r.FormValue("poll_interval"); interval != "" {
		setOrLog(db.KeyPollInterval, interval)
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
		log.Printf("settings senders: query: %v", err)
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
			log.Printf("settings senders: scan: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		senders = append(senders, s)
	}
	if err := rows.Err(); err != nil {
		log.Printf("settings senders: rows error: %v", err)
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
		if _, err := h.DB.Exec(
			`INSERT OR IGNORE INTO allowed_senders (email, name) VALUES (?, ?)`,
			emailAddr, name,
		); err != nil {
			log.Printf("settings senders: insert %q: %v", emailAddr, err)
		}
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
		if _, err := h.DB.Exec(`DELETE FROM allowed_senders WHERE id = ?`, id); err != nil {
			log.Printf("settings senders: delete id=%s: %v", id, err)
		}
	}
	http.Redirect(w, r, "/settings/senders", http.StatusSeeOther)
}

// ── Categories ────────────────────────────────────────────────────────────

func (h *Handler) settingsCategoriesGet(w http.ResponseWriter, r *http.Request) {
	cats, err := email.ListCategories(h.DB)
	if err != nil {
		log.Printf("settings categories: list: %v", err)
	}
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
			if _, err := h.DB.Exec(
				`INSERT OR IGNORE INTO categories (name, slug, color) VALUES (?, ?, ?)`,
				name, slug, color,
			); err != nil {
				log.Printf("settings categories: add %q: %v", name, err)
			}
		}
	case "delete":
		id := r.FormValue("id")
		if id != "" {
			// Protect inbox — it is the permanent fallback for uncategorised emails.
			var slug string
			if err := h.DB.QueryRow(`SELECT slug FROM categories WHERE id = ?`, id).Scan(&slug); err != nil {
				log.Printf("settings categories: lookup id=%s: %v", id, err)
				break
			}
			if slug == "inbox" {
				break
			}
			if _, err := h.DB.Exec(`DELETE FROM categories WHERE id = ?`, id); err != nil {
				log.Printf("settings categories: delete id=%s: %v", id, err)
			}
		}
	case "add_rule":
		catID := r.FormValue("category_id")
		pattern := r.FormValue("pattern")
		if catID != "" && pattern != "" {
			if _, err := h.DB.Exec(
				`INSERT INTO category_rules (category_id, pattern) VALUES (?, ?)`,
				catID, pattern,
			); err != nil {
				log.Printf("settings categories: add rule cat=%s pattern=%q: %v", catID, pattern, err)
			}
		}
	case "delete_rule":
		ruleID := r.FormValue("rule_id")
		if ruleID != "" {
			if _, err := h.DB.Exec(`DELETE FROM category_rules WHERE id = ?`, ruleID); err != nil {
				log.Printf("settings categories: delete rule id=%s: %v", ruleID, err)
			}
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
			if err := db.SettingSet(h.DB, db.KeyMaxAttachBytes, strconv.FormatInt(n*1024*1024, 10)); err != nil {
				log.Printf("settings general: save max_attach_mb: %v", err)
			}
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
	s, err := db.SettingGetAll(h.DB)
	if err != nil {
		log.Printf("settings policy: load settings: %v", err)
		s = map[string]string{}
	}
	csrf := auth.NewCSRFToken(w)

	mode := s[db.KeySecurityMode]
	tokens := s[db.KeySecurityTokens]
	requireToken := s[db.KeySecurityRequireToken] == "1"

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
	setOrLog := func(key, val string) {
		if err := db.SettingSet(h.DB, key, val); err != nil {
			log.Printf("settings policy: set %s: %v", key, err)
		}
	}
	mode := r.FormValue("mode")
	if mode != "strict" && mode != "balanced" && mode != "relaxed" {
		mode = "strict"
	}
	setOrLog(db.KeySecurityMode, mode)
	setOrLog(db.KeySecurityRequireToken, boolStr(r.FormValue("require_token") == "on"))
	loc := r.FormValue("token_location")
	if loc != "subject" && loc != "header" {
		loc = "subject"
	}
	setOrLog(db.KeySecurityTokenLocation, loc)
	setOrLog(db.KeySecurityTokens, r.FormValue("tokens"))
	if v := r.FormValue("max_email_mb"); v != "" {
		setOrLog(db.KeySecurityMaxEmailMB, v)
	}
	if v := r.FormValue("max_attachments"); v != "" {
		setOrLog(db.KeySecurityMaxAttachments, v)
	}
	if v := r.FormValue("max_attach_mb"); v != "" {
		setOrLog(db.KeySecurityMaxAttachMB, v)
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
