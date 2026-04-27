package handler

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	ver "emailstore/internal/version"

	"emailstore/internal/auth"
	"emailstore/internal/db"
	"emailstore/internal/email"
)

func (h *Handler) settingsIndex(w http.ResponseWriter, r *http.Request) {
	csrf := auth.NewCSRFToken(w)
	h.renderV(w, "settings/index.html", map[string]any{
		"CSRF":    csrf,
		"Version": ver.String(),
	})
}

// ── Security ──────────────────────────────────────────────────────────────

func (h *Handler) settingsSecurityGet(w http.ResponseWriter, r *http.Request) {
	timeout, _ := db.SettingGet(h.DB, db.KeySessionTimeout)
	csrf := auth.NewCSRFToken(w)
	h.renderV(w, "settings/security.html", map[string]any{
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

	// ── Password change ────────────────────────────────────────────────
	newPassword := r.FormValue("new_password")
	if newPassword != "" {
		confirm := r.FormValue("confirm_password")
		current := r.FormValue("current_password")
		hash, _ := db.SettingGet(h.DB, db.KeyPasswordHash)
		if !auth.CheckPassword(hash, current) {
			h.renderV(w, "settings/security.html", map[string]any{
				"Error":          "Current password is incorrect",
				"SessionTimeout": r.FormValue("session_timeout"),
				"CSRF":           csrf,
			})
			return
		}
		if len(newPassword) < 8 {
			h.renderV(w, "settings/security.html", map[string]any{
				"Error":          "New password must be at least 8 characters",
				"SessionTimeout": r.FormValue("session_timeout"),
				"CSRF":           csrf,
			})
			return
		}
		if newPassword != confirm {
			h.renderV(w, "settings/security.html", map[string]any{
				"Error":          "New passwords do not match",
				"SessionTimeout": r.FormValue("session_timeout"),
				"CSRF":           csrf,
			})
			return
		}
		newHash, err := auth.HashPassword(newPassword)
		if err != nil {
			log.Printf("settings security: hash password: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := db.SettingSet(h.DB, db.KeyPasswordHash, newHash); err != nil {
			log.Printf("settings security: save password hash: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	// ── Session timeout ───────────────────────────────────────────────
	timeoutStr := r.FormValue("session_timeout")
	if timeoutStr != "" {
		n, err := strconv.Atoi(timeoutStr)
		if err != nil || n <= 0 {
			// Reload saved value so form shows what is actually stored
			saved, _ := db.SettingGet(h.DB, db.KeySessionTimeout)
			h.renderV(w, "settings/security.html", map[string]any{
				"Error":          "Session timeout must be a positive number of minutes",
				"SessionTimeout": saved,
				"CSRF":           csrf,
			})
			return
		}
		if err := db.SettingSet(h.DB, db.KeySessionTimeout, strconv.Itoa(n)); err != nil {
			log.Printf("settings security: save session timeout: %v", err)
		}
	}

	// Re-read from DB so the rendered form always reflects what was actually saved
	savedTimeout, _ := db.SettingGet(h.DB, db.KeySessionTimeout)
	h.renderV(w, "settings/security.html", map[string]any{
		"Success":        "Settings saved",
		"SessionTimeout": savedTimeout,
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
	mode := imapMode(s)
	h.renderV(w, "settings/mailbox.html", map[string]any{
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

	setOrLog(db.KeyIMAPHost, strings.TrimSpace(r.FormValue("host")))
	setOrLog(db.KeyIMAPPort, strings.TrimSpace(r.FormValue("port")))
	setOrLog(db.KeyIMAPUser, strings.TrimSpace(r.FormValue("user")))
	if p := r.FormValue("password"); p != "" {
		setOrLog(db.KeyIMAPPassword, p)
	}
	mode := r.FormValue("mode")
	if mode != "tls" && mode != "starttls" && mode != "plain" {
		mode = "tls" // safe default
	}
	setOrLog(db.KeyIMAPTLS, boolStr(mode == "tls"))
	setOrLog(db.KeyIMAPStartTLS, boolStr(mode == "starttls"))
	setOrLog(db.KeyIMAPDebug, boolStr(r.FormValue("debug") == "on"))

	if interval := strings.TrimSpace(r.FormValue("poll_interval")); interval != "" {
		if n, err := strconv.Atoi(interval); err == nil && n > 0 {
			setOrLog(db.KeyPollInterval, strconv.Itoa(n))
		} else {
			log.Printf("settings mailbox: invalid poll_interval %q", interval)
		}
	}

	// Re-read from DB so the form always shows what is actually persisted
	s, err := db.SettingGetAll(h.DB)
	if err != nil {
		log.Printf("settings mailbox: reload after save: %v", err)
		s = map[string]string{}
	}
	csrf := auth.NewCSRFToken(w)
	h.renderV(w, "settings/mailbox.html", map[string]any{
		"Host":         s[db.KeyIMAPHost],
		"Port":         s[db.KeyIMAPPort],
		"User":         s[db.KeyIMAPUser],
		"Mode":         imapMode(s),
		"PollInterval": s[db.KeyPollInterval],
		"Debug":        s[db.KeyIMAPDebug] == "1",
		"Success":      "Mailbox settings saved",
		"CSRF":         csrf,
	})
}

// imapMode derives the radio-button mode value from stored TLS/StartTLS flags.
func imapMode(s map[string]string) string {
	if s[db.KeyIMAPTLS] == "1" {
		return "tls"
	}
	if s[db.KeyIMAPStartTLS] == "1" {
		return "starttls"
	}
	return "plain"
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
	h.renderV(w, "settings/senders.html", map[string]any{
		"Senders": senders,
		"CSRF":    csrf,
	})
}

func (h *Handler) settingsSendersPost(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	emailAddr := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	name := strings.TrimSpace(r.FormValue("name"))
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
	h.renderV(w, "settings/categories.html", map[string]any{
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
		name := strings.TrimSpace(r.FormValue("name"))
		color := r.FormValue("color")
		if color == "" {
			color = "#6366f1"
		}
		if name != "" {
			slug := toSlug(name)
			if slug == "" {
				log.Printf("settings categories: add %q: slug is empty after conversion", name)
				break
			}
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
			var slug string
			if err := h.DB.QueryRow(`SELECT slug FROM categories WHERE id = ?`, id).Scan(&slug); err != nil {
				log.Printf("settings categories: lookup id=%s: %v", id, err)
				break
			}
			if slug == "inbox" {
				// Inbox is the permanent fallback category — never delete it
				break
			}
			if _, err := h.DB.Exec(`DELETE FROM categories WHERE id = ?`, id); err != nil {
				log.Printf("settings categories: delete id=%s: %v", id, err)
			}
		}
	case "add_rule":
		catID := r.FormValue("category_id")
		pattern := strings.TrimSpace(r.FormValue("pattern"))
		if catID != "" && pattern != "" {
			if _, err := h.DB.Exec(
				`INSERT INTO category_rules (category_id, pattern) VALUES (?, ?)`,
				catID, pattern,
			); err != nil {
				log.Printf("settings categories: add rule cat=%s pattern=%q: %v", catID, pattern, err)
			}
		}
	case "set_retain":
		id := r.FormValue("id")
		daysStr := strings.TrimSpace(r.FormValue("retain_days"))
		if id != "" && daysStr != "" {
			days, err := strconv.Atoi(daysStr)
			if err != nil || days < 0 {
				log.Printf("settings categories: invalid retain_days %q for id=%s", daysStr, id)
				days = 0
			}
			if _, err := h.DB.Exec(`UPDATE categories SET retain_days = ? WHERE id = ?`, days, id); err != nil {
				log.Printf("settings categories: set retain_days id=%s days=%d: %v", id, days, err)
			}
		}
	case "edit":
		id := r.FormValue("id")
		name := strings.TrimSpace(r.FormValue("name"))
		color := r.FormValue("color")
		if id == "" {
			break
		}
		if color == "" {
			color = "#6366f1"
		}
		var slug string
		if err := h.DB.QueryRow(`SELECT slug FROM categories WHERE id = ?`, id).Scan(&slug); err != nil {
			log.Printf("settings categories: edit lookup id=%s: %v", id, err)
			break
		}
		if slug == "inbox" {
			// Inbox: colour change only — name and slug are fixed
			if _, err := h.DB.Exec(`UPDATE categories SET color = ? WHERE id = ?`, color, id); err != nil {
				log.Printf("settings categories: edit inbox color id=%s: %v", id, err)
			}
		} else {
			if name == "" {
				log.Printf("settings categories: edit id=%s: empty name rejected", id)
				break
			}
			newSlug := toSlug(name)
			if newSlug == "" {
				log.Printf("settings categories: edit id=%s name=%q: slug is empty", id, name)
				break
			}
			if _, err := h.DB.Exec(
				`UPDATE categories SET name = ?, slug = ?, color = ? WHERE id = ?`,
				name, newSlug, color, id,
			); err != nil {
				log.Printf("settings categories: edit id=%s name=%q: %v", id, name, err)
			}
		}
	case "delete_rule":
		ruleID := r.FormValue("rule_id")
		if ruleID != "" {
			if _, err := h.DB.Exec(`DELETE FROM category_rules WHERE id = ?`, ruleID); err != nil {
				log.Printf("settings categories: delete rule id=%s: %v", ruleID, err)
			}
		}
	default:
		if action != "" {
			log.Printf("settings categories: unknown action %q", action)
		}
	}
	http.Redirect(w, r, "/settings/categories", http.StatusSeeOther)
}

// ── General ───────────────────────────────────────────────────────────────

func (h *Handler) settingsGeneralGet(w http.ResponseWriter, r *http.Request) {
	maxBytes, _ := db.SettingGet(h.DB, db.KeyMaxAttachBytes)
	csrf := auth.NewCSRFToken(w)
	h.renderV(w, "settings/general.html", map[string]any{
		"MaxAttachMB": bytesToMB(maxBytes),
		"CSRF":        csrf,
	})
}

func (h *Handler) settingsGeneralPost(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	csrf := auth.NewCSRFToken(w)
	if mb := strings.TrimSpace(r.FormValue("max_attach_mb")); mb != "" {
		n, err := strconv.ParseInt(mb, 10, 64)
		if err != nil || n <= 0 {
			// Re-read saved value so form shows what is actually stored
			saved, _ := db.SettingGet(h.DB, db.KeyMaxAttachBytes)
			h.renderV(w, "settings/general.html", map[string]any{
				"Error":       "Max attachment size must be a positive number",
				"MaxAttachMB": bytesToMB(saved),
				"CSRF":        csrf,
			})
			return
		}
		if err := db.SettingSet(h.DB, db.KeyMaxAttachBytes, strconv.FormatInt(n*1024*1024, 10)); err != nil {
			log.Printf("settings general: save max_attach_mb: %v", err)
		}
	}
	// Re-read from DB so form always shows what is actually persisted
	saved, _ := db.SettingGet(h.DB, db.KeyMaxAttachBytes)
	h.renderV(w, "settings/general.html", map[string]any{
		"MaxAttachMB": bytesToMB(saved),
		"Success":     "Settings saved",
		"CSRF":        csrf,
	})
}

// ── Security policy ───────────────────────────────────────────────────────

func (h *Handler) settingsPolicyGet(w http.ResponseWriter, r *http.Request) {
	s, err := db.SettingGetAll(h.DB)
	if err != nil {
		log.Printf("settings policy: load settings: %v", err)
		s = map[string]string{}
	}
	h.renderV(w, "settings/policy.html", policyData(s, auth.NewCSRFToken(w), "", ""))
}

func (h *Handler) settingsPolicyPost(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	csrf := auth.NewCSRFToken(w)
	setOrLog := func(key, val string) {
		if err := db.SettingSet(h.DB, key, val); err != nil {
			log.Printf("settings policy: set %s: %v", key, err)
		}
	}

	// ── Mode ───────────────────────────────────────────────────────────
	mode := r.FormValue("mode")
	if mode != "strict" && mode != "balanced" && mode != "relaxed" {
		mode = "relaxed" // safe default
	}
	setOrLog(db.KeySecurityMode, mode)

	// ── Token settings ─────────────────────────────────────────────────
	setOrLog(db.KeySecurityRequireToken, boolStr(r.FormValue("require_token") == "on"))
	loc := r.FormValue("token_location")
	if loc != "subject" && loc != "header" {
		loc = "subject"
	}
	setOrLog(db.KeySecurityTokenLocation, loc)
	setOrLog(db.KeySecurityTokens, strings.TrimSpace(r.FormValue("tokens")))

	// ── Size limits — always save, use defaults if blank ───────────────
	maxEmailMB := strings.TrimSpace(r.FormValue("max_email_mb"))
	if maxEmailMB == "" {
		maxEmailMB = "10"
	}
	if n, err := strconv.ParseInt(maxEmailMB, 10, 64); err != nil || n <= 0 {
		maxEmailMB = "10"
	}
	setOrLog(db.KeySecurityMaxEmailMB, maxEmailMB)

	maxAttachments := strings.TrimSpace(r.FormValue("max_attachments"))
	if maxAttachments == "" {
		maxAttachments = "5"
	}
	if n, err := strconv.Atoi(maxAttachments); err != nil || n < 0 {
		maxAttachments = "5"
	}
	setOrLog(db.KeySecurityMaxAttachments, maxAttachments)

	maxAttachMB := strings.TrimSpace(r.FormValue("max_attach_mb"))
	if maxAttachMB == "" {
		maxAttachMB = "5"
	}
	if n, err := strconv.ParseInt(maxAttachMB, 10, 64); err != nil || n <= 0 {
		maxAttachMB = "5"
	}
	setOrLog(db.KeySecurityMaxAttachMB, maxAttachMB)

	// ── IP allowlist — validate before saving ─────────────────────────
	subnets := strings.TrimSpace(r.FormValue("allowed_subnets"))
	if err := validateSubnets(subnets); err != nil {
		// Reload all other saved values so the form is accurate
		s, _ := db.SettingGetAll(h.DB)
		data := policyData(s, csrf, "Invalid subnet: "+err.Error(), "")
		h.renderV(w, "settings/policy.html", data)
		return
	}
	setOrLog(db.KeyAllowedSubnets, subnets)

	// Re-read everything from DB so form always reflects what was actually saved
	s, err := db.SettingGetAll(h.DB)
	if err != nil {
		log.Printf("settings policy: reload after save: %v", err)
		s = map[string]string{}
	}
	data := policyData(s, csrf, "", "Security policy saved")
	h.renderV(w, "settings/policy.html", data)
}

// policyData builds the template data map for the security policy page,
// always sourced from the database so the form reflects what was saved.
func policyData(s map[string]string, csrf, errMsg, successMsg string) map[string]any {
	mode := s[db.KeySecurityMode]
	tokens := s[db.KeySecurityTokens]
	requireToken := s[db.KeySecurityRequireToken] == "1"

	var warn string
	if requireToken && tokens == "" && (mode == "strict" || mode == "balanced") {
		warn = "Token authentication is required but no tokens are configured. All emails will be rejected until you add at least one token, or switch to Relaxed mode."
	}
	return map[string]any{
		"Mode":           mode,
		"RequireToken":   requireToken,
		"TokenLocation":  s[db.KeySecurityTokenLocation],
		"Tokens":         tokens,
		"MaxEmailMB":     s[db.KeySecurityMaxEmailMB],
		"MaxAttachments": s[db.KeySecurityMaxAttachments],
		"MaxAttachMB":    s[db.KeySecurityMaxAttachMB],
		"AllowedSubnets": s[db.KeyAllowedSubnets],
		"Warning":        warn,
		"Error":          errMsg,
		"Success":        successMsg,
		"CSRF":           csrf,
	}
}

func toSlug(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			b.WriteRune(c)
		case c >= 'A' && c <= 'Z':
			b.WriteRune(c + 32)
		case c == ' ' || c == '-' || c == '_':
			b.WriteByte('-')
		}
	}
	// Trim leading/trailing hyphens
	return strings.Trim(b.String(), "-")
}

func bytesToMB(s string) string {
	if s == "" {
		return "25"
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return "25"
	}
	return strconv.FormatInt(n/1024/1024, 10)
}

func validateSubnets(raw string) error {
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		cidr := part
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("%q is not a valid IP or CIDR", part)
		}
	}
	return nil
}
