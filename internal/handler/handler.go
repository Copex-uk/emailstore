package handler

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"emailstore/internal/auth"
	"emailstore/internal/db"
	"emailstore/internal/email"
	imappoller "emailstore/internal/imap"
)

type Handler struct {
	DB          *sql.DB
	Templates   *template.Template
	AttachDir   string
	LoginLimiter *auth.RateLimiter
}

func New(sqldb *sql.DB, tmpl *template.Template, attachDir string) *Handler {
	return &Handler{
		DB:           sqldb,
		Templates:    tmpl,
		AttachDir:    attachDir,
		LoginLimiter: auth.NewLoginRateLimiter(),
	}
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()

	// Static files
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/favicon.svg")
	})
	mux.HandleFunc("GET /favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		http.ServeFile(w, r, "./static/favicon.svg")
	})

	// Public routes
	mux.HandleFunc("GET /setup", h.setupGet)
	mux.HandleFunc("POST /setup", h.setupPost)
	mux.HandleFunc("GET /setup/finish", h.setupFinish)
	mux.HandleFunc("GET /login", h.loginGet)
	mux.HandleFunc("POST /login", h.loginPost)
	mux.HandleFunc("POST /logout", h.logout)
	mux.HandleFunc("GET /reset-password", h.resetPasswordGet)
	mux.HandleFunc("GET /reset-password/check", h.resetPasswordCheck)
	mux.HandleFunc("POST /reset-password/cancel", h.resetPasswordCancel)
	mux.HandleFunc("GET /reset-password/new", h.resetPasswordNewGet)
	mux.HandleFunc("POST /reset-password/new", h.resetPasswordNewPost)

	// Protected routes
	protected := http.NewServeMux()
	protected.HandleFunc("GET /", h.inbox)
	protected.HandleFunc("GET /emails/{id}", h.viewEmail)
	protected.HandleFunc("POST /emails/{id}/category", h.setCategory)
	protected.HandleFunc("POST /emails/{id}/delete", h.deleteEmail)
	protected.HandleFunc("GET /emails/{id}/download", h.downloadEmail)
	protected.HandleFunc("GET /attachments/{id}", h.downloadAttachment)
	protected.HandleFunc("GET /settings", h.settingsIndex)
	protected.HandleFunc("GET /settings/security", h.settingsSecurityGet)
	protected.HandleFunc("POST /settings/security", h.settingsSecurityPost)
	protected.HandleFunc("GET /settings/mailbox", h.settingsMailboxGet)
	protected.HandleFunc("POST /settings/mailbox", h.settingsMailboxPost)
	protected.HandleFunc("GET /settings/senders", h.settingsSendersGet)
	protected.HandleFunc("POST /settings/senders", h.settingsSendersPost)
	protected.HandleFunc("POST /settings/senders/delete", h.settingsSendersDelete)
	protected.HandleFunc("GET /settings/categories", h.settingsCategoriesGet)
	protected.HandleFunc("POST /settings/categories", h.settingsCategoriesPost)
	protected.HandleFunc("GET /settings/general", h.settingsGeneralGet)
	protected.HandleFunc("POST /settings/general", h.settingsGeneralPost)
	protected.HandleFunc("GET /settings/policy", h.settingsPolicyGet)
	protected.HandleFunc("POST /settings/policy", h.settingsPolicyPost)
	protected.HandleFunc("POST /settings/reset-setup", h.resetSetup)
	protected.HandleFunc("POST /poll", h.manualPoll)
	protected.HandleFunc("GET /help", h.help)

	authed := auth.RequireAuth(h.DB, protected)

	// Wrap entire mux with security headers
	mux.Handle("/", authed)

	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) render(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := h.Templates.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("template error [%s]: %v", name, err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

func (h *Handler) setupGet(w http.ResponseWriter, r *http.Request) {
	done, _ := db.SettingGet(h.DB, db.KeySetupDone)
	if done == "1" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	step := r.URL.Query().Get("step")
	if step == "" {
		step = "password"
	}
	// No CSRF on setup — no account exists yet so nothing sensitive to protect.
	// The setup_done flag prevents replay once setup is complete.
	switch step {
	case "mailbox":
		s, _ := db.SettingGetAll(h.DB)
		mode := "tls"
		if s[db.KeyIMAPStartTLS] == "1" {
			mode = "starttls"
		} else if s[db.KeyIMAPTLS] != "1" && s[db.KeyIMAPHost] != "" {
			mode = "plain"
		}
		h.render(w, "setup.html", map[string]any{
			"Step": "mailbox",
			"Host": s[db.KeyIMAPHost], "Port": s[db.KeyIMAPPort],
			"User": s[db.KeyIMAPUser], "Mode": mode,
			"PollInterval": s[db.KeyPollInterval],
		})
	case "categories":
		h.render(w, "setup.html", map[string]any{
			"Step": "categories",
			"DefaultCategories": []map[string]string{
				{"name": "Inbox", "slug": "inbox", "color": "#6366f1"},
				{"name": "Work", "slug": "work", "color": "#0ea5e9"},
				{"name": "Personal", "slug": "personal", "color": "#22c55e"},
				{"name": "Finance", "slug": "finance", "color": "#f59e0b"},
				{"name": "Other", "slug": "other", "color": "#94a3b8"},
			},
		})
	default:
		h.render(w, "setup.html", map[string]any{"Step": "password"})
	}
}

func (h *Handler) setupPost(w http.ResponseWriter, r *http.Request) {
	done, _ := db.SettingGet(h.DB, db.KeySetupDone)
	if done == "1" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// CSRF is not enforced during setup: no account exists yet so there is
	// nothing sensitive to protect, and enforcing it causes failures when
	// accessed over a local network IP via plain HTTP where the browser may
	// not send the SameSite cookie on the first POST.
	// The setup_done flag is the guard — once set, this handler redirects away.
	step := r.FormValue("step")
	switch step {
	case "password":
		password := r.FormValue("password")
		confirm := r.FormValue("confirm")
		if len(password) < 8 {
			csrf := auth.NewCSRFToken(w)
			h.render(w, "setup.html", map[string]any{
				"Step": "password", "CSRF": csrf,
				"Error": "Password must be at least 8 characters",
			})
			return
		}
		if password != confirm {
			csrf := auth.NewCSRFToken(w)
			h.render(w, "setup.html", map[string]any{
				"Step": "password", "CSRF": csrf,
				"Error": "Passwords do not match",
			})
			return
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		db.SettingSet(h.DB, db.KeyPasswordHash, hash)
		db.SettingSet(h.DB, db.KeySessionTimeout, "480")
		db.SettingSet(h.DB, db.KeyPollInterval, "15")
		http.Redirect(w, r, "/setup?step=mailbox", http.StatusSeeOther)
	case "mailbox":
		if host := r.FormValue("host"); host != "" {
			db.SettingSet(h.DB, db.KeyIMAPHost, host)
			db.SettingSet(h.DB, db.KeyIMAPPort, r.FormValue("port"))
			db.SettingSet(h.DB, db.KeyIMAPUser, r.FormValue("user"))
			if p := r.FormValue("password"); p != "" {
				db.SettingSet(h.DB, db.KeyIMAPPassword, p)
			}
			mode := r.FormValue("mode")
			db.SettingSet(h.DB, db.KeyIMAPTLS, boolStr(mode == "tls"))
			db.SettingSet(h.DB, db.KeyIMAPStartTLS, boolStr(mode == "starttls"))
			if interval := r.FormValue("poll_interval"); interval != "" {
				db.SettingSet(h.DB, db.KeyPollInterval, interval)
			}
		}
		http.Redirect(w, r, "/setup?step=categories", http.StatusSeeOther)
	case "categories":
		selected := r.Form["categories"]
		allDefaults := []struct{ name, slug, color string }{
			{"Inbox", "inbox", "#6366f1"},
			{"Work", "work", "#0ea5e9"},
			{"Personal", "personal", "#22c55e"},
			{"Finance", "finance", "#f59e0b"},
			{"Other", "other", "#94a3b8"},
		}
		// Remove all default categories first so unchecked ones are cleared,
		// but NEVER remove inbox — it is the permanent fallback category.
		for _, cat := range allDefaults {
			if cat.slug != "inbox" {
				h.DB.Exec(`DELETE FROM categories WHERE slug = ?`, cat.slug)
			}
		}
		// Always ensure inbox exists regardless of what was checked
		h.DB.Exec(
			`INSERT OR IGNORE INTO categories (name, slug, color) VALUES ('Inbox', 'inbox', '#6366f1')`,
		)
		// Insert the other categories the user selected
		for _, sel := range selected {
			if sel == "inbox" {
				continue // already handled above
			}
			for _, cat := range allDefaults {
				if sel == cat.slug {
					h.DB.Exec(
						`INSERT OR IGNORE INTO categories (name, slug, color) VALUES (?, ?, ?)`,
						cat.name, cat.slug, cat.color,
					)
					break
				}
			}
		}
		db.SettingSet(h.DB, db.KeySetupDone, "1")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
	}
}

func (h *Handler) setupFinish(w http.ResponseWriter, r *http.Request) {
	// Skipping categories — still ensure inbox always exists as the fallback
	done, _ := db.SettingGet(h.DB, db.KeySetupDone)
	if done == "1" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	h.DB.Exec(
		`INSERT OR IGNORE INTO categories (name, slug, color) VALUES ('Inbox', 'inbox', '#6366f1')`,
	)
	db.SettingSet(h.DB, db.KeySetupDone, "1")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) loginGet(w http.ResponseWriter, r *http.Request) {
	done, _ := db.SettingGet(h.DB, db.KeySetupDone)
	if done != "1" {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	csrf := auth.NewCSRFToken(w)
	h.render(w, "login.html", map[string]any{"CSRF": csrf})
}

func (h *Handler) loginPost(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	ip := auth.RemoteIP(r)
	if !h.LoginLimiter.Allow(ip) {
		log.Printf("event=login_rate_limited ip=%s", ip)
		csrf := auth.NewCSRFToken(w)
		h.render(w, "login.html", map[string]any{
			"Error": "Too many failed attempts. Please wait 15 minutes before trying again.",
			"CSRF":  csrf,
		})
		return
	}
	sessionID, err := auth.Login(h.DB, r.FormValue("password"))
	if err != nil {
		h.LoginLimiter.RecordFailure(ip)
		log.Printf("event=login_failed ip=%s", ip)
		csrf := auth.NewCSRFToken(w)
		h.render(w, "login.html", map[string]any{
			"Error": "Invalid password",
			"CSRF":  csrf,
		})
		return
	}
	h.LoginLimiter.Reset(ip)
	log.Printf("event=login_success ip=%s", ip)
	timeoutStr, _ := db.SettingGet(h.DB, db.KeySessionTimeout)
	timeout, _ := strconv.Atoi(timeoutStr)
	if timeout <= 0 {
		timeout = 480
	}
	auth.SetCookie(w, sessionID, timeout)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	sid := auth.GetSessionID(r)
	if sid != "" {
		auth.DeleteSession(h.DB, sid)
	}
	auth.ClearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) manualPoll(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	start := time.Now()
	err := imappoller.Poll(h.DB, h.AttachDir)
	elapsed := time.Since(start).Round(time.Millisecond)
	if err != nil {
		log.Printf("manual poll error: %v", err)
		// Redirect back with error in query param
		http.Redirect(w, r, "/settings/mailbox?poll_error="+urlEncode(err.Error()), http.StatusSeeOther)
		return
	}
	log.Printf("manual poll completed in %s", elapsed)
	http.Redirect(w, r, "/?polled=1", http.StatusSeeOther)
}

func (h *Handler) help(w http.ResponseWriter, r *http.Request) {
	h.render(w, "help.html", nil)
}

func urlEncode(s string) string {
	var out []byte
	for _, b := range []byte(s) {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.' {
			out = append(out, b)
		} else {
			out = append(out, '+')
		}
	}
	return string(out)
}
func (h *Handler) resetSetup(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	db.SettingSet(h.DB, db.KeySetupDone, "0")
	sid := auth.GetSessionID(r)
	if sid != "" {
		auth.DeleteSession(h.DB, sid)
	}
	auth.ClearCookie(w)
	http.Redirect(w, r, "/setup", http.StatusSeeOther)
}

func (h *Handler) inbox(w http.ResponseWriter, r *http.Request) {
	cats, _ := email.ListCategories(h.DB)
	counts, _ := email.CountByCategory(h.DB)

	slug := r.URL.Query().Get("category")
	var catID int64
	activeCatName := ""
	if slug != "" {
		if cat, err := email.CategoryBySlug(h.DB, slug); err == nil {
			catID = cat.ID
			activeCatName = cat.Name
		}
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit := 25
	offset := (page - 1) * limit

	emails, _ := email.List(h.DB, catID, limit, offset)

	h.render(w, "inbox.html", map[string]any{
		"Emails":        emails,
		"Categories":    cats,
		"Counts":        counts,
		"ActiveSlug":    slug,
		"ActiveCatName": activeCatName,
		"Page":          page,
		"Polled":        r.URL.Query().Get("polled") == "1",
		"CSRF":          auth.NewCSRFToken(w),
	})
}

func (h *Handler) viewEmail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	e, err := email.Get(h.DB, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	email.MarkRead(h.DB, id)

	cats, _ := email.ListCategories(h.DB)
	csrf := auth.NewCSRFToken(w)
	h.render(w, "email.html", map[string]any{
		"Email":      e,
		"Categories": cats,
		"CSRF":       csrf,
	})
}

func (h *Handler) setCategory(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	emailID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	catID, err := strconv.ParseInt(r.FormValue("category_id"), 10, 64)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email.SetCategory(h.DB, emailID, catID)
	http.Redirect(w, r, "/emails/"+r.PathValue("id"), http.StatusSeeOther)
}

func (h *Handler) deleteEmail(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Require the user to have typed "delete" as confirmation
	if r.FormValue("confirm") != "delete" {
		http.Redirect(w, r, "/emails/"+r.PathValue("id"), http.StatusSeeOther)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Get attachment paths before deleting from DB (FK cascade removes rows)
	paths, _ := email.GetAttachmentPaths(h.DB, id)

	if err := email.Delete(h.DB, id); err != nil {
		log.Printf("event=delete_error email_id=%d err=%q", id, err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}

	// Remove attachment files and their directory from disk
	for _, p := range paths {
		os.Remove(p)
	}
	if len(paths) > 0 {
		// Remove the per-email attachment directory if now empty
		dir := filepath.Dir(paths[0])
		os.Remove(dir) // only removes if empty
	}

	log.Printf("event=email_deleted email_id=%d", id)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) downloadEmail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	e, err := email.Get(h.DB, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if len(e.Attachments) == 0 {
		// No attachments — serve a plain .eml file
		eml := buildEML(e)
		filename := fmt.Sprintf("email-%d.eml", e.ID)
		w.Header().Set("Content-Disposition",
			mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
		w.Header().Set("Content-Type", "message/rfc822")
		w.Write(eml)
		return
	}

	// Has attachments — serve a zip containing the .eml and all attachment files
	filename := fmt.Sprintf("email-%d.zip", e.ID)
	w.Header().Set("Content-Disposition",
		mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
	w.Header().Set("Content-Type", "application/zip")

	zw := zip.NewWriter(w)
	defer zw.Close()

	// Write the email body as a .eml file inside the zip
	emlWriter, err := zw.Create(fmt.Sprintf("email-%d.eml", e.ID))
	if err == nil {
		emlWriter.Write(buildEML(e))
	}

	// Write each attachment file
	for _, att := range e.Attachments {
		data, err := os.ReadFile(att.StoredPath)
		if err != nil {
			log.Printf("event=download_attach_read_error path=%q err=%q", att.StoredPath, err)
			continue
		}
		f, err := zw.Create(att.Filename)
		if err != nil {
			continue
		}
		f.Write(data)
	}
}

// buildEML constructs a minimal RFC 822 formatted email from stored content.
func buildEML(e *email.Email) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s <%s>\r\n", e.SenderName, e.SenderEmail)
	fmt.Fprintf(&b, "Subject: %s\r\n", e.Subject)
	fmt.Fprintf(&b, "Date: %s\r\n", e.ReceivedAt.Format("Mon, 02 Jan 2006 15:04:05 -0700"))
	fmt.Fprintf(&b, "Message-ID: %s\r\n", e.MessageID)
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	if e.BodyHTML != "" {
		fmt.Fprintf(&b, "Content-Type: text/html; charset=utf-8\r\n\r\n")
		b.WriteString(e.BodyHTML)
	} else {
		fmt.Fprintf(&b, "Content-Type: text/plain; charset=utf-8\r\n\r\n")
		b.WriteString(e.BodyText)
	}
	return b.Bytes()
}

func (h *Handler) downloadAttachment(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var filename, mimeType, storedPath string
	err = h.DB.QueryRow(
		`SELECT filename, mime_type, stored_path FROM attachments WHERE id = ?`, id,
	).Scan(&filename, &mimeType, &storedPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Disposition",
		mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
	w.Header().Set("Content-Type", mimeType)
	http.ServeFile(w, r, storedPath)
}
