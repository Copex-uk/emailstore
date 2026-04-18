package handler

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"emailstore/internal/auth"
	"emailstore/internal/db"
	"emailstore/internal/testhelper"
)

// newTestHandler creates a Handler with a real in-memory DB and minimal templates.
func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	sqldb := testhelper.NewDB(t)

	// Minimal template set — just enough for the handlers under test
	tmpl := template.Must(template.New("").Funcs(template.FuncMap{
		"add":         func(a, b int) int { return a + b },
		"sub":         func(a, b int) int { return a - b },
		"not":         func(v any) bool { return v == nil },
		"formatBytes": func(n int64) string { return "0 B" },
	}).Parse(`
{{define "login.html"}}<html><body>{{if .Error}}ERROR:{{.Error}}{{end}}</body></html>{{end}}
{{define "setup.html"}}<html><body>SETUP:{{.Step}}{{if .Error}}:{{.Error}}{{end}}</body></html>{{end}}
{{define "inbox.html"}}<html><body>INBOX</body></html>{{end}}
{{define "settings/index.html"}}<html><body>SETTINGS</body></html>{{end}}
`))

	return &Handler{
		DB:           sqldb,
		Templates:    tmpl,
		AttachDir:    t.TempDir(),
		LoginLimiter: auth.NewLoginRateLimiter(),
	}
}

// postForm sends a POST with form values and a matching CSRF cookie+field.
func postForm(t *testing.T, h http.Handler, path string, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	// Generate a CSRF token and add it to the form
	csrfToken := "testcsrftoken123456789012345678"
	values.Set("csrf_token", csrfToken)

	req := httptest.NewRequest("POST", path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "es_csrf", Value: csrfToken})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// ── Setup wizard ──────────────────────────────────────────────────────────

func TestSetupGet_ShowsWizard(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest("GET", "/setup", nil)
	w := httptest.NewRecorder()
	h.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /setup: want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "SETUP:password") {
		t.Errorf("GET /setup: expected setup step=password in body")
	}
}

func TestSetupGet_RedirectsIfDone(t *testing.T) {
	h := newTestHandler(t)
	db.SettingSet(h.DB, db.KeySetupDone, "1")
	db.SettingSet(h.DB, db.KeyPasswordHash, "$2a$10$dummy")

	req := httptest.NewRequest("GET", "/setup", nil)
	w := httptest.NewRecorder()
	h.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("GET /setup when done: want 303, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "/login") {
		t.Errorf("expected redirect to /login, got %s", w.Header().Get("Location"))
	}
}

func TestSetupPost_PasswordTooShort(t *testing.T) {
	h := newTestHandler(t)
	w := postForm(t, h.Routes(), "/setup", url.Values{
		"step":     {"password"},
		"password": {"short"},
		"confirm":  {"short"},
	})
	if w.Code != http.StatusOK {
		t.Errorf("short password: want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "least 8") {
		t.Errorf("expected 'at least 8' error message")
	}
}

func TestSetupPost_PasswordMismatch(t *testing.T) {
	h := newTestHandler(t)
	w := postForm(t, h.Routes(), "/setup", url.Values{
		"step":     {"password"},
		"password": {"longenough1"},
		"confirm":  {"longenough2"},
	})
	if !strings.Contains(w.Body.String(), "match") {
		t.Errorf("expected password mismatch error")
	}
}

func TestSetupPost_ValidPassword_AdvancesToMailbox(t *testing.T) {
	h := newTestHandler(t)
	w := postForm(t, h.Routes(), "/setup", url.Values{
		"step":     {"password"},
		"password": {"securePa$$word1"},
		"confirm":  {"securePa$$word1"},
	})
	if w.Code != http.StatusSeeOther {
		t.Errorf("valid password: want redirect, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "step=mailbox") {
		t.Errorf("expected redirect to mailbox step, got %s", w.Header().Get("Location"))
	}
}

// ── Login ─────────────────────────────────────────────────────────────────

func TestLoginGet_RedirectsToSetupIfNotDone(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()
	h.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("GET /login before setup: want 303, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "/setup") {
		t.Errorf("expected redirect to /setup")
	}
}

func TestLoginPost_WrongPassword(t *testing.T) {
	h := newTestHandler(t)
	// Complete setup first
	hash, _ := auth.HashPassword("correctpassword")
	db.SettingSet(h.DB, db.KeyPasswordHash, hash)
	db.SettingSet(h.DB, db.KeySetupDone, "1")

	w := postForm(t, h.Routes(), "/login", url.Values{
		"password": {"wrongpassword"},
	})
	if w.Code != http.StatusOK {
		t.Errorf("wrong password: want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ERROR:Invalid password") {
		t.Errorf("expected invalid password error, got: %s", w.Body.String())
	}
}

func TestLoginPost_CorrectPassword_SetsSessionCookie(t *testing.T) {
	h := newTestHandler(t)
	hash, _ := auth.HashPassword("correctpassword")
	db.SettingSet(h.DB, db.KeyPasswordHash, hash)
	db.SettingSet(h.DB, db.KeySetupDone, "1")

	w := postForm(t, h.Routes(), "/login", url.Values{
		"password": {"correctpassword"},
	})
	if w.Code != http.StatusSeeOther {
		t.Errorf("correct password: want redirect, got %d", w.Code)
	}

	var sessionCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "es_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie set after successful login")
	}
	if !sessionCookie.HttpOnly {
		t.Error("session cookie should be HttpOnly")
	}
}

// ── Auth middleware ───────────────────────────────────────────────────────

func TestRequireAuth_RedirectsUnauthenticated(t *testing.T) {
	h := newTestHandler(t)
	db.SettingSet(h.DB, db.KeySetupDone, "1")

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("unauthenticated /: want 303, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "/login") {
		t.Errorf("expected redirect to /login")
	}
}

func TestRequireAuth_AllowsWithValidSession(t *testing.T) {
	h := newTestHandler(t)
	db.SettingSet(h.DB, db.KeySetupDone, "1")

	// Create a valid session
	sessionID, _ := auth.NewSession(h.DB, 60)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "es_session", Value: sessionID})
	w := httptest.NewRecorder()
	h.Routes().ServeHTTP(w, req)

	// Should render inbox (200), not redirect
	if w.Code != http.StatusOK {
		t.Errorf("authenticated /: want 200, got %d", w.Code)
	}
}

// ── Security headers ──────────────────────────────────────────────────────

func TestSecurityHeaders_Present(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()
	h.Routes().ServeHTTP(w, req)

	headers := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
	}
	for header, want := range headers {
		got := w.Header().Get(header)
		if got != want {
			t.Errorf("header %s = %q, want %q", header, got, want)
		}
	}
}

// ── Logout ────────────────────────────────────────────────────────────────

func TestLogout_ClearsSession(t *testing.T) {
	h := newTestHandler(t)
	db.SettingSet(h.DB, db.KeySetupDone, "1")

	sessionID, _ := auth.NewSession(h.DB, 60)

	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "es_session", Value: sessionID})
	w := httptest.NewRecorder()
	h.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("logout: want redirect, got %d", w.Code)
	}

	// Session should now be invalid
	if auth.ValidateSession(h.DB, sessionID) {
		t.Error("session should be invalid after logout")
	}
}
