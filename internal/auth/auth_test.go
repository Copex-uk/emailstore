package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"emailstore/internal/testhelper"
)

// ── Password hashing ──────────────────────────────────────────────────────

func TestHashAndCheckPassword(t *testing.T) {
	hash, err := HashPassword("correcthorsebattery")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}

	if !CheckPassword(hash, "correcthorsebattery") {
		t.Error("CheckPassword: correct password returned false")
	}
	if CheckPassword(hash, "wrongpassword") {
		t.Error("CheckPassword: wrong password returned true")
	}
}

func TestHashPassword_MinLength(t *testing.T) {
	// Even a 1-char password should hash without error — length enforcement
	// is the caller's responsibility, not the hasher's.
	_, err := HashPassword("x")
	if err != nil {
		t.Errorf("HashPassword short string: %v", err)
	}
}

// ── Sessions ──────────────────────────────────────────────────────────────

func TestSessionLifecycle(t *testing.T) {
	sqldb := testhelper.NewDB(t)

	// Create a session
	id, err := NewSession(sqldb, 60)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if len(id) != 64 { // 32 bytes hex-encoded
		t.Errorf("expected 64-char session ID, got %d", len(id))
	}

	// Should be valid immediately
	if !ValidateSession(sqldb, id) {
		t.Error("session should be valid immediately after creation")
	}

	// Non-existent session should be invalid
	if ValidateSession(sqldb, "doesnotexist") {
		t.Error("non-existent session should be invalid")
	}

	// Delete and verify
	DeleteSession(sqldb, id)
	if ValidateSession(sqldb, id) {
		t.Error("deleted session should be invalid")
	}
}

func TestSessionExpiry(t *testing.T) {
	sqldb := testhelper.NewDB(t)

	// Create a session that expires immediately (0 minutes = expires at now)
	id, err := NewSession(sqldb, 0)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	// With 0 minutes timeout, exp = now + 0 = already expired
	if ValidateSession(sqldb, id) {
		t.Error("zero-timeout session should be immediately invalid")
	}
}

func TestPruneExpiredSessions(t *testing.T) {
	sqldb := testhelper.NewDB(t)

	// Create a valid session
	validID, _ := NewSession(sqldb, 60)

	// Insert an already-expired session directly with a past timestamp
	sqldb.Exec(
		`INSERT INTO sessions (id, created_at, expires_at) VALUES (?, ?, ?)`,
		"expired-session-id",
		time.Now().Add(-2*time.Hour).Unix(),
		time.Now().Add(-1*time.Hour).Unix(), // expired 1 hour ago
	)

	if err := PruneExpiredSessions(sqldb); err != nil {
		t.Fatalf("PruneExpiredSessions: %v", err)
	}

	if !ValidateSession(sqldb, validID) {
		t.Error("valid session should survive pruning")
	}

	var count int
	sqldb.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 session after prune, got %d", count)
	}
}

// ── CSRF ──────────────────────────────────────────────────────────────────

func TestCSRFRoundTrip(t *testing.T) {
	w := httptest.NewRecorder()
	token := NewCSRFToken(w)
	if len(token) != 32 {
		t.Errorf("expected 32-char CSRF token, got %d", len(token))
	}

	// Verify the cookie has the right attributes
	var csrfCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "es_csrf" {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("CSRF cookie not set")
	}
	if csrfCookie.MaxAge != 3600 {
		t.Errorf("CSRF cookie MaxAge = %d, want 3600", csrfCookie.MaxAge)
	}
	// SameSite is not set — browser defaults to Lax.
	// Explicitly setting it to Strict or None both cause failures over plain HTTP.
	if csrfCookie.SameSite == http.SameSiteStrictMode {
		t.Error("CSRF cookie must not use SameSite=Strict (breaks LAN form POSTs)")
	}
	if csrfCookie.SameSite == http.SameSiteNoneMode {
		t.Error("CSRF cookie must not use SameSite=None without Secure flag (browser drops it)")
	}

	// Build a request that carries the cookie and form value
	req := httptest.NewRequest("POST", "/", nil)
	req.AddCookie(&http.Cookie{Name: "es_csrf", Value: token})
	req.Form = map[string][]string{"csrf_token": {token}}

	if !ValidateCSRF(req) {
		t.Error("CSRF validation should pass when cookie and form value match")
	}
}

func TestCSRFMismatch(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	req.AddCookie(&http.Cookie{Name: "es_csrf", Value: "tokenA"})
	req.Form = map[string][]string{"csrf_token": {"tokenB"}}

	if ValidateCSRF(req) {
		t.Error("CSRF validation should fail when cookie and form value differ")
	}
}

func TestCSRFMissingCookie(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	req.Form = map[string][]string{"csrf_token": {"sometoken"}}

	if ValidateCSRF(req) {
		t.Error("CSRF validation should fail when cookie is absent")
	}
}

// ── Rate limiter ──────────────────────────────────────────────────────────

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := &RateLimiter{
		attempts:    make(map[string]*loginAttempt),
		maxAttempts: 5,
		window:      10 * time.Minute,
		lockFor:     15 * time.Minute,
	}
	for i := 0; i < 4; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Errorf("should be allowed on attempt %d", i+1)
		}
		rl.RecordFailure("1.2.3.4")
	}
}

func TestRateLimiter_BlocksAfterMax(t *testing.T) {
	rl := &RateLimiter{
		attempts:    make(map[string]*loginAttempt),
		maxAttempts: 3,
		window:      10 * time.Minute,
		lockFor:     15 * time.Minute,
	}
	for i := 0; i < 3; i++ {
		rl.RecordFailure("1.2.3.4")
	}
	if rl.Allow("1.2.3.4") {
		t.Error("IP should be blocked after maxAttempts failures")
	}
}

func TestRateLimiter_ResetClearsBlock(t *testing.T) {
	rl := &RateLimiter{
		attempts:    make(map[string]*loginAttempt),
		maxAttempts: 2,
		window:      10 * time.Minute,
		lockFor:     15 * time.Minute,
	}
	rl.RecordFailure("1.2.3.4")
	rl.RecordFailure("1.2.3.4")
	rl.Reset("1.2.3.4")
	if !rl.Allow("1.2.3.4") {
		t.Error("IP should be allowed after reset")
	}
}

func TestRateLimiter_DifferentIPsIndependent(t *testing.T) {
	rl := &RateLimiter{
		attempts:    make(map[string]*loginAttempt),
		maxAttempts: 2,
		window:      10 * time.Minute,
		lockFor:     15 * time.Minute,
	}
	rl.RecordFailure("1.1.1.1")
	rl.RecordFailure("1.1.1.1")
	// 1.1.1.1 is now blocked, but 2.2.2.2 should be fine
	if !rl.Allow("2.2.2.2") {
		t.Error("different IP should not be affected by another IP's failures")
	}
}

func TestRemoteIP(t *testing.T) {
	tests := []struct {
		remoteAddr string
		want       string
	}{
		{"192.168.1.1:1234", "192.168.1.1"},
		{"[::1]:8080", "[::1]"},
		{"10.0.0.1:9999", "10.0.0.1"},
	}
	for _, tt := range tests {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = tt.remoteAddr
		got := RemoteIP(req)
		if got != tt.want {
			t.Errorf("RemoteIP(%q) = %q, want %q", tt.remoteAddr, got, tt.want)
		}
	}
}

// ── Cookie helpers ────────────────────────────────────────────────────────

func TestSetAndClearCookie(t *testing.T) {
	w := httptest.NewRecorder()
	SetCookie(w, "mysessionid", 60)

	cookies := w.Result().Cookies()
	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == cookieName {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatal("session cookie not set")
	}
	if found.Value != "mysessionid" {
		t.Errorf("cookie value = %q, want mysessionid", found.Value)
	}
	if !found.HttpOnly {
		t.Error("session cookie should be HttpOnly")
	}

	// Clear
	w2 := httptest.NewRecorder()
	ClearCookie(w2)
	cookies2 := w2.Result().Cookies()
	for _, c := range cookies2 {
		if c.Name == cookieName && c.MaxAge != -1 {
			t.Error("cleared cookie should have MaxAge=-1")
		}
	}
}
