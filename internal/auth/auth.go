package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"emailstore/internal/db"

	"golang.org/x/crypto/bcrypt"
)

const (
	cookieName        = "es_session"
	defaultTimeoutMin = 480
)

var ErrInvalidCredentials = errors.New("invalid credentials")

func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(b), err
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func NewSession(sqldb *sql.DB, timeoutMins int) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	now := time.Now().Unix()
	exp := now + int64(timeoutMins)*60

	_, err := sqldb.Exec(
		`INSERT INTO sessions (id, created_at, expires_at) VALUES (?, ?, ?)`,
		id, now, exp,
	)
	return id, err
}

func ValidateSession(sqldb *sql.DB, id string) bool {
	var exp int64
	err := sqldb.QueryRow(
		`SELECT expires_at FROM sessions WHERE id = ?`, id,
	).Scan(&exp)
	if err != nil {
		return false
	}
	return time.Now().Unix() < exp
}

func DeleteSession(sqldb *sql.DB, id string) {
	sqldb.Exec(`DELETE FROM sessions WHERE id = ?`, id)
}

func PruneExpiredSessions(sqldb *sql.DB) {
	sqldb.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().Unix())
}

func SetCookie(w http.ResponseWriter, sessionID string, timeoutMins int) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   timeoutMins * 60,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func GetSessionID(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func timeoutMins(sqldb *sql.DB) int {
	v, _ := db.SettingGet(sqldb, db.KeySessionTimeout)
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return n
	}
	return defaultTimeoutMin
}

func RequireAuth(sqldb *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sid := GetSessionID(r)
		if sid == "" || !ValidateSession(sqldb, sid) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func RequireSetup(sqldb *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, _ := db.SettingGet(sqldb, db.KeySetupDone)
		if v != "1" {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func Login(sqldb *sql.DB, password string) (string, error) {
	hash, err := db.SettingGet(sqldb, db.KeyPasswordHash)
	if err != nil || hash == "" {
		return "", ErrInvalidCredentials
	}
	if !CheckPassword(hash, password) {
		return "", ErrInvalidCredentials
	}
	mins := timeoutMins(sqldb)
	return NewSession(sqldb, mins)
}

// CSRF helpers — double-submit cookie pattern
func CSRFToken(r *http.Request) string {
	c, err := r.Cookie("es_csrf")
	if err != nil {
		return ""
	}
	return c.Value
}

func NewCSRFToken(w http.ResponseWriter) string {
	b := make([]byte, 16)
	rand.Read(b)
	token := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:  "es_csrf",
		Value: token,
		Path:  "/",
		// MaxAge keeps the cookie alive across the page → form submit round trip.
		// 1 hour is plenty; the token is single-use per page load anyway.
		MaxAge:   3600,
		HttpOnly: false,
		// SameSite=Lax (not Strict) is correct here:
		// - Strict blocks cookies on top-level navigations, breaking setup POST
		//   when accessed via a local network IP (192.168.x.x) over plain HTTP.
		// - Lax allows same-site form POSTs while still blocking cross-site requests.
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

func ValidateCSRF(r *http.Request) bool {
	cookie := CSRFToken(r)
	form := r.FormValue("csrf_token")
	return cookie != "" && cookie == form
}
