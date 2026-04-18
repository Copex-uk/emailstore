package handler

import (
	"encoding/json"
	"net/http"

	"emailstore/internal/auth"
	"emailstore/internal/db"
)

// GET /reset-password — generate a code and show the waiting screen
func (h *Handler) resetPasswordGet(w http.ResponseWriter, r *http.Request) {
	// Must have a mailbox user configured — otherwise there's no way to receive the code
	mailboxUser, _ := db.SettingGet(h.DB, db.KeyIMAPUser)
	if mailboxUser == "" {
		h.render(w, "login.html", map[string]any{
			"Error": "Password reset is unavailable: no mailbox is configured yet.",
			"CSRF":  auth.NewCSRFToken(w),
		})
		return
	}

	token, code, err := auth.NewResetToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.render(w, "reset_request.html", map[string]any{
		"Token":       token,
		"Code":        code,
		"MailboxUser": mailboxUser,
	})
}

// GET /reset-password/check?token=... — polled by JS every 4s
func (h *Handler) resetPasswordCheck(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	status := auth.CheckResetToken(token)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": status})
}

// POST /reset-password/cancel?token=... — called by JS on timeout
func (h *Handler) resetPasswordCancel(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	auth.CancelResetToken(token)
	w.WriteHeader(http.StatusNoContent)
}

// GET /reset-password/new?token=... — show new password form (only if verified)
func (h *Handler) resetPasswordNewGet(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if auth.CheckResetToken(token) != "verified" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	csrf := auth.NewCSRFToken(w)
	h.render(w, "reset_new.html", map[string]any{
		"Token": token,
		"CSRF":  csrf,
	})
}

// POST /reset-password/new — set the new password
func (h *Handler) resetPasswordNewPost(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	token := r.FormValue("token")

	// ConsumeResetToken verifies AND removes the token atomically
	if !auth.ConsumeResetToken(token) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	if len(password) < 8 {
		csrf := auth.NewCSRFToken(w)
		h.render(w, "reset_new.html", map[string]any{
			"Token": token,
			"Error": "Password must be at least 8 characters",
			"CSRF":  csrf,
		})
		return
	}
	if password != confirm {
		csrf := auth.NewCSRFToken(w)
		h.render(w, "reset_new.html", map[string]any{
			"Token": token,
			"Error": "Passwords do not match",
			"CSRF":  csrf,
		})
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	db.SettingSet(h.DB, db.KeyPasswordHash, hash)

	// Kill all existing sessions
	h.DB.Exec(`DELETE FROM sessions`)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
