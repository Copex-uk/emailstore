package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// ResetToken holds an in-memory pending password reset.
// Nothing is stored in the DB — if the server restarts the reset is cancelled.
type ResetToken struct {
	Token     string
	Code      string // the subject line the user must send
	CreatedAt time.Time
	Verified  bool
}

var (
	resetMu     sync.Mutex
	resetTokens = map[string]*ResetToken{}
)

const resetTTL = 5 * time.Minute

// NewResetToken creates a fresh reset attempt and returns the token and code.
func NewResetToken() (token, code string, err error) {
	// Token is a 32-byte hex used in URLs (not guessable)
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	token = hex.EncodeToString(b)

	// Code is a memorable 6-digit number the user puts in an email subject
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return
	}
	code = fmt.Sprintf("RESET-%06d", n.Int64()+100000)

	resetMu.Lock()
	defer resetMu.Unlock()

	// Purge any previous pending resets (only one at a time allowed)
	resetTokens = map[string]*ResetToken{}

	resetTokens[token] = &ResetToken{
		Token:     token,
		Code:      code,
		CreatedAt: time.Now(),
	}
	return
}

// CheckResetToken returns the token status: "pending", "verified", "expired", "notfound"
func CheckResetToken(token string) string {
	resetMu.Lock()
	defer resetMu.Unlock()
	rt, ok := resetTokens[token]
	if !ok {
		return "notfound"
	}
	if time.Since(rt.CreatedAt) > resetTTL {
		delete(resetTokens, token)
		return "expired"
	}
	if rt.Verified {
		return "verified"
	}
	return "pending"
}

// VerifyResetByCode is called by the IMAP poller when it sees an email
// with a subject matching a pending reset code.
func VerifyResetByCode(code string) bool {
	resetMu.Lock()
	defer resetMu.Unlock()
	for _, rt := range resetTokens {
		if rt.Code == code && time.Since(rt.CreatedAt) <= resetTTL {
			rt.Verified = true
			return true
		}
	}
	return false
}

// CancelResetToken removes a reset token (used on timeout or cancel).
func CancelResetToken(token string) {
	resetMu.Lock()
	defer resetMu.Unlock()
	delete(resetTokens, token)
}

// ConsumeResetToken removes and returns the token if valid and verified.
func ConsumeResetToken(token string) bool {
	resetMu.Lock()
	defer resetMu.Unlock()
	rt, ok := resetTokens[token]
	if !ok {
		return false
	}
	if !rt.Verified || time.Since(rt.CreatedAt) > resetTTL {
		delete(resetTokens, token)
		return false
	}
	delete(resetTokens, token)
	return true
}
