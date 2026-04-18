package auth

import (
	"net/http"
	"sync"
	"time"
)

// loginAttempt tracks failed login attempts for a single IP.
type loginAttempt struct {
	count       int
	firstSeen   time.Time
	lockedUntil time.Time
}

// RateLimiter enforces a cap on failed login attempts per IP.
// After maxAttempts failures within window, the IP is locked for lockDuration.
type RateLimiter struct {
	mu          sync.Mutex
	attempts    map[string]*loginAttempt
	maxAttempts int
	window      time.Duration
	lockFor     time.Duration
}

// NewLoginRateLimiter returns a limiter suited for a login page:
// 5 failures per 10 minutes → 15 minute lockout.
func NewLoginRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		attempts:    make(map[string]*loginAttempt),
		maxAttempts: 5,
		window:      10 * time.Minute,
		lockFor:     15 * time.Minute,
	}
	// Periodically clean up old entries
	go rl.cleanup()
	return rl
}

// Allow returns true if the IP is permitted to attempt login.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	a, ok := rl.attempts[ip]
	if !ok {
		return true
	}
	if time.Now().Before(a.lockedUntil) {
		return false
	}
	if time.Since(a.firstSeen) > rl.window {
		delete(rl.attempts, ip)
		return true
	}
	return a.count < rl.maxAttempts
}

// RecordFailure increments the failure count for an IP.
func (rl *RateLimiter) RecordFailure(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	a, ok := rl.attempts[ip]
	if !ok {
		rl.attempts[ip] = &loginAttempt{count: 1, firstSeen: time.Now()}
		return
	}
	if time.Since(a.firstSeen) > rl.window {
		a.count = 1
		a.firstSeen = time.Now()
		a.lockedUntil = time.Time{}
		return
	}
	a.count++
	if a.count >= rl.maxAttempts {
		a.lockedUntil = time.Now().Add(rl.lockFor)
	}
}

// Reset clears the failure record for an IP on successful login.
func (rl *RateLimiter) Reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, ip)
}

func (rl *RateLimiter) cleanup() {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for range t.C {
		rl.mu.Lock()
		for ip, a := range rl.attempts {
			if time.Since(a.firstSeen) > rl.window && time.Now().After(a.lockedUntil) {
				delete(rl.attempts, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// RemoteIP extracts the client IP from a request, respecting X-Forwarded-For
// only when behind a trusted proxy. For local-only use, r.RemoteAddr is fine.
func RemoteIP(r *http.Request) string {
	// Strip port from RemoteAddr
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
