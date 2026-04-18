package security

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ValidationError carries both a human-readable reason and a structured code
// for logging.
type ValidationError struct {
	Code   string // machine-readable: "sender_not_allowed", "token_missing", etc.
	Reason string // human-readable log message
}

func (e *ValidationError) Error() string { return e.Reason }

// ParsedEmail holds the data the validator needs. Using a plain struct keeps
// the security package free of any IMAP or mail library dependencies.
type ParsedEmail struct {
	SenderAddr      string // normalised lowercase email address
	Subject         string
	Headers         map[string]string // lowercase header names
	BodySizeBytes   int64
	Attachments     []AttachmentMeta
}

// AttachmentMeta describes a single attachment without holding its data.
type AttachmentMeta struct {
	Filename  string
	SizeBytes int64
	Data      []byte // first 512 bytes is enough for content detection
}

// ValidateEmail applies the security policy to a parsed email.
// It returns nil on success, or a *ValidationError describing the first
// rule that failed. Validation is ordered from cheapest to most expensive:
//  1. Sender check (O(n) DB lookup — already done by caller, passed in)
//  2. Token check  (string scan)
//  3. Size limits  (arithmetic)
//  4. Attachment limits (arithmetic + content detection)
func ValidateEmail(e *ParsedEmail, senderAllowed bool, policy *Policy) error {
	// ── 1. Sender ──────────────────────────────────────────────────────────
	senderOK := senderAllowed

	// ── 2. Token ───────────────────────────────────────────────────────────
	tokenOK := false
	if policy.TokenRequired && len(policy.Tokens) > 0 {
		extracted := ExtractToken(e, policy.TokenLocation)
		tokenOK = matchesToken(extracted, policy.Tokens)
	} else if !policy.TokenRequired {
		// Token not required — treat as satisfied
		tokenOK = true
	}
	// If tokens are required but none are configured, tokenOK stays false.
	// This is intentional: strict mode with no tokens rejects everything.

	// ── Apply mode logic ───────────────────────────────────────────────────
	switch policy.Mode {
	case ModeStrict:
		// Both required
		if !senderOK {
			return &ValidationError{Code: "sender_not_allowed",
				Reason: fmt.Sprintf("sender %q not in allowlist (strict mode)", e.SenderAddr)}
		}
		if policy.TokenRequired && !tokenOK {
			return &ValidationError{Code: "token_invalid",
				Reason: fmt.Sprintf("valid token required but not found (strict mode, location=%s)", policy.TokenLocation)}
		}
	case ModeBalanced:
		// Either is sufficient
		if !senderOK && !tokenOK {
			return &ValidationError{Code: "auth_failed",
				Reason: fmt.Sprintf("sender %q not allowed and no valid token (balanced mode)", e.SenderAddr)}
		}
	case ModeRelaxed:
		// Sender only
		if !senderOK {
			return &ValidationError{Code: "sender_not_allowed",
				Reason: fmt.Sprintf("sender %q not in allowlist (relaxed mode)", e.SenderAddr)}
		}
	default:
		// Unknown mode — default to strict
		if !senderOK {
			return &ValidationError{Code: "sender_not_allowed",
				Reason: fmt.Sprintf("sender %q not in allowlist (unknown mode, defaulting strict)", e.SenderAddr)}
		}
	}

	// ── 3. Size limits ─────────────────────────────────────────────────────
	maxBytes := policy.Limits.MaxEmailSizeMB * 1024 * 1024
	if maxBytes > 0 && e.BodySizeBytes > maxBytes {
		return &ValidationError{Code: "email_too_large",
			Reason: fmt.Sprintf("email size %d bytes exceeds limit %d MB", e.BodySizeBytes, policy.Limits.MaxEmailSizeMB)}
	}

	// ── 4. Attachment limits ───────────────────────────────────────────────
	if policy.Limits.MaxAttachments > 0 && len(e.Attachments) > policy.Limits.MaxAttachments {
		return &ValidationError{Code: "too_many_attachments",
			Reason: fmt.Sprintf("%d attachments exceeds limit of %d", len(e.Attachments), policy.Limits.MaxAttachments)}
	}

	maxAttachBytes := policy.Limits.MaxAttachSizeMB * 1024 * 1024
	for _, att := range e.Attachments {
		if maxAttachBytes > 0 && att.SizeBytes > maxAttachBytes {
			return &ValidationError{Code: "attachment_too_large",
				Reason: fmt.Sprintf("attachment %q size %d bytes exceeds limit %d MB",
					att.Filename, att.SizeBytes, policy.Limits.MaxAttachSizeMB)}
		}
	}

	return nil
}

// ExtractToken pulls an auth token from the email based on the configured location.
//
// Subject format: any occurrence of [ES:sometoken] — case-insensitive prefix.
// Header format:  X-EmailStore-Auth: sometoken
func ExtractToken(e *ParsedEmail, location TokenLocation) string {
	switch location {
	case TokenInHeader:
		// Check both canonical and lowercase forms
		for _, key := range []string{"x-emailstore-auth", "X-EmailStore-Auth"} {
			if v, ok := e.Headers[strings.ToLower(key)]; ok && v != "" {
				return strings.TrimSpace(v)
			}
		}
	default: // TokenInSubject
		return extractSubjectToken(e.Subject)
	}
	return ""
}

// extractSubjectToken finds [ES:token] anywhere in the subject (case-insensitive).
// Example: "Fwd: Invoice [ES:mytoken] Q1" → "mytoken"
func extractSubjectToken(subject string) string {
	lower := strings.ToLower(subject)
	const prefix = "[es:"
	start := strings.Index(lower, prefix)
	if start == -1 {
		return ""
	}
	rest := subject[start+len(prefix):]
	end := strings.Index(rest, "]")
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(rest[:end])
}

func matchesToken(candidate string, tokens []string) bool {
	if candidate == "" {
		return false
	}
	for _, t := range tokens {
		if t == candidate {
			return true
		}
	}
	return false
}

// DetectMIMEType sniffs the actual content type from the first 512 bytes.
// This is used instead of trusting the declared Content-Type header.
func DetectMIMEType(data []byte) string {
	if len(data) == 0 {
		return "application/octet-stream"
	}
	// http.DetectContentType uses the first 512 bytes
	sniff := data
	if len(sniff) > 512 {
		sniff = sniff[:512]
	}
	return http.DetectContentType(sniff)
}

// ErrNoPolicy is returned when no policy is available.
var ErrNoPolicy = errors.New("security: no policy configured")
