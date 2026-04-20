package security

import (
	"testing"
)

func TestExtractSubjectToken(t *testing.T) {
	tests := []struct {
		subject string
		want    string
	}{
		{"Invoice [ES:abc123] Q1", "abc123"},
		{"[ES:tok] prefix", "tok"},
		{"suffix [ES:end]", "end"},
		{"No token here", ""},
		{"[es:lowercase] works", "lowercase"},
		{"[ES:  spaced  ]", "spaced"},
		{"[ES:]", ""}, // empty token
		{"broken [ES:no-close", ""},
	}
	for _, tt := range tests {
		got := extractSubjectToken(tt.subject)
		if got != tt.want {
			t.Errorf("extractSubjectToken(%q) = %q, want %q", tt.subject, got, tt.want)
		}
	}
}

func TestValidateEmail_StrictMode(t *testing.T) {
	policy := &Policy{
		Mode:          ModeStrict,
		TokenRequired: true,
		TokenLocation: TokenInSubject,
		Tokens:        []string{"secret123"},
		Limits:        Limits{MaxEmailSizeMB: 10, MaxAttachments: 5, MaxAttachSizeMB: 5},
	}

	t.Run("valid_sender_and_token", func(t *testing.T) {
		e := &ParsedEmail{
			SenderAddr: "alice@example.com",
			Subject:    "Hello [ES:secret123]",
		}
		if err := ValidateEmail(e, true, policy); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("invalid_sender", func(t *testing.T) {
		e := &ParsedEmail{
			SenderAddr: "evil@attacker.com",
			Subject:    "Hello [ES:secret123]",
		}
		err := ValidateEmail(e, false, policy)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		ve := err.(*ValidationError)
		if ve.Code != "sender_not_allowed" {
			t.Errorf("expected sender_not_allowed, got %s", ve.Code)
		}
	})

	t.Run("missing_token", func(t *testing.T) {
		e := &ParsedEmail{
			SenderAddr: "alice@example.com",
			Subject:    "Hello, no token here",
		}
		err := ValidateEmail(e, true, policy)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		ve := err.(*ValidationError)
		if ve.Code != "token_invalid" {
			t.Errorf("expected token_invalid, got %s", ve.Code)
		}
	})

	t.Run("wrong_token", func(t *testing.T) {
		e := &ParsedEmail{
			SenderAddr: "alice@example.com",
			Subject:    "Hello [ES:wrongtoken]",
		}
		err := ValidateEmail(e, true, policy)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestValidateEmail_BalancedMode(t *testing.T) {
	policy := &Policy{
		Mode:          ModeBalanced,
		TokenRequired: true,
		TokenLocation: TokenInSubject,
		Tokens:        []string{"secret123"},
		Limits:        Limits{MaxEmailSizeMB: 10, MaxAttachments: 5, MaxAttachSizeMB: 5},
	}

	t.Run("unknown_sender_but_valid_token", func(t *testing.T) {
		e := &ParsedEmail{Subject: "Hello [ES:secret123]"}
		if err := ValidateEmail(e, false, policy); err != nil {
			t.Errorf("balanced mode should accept valid token even with unknown sender: %v", err)
		}
	})

	t.Run("known_sender_no_token", func(t *testing.T) {
		e := &ParsedEmail{SenderAddr: "alice@example.com", Subject: "No token"}
		if err := ValidateEmail(e, true, policy); err != nil {
			t.Errorf("balanced mode should accept known sender even without token: %v", err)
		}
	})

	t.Run("neither_sender_nor_token", func(t *testing.T) {
		e := &ParsedEmail{SenderAddr: "evil@example.com", Subject: "No token"}
		if err := ValidateEmail(e, false, policy); err == nil {
			t.Fatal("expected error when neither sender nor token valid")
		}
	})
}

func TestValidateEmail_RelaxedMode(t *testing.T) {
	policy := &Policy{
		Mode:          ModeRelaxed,
		TokenRequired: false,
		Limits:        Limits{MaxEmailSizeMB: 10, MaxAttachments: 5, MaxAttachSizeMB: 5},
	}

	t.Run("known_sender_no_token_needed", func(t *testing.T) {
		e := &ParsedEmail{SenderAddr: "alice@example.com", Subject: "No token needed"}
		if err := ValidateEmail(e, true, policy); err != nil {
			t.Errorf("relaxed mode: known sender should pass: %v", err)
		}
	})

	t.Run("unknown_sender_rejected", func(t *testing.T) {
		e := &ParsedEmail{SenderAddr: "random@example.com", Subject: "No token"}
		if err := ValidateEmail(e, false, policy); err == nil {
			t.Fatal("relaxed mode: unknown sender should still be rejected")
		}
	})
}

func TestValidateEmail_SizeLimits(t *testing.T) {
	policy := &Policy{
		Mode:          ModeRelaxed,
		TokenRequired: false,
		Limits:        Limits{MaxEmailSizeMB: 1, MaxAttachments: 2, MaxAttachSizeMB: 1},
	}

	t.Run("oversized_email", func(t *testing.T) {
		e := &ParsedEmail{
			SenderAddr:    "alice@example.com",
			BodySizeBytes: 2 * 1024 * 1024, // 2 MB > 1 MB limit
		}
		err := ValidateEmail(e, true, policy)
		if err == nil {
			t.Fatal("expected error for oversized email")
		}
		ve := err.(*ValidationError)
		if ve.Code != "email_too_large" {
			t.Errorf("expected email_too_large, got %s", ve.Code)
		}
	})

	t.Run("too_many_attachments", func(t *testing.T) {
		e := &ParsedEmail{
			SenderAddr: "alice@example.com",
			Attachments: []AttachmentMeta{
				{Filename: "a.pdf", SizeBytes: 100},
				{Filename: "b.pdf", SizeBytes: 100},
				{Filename: "c.pdf", SizeBytes: 100}, // > limit of 2
			},
		}
		err := ValidateEmail(e, true, policy)
		if err == nil {
			t.Fatal("expected error for too many attachments")
		}
		ve := err.(*ValidationError)
		if ve.Code != "too_many_attachments" {
			t.Errorf("expected too_many_attachments, got %s", ve.Code)
		}
	})

	t.Run("oversized_attachment", func(t *testing.T) {
		e := &ParsedEmail{
			SenderAddr: "alice@example.com",
			Attachments: []AttachmentMeta{
				{Filename: "big.pdf", SizeBytes: 2 * 1024 * 1024}, // 2 MB > 1 MB limit
			},
		}
		err := ValidateEmail(e, true, policy)
		if err == nil {
			t.Fatal("expected error for oversized attachment")
		}
		ve := err.(*ValidationError)
		if ve.Code != "attachment_too_large" {
			t.Errorf("expected attachment_too_large, got %s", ve.Code)
		}
	})
}

func TestExtractToken_Header(t *testing.T) {
	e := &ParsedEmail{
		Subject: "No subject token",
		Headers: map[string]string{
			"x-emailstore-auth": "headertoken",
		},
	}
	got := ExtractToken(e, TokenInHeader)
	if got != "headertoken" {
		t.Errorf("expected headertoken, got %q", got)
	}
}

func TestDefaultPolicy_AllowsWithSenderOnly(t *testing.T) {
	// Default policy is relaxed — should accept known sender without any token
	policy := DefaultPolicy()
	if policy.Mode != ModeRelaxed {
		t.Errorf("DefaultPolicy mode = %s, want relaxed", policy.Mode)
	}
	if policy.TokenRequired {
		t.Error("DefaultPolicy should not require token by default")
	}
	e := &ParsedEmail{
		SenderAddr: "alice@example.com",
		Subject:    "Just a plain email, no token",
	}
	if err := ValidateEmail(e, true, policy); err != nil {
		t.Errorf("default policy should accept known sender: %v", err)
	}
}

func TestDefaultPolicy_RejectsUnknownSender(t *testing.T) {
	policy := DefaultPolicy()
	e := &ParsedEmail{
		SenderAddr: "unknown@attacker.com",
		Subject:    "Spam",
	}
	if err := ValidateEmail(e, false, policy); err == nil {
		t.Error("default policy should still reject unknown senders")
	}
}
