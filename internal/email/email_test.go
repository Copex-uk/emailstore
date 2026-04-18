package email

import (
	"database/sql"
	"testing"
	"time"

	"emailstore/internal/testhelper"
)

func newEmail(msgID, sender, subject string) *Email {
	return &Email{
		MessageID:   msgID,
		SenderEmail: sender,
		SenderName:  "Test Sender",
		Subject:     subject,
		BodyText:    "Hello world",
		BodyHTML:    "<p>Hello world</p>",
		ReceivedAt:  time.Now(),
	}
}

// ── Save / Exists / Get ───────────────────────────────────────────────────

func TestSave_And_Exists(t *testing.T) {
	db := testhelper.NewDB(t)

	e := newEmail("msg-001", "alice@example.com", "Test subject")
	id, err := Save(db, e)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if id == 0 {
		t.Fatal("Save returned id=0")
	}

	exists, err := Exists(db, "msg-001")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Error("Exists should return true after Save")
	}

	exists, _ = Exists(db, "msg-999")
	if exists {
		t.Error("Exists should return false for unknown message ID")
	}
}

func TestSave_Duplicate_ReturnsExistingID(t *testing.T) {
	db := testhelper.NewDB(t)

	e := newEmail("msg-dup", "alice@example.com", "Duplicate")
	id1, err := Save(db, e)
	if err != nil {
		t.Fatalf("first Save: %v", err)
	}
	id2, err := Save(db, e)
	if err != nil {
		t.Fatalf("second Save: %v", err)
	}
	if id1 != id2 {
		t.Errorf("duplicate save: expected same ID %d, got %d", id1, id2)
	}
}

func TestGet(t *testing.T) {
	db := testhelper.NewDB(t)

	e := newEmail("msg-get", "bob@example.com", "Get me")
	id, _ := Save(db, e)

	got, err := Get(db, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SenderEmail != "bob@example.com" {
		t.Errorf("SenderEmail = %q, want bob@example.com", got.SenderEmail)
	}
	if got.Subject != "Get me" {
		t.Errorf("Subject = %q, want %q", got.Subject, "Get me")
	}
	if got.BodyText != "Hello world" {
		t.Errorf("BodyText = %q, want Hello world", got.BodyText)
	}
}

func TestGet_NotFound(t *testing.T) {
	db := testhelper.NewDB(t)
	_, err := Get(db, 99999)
	if err == nil {
		t.Error("Get non-existent ID should return error")
	}
}

// ── MarkRead ──────────────────────────────────────────────────────────────

func TestMarkRead(t *testing.T) {
	db := testhelper.NewDB(t)

	e := newEmail("msg-read", "alice@example.com", "Read me")
	id, _ := Save(db, e)

	got, _ := Get(db, id)
	if got.Read {
		t.Error("email should start as unread")
	}

	if err := MarkRead(db, id); err != nil {
		t.Fatalf("MarkRead: %v", err)
	}

	got, _ = Get(db, id)
	if !got.Read {
		t.Error("email should be read after MarkRead")
	}
}

// ── List ──────────────────────────────────────────────────────────────────

func TestList_AllEmails(t *testing.T) {
	db := testhelper.NewDB(t)

	for i := range 3 {
		Save(db, newEmail("msg-list-"+string(rune('A'+i)), "a@b.com", "Subject"))
	}

	emails, err := List(db, 0, 10, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(emails) != 3 {
		t.Errorf("List returned %d emails, want 3", len(emails))
	}
}

func TestList_Pagination(t *testing.T) {
	db := testhelper.NewDB(t)

	for i := range 5 {
		Save(db, newEmail("msg-page-"+string(rune('A'+i)), "a@b.com", "Subject"))
	}

	page1, _ := List(db, 0, 3, 0)
	page2, _ := List(db, 0, 3, 3)

	if len(page1) != 3 {
		t.Errorf("page1: want 3, got %d", len(page1))
	}
	if len(page2) != 2 {
		t.Errorf("page2: want 2, got %d", len(page2))
	}
}

// ── SetCategory ───────────────────────────────────────────────────────────

func TestSetCategory(t *testing.T) {
	db := testhelper.NewDB(t)

	// Insert a category directly
	var catID int64
	db.QueryRow(`INSERT INTO categories (name, slug, color) VALUES ('Work','work','#000') RETURNING id`).Scan(&catID)

	e := newEmail("msg-cat", "a@b.com", "Categorise me")
	id, _ := Save(db, e)

	if err := SetCategory(db, id, catID); err != nil {
		t.Fatalf("SetCategory: %v", err)
	}

	got, _ := Get(db, id)
	if !got.CategoryID.Valid || got.CategoryID.Int64 != catID {
		t.Errorf("CategoryID = %v, want %d", got.CategoryID, catID)
	}
}

// ── Attachments ───────────────────────────────────────────────────────────

func TestSaveAttachment(t *testing.T) {
	db := testhelper.NewDB(t)

	e := newEmail("msg-att", "a@b.com", "With attachment")
	emailID, _ := Save(db, e)

	att := &Attachment{
		EmailID:    emailID,
		Filename:   "document.pdf",
		MIMEType:   "application/pdf",
		Size:       1024,
		StoredPath: "/app/data/attachments/1/document.pdf",
	}
	if err := SaveAttachment(db, att); err != nil {
		t.Fatalf("SaveAttachment: %v", err)
	}

	got, _ := Get(db, emailID)
	if len(got.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(got.Attachments))
	}
	if got.Attachments[0].Filename != "document.pdf" {
		t.Errorf("Filename = %q, want document.pdf", got.Attachments[0].Filename)
	}
	if got.Attachments[0].Size != 1024 {
		t.Errorf("Size = %d, want 1024", got.Attachments[0].Size)
	}
}

// ── Categories ────────────────────────────────────────────────────────────

func TestListCategories(t *testing.T) {
	db := testhelper.NewDB(t)

	db.Exec(`INSERT INTO categories (name, slug, color) VALUES ('Work','work','#00f'),('Personal','personal','#0f0')`)

	cats, err := ListCategories(db)
	if err != nil {
		t.Fatalf("ListCategories: %v", err)
	}
	if len(cats) != 2 {
		t.Errorf("want 2 categories, got %d", len(cats))
	}
}

func TestCategoryBySlug(t *testing.T) {
	db := testhelper.NewDB(t)
	db.Exec(`INSERT INTO categories (name, slug, color) VALUES ('Finance','finance','#ff0')`)

	cat, err := CategoryBySlug(db, "finance")
	if err != nil {
		t.Fatalf("CategoryBySlug: %v", err)
	}
	if cat.Name != "Finance" {
		t.Errorf("Name = %q, want Finance", cat.Name)
	}
}

func TestCategoryBySlug_NotFound(t *testing.T) {
	db := testhelper.NewDB(t)
	_, err := CategoryBySlug(db, "nonexistent")
	if err == nil {
		t.Error("expected error for unknown slug")
	}
}

// ── MatchCategory ─────────────────────────────────────────────────────────

func TestMatchCategory_BracketSyntax(t *testing.T) {
	db := testhelper.NewDB(t)
	var catID int64
	db.QueryRow(`INSERT INTO categories (name, slug, color) VALUES ('Invoices','invoices','#000') RETURNING id`).Scan(&catID)

	id, ok := MatchCategory(db, "[invoices] Q1 receipt")
	if !ok {
		t.Fatal("MatchCategory should match [invoices] prefix")
	}
	if id != catID {
		t.Errorf("MatchCategory returned id=%d, want %d", id, catID)
	}
}

func TestMatchCategory_KeywordRule(t *testing.T) {
	db := testhelper.NewDB(t)
	var catID int64
	db.QueryRow(`INSERT INTO categories (name, slug, color) VALUES ('Finance','finance','#000') RETURNING id`).Scan(&catID)
	db.Exec(`INSERT INTO category_rules (category_id, pattern) VALUES (?, 'receipt')`, catID)

	id, ok := MatchCategory(db, "Your receipt from Amazon")
	if !ok {
		t.Fatal("MatchCategory should match keyword rule")
	}
	if id != catID {
		t.Errorf("MatchCategory returned id=%d, want %d", id, catID)
	}
}

func TestMatchCategory_NoMatch(t *testing.T) {
	db := testhelper.NewDB(t)
	_, ok := MatchCategory(db, "No category matches this subject")
	if ok {
		t.Error("MatchCategory should return false for unmatched subject")
	}
}

// ── IsAllowedSender ───────────────────────────────────────────────────────

func TestIsAllowedSender(t *testing.T) {
	db := testhelper.NewDB(t)
	db.Exec(`INSERT INTO allowed_senders (email, name) VALUES ('alice@example.com', 'Alice')`)

	allowed, err := IsAllowedSender(db, "alice@example.com")
	if err != nil {
		t.Fatalf("IsAllowedSender: %v", err)
	}
	if !allowed {
		t.Error("alice@example.com should be allowed")
	}

	// Case-insensitive check
	allowed, _ = IsAllowedSender(db, "ALICE@EXAMPLE.COM")
	if !allowed {
		t.Error("IsAllowedSender should be case-insensitive")
	}

	// Unknown sender
	allowed, _ = IsAllowedSender(db, "evil@attacker.com")
	if allowed {
		t.Error("unknown sender should not be allowed")
	}
}

// ── CountByCategory ───────────────────────────────────────────────────────

func TestCountByCategory(t *testing.T) {
	db := testhelper.NewDB(t)

	var catID int64
	db.QueryRow(`INSERT INTO categories (name, slug, color) VALUES ('Work','work','#000') RETURNING id`).Scan(&catID)

	for i := range 3 {
		e := newEmail("msg-count-"+string(rune('A'+i)), "a@b.com", "Work email")
		id, _ := Save(db, e)
		db.Exec(`UPDATE emails SET category_id = ? WHERE id = ?`, catID, id)
	}

	counts, err := CountByCategory(db)
	if err != nil {
		t.Fatalf("CountByCategory: %v", err)
	}
	if counts[catID] != 3 {
		t.Errorf("CountByCategory[%d] = %d, want 3", catID, counts[catID])
	}
}

// ── nullInt64 helper ──────────────────────────────────────────────────────

func TestNullInt64(t *testing.T) {
	valid := sql.NullInt64{Int64: 42, Valid: true}
	if nullInt64(valid) != int64(42) {
		t.Error("nullInt64 valid should return int64")
	}

	invalid := sql.NullInt64{Valid: false}
	if nullInt64(invalid) != nil {
		t.Error("nullInt64 invalid should return nil")
	}
}
