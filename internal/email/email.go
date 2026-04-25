package email

import (
	"database/sql"
	"strings"
	"time"
)

type Email struct {
	ID          int64
	MessageID   string
	CategoryID  sql.NullInt64
	SenderEmail string
	SenderName  string
	Subject     string
	BodyText    string
	BodyHTML    string
	ReceivedAt  time.Time
	Read        bool
	Attachments []Attachment
}

type Attachment struct {
	ID         int64
	EmailID    int64
	Filename   string
	MIMEType   string
	Size       int64
	StoredPath string
}

type Category struct {
	ID    int64
	Name  string
	Slug  string
	Color string
}

func Save(db *sql.DB, e *Email) (int64, error) {
	res, err := db.Exec(`
		INSERT INTO emails
			(message_id, category_id, sender_email, sender_name, subject, body_text, body_html, received_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(message_id) DO NOTHING`,
		e.MessageID,
		nullInt64(e.CategoryID),
		e.SenderEmail,
		e.SenderName,
		e.Subject,
		e.BodyText,
		e.BodyHTML,
		e.ReceivedAt.Unix(),
	)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	// ON CONFLICT DO NOTHING returns id=0 — look up the existing row
	if id == 0 {
		err = db.QueryRow(`SELECT id FROM emails WHERE message_id = ?`, e.MessageID).Scan(&id)
	}
	return id, err
}

func SaveAttachment(db *sql.DB, a *Attachment) error {
	_, err := db.Exec(`
		INSERT INTO attachments (email_id, filename, mime_type, size, stored_path)
		VALUES (?, ?, ?, ?, ?)`,
		a.EmailID, a.Filename, a.MIMEType, a.Size, a.StoredPath,
	)
	return err
}

func Exists(db *sql.DB, messageID string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(1) FROM emails WHERE message_id = ?`, messageID).Scan(&n)
	return n > 0, err
}

func List(db *sql.DB, categoryID int64, limit, offset int) ([]*Email, error) {
	query := `
		SELECT id, message_id, category_id, sender_email, sender_name, subject, received_at, read
		FROM emails`
	args := []any{}
	if categoryID > 0 {
		query += ` WHERE category_id = ?`
		args = append(args, categoryID)
	}
	query += ` ORDER BY received_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEmails(rows)
}

func Get(db *sql.DB, id int64) (*Email, error) {
	e := &Email{}
	var recvUnix int64
	var read int
	err := db.QueryRow(`
		SELECT id, message_id, category_id, sender_email, sender_name,
		       subject, body_text, body_html, received_at, read
		FROM emails WHERE id = ?`, id).Scan(
		&e.ID, &e.MessageID, &e.CategoryID,
		&e.SenderEmail, &e.SenderName,
		&e.Subject, &e.BodyText, &e.BodyHTML,
		&recvUnix, &read,
	)
	if err != nil {
		return nil, err
	}
	e.ReceivedAt = time.Unix(recvUnix, 0)
	e.Read = read == 1

	atts, err := getAttachments(db, id)
	if err != nil {
		return nil, err
	}
	e.Attachments = atts
	return e, nil
}

func MarkRead(db *sql.DB, id int64) error {
	_, err := db.Exec(`UPDATE emails SET read = 1 WHERE id = ?`, id)
	return err
}

// Delete removes an email and all its attachments from the database.
// Attachment files on disk must be removed separately by the caller.
func Delete(db *sql.DB, id int64) error {
	_, err := db.Exec(`DELETE FROM emails WHERE id = ?`, id)
	return err
}

// GetAttachmentPaths returns the stored file paths for all attachments of an email.
func GetAttachmentPaths(db *sql.DB, emailID int64) ([]string, error) {
	rows, err := db.Query(`SELECT stored_path FROM attachments WHERE email_id = ?`, emailID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var paths []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		paths = append(paths, p)
	}
	return paths, rows.Err()
}

// InboxCategoryID returns the ID of the category with slug "inbox", or 0 if not found.
func InboxCategoryID(db *sql.DB) int64 {
	cat, err := CategoryBySlug(db, "inbox")
	if err != nil {
		return 0
	}
	return cat.ID
}

func SetCategory(db *sql.DB, emailID, categoryID int64) error {
	_, err := db.Exec(`UPDATE emails SET category_id = ? WHERE id = ?`, categoryID, emailID)
	return err
}

func ListCategories(db *sql.DB) ([]*Category, error) {
	rows, err := db.Query(`SELECT id, name, slug, color FROM categories ORDER BY CASE slug WHEN 'inbox' THEN 0 ELSE 1 END, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cats []*Category
	for rows.Next() {
		c := &Category{}
		if err := rows.Scan(&c.ID, &c.Name, &c.Slug, &c.Color); err != nil {
			return nil, err
		}
		cats = append(cats, c)
	}
	return cats, rows.Err()
}

func CategoryBySlug(db *sql.DB, slug string) (*Category, error) {
	c := &Category{}
	err := db.QueryRow(`SELECT id, name, slug, color FROM categories WHERE slug = ?`, slug).
		Scan(&c.ID, &c.Name, &c.Slug, &c.Color)
	return c, err
}

// MatchCategory checks if a subject matches any category rule.
// Subject line convention: [category-slug] rest of subject
func MatchCategory(db *sql.DB, subject string) (int64, bool) {
	subject = strings.ToLower(subject)

	rows, err := db.Query(`
		SELECT cr.category_id, cr.pattern
		FROM category_rules cr`)
	if err != nil {
		return 0, false
	}
	defer rows.Close()

	for rows.Next() {
		var catID int64
		var pattern string
		if err := rows.Scan(&catID, &pattern); err != nil {
			continue
		}
		if strings.Contains(subject, strings.ToLower(pattern)) {
			return catID, true
		}
	}

	// Check bracket syntax: [slug]
	if strings.HasPrefix(subject, "[") {
		end := strings.Index(subject, "]")
		if end > 1 {
			slug := subject[1:end]
			cat, err := CategoryBySlug(db, slug)
			if err == nil {
				return cat.ID, true
			}
		}
	}

	return 0, false
}

func IsAllowedSender(db *sql.DB, email string) (bool, error) {
	var n int
	err := db.QueryRow(
		`SELECT COUNT(1) FROM allowed_senders WHERE LOWER(email) = LOWER(?)`, email,
	).Scan(&n)
	return n > 0, err
}

func CountByCategory(db *sql.DB) (map[int64]int, error) {
	rows, err := db.Query(`SELECT category_id, COUNT(*) FROM emails GROUP BY category_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make(map[int64]int)
	for rows.Next() {
		var catID sql.NullInt64
		var n int
		if err := rows.Scan(&catID, &n); err != nil {
			return nil, err
		}
		if catID.Valid {
			counts[catID.Int64] = n
		}
	}
	return counts, rows.Err()
}

func getAttachments(db *sql.DB, emailID int64) ([]Attachment, error) {
	rows, err := db.Query(`
		SELECT id, email_id, filename, mime_type, size, stored_path
		FROM attachments WHERE email_id = ?`, emailID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var atts []Attachment
	for rows.Next() {
		var a Attachment
		if err := rows.Scan(&a.ID, &a.EmailID, &a.Filename, &a.MIMEType, &a.Size, &a.StoredPath); err != nil {
			return nil, err
		}
		atts = append(atts, a)
	}
	return atts, rows.Err()
}

func scanEmails(rows *sql.Rows) ([]*Email, error) {
	var emails []*Email
	for rows.Next() {
		e := &Email{}
		var recvUnix int64
		var read int
		if err := rows.Scan(
			&e.ID, &e.MessageID, &e.CategoryID,
			&e.SenderEmail, &e.SenderName, &e.Subject,
			&recvUnix, &read,
		); err != nil {
			return nil, err
		}
		e.ReceivedAt = time.Unix(recvUnix, 0)
		e.Read = read == 1
		emails = append(emails, e)
	}
	return emails, rows.Err()
}

func nullInt64(v sql.NullInt64) any {
	if v.Valid {
		return v.Int64
	}
	return nil
}
