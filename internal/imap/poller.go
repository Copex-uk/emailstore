package imap

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"emailstore/internal/db"
	"emailstore/internal/email"
	"emailstore/internal/security"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	gomessage "github.com/emersion/go-message"
	gomail "github.com/emersion/go-message/mail"
)

// MaxEmailsPerRun caps how many emails are processed in a single poll.
// Prevents a flooded mailbox from holding up the poller indefinitely.
const MaxEmailsPerRun = 50

type Config struct {
	Host      string
	Port      string
	User      string
	Password  string
	TLS       bool
	StartTLS  bool
	Debug     bool
	AttachDir string
}

func LoadConfig(sqldb *sql.DB, attachDir string) (*Config, error) {
	settings, err := db.SettingGetAll(sqldb)
	if err != nil {
		return nil, err
	}
	c := &Config{
		Host:      settings[db.KeyIMAPHost],
		Port:      settings[db.KeyIMAPPort],
		User:      settings[db.KeyIMAPUser],
		Password:  settings[db.KeyIMAPPassword],
		TLS:       settings[db.KeyIMAPTLS] == "1",
		StartTLS:  settings[db.KeyIMAPStartTLS] == "1",
		Debug:     settings[db.KeyIMAPDebug] == "1",
		AttachDir: attachDir,
	}
	if c.Host == "" || c.User == "" {
		return nil, fmt.Errorf("imap not configured")
	}
	if c.Port == "" {
		if c.TLS {
			c.Port = "993"
		} else {
			c.Port = "143"
		}
	}
	return c, nil
}

// normalisedAddr parses a raw RFC 5322 address and returns the lowercase
// email portion only. Display names and angle brackets are stripped.
func normalisedAddr(raw string) string {
	addr, err := mail.ParseAddress(raw)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(raw))
	}
	return strings.ToLower(addr.Address)
}

// deleteMessage marks a message \Deleted and immediately expunges it.
func deleteMessage(client *imapclient.Client, seqNum uint32) {
	seqSet := imap.SeqSetNum(seqNum)
	if err := client.Store(seqSet, &imap.StoreFlags{
		Op: imap.StoreFlagsAdd, Silent: true,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		log.Printf("event=delete_failed seq=%d err=%q", seqNum, err)
		return
	}
	if err := client.Expunge().Close(); err != nil {
		log.Printf("event=expunge_failed seq=%d err=%q", seqNum, err)
	}
}

// safeFilename returns a path inside attachDir that cannot escape via traversal.
func safeFilename(attachDir string, emailID int64, rawName string) (string, error) {
	if rawName == "" {
		rawName = "attachment"
	}
	base := filepath.Base(rawName)
	if base == "." || base == ".." || base == string(filepath.Separator) {
		base = "attachment"
	}
	dir := filepath.Join(attachDir, strconv.FormatInt(emailID, 10))
	dest := filepath.Join(dir, base)
	// Boundary check — dest must remain inside attachDir
	clean := filepath.Clean(attachDir) + string(filepath.Separator)
	if !strings.HasPrefix(dest, clean) {
		return "", fmt.Errorf("filename %q escapes attachment directory", rawName)
	}
	return dest, nil
}

func Poll(sqldb *sql.DB, attachDir string) error {
	cfg, err := LoadConfig(sqldb, attachDir)
	if err != nil {
		return fmt.Errorf("load imap config: %w", err)
	}

	// Load security policy fresh on every poll so settings changes apply immediately
	policy := security.LoadPolicy(sqldb)

	addr := cfg.Host + ":" + cfg.Port
	var client *imapclient.Client

	tlsCfg := &tls.Config{ServerName: cfg.Host}
	var debugWriter io.Writer
	if cfg.Debug {
		debugWriter = os.Stderr
	}
	clientOpts := &imapclient.Options{TLSConfig: tlsCfg, DebugWriter: debugWriter}

	switch {
	case cfg.TLS:
		client, err = imapclient.DialTLS(addr, clientOpts)
	case cfg.StartTLS:
		client, err = imapclient.DialStartTLS(addr, clientOpts)
	default:
		client, err = imapclient.DialInsecure(addr, &imapclient.Options{DebugWriter: debugWriter})
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer client.Close()

	if err := client.Login(cfg.User, cfg.Password).Wait(); err != nil {
		return fmt.Errorf("login %s: %w", cfg.User, err)
	}
	defer func() { client.Logout().Wait() }()

	if _, err = client.Select("INBOX", nil).Wait(); err != nil {
		return fmt.Errorf("select inbox: %w", err)
	}

	searchData, err := client.Search(&imap.SearchCriteria{
		NotFlag: []imap.Flag{imap.FlagSeen},
	}, nil).Wait()
	if err != nil {
		return fmt.Errorf("search: %w", err)
	}
	seqNums := searchData.AllSeqNums()
	if len(seqNums) == 0 {
		log.Printf("event=poll_complete accepted=0 rejected=0 reason=no_new_messages")
		return nil
	}

	// Cap per-run processing
	if len(seqNums) > MaxEmailsPerRun {
		log.Printf("event=poll_capped total=%d cap=%d", len(seqNums), MaxEmailsPerRun)
		seqNums = seqNums[:MaxEmailsPerRun]
	}

	fetchCmd := client.Fetch(imap.SeqSetNum(seqNums...), &imap.FetchOptions{
		UID:         true,
		Envelope:    true,
		BodySection: []*imap.FetchItemBodySection{{}},
	})
	defer fetchCmd.Close()

	accepted, rejected := 0, 0

	for {
		msg := fetchCmd.Next()
		if msg == nil {
			break
		}
		buf, err := msg.Collect()
		if err != nil {
			log.Printf("event=collect_error err=%q", err)
			continue
		}

		seqNum := buf.SeqNum
		env := buf.Envelope
		if env == nil {
			log.Printf("event=email_rejected reason=no_envelope seq=%d", seqNum)
			deleteMessage(client, seqNum)
			rejected++
			continue
		}

		// ── Normalise sender address ──────────────────────────────────────
		senderAddr := ""
		if len(env.From) > 0 {
			senderAddr = strings.ToLower(strings.TrimSpace(env.From[0].Addr()))
		}
		senderName := ""
		if len(env.From) > 0 {
			senderName = env.From[0].Name
		}

		// ── Duplicate check (cheap — before any body work) ────────────────
		msgID := env.MessageID
		if msgID == "" {
			msgID = fmt.Sprintf("generated-%d-%s", time.Now().UnixNano(), senderAddr)
		}
		if exists, _ := email.Exists(sqldb, msgID); exists {
			deleteMessage(client, seqNum)
			continue
		}

		// ── Get body bytes ────────────────────────────────────────────────
		var bodyBytes []byte
		for _, section := range buf.BodySection {
			bodyBytes = section.Bytes
			break
		}

		// ── Build ParsedEmail for validator ──────────────────────────────
		senderAllowed, _ := email.IsAllowedSender(sqldb, senderAddr)

		parsed := &security.ParsedEmail{
			SenderAddr:    senderAddr,
			Subject:       env.Subject,
			Headers:       map[string]string{},
			BodySizeBytes: int64(len(bodyBytes)),
		}
		// We don't parse headers at this stage to avoid unnecessary work;
		// header-based token extraction happens inside ValidateEmail via
		// the Headers map. Populate it only for the auth header.
		// (Full header parsing happens after validation passes.)

		// ── Security validation — BEFORE any MIME parsing ─────────────────
		if err := security.ValidateEmail(parsed, senderAllowed, policy); err != nil {
			ve := err.(*security.ValidationError)
			log.Printf("event=email_rejected reason=%s sender=%q subject=%q seq=%d ts=%s",
				ve.Code, senderAddr, env.Subject, seqNum, time.Now().Format(time.RFC3339))
			if policy.OnReject == "delete" {
				deleteMessage(client, seqNum)
			}
			rejected++
			continue
		}

		// ── Parse MIME (only for validated emails) ────────────────────────
		e, attachments, err := parseMessage(bodyBytes, msgID, senderAddr, senderName, policy)
		if err != nil {
			log.Printf("event=parse_error msg_id=%q err=%q", msgID, err)
			continue
		}

		// ── Category assignment ───────────────────────────────────────────
		if catID, ok := email.MatchCategory(sqldb, e.Subject); ok {
			e.CategoryID = sql.NullInt64{Int64: catID, Valid: true}
		}

		// ── Persist ───────────────────────────────────────────────────────
		emailID, err := email.Save(sqldb, e)
		if err != nil {
			log.Printf("event=save_error msg_id=%q err=%q", msgID, err)
			continue
		}
		for i := range attachments {
			if err := saveAttachment(sqldb, emailID, &attachments[i], attachDir, policy); err != nil {
				log.Printf("event=attachment_save_error email_id=%d err=%q", emailID, err)
			}
		}

		deleteMessage(client, seqNum)
		accepted++
		log.Printf("event=email_accepted sender=%q subject=%q email_id=%d ts=%s",
			senderAddr, e.Subject, emailID, time.Now().Format(time.RFC3339))
	}

	fetchCmd.Close()
	log.Printf("event=poll_complete accepted=%d rejected=%d", accepted, rejected)
	return nil
}

// StartPoller runs Poll in a background goroutine with context-aware shutdown
// and exponential backoff on consecutive errors.
func StartPoller(ctx context.Context, sqldb *sql.DB, attachDir string) {
	go func() {
		backoff := 30 * time.Second
		const maxBackoff = 30 * time.Minute

		for {
			select {
			case <-ctx.Done():
				log.Printf("event=poller_shutdown")
				return
			default:
			}

			if err := Poll(sqldb, attachDir); err != nil {
				log.Printf("event=poll_error err=%q backoff=%s", err, backoff)
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}

			backoff = 30 * time.Second
			intervalStr, _ := db.SettingGet(sqldb, db.KeyPollInterval)
			mins, _ := strconv.Atoi(intervalStr)
			if mins <= 0 {
				mins = 15
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(mins) * time.Minute):
			}
		}
	}()
}

type pendingAttachment struct {
	Filename     string
	OrigFilename string // kept for display, never used as a path
	MIMEType     string
	Data         []byte
}

func parseMessage(raw []byte, msgID, senderEmail, senderName string, policy *security.Policy) (*email.Email, []pendingAttachment, error) {
	mr, err := gomail.CreateReader(bytes.NewReader(raw))
	if err != nil && !gomessage.IsUnknownCharset(err) {
		return nil, nil, err
	}

	e := &email.Email{
		MessageID:   msgID,
		SenderEmail: senderEmail,
		SenderName:  senderName,
		ReceivedAt:  time.Now(),
	}

	if mr != nil {
		if subj, err := mr.Header.Subject(); err == nil {
			e.Subject = subj
		}
		if date, err := mr.Header.Date(); err == nil {
			e.ReceivedAt = date
		}
	}

	var attachments []pendingAttachment
	if mr == nil {
		return e, attachments, nil
	}

	maxAttachBytes := policy.Limits.MaxAttachSizeMB * 1024 * 1024

	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}

		switch h := part.Header.(type) {
		case *gomail.InlineHeader:
			ct, _, _ := h.ContentType()
			body, err := io.ReadAll(part.Body)
			if err != nil {
				continue
			}
			switch {
			case strings.HasPrefix(ct, "text/plain") && e.BodyText == "":
				e.BodyText = string(body)
			case strings.HasPrefix(ct, "text/html") && e.BodyHTML == "":
				e.BodyHTML = string(body)
			}

		case *gomail.AttachmentHeader:
			if policy.Limits.MaxAttachments > 0 && len(attachments) >= policy.Limits.MaxAttachments {
				log.Printf("event=attachment_skipped reason=count_limit msg_id=%q", msgID)
				continue
			}
			origFilename, _ := h.Filename()
			if origFilename == "" {
				origFilename = "attachment"
			}
			data, err := io.ReadAll(part.Body)
			if err != nil {
				continue
			}
			if maxAttachBytes > 0 && int64(len(data)) > maxAttachBytes {
				log.Printf("event=attachment_skipped reason=size_limit filename=%q size=%d msg_id=%q",
					origFilename, len(data), msgID)
				continue
			}
			// Detect actual MIME type from content — never trust declared type
			detectedMIME := security.DetectMIMEType(data)
			attachments = append(attachments, pendingAttachment{
				Filename:     origFilename,
				OrigFilename: origFilename,
				MIMEType:     detectedMIME,
				Data:         data,
			})
		}
	}

	return e, attachments, nil
}

func saveAttachment(sqldb *sql.DB, emailID int64, att *pendingAttachment, attachDir string, policy *security.Policy) error {
	dir := filepath.Join(attachDir, strconv.FormatInt(emailID, 10))
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	dest, err := safeFilename(attachDir, emailID, att.Filename)
	if err != nil {
		return fmt.Errorf("unsafe filename: %w", err)
	}

	// Avoid collision with a nanosecond suffix
	if _, err := os.Stat(dest); err == nil {
		ext := filepath.Ext(dest)
		base := strings.TrimSuffix(dest, ext)
		dest = fmt.Sprintf("%s_%d%s", base, time.Now().UnixNano(), ext)
	}

	if err := os.WriteFile(dest, att.Data, 0640); err != nil {
		return err
	}

	return email.SaveAttachment(sqldb, &email.Attachment{
		EmailID:    emailID,
		Filename:   att.OrigFilename,          // display name for the UI
		MIMEType:   att.MIMEType,              // sniffed, not declared
		Size:       int64(len(att.Data)),
		StoredPath: dest,
	})
}
