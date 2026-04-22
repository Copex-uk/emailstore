// Package imap implements IMAP mailbox polling for EmailStore.
//
// Architecture: two-pass fetch.
//   Pass 1 – fetch envelopes for all messages via Collect() into memory,
//             close the FetchCommand, THEN validate/delete rejects.
//   Pass 2 – for each validated candidate, open a new FetchCommand for
//             the body alone, Collect() it, close the command, then
//             parse/store/delete.
//
// This order is required because Dovecot (IMAP4rev1) rejects Expunge while
// a FetchCommand is still open ("command out of order"). Using Collect()
// ensures the command is fully consumed and implicitly closed before any
// Store/Expunge is sent.
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

const MaxEmailsPerRun = 50

// ── Config ─────────────────────────────────────────────────────────────────

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
		return nil, fmt.Errorf("load settings: %w", err)
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

// ── Helpers ────────────────────────────────────────────────────────────────

func normalisedAddr(raw string) string {
	addr, err := mail.ParseAddress(raw)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(raw))
	}
	return strings.ToLower(addr.Address)
}

func safeFilename(attachDir string, emailID int64, rawName string) (string, error) {
	if rawName == "" {
		rawName = "attachment"
	}
	base := filepath.Base(rawName)
	if base == "." || base == ".." || base == string(filepath.Separator) {
		base = "attachment"
	}
	dir := filepath.Join(attachDir, strconv.FormatInt(emailID, 10))
	dest := filepath.Clean(filepath.Join(dir, base))
	boundary := filepath.Clean(attachDir) + string(filepath.Separator)
	if !strings.HasPrefix(dest, boundary) {
		return "", fmt.Errorf("filename %q escapes attachment directory", rawName)
	}
	return dest, nil
}

// deleteMsg flags a message \Deleted and expunges it.
// MUST only be called when no FetchCommand is open on this connection.
func deleteMsg(c *imapclient.Client, seqNum uint32) {
	log.Printf("event=delete_message seq=%d", seqNum)
	if err := c.Store(imap.SeqSetNum(seqNum), &imap.StoreFlags{
		Op: imap.StoreFlagsAdd, Silent: true,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		log.Printf("event=delete_flag_error seq=%d err=%v", seqNum, err)
		return
	}
	if err := c.Expunge().Close(); err != nil {
		log.Printf("event=expunge_error seq=%d err=%v", seqNum, err)
	}
}

// ── Poll ───────────────────────────────────────────────────────────────────

type candidate struct {
	seqNum     uint32
	msgID      string
	senderAddr string
	senderName string
	subject    string
}

func Poll(sqldb *sql.DB, attachDir string) error {
	cfg, err := LoadConfig(sqldb, attachDir)
	if err != nil {
		return fmt.Errorf("poll: %w", err)
	}

	policy := security.LoadPolicy(sqldb)
	log.Printf("event=poll_start mode=%s require_token=%v tokens_configured=%v",
		policy.Mode, policy.TokenRequired, len(policy.Tokens) > 0)

	// ── Connect ────────────────────────────────────────────────────────
	addr := cfg.Host + ":" + cfg.Port
	tlsCfg := &tls.Config{ServerName: cfg.Host}

	var dbgWriter io.Writer
	if cfg.Debug {
		dbgWriter = os.Stderr
	}

	var c *imapclient.Client
	switch {
	case cfg.TLS:
		log.Printf("event=dial_tls addr=%s", addr)
		c, err = imapclient.DialTLS(addr, &imapclient.Options{TLSConfig: tlsCfg, DebugWriter: dbgWriter})
	case cfg.StartTLS:
		log.Printf("event=dial_starttls addr=%s", addr)
		c, err = imapclient.DialStartTLS(addr, &imapclient.Options{TLSConfig: tlsCfg, DebugWriter: dbgWriter})
	default:
		log.Printf("event=dial_plain addr=%s", addr)
		c, err = imapclient.DialInsecure(addr, &imapclient.Options{DebugWriter: dbgWriter})
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer func() {
		log.Printf("event=connection_close")
		c.Close()
	}()

	// ── Login ──────────────────────────────────────────────────────────
	log.Printf("event=login user=%s", cfg.User)
	if err := c.Login(cfg.User, cfg.Password).Wait(); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	defer func() {
		if logoutErr := c.Logout().Wait(); logoutErr != nil {
			log.Printf("event=logout_error err=%v", logoutErr)
		}
	}()

	// ── SELECT INBOX ───────────────────────────────────────────────────
	// NumMessages from SELECT avoids the SEARCH command entirely.
	// Bare SEARCH with no arguments is rejected by Dovecot.
	log.Printf("event=select_inbox")
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		return fmt.Errorf("SELECT INBOX: %w", err)
	}
	total := selectData.NumMessages
	log.Printf("event=inbox_selected total=%d", total)

	if total == 0 {
		log.Printf("event=poll_complete accepted=0 rejected=0 reason=mailbox_empty")
		return nil
	}

	fetchCount := total
	if fetchCount > uint32(MaxEmailsPerRun) {
		log.Printf("event=poll_capped total=%d cap=%d", fetchCount, MaxEmailsPerRun)
		fetchCount = uint32(MaxEmailsPerRun)
	}

	seqSet := imap.SeqSet{}
	seqSet.AddRange(1, fetchCount)

	// ── PASS 1: collect ALL envelopes into memory, then close ──────────
	// Using .Collect() on the FetchCommand reads every message and closes
	// the command automatically before we return. This is essential:
	// deleteMsg (which calls Expunge) must not run while a FetchCommand
	// is open or Dovecot will return a protocol error.
	log.Printf("event=pass1_fetch_envelopes seq_range=1:%d", fetchCount)
	envBufs, err := c.Fetch(seqSet, &imap.FetchOptions{
		Envelope: true,
		UID:      true,
	}).Collect()
	if err != nil {
		return fmt.Errorf("FETCH envelopes: %w", err)
	}
	log.Printf("event=pass1_complete received=%d", len(envBufs))

	// Evaluate each envelope: build candidates list and reject/duplicate list.
	var candidates []candidate
	var deleteSeqs []uint32

	for _, buf := range envBufs {
		seqNum := buf.SeqNum
		env := buf.Envelope

		if env == nil {
			log.Printf("event=skip seq=%d reason=no_envelope", seqNum)
			deleteSeqs = append(deleteSeqs, seqNum)
			continue
		}

		senderAddr := ""
		senderName := ""
		if len(env.From) > 0 {
			senderAddr = strings.ToLower(strings.TrimSpace(env.From[0].Addr()))
			senderName = env.From[0].Name
		}
		log.Printf("event=envelope seq=%d sender=%q subject=%q msg_id=%q",
			seqNum, senderAddr, env.Subject, env.MessageID)

		msgID := env.MessageID
		if msgID == "" {
			msgID = fmt.Sprintf("generated-%d-%s", time.Now().UnixNano(), senderAddr)
		}

		// Duplicate check via message-ID
		if exists, dbErr := email.Exists(sqldb, msgID); dbErr != nil {
			log.Printf("event=duplicate_check_error seq=%d err=%v", seqNum, dbErr)
		} else if exists {
			log.Printf("event=skip seq=%d reason=duplicate msg_id=%q", seqNum, msgID)
			deleteSeqs = append(deleteSeqs, seqNum)
			continue
		}

		// Security policy check
		senderAllowed, senderErr := email.IsAllowedSender(sqldb, senderAddr)
		if senderErr != nil {
			log.Printf("event=sender_check_error seq=%d err=%v", seqNum, senderErr)
		}
		parsed := &security.ParsedEmail{
			SenderAddr: senderAddr,
			Subject:    env.Subject,
			Headers:    map[string]string{},
		}
		if valErr := security.ValidateEmail(parsed, senderAllowed, policy); valErr != nil {
			ve := valErr.(*security.ValidationError)
			log.Printf("event=skip seq=%d reason=policy code=%s sender=%q subject=%q",
				seqNum, ve.Code, senderAddr, env.Subject)
			deleteSeqs = append(deleteSeqs, seqNum)
			continue
		}

		log.Printf("event=candidate seq=%d sender=%q subject=%q", seqNum, senderAddr, env.Subject)
		candidates = append(candidates, candidate{
			seqNum:     seqNum,
			msgID:      msgID,
			senderAddr: senderAddr,
			senderName: senderName,
			subject:    env.Subject,
		})
	}

	// Delete rejects now — envelope FetchCommand is fully closed via Collect().
	for _, seq := range deleteSeqs {
		deleteMsg(c, seq)
	}

	if len(candidates) == 0 {
		log.Printf("event=poll_complete accepted=0 rejected=%d reason=no_valid_candidates",
			len(deleteSeqs))
		return nil
	}
	log.Printf("event=pass2_start candidates=%d", len(candidates))

	// ── PASS 2: fetch body for each candidate individually ─────────────
	accepted, rejected := 0, 0

	for _, cand := range candidates {
		log.Printf("event=fetch_body seq=%d msg_id=%q", cand.seqNum, cand.msgID)

		// One Collect() per message — closes the command before deleteMsg.
		bodyBufs, fetchErr := c.Fetch(
			imap.SeqSetNum(cand.seqNum),
			&imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{}}},
		).Collect()

		if fetchErr != nil {
			log.Printf("event=fetch_body_error seq=%d msg_id=%q err=%v",
				cand.seqNum, cand.msgID, fetchErr)
			rejected++
			continue
		}
		if len(bodyBufs) == 0 {
			log.Printf("event=skip seq=%d msg_id=%q reason=empty_fetch_result", cand.seqNum, cand.msgID)
			deleteMsg(c, cand.seqNum)
			rejected++
			continue
		}

		// Extract body bytes from BodySection slice (beta.5+ stores as slice).
		var bodyBytes []byte
		for _, section := range bodyBufs[0].BodySection {
			if section.Bytes != nil {
				bodyBytes = section.Bytes
				break
			}
		}
		if bodyBytes == nil {
			log.Printf("event=skip seq=%d msg_id=%q reason=nil_body_section", cand.seqNum, cand.msgID)
			deleteMsg(c, cand.seqNum)
			rejected++
			continue
		}
		log.Printf("event=body_received seq=%d msg_id=%q bytes=%d",
			cand.seqNum, cand.msgID, len(bodyBytes))

		// Parse MIME
		e, attachments, parseErr := parseMessage(
			bodyBytes, cand.msgID, cand.senderAddr, cand.senderName, policy,
		)
		if parseErr != nil {
			log.Printf("event=parse_error seq=%d msg_id=%q err=%v",
				cand.seqNum, cand.msgID, parseErr)
			deleteMsg(c, cand.seqNum)
			rejected++
			continue
		}

		// Category
		if catID, ok := email.MatchCategory(sqldb, e.Subject); ok {
			e.CategoryID = sql.NullInt64{Int64: catID, Valid: true}
		} else if inboxID := email.InboxCategoryID(sqldb); inboxID > 0 {
			e.CategoryID = sql.NullInt64{Int64: inboxID, Valid: true}
		}

		// Persist
		emailID, saveErr := email.Save(sqldb, e)
		if saveErr != nil {
			log.Printf("event=save_error seq=%d msg_id=%q err=%v",
				cand.seqNum, cand.msgID, saveErr)
			rejected++
			continue
		}

		for i := range attachments {
			if attErr := saveAttachment(sqldb, emailID, &attachments[i], attachDir, policy); attErr != nil {
				log.Printf("event=attachment_error email_id=%d filename=%q err=%v",
					emailID, attachments[i].OrigFilename, attErr)
			}
		}

		deleteMsg(c, cand.seqNum)
		accepted++
		log.Printf("event=email_accepted seq=%d sender=%q subject=%q email_id=%d",
			cand.seqNum, cand.senderAddr, e.Subject, emailID)
	}

	log.Printf("event=poll_complete accepted=%d rejected=%d skipped=%d",
		accepted, rejected, len(deleteSeqs))
	return nil
}

// ── StartPoller ────────────────────────────────────────────────────────────

func StartPoller(ctx context.Context, sqldb *sql.DB, attachDir string) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("event=poller_panic recovered=%v", r)
			}
		}()

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
				log.Printf("event=poll_error err=%v backoff=%s", err, backoff)
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
			log.Printf("event=poll_sleeping minutes=%d", mins)

			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(mins) * time.Minute):
			}
		}
	}()
}

// ── MIME parsing ───────────────────────────────────────────────────────────

type pendingAttachment struct {
	Filename     string
	OrigFilename string
	MIMEType     string
	Data         []byte
}

func parseMessage(
	raw []byte,
	msgID, senderEmail, senderName string,
	policy *security.Policy,
) (*email.Email, []pendingAttachment, error) {

	mr, err := gomail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		if !gomessage.IsUnknownCharset(err) {
			return nil, nil, fmt.Errorf("create reader: %w", err)
		}
		log.Printf("event=parse_charset_warning msg_id=%q err=%v", msgID, err)
	}

	e := &email.Email{
		MessageID:   msgID,
		SenderEmail: senderEmail,
		SenderName:  senderName,
		ReceivedAt:  time.Now().UTC(),
	}

	if mr != nil {
		if subj, err := mr.Header.Subject(); err == nil {
			e.Subject = subj
		} else {
			log.Printf("event=subject_parse_error msg_id=%q err=%v", msgID, err)
		}
		if date, err := mr.Header.Date(); err == nil {
			e.ReceivedAt = date
		}
	}

	if mr == nil {
		return e, nil, nil
	}

	var attachments []pendingAttachment
	maxAttachBytes := policy.Limits.MaxAttachSizeMB * 1024 * 1024

	for {
		part, err := mr.NextPart()
		if err != nil {
			if err != io.EOF {
				log.Printf("event=part_error msg_id=%q err=%v", msgID, err)
			}
			break
		}

		switch h := part.Header.(type) {
		case *gomail.InlineHeader:
			ct, _, _ := h.ContentType()
			body, err := io.ReadAll(part.Body)
			if err != nil {
				log.Printf("event=inline_read_error msg_id=%q ct=%q err=%v", msgID, ct, err)
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
				log.Printf("event=attachment_read_error filename=%q msg_id=%q err=%v",
					origFilename, msgID, err)
				continue
			}
			if maxAttachBytes > 0 && int64(len(data)) > maxAttachBytes {
				log.Printf("event=attachment_skipped reason=size_limit filename=%q size=%d msg_id=%q",
					origFilename, len(data), msgID)
				continue
			}
			attachments = append(attachments, pendingAttachment{
				Filename:     origFilename,
				OrigFilename: origFilename,
				MIMEType:     security.DetectMIMEType(data),
				Data:         data,
			})
		}
	}

	log.Printf("event=parse_complete msg_id=%q has_text=%v has_html=%v attachments=%d",
		msgID, e.BodyText != "", e.BodyHTML != "", len(attachments))
	return e, attachments, nil
}

// ── Attachment persistence ─────────────────────────────────────────────────

func saveAttachment(
	sqldb *sql.DB,
	emailID int64,
	att *pendingAttachment,
	attachDir string,
	policy *security.Policy,
) error {
	dir := filepath.Join(attachDir, strconv.FormatInt(emailID, 10))
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	dest, err := safeFilename(attachDir, emailID, att.Filename)
	if err != nil {
		return fmt.Errorf("unsafe filename: %w", err)
	}
	if _, statErr := os.Stat(dest); statErr == nil {
		ext := filepath.Ext(dest)
		dest = fmt.Sprintf("%s_%d%s", strings.TrimSuffix(dest, ext), time.Now().UnixNano(), ext)
	}
	if err := os.WriteFile(dest, att.Data, 0640); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	return email.SaveAttachment(sqldb, &email.Attachment{
		EmailID:    emailID,
		Filename:   att.OrigFilename,
		MIMEType:   att.MIMEType,
		Size:       int64(len(att.Data)),
		StoredPath: dest,
	})
}
