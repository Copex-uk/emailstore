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

type Config struct {
	Host, Port, User, Password string
	TLS, StartTLS, Debug       bool
	AttachDir                  string
}

func LoadConfig(sqldb *sql.DB, attachDir string) (*Config, error) {
	s, err := db.SettingGetAll(sqldb)
	if err != nil {
		return nil, fmt.Errorf("load settings: %w", err)
	}
	c := &Config{
		Host: s[db.KeyIMAPHost], Port: s[db.KeyIMAPPort],
		User: s[db.KeyIMAPUser], Password: s[db.KeyIMAPPassword],
		TLS: s[db.KeyIMAPTLS] == "1", StartTLS: s[db.KeyIMAPStartTLS] == "1",
		Debug: s[db.KeyIMAPDebug] == "1", AttachDir: attachDir,
	}
	if c.Host == "" {
		return nil, fmt.Errorf("imap host not configured")
	}
	if c.User == "" {
		return nil, fmt.Errorf("imap user not configured")
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

func normalisedAddr(raw string) string {
	a, err := mail.ParseAddress(raw)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(raw))
	}
	return strings.ToLower(a.Address)
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

// deleteMsg flags \Deleted then expunges. MUST be called only when no
// FetchCommand is open — Dovecot rejects Store/Expunge otherwise.
func deleteMsg(c *imapclient.Client, seqNum uint32) {
	log.Printf("event=delete_message seq=%d", seqNum)
	if err := c.Store(imap.SeqSetNum(seqNum), &imap.StoreFlags{
		Op: imap.StoreFlagsAdd, Silent: true,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		log.Printf("event=store_deleted_flag_error seq=%d err=%v", seqNum, err)
		return
	}
	if err := c.Expunge().Close(); err != nil {
		log.Printf("event=expunge_error seq=%d err=%v", seqNum, err)
	}
}

type candidate struct {
	seqNum                  uint32
	msgID, senderAddr, senderName, subject string
}

// Poll connects, selects INBOX, and processes all messages.
// Every message (accepted, rejected, duplicate) is deleted from the server.
// Two-pass design: pass 1 fetches envelopes via Collect() (closes the
// FetchCommand), pass 2 fetches bodies one-by-one via Collect().
func Poll(sqldb *sql.DB, attachDir string) error {
	cfg, err := LoadConfig(sqldb, attachDir)
	if err != nil {
		return fmt.Errorf("poll: %w", err)
	}

	policy := security.LoadPolicy(sqldb)
	log.Printf("event=poll_start mode=%s require_token=%v tokens_configured=%v",
		policy.Mode, policy.TokenRequired, len(policy.Tokens) > 0)

	// ── Dial ──────────────────────────────────────────────────────────
	addr := cfg.Host + ":" + cfg.Port
	tlsCfg := &tls.Config{ServerName: cfg.Host}
	var dbgW io.Writer
	if cfg.Debug {
		dbgW = os.Stderr
	}
	log.Printf("event=dial addr=%s tls=%v starttls=%v", addr, cfg.TLS, cfg.StartTLS)

	var c *imapclient.Client
	switch {
	case cfg.TLS:
		c, err = imapclient.DialTLS(addr, &imapclient.Options{TLSConfig: tlsCfg, DebugWriter: dbgW})
	case cfg.StartTLS:
		c, err = imapclient.DialStartTLS(addr, &imapclient.Options{TLSConfig: tlsCfg, DebugWriter: dbgW})
	default:
		c, err = imapclient.DialInsecure(addr, &imapclient.Options{DebugWriter: dbgW})
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer func() { log.Printf("event=connection_close"); c.Close() }()

	// ── Login ──────────────────────────────────────────────────────────
	log.Printf("event=login user=%s", cfg.User)
	if err := c.Login(cfg.User, cfg.Password).Wait(); err != nil {
		return fmt.Errorf("login %s: %w", cfg.User, err)
	}
	defer func() {
		if err := c.Logout().Wait(); err != nil {
			log.Printf("event=logout_error err=%v", err)
		}
	}()

	// ── SELECT INBOX ───────────────────────────────────────────────────
	// NumMessages from SELECT avoids SEARCH entirely.
	// Empty SEARCH criteria is rejected by Dovecot (IMAP4rev1).
	log.Printf("event=select_inbox")
	selData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		return fmt.Errorf("SELECT INBOX: %w", err)
	}
	total := selData.NumMessages
	log.Printf("event=inbox_selected total_messages=%d uid_next=%d", total, selData.UIDNext)

	if total == 0 {
		log.Printf("event=poll_complete accepted=0 rejected=0 skipped=0 reason=mailbox_empty")
		return nil
	}

	fetchCount := total
	if fetchCount > MaxEmailsPerRun {
		log.Printf("event=poll_capped total=%d cap=%d", fetchCount, MaxEmailsPerRun)
		fetchCount = MaxEmailsPerRun
	}
	seqSet := imap.SeqSet{}
	seqSet.AddRange(1, fetchCount)
	log.Printf("event=fetch_range end=%d", fetchCount)

	// ── Pass 1: envelopes ──────────────────────────────────────────────
	// Collect() reads everything from the wire into memory and closes the
	// FetchCommand before returning — safe to call Store/Expunge after.
	log.Printf("event=pass1_start")
	envBufs, err := c.Fetch(seqSet, &imap.FetchOptions{Envelope: true, UID: true}).Collect()
	if err != nil {
		return fmt.Errorf("FETCH envelopes 1:%d: %w", fetchCount, err)
	}
	log.Printf("event=pass1_complete received=%d", len(envBufs))

	if len(envBufs) == 0 {
		log.Printf("event=poll_complete accepted=0 rejected=0 skipped=0 reason=server_returned_no_envelopes reported=%d", total)
		return nil
	}

	var cands    []candidate
	var delSeqs  []uint32

	for _, buf := range envBufs {
		seq := buf.SeqNum
		env := buf.Envelope
		if env == nil {
			log.Printf("event=skip seq=%d reason=nil_envelope", seq)
			delSeqs = append(delSeqs, seq)
			continue
		}

		senderAddr, senderName := "", ""
		if len(env.From) > 0 {
			senderAddr = strings.ToLower(strings.TrimSpace(env.From[0].Addr()))
			senderName = env.From[0].Name
		}
		log.Printf("event=envelope seq=%d uid=%d sender=%q subject=%q msg_id=%q",
			seq, buf.UID, senderAddr, env.Subject, env.MessageID)

		msgID := strings.TrimSpace(env.MessageID)
		if msgID == "" {
			msgID = fmt.Sprintf("generated-%s-%s-%d", senderAddr, env.Subject, seq)
			log.Printf("event=generated_msg_id seq=%d id=%q", seq, msgID)
		}

		if exists, dbErr := email.Exists(sqldb, msgID); dbErr != nil {
			log.Printf("event=duplicate_check_error seq=%d err=%v", seq, dbErr)
			continue // DB error — skip without deleting, retry next poll
		} else if exists {
			log.Printf("event=skip seq=%d reason=duplicate msg_id=%q", seq, msgID)
			delSeqs = append(delSeqs, seq)
			continue
		}

		allowed, aErr := email.IsAllowedSender(sqldb, senderAddr)
		if aErr != nil {
			log.Printf("event=allowed_sender_error seq=%d sender=%q err=%v", seq, senderAddr, aErr)
			allowed = false
		}
		log.Printf("event=policy_check seq=%d sender=%q allowed=%v mode=%s",
			seq, senderAddr, allowed, policy.Mode)

		if valErr := security.ValidateEmail(&security.ParsedEmail{
			SenderAddr: senderAddr, Subject: env.Subject, Headers: map[string]string{},
		}, allowed, policy); valErr != nil {
			ve := valErr.(*security.ValidationError)
			log.Printf("event=skip seq=%d reason=policy code=%s sender=%q", seq, ve.Code, senderAddr)
			delSeqs = append(delSeqs, seq)
			continue
		}

		log.Printf("event=candidate seq=%d sender=%q subject=%q", seq, senderAddr, env.Subject)
		cands = append(cands, candidate{seq, msgID, senderAddr, senderName, env.Subject})
	}

	// Delete rejects/dupes — FetchCommand is closed, safe to call Store/Expunge
	log.Printf("event=pass1_results candidates=%d to_delete=%d", len(cands), len(delSeqs))
	for _, seq := range delSeqs {
		deleteMsg(c, seq)
	}

	if len(cands) == 0 {
		log.Printf("event=poll_complete accepted=0 rejected=%d skipped=%d reason=no_valid_candidates",
			len(delSeqs), 0)
		return nil
	}

	// ── Pass 2: body per candidate ─────────────────────────────────────
	// Keep the bodySection pointer alive — FindBodySection uses it for matching.
	log.Printf("event=pass2_start candidates=%d", len(cands))
	bodySection := &imap.FetchItemBodySection{}
	accepted, rejected := 0, 0

	for _, cand := range cands {
		log.Printf("event=fetch_body seq=%d msg_id=%q sender=%q subject=%q",
			cand.seqNum, cand.msgID, cand.senderAddr, cand.subject)

		// Collect() closes the command before we return — safe to deleteMsg after
		bodyBufs, fErr := c.Fetch(
			imap.SeqSetNum(cand.seqNum),
			&imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{bodySection}},
		).Collect()
		if fErr != nil {
			log.Printf("event=fetch_body_error seq=%d err=%v", cand.seqNum, fErr)
			rejected++
			continue // keep on server for retry
		}
		if len(bodyBufs) == 0 {
			log.Printf("event=skip seq=%d reason=no_body_buffer", cand.seqNum)
			deleteMsg(c, cand.seqNum)
			rejected++
			continue
		}

		// FindBodySection uses pointer equality to match our section request.
		// Fall back to scanning the slice in case the pointer comparison misses.
		bodyBytes := bodyBufs[0].FindBodySection(bodySection)
		if len(bodyBytes) == 0 {
			log.Printf("event=findbodysection_miss seq=%d trying_slice_fallback", cand.seqNum)
			for _, sec := range bodyBufs[0].BodySection {
				if len(sec.Bytes) > 0 {
					bodyBytes = sec.Bytes
					break
				}
			}
		}
		if len(bodyBytes) == 0 {
			log.Printf("event=skip seq=%d reason=empty_body_bytes", cand.seqNum)
			deleteMsg(c, cand.seqNum)
			rejected++
			continue
		}
		log.Printf("event=body_received seq=%d bytes=%d", cand.seqNum, len(bodyBytes))

		e, atts, pErr := parseMessage(bodyBytes, cand.msgID, cand.senderAddr, cand.senderName, policy)
		if pErr != nil {
			log.Printf("event=parse_error seq=%d err=%v", cand.seqNum, pErr)
			deleteMsg(c, cand.seqNum)
			rejected++
			continue
		}

		if catID, ok := email.MatchCategory(sqldb, e.Subject); ok {
			e.CategoryID = sql.NullInt64{Int64: catID, Valid: true}
		} else if inboxID := email.InboxCategoryID(sqldb); inboxID > 0 {
			e.CategoryID = sql.NullInt64{Int64: inboxID, Valid: true}
		}

		emailID, sErr := email.Save(sqldb, e)
		if sErr != nil {
			log.Printf("event=save_error seq=%d err=%v", cand.seqNum, sErr)
			rejected++
			continue // keep on server — DB error, retry next poll
		}

		for i := range atts {
			if aErr := saveAttachment(sqldb, emailID, &atts[i], attachDir, policy); aErr != nil {
				log.Printf("event=attachment_error email_id=%d filename=%q err=%v",
					emailID, atts[i].OrigFilename, aErr)
			}
		}

		deleteMsg(c, cand.seqNum)
		accepted++
		log.Printf("event=email_accepted seq=%d sender=%q subject=%q email_id=%d atts=%d",
			cand.seqNum, cand.senderAddr, e.Subject, emailID, len(atts))
	}

	log.Printf("event=poll_complete accepted=%d rejected=%d skipped=%d",
		accepted, rejected, len(delSeqs))
	return nil
}

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
				if backoff *= 2; backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
			backoff = 30 * time.Second
			s, _ := db.SettingGet(sqldb, db.KeyPollInterval)
			mins, _ := strconv.Atoi(s)
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

type pendingAttachment struct {
	Filename, OrigFilename, MIMEType string
	Data                             []byte
}

func parseMessage(raw []byte, msgID, senderEmail, senderName string, policy *security.Policy) (*email.Email, []pendingAttachment, error) {
	if len(raw) == 0 {
		return nil, nil, fmt.Errorf("empty body msg_id=%q", msgID)
	}
	mr, err := gomail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		if !gomessage.IsUnknownCharset(err) {
			return nil, nil, fmt.Errorf("mail reader: %w", err)
		}
		log.Printf("event=charset_warning msg_id=%q err=%v", msgID, err)
	}
	e := &email.Email{
		MessageID: msgID, SenderEmail: senderEmail,
		SenderName: senderName, ReceivedAt: time.Now().UTC(),
	}
	if mr != nil {
		if subj, err := mr.Header.Subject(); err == nil {
			e.Subject = subj
		} else {
			log.Printf("event=subject_decode_error msg_id=%q err=%v", msgID, err)
		}
		if date, err := mr.Header.Date(); err == nil {
			e.ReceivedAt = date
		}
	}
	if mr == nil {
		return e, nil, nil
	}
	var atts []pendingAttachment
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
			body, rErr := io.ReadAll(part.Body)
			if rErr != nil {
				log.Printf("event=inline_read_error msg_id=%q ct=%q err=%v", msgID, ct, rErr)
				continue
			}
			switch {
			case strings.HasPrefix(ct, "text/plain") && e.BodyText == "":
				e.BodyText = string(body)
			case strings.HasPrefix(ct, "text/html") && e.BodyHTML == "":
				e.BodyHTML = string(body)
			}
		case *gomail.AttachmentHeader:
			if policy.Limits.MaxAttachments > 0 && len(atts) >= policy.Limits.MaxAttachments {
				log.Printf("event=attachment_skipped reason=count_limit msg_id=%q", msgID)
				continue
			}
			fn, _ := h.Filename()
			if fn == "" {
				fn = "attachment"
			}
			data, rErr := io.ReadAll(part.Body)
			if rErr != nil {
				log.Printf("event=attachment_read_error fn=%q msg_id=%q err=%v", fn, msgID, rErr)
				continue
			}
			if maxAttachBytes > 0 && int64(len(data)) > maxAttachBytes {
				log.Printf("event=attachment_skipped reason=size fn=%q size=%d msg_id=%q", fn, len(data), msgID)
				continue
			}
			atts = append(atts, pendingAttachment{fn, fn, security.DetectMIMEType(data), data})
		}
	}
	log.Printf("event=parse_complete msg_id=%q has_text=%v has_html=%v atts=%d subject=%q",
		msgID, e.BodyText != "", e.BodyHTML != "", len(atts), e.Subject)
	return e, atts, nil
}

func saveAttachment(sqldb *sql.DB, emailID int64, att *pendingAttachment, attachDir string, _ *security.Policy) error {
	dir := filepath.Join(attachDir, strconv.FormatInt(emailID, 10))
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	dest, err := safeFilename(attachDir, emailID, att.Filename)
	if err != nil {
		return fmt.Errorf("unsafe filename %q: %w", att.Filename, err)
	}
	if _, sErr := os.Stat(dest); sErr == nil {
		ext := filepath.Ext(dest)
		dest = fmt.Sprintf("%s_%d%s", strings.TrimSuffix(dest, ext), time.Now().UnixNano(), ext)
	}
	if err := os.WriteFile(dest, att.Data, 0640); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	return email.SaveAttachment(sqldb, &email.Attachment{
		EmailID: emailID, Filename: att.OrigFilename,
		MIMEType: att.MIMEType, Size: int64(len(att.Data)), StoredPath: dest,
	})
}
