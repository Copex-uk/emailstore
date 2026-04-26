# Changelog

All notable changes to EmailStore are documented here.

## [Unreleased]

### Added
- Auto-delete retention per category — set days in Settings → Categories or via `[slug:days]` subject tag
- IP allowlist — restrict web access to specific subnets (Settings → Security policy)
- Category editing — rename and recolour categories inline without deleting and recreating
- Version stamping — version, commit SHA, and build time baked into binary at build and shown in UI

### Changed
- Default security policy changed to **Relaxed** (sender allowlist only) for easier initial setup
- Inbox category is now protected — cannot be deleted or renamed
- IMAP polling switched to UID-based fetch and delete — fixes sequence number renumbering bug with Dovecot
- All database errors now logged explicitly (no more silent failures)
- HTTP server now recovers from panics gracefully

### Fixed
- CSRF cookie now uses no SameSite attribute — fixes login failures on LAN IPs over plain HTTP
- Setup wizard CSRF removed — guarded by `setup_done` flag instead
- Subnet placeholder text changed to "Allow all — enter subnet/s to restrict" to avoid confusion

---

## [v1.0.0] — First stable release

- Two-pass UID-based IMAP polling (Dovecot compatible)
- Zero-trust security policy engine (strict / balanced / relaxed)
- Token authentication via subject tag `[ES:token]` or `X-EmailStore-Auth` header
- Sender allowlist
- Category routing via subject tags and keyword rules
- Auto-categorisation fallback to Inbox
- Email download as `.eml` or `.zip` with attachments
- Delete with typed confirmation
- Dark / light mode (user-selectable)
- Docker deployment with hardened container settings
- GitHub Actions CI: test → build → push to GHCR → GitHub Release
