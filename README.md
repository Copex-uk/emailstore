# EmailStore

<div align="center">

[![Vibe Coded with Claude](https://img.shields.io/badge/vibe%20coded%20with-Claude%20AI-6366f1?style=for-the-badge&logo=anthropic&logoColor=white)](https://claude.ai)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![SQLite](https://img.shields.io/badge/SQLite-WAL-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org)
[![Docker](https://img.shields.io/badge/Docker-hardened-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)

**A secure, self-hosted email archive that polls a dedicated IMAP mailbox,  
validates every email against a configurable security policy, and stores  
everything locally — no cloud, no third-party services.**

[Features](#features) · [Quick start](#quick-start) · [Docker](#docker-deployment) · [Security](#security-model) · [Subject tags](#subject-line-tags) · [Architecture](#architecture)

</div>

---

> **Built entirely by vibe coding with [Claude](https://claude.ai)** — every line of Go, every template, every test, every Docker config, and this README were produced through conversation with Anthropic's AI assistant. Zero code was written by hand.

---

## Features

| Feature | Details |
|---|---|
| **Zero-trust security** | Emails rejected by default — configurable strict / balanced / relaxed policy engine |
| **Sender allowlist** | Only approved email addresses are ever stored |
| **Token authentication** | Optional second factor via `[ES:token]` subject tag or `X-EmailStore-Auth` header |
| **Auto-categorisation** | Subject line tags `[work]` or keyword rules route emails on arrival |
| **Auto-delete** | Per-category retention periods — e.g. `[inbox:30]` deletes after 30 days |
| **IP allowlist** | Restrict web access to specific subnets e.g. `192.168.1.0/24` |
| **Download emails** | Export as `.eml` or `.zip` with attachments |
| **Delete with confirmation** | Typed "delete" confirmation prevents accidents |
| **Dark / light mode** | User-selectable, persisted in the browser |
| **Panic recovery** | HTTP server survives individual request panics |
| **Exponential backoff** | IMAP errors retry at 30s → 1m → 2m → up to 30m |
| **Docker-ready** | Hardened container: read-only fs, no root, `cap_drop ALL`, resource limits |
| **GitHub Actions CI** | Tests + Docker image built and pushed to GHCR on every commit |

---

## Quick start

```bash
# 1. Install Go 1.26+ then clone or extract the project
cd emailstore

# 2. Generate go.sum (required before first run or push)
go mod tidy

# 3. Run
go run ./main.go

# 4. Open http://localhost:8080 and complete the 3-step setup wizard
#    Step 1 — set your password
#    Step 2 — enter IMAP mailbox details (skippable, configure later in Settings)
#    Step 3 — choose default categories (Inbox is always created)
```

## Run tests

```bash
go test ./...
# Expected output: all packages pass, ~40 tests
```

---

## Docker deployment

### First time setup

```bash
# 1. The image is built by GitHub Actions and pushed to ghcr.io/copex-uk/emailstore

# 2. Create data directory with correct permissions
#    (container runs as UID 10001 — this must match)
mkdir -p data/attachments
sudo chown -R 10001:10001 data/

# 3. Pull and start
docker compose pull
docker compose up -d

# 4. View logs
docker compose logs -f
```

### Pushing to GitHub (first time)

```bash
go mod tidy          # generates go.sum — must be committed

git init
git add .
git commit -m "initial commit"
git remote add origin https://github.com/Copex-uk/emailstore.git
git push -u origin main
# GitHub Actions runs tests → builds → pushes ghcr.io/copex-uk/emailstore:latest
```

### Updating

```bash
# After pushing new code GitHub Actions rebuilds the image automatically.
# On the server:
docker compose pull && docker compose up -d
```

See [DOCKER.md](DOCKER.md) for the full deployment walkthrough.

---

## Configuration

All configuration is done through the web UI. The only environment variables are:

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | HTTP listen port |
| `BIND_HOST` | `127.0.0.1` | Bind address — set to `0.0.0.0` in Docker |
| `DATA_DIR` | `./data` | Directory for SQLite database and attachments |

---

## Security model

EmailStore operates on zero-trust principles — every email is rejected unless it passes all configured checks.

### Security modes (Settings → Security policy)

| Mode | Requirement | Use case |
|---|---|---|
| **Strict** | Allowlisted sender **AND** valid token | Maximum security |
| **Balanced** | Allowlisted sender **OR** valid token | Flexible |
| **Relaxed** (default) | Allowlisted sender only | Simple setup |

### Token authentication

Add `[ES:yourtoken]` anywhere in the subject line, or use the `X-EmailStore-Auth` email header. Generate tokens with:

```bash
openssl rand -hex 16
```

### IP allowlist (Settings → Security policy)

Restricts the web UI to specific subnets or IPs. Leave empty to allow all connections.

```
192.168.1.0/24          # entire home subnet
10.0.0.5                # single IP
192.168.0.0/16, 10.0.0.0/8   # multiple ranges, comma-separated
```

⚠️ If you lock yourself out: `sqlite3 data/emailstore.db "DELETE FROM settings WHERE key='allowed_subnets'"`

---

## Subject line tags

Tags at the start of the subject line control categorisation and retention:

| Subject | Effect |
|---|---|
| `[work] Project update` | Assign to **work** category |
| `[finance] Invoice Q1` | Assign to **finance** category |
| `[inbox:30] Receipt` | Assign to inbox, **auto-delete after 30 days** |
| `[work:90] Annual report` | Assign to work, **auto-delete after 90 days** |
| `[ES:mytoken] Subject` | Include auth token (for strict / balanced mode) |
| `Normal subject` | No tag — keyword rules checked, then → Inbox |

Tags are case-insensitive. The `[slug:days]` format sets the category's retention period if it isn't already set.

---

## Auto-delete / retention

Set per-category retention in **Settings → Categories** (the "Auto-delete after" column).  
Enter days to keep — `0` means keep forever.

A background job runs at startup and every 24 hours, deleting emails (and their attachments) whose category's retention period has elapsed. The log shows `event=expiry_complete deleted=N` when emails are purged.

---

## How it works

Two-pass IMAP polling designed for Dovecot (IMAP4rev1) compatibility:

```
Poll start
│
├─ SELECT INBOX → get message count from server
├─ PASS 1: Fetch envelopes (sender, subject, message ID)
│   ├─ Skip duplicates  → delete from server by UID
│   ├─ Check sender     → delete rejected by UID
│   └─ Check policy     → delete rejected by UID
│
└─ PASS 2: Fetch body per candidate (by UID — immune to seq renumbering)
    ├─ Parse MIME (text, HTML, attachments)
    ├─ Assign category (tag → keyword rule → Inbox)
    ├─ Apply retention tag if present
    ├─ Save to SQLite + attachments to disk
    └─ Delete from server by UID

Mailbox always empty after a successful poll.
```

Using UID-based fetches throughout is critical — `EXPUNGE` renumbers sequence numbers, causing `BAD: Invalid messageset` errors if subsequent fetches use the old sequence numbers.

---

## Architecture

```
emailstore/
├── main.go                    — startup, background goroutines, graceful shutdown
├── Dockerfile                 — multi-stage build, static binary, UID 10001
├── docker-compose.yml         — read-only fs, tmpfs /tmp, cap_drop ALL, memory limit
├── .github/workflows/ci.yml   — test → build → push to GHCR
├── templates/                 — Go html/template (server-rendered, no JS framework)
│   └── settings/
├── static/                    — CSS (CSS variables, dark/light themes), theme.js, favicon
└── internal/
    ├── auth/       — bcrypt, sessions, CSRF double-submit, login rate limiter
    ├── config/     — env var loading
    ├── db/         — SQLite (WAL mode, single connection), migrations, settings KV store
    ├── email/      — Email/Category/Attachment models, CRUD, expiry queries
    ├── handler/    — HTTP handlers, setup wizard, IP filter middleware, settings UI
    ├── imap/       — two-pass UID-based poller, MIME parser, attachment storage
    ├── security/   — policy engine (strict/balanced/relaxed), validator, token extractor
    └── testhelper/ — shared in-memory SQLite for tests
```

**Dependencies** (zero new ones added during development):

| Package | Purpose |
|---|---|
| `modernc.org/sqlite` | Pure-Go SQLite driver — no CGO, works in Alpine |
| `github.com/emersion/go-imap/v2` | IMAP4rev2 client |
| `github.com/emersion/go-message` | MIME parsing |
| `golang.org/x/crypto` | bcrypt password hashing |

Everything else is Go standard library.

---

## IMAP provider settings

| Provider | Host | Port | Mode |
|---|---|---|---|
| Gmail | `imap.gmail.com` | 993 | TLS |
| Outlook / 365 | `outlook.office365.com` | 993 | TLS |
| Yahoo | `imap.mail.yahoo.com` | 993 | TLS |
| iCloud | `imap.mail.me.com` | 993 | TLS |
| Fastmail | `imap.fastmail.com` | 993 | TLS |
| cPanel / Dovecot | `mail.yourdomain.com` | 993 | TLS |

Gmail requires an **App Password** if 2-step verification is enabled (Google Account → Security → 2-Step Verification → App passwords).

---

<div align="center">

*Built entirely by vibe coding with [Claude](https://claude.ai) by Anthropic.*  
*No code was written by hand — every feature, fix, and refactor came from conversation.*

</div>
