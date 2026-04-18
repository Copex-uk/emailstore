# EmailStore

A secure, self-hosted email store that polls a dedicated IMAP mailbox, validates 
emails against a configurable security policy, and presents them in a clean local web UI.

## Quick start (local development)

```bash
# 1. Generate go.sum and download dependencies (required before first run or push)
go mod tidy

# 2. Run locally
go run ./main.go

# 3. Open http://localhost:8080
```

## Run tests

```bash
go test ./...
```

## Docker (pull pre-built image)

```bash
# Edit docker-compose.yml and set your GitHub username, then:
docker compose pull
docker compose up -d
```

See [DOCKER.md](DOCKER.md) for full instructions.

## Push to GitHub (first time)

```bash
# Must run go mod tidy first to generate go.sum
go mod tidy

git init
git add .
git commit -m "initial commit"
git remote add origin https://github.com/YOURUSERNAME/emailstore.git
git push -u origin main
```

GitHub Actions will automatically run tests and build a Docker image on every push to main.

## Architecture

- **Go 1.26** — stdlib HTTP router, no web framework
- **SQLite** — all data stored locally via `modernc.org/sqlite` (pure Go, no CGO)  
- **go-imap/v2** — IMAP4rev2 client for mailbox polling
- **Zero-trust security** — configurable policy engine with strict/balanced/relaxed modes

## Project structure

```
internal/
  auth/       — password hashing, sessions, CSRF, rate limiting
  config/     — environment variable loading
  db/         — SQLite setup, migrations, settings store
  email/      — email model, storage, categories
  handler/    — HTTP handlers, setup wizard, settings UI
  imap/       — IMAP poller with security validation
  security/   — policy engine, email validator, token extraction
  testhelper/ — shared test utilities
.github/
  workflows/
    ci.yml    — test + build + push Docker image
```
