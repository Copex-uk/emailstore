# EmailStore — Docker Setup Guide

## Prerequisites

- Docker Engine 24+ installed
- Docker Compose v2+ (`docker compose` not `docker-compose`)
- Git (optional)

---

## Quick start

### 1. Get the files

Either extract the tar archive or clone the repo into a directory:

```bash
mkdir -p emailstore/data/attachments && cd emailstore

# Fix permissions so the container (UID 10001) can write to the data directory
sudo chown -R 10001:10001 data/
tar -xzf emailstore.tar.gz --strip-components=1
```

### 2. Build and start

```bash
docker compose up -d
```

This builds the image and starts the container. On first run it will download
the Go build image (~300 MB) and compile the binary. Subsequent starts are instant.

### 3. Open the app

```
http://localhost:8080
```

The setup wizard will appear. Complete it to set your password, mailbox
connection, and initial categories.

### 4. Check it is running

```bash
docker compose ps
docker compose logs -f
```

---

## Data persistence

All data is stored in `./data/` on your host machine:

```
emailstore/
└── data/
    ├── emailstore.db       ← SQLite database (emails, settings, sessions)
    └── attachments/        ← Downloaded attachment files
```

This directory is mounted as a volume — data survives container restarts,
rebuilds, and upgrades. **Back up the `data/` directory to keep your emails.**

---

## Configuration

Settings are managed through the web UI (Settings → Mailbox, etc.).
The only environment variables are:

| Variable   | Default      | Description                        |
|------------|--------------|------------------------------------|
| `PORT`     | `8080`       | Port the app listens on            |
| `DATA_DIR` | `/app/data`  | Where the DB and attachments live  |

To change the port, edit `docker-compose.yml`:

```yaml
ports:
  - "127.0.0.1:9090:8080"   # host port 9090 → container port 8080
```

---

## Upgrading

When a new version is available:

```bash
# Pull new code / extract new archive
docker compose down
docker compose build --no-cache
docker compose up -d
```

Your `data/` directory is untouched — all emails and settings are preserved.

---

## Stopping and starting

```bash
docker compose stop      # stop without removing container
docker compose start     # start again
docker compose down      # stop and remove container (data is safe)
docker compose up -d     # recreate and start
```

---

## Viewing logs

```bash
docker compose logs -f                  # follow live logs
docker compose logs --tail=100          # last 100 lines
```

---

## Accessing the database directly

```bash
# Run sqlite3 inside the container
docker compose exec emailstore sh
# then: sqlite3 /app/data/emailstore.db

# Or from the host (if sqlite3 is installed)
sqlite3 data/emailstore.db ".tables"
sqlite3 data/emailstore.db "SELECT key, value FROM settings;"
```

---

## Exposing on the local network (not just localhost)

By default EmailStore only listens on `127.0.0.1` — visible only on the
machine it runs on. To make it available to other devices on your local network:

```yaml
# docker-compose.yml
ports:
  - "0.0.0.0:8080:8080"   # listen on all interfaces
```

> **Note:** EmailStore has no HTTPS. Do not expose it to the public internet
> without a reverse proxy (nginx/Caddy) with TLS in front of it.

---

## Behind a reverse proxy (nginx example)

```nginx
server {
    listen 443 ssl;
    server_name emailstore.yourdomain.local;

    ssl_certificate     /etc/ssl/certs/yourdomain.crt;
    ssl_certificate_key /etc/ssl/private/yourdomain.key;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
    }
}
```

---

## Resetting everything

To start completely fresh (deletes all emails and settings):

```bash
docker compose down
rm -rf data/
docker compose up -d
```

---

## Troubleshooting

**Container exits immediately**
```bash
docker compose logs emailstore
```
Usually a permissions issue on `./data/` or a port conflict.

**Port already in use**
Change the host port in `docker-compose.yml`:
```yaml
ports:
  - "127.0.0.1:8081:8080"
```

**Can't connect to mail server from container**
The container can reach external hosts. If polling fails, check:
- IMAP host and port in Settings → Mailbox
- Enable debug logging in Settings → Mailbox to see the raw connection

**Permissions error on ./data/**
```bash
# The container runs as UID 1000 by default
# If your host data/ was created by root, fix it:
sudo chown -R 1000:1000 data/
```
