# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

WORKDIR /build

# Download dependencies first for layer caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# Version info injected at build time by CI via --build-arg.
# Falls back to "dev" / "unknown" for local builds.
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

# Stamp version into the binary via ldflags so it appears in logs and the UI.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
      -ldflags="-s -w -extldflags=-static \
        -X emailstore/internal/version.Version=${VERSION} \
        -X emailstore/internal/version.Commit=${COMMIT} \
        -X emailstore/internal/version.BuildTime=${BUILD_TIME}" \
      -trimpath -o emailstore .

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# Pin to a specific alpine version for reproducible builds
FROM alpine:3.21

# ca-certificates: needed for TLS connections to mail servers
# tzdata: needed for correct timezone handling in logs
RUN apk add --no-cache ca-certificates tzdata && \
    update-ca-certificates

WORKDIR /app

# Copy only what the binary needs at runtime
COPY --from=builder /build/emailstore  ./emailstore
COPY --from=builder /build/templates   ./templates
COPY --from=builder /build/static      ./static

# Pre-create the data directory with correct permissions
RUN addgroup -S -g 10001 emailstore && \
    adduser  -S -u 10001 -G emailstore emailstore && \
    mkdir -p /app/data/attachments && \
    chown -R emailstore:emailstore /app

USER emailstore

EXPOSE 8080

# Health check so docker-compose and orchestrators know when we're ready
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:8080/login > /dev/null || exit 1

CMD ["./emailstore"]
