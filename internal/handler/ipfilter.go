package handler

import (
	"database/sql"
	"log"
	"net"
	"net/http"
	"strings"

	"emailstore/internal/auth"
	"emailstore/internal/db"
)

// WithIPFilter wraps the entire HTTP handler with an IP allowlist check.
// It reads the KeyAllowedSubnets setting on every request so changes made
// in Settings → Security policy apply immediately without a restart.
//
// If the setting is empty all connections are accepted (no restriction).
// Subnets are a comma-separated list of CIDRs or bare IPs, e.g.:
//
//	192.168.1.0/24, 10.0.0.5, 172.16.0.0/12
//
// Bare IPs are treated as /32 (IPv4) or /128 (IPv6) host routes.
func WithIPFilter(sqldb *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := db.SettingGet(sqldb, db.KeyAllowedSubnets)
		if err != nil {
			log.Printf("ip_filter: read setting: %v", err)
			// Fail open — if we can't read the setting, let the request through
			// rather than locking everyone out.
			next.ServeHTTP(w, r)
			return
		}
		if raw == "" {
			// No restriction configured — allow all
			next.ServeHTTP(w, r)
			return
		}

		clientIP := auth.RemoteIP(r)
		ip := net.ParseIP(clientIP)
		if ip == nil {
			log.Printf("event=ip_filter_reject reason=unparseable_ip ip=%q url=%s", clientIP, r.URL.Path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		for _, subnet := range parseSubnets(raw) {
			if subnet.Contains(ip) {
				next.ServeHTTP(w, r)
				return
			}
		}

		log.Printf("event=ip_filter_reject ip=%s url=%s", clientIP, r.URL.Path)
		http.Error(w, "Forbidden — connection not allowed from your IP address", http.StatusForbidden)
	})
}

// parseSubnets splits a comma-separated string of CIDRs and bare IPs.
// Invalid entries are logged and skipped rather than causing a hard failure.
func parseSubnets(raw string) []*net.IPNet {
	var nets []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Bare IP — promote to host CIDR
		if !strings.Contains(part, "/") {
			if strings.Contains(part, ":") {
				part += "/128" // IPv6
			} else {
				part += "/32" // IPv4
			}
		}
		_, ipnet, err := net.ParseCIDR(part)
		if err != nil {
			log.Printf("ip_filter: invalid subnet %q (skipping): %v", part, err)
			continue
		}
		nets = append(nets, ipnet)
	}
	return nets
}
