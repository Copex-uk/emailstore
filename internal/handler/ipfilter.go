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

// WithIPFilter wraps the entire HTTP handler with IP access controls.
// Two independent checks run on every request, in order:
//
//  1. IPv6 block — if KeyDisableIPv6 is "1", any IPv6 source is rejected.
//  2. Subnet allowlist — if KeyAllowedSubnets is non-empty, the source IP
//     must match at least one listed CIDR or bare IP.
//
// Both settings are read from the database on every request so changes
// apply immediately without a restart.
// On a DB read error the filter fails open to avoid locking everyone out.
func WithIPFilter(sqldb *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := auth.RemoteIP(r)
		ip := net.ParseIP(clientIP)

		// ── 1. IPv6 block ──────────────────────────────────────────────
		disableIPv6, err := db.SettingGet(sqldb, db.KeyDisableIPv6)
		if err != nil {
			log.Printf("ip_filter: read disable_ipv6 setting: %v", err)
		}
		if disableIPv6 == "1" && ip != nil && ip.To4() == nil {
			// ip.To4() returns nil for genuine IPv6 addresses.
			// The loopback check (::1) is intentionally included — if IPv6
			// is disabled the healthcheck should use IPv4 (127.0.0.1).
			log.Printf("event=ip_filter_reject reason=ipv6_disabled ip=%s url=%s", clientIP, r.URL.Path)
			http.Error(w, "Forbidden — IPv6 connections are not permitted", http.StatusForbidden)
			return
		}

		// ── 2. Subnet allowlist ────────────────────────────────────────
		raw, err := db.SettingGet(sqldb, db.KeyAllowedSubnets)
		if err != nil {
			log.Printf("ip_filter: read allowed_subnets setting: %v", err)
			// Fail open — cannot read setting, allow through
			next.ServeHTTP(w, r)
			return
		}
		if raw == "" {
			// No restriction — allow all
			next.ServeHTTP(w, r)
			return
		}
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
