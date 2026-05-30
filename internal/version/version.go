// Package version holds the application version stamped at build time.
//
// The variables are set via -ldflags during the build:
//
//	go build -ldflags "-X emailstore/internal/version.Version=v1.2.3 \
//	                   -X emailstore/internal/version.Commit=abc1234  \
//	                   -X emailstore/internal/version.BuildTime=2026-04-25T12:00:00Z" .
//
// When running without ldflags (local dev / go run) it falls back to "dev".
package version

import "fmt"

// Version is the semver release tag, e.g. "v1.0.0".
var Version = "v1.1.0"

// Commit is the short git SHA of the build.
var Commit = "unknown"

// BuildTime is the UTC ISO-8601 timestamp of the build.
var BuildTime = "unknown"

// String returns a single human-readable version line.
func String() string {
	if Version == "dev" {
		return "dev"
	}
	return fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, BuildTime)
}
