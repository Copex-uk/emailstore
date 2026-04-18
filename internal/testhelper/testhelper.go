// Package testhelper provides shared utilities for package-level tests.
// Using an in-memory SQLite database keeps tests fast, hermetic, and
// free of any filesystem setup.
package testhelper

import (
	"database/sql"
	"testing"

	"emailstore/internal/db"
)

// NewDB opens a fresh in-memory SQLite database, runs all migrations, and
// registers a cleanup function that closes it when the test ends.
func NewDB(t *testing.T) *sql.DB {
	t.Helper()
	sqldb, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("testhelper.NewDB: %v", err)
	}
	t.Cleanup(func() { sqldb.Close() })
	return sqldb
}
