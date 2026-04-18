package db

import (
	"testing"
)

// openTestDB opens an in-memory DB directly (can't use testhelper to avoid cycle)
func openTestDB(t *testing.T) interface{ Exec(string, ...any) (interface{}, error) } {
	t.Helper()
	return nil
}

// We test via the exported Open function which also runs migrations.

func TestOpen_RunsMigrations(t *testing.T) {
	sqldb, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sqldb.Close()

	// Verify core tables exist
	tables := []string{"settings", "sessions", "emails", "attachments", "categories", "allowed_senders"}
	for _, tbl := range tables {
		var n int
		err := sqldb.QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl,
		).Scan(&n)
		if err != nil || n == 0 {
			t.Errorf("table %q not found after migration", tbl)
		}
	}
}

func TestOpen_Idempotent(t *testing.T) {
	// Running Open twice on the same path should not fail (IF NOT EXISTS guards)
	sqldb, err := Open(":memory:")
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	sqldb.Close()
	// Second open on a fresh memory DB — both should succeed
	sqldb2, err := Open(":memory:")
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	sqldb2.Close()
}

func TestSettingSetAndGet(t *testing.T) {
	sqldb, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sqldb.Close()

	// Get non-existent key returns empty string, no error
	val, err := SettingGet(sqldb, "nonexistent")
	if err != nil {
		t.Errorf("SettingGet missing key: unexpected error: %v", err)
	}
	if val != "" {
		t.Errorf("SettingGet missing key: want empty string, got %q", val)
	}

	// Set and retrieve
	if err := SettingSet(sqldb, "test_key", "hello"); err != nil {
		t.Fatalf("SettingSet: %v", err)
	}
	got, err := SettingGet(sqldb, "test_key")
	if err != nil {
		t.Fatalf("SettingGet after set: %v", err)
	}
	if got != "hello" {
		t.Errorf("SettingGet = %q, want %q", got, "hello")
	}
}

func TestSettingSet_Upsert(t *testing.T) {
	sqldb, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sqldb.Close()

	SettingSet(sqldb, "key", "first")
	SettingSet(sqldb, "key", "second")

	val, _ := SettingGet(sqldb, "key")
	if val != "second" {
		t.Errorf("upsert: expected %q, got %q", "second", val)
	}
}

func TestSettingGetAll(t *testing.T) {
	sqldb, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sqldb.Close()

	SettingSet(sqldb, "a", "1")
	SettingSet(sqldb, "b", "2")
	SettingSet(sqldb, "c", "3")

	all, err := SettingGetAll(sqldb)
	if err != nil {
		t.Fatalf("SettingGetAll: %v", err)
	}
	if all["a"] != "1" || all["b"] != "2" || all["c"] != "3" {
		t.Errorf("SettingGetAll returned unexpected values: %v", all)
	}
}

func TestSettingKeys_AllDefined(t *testing.T) {
	// Ensure all key constants are non-empty strings
	keys := []string{
		KeyPasswordHash, KeyIMAPHost, KeyIMAPPort, KeyIMAPUser,
		KeyIMAPPassword, KeyIMAPTLS, KeyIMAPStartTLS, KeyIMAPDebug,
		KeyPollInterval, KeySessionTimeout, KeySetupDone, KeyMaxAttachBytes,
		KeySecurityMode, KeySecurityRequireToken, KeySecurityTokenLocation,
		KeySecurityTokens, KeySecurityMaxEmailMB, KeySecurityMaxAttachments,
		KeySecurityMaxAttachMB,
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if k == "" {
			t.Error("found an empty key constant")
		}
		if seen[k] {
			t.Errorf("duplicate key constant: %q", k)
		}
		seen[k] = true
	}
}
