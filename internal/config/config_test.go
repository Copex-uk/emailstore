package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	// Clear any env vars that might be set
	os.Unsetenv("PORT")
	os.Unsetenv("DATA_DIR")

	cfg := Load()

	if cfg.Port != "8080" {
		t.Errorf("default Port = %q, want 8080", cfg.Port)
	}
	if cfg.DataDir != "./data" {
		t.Errorf("default DataDir = %q, want ./data", cfg.DataDir)
	}
	if cfg.DBPath != filepath.Join("./data", "emailstore.db") {
		t.Errorf("DBPath = %q, unexpected", cfg.DBPath)
	}
	if cfg.AttachDir != filepath.Join("./data", "attachments") {
		t.Errorf("AttachDir = %q, unexpected", cfg.AttachDir)
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	os.Setenv("PORT", "9090")
	os.Setenv("DATA_DIR", "/tmp/testdata")
	defer os.Unsetenv("PORT")
	defer os.Unsetenv("DATA_DIR")

	cfg := Load()

	if cfg.Port != "9090" {
		t.Errorf("PORT override: got %q, want 9090", cfg.Port)
	}
	if cfg.DataDir != "/tmp/testdata" {
		t.Errorf("DATA_DIR override: got %q, want /tmp/testdata", cfg.DataDir)
	}
	if cfg.DBPath != filepath.Join("/tmp/testdata", "emailstore.db") {
		t.Errorf("DBPath derived from DATA_DIR: got %q", cfg.DBPath)
	}
}

func TestEnsureDirs(t *testing.T) {
	tmp := t.TempDir()
	cfg := &Config{
		DataDir:   filepath.Join(tmp, "data"),
		AttachDir: filepath.Join(tmp, "data", "attachments"),
	}

	if err := cfg.EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}

	for _, dir := range []string{cfg.DataDir, cfg.AttachDir} {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("directory not created: %s", dir)
		}
	}
}

func TestEnsureDirs_Idempotent(t *testing.T) {
	tmp := t.TempDir()
	cfg := &Config{
		DataDir:   filepath.Join(tmp, "data"),
		AttachDir: filepath.Join(tmp, "data", "attachments"),
	}
	// Calling twice should not error
	cfg.EnsureDirs()
	if err := cfg.EnsureDirs(); err != nil {
		t.Errorf("EnsureDirs twice: %v", err)
	}
}
