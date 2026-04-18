package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	os.Unsetenv("PORT")
	os.Unsetenv("DATA_DIR")
	os.Unsetenv("BIND_HOST")

	cfg := Load()

	if cfg.Host != "127.0.0.1" {
		t.Errorf("default Host = %q, want 127.0.0.1", cfg.Host)
	}
	if cfg.Port != "8080" {
		t.Errorf("default Port = %q, want 8080", cfg.Port)
	}
	if cfg.DataDir != "./data" {
		t.Errorf("default DataDir = %q, want ./data", cfg.DataDir)
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	os.Setenv("PORT", "9090")
	os.Setenv("DATA_DIR", "/tmp/testdata")
	os.Setenv("BIND_HOST", "0.0.0.0")
	defer os.Unsetenv("PORT")
	defer os.Unsetenv("DATA_DIR")
	defer os.Unsetenv("BIND_HOST")

	cfg := Load()

	if cfg.Host != "0.0.0.0" {
		t.Errorf("BIND_HOST override: got %q, want 0.0.0.0", cfg.Host)
	}
	if cfg.Port != "9090" {
		t.Errorf("PORT override: got %q, want 9090", cfg.Port)
	}
	if cfg.DataDir != "/tmp/testdata" {
		t.Errorf("DATA_DIR override: got %q, want /tmp/testdata", cfg.DataDir)
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
