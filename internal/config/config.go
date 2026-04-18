package config

import (
	"os"
	"path/filepath"
)

type Config struct {
	Host      string // bind address, e.g. "127.0.0.1" or "0.0.0.0"
	Port      string
	DataDir   string
	DBPath    string
	AttachDir string
}

func Load() *Config {
	dataDir := getEnv("DATA_DIR", "./data")

	return &Config{
		// Default to localhost for local dev safety.
		// In Docker, set BIND_HOST=0.0.0.0 so the container accepts connections.
		Host:      getEnv("BIND_HOST", "127.0.0.1"),
		Port:      getEnv("PORT", "8080"),
		DataDir:   dataDir,
		DBPath:    filepath.Join(dataDir, "emailstore.db"),
		AttachDir: filepath.Join(dataDir, "attachments"),
	}
}

func (c *Config) EnsureDirs() error {
	if err := os.MkdirAll(c.DataDir, 0750); err != nil {
		return err
	}
	return os.MkdirAll(c.AttachDir, 0750)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
