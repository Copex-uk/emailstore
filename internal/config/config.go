package config

import (
	"os"
	"path/filepath"
)

type Config struct {
	Port      string
	DataDir   string
	DBPath    string
	AttachDir string
}

func Load() *Config {
	dataDir := getEnv("DATA_DIR", "./data")

	return &Config{
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
