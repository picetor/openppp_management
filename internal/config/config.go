package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen           string
	PublicURL        string
	DatabaseDriver   string
	DatabaseDSN      string
	DatabasePath     string
	AdminUsername    string
	AdminPassword    string
	CommunicationKey string
	SessionTTL       time.Duration
	NodeOfflineAfter time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		Listen:           env("OPENPPP2_LISTEN", "0.0.0.0:8080"),
		PublicURL:        strings.TrimRight(env("OPENPPP2_PUBLIC_URL", "http://localhost:8080"), "/"),
		DatabaseDriver:   strings.ToLower(env("OPENPPP2_DATABASE_DRIVER", "sqlite")),
		DatabaseDSN:      os.Getenv("OPENPPP2_DATABASE_DSN"),
		DatabasePath:     env("OPENPPP2_DATABASE_PATH", "./data/management.db"),
		AdminUsername:    env("OPENPPP2_ADMIN_USERNAME", "admin"),
		AdminPassword:    os.Getenv("OPENPPP2_ADMIN_PASSWORD"),
		CommunicationKey: strings.TrimSpace(os.Getenv("OPENPPP2_COMMUNICATION_KEY")),
		SessionTTL:       durationEnv("OPENPPP2_SESSION_TTL_HOURS", 168) * time.Hour,
		NodeOfflineAfter: durationEnv("OPENPPP2_NODE_OFFLINE_SECONDS", 90) * time.Second,
	}

	switch cfg.DatabaseDriver {
	case "mysql":
		if cfg.DatabaseDSN == "" {
			return Config{}, fmt.Errorf("OPENPPP2_DATABASE_DSN is required for mysql")
		}
	case "sqlite":
	default:
		return Config{}, fmt.Errorf("unsupported database driver %q", cfg.DatabaseDriver)
	}

	return cfg, nil
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func durationEnv(key string, fallback int64) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return time.Duration(fallback)
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n <= 0 {
		return time.Duration(fallback)
	}
	return time.Duration(n)
}
