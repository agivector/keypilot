/*
Description: Loads and validates KeyPilot server configuration from environment variables.
Author: vectorshi
Created: 2026-11-25
*/
package config

import (
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var adminIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Config describes the runtime configuration required by the KeyPilot server.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type Config struct {
	Address         string
	DataFile        string
	AdminID         string
	AdminToken      string
	JWKSMaxAge      int
	ShutdownTimeout time.Duration
}

// Load reads configuration from environment variables and applies safe defaults.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns:
//   - Config: validated runtime configuration.
//   - error: invalid or missing configuration error.
func Load() (Config, error) {
	configuration := Config{
		Address:         envOrDefault("KEYPILOT_ADDR", ":8080"),
		DataFile:        envOrDefault("KEYPILOT_DATA_FILE", "data/keypilot.json"),
		AdminID:         envOrDefault("KEYPILOT_ADMIN_ID", "default-admin"),
		AdminToken:      strings.TrimSpace(os.Getenv("KEYPILOT_ADMIN_TOKEN")),
		JWKSMaxAge:      300,
		ShutdownTimeout: 10 * time.Second,
	}
	if len(configuration.AdminToken) < 16 {
		return Config{}, errors.New("KEYPILOT_ADMIN_TOKEN must contain at least 16 characters")
	}
	if !adminIDPattern.MatchString(configuration.AdminID) {
		return Config{}, errors.New("KEYPILOT_ADMIN_ID must contain 1 to 64 letters, numbers, dots, underscores, or hyphens")
	}

	if rawMaxAge := strings.TrimSpace(os.Getenv("KEYPILOT_JWKS_MAX_AGE")); rawMaxAge != "" {
		maxAge, err := strconv.Atoi(rawMaxAge)
		if err != nil || maxAge < 0 || maxAge > 86400 {
			return Config{}, errors.New("KEYPILOT_JWKS_MAX_AGE must be an integer between 0 and 86400")
		}
		configuration.JWKSMaxAge = maxAge
	}

	if rawTimeout := strings.TrimSpace(os.Getenv("KEYPILOT_SHUTDOWN_TIMEOUT")); rawTimeout != "" {
		timeout, err := time.ParseDuration(rawTimeout)
		if err != nil || timeout <= 0 {
			return Config{}, errors.New("KEYPILOT_SHUTDOWN_TIMEOUT must be a positive duration")
		}
		configuration.ShutdownTimeout = timeout
	}
	return configuration, nil
}

// envOrDefault returns an environment value or its fallback when empty.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - name: environment variable name.
//   - fallback: value returned when the environment variable is empty.
//
// Returns:
//   - string: configured or fallback value.
func envOrDefault(name string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}
