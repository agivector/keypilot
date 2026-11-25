/*
Description: Tests KeyPilot environment configuration defaults and validation.
Author: vectorshi
Created: 2026-11-25
*/
package config

import "testing"

// TestLoadRequiresStrongAdminToken verifies that the administration token is mandatory.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestLoadRequiresStrongAdminToken(testingContext *testing.T) {
	testingContext.Setenv("KEYPILOT_ADMIN_TOKEN", "short")
	if _, err := Load(); err == nil {
		testingContext.Fatal("expected short administration token to fail")
	}
	testingContext.Setenv("KEYPILOT_ADMIN_TOKEN", "0123456789abcdef")
	testingContext.Setenv("KEYPILOT_ADMIN_ID", "invalid admin id")
	if _, err := Load(); err == nil {
		testingContext.Fatal("expected invalid administration identity to fail")
	}
}

// TestLoadAppliesDefaultsAndOverrides verifies safe defaults and explicit environment values.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestLoadAppliesDefaultsAndOverrides(testingContext *testing.T) {
	testingContext.Setenv("KEYPILOT_ADMIN_TOKEN", "0123456789abcdef")
	testingContext.Setenv("KEYPILOT_ADMIN_ID", "security-operator")
	testingContext.Setenv("KEYPILOT_JWKS_MAX_AGE", "600")
	testingContext.Setenv("KEYPILOT_SHUTDOWN_TIMEOUT", "5s")
	configuration, err := Load()
	if err != nil {
		testingContext.Fatalf("load configuration: %v", err)
	}
	if configuration.Address != ":8080" || configuration.StorageType != StorageTypeSQLite || configuration.DataFile != "data/keypilot.db" || configuration.AdminID != "security-operator" || configuration.JWKSMaxAge != 600 || configuration.ShutdownTimeout.String() != "5s" {
		testingContext.Fatalf("unexpected configuration: %+v", configuration)
	}
}

// TestLoadSupportsNumericStorageTypes verifies numeric storage selection and matching default paths.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestLoadSupportsNumericStorageTypes(testingContext *testing.T) {
	testingContext.Setenv("KEYPILOT_ADMIN_TOKEN", "0123456789abcdef")
	testingContext.Setenv("KEYPILOT_STORAGE_TYPE", "1")
	configuration, err := Load()
	if err != nil {
		testingContext.Fatalf("load JSON storage configuration: %v", err)
	}
	if configuration.StorageType != StorageTypeJSONFile || configuration.DataFile != "data/keypilot.json" || configuration.JWKSMaxAge != 30 {
		testingContext.Fatalf("unexpected JSON storage configuration: %+v", configuration)
	}
	testingContext.Setenv("KEYPILOT_STORAGE_TYPE", "3")
	if _, err := Load(); err == nil {
		testingContext.Fatal("expected unsupported storage type to fail")
	}
}
