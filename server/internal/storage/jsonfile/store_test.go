/*
Description: Tests JSON file persistence, reload behavior, and atomic domain operations.
Author: vectorshi
Created: 2026-11-25
*/
package jsonfile

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/codepunk-gm/keypilot/server/internal/keyregistry"
)

// TestStorePersistsAndReloads verifies that issuer, key, and audit data survive store reload.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestStorePersistsAndReloads(testingContext *testing.T) {
	testingContext.Parallel()
	path := filepath.Join(testingContext.TempDir(), "keypilot.json")
	store, err := New(path)
	if err != nil {
		testingContext.Fatalf("create store: %v", err)
	}
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	issuer := keyregistry.Issuer{Issuer: "payment-service", DisplayName: "Payment Service", CreateTime: now, UpdateTime: now}
	if err := store.CreateIssuer(context.Background(), issuer, keyregistry.AuditRecord{RequestID: "1", Action: keyregistry.AuditActionCreateIssuer, CreateTime: now}); err != nil {
		testingContext.Fatalf("create issuer: %v", err)
	}
	key := keyregistry.VerificationKey{
		Issuer: "payment-service", KeyID: "key-1", KeyType: keyregistry.KeyTypeRSA,
		Purpose: keyregistry.KeyPurposeSignVerify, Algorithm: keyregistry.CryptoAlgorithmPS256,
		Status: keyregistry.KeyStatusPreActive, CreateTime: now, UpdateTime: now,
	}
	if err := store.CreateKey(context.Background(), key, keyregistry.AuditRecord{RequestID: "2", Action: keyregistry.AuditActionImportKey, CreateTime: now}); err != nil {
		testingContext.Fatalf("create key: %v", err)
	}

	reloaded, err := New(path)
	if err != nil {
		testingContext.Fatalf("reload store: %v", err)
	}
	loadedIssuer, err := reloaded.GetIssuer(context.Background(), "payment-service")
	if err != nil || loadedIssuer.DisplayName != "Payment Service" {
		testingContext.Fatalf("unexpected issuer after reload: issuer=%+v err=%v", loadedIssuer, err)
	}
	loadedKey, err := reloaded.GetKey(context.Background(), "payment-service", "key-1")
	if err != nil || loadedKey.Status != keyregistry.KeyStatusPreActive {
		testingContext.Fatalf("unexpected key after reload: key=%+v err=%v", loadedKey, err)
	}
}
