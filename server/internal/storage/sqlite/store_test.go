/*
Description: Tests SQLite persistence, transaction atomicity, and reload behavior.
Author: vectorshi
Created: 2026-11-25
*/
package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/agivector/keypilot/server/internal/keyregistry"
)

// TestStorePersistsAndReloads verifies durable issuer, key, and audit storage.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestStorePersistsAndReloads(testingContext *testing.T) {
	testingContext.Parallel()
	path := filepath.Join(testingContext.TempDir(), "keypilot.db")
	store, err := New(path)
	if err != nil {
		testingContext.Fatalf("create store: %v", err)
	}
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	issuer := testIssuer(now, "payment-service")
	if err := store.CreateIssuer(context.Background(), issuer, testAudit(now, "1", keyregistry.AuditActionCreateIssuer)); err != nil {
		testingContext.Fatalf("create issuer: %v", err)
	}
	key := testKey(now, issuer.Issuer)
	if err := store.CreateKey(context.Background(), key, testAudit(now, "2", keyregistry.AuditActionImportKey)); err != nil {
		testingContext.Fatalf("create key: %v", err)
	}
	key.Status = keyregistry.KeyStatusActive
	key.UpdateTime = now.Add(time.Minute)
	if err := store.UpdateKey(context.Background(), key, testAudit(now, "3", keyregistry.AuditActionUpdateKeyState)); err != nil {
		testingContext.Fatalf("update key: %v", err)
	}
	if err := store.AppendAudit(context.Background(), testAudit(now, "4", keyregistry.AuditActionAuthentication)); err != nil {
		testingContext.Fatalf("append audit: %v", err)
	}
	if err := store.Close(); err != nil {
		testingContext.Fatalf("close store: %v", err)
	}

	reloaded, err := New(path)
	if err != nil {
		testingContext.Fatalf("reload store: %v", err)
	}
	defer reloaded.Close()
	loadedIssuer, err := reloaded.GetIssuer(context.Background(), issuer.Issuer)
	if err != nil || loadedIssuer.DisplayName != issuer.DisplayName {
		testingContext.Fatalf("unexpected issuer: issuer=%+v err=%v", loadedIssuer, err)
	}
	loadedKey, err := reloaded.GetKey(context.Background(), issuer.Issuer, key.KeyID)
	if err != nil || loadedKey.Status != keyregistry.KeyStatusActive {
		testingContext.Fatalf("unexpected key: key=%+v err=%v", loadedKey, err)
	}
	audits, err := reloaded.ListAudits(context.Background())
	if err != nil || len(audits) != 4 || audits[3].RequestID != "4" {
		testingContext.Fatalf("unexpected audits: audits=%+v err=%v", audits, err)
	}
	if err := reloaded.CreateIssuer(context.Background(), issuer, testAudit(now, "5", keyregistry.AuditActionCreateIssuer)); !errors.Is(err, keyregistry.ErrStorageConflict) {
		testingContext.Fatalf("expected issuer conflict, got %v", err)
	}
	missingKey := testKey(now, "missing")
	if err := reloaded.CreateKey(context.Background(), missingKey, testAudit(now, "6", keyregistry.AuditActionImportKey)); !errors.Is(err, keyregistry.ErrStorageNotFound) {
		testingContext.Fatalf("expected missing issuer, got %v", err)
	}
}

// TestStoreRollsBackBusinessMutationWhenAuditFails verifies atomic business and audit writes.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestStoreRollsBackBusinessMutationWhenAuditFails(testingContext *testing.T) {
	testingContext.Parallel()
	store, err := New(filepath.Join(testingContext.TempDir(), "keypilot.db"))
	if err != nil {
		testingContext.Fatalf("create store: %v", err)
	}
	defer store.Close()
	if _, err := store.database.Exec(`CREATE TRIGGER reject_audits BEFORE INSERT ON audits BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END`); err != nil {
		testingContext.Fatalf("create audit trigger: %v", err)
	}
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	issuer := testIssuer(now, "transaction-test")
	if err := store.CreateIssuer(context.Background(), issuer, testAudit(now, "1", keyregistry.AuditActionCreateIssuer)); err == nil {
		testingContext.Fatal("expected forced audit failure")
	}
	if _, err := store.GetIssuer(context.Background(), issuer.Issuer); !errors.Is(err, keyregistry.ErrStorageNotFound) {
		testingContext.Fatalf("issuer escaped rolled back transaction: %v", err)
	}
}

// testIssuer creates one deterministic issuer fixture.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - now: fixture timestamp.
//   - identifier: issuer identifier.
//
// Returns:
//   - keyregistry.Issuer: issuer fixture.
func testIssuer(now time.Time, identifier string) keyregistry.Issuer {
	return keyregistry.Issuer{Issuer: identifier, DisplayName: identifier, CreateTime: now, UpdateTime: now}
}

// testKey creates one deterministic verification key fixture.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - now: fixture timestamp.
//   - issuer: owner issuer identifier.
//
// Returns:
//   - keyregistry.VerificationKey: verification key fixture.
func testKey(now time.Time, issuer string) keyregistry.VerificationKey {
	return keyregistry.VerificationKey{
		Issuer: issuer, KeyID: "key-1", KeyType: keyregistry.KeyTypeRSA,
		Purpose: keyregistry.KeyPurposeSignVerify, Algorithm: keyregistry.CryptoAlgorithmPS256,
		Status: keyregistry.KeyStatusPreActive, CreateTime: now, UpdateTime: now,
	}
}

// testAudit creates one deterministic audit fixture.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - now: fixture timestamp.
//   - requestID: stable request identifier.
//   - action: numeric audit action.
//
// Returns:
//   - keyregistry.AuditRecord: audit fixture.
func testAudit(now time.Time, requestID string, action keyregistry.AuditAction) keyregistry.AuditRecord {
	return keyregistry.AuditRecord{RequestID: requestID, Actor: "vectorshi", Action: action, Result: keyregistry.AuditResultSuccess, CreateTime: now}
}
